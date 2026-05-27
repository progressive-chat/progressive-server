// progressive-server: XMPP Daemon - Network server, SASL, TLS, stanza routing
// Reference: ejabberd (155,521 lines) - c2s, s2s, component connections,
// stream negotiation, SASL (PLAIN, SCRAM, EXTERNAL), STARTTLS,
// BOSH, WebSocket, stanza routing, s2s dialback, clustering

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <atomic>
#include <mutex>
#include <ctime>
#include <functional>
#include <deque>
#include <cstring>
#include <sstream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

namespace progressive {
namespace xmpp {

// Forward declarations from xmpp_core_v2
struct Jid; class XmppStanza;

// =============================================================================
// Stream header constants
// =============================================================================
static constexpr const char* STREAM_OPEN = 
    "<?xml version='1.0'?>"
    "<stream:stream "
    "xmlns='jabber:client' "
    "xmlns:stream='http://etherx.jabber.org/streams' "
    "version='1.0' "
    "from='{FROM}' "
    "id='{SID}' "
    "xml:lang='en'>";

static constexpr const char* STREAM_FEATURES = 
    "<stream:features>"
    "{FEATURES}"
    "</stream:features>";

static constexpr const char* STREAM_ERROR = 
    "<stream:error>"
    "<{CONDITION} xmlns='urn:ietf:params:xml:ns:xmpp-streams'/>"
    "<text xmlns='urn:ietf:params:xml:ns:xmpp-streams'>{TEXT}</text>"
    "</stream:error>"
    "</stream:stream>";

static constexpr const char* TLS_PROCEED = 
    "<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";

static constexpr const char* TLS_FAILURE = 
    "<failure xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>";

// =============================================================================
// XMPP stream parser (SAX-based XML for stream-level parsing)
// =============================================================================
enum class StreamState : uint8_t {
    INIT,
    STREAM_OPEN_SENT,
    STREAM_OPEN_RECEIVED,
    FEATURES_SENT,
    TLS_NEGOTIATING,
    TLS_ESTABLISHED,
    SASL_NEGOTIATING,
    SASL_AUTHENTICATED,
    RESOURCE_BINDING,
    SESSION_ESTABLISHING,
    READY,
    CLOSING,
    CLOSED,
};

struct StreamSession {
    int fd = -1;
    StreamState state = StreamState::INIT;
    Jid user_jid;
    std::string stream_id;
    std::string remote_domain;
    std::string stream_namespace;   // jabber:client, jabber:server
    std::string xml_lang;
    std::string stream_from;
    std::string stream_to;
    bool tls_enabled = false;
    bool compression_enabled = false;
    bool sasl_authenticated = false;
    std::string sasl_mechanism;
    bool resource_bound = false;
    bool session_established = false;

    // Stream management (XEP-0198)
    bool sm_enabled = false;
    uint32_t sm_in_count = 0;
    uint32_t sm_out_count = 0;
    std::string sm_id;
    bool sm_resumed = false;

    // CSI (XEP-0352)
    bool csi_active = false;

    // Timing
    time_t connected_at = 0;
    time_t last_activity = 0;
    time_t stream_opened_at = 0;

    // Buffers
    std::string xml_buffer;
    std::deque<std::string> send_queue;

    // Presence state
    std::string presence_show;
    std::string presence_status;
    int presence_priority = 0;
};

// =============================================================================
// SASL mechanisms
// =============================================================================
enum class SaslMechanism : uint8_t {
    PLAIN,
    SCRAM_SHA_1,
    SCRAM_SHA_256,
    SCRAM_SHA_512,
    DIGEST_MD5,
    EXTERNAL,
    ANONYMOUS,
    X_OAUTH2,
};

struct SaslChallenge {
    std::string mechanism;
    std::string initial_response;
    std::string challenge_data;
    std::string response_data;
    bool success = false;
    std::string error;
};

class SaslEngine {
public:
    static const std::vector<std::string>& supported_mechanisms() {
        static std::vector<std::string> mechs = {
            "SCRAM-SHA-512", "SCRAM-SHA-256", "SCRAM-SHA-1",
            "PLAIN", "EXTERNAL"
        };
        return mechs;
    }

    struct ScramState {
        std::string stored_key;
        std::string server_key;
        std::string client_key;
        std::string salt;
        int iterations = 4096;
        std::string nonce;
        std::string client_first_message_bare;
        std::string server_signature;
        bool client_proof_verified = false;
    };

    static SaslChallenge process_plain(const std::string& authzid,
                                        const std::string& authcid,
                                        const std::string& password) {
        SaslChallenge result;
        result.mechanism = "PLAIN";
        // Format: authzid\0authcid\0password
        std::string data = authzid + '\0' + authcid + '\0' + password;
        // Base64 encode
        result.initial_response = base64_encode(data);
        result.success = !password.empty();
        return result;
    }

    static ScramState init_scram(const std::string& mechanism,
                                  const std::string& password) {
        ScramState state;
        state.salt = generate_salt(16);
        state.iterations = 4096;
        state.nonce = generate_nonce(24);
        return state;
    }

    static std::string compute_scram_server_first(const ScramState& state) {
        // r=<nonce>,s=<salt_base64>,i=<iterations>
        std::string msg = "r=" + state.nonce + 
                          ",s=" + base64_encode(state.salt) +
                          ",i=" + std::to_string(state.iterations);
        return base64_encode(msg);
    }

    static std::string compute_scram_server_final(const ScramState& state) {
        // v=<server_signature_base64>
        return "v=" + base64_encode(state.server_signature);
    }

private:
    static std::string generate_salt(size_t len) {
        static const char* hex = "0123456789abcdef";
        std::string salt;
        salt.reserve(len * 2);
        for (size_t i = 0; i < len; i++) {
            salt += hex[rand() % 16];
            salt += hex[rand() % 16];
        }
        return salt;
    }

    static std::string generate_nonce(size_t len) {
        static const char* chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        std::string nonce;
        nonce.reserve(len);
        for (size_t i = 0; i < len; i++) {
            nonce += chars[rand() % 62];
        }
        return nonce;
    }

    static std::string base64_encode(const std::string& input) {
        static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve((input.size() + 2) / 3 * 4);
        for (size_t i = 0; i < input.size(); i += 3) {
            uint32_t n = (uint8_t)input[i] << 16;
            if (i + 1 < input.size()) n |= (uint8_t)input[i + 1] << 8;
            if (i + 2 < input.size()) n |= (uint8_t)input[i + 2];
            out += table[(n >> 18) & 0x3F];
            out += table[(n >> 12) & 0x3F];
            out += (i + 1 < input.size()) ? table[(n >> 6) & 0x3F] : '=';
            out += (i + 2 < input.size()) ? table[n & 0x3F] : '=';
        }
        return out;
    }
};

// =============================================================================
// XMPP Router - routes stanzas between sessions and to remote servers
// =============================================================================
struct RouteEntry {
    Jid jid;
    int fd;
    int priority;
    bool is_local;
};

class XmppRouter {
public:
    void register_session(const Jid& jid, int fd, int priority = 0) {
        std::lock_guard lock(mutex_);
        RouteEntry entry{ jid, fd, priority, true };
        routes_by_jid_[jid.bare()].push_back(entry);
        fd_to_jid_[fd] = jid;

        // Re-sort by priority descending
        auto& entries = routes_by_jid_[jid.bare()];
        std::sort(entries.begin(), entries.end(),
            [](const RouteEntry& a, const RouteEntry& b) {
                return a.priority > b.priority;
            });
    }

    void unregister_session(int fd) {
        std::lock_guard lock(mutex_);
        auto it = fd_to_jid_.find(fd);
        if (it != fd_to_jid_.end()) {
            auto& entries = routes_by_jid_[it->second.bare()];
            entries.erase(std::remove_if(entries.begin(), entries.end(),
                [fd](const RouteEntry& e) { return e.fd == fd; }), entries.end());
            if (entries.empty()) routes_by_jid_.erase(it->second.bare());
            fd_to_jid_.erase(it);
        }
    }

    std::vector<RouteEntry> route(const Jid& to) {
        std::lock_guard lock(mutex_);

        // 1. Try full JID match
        for (auto& [bare, entries] : routes_by_jid_) {
            for (auto& e : entries) {
                if (e.jid.full() == to.full()) return {e};
            }
        }

        // 2. Try bare JID match (pick highest priority)
        auto it = routes_by_jid_.find(to.bare());
        if (it != routes_by_jid_.end()) {
            std::vector<RouteEntry> result;
            if (!to.resource.empty()) {
                // Look for exact resource match
                for (auto& e : it->second) {
                    if (e.jid.resource == to.resource) {
                        result.push_back(e);
                    }
                }
            }
            if (result.empty() && !it->second.empty()) {
                result.push_back(it->second.front());
            }
            if (!result.empty()) return result;
        }

        // 3. Try domain-level routing (s2s)
        auto dit = routes_by_domain_.find(to.domain);
        if (dit != routes_by_domain_.end()) {
            return {dit->second};
        }

        return {};
    }

    void register_domain_route(const std::string& domain, int fd) {
        std::lock_guard lock(mutex_);
        RouteEntry entry;
        entry.jid = Jid("", domain, "");
        entry.fd = fd;
        entry.priority = 0;
        entry.is_local = true;
        routes_by_domain_[domain] = entry;
    }

    Jid get_jid_for_fd(int fd) {
        auto it = fd_to_jid_.find(fd);
        return (it != fd_to_jid_.end()) ? it->second : Jid();
    }

private:
    std::unordered_map<std::string, std::vector<RouteEntry>> routes_by_jid_;
    std::unordered_map<std::string, RouteEntry> routes_by_domain_;
    std::unordered_map<int, Jid> fd_to_jid_;
    std::mutex mutex_;
};

// =============================================================================
// XMPP Server (C2S)
// =============================================================================
class XmppDaemon {
public:
    struct Config {
        std::string hostname = "localhost";
        std::vector<int> c2s_ports = {5222, 5223};
        std::vector<int> s2s_ports = {5269, 5270};
        std::vector<int> component_ports = {5347};
        std::vector<int> bosh_ports = {5280, 5281};
        std::vector<int> websocket_ports = {5443};
        std::string cert_file;
        std::string key_file;
        int max_stanza_size = 65536;
        int max_clients = 100000;
        int c2s_shaper = 1000;        // bytes/sec per c2s connection
        int s2s_shaper = 10000;       // bytes/sec per s2s connection
        int c2s_timeout = 300;
        int s2s_timeout = 300;
        int stream_mgmt_timeout = 600;
        bool tls_required = false;
        bool s2s_use_starttls = true;
        bool s2s_tls_required = false;
        bool auth_anonymous = false;
        bool registration_enabled = false;
        bool inband_registration = false;
        std::string welcome_message;
        std::vector<std::string> trusted_proxies;
        std::string server_info;
    };

    XmppDaemon() = default;

    void configure(const Config& cfg) {
        config_ = cfg;
    }

    bool start() {
        if (running_.exchange(true)) return false;

        // Create listen sockets
        for (int port : config_.c2s_ports) {
            int fd = create_listen_socket(port);
            if (fd >= 0) {
                listen_sockets_.push_back({fd, port, "c2s"});
            }
        }
        for (int port : config_.s2s_ports) {
            int fd = create_listen_socket(port);
            if (fd >= 0) {
                listen_sockets_.push_back({fd, port, "s2s"});
            }
        }

        return !listen_sockets_.empty();
    }

    void stop() {
        running_.store(false);
        for (auto& [fd, _] : listen_sockets_) {
            close(fd);
        }
        listen_sockets_.clear();
        for (auto& [fd, session] : sessions_) {
            close(fd);
        }
        sessions_.clear();
    }

    // ========== Session management ==========
    StreamSession* get_session(int fd) {
        auto it = sessions_.find(fd);
        return (it != sessions_.end()) ? &it->second : nullptr;
    }

    void close_session(int fd, const std::string& reason = "closed") {
        auto session = get_session(fd);
        if (!session) return;

        if (session->state >= StreamState::SASL_AUTHENTICATED) {
            // Broadcast unavailable presence
            auto unavail = XmppStanza::make_presence(session->user_jid);
            unavail->set_presence_type(PresenceType::UNAVAILABLE);
            broadcast_presence(session->user_jid, *unavail);
        }

        router_.unregister_session(fd);
        close(fd);
        sessions_.erase(fd);
    }

    // ========== Stream negotiation ==========
    void on_accept(int fd, const std::string& remote_addr) {
        StreamSession session;
        session.fd = fd;
        session.state = StreamState::INIT;
        session.connected_at = std::time(nullptr);
        session.last_activity = session.connected_at;
        session.stream_namespace = "jabber:client";

        sessions_[fd] = session;

        // Send stream opening
        send_stream_open(fd);
    }

    void on_stream_open(int fd, const std::string& xmlns,
                        const std::string& to, const std::string& from,
                        const std::string& version, const std::string& xml_lang) {
        auto session = get_session(fd);
        if (!session) return;

        session->stream_namespace = xmlns;
        session->stream_to = to;
        session->stream_from = from;
        session->xml_lang = xml_lang;
        session->state = StreamState::STREAM_OPEN_RECEIVED;
        session->last_activity = std::time(nullptr);

        // Send stream features
        send_features(fd);
    }

    void on_tls_proceed(int fd) {
        auto session = get_session(fd);
        if (!session) return;
        session->state = StreamState::TLS_NEGOTIATING;
    }

    void on_tls_established(int fd) {
        auto session = get_session(fd);
        if (!session) return;
        session->state = StreamState::TLS_ESTABLISHED;
        session->tls_enabled = true;

        // Restart stream
        send_stream_open(fd);
    }

    void on_sasl_auth(int fd, const std::string& mechanism,
                      const std::string& data) {
        auto session = get_session(fd);
        if (!session) return;

        session->sasl_mechanism = mechanism;
        session->state = StreamState::SASL_NEGOTIATING;

        if (mechanism == "PLAIN") {
            handle_sasl_plain(fd, data);
        } else if (mechanism.find("SCRAM-SHA-") == 0) {
            handle_sasl_scram(fd, mechanism, data);
        } else if (mechanism == "EXTERNAL") {
            handle_sasl_external(fd, data);
        }
    }

    void on_sasl_response(int fd, const std::string& data) {
        auto session = get_session(fd);
        if (!session) return;

        if (session->sasl_mechanism.find("SCRAM-SHA-") == 0) {
            handle_scram_response(fd, data);
        }
    }

    void on_stanza(int fd, XmppStanza::ptr stanza) {
        auto session = get_session(fd);
        if (!session) return;

        session->last_activity = std::time(nullptr);

        if (!session->sasl_authenticated) {
            send_stream_error(fd, "not-authorized", "Not authenticated");
            return;
        }

        // Handle resource binding (XEP-0199)
        if (!session->resource_bound && stanza->type() == StanzaType::IQ) {
            handle_resource_bind(fd, stanza);
            return;
        }

        // Handle session establishment
        if (!session->session_established && stanza->type() == StanzaType::IQ) {
            handle_session_establish(fd, stanza);
            return;
        }

        // Route the stanza
        route_stanza(fd, stanza);
    }

private:
    Config config_;
    std::atomic<bool> running_{false};
    struct ListenInfo { int fd; int port; std::string type; };

    std::vector<ListenInfo> listen_sockets_;
    std::unordered_map<int, StreamSession> sessions_;
    XmppRouter router_;

    // ========== Helpers ==========
    static int create_listen_socket(int port) {
        int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) return -1;

        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }

        if (listen(fd, 128) < 0) {
            close(fd);
            return -1;
        }

        return fd;
    }

    void send_stream_open(int fd) {
        std::string xml = STREAM_OPEN;
        size_t pos = xml.find("{FROM}");
        if (pos != std::string::npos) xml.replace(pos, 6, config_.hostname);
        pos = xml.find("{SID}");
        if (pos != std::string::npos) {
            char sid[32];
            snprintf(sid, sizeof(sid), "%lx", (unsigned long)std::time(nullptr));
            xml.replace(pos, 5, sid);
        }
        queue_xml(fd, xml);
    }

    void send_features(int fd) {
        auto session = get_session(fd);
        if (!session) return;

        std::string features;

        // TLS
        if (!session->tls_enabled && session->stream_namespace == "jabber:client") {
            features += "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'>"
                        "<required/></starttls>";
        }

        // SASL
        if (session->tls_enabled || !config_.tls_required) {
            features += "<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>";
            for (auto& mech : SaslEngine::supported_mechanisms()) {
                features += "<mechanism>" + mech + "</mechanism>";
            }
            features += "</mechanisms>";
        }

        // Compression
        features += "<compression xmlns='http://jabber.org/features/compress'>"
                     "<method>zlib</method></compression>";

        // Resource binding
        if (session->sasl_authenticated && !session->resource_bound) {
            features += "<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>";
        }

        // Session
        if (session->sasl_authenticated && !session->session_established) {
            features += "<session xmlns='urn:ietf:params:xml:ns:xmpp-session'/>";
        }

        // Stream management
        features += "<sm xmlns='urn:xmpp:sm:3'/>";

        // CSI
        features += "<csi xmlns='urn:xmpp:csi:0'/>";

        std::string xml = STREAM_FEATURES;
        size_t pos = xml.find("{FEATURES}");
        if (pos != std::string::npos) xml.replace(pos, 10, features);
        queue_xml(fd, xml);

        session->state = StreamState::FEATURES_SENT;
    }

    // ========== SASL handlers ==========
    void handle_sasl_plain(int fd, const std::string& b64_data) {
        std::string decoded = base64_decode(b64_data);

        // Format: authzid\0authcid\0password
        size_t nul1 = decoded.find('\0');
        size_t nul2 = (nul1 != std::string::npos) ? decoded.find('\0', nul1 + 1) : std::string::npos;

        std::string authzid = (nul1 != std::string::npos) ? decoded.substr(0, nul1) : "";
        std::string authcid = (nul1 != std::string::npos && nul2 != std::string::npos)
                             ? decoded.substr(nul1 + 1, nul2 - nul1 - 1) : "";
        std::string password = (nul2 != std::string::npos)
                              ? decoded.substr(nul2 + 1) : "";

        // Verify credentials against user database
        if (verify_password(authcid, password)) {
            auto session = get_session(fd);
            if (session) {
                session->user_jid = Jid(authcid, config_.hostname, "");
                session->sasl_authenticated = true;
                session->state = StreamState::SASL_AUTHENTICATED;
            }
            queue_xml(fd, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
        } else {
            queue_xml(fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                           "<not-authorized/></failure>");
        }
    }

    void handle_sasl_external(int fd, const std::string& data) {
        // CERT-based auth - uses client TLS certificate CN
        auto session = get_session(fd);
        if (!session || !session->tls_enabled) {
            queue_xml(fd, "<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>"
                           "<encryption-required/></failure>");
            return;
        }
        // Extract CN from certificate
        std::string cert_cn = data.empty() ? "" : base64_decode(data);
        if (!cert_cn.empty()) {
            session->user_jid = Jid(cert_cn, config_.hostname, "");
            session->sasl_authenticated = true;
            session->state = StreamState::SASL_AUTHENTICATED;
            queue_xml(fd, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>");
        }
    }

    void handle_sasl_scram(int fd, const std::string& mechanism,
                           const std::string& client_first_b64) {
        auto session = get_session(fd);
        if (!session) return;

        // Parse client-first-message: n,authzid,n=username,r=nonce
        std::string client_first = base64_decode(client_first_b64);

        // Generate server nonce and salt
        session->scram.nonce = generate_nonce(24);
        session->scram.salt = generate_salt(16);
        session->scram.iterations = 4096;

        std::string server_first = "r=" + session->scram.nonce +
                                    ",s=" + base64_encode(session->scram.salt) +
                                    ",i=" + std::to_string(session->scram.iterations);

        queue_xml(fd, "<challenge xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" +
                       base64_encode(server_first) + "</challenge>");
    }

    void handle_scram_response(int fd, const std::string& client_final_b64) {
        std::string client_final = base64_decode(client_final_b64);

        // Verify client proof (simplified - real implementation uses HMAC-SHA-2)
        // For now, accept the response

        std::string server_final = "v=" + base64_encode(generate_salt(32));
        queue_xml(fd, "<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>" +
                       base64_encode(server_final) + "</success>");

        auto session = get_session(fd);
        if (session) {
            session->sasl_authenticated = true;
            session->state = StreamState::SASL_AUTHENTICATED;
        }
    }

    // ========== Resource binding ==========
    void handle_resource_bind(int fd, XmppStanza::ptr stanza) {
        if (stanza->iq_type() != IqType::SET) return;

        auto* bind_ext = stanza->find_extension("urn:ietf:params:xml:ns:xmpp-bind", "bind");
        if (!bind_ext) return;

        auto session = get_session(fd);
        if (!session) return;

        // Extract desired resource or generate random
        std::string resource;
        auto res_it = bind_ext->attrs.find("resource");
        if (res_it != bind_ext->attrs.end() && !res_it->second.empty()) {
            resource = res_it->second;
        } else {
            char res[32];
            snprintf(res, sizeof(res), "%lx%04x",
                     (unsigned long)std::time(nullptr), rand() & 0xFFFF);
            resource = res;
        }

        session->user_jid.resource = resource;
        session->resource_bound = true;
        router_.register_session(session->user_jid, fd);

        // Send bind result
        auto result = XmppStanza::make_iq_result(*stanza);
        XmppStanza::Extension ext;
        ext.xmlns = "urn:ietf:params:xml:ns:xmpp-bind";
        ext.tag = "bind";
        ext.content = "<jid>" + session->user_jid.full() + "</jid>";
        result->add_extension(ext);

        queue_xml(fd, result->to_xml());

        send_features(fd);
    }

    // ========== Session establishment ==========
    void handle_session_establish(int fd, XmppStanza::ptr stanza) {
        if (stanza->iq_type() != IqType::SET) return;

        auto* sess_ext = stanza->find_extension("urn:ietf:params:xml:ns:xmpp-session", "session");
        if (!sess_ext) return;

        auto session = get_session(fd);
        if (!session) return;

        session->session_established = true;
        session->state = StreamState::READY;

        auto result = XmppStanza::make_iq_result(*stanza);
        result->add_extension("urn:ietf:params:xml:ns:xmpp-session", "session");
        queue_xml(fd, result->to_xml());

        // Broadcast available presence
        auto pres = XmppStanza::make_presence(session->user_jid);
        broadcast_presence(session->user_jid, *pres);

        // Send roster
        send_roster(fd);
    }

    // ========== Stanza routing ==========
    void route_stanza(int fd, XmppStanza::ptr stanza) {
        // Add from if missing
        if (stanza->from().domain.empty()) {
            stanza->set_from(router_.get_jid_for_fd(fd));
        }

        auto routes = router_.route(stanza->to());

        for (auto& route : routes) {
            if (route.is_local) {
                queue_xml(route.fd, stanza->to_xml());
            } else {
                // S2S routing - forward to remote domain
                route_to_remote(route, stanza);
            }
        }

        if (routes.empty()) {
            // Generate error
            auto error = XmppStanza::make_iq_error(*stanza,
                StanzaErrorCondition::SERVICE_UNAVAILABLE,
                "No route to " + stanza->to().full());
            queue_xml(fd, error->to_xml());
        }
    }

    void route_to_remote(const RouteEntry& route, XmppStanza::ptr stanza) {
        // In a real implementation:
        // 1. Check if we have an s2s connection to the remote domain
        // 2. If not, establish one
        // 3. Send the stanza over the s2s connection
        // 4. Handle s2s dialback for server verification
        (void)route;
        (void)stanza;
    }

    void broadcast_presence(const Jid& from, const XmppStanza& presence) {
        // Send presence to all subscribed contacts
        for (auto& sub : router_.get_subscribers(from)) {
            auto routes = router_.route(sub);
            for (auto& r : routes) {
                if (r.is_local) {
                    queue_xml(r.fd, presence.to_xml());
                }
            }
        }
    }

    void send_roster(int fd) {
        auto session = get_session(fd);
        if (!session) return;

        auto iq = XmppStanza::make_iq(Jid(config_.hostname), session->user_jid, IqType::RESULT);
        iq->set_id("roster1");

        XmppStanza::Extension query;
        query.xmlns = "jabber:iq:roster";
        query.tag = "query";

        // Add roster items (from user's roster storage)
        for (auto& item : get_roster_items(session->user_jid)) {
            query.content += "<item jid='" + item.jid.bare() + "' "
                            "name='" + item.name + "' "
                            "subscription='" + item.subscription + "'";
            if (!item.groups.empty()) {
                query.content += ">";
                for (auto& g : item.groups) {
                    query.content += "<group>" + g + "</group>";
                }
                query.content += "</item>";
            } else {
                query.content += "/>";
            }
        }

        iq->add_extension(query);
        queue_xml(fd, iq->to_xml());
    }

    std::vector<RosterItem> get_roster_items(const Jid& jid) {
        // In real implementation, query roster storage
        return {};
    }

    // ========== Utility ==========
    void send_stream_error(int fd, const std::string& condition,
                           const std::string& text) {
        std::string xml = STREAM_ERROR;
        size_t pos = xml.find("{CONDITION}");
        if (pos != std::string::npos) xml.replace(pos, 11, condition);
        pos = xml.find("{TEXT}");
        if (pos != std::string::npos) xml.replace(pos, 6, text);
        queue_xml(fd, xml);
    }

    void queue_xml(int fd, const std::string& xml) {
        auto session = get_session(fd);
        if (session) {
            session->send_queue.push_back(xml);
        }
    }

    static std::string base64_decode(const std::string& input) {
        static const std::string table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(input.size() * 3 / 4);

        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) T[(uint8_t)table[i]] = i;

        int val = 0, valb = -8;
        for (uint8_t c : input) {
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                out.push_back((val >> valb) & 0xFF);
                valb -= 8;
            }
        }
        return out;
    }

    static std::string generate_nonce(size_t len) {
        std::string nonce;
        for (size_t i = 0; i < len; i++) {
            nonce += "abcdefghijklmnopqrstuvwxyz0123456789"[rand() % 36];
        }
        return nonce;
    }

    static std::string generate_salt(size_t len) { return generate_nonce(len); }

    bool verify_password(const std::string& user, const std::string& pass) {
        // In real implementation, check against user database/bcrypt
        return true;
    }
};

} // namespace xmpp
} // namespace progressive
