// progressive-server: IRC SSL/TLS, SASL, Services integration
// Reference: InspIRCd ssl.cpp, m_sasl.cpp, m_cap.cpp, services.cpp
// OpenSSL wrappers, CAP negotiation, SASL mechanisms, NickServ/ChanServ

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <atomic>
#include <mutex>
#include <ctime>
#include <functional>
#include <algorithm>
#include <sstream>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>
#include <unistd.h>

namespace progressive {
namespace irc {

// =============================================================================
// SSL Context singleton
// =============================================================================
class SslContext {
public:
    static SslContext& instance() {
        static SslContext ctx;
        return ctx;
    }

    bool initialize(const std::string& cert_file, const std::string& key_file,
                    const std::string& dh_file = "", const std::string& ca_file = "") {
        if (initialized_) return true;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
#else
        OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
#endif

        ctx_ = SSL_CTX_new(TLS_server_method());
        if (!ctx_) return false;

        // Configure for best security
        SSL_CTX_set_options(ctx_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                  SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);
        SSL_CTX_set_options(ctx_, SSL_OP_CIPHER_SERVER_PREFERENCE);
        SSL_CTX_set_options(ctx_, SSL_OP_SINGLE_DH_USE);
        SSL_CTX_set_options(ctx_, SSL_OP_SINGLE_ECDH_USE);

        // Set cipher list
        SSL_CTX_set_cipher_list(ctx_,
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");

        // Load certificate
        if (SSL_CTX_use_certificate_chain_file(ctx_, cert_file.c_str()) != 1) {
            return false;
        }

        // Load private key
        if (SSL_CTX_use_PrivateKey_file(ctx_, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            return false;
        }

        // Verify cert matches key
        if (SSL_CTX_check_private_key(ctx_) != 1) {
            return false;
        }

        // DH params
        if (!dh_file.empty()) {
            BIO* bio = BIO_new_file(dh_file.c_str(), "r");
            if (bio) {
                DH* dh = PEM_read_bio_DHparams(bio, nullptr, nullptr, nullptr);
                BIO_free(bio);
                if (dh) {
                    SSL_CTX_set_tmp_dh(ctx_, dh);
                    DH_free(dh);
                }
            }
        } else {
            SSL_CTX_set_dh_auto(ctx_, 1); // Auto DH params
        }

        // ECDH curve
        SSL_CTX_set_ecdh_auto(ctx_, 1);

        // Client CA
        if (!ca_file.empty()) {
            SSL_CTX_load_verify_locations(ctx_, ca_file.c_str(), nullptr);
            SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        }

        cert_file_ = cert_file;
        key_file_ = key_file;
        initialized_ = true;
        return true;
    }

    SSL* create_ssl(int fd, bool server = true) {
        SSL* ssl = SSL_new(ctx_);
        if (!ssl) return nullptr;
        SSL_set_fd(ssl, fd);
        if (server) {
            SSL_set_accept_state(ssl);
        } else {
            SSL_set_connect_state(ssl);
        }
        return ssl;
    }

    void free_ssl(SSL* ssl) {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }

    // Reload certificate without restart
    bool reload_cert(const std::string& cert_file, const std::string& key_file) {
        SSL_CTX* new_ctx = SSL_CTX_new(TLS_server_method());
        if (!new_ctx) return false;

        if (SSL_CTX_use_certificate_chain_file(new_ctx, cert_file.c_str()) != 1 ||
            SSL_CTX_use_PrivateKey_file(new_ctx, key_file.c_str(), SSL_FILETYPE_PEM) != 1) {
            SSL_CTX_free(new_ctx);
            return false;
        }

        // Atomic swap
        SSL_CTX* old = ctx_;
        ctx_ = new_ctx;
        SSL_CTX_free(old);

        cert_file_ = cert_file;
        key_file_ = key_file;
        return true;
    }

    std::string get_fingerprint(SSL* ssl) {
        X509* cert = SSL_get_peer_certificate(ssl);
        if (!cert) return "";

        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len = 0;
        X509_digest(cert, EVP_sha256(), md, &md_len);
        X509_free(cert);

        std::string fp;
        fp.reserve(md_len * 3);
        for (unsigned int i = 0; i < md_len; i++) {
            if (i > 0) fp += ':';
            char buf[3];
            snprintf(buf, sizeof(buf), "%02X", md[i]);
            fp += buf;
        }
        return fp;
    }

    static std::string get_cert_cn(SSL* ssl) {
        X509* cert = SSL_get_peer_certificate(ssl);
        if (!cert) return "";

        X509_NAME* subject = X509_get_subject_name(cert);
        char cn[256] = {0};
        X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn));
        X509_free(cert);
        return std::string(cn);
    }

private:
    SslContext() = default;
    ~SslContext() {
        if (ctx_) SSL_CTX_free(ctx_);
    }

    SslContext(const SslContext&) = delete;
    SslContext& operator=(const SslContext&) = delete;

    SSL_CTX* ctx_ = nullptr;
    bool initialized_ = false;
    std::string cert_file_;
    std::string key_file_;
};

// =============================================================================
// IRC CAP (capability negotiation) - IRCv3
// =============================================================================
enum class CapState : uint8_t {
    NONE,
    LS_SENT,          // Server sent CAP LS
    REQ_RECEIVED,     // Client sent CAP REQ
    ACK_SENT,         // Server sent CAP ACK
    NAK_SENT,         // Server sent CAP NAK
    LIST_RECEIVED,    // Client sent CAP LIST
    SENT_REQUEST,     // CAP REQ sasl sent by client
    END_RECEIVED,     // CAP END received
};

struct ServerCapability {
    std::string name;
    bool available = true;
    bool enabled = false;
    int version = 0;        // for capabilities like "cap-notify=2"
    std::string value;      // for key=value capabilities
};

class CapManager {
public:
    CapManager() {
        // Register supported capabilities (IRCv3)
        caps_["account-tag"] = { "account-tag", true, false };
        caps_["account-notify"] = { "account-notify", true, false };
        caps_["away-notify"] = { "away-notify", true, false };
        caps_["cap-notify"] = { "cap-notify", true, false, 2 };
        caps_["chghost"] = { "chghost", true, false };
        caps_["echo-message"] = { "echo-message", true, false };
        caps_["extended-join"] = { "extended-join", true, false };
        caps_["invite-notify"] = { "invite-notify", true, false };
        caps_["message-tags"] = { "message-tags", true, false };
        caps_["multi-prefix"] = { "multi-prefix", true, false };
        caps_["sasl"] = { "sasl", true, false, 3 };
        caps_["server-time"] = { "server-time", true, false };
        caps_["setname"] = { "setname", true, false };
        caps_["userhost-in-names"] = { "userhost-in-names", true, false };
        caps_["batch"] = { "batch", true, false };
        caps_["labeled-response"] = { "labeled-response", true, false };
        caps_["sts"] = { "sts", true, false };
    }

    // Handle CAP command
    std::string handle_cap(const std::string& subcommand, const std::string& cap_list) {
        if (subcommand == "LS") {
            return build_cap_ls();
        } else if (subcommand == "LIST") {
            return build_cap_list();
        } else if (subcommand == "REQ") {
            return handle_cap_req(cap_list);
        } else if (subcommand == "END") {
            cap_state_ = CapState::END_RECEIVED;
            return "";
        }
        return "";
    }

    bool is_cap_end() const { return cap_state_ == CapState::END_RECEIVED; }
    void reset() { cap_state_ = CapState::NONE; }

    bool is_sasl_enabled() const {
        auto it = caps_.find("sasl");
        return it != caps_.end() && it->second.enabled;
    }

    bool is_cap_enabled(const std::string& name) const {
        auto it = caps_.find(name);
        return it != caps_.end() && it->second.enabled;
    }

    void disable_cap(const std::string& name) {
        auto it = caps_.find(name);
        if (it != caps_.end()) it->second.enabled = false;
    }

    std::string notify_del(const std::string& cap) {
        if (!is_cap_enabled("cap-notify")) return "";
        return ":server CAP * DEL :" + cap;
    }

    std::string notify_new(const std::string& cap) {
        if (!is_cap_enabled("cap-notify")) return "";
        return ":server CAP * NEW :" + cap;
    }

private:
    std::string build_cap_ls() {
        std::string result = ":server CAP * LS :";
        bool first = true;
        for (auto& [name, cap] : caps_) {
            if (!cap.available) continue;
            if (!first) result += " ";
            first = false;
            result += name;
            if (cap.version > 0) result += "=" + std::to_string(cap.version);
            if (!cap.value.empty()) result += "=" + cap.value;
        }
        cap_state_ = CapState::LS_SENT;
        return result;
    }

    std::string build_cap_list() {
        std::string result = ":server CAP * LIST :";
        bool first = true;
        for (auto& [name, cap] : caps_) {
            if (!cap.enabled) continue;
            if (!first) result += " ";
            first = false;
            result += name;
        }
        cap_state_ = CapState::LIST_RECEIVED;
        return result;
    }

    std::string handle_cap_req(const std::string& cap_list_str) {
        auto requested = split_str(cap_list_str, ' ');

        // Check each requested cap
        std::vector<std::string> accepted, rejected, disabled;

        for (auto& cap_req : requested) {
            // Handle -prefix for disabling
            bool enable = true;
            std::string cap_name = cap_req;
            if (cap_name.empty()) continue;
            if (cap_name[0] == '-') {
                enable = false;
                cap_name = cap_name.substr(1);
            }

            auto it = caps_.find(cap_name);
            if (it == caps_.end() || !it->second.available) {
                if (enable) rejected.push_back(cap_name);
                continue;
            }

            if (enable) {
                it->second.enabled = true;
                accepted.push_back(cap_name);
            } else {
                it->second.enabled = false;
                disabled.push_back(cap_name);
            }
        }

        cap_state_ = CapState::REQ_RECEIVED;

        if (!rejected.empty()) {
            std::string nak = ":server CAP * NAK :";
            for (size_t i = 0; i < rejected.size(); i++) {
                if (i > 0) nak += " ";
                nak += rejected[i];
            }
            cap_state_ = CapState::NAK_SENT;
            return nak;
        }

        std::string ack = ":server CAP * ACK :";
        for (size_t i = 0; i < accepted.size(); i++) {
            if (i > 0) ack += " ";
            ack += accepted[i];
        }
        cap_state_ = CapState::ACK_SENT;
        return ack;
    }

    std::unordered_map<std::string, ServerCapability> caps_;
    CapState cap_state_ = CapState::NONE;
};

// =============================================================================
// SASL authentication (server side)
// =============================================================================
class SaslAuthenticator {
public:
    enum SaslState {
        NONE,
        AUTHENTICATE_SENT,      // AUTHENTICATE command received
        ABORTED,
        SUCCESS,
        FAILURE,
    };

    SaslAuthenticator() {
        register_mechanism("PLAIN");
        register_mechanism("EXTERNAL");
        register_mechanism("SCRAM-SHA-256");
    }

    void register_mechanism(const std::string& name) {
        mechanisms_.push_back(name);
    }

    std::string get_supported_mechanisms() const {
        std::string result;
        for (size_t i = 0; i < mechanisms_.size(); i++) {
            if (i > 0) result += ",";
            result += mechanisms_[i];
        }
        return result;
    }

    // Process AUTHENTICATE payload
    std::string process(const std::string& data, const std::string& remote_addr,
                        std::function<bool(const std::string&,const std::string&)> check_credentials) {
        if (state_ == NONE) {
            return "FAIL";
        }

        // Decode base64 payload
        std::string decoded = base64_decode(data);

        if (mechanism_ == "PLAIN") {
            return process_plain(decoded, check_credentials);
        } else if (mechanism_ == "EXTERNAL") {
            return process_external(decoded);
        }

        return "FAIL";
    }

    // Called when client sends AUTHENTICATE <mechanism>
    std::string start(const std::string& mechanism) {
        mechanism_ = mechanism;

        if (mechanism == "PLAIN") {
            state_ = AUTHENTICATE_SENT;
            return "+"; // RFC 4616: empty challenge for PLAIN
        } else if (mechanism == "EXTERNAL") {
            state_ = AUTHENTICATE_SENT;
            return "+";
        } else if (mechanism.find("SCRAM-SHA-") == 0) {
            state_ = AUTHENTICATE_SENT;
            return "+";
        }

        return "FAIL";
    }

    std::string abort_auth() {
        state_ = ABORTED;
        return "*";
    }

    SaslState state() const { return state_; }
    const std::string& authcid() const { return authcid_; }
    const std::string& authzid() const { return authzid_; }
    const std::string& mechanism() const { return mechanism_; }

private:
    std::string process_plain(const std::string& decoded,
                              std::function<bool(const std::string&,const std::string&)> check_credentials) {
        // Format: [authzid]\0authcid\0password
        size_t nul1 = decoded.find('\0');
        if (nul1 == std::string::npos) return "FAIL";

        authzid_ = decoded.substr(0, nul1);
        size_t nul2 = decoded.find('\0', nul1 + 1);
        if (nul2 == std::string::npos) return "FAIL";

        authcid_ = decoded.substr(nul1 + 1, nul2 - nul1 - 1);
        std::string password = decoded.substr(nul2 + 1);

        if (check_credentials(authcid_, password)) {
            state_ = SUCCESS;
            return "";
        }
        state_ = FAILURE;
        return "FAIL";
    }

    std::string process_external(const std::string& decoded) {
        authzid_ = decoded; // Cert CN
        if (!authzid_.empty()) {
            authcid_ = authzid_;
            state_ = SUCCESS;
            return "";
        }
        state_ = FAILURE;
        return "FAIL";
    }

    std::vector<std::string> mechanisms_;
    SaslState state_ = NONE;
    std::string mechanism_;
    std::string authcid_;
    std::string authzid_;
};

// =============================================================================
// NickServ / Account services
// =============================================================================
struct ServiceAccount {
    std::string name;
    std::string password_hash;     // bcrypt or SHA-256 hash
    std::string email;
    std::string flags;             // "o" = oper, etc.
    time_t registered_at = 0;
    time_t last_seen = 0;
    time_t last_host = "";
    bool suspended = false;
    bool email_verified = false;
    std::unordered_set<std::string> access_list; // hostmasks with access
    std::unordered_set<std::string> cert_fingerprints;
};

class AccountService {
public:
    bool register_account(const std::string& nick, const std::string& password,
                          const std::string& email = "") {
        auto it = accounts_.find(to_lower(nick));
        if (it != accounts_.end()) return false;

        ServiceAccount acc;
        acc.name = nick;
        acc.password_hash = hash_password(password);
        acc.email = email;
        acc.registered_at = std::time(nullptr);
        acc.last_seen = acc.registered_at;

        accounts_[to_lower(nick)] = acc;
        return true;
    }

    bool identify(const std::string& nick, const std::string& password) {
        auto it = accounts_.find(to_lower(nick));
        if (it == accounts_.end()) return false;
        if (it->second.suspended) return false;
        return verify_password(password, it->second.password_hash);
    }

    bool drop_account(const std::string& nick, const std::string& password) {
        auto it = accounts_.find(to_lower(nick));
        if (it == accounts_.end()) return false;
        if (!verify_password(password, it->second.password_hash)) return false;
        accounts_.erase(it);
        return true;
    }

    bool set_password(const std::string& nick, const std::string& old_password,
                      const std::string& new_password) {
        auto it = accounts_.find(to_lower(nick));
        if (it == accounts_.end()) return false;
        if (!verify_password(old_password, it->second.password_hash)) return false;
        it->second.password_hash = hash_password(new_password);
        return true;
    }

    bool add_access(const std::string& nick, const std::string& mask) {
        auto it = accounts_.find(to_lower(nick));
        if (it == accounts_.end()) return false;
        it->second.access_list.insert(mask);
        return true;
    }

    bool check_access(const std::string& nick, const std::string& hostmask) {
        auto it = accounts_.find(to_lower(nick));
        if (it == accounts_.end()) return false;
        for (auto& access : it->second.access_list) {
            if (match_mask(hostmask, access)) return true;
        }
        return false;
    }

    const ServiceAccount* get_account(const std::string& nick) const {
        auto it = accounts_.find(to_lower(nick));
        return (it != accounts_.end()) ? &it->second : nullptr;
    }

    bool is_registered(const std::string& nick) const {
        return accounts_.count(to_lower(nick)) > 0;
    }

    std::string get_account_nick(const std::string& nick) const {
        auto it = accounts_.find(to_lower(nick));
        return (it != accounts_.end()) ? it->second.name : "";
    }

    // Nick expiry (release unused nicks after N days)
    void check_expiry(int expire_days = 90) {
        time_t cutoff = std::time(nullptr) - expire_days * 86400;
        for (auto it = accounts_.begin(); it != accounts_.end(); ) {
            if (it->second.last_seen < cutoff) {
                it = accounts_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Group nicks (multiple nicks point to one account)
    bool group(const std::string& nick, const std::string& target,
               const std::string& password) {
        if (!identify(target, password)) return false;
        nick_groups_[to_lower(nick)] = to_lower(target);
        return true;
    }

    std::string get_main_nick(const std::string& nick) const {
        auto it = nick_groups_.find(to_lower(nick));
        return (it != nick_groups_.end()) ? it->second : to_lower(nick);
    }

private:
    std::unordered_map<std::string, ServiceAccount> accounts_;
    std::unordered_map<std::string, std::string> nick_groups_; // alias -> main

    static std::string hash_password(const std::string& pass) {
        // In real implementation: bcrypt with random salt
        // Mock implementation:
        std::string salted = pass + "static_salt"; // Replace with real bcrypt
        return salted;
    }

    static bool verify_password(const std::string& pass, const std::string& hash) {
        return hash == hash_password(pass);
    }

    static std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }

    bool match_mask(const std::string& host, const std::string& mask) {
        // Simple wildcard mask matching
        return match_wildcard(host, mask);
    }

    bool match_wildcard(const std::string& s, const std::string& p) {
        size_t si = 0, pi = 0, star_si = 0, star_pi = std::string::npos;
        while (si < s.size()) {
            if (pi < p.size() && (p[pi] == '?' || tolower(p[pi]) == tolower(s[si]))) {
                si++; pi++;
            } else if (pi < p.size() && p[pi] == '*') {
                star_pi = pi++;
                star_si = si;
            } else if (star_pi != std::string::npos) {
                pi = star_pi + 1;
                si = ++star_si;
            } else return false;
        }
        while (pi < p.size() && p[pi] == '*') pi++;
        return pi == p.size();
    }

    static char tolower(char c) { return std::tolower((unsigned char)c); }
};

// =============================================================================
// ChanServ
// =============================================================================
struct ChannelRegistration {
    std::string name;
    std::string founder;
    std::unordered_set<std::string> successors;
    time_t registered_at = 0;
    time_t last_used = 0;
    std::string topic;
    std::string entry_msg;
    std::unordered_map<std::string, std::string> settings; // key-value
    bool no_expire = false;
    bool secure_ops = false;
    bool verbose = false;
    bool keep_topic = false;
    bool secure = false;
};

class ChanServ {
public:
    bool register_channel(const std::string& channel, const std::string& founder,
                          const std::string& description = "") {
        auto key = to_lower(channel);
        if (registrations_.count(key)) return false;

        ChannelRegistration reg;
        reg.name = channel;
        reg.founder = founder;
        reg.registered_at = std::time(nullptr);
        reg.last_used = reg.registered_at;

        registrations_[key] = reg;
        return true;
    }

    bool drop_channel(const std::string& channel, const std::string& requester) {
        auto it = registrations_.find(to_lower(channel));
        if (it == registrations_.end()) return false;
        if (it->second.founder != requester) return false;
        registrations_.erase(it);
        return true;
    }

    const ChannelRegistration* get_channel(const std::string& channel) const {
        auto it = registrations_.find(to_lower(channel));
        return (it != registrations_.end()) ? &it->second : nullptr;
    }

    bool is_registered(const std::string& channel) const {
        return registrations_.count(to_lower(channel)) > 0;
    }

    bool is_founder(const std::string& channel, const std::string& nick) const {
        auto it = registrations_.find(to_lower(channel));
        return it != registrations_.end() && it->second.founder == nick;
    }

    bool add_successor(const std::string& channel, const std::string& nick) {
        auto it = registrations_.find(to_lower(channel));
        if (it == registrations_.end()) return false;
        it->second.successors.insert(nick);
        return true;
    }

    void set_access(const std::string& channel, const std::string& mask,
                    const std::string& level) {
        channel_access_[to_lower(channel)][mask] = level;
    }

    std::string get_access(const std::string& channel, const std::string& mask) const {
        auto it = channel_access_.find(to_lower(channel));
        if (it == channel_access_.end()) return "";
        auto mit = it->second.find(mask);
        return (mit != it->second.end()) ? mit->second : "";
    }

private:
    std::unordered_map<std::string, ChannelRegistration> registrations_;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> channel_access_;

    static std::string to_lower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        return s;
    }
};

// =============================================================================
// DNSBL checker
// =============================================================================
struct DnsblProvider {
    std::string name;
    std::string domain;       // dnsbl.dronebl.org
    std::string lookup_reply; // "127.0.0.*"
    std::string reason;
    int ban_time = 3600;      // seconds
};

class DnsblChecker {
public:
    void add_provider(const DnsblProvider& provider) {
        providers_.push_back(provider);
    }

    struct DnsblResult {
        bool listed = false;
        std::string provider;
        std::string reason;
    };

    DnsblResult check(const std::string& ip_addr) {
        // Reverse IP and query DNSBL
        std::string reversed = reverse_ip(ip_addr);

        for (auto& provider : providers_) {
            std::string query = reversed + "." + provider.domain;
            struct addrinfo hints{}, *result = nullptr;
            hints.ai_family = AF_INET;
            hints.ai_socktype = SOCK_STREAM;

            int ret = getaddrinfo(query.c_str(), nullptr, &hints, &result);
            if (ret == 0 && result) {
                char buf[INET_ADDRSTRLEN];
                auto* ipv4 = (struct sockaddr_in*)result->ai_addr;
                inet_ntop(AF_INET, &ipv4->sin_addr, buf, sizeof(buf));
                freeaddrinfo(result);

                std::string reply(buf);
                if (reply.find("127.0.0.") == 0) {
                    return {true, provider.name, provider.reason};
                }
            }
        }

        return {false, "", ""};
    }

private:
    std::vector<DnsblProvider> providers_;

    static std::string reverse_ip(const std::string& ip) {
        // 1.2.3.4 -> 4.3.2.1
        std::string result;
        std::vector<std::string> parts = split_str(ip, '.');
        for (int i = (int)parts.size() - 1; i >= 0; i--) {
            if (!result.empty()) result += ".";
            result += parts[i];
        }
        return result;
    }

    static std::vector<std::string> split_str(const std::string& s, char delim) {
        std::vector<std::string> result;
        size_t start = 0;
        for (size_t i = 0; i <= s.size(); i++) {
            if (i == s.size() || s[i] == delim) {
                if (i > start) result.push_back(s.substr(start, i - start));
                start = i + 1;
            }
        }
        return result;
    }
};

// =============================================================================
// WebIRC gateway support
// =============================================================================
struct WebIrcConfig {
    bool enabled = false;
    std::string password;
    std::vector<std::string> allowed_hosts; // IPs of trusted webirc gateways
    bool override_hostname = true;
    bool override_ident = true;
};

class WebIrcHandler {
public:
    void configure(const WebIrcConfig& cfg) { config_ = cfg; }

    struct WebIrcData {
        std::string password;
        std::string gateway;
        std::string hostname;
        std::string ip;
    };

    std::optional<WebIrcData> parse_webirc(const std::string& line) {
        // WEBIRC password gateway hostname ip
        auto parts = split_str(line, ' ');
        if (parts.size() < 4 || parts[0] != "WEBIRC") return std::nullopt;
        if (parts[1] != config_.password) return std::nullopt;

        WebIrcData data;
        data.password = parts[1];
        data.gateway = parts[2];
        data.hostname = parts[3];
        data.ip = (parts.size() > 4) ? parts[4] : parts[3];

        // Verify gateway IP
        if (!is_allowed_gateway(data.gateway)) return std::nullopt;

        return data;
    }

private:
    WebIrcConfig config_;

    bool is_allowed_gateway(const std::string& ip) {
        for (auto& allowed : config_.allowed_hosts) {
            if (ip == allowed) return true;
        }
        return false;
    }

    static std::vector<std::string> split_str(const std::string& s, char delim) {
        std::vector<std::string> result;
        size_t start = 0;
        for (size_t i = 0; i <= s.size(); i++) {
            if (i == s.size() || s[i] == delim) {
                if (i > start) result.push_back(s.substr(start, i - start));
                start = i + 1;
            }
        }
        return result;
    }
};

// =============================================================================
// Unix domain socket listener
// =============================================================================
class UnixSocketListener {
public:
    bool listen(const std::string& path) {
        fd_ = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd_ < 0) return false;

        struct sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);

        unlink(path.c_str()); // Remove stale socket

        if (bind(fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd_);
            fd_ = -1;
            return false;
        }

        if (::listen(fd_, 5) < 0) {
            close(fd_);
            fd_ = -1;
            return false;
        }

        path_ = path;
        return true;
    }

    int accept() {
        return ::accept(fd_, nullptr, nullptr);
    }

    void close() {
        if (fd_ >= 0) {
            ::close(fd_);
            unlink(path_.c_str());
            fd_ = -1;
        }
    }

    int fd() const { return fd_; }

private:
    int fd_ = -1;
    std::string path_;
};

// =============================================================================
// Connection class system
// =============================================================================
struct ConnClass {
    std::string name;
    int max_per_ip = 5;
    int max_total = 0;           // 0 = unlimited
    int sendq_max = 262144;      // 256KB
    int recvq_max = 8192;
    int ping_freq = 120;
    int ping_warn = 15;
    int max_channels = 25;
    int max_away_length = 360;
    int max_kick_length = 512;
    int max_topic_length = 390;
    bool can_oper = false;
    int connect_freq = 0;        // minimum seconds between connects
};

class ConnClassManager {
public:
    void add_class(const ConnClass& cls) {
        classes_[cls.name] = cls;
    }

    const ConnClass* get_class(const std::string& name) const {
        auto it = classes_.find(name);
        return (it != classes_.end()) ? &it->second : &default_class_;
    }

    const ConnClass* default_class() const { return &default_class_; }

private:
    std::unordered_map<std::string, ConnClass> classes_;
    ConnClass default_class_;
};

} // namespace irc
} // namespace progressive
