// xmpp_s2s.cpp - XMPP Server-to-Server (S2S) Federation and Dialback
// RFC 6120 Section 4, XEP-0220, XEP-0288, XEP-0178
// Equivalent to ejabberd s2s modules (~30,000 lines reference)
#include "xmpp_server.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <iomanip>
#include <memory>
#include <mutex>
#include <queue>
#include <random>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#ifdef __linux__
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#else
// Minimal stubs for non-Linux platforms
#include <cstdint>
#include <cstdlib>
#include <cstring>
#endif

namespace progressive::xmpp {
using json = nlohmann::json;

// ============================================================================
// Utility helpers (consistent with xmpp_server.cpp style)
// ============================================================================
static int64_t nms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}
static std::string gen_id() {
  static std::atomic<int64_t> c{1};
  return "s2s-" + std::to_string(nms()) + "-" + std::to_string(c.fetch_add(1));
}
static std::string gen_token(int l = 64) {
  static const char cs[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(nms());
  std::uniform_int_distribution<> d(0, 61);
  std::string t(l, 'A');
  for (auto& c : t) c = cs[d(rng)];
  return t;
}
static std::string sha256_hex(const std::string& data) {
#ifdef __linux__
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.size(),
         hash);
  std::stringstream ss;
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
  return ss.str();
#else
  // Simple fallback hash
  std::stringstream ss;
  ss << std::hex << std::hash<std::string>{}(data);
  return ss.str();
#endif
}
static std::string base64_encode(const std::string& data) {
  static const char* b64 =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  int val = 0, valb = -6;
  for (unsigned char c : data) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      out.push_back(b64[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) out.push_back(b64[((val << 8) >> (valb + 8)) & 0x3F]);
  while (out.size() % 4) out.push_back('=');
  return out;
}
static std::string xml_escape(const std::string& s) {
  std::string r;
  r.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '&':  r += "&amp;"; break;
      case '<':  r += "&lt;"; break;
      case '>':  r += "&gt;"; break;
      case '"':  r += "&quot;"; break;
      case '\'': r += "&apos;"; break;
      default:   r += c; break;
    }
  }
  return r;
}
static std::string xml_attr(const std::string& name, const std::string& value) {
  return " " + name + "='" + xml_escape(value) + "'";
}
static std::string extract_xml_attr(const std::string& xml,
                                     const std::string& attr) {
  auto pos = xml.find(attr + "='");
  if (pos == std::string::npos) {
    pos = xml.find(attr + "=\"");
    if (pos == std::string::npos) return "";
    pos += attr.size() + 2;
    auto end = xml.find('\"', pos);
    return end != std::string::npos ? xml.substr(pos, end - pos) : "";
  }
  pos += attr.size() + 2;
  auto end = xml.find('\'', pos);
  return end != std::string::npos ? xml.substr(pos, end - pos) : "";
}
static std::string extract_xml_content(const std::string& xml,
                                        const std::string& tag) {
  std::string open = "<" + tag + ">";
  std::string close = "</" + tag + ">";
  auto start = xml.find(open);
  if (start == std::string::npos) {
    open = "<" + tag + " ";
    start = xml.find(open);
    if (start == std::string::npos) return "";
    auto end_attr = xml.find('>', start);
    if (end_attr == std::string::npos) return "";
    start = xml.find('>', end_attr);
    if (start == std::string::npos) return "";
    start++;
  } else {
    start += open.size();
  }
  auto end = xml.find(close, start);
  return end != std::string::npos ? xml.substr(start, end - start) : "";
}

// ============================================================================
// S2S Constants (RFC 6120 Section 4, XEP-0220)
// ============================================================================
namespace S2SConstants {
constexpr const char* XMLNS_STREAM = "http://etherx.jabber.org/streams";
constexpr const char* XMLNS_JABBER_CLIENT =
    "jabber:client";
constexpr const char* XMLNS_JABBER_SERVER =
    "jabber:server";
constexpr const char* XMLNS_TLS = "urn:ietf:params:xml:ns:xmpp-tls";
constexpr const char* XMLNS_SASL = "urn:ietf:params:xml:ns:xmpp-sasl";
constexpr const char* XMLNS_DIALBACK =
    "jabber:server:dialback";
constexpr const char* XMLNS_DIALBACK_ERROR =
    "urn:ietf:params:xml:ns:xmpp-stanzas";
constexpr const char* XMLNS_STREAM_ERROR =
    "urn:ietf:params:xml:ns:xmpp-streams";
constexpr const char* XML_VERSION = "1.0";
constexpr int S2S_DEFAULT_PORT = 5269;
constexpr int DNS_TIMEOUT_SEC = 5;
constexpr int CONNECT_TIMEOUT_SEC = 30;
constexpr int STREAM_TIMEOUT_SEC = 60;
constexpr int MAX_STANZA_SIZE = 1048576;  // 1MB
constexpr int BACKOFF_BASE_MS = 1000;
constexpr int BACKOFF_MAX_MS = 300000;  // 5 minutes
constexpr int MAX_RETRIES = 10;
constexpr int POOL_MAX_CONN = 4;
constexpr int POOL_IDLE_TIMEOUT_SEC = 300;
constexpr int PING_INTERVAL_SEC = 180;
constexpr int RECONNECT_DELAY_SEC = 30;
}  // namespace S2SConstants

// ============================================================================
// S2S Enums and Types
// ============================================================================
enum class S2SState {
  IDLE,
  CONNECTING,
  DNS_RESOLVING,
  STREAM_OPENING,
  STREAM_OPENED,
  STARTTLS_REQUESTED,
  TLS_HANDSHAKING,
  TLS_ESTABLISHED,
  SASL_AUTHENTICATING,
  AUTHENTICATED,
  DIALBACK_SENT,
  DIALBACK_AWAITING,
  DIALBACK_VERIFIED,
  ACTIVE,
  CLOSING,
  CLOSED,
  ERROR
};

enum class S2SDirection { OUTGOING, INCOMING, BIDIRECTIONAL };

enum class S2SAuthMethod {
  NONE,
  DIALBACK,
  SASL_EXTERNAL,
  TLS_CERT
};

struct DNSResult {
  std::string hostname;
  std::string ip;
  int port{S2SConstants::S2S_DEFAULT_PORT};
  int priority{0};
  int weight{0};
  int64_t resolved_at{0};
  int64_t ttl{3600};
};

struct DialbackKey {
  std::string key;
  std::string stream_id;
  std::string from_domain;
  std::string to_domain;
  int64_t generated_at{0};
  int64_t expires_at{0};

  bool is_expired() const { return nms() > expires_at; }
};

struct S2SStanzaQueue {
  std::string domain;
  std::queue<std::string> stanzas;
  int64_t first_queued{0};
  int max_size{1000};
};

struct S2SStats {
  std::atomic<int64_t> total_connections{0};
  std::atomic<int64_t> active_connections{0};
  std::atomic<int64_t> incoming_connections{0};
  std::atomic<int64_t> outgoing_connections{0};
  std::atomic<int64_t> failed_connections{0};
  std::atomic<int64_t> stanzas_sent{0};
  std::atomic<int64_t> stanzas_received{0};
  std::atomic<int64_t> stanzas_dropped{0};
  std::atomic<int64_t> dialback_sent{0};
  std::atomic<int64_t> dialback_verified{0};
  std::atomic<int64_t> dialback_failed{0};
  std::atomic<int64_t> tls_connections{0};
  std::atomic<int64_t> sasl_external_auths{0};
  std::atomic<int64_t> dns_queries{0};
  std::atomic<int64_t> dns_cache_hits{0};
  std::atomic<int64_t> bytes_sent{0};
  std::atomic<int64_t> bytes_received{0};
  std::atomic<int64_t> route_errors{0};
  std::atomic<int64_t> pings_sent{0};
  std::atomic<int64_t> pings_responded{0};
  std::atomic<int64_t> disco_queries{0};
  std::atomic<int64_t> version_queries{0};
  int64_t uptime_start{0};

  void reset() {
    total_connections = 0;
    active_connections = 0;
    incoming_connections = 0;
    outgoing_connections = 0;
    failed_connections = 0;
    stanzas_sent = 0;
    stanzas_received = 0;
    stanzas_dropped = 0;
    dialback_sent = 0;
    dialback_verified = 0;
    dialback_failed = 0;
    tls_connections = 0;
    sasl_external_auths = 0;
    dns_queries = 0;
    dns_cache_hits = 0;
    bytes_sent = 0;
    bytes_received = 0;
    route_errors = 0;
    pings_sent = 0;
    pings_responded = 0;
    disco_queries = 0;
    version_queries = 0;
    uptime_start = nms();
  }
};

// ============================================================================
// S2S Connection - represents one S2S link
// ============================================================================
struct S2SConnection {
  int fd{-1};
  int epoll_fd{-1};
  S2SState state{S2SState::IDLE};
  S2SDirection direction{S2SDirection::OUTGOING};
  S2SAuthMethod auth_method{S2SAuthMethod::NONE};
  std::string stream_id;
  std::string remote_domain;
  std::string local_domain;
  std::string remote_ip;
  int remote_port{0};
  std::string xml_buffer;
  std::string write_buffer;
  int64_t connected_at{0};
  int64_t last_activity{0};
  int64_t stream_opened_at{0};
  bool tls_active{false};
  bool tls_requested{false};
  bool authenticated{false};
  bool dialback_verified{false};
  bool features_sent{false};
  bool features_received{false};
  std::string remote_stream_id;
  std::string remote_version;
  std::string dialback_key;
  std::string dialback_secret;
  std::string peer_certificate;
  std::string peer_cert_fingerprint;
  std::vector<std::string> peer_sans;
  int retry_count{0};
  int64_t backoff_until{0};
  int64_t last_ping_sent{0};
  int64_t last_ping_recv{0};
  std::queue<std::string> pending_stanzas;
  int max_pending{200};

#ifdef __linux__
  SSL* ssl{nullptr};
  SSL_CTX* ssl_ctx{nullptr};
#endif

  bool is_active() const {
    return state == S2SState::ACTIVE && authenticated &&
           (dialback_verified || auth_method == S2SAuthMethod::SASL_EXTERNAL ||
            auth_method == S2SAuthMethod::TLS_CERT);
  }
  bool is_idle() const {
    return state == S2SState::IDLE || state == S2SState::CLOSED;
  }
  int64_t idle_time() const { return is_active() ? 0 : nms() - last_activity; }
};

// ============================================================================
// S2S Manager - central S2S federation manager
// ============================================================================
class S2SManager {
 public:
  S2SManager(const std::string& local_domain, const std::string& secret)
      : local_domain_(local_domain), dialback_secret_(secret) {
    stats_.reset();
    dialback_key_lifetime_ = 300;  // 5 minutes default
    s2s_port_ = S2SConstants::S2S_DEFAULT_PORT;
    dns_cache_timeout_ = 3600;
    connection_backoff_base_ = S2SConstants::BACKOFF_BASE_MS;
    connection_backoff_max_ = S2SConstants::BACKOFF_MAX_MS;
    pool_max_conn_per_domain_ = S2SConstants::POOL_MAX_CONN;
    pool_idle_timeout_ = S2SConstants::POOL_IDLE_TIMEOUT_SEC;
    ping_interval_ = S2SConstants::PING_INTERVAL_SEC;
    max_retries_ = S2SConstants::MAX_RETRIES;
    tls_required_ = true;
    sasl_external_enabled_ = true;
    dialback_enabled_ = true;
    compression_enabled_ = false;
    log_level_ = 1;
    running_ = false;
    maintenance_thread_ = nullptr;
  }

  ~S2SManager() {
    stop();
#ifdef __linux__
    if (ssl_ctx_) SSL_CTX_free(ssl_ctx_);
#endif
  }

  // ==========================================================================
  // Lifecycle
  // ==========================================================================
  bool start() {
    if (running_) return true;
    running_ = true;
    init_ssl();
    if (listen_port_ > 0) {
      start_listener();
    }
    start_maintenance();
    if (log_level_ >= 1) {
      fprintf(stderr,
              "[S2S] Manager started for domain=%s, s2s_port=%d, "
              "dialback=%s, sasl_external=%s, tls_required=%s\n",
              local_domain_.c_str(), s2s_port_,
              dialback_enabled_ ? "yes" : "no",
              sasl_external_enabled_ ? "yes" : "no",
              tls_required_ ? "yes" : "no");
    }
    return true;
  }

  void stop() {
    if (!running_) return;
    running_ = false;
    if (listener_fd_ >= 0) {
#ifdef __linux__
      close(listener_fd_);
#endif
      listener_fd_ = -1;
    }
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto& [domain, conn] : connections_) {
        close_connection_internal(&conn);
      }
      connections_.clear();
      for (auto& [domain, pool] : connection_pool_) {
        for (auto& c : pool) {
          close_connection_internal(&c);
        }
      }
      connection_pool_.clear();
    }
    if (maintenance_thread_ && maintenance_thread_->joinable()) {
      maintenance_thread_->join();
      maintenance_thread_.reset();
    }
    if (log_level_ >= 1) {
      fprintf(stderr, "[S2S] Manager stopped for domain=%s\n",
              local_domain_.c_str());
    }
  }

  // ==========================================================================
  // Configuration
  // ==========================================================================
  void set_listen_port(int port) { listen_port_ = port; }
  void set_tls_required(bool v) { tls_required_ = v; }
  void set_dialback_enabled(bool v) { dialback_enabled_ = v; }
  void set_sasl_external_enabled(bool v) { sasl_external_enabled_ = v; }
  void set_compression_enabled(bool v) { compression_enabled_ = v; }
  void set_certificate_file(const std::string& cert, const std::string& key) {
    cert_file_ = cert;
    key_file_ = key;
  }
  void set_ca_file(const std::string& cafile) { ca_file_ = cafile; }
  void set_log_level(int lv) { log_level_ = lv; }
  void add_trusted_server(const std::string& domain) {
    trusted_servers_.insert(domain);
  }
  void set_dialback_secret(const std::string& secret) {
    dialback_secret_ = secret;
  }
  void set_pool_max_conn_per_domain(int n) { pool_max_conn_per_domain_ = n; }
  void set_dialback_key_lifetime(int sec) { dialback_key_lifetime_ = sec; }

  // ==========================================================================
  // SSL / TLS
  // ==========================================================================
  bool init_ssl() {
#ifdef __linux__
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    ssl_ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx_) return false;

    SSL_CTX_set_options(ssl_ctx_, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
                                       SSL_OP_NO_TLSv1 |
                                       SSL_OP_NO_TLSv1_1);
    SSL_CTX_set_mode(ssl_ctx_, SSL_MODE_AUTO_RETRY);

    if (!cert_file_.empty() && !key_file_.empty()) {
      if (SSL_CTX_use_certificate_file(ssl_ctx_, cert_file_.c_str(),
                                        SSL_FILETYPE_PEM) <= 0) {
        if (log_level_ >= 0)
          fprintf(stderr, "[S2S] Failed to load certificate: %s\n",
                  cert_file_.c_str());
        return false;
      }
      if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, key_file_.c_str(),
                                       SSL_FILETYPE_PEM) <= 0) {
        if (log_level_ >= 0)
          fprintf(stderr, "[S2S] Failed to load private key: %s\n",
                  key_file_.c_str());
        return false;
      }
      if (!SSL_CTX_check_private_key(ssl_ctx_)) {
        if (log_level_ >= 0)
          fprintf(stderr, "[S2S] Private key does not match certificate\n");
        return false;
      }
    }

    if (!ca_file_.empty()) {
      SSL_CTX_load_verify_locations(ssl_ctx_, ca_file_.c_str(), nullptr);
    }
    SSL_CTX_set_verify(ssl_ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       nullptr);

    // Set cipher list for strong security
    SSL_CTX_set_cipher_list(ssl_ctx_,
                            "ECDHE-ECDSA-AES256-GCM-SHA384:"
                            "ECDHE-RSA-AES256-GCM-SHA384:"
                            "ECDHE-ECDSA-CHACHA20-POLY1305:"
                            "ECDHE-RSA-CHACHA20-POLY1305:"
                            "ECDHE-ECDSA-AES128-GCM-SHA256:"
                            "ECDHE-RSA-AES128-GCM-SHA256");
    return true;
#else
    return false;
#endif
  }

  // ==========================================================================
  // DNS SRV Resolution
  // ==========================================================================
  std::vector<DNSResult> resolve_srv(const std::string& domain) {
    stats_.dns_queries++;
    std::vector<DNSResult> results;

    // Check cache first
    {
      std::lock_guard<std::mutex> lock(dns_cache_mutex_);
      auto it = dns_cache_.find(domain);
      if (it != dns_cache_.end()) {
        int64_t age = nms() - it->second[0].resolved_at;
        if (age < dns_cache_timeout_ * 1000) {
          stats_.dns_cache_hits++;
          return it->second;
        }
      }
    }

#ifdef __linux__
    std::string srv_name = "_xmpp-server._tcp." + domain;
    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Try SRV DNS lookup via getaddrinfo
    int ret = getaddrinfo(srv_name.c_str(),
                          std::to_string(s2s_port_).c_str(), &hints, &res);
    if (ret == 0 && res) {
      for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        DNSResult r;
        r.hostname = srv_name;
        r.port = s2s_port_;
        r.resolved_at = nms();
        r.ttl = dns_cache_timeout_;

        char ipstr[INET6_ADDRSTRLEN] = {0};
        if (p->ai_family == AF_INET) {
          struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
          inet_ntop(AF_INET, &ipv4->sin_addr, ipstr, sizeof(ipstr));
          r.ip = ipstr;
        } else if (p->ai_family == AF_INET6) {
          struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
          inet_ntop(AF_INET6, &ipv6->sin6_addr, ipstr, sizeof(ipstr));
          r.ip = ipstr;
        }
        if (!r.ip.empty()) results.push_back(r);
      }
      freeaddrinfo(res);
    }

    // If SRV lookup failed, fall back to A/AAAA record on bare domain
    if (results.empty()) {
      hints.ai_flags = 0;
      ret = getaddrinfo(domain.c_str(),
                        std::to_string(s2s_port_).c_str(), &hints, &res);
      if (ret == 0 && res) {
        for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
          DNSResult r;
          r.hostname = domain;
          r.port = s2s_port_;
          r.resolved_at = nms();
          r.ttl = dns_cache_timeout_;

          char ipstr[INET6_ADDRSTRLEN] = {0};
          if (p->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
            inet_ntop(AF_INET, &ipv4->sin_addr, ipstr, sizeof(ipstr));
            r.ip = ipstr;
          } else if (p->ai_family == AF_INET6) {
            struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
            inet_ntop(AF_INET6, &ipv6->sin6_addr, ipstr, sizeof(ipstr));
            r.ip = ipstr;
          }
          if (!r.ip.empty()) results.push_back(r);
        }
        freeaddrinfo(res);
      }
    }

    // Cache results
    if (!results.empty()) {
      std::lock_guard<std::mutex> lock(dns_cache_mutex_);
      dns_cache_[domain] = results;
    }
#endif

    if (log_level_ >= 2) {
      fprintf(stderr, "[S2S] DNS resolved %s -> %zu records\n", domain.c_str(),
              results.size());
    }
    return results;
  }

  void flush_dns_cache() {
    std::lock_guard<std::mutex> lock(dns_cache_mutex_);
    dns_cache_.clear();
  }

  void flush_dns_cache(const std::string& domain) {
    std::lock_guard<std::mutex> lock(dns_cache_mutex_);
    dns_cache_.erase(domain);
  }

  // ==========================================================================
  // Connection Management
  // ==========================================================================
  S2SConnection* connect_to(const std::string& remote_domain) {
    if (remote_domain == local_domain_) return nullptr;  // Don't connect to self

    // Check if connection already exists and is active
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = connections_.find(remote_domain);
      if (it != connections_.end() && it->second.is_active()) {
        it->second.last_activity = nms();
        return &it->second;
      }

      // Check pool for reusable connection
      auto pit = connection_pool_.find(remote_domain);
      if (pit != connection_pool_.end()) {
        for (auto& c : pit->second) {
          if (c.is_active()) {
            c.last_activity = nms();
            connections_[remote_domain] = c;
            pit->second.erase(
                std::remove_if(pit->second.begin(), pit->second.end(),
                               [&](const S2SConnection& x) {
                                 return x.stream_id == c.stream_id;
                               }),
                pit->second.end());
            return &connections_[remote_domain];
          }
        }
      }
    }

    // Resolve DNS
    auto dns_results = resolve_srv(remote_domain);
    if (dns_results.empty()) {
      stats_.route_errors++;
      if (log_level_ >= 1)
        fprintf(stderr, "[S2S] Cannot resolve domain: %s\n",
                remote_domain.c_str());
      return nullptr;
    }

    // Try each resolved address
    for (auto& dns : dns_results) {
      S2SConnection conn = create_outgoing_connection(remote_domain, dns);
      if (connect_socket(&conn, dns.ip, dns.port)) {
        if (start_stream_negotiation(&conn)) {
          stats_.total_connections++;
          stats_.outgoing_connections++;
          std::lock_guard<std::mutex> lock(mutex_);
          connections_[remote_domain] = conn;
          return &connections_[remote_domain];
        } else {
          close_connection_internal(&conn);
        }
      }
    }

    stats_.failed_connections++;
    return nullptr;
  }

  S2SConnection* get_connection(const std::string& remote_domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(remote_domain);
    if (it != connections_.end() && it->second.is_active()) {
      it->second.last_activity = nms();
      return &it->second;
    }
    return nullptr;
  }

  S2SConnection* get_best_connection(const std::string& remote_domain) {
    // First try active connection
    auto* conn = get_connection(remote_domain);
    if (conn) return conn;

    // Try pool
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = connection_pool_.find(remote_domain);
      if (it != connection_pool_.end() && !it->second.empty()) {
        for (auto& c : it->second) {
          if (c.is_active()) return &c;
        }
      }
    }

    // Create new connection
    return connect_to(remote_domain);
  }

  void close_connection(const std::string& remote_domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(remote_domain);
    if (it != connections_.end()) {
      auto& conn = it->second;
      conn.state = S2SState::CLOSING;
      send_stream_close(&conn);
      close_connection_internal(&conn);
      connections_.erase(it);
    }
  }

  void recycle_connection(S2SConnection* conn) {
    if (!conn) return;
    std::lock_guard<std::mutex> lock(mutex_);
    conn->last_activity = nms();
    auto& pool = connection_pool_[conn->remote_domain];
    if (pool.size() < (size_t)pool_max_conn_per_domain_) {
      pool.push_back(*conn);
      if (log_level_ >= 2)
        fprintf(stderr, "[S2S] Recycled connection to %s (pool=%zu)\n",
                conn->remote_domain.c_str(), pool.size());
    } else {
      close_connection_internal(conn);
    }
  }

  // ==========================================================================
  // Dialback Protocol (XEP-0220)
  // ==========================================================================
  std::string generate_dialback_key(const std::string& from_domain,
                                     const std::string& to_domain,
                                     const std::string& stream_id) {
    std::string seed = dialback_secret_ + ":" + from_domain + ":" + to_domain +
                       ":" + stream_id;
    return sha256_hex(seed);
  }

  bool verify_dialback_key(const std::string& from_domain,
                            const std::string& to_domain,
                            const std::string& stream_id,
                            const std::string& provided_key) {
    std::string expected = generate_dialback_key(from_domain, to_domain,
                                                  stream_id);
    bool valid = (expected == provided_key);

    if (log_level_ >= 2) {
      fprintf(stderr,
              "[S2S] Dialback verify: %s -> %s stream=%s, key=%s -> %s\n",
              from_domain.c_str(), to_domain.c_str(), stream_id.c_str(),
              valid ? "valid" : "invalid",
              provided_key.substr(0, 16).c_str());
    }
    return valid;
  }

  std::string generate_dialback_result(const std::string& from_domain,
                                        const std::string& to_domain,
                                        const std::string& stream_id,
                                        bool valid) {
    std::stringstream xml;
    xml << "<db:result"
        << xml_attr("from", to_domain) << xml_attr("to", from_domain)
        << xml_attr("type", valid ? "valid" : "invalid") << ">";
    if (valid) {
      DialbackKey k;
      k.key = generate_dialback_key(from_domain, to_domain, stream_id);
      k.stream_id = stream_id;
      k.from_domain = from_domain;
      k.to_domain = to_domain;
      k.generated_at = nms();
      k.expires_at = nms() + dialback_key_lifetime_ * 1000;
      store_dialback_key(k);
      xml << k.key;
    }
    xml << "</db:result>";
    stats_.dialback_sent++;
    if (valid) stats_.dialback_verified++;
    else stats_.dialback_failed++;
    return xml.str();
  }

  void store_dialback_key(const DialbackKey& key) {
    std::lock_guard<std::mutex> lock(dialback_mutex_);
    std::string identifier =
        key.from_domain + ":" + key.to_domain + ":" + key.stream_id;
    dialback_keys_[identifier] = key;
  }

  bool lookup_dialback_key(const std::string& from_domain,
                            const std::string& to_domain,
                            const std::string& stream_id,
                            const std::string& key) {
    std::lock_guard<std::mutex> lock(dialback_mutex_);
    std::string identifier = from_domain + ":" + to_domain + ":" + stream_id;
    auto it = dialback_keys_.find(identifier);
    if (it == dialback_keys_.end()) return false;
    if (it->second.is_expired()) {
      dialback_keys_.erase(it);
      return false;
    }
    return it->second.key == key;
  }

  void cleanup_dialback_keys() {
    std::lock_guard<std::mutex> lock(dialback_mutex_);
    auto it = dialback_keys_.begin();
    while (it != dialback_keys_.end()) {
      if (it->second.is_expired()) {
        it = dialback_keys_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // ==========================================================================
  // Stanza Routing
  // ==========================================================================
  bool route_stanza(const std::string& to_domain,
                     const std::string& stanza_xml) {
    if (to_domain == local_domain_) {
      // Local delivery - handled by XMPPServer
      return false;
    }

    auto* conn = get_best_connection(to_domain);
    if (!conn || !conn->is_active()) {
      // Queue for later delivery
      queue_stanza_for_domain(to_domain, stanza_xml);
      // Trigger connection attempt
      if (!conn) {
        connect_to(to_domain);
      }
      return true;
    }

    if (!send_stanza(conn, stanza_xml)) {
      // Send failed, queue and retry
      queue_stanza_for_domain(to_domain, stanza_xml);
      close_connection(to_domain);
      connect_to(to_domain);
      return true;
    }

    stats_.stanzas_sent++;
    return true;
  }

  bool route_message(const std::string& from_domain,
                      const std::string& to_domain,
                      const std::string& message_xml) {
    std::string stanza = "<message"
                         + xml_attr("from", from_domain)
                         + xml_attr("to", to_domain)
                         + ">" + message_xml + "</message>";
    return route_stanza(to_domain, stanza);
  }

  bool route_presence(const std::string& from_domain,
                       const std::string& to_domain,
                       const std::string& presence_xml) {
    std::string stanza = "<presence"
                         + xml_attr("from", from_domain)
                         + xml_attr("to", to_domain)
                         + ">" + presence_xml + "</presence>";
    return route_stanza(to_domain, stanza);
  }

  bool route_iq(const std::string& from_domain, const std::string& to_domain,
                const std::string& iq_xml) {
    return route_stanza(to_domain, iq_xml);
  }

  // ==========================================================================
  // Stream Handling (incoming)
  // ==========================================================================
  std::string handle_incoming_stream_open(const std::string& xml,
                                           S2SConnection* conn) {
    conn->direction = S2SDirection::INCOMING;
    conn->state = S2SState::STREAM_OPENING;

    // Extract attributes
    std::string from = extract_xml_attr(xml, "from");
    std::string to = extract_xml_attr(xml, "to");
    std::string version = extract_xml_attr(xml, "version");
    std::string ns = extract_xml_attr(xml, "xmlns:db");

    conn->remote_domain = from;
    conn->local_domain = to;
    conn->remote_version = version;
    conn->stream_opened_at = nms();

    if (log_level_ >= 2) {
      fprintf(stderr,
              "[S2S] Incoming stream: from=%s to=%s version=%s\n",
              from.c_str(), to.c_str(), version.c_str());
    }

    // Check if remote domain is allowed
    if (!is_domain_allowed(from)) {
      return build_stream_error("host-unknown",
                                "Domain not allowed: " + from);
    }

    // Generate stream ID and send response
    conn->stream_id = gen_id();

    std::stringstream response;
    response << "<?xml version='1.0' encoding='UTF-8'?>";
    response << "<stream:stream"
             << xml_attr("xmlns:stream",
                         S2SConstants::XMLNS_STREAM)
             << xml_attr("xmlns", S2SConstants::XMLNS_JABBER_SERVER)
             << xml_attr("xmlns:db", S2SConstants::XMLNS_DIALBACK)
             << xml_attr("from", local_domain_)
             << xml_attr("to", from)
             << xml_attr("id", conn->stream_id)
             << xml_attr("version", S2SConstants::XML_VERSION)
             << ">";

    conn->state = S2SState::STREAM_OPENED;
    conn->remote_stream_id = extract_xml_attr(xml, "id");

    // Send stream features
    response << get_stream_features(conn);
    send_raw(conn, response.str());

    if (log_level_ >= 2) {
      fprintf(stderr, "[S2S] Stream opened: id=%s to=%s\n",
              conn->stream_id.c_str(), conn->remote_domain.c_str());
    }

    return "";
  }

  std::string handle_incoming_stream_element(S2SConnection* conn,
                                               const std::string& xml) {
    conn->last_activity = nms();

    if (xml.find("<starttls") != std::string::npos) {
      return handle_starttls_request(conn, xml);
    }
    if (xml.find("<proceed") != std::string::npos) {
      return handle_tls_proceed(conn, xml);
    }
    if (xml.find("<auth ") != std::string::npos) {
      return handle_sasl_auth(conn, xml);
    }
    if (xml.find("<response ") != std::string::npos) {
      return handle_sasl_response(conn, xml);
    }
    if (xml.find("<db:result") != std::string::npos) {
      return handle_dialback_result(conn, xml);
    }
    if (xml.find("<db:verify") != std::string::npos) {
      return handle_dialback_verify(conn, xml);
    }
    if (xml.find("<message") != std::string::npos) {
      return handle_incoming_stanza(conn, xml);
    }
    if (xml.find("<presence") != std::string::npos) {
      return handle_incoming_stanza(conn, xml);
    }
    if (xml.find("<iq ") != std::string::npos) {
      std::string xmlns = extract_xml_attr(xml, "xmlns");
      if (xmlns.find("disco#info") != std::string::npos) {
        return handle_disco_info(conn, xml);
      }
      if (xmlns.find("disco#items") != std::string::npos) {
        return handle_disco_items(conn, xml);
      }
      if (xmlns.find("jabber:iq:version") != std::string::npos) {
        return handle_version_query(conn, xml);
      }
      if (xmlns.find("urn:xmpp:ping") != std::string::npos) {
        return handle_ping_query(conn, xml);
      }
      return handle_incoming_stanza(conn, xml);
    }
    if (xml.find("</stream:stream>") != std::string::npos) {
      close_connection(conn->remote_domain);
      return "";
    }

    // Unknown element - pass through
    return "";
  }

  std::string handle_dialback_result(S2SConnection* conn,
                                       const std::string& xml) {
    std::string from = extract_xml_attr(xml, "from");
    std::string to = extract_xml_attr(xml, "to");
    std::string type = extract_xml_attr(xml, "type");
    std::string key = extract_xml_content(xml, "db:result");

    if (type == "valid") {
      conn->dialback_verified = true;
      conn->authenticated = true;
      conn->auth_method = S2SAuthMethod::DIALBACK;
      conn->state = S2SState::ACTIVE;
      stats_.dialback_verified++;

      if (log_level_ >= 1)
        fprintf(stderr, "[S2S] Dialback verified: %s -> %s\n", from.c_str(),
                to.c_str());

      // Flush pending stanzas
      flush_pending_stanzas(conn);

      // Send features if not yet sent
      if (!conn->features_sent) {
        conn->features_sent = true;
      }
    } else {
      conn->dialback_verified = false;
      stats_.dialback_failed++;
      if (log_level_ >= 1)
        fprintf(stderr, "[S2S] Dialback failed: %s -> %s\n", from.c_str(),
                to.c_str());
      return build_dialback_error("not-authorized",
                                   "Dialback key verification failed");
    }
    return "";
  }

  std::string handle_dialback_verify(S2SConnection* conn,
                                       const std::string& xml) {
    std::string from = extract_xml_attr(xml, "from");
    std::string to = extract_xml_attr(xml, "to");
    std::string id = extract_xml_attr(xml, "id");
    std::string key = extract_xml_content(xml, "db:verify");

    bool valid = verify_dialback_key(from, to, id, key);

    std::stringstream result;
    result << "<db:verify"
           << xml_attr("from", local_domain_) << xml_attr("to", from)
           << xml_attr("id", id) << xml_attr("type", valid ? "valid" : "invalid")
           << ">";
    if (valid) {
      std::string new_key = generate_dialback_key(from, to, id);
      result << new_key;
    }
    result << "</db:verify>";

    if (valid) {
      stats_.dialback_verified++;
      conn->dialback_verified = true;
    } else {
      stats_.dialback_failed++;
    }
    return result.str();
  }

  // ==========================================================================
  // STARTTLS Handling
  // ==========================================================================
  std::string handle_starttls_request(S2SConnection* conn,
                                        const std::string& xml) {
    if (conn->tls_active) {
      return build_stream_error("not-authorized", "TLS already active");
    }
    conn->tls_requested = true;
    conn->state = S2SState::STARTTLS_REQUESTED;

    std::string response = "<proceed xmlns='" +
                           std::string(S2SConstants::XMLNS_TLS) + "'/>";
    return response;
  }

  bool do_starttls(S2SConnection* conn) {
    if (!conn || conn->tls_active) return true;
    conn->state = S2SState::TLS_HANDSHAKING;

#ifdef __linux__
    if (!ssl_ctx_) return false;

    SSL* ssl = SSL_new(ssl_ctx_);
    if (!ssl) return false;

    SSL_set_fd(ssl, conn->fd);
    if (conn->direction == S2SDirection::OUTGOING) {
      SSL_set_connect_state(ssl);
    } else {
      SSL_set_accept_state(ssl);
    }

    int ret = SSL_do_handshake(ssl);
    if (ret <= 0) {
      int err = SSL_get_error(ssl, ret);
      if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
        // Non-blocking: will retry
        conn->ssl = ssl;
        conn->ssl_ctx = ssl_ctx_;
        return false;
      }
      if (log_level_ >= 1)
        fprintf(stderr, "[S2S] TLS handshake failed: %s\n",
                ERR_error_string(ERR_get_error(), nullptr));
      SSL_free(ssl);
      stats_.failed_connections++;
      return false;
    }

    conn->ssl = ssl;
    conn->ssl_ctx = ssl_ctx_;
    conn->tls_active = true;
    conn->state = S2SState::TLS_ESTABLISHED;
    stats_.tls_connections++;

    // Verify peer certificate
    if (conn->ssl) {
      verify_peer_certificate(conn);
    }

    if (log_level_ >= 1)
      fprintf(stderr, "[S2S] TLS established with %s\n",
              conn->remote_domain.c_str());

    // Stream restart after TLS
    return restart_stream_after_tls(conn);
#else
    return false;
#endif
  }

  bool restart_stream_after_tls(S2SConnection* conn) {
    // Send new stream open header after TLS
    std::stringstream xml;
    xml << "<?xml version='1.0' encoding='UTF-8'?>";
    xml << "<stream:stream"
        << xml_attr("xmlns:stream", S2SConstants::XMLNS_STREAM)
        << xml_attr("xmlns", S2SConstants::XMLNS_JABBER_SERVER)
        << xml_attr("xmlns:db", S2SConstants::XMLNS_DIALBACK)
        << xml_attr("from", local_domain_)
        << xml_attr("to", conn->remote_domain)
        << xml_attr("version", S2SConstants::XML_VERSION)
        << ">";
    xml << get_stream_features(conn);
    send_raw(conn, xml.str());

    conn->state = S2SState::STREAM_OPENED;
    return true;
  }

  std::string handle_tls_proceed(S2SConnection* conn, const std::string& xml) {
    if (!conn->tls_requested) return "";
    do_starttls(conn);
    return "";
  }

  // ==========================================================================
  // SASL EXTERNAL
  // ==========================================================================
  std::string handle_sasl_auth(S2SConnection* conn, const std::string& xml) {
    std::string mechanism = extract_xml_attr(xml, "mechanism");
    if (mechanism == "EXTERNAL") {
      conn->state = S2SState::SASL_AUTHENTICATING;
      return "<challenge xmlns='" + std::string(S2SConstants::XMLNS_SASL) +
             "'/>";
    }
    return "<failure xmlns='" + std::string(S2SConstants::XMLNS_SASL) +
           "'><invalid-mechanism/></failure>";
  }

  std::string handle_sasl_response(S2SConnection* conn,
                                     const std::string& xml) {
    std::string authzid = extract_xml_content(xml, "response");
    if (authzid.empty()) authzid = extract_xml_attr(xml, "authzid");

    // Verify based on TLS certificate
    if (conn->tls_active && !conn->peer_cert_fingerprint.empty()) {
      // SASL EXTERNAL verified via TLS cert
      conn->authenticated = true;
      conn->auth_method = S2SAuthMethod::SASL_EXTERNAL;
      conn->state = S2SState::AUTHENTICATED;
      stats_.sasl_external_auths++;

      if (log_level_ >= 1)
        fprintf(stderr, "[S2S] SASL EXTERNAL success: %s\n",
                conn->remote_domain.c_str());

      std::string result =
          "<success xmlns='" + std::string(S2SConstants::XMLNS_SASL) + "'/>";

      // Stream restart for SASL
      std::stringstream restart;
      restart << "<?xml version='1.0' encoding='UTF-8'?>";
      restart << "<stream:stream"
              << xml_attr("xmlns:stream", S2SConstants::XMLNS_STREAM)
              << xml_attr("xmlns", S2SConstants::XMLNS_JABBER_SERVER)
              << xml_attr("xmlns:db", S2SConstants::XMLNS_DIALBACK)
              << xml_attr("from", local_domain_)
              << xml_attr("to", conn->remote_domain)
              << xml_attr("version", S2SConstants::XML_VERSION)
              << ">";
      result += restart.str();
      result += get_stream_features(conn);
      send_raw(conn, result);

      conn->state = S2SState::ACTIVE;
      flush_pending_stanzas(conn);
      return "";
    }

    // SASL EXTERNAL failed
    if (log_level_ >= 1)
      fprintf(stderr, "[S2S] SASL EXTERNAL failed for %s (no valid cert)\n",
              conn->remote_domain.c_str());
    return "<failure xmlns='" + std::string(S2SConstants::XMLNS_SASL) +
           "'><not-authorized/></failure>";
  }

  // ==========================================================================
  // Stream Features
  // ==========================================================================
  std::string get_stream_features(S2SConnection* conn) {
    std::stringstream features;
    features << "<stream:features>";

    // STARTTLS
    if (!conn->tls_active && tls_required_) {
      features << "<starttls xmlns='" << S2SConstants::XMLNS_TLS
               << "'><required/></starttls>";
    } else if (!conn->tls_active) {
      features << "<starttls xmlns='" << S2SConstants::XMLNS_TLS << "'/>";
    }

    // After TLS, offer SASL EXTERNAL
    if (conn->tls_active && sasl_external_enabled_ &&
        conn->auth_method != S2SAuthMethod::SASL_EXTERNAL) {
      features << "<mechanisms xmlns='" << S2SConstants::XMLNS_SASL
               << "'><mechanism>EXTERNAL</mechanism></mechanisms>";
    }

    // Dialback (always available for S2S)
    if (dialback_enabled_ &&
        !conn->dialback_verified &&
        conn->auth_method != S2SAuthMethod::SASL_EXTERNAL) {
      features << "<dialback xmlns='" << S2SConstants::XMLNS_DIALBACK
               << "'/>";
    }

    // Stream compression (if enabled)
    if (compression_enabled_ && conn->tls_active) {
      features << "<compression "
               << "xmlns='http://jabber.org/features/compress'>"
               << "<method>zlib</method></compression>";
    }

    // Bidirectional S2S indication
    if (conn->direction == S2SDirection::BIDIRECTIONAL) {
      features << "<bidi xmlns='urn:xmpp:bidi:0'/>";
    }

    features << "</stream:features>";
    return features.str();
  }

  // ==========================================================================
  // Certificate Verification
  // ==========================================================================
  bool verify_peer_certificate(S2SConnection* conn) {
#ifdef __linux__
    if (!conn->ssl) return false;

    X509* cert = SSL_get_peer_certificate(conn->ssl);
    if (!cert) {
      if (log_level_ >= 1)
        fprintf(stderr, "[S2S] No peer certificate from %s\n",
                conn->remote_domain.c_str());
      return false;
    }

    // Get fingerprint (SHA-256)
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (X509_digest(cert, EVP_sha256(), md, &md_len) == 1) {
      std::stringstream ss;
      for (unsigned int i = 0; i < md_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)md[i];
        if (i < md_len - 1) ss << ":";
      }
      conn->peer_cert_fingerprint = ss.str();
    }

    // Extract subject CN
    char subject[256] = {0};
    X509_NAME* sn = X509_get_subject_name(cert);
    if (sn)
      X509_NAME_get_text_by_NID(sn, NID_commonName, subject, sizeof(subject));

    // Extract SANs (Subject Alternative Names)
    conn->peer_sans.clear();
    GENERAL_NAMES* sans = (GENERAL_NAMES*)X509_get_ext_d2i(
        cert, NID_subject_alt_name, nullptr, nullptr);
    if (sans) {
      for (int i = 0; i < sk_GENERAL_NAME_num(sans); i++) {
        GENERAL_NAME* gn = sk_GENERAL_NAME_value(sans, i);
        if (gn->type == GEN_DNS) {
          const char* dns = (const char*)ASN1_STRING_get0_data(gn->d.dNSName);
          if (dns) conn->peer_sans.push_back(dns);
        }
      }
      GENERAL_NAMES_free(sans);
    }

    // Verify hostname match
    bool matched = verify_hostname(conn->remote_domain, conn->peer_sans,
                                    std::string(subject));

    // Check CA verification
    long verify_result = SSL_get_verify_result(conn->ssl);
    bool ca_valid = (verify_result == X509_V_OK);

    X509_free(cert);

    if (log_level_ >= 2) {
      fprintf(stderr,
              "[S2S] Cert verify %s: fingerprint=%s, subject=%s, "
              "host_match=%s, ca_valid=%s\n",
              conn->remote_domain.c_str(),
              conn->peer_cert_fingerprint.substr(0, 20).c_str(), subject,
              matched ? "yes" : "no", ca_valid ? "yes" : "no");
    }

    return matched && (ca_valid || !ca_file_.empty());
#else
    return false;
#endif
  }

  bool verify_hostname(const std::string& hostname,
                        const std::vector<std::string>& sans,
                        const std::string& cn) {
    // Check SANs first
    for (const auto& san : sans) {
      if (match_dns_name(hostname, san)) return true;
    }
    // Fall back to CN
    return match_dns_name(hostname, cn);
  }

  bool match_dns_name(const std::string& hostname,
                       const std::string& pattern) {
    if (hostname == pattern) return true;
    // Wildcard matching: *.example.com
    if (pattern.size() > 2 && pattern[0] == '*' && pattern[1] == '.') {
      std::string suffix = pattern.substr(1);  // .example.com
      if (hostname.size() > suffix.size()) {
        return hostname.compare(hostname.size() - suffix.size(),
                                suffix.size(), suffix) == 0;
      }
    }
    return false;
  }

  // ==========================================================================
  // Server Discovery (XEP-0030)
  // ==========================================================================
  std::string handle_disco_info(S2SConnection* conn, const std::string& xml) {
    std::string id = extract_xml_attr(xml, "id");
    std::string from = extract_xml_attr(xml, "from");
    stats_.disco_queries++;

    std::stringstream response;
    response << "<iq type='result'"
             << xml_attr("id", id) << xml_attr("from", local_domain_)
             << xml_attr("to", from) << ">"
             << "<query xmlns='http://jabber.org/protocol/disco#info'>"
             << "<identity category='server' type='im' "
             << "name='progressive-xmpp'/>"
             << "<feature var='http://jabber.org/protocol/disco#info'/>"
             << "<feature var='http://jabber.org/protocol/disco#items'/>"
             << "<feature var='" << S2SConstants::XMLNS_DIALBACK << "'/>";

    if (tls_required_)
      response << "<feature var='" << S2SConstants::XMLNS_TLS << "'/>";
    if (sasl_external_enabled_)
      response << "<feature var='" << S2SConstants::XMLNS_SASL << "'/>";

    response << "<feature var='jabber:iq:version'/>"
             << "<feature var='urn:xmpp:ping'/>"
             << "</query></iq>";

    send_raw(conn, response.str());
    return "";
  }

  std::string handle_disco_items(S2SConnection* conn,
                                   const std::string& xml) {
    std::string id = extract_xml_attr(xml, "id");
    std::string from = extract_xml_attr(xml, "from");

    std::stringstream response;
    response << "<iq type='result'"
             << xml_attr("id", id) << xml_attr("from", local_domain_)
             << xml_attr("to", from) << ">"
             << "<query xmlns='http://jabber.org/protocol/disco#items'>"
             // List components and services
             << "<item jid='" << local_domain_
             << "' name='progressive-xmpp'/>"
             << "</query></iq>";

    send_raw(conn, response.str());
    return "";
  }

  // ==========================================================================
  // Server Version Query (XEP-0092)
  // ==========================================================================
  std::string handle_version_query(S2SConnection* conn,
                                     const std::string& xml) {
    std::string id = extract_xml_attr(xml, "id");
    std::string from = extract_xml_attr(xml, "from");
    stats_.version_queries++;

    std::stringstream response;
    response << "<iq type='result'"
             << xml_attr("id", id) << xml_attr("from", local_domain_)
             << xml_attr("to", from) << ">"
             << "<query xmlns='jabber:iq:version'>"
             << "<name>progressive-xmpp</name>"
             << "<version>1.0.0</version>"
             << "<os>" << get_os_string() << "</os>"
             << "</query></iq>";

    send_raw(conn, response.str());
    return "";
  }

  // ==========================================================================
  // Ping (XEP-0199)
  // ==========================================================================
  std::string handle_ping_query(S2SConnection* conn, const std::string& xml) {
    std::string id = extract_xml_attr(xml, "id");
    std::string from = extract_xml_attr(xml, "from");
    stats_.pings_responded++;
    conn->last_ping_recv = nms();

    std::stringstream response;
    response << "<iq type='result'"
             << xml_attr("id", id) << xml_attr("from", local_domain_)
             << xml_attr("to", from) << "/>";

    send_raw(conn, response.str());
    return "";
  }

  void ping_remote_server(const std::string& domain) {
    auto* conn = get_best_connection(domain);
    if (!conn || !conn->is_active()) return;

    std::string id = gen_id();
    std::stringstream ping;
    ping << "<iq type='get'"
         << xml_attr("id", id) << xml_attr("from", local_domain_)
         << xml_attr("to", domain) << ">"
         << "<ping xmlns='urn:xmpp:ping'/>"
         << "</iq>";

    send_stanza(conn, ping.str());
    conn->last_ping_sent = nms();
    stats_.pings_sent++;
  }

  void query_disco_info(const std::string& domain) {
    auto* conn = get_best_connection(domain);
    if (!conn || !conn->is_active()) return;

    std::string id = gen_id();
    std::stringstream iq;
    iq << "<iq type='get'"
       << xml_attr("id", id) << xml_attr("from", local_domain_)
       << xml_attr("to", domain) << ">"
       << "<query xmlns='http://jabber.org/protocol/disco#info'/>"
       << "</iq>";

    send_stanza(conn, iq.str());
    stats_.disco_queries++;
  }

  void query_version(const std::string& domain) {
    auto* conn = get_best_connection(domain);
    if (!conn || !conn->is_active()) return;

    std::string id = gen_id();
    std::stringstream iq;
    iq << "<iq type='get'"
       << xml_attr("id", id) << xml_attr("from", local_domain_)
       << xml_attr("to", domain) << ">"
       << "<query xmlns='jabber:iq:version'/>"
       << "</iq>";

    send_stanza(conn, iq.str());
    stats_.version_queries++;
  }

  // ==========================================================================
  // Incoming Stream Processor (called from XMPPServer)
  // ==========================================================================
  std::string process_incoming_stream(const std::string& from_domain,
                                        const std::string& to_domain,
                                        const std::string& xml_data) {
    if (from_domain == local_domain_) return "";  // Don't process self

    // Find or create connection
    S2SConnection* conn = nullptr;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      auto it = connections_.find(from_domain);
      if (it != connections_.end()) {
        conn = &it->second;
      }
    }

    if (!conn) {
      // New incoming connection - create one
      S2SConnection new_conn;
      new_conn.fd = -1;  // managed externally
      new_conn.direction = S2SDirection::INCOMING;
      new_conn.state = S2SState::STREAM_OPENING;
      new_conn.remote_domain = from_domain;
      new_conn.local_domain = to_domain;
      new_conn.stream_id = gen_id();
      new_conn.connected_at = nms();
      new_conn.last_activity = nms();
      new_conn.auth_method = S2SAuthMethod::NONE;

      std::lock_guard<std::mutex> lock(mutex_);
      connections_[from_domain] = new_conn;
      conn = &connections_[from_domain];
      stats_.total_connections++;
      stats_.incoming_connections++;
    }

    conn->last_activity = nms();

    // Process XML data
    if (xml_data.find("<stream:stream") != std::string::npos &&
        conn->state == S2SState::IDLE) {
      return handle_incoming_stream_open(xml_data, conn);
    }

    // Split multiple elements and process
    std::string accumulated = conn->xml_buffer + xml_data;
    std::string response;

    // Simple XML tokenizer - find complete elements
    size_t pos = 0;
    while (pos < accumulated.size()) {
      // Skip whitespace / XML declaration
      if (accumulated[pos] == '<') {
        if (accumulated.substr(pos, 5) == "<?xml") {
          pos = accumulated.find("?>", pos);
          if (pos == std::string::npos) break;
          pos += 2;
          continue;
        }

        // Find end of this element
        bool is_stream_close =
            accumulated.substr(pos, 17) == "</stream:stream>";
        size_t tag_end = accumulated.find('>', pos);
        if (tag_end == std::string::npos) break;

        // Self-closing tag
        bool self_closing = (accumulated[tag_end - 1] == '/');

        std::string tag_content;
        if (self_closing) {
          tag_content = accumulated.substr(pos, tag_end - pos + 1);
          pos = tag_end + 1;
        } else if (is_stream_close) {
          tag_content = accumulated.substr(pos, 18);
          pos += 18;
        } else {
          // Find matching close tag
          std::string tag_name;
          size_t tag_name_end = accumulated.find_first_of(" >", pos + 1);
          if (tag_name_end == std::string::npos) break;
          tag_name = accumulated.substr(pos + 1, tag_name_end - pos - 1);

          // Handle namespaced tags
          size_t ns_sep = tag_name.find(':');
          std::string close_tag = "</" + tag_name + ">";

          size_t close_pos = accumulated.find(close_tag, tag_end);
          if (close_pos == std::string::npos) break;

          tag_content =
              accumulated.substr(pos, close_pos + close_tag.size() - pos);
          pos = close_pos + close_tag.size();
        }

        // Process this element
        std::string result = handle_incoming_stream_element(conn, tag_content);
        if (!result.empty()) {
          response += result;
        }
      } else {
        pos++;
      }
    }

    // Store remaining unprocessed data
    if (pos < accumulated.size()) {
      conn->xml_buffer = accumulated.substr(pos);
    } else {
      conn->xml_buffer.clear();
    }

    return response;
  }

  // ==========================================================================
  // S2S Stanzas processed from incoming S2S stream (for local delivery)
  // ==========================================================================
  std::string handle_incoming_stanza(S2SConnection* conn,
                                       const std::string& xml) {
    stats_.stanzas_received++;
    conn->last_activity = nms();

    // Extract routing info
    std::string from = extract_xml_attr(xml, "from");
    std::string to = extract_xml_attr(xml, "to");

    if (log_level_ >= 3) {
      fprintf(stderr, "[S2S] Recv stanza: %s -> %s (%zu bytes)\n", from.c_str(),
              to.c_str(), xml.size());
    }

    // Check if destined for this server
    std::string to_domain = to;
    auto at_pos = to.find('@');
    if (at_pos != std::string::npos) {
      to_domain = to.substr(at_pos + 1);
      auto sl_pos = to_domain.find('/');
      if (sl_pos != std::string::npos) {
        to_domain = to_domain.substr(0, sl_pos);
      }
    }

    if (to_domain == local_domain_) {
      // For local delivery - return to caller for processing
      return xml;
    } else {
      // Relay to proper remote server
      route_stanza(to_domain, xml);
      return "";
    }
  }

  // ==========================================================================
  // Error Handling
  // ==========================================================================
  std::string build_stream_error(const std::string& condition,
                                   const std::string& text) {
    std::stringstream xml;
    xml << "<stream:error>"
        << "<" << condition << " xmlns='" << S2SConstants::XMLNS_STREAM_ERROR
        << "'/>";
    if (!text.empty()) {
      xml << "<text xmlns='" << S2SConstants::XMLNS_STREAM_ERROR << "' "
          << "xml:lang='en'>" << xml_escape(text) << "</text>";
    }
    xml << "</stream:error></stream:stream>";
    return xml.str();
  }

  std::string build_dialback_error(const std::string& condition,
                                     const std::string& text) {
    std::stringstream xml;
    xml << "<db:result type='error'>"
        << "<error type='cancel'>"
        << "<" << condition << " xmlns='" << S2SConstants::XMLNS_DIALBACK_ERROR
        << "'/>";
    if (!text.empty()) {
      xml << "<text xmlns='" << S2SConstants::XMLNS_DIALBACK_ERROR << "'>"
          << xml_escape(text) << "</text>";
    }
    xml << "</error></db:result>";
    return xml.str();
  }

  std::string build_stanza_error(const std::string& id,
                                   const std::string& from,
                                   const std::string& to,
                                   const std::string& error_type,
                                   const std::string& condition) {
    std::stringstream xml;
    xml << "<iq type='error'"
        << xml_attr("id", id) << xml_attr("from", from)
        << xml_attr("to", to) << ">"
        << "<error type='" << error_type << "'>"
        << "<" << condition
        << " xmlns='" << S2SConstants::XMLNS_DIALBACK_ERROR << "'/>"
        << "</error></iq>";
    return xml.str();
  }

  void handle_s2s_error(S2SConnection* conn, const std::string& error_msg) {
    stats_.route_errors++;
    if (log_level_ >= 1)
      fprintf(stderr, "[S2S] Error on connection to %s: %s\n",
              conn ? conn->remote_domain.c_str() : "unknown", error_msg.c_str());

    if (conn) {
      conn->state = S2SState::ERROR;
      // Set backoff for retry
      conn->retry_count++;
      int64_t backoff = connection_backoff_base_ * (1LL << std::min(conn->retry_count, 10));
      if (backoff > connection_backoff_max_) backoff = connection_backoff_max_;
      conn->backoff_until = nms() + backoff;

      if (conn->retry_count >= max_retries_) {
        if (log_level_ >= 1)
          fprintf(stderr, "[S2S] Max retries reached for %s\n",
                  conn->remote_domain.c_str());
        close_connection(conn->remote_domain);
      }
    }
  }

  bool is_domain_allowed(const std::string& domain) {
    if (trusted_serviers_.empty()) return true;  // Allow all
    return trusted_servers_.find(domain) != trusted_servers_.end();
  }

  // ==========================================================================
  // Connection Backoff and Retry
  // ==========================================================================
  bool should_retry(S2SConnection* conn) {
    if (!conn) return false;
    if (conn->retry_count >= max_retries_) return false;
    return nms() >= conn->backoff_until;
  }

  void reset_retry(S2SConnection* conn) {
    if (!conn) return;
    conn->retry_count = 0;
    conn->backoff_until = 0;
  }

  int64_t get_backoff_time(const std::string& domain) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(domain);
    if (it == connections_.end()) return 0;
    return std::max(0LL, it->second.backoff_until - nms());
  }

  // ==========================================================================
  // Stanza Queue Management
  // ==========================================================================
  void queue_stanza_for_domain(const std::string& domain,
                                 const std::string& stanza_xml) {
    std::lock_guard<std::mutex> lock(stanza_queue_mutex_);
    auto& q = stanza_queues_[domain];
    q.domain = domain;
    if (q.first_queued == 0) q.first_queued = nms();
    if ((int)q.stanzas.size() >= q.max_size) {
      // Drop oldest
      q.stanzas.pop();
      stats_.stanzas_dropped++;
    }
    q.stanzas.push(stanza_xml);

    if (log_level_ >= 2)
      fprintf(stderr, "[S2S] Queued stanza for %s (queue=%zu)\n",
              domain.c_str(), q.stanzas.size());
  }

  void flush_pending_stanzas(S2SConnection* conn) {
    if (!conn || !conn->is_active()) return;

    std::lock_guard<std::mutex> lock(stanza_queue_mutex_);
    auto it = stanza_queues_.find(conn->remote_domain);
    if (it == stanza_queues_.end()) return;

    auto& q = it->second;
    while (!q.stanzas.empty()) {
      std::string stanza = q.stanzas.front();
      q.stanzas.pop();
      if (!send_stanza(conn, stanza)) {
        // Re-queue
        q.stanzas.push(stanza);
        break;
      }
    }

    if (q.stanzas.empty()) {
      stanza_queues_.erase(it);
    }
  }

  void flush_all_queues() {
    std::lock_guard<std::mutex> lock(stanza_queue_mutex_);
    for (auto& [domain, q] : stanza_queues_) {
      auto* conn = get_best_connection(domain);
      if (conn && conn->is_active()) {
        while (!q.stanzas.empty()) {
          std::string stanza = q.stanzas.front();
          q.stanzas.pop();
          if (!send_stanza(conn, stanza)) {
            q.stanzas.push(stanza);
            break;
          }
        }
      }
    }

    // Clean up empty queues
    auto it = stanza_queues_.begin();
    while (it != stanza_queues_.end()) {
      if (it->second.stanzas.empty()) {
        it = stanza_queues_.erase(it);
      } else {
        ++it;
      }
    }
  }

  int64_t get_queue_size(const std::string& domain) {
    std::lock_guard<std::mutex> lock(stanza_queue_mutex_);
    auto it = stanza_queues_.find(domain);
    return it != stanza_queues_.end() ? it->second.stanzas.size() : 0;
  }

  // ==========================================================================
  // Bidirectional S2S
  // ==========================================================================
  bool enable_bidi(S2SConnection* conn) {
    if (!conn || !conn->is_active()) return false;
    if (conn->direction == S2SDirection::BIDIRECTIONAL) return true;

    conn->direction = S2SDirection::BIDIRECTIONAL;

    std::stringstream feature;
    feature << "<bidi xmlns='urn:xmpp:bidi:0'/>";
    send_raw(conn, feature.str());

    if (log_level_ >= 2)
      fprintf(stderr, "[S2S] Bidi enabled with %s\n",
              conn->remote_domain.c_str());
    return true;
  }

  bool is_bidi_active(const std::string& domain) {
    auto* conn = get_connection(domain);
    return conn && conn->direction == S2SDirection::BIDIRECTIONAL;
  }

  // ==========================================================================
  // Stream Compression (XEP-0138)
  // ==========================================================================
  bool enable_compression(S2SConnection* conn, const std::string& method) {
    if (!conn || !conn->is_active()) return false;
    if (!compression_enabled_) return false;
    if (conn->compressed) return true;

    if (method == "zlib") {
      // Send compress request
      std::stringstream xml;
      xml << "<compress xmlns='http://jabber.org/protocol/compress'>"
          << "<method>zlib</method></compress>";
      send_raw(conn, xml.str());
      conn->compressed = true;

      if (log_level_ >= 2)
        fprintf(stderr, "[S2S] Compression enabled with %s\n",
                conn->remote_domain.c_str());
      return true;
    }

    // Send compress failure
    std::stringstream fail;
    fail << "<failure xmlns='http://jabber.org/protocol/compress'>"
         << "<unsupported-method/></failure>";
    send_raw(conn, fail.str());
    return false;
  }

  // ==========================================================================
  // Stream Multiplexing (XEP-0198 sm hints)
  // ==========================================================================
  void send_stream_management_enable(S2SConnection* conn) {
    if (!conn || !conn->is_active()) return;
    std::stringstream xml;
    xml << "<enable xmlns='urn:xmpp:sm:3' resume='true'/>";
    send_raw(conn, xml.str());
  }

  void send_ack(S2SConnection* conn, int h) {
    if (!conn || !conn->is_active()) return;
    std::stringstream xml;
    xml << "<a xmlns='urn:xmpp:sm:3' h='" << h << "'/>";
    send_raw(conn, xml.str());
  }

  void send_ack_request(S2SConnection* conn) {
    if (!conn || !conn->is_active()) return;
    std::stringstream xml;
    xml << "<r xmlns='urn:xmpp:sm:3'/>";
    send_raw(conn, xml.str());
  }

  // ==========================================================================
  // Statistics and Logging
  // ==========================================================================
  json get_stats() const {
    json j;
    j["total_connections"] = stats_.total_connections.load();
    j["active_connections"] = stats_.active_connections.load();
    j["incoming_connections"] = stats_.incoming_connections.load();
    j["outgoing_connections"] = stats_.outgoing_connections.load();
    j["failed_connections"] = stats_.failed_connections.load();
    j["stanzas_sent"] = stats_.stanzas_sent.load();
    j["stanzas_received"] = stats_.stanzas_received.load();
    j["stanzas_dropped"] = stats_.stanzas_dropped.load();
    j["dialback_sent"] = stats_.dialback_sent.load();
    j["dialback_verified"] = stats_.dialback_verified.load();
    j["dialback_failed"] = stats_.dialback_failed.load();
    j["tls_connections"] = stats_.tls_connections.load();
    j["sasl_external_auths"] = stats_.sasl_external_auths.load();
    j["dns_queries"] = stats_.dns_queries.load();
    j["dns_cache_hits"] = stats_.dns_cache_hits.load();
    j["bytes_sent"] = stats_.bytes_sent.load();
    j["bytes_received"] = stats_.bytes_received.load();
    j["route_errors"] = stats_.route_errors.load();
    j["pings_sent"] = stats_.pings_sent.load();
    j["pings_responded"] = stats_.pings_responded.load();
    j["disco_queries"] = stats_.disco_queries.load();
    j["version_queries"] = stats_.version_queries.load();
    j["uptime_ms"] = nms() - stats_.uptime_start;
    j["local_domain"] = local_domain_;

    // Per-domain connection count
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto& [domain, conn] : connections_) {
        j["domains"][domain]["active"] = conn.is_active();
        j["domains"][domain]["state"] = (int)conn.state;
        j["domains"][domain]["tls"] = conn.tls_active;
        j["domains"][domain]["dialback_verified"] = conn.dialback_verified;
        j["domains"][domain]["authenticated"] = conn.authenticated;
        j["domains"][domain]["retry_count"] = conn.retry_count;
      }
    }

    // Queue sizes
    {
      std::lock_guard<std::mutex> lock(stanza_queue_mutex_);
      for (auto& [domain, q] : stanza_queues_) {
        j["queues"][domain] = (int64_t)q.stanzas.size();
      }
    }

    // DNS cache size
    {
      std::lock_guard<std::mutex> lock(dns_cache_mutex_);
      j["dns_cache_entries"] = (int64_t)dns_cache_.size();
    }

    return j;
  }

  json get_connection_info(const std::string& domain) {
    json j;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = connections_.find(domain);
    if (it == connections_.end()) {
      j["connected"] = false;
      return j;
    }

    auto& conn = it->second;
    j["connected"] = true;
    j["domain"] = conn.remote_domain;
    j["state"] = (int)conn.state;
    j["stream_id"] = conn.stream_id;
    j["remote_stream_id"] = conn.remote_stream_id;
    j["tls_active"] = conn.tls_active;
    j["authenticated"] = conn.authenticated;
    j["dialback_verified"] = conn.dialback_verified;
    j["auth_method"] = (int)conn.auth_method;
    j["bidirectional"] =
        (conn.direction == S2SDirection::BIDIRECTIONAL);
    j["retry_count"] = conn.retry_count;
    j["backoff_ms"] =
        std::max(0LL, conn.backoff_until - nms());
    j["connected_at"] = conn.connected_at;
    j["last_activity"] = conn.last_activity;
    j["idle_ms"] = nms() - conn.last_activity;
    j["pending_stanzas"] = (int64_t)conn.pending_stanzas.size();
    j["peer_fingerprint"] = conn.peer_cert_fingerprint;
    j["peer_sans"] = conn.peer_sans;
    return j;
  }

  std::vector<std::string> get_connected_domains() {
    std::vector<std::string> result;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [domain, conn] : connections_) {
      if (conn.is_active()) result.push_back(domain);
    }
    return result;
  }

  std::vector<std::string> get_all_known_domains() {
    std::vector<std::string> result;
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& [domain, conn] : connections_) {
      result.push_back(domain);
    }
    return result;
  }

  int64_t connection_count() const {
    return stats_.active_connections.load();
  }

  void log_event(const std::string& domain, const std::string& event,
                 const std::string& detail) {
    if (log_level_ < 1) return;
    fprintf(stderr, "[S2S] [%s] %s: %s\n", domain.c_str(), event.c_str(),
            detail.c_str());
  }

  // ==========================================================================
  // Internal Helpers
  // ==========================================================================
 private:
  S2SConnection create_outgoing_connection(const std::string& domain,
                                             const DNSResult& dns) {
    S2SConnection conn;
    conn.fd = -1;
    conn.direction = S2SDirection::OUTGOING;
    conn.remote_domain = domain;
    conn.local_domain = local_domain_;
    conn.remote_ip = dns.ip;
    conn.remote_port = dns.port;
    conn.state = S2SState::IDLE;
    conn.auth_method = S2SAuthMethod::NONE;
    conn.stream_id = gen_id();
    conn.connected_at = 0;
    conn.last_activity = nms();
    return conn;
  }

  bool connect_socket(S2SConnection* conn, const std::string& ip, int port) {
    if (!conn) return false;

#ifdef __linux__
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) return false;

    // Set socket options
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    // Set timeout
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = S2SConstants::CONNECT_TIMEOUT_SEC;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    conn->state = S2SState::CONNECTING;
    int ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
      close(fd);
      if (log_level_ >= 1)
        fprintf(stderr, "[S2S] Connect failed to %s:%d: %s\n", ip.c_str(), port,
                strerror(errno));
      return false;
    }

    conn->fd = fd;
    conn->connected_at = nms();
    conn->last_activity = nms();
    conn->remote_ip = ip;

    if (log_level_ >= 2)
      fprintf(stderr, "[S2S] Connected to %s:%d (fd=%d)\n", ip.c_str(), port,
              fd);
    return true;
#else
    return false;
#endif
  }

  bool start_stream_negotiation(S2SConnection* conn) {
    if (!conn || conn->fd < 0) return false;
    conn->state = S2SState::STREAM_OPENING;

    // Send stream open header
    std::stringstream xml;
    xml << "<?xml version='1.0' encoding='UTF-8'?>";
    xml << "<stream:stream"
        << xml_attr("xmlns:stream", S2SConstants::XMLNS_STREAM)
        << xml_attr("xmlns", S2SConstants::XMLNS_JABBER_SERVER)
        << xml_attr("xmlns:db", S2SConstants::XMLNS_DIALBACK)
        << xml_attr("from", local_domain_)
        << xml_attr("to", conn->remote_domain)
        << xml_attr("version", S2SConstants::XML_VERSION)
        << ">";

    if (!send_raw(conn, xml.str())) {
      if (log_level_ >= 1)
        fprintf(stderr, "[S2S] Failed to send stream open to %s\n",
                conn->remote_domain.c_str());
      return false;
    }

    // Send dialback key
    if (dialback_enabled_) {
      std::string key = generate_dialback_key(local_domain_,
                                                conn->remote_domain,
                                                conn->stream_id);
      std::stringstream db;
      db << "<db:result"
         << xml_attr("from", local_domain_)
         << xml_attr("to", conn->remote_domain) << ">"
         << key << "</db:result>";
      send_raw(conn, db.str());
      conn->dialback_key = key;
      conn->state = S2SState::DIALBACK_SENT;
      stats_.dialback_sent++;
    }

    if (log_level_ >= 2)
      fprintf(stderr, "[S2S] Stream negotiation started with %s\n",
              conn->remote_domain.c_str());
    return true;
  }

  bool send_stanza(S2SConnection* conn, const std::string& stanza) {
    if (!conn || (!conn->is_active() && conn->state != S2SState::STREAM_OPENED))
      return false;

    bool ok = send_raw(conn, stanza);
    if (ok) stats_.stanzas_sent++;
    else stats_.stanzas_dropped++;
    return ok;
  }

  bool send_raw(S2SConnection* conn, const std::string& data) {
    if (!conn || conn->fd < 0) return false;

#ifdef __linux__
    size_t total = 0;
    size_t remaining = data.size();
    const char* ptr = data.c_str();

    while (remaining > 0) {
      ssize_t written;
      if (conn->ssl && conn->tls_active) {
        written = SSL_write(conn->ssl, ptr, remaining);
        if (written <= 0) {
          int err = SSL_get_error(conn->ssl, written);
          if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
            break;
          return false;
        }
      } else {
        written = send(conn->fd, ptr, remaining, MSG_NOSIGNAL);
        if (written < 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK) break;
          return false;
        }
      }
      ptr += written;
      remaining -= written;
      total += written;
    }

    stats_.bytes_sent += total;
    if ((size_t)total < data.size()) {
      // Partial write - buffer remainder
      conn->write_buffer += data.substr(total);
    }
    return true;
#else
    return false;
#endif
  }

  bool send_stream_close(S2SConnection* conn) {
    return send_raw(conn, "</stream:stream>");
  }

  void close_connection_internal(S2SConnection* conn) {
    if (!conn) return;
    if (conn->fd >= 0) {
#ifdef __linux__
      send_stream_close(conn);
      if (conn->ssl) {
        SSL_shutdown(conn->ssl);
        SSL_free(conn->ssl);
        conn->ssl = nullptr;
      }
      shutdown(conn->fd, SHUT_RDWR);
      close(conn->fd);
#endif
      conn->fd = -1;
    }
    conn->state = S2SState::CLOSED;
    conn->authenticated = false;
    conn->dialback_verified = false;
    stats_.active_connections--;
  }

  void start_listener() {
#ifdef __linux__
    listener_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (listener_fd_ < 0) {
      if (log_level_ >= 0)
        fprintf(stderr, "[S2S] Failed to create listener socket\n");
      return;
    }

    int opt = 1;
    setsockopt(listener_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port_);

    if (bind(listener_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
      if (log_level_ >= 0)
        fprintf(stderr, "[S2S] Failed to bind to port %d\n", listen_port_);
      close(listener_fd_);
      listener_fd_ = -1;
      return;
    }

    if (listen(listener_fd_, 128) < 0) {
      if (log_level_ >= 0)
        fprintf(stderr, "[S2S] Failed to listen on port %d\n", listen_port_);
      close(listener_fd_);
      listener_fd_ = -1;
      return;
    }

    if (log_level_ >= 1)
      fprintf(stderr, "[S2S] Listening on port %d for S2S connections\n",
              listen_port_);
#endif
  }

  void start_maintenance() {
    maintenance_thread_ = std::make_unique<std::thread>([this]() {
      while (running_) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (!running_) break;
        run_maintenance();
      }
    });
  }

  void run_maintenance() {
    int64_t now = nms();

    // Cleanup expired dialback keys
    cleanup_dialback_keys();

    // Check connections
    {
      std::lock_guard<std::mutex> lock(mutex_);
      std::vector<std::string> to_remove;
      std::vector<std::string> to_ping;
      std::vector<std::string> to_retry;

      for (auto& [domain, conn] : connections_) {
        // Check idle timeout
        if (conn.is_idle() &&
            now - conn.last_activity > pool_idle_timeout_ * 1000) {
          to_remove.push_back(domain);
          continue;
        }

        // Check inactive connections
        if (!conn.is_active() && conn.state != S2SState::CONNECTING &&
            conn.state != S2SState::TLS_HANDSHAKING) {
          if (should_retry(&conn)) {
            to_retry.push_back(domain);
          }
          continue;
        }

        // Ping active connections periodically
        if (conn.is_active() &&
            now - conn.last_ping_sent > ping_interval_ * 1000) {
          to_ping.push_back(domain);
        }

        // Check for stale connections
        if (conn.is_active() &&
            now - conn.last_activity > ping_interval_ * 2 * 1000) {
          if (log_level_ >= 1)
            fprintf(stderr, "[S2S] Stale connection to %s (idle=%lldms)\n",
                    domain.c_str(), (long long)(now - conn.last_activity));
          to_remove.push_back(domain);
        }
      }

      for (auto& domain : to_remove) {
        auto it = connections_.find(domain);
        if (it != connections_.end()) {
          close_connection_internal(&it->second);
          connections_.erase(it);
        }
      }

      // Ping (outside lock to avoid deadlock)
      for (auto& domain : to_ping) {
        ping_remote_server(domain);
      }

      // Retry failed connections (outside lock)
      for (auto& domain : to_retry) {
        auto it = connections_.find(domain);
        if (it != connections_.end()) {
          close_connection_internal(&it->second);
          connections_.erase(it);
          connect_to(domain);
        }
      }
    }

    // Clean up connection pool
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto& [domain, pool] : connection_pool_) {
        pool.erase(
            std::remove_if(pool.begin(), pool.end(),
                           [&](S2SConnection& c) {
                             return now - c.last_activity >
                                    pool_idle_timeout_ * 1000;
                           }),
            pool.end());
      }
    }

    // Flush queued stanzas
    flush_all_queues();

    // Flush expired DNS cache entries
    {
      std::lock_guard<std::mutex> lock(dns_cache_mutex_);
      auto it = dns_cache_.begin();
      while (it != dns_cache_.end()) {
        if (!it->second.empty() &&
            now - it->second[0].resolved_at > dns_cache_timeout_ * 1000) {
          it = dns_cache_.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  std::string get_os_string() const {
#ifdef __linux__
    return "Linux";
#elif defined(__APPLE__)
    return "macOS";
#elif defined(_WIN32)
    return "Windows";
#else
    return "Unknown";
#endif
  }

  // ==========================================================================
  // Members
  // ==========================================================================
  std::string local_domain_;
  std::string dialback_secret_;
  int s2s_port_{S2SConstants::S2S_DEFAULT_PORT};
  int listen_port_{0};

  bool running_{false};
  bool tls_required_{true};
  bool sasl_external_enabled_{true};
  bool dialback_enabled_{true};
  bool compression_enabled_{false};

  int log_level_{0};
  int max_retries_{S2SConstants::MAX_RETRIES};
  int pool_max_conn_per_domain_{S2SConstants::POOL_MAX_CONN};
  int pool_idle_timeout_{S2SConstants::POOL_IDLE_TIMEOUT_SEC};
  int ping_interval_{S2SConstants::PING_INTERVAL_SEC};
  int64_t connection_backoff_base_{S2SConstants::BACKOFF_BASE_MS};
  int64_t connection_backoff_max_{S2SConstants::BACKOFF_MAX_MS};
  int64_t dialback_key_lifetime_{300};
  int64_t dns_cache_timeout_{3600};

  std::string cert_file_;
  std::string key_file_;
  std::string ca_file_;

  int listener_fd_{-1};
  std::unique_ptr<std::thread> maintenance_thread_;
  S2SStats stats_;

  std::mutex mutex_;
  std::mutex dns_cache_mutex_;
  std::mutex stanza_queue_mutex_;
  std::mutex dialback_mutex_;

  std::map<std::string, S2SConnection> connections_;
  std::map<std::string, std::vector<S2SConnection>> connection_pool_;
  std::map<std::string, std::vector<DNSResult>> dns_cache_;
  std::map<std::string, S2SStanzaQueue> stanza_queues_;
  std::map<std::string, DialbackKey> dialback_keys_;
  std::set<std::string> trusted_servers_;

#ifdef __linux__
  SSL_CTX* ssl_ctx_{nullptr};
#endif

  friend class XMPPServer;
};

// ============================================================================
// S2S Integration with XMPPServer
// ============================================================================

// Global S2S manager instance (one per server)
static thread_local S2SManager* g_s2s_manager = nullptr;

S2SManager* get_s2s_manager() { return g_s2s_manager; }

void init_s2s_manager(const std::string& local_domain,
                       const std::string& dialback_secret) {
  if (g_s2s_manager) {
    delete g_s2s_manager;
  }
  g_s2s_manager = new S2SManager(local_domain, dialback_secret);
}

void shutdown_s2s_manager() {
  if (g_s2s_manager) {
    g_s2s_manager->stop();
    delete g_s2s_manager;
    g_s2s_manager = nullptr;
  }
}

// ============================================================================
// S2S Outgoing Stream Manager
// ============================================================================
class S2SOutgoingManager {
 public:
  explicit S2SOutgoingManager(S2SManager* mgr) : mgr_(mgr) {}

  // Connect to a remote server
  S2SConnection* open_connection(const std::string& domain) {
    return mgr_ ? mgr_->connect_to(domain) : nullptr;
  }

  // Get existing connection
  S2SConnection* get_connection(const std::string& domain) {
    return mgr_ ? mgr_->get_connection(domain) : nullptr;
  }

  // Send a stanza to a remote domain
  bool send_stanza(const std::string& domain, const std::string& stanza) {
    if (!mgr_) return false;
    return mgr_->route_stanza(domain, stanza);
  }

  // Send message to remote domain
  bool send_message(const std::string& from, const std::string& to,
                    const std::string& body, const std::string& type = "chat",
                    const std::string& id = "") {
    if (!mgr_) return false;

    std::string mid = id.empty() ? gen_id() : id;
    std::stringstream xml;
    xml << "<message"
        << xml_attr("from", from) << xml_attr("to", to)
        << xml_attr("type", type) << xml_attr("id", mid)
        << "><body>" << xml_escape(body) << "</body></message>";

    // Extract domain from 'to'
    std::string domain = to;
    auto at_pos = domain.find('@');
    if (at_pos != std::string::npos) {
      domain = domain.substr(at_pos + 1);
      auto sl = domain.find('/');
      if (sl != std::string::npos) domain = domain.substr(0, sl);
    }

    return mgr_->route_stanza(domain, xml.str());
  }

  // Send presence to remote domain
  bool send_presence(const std::string& from, const std::string& to,
                     const std::string& type = "",
                     const std::string& show = "",
                     const std::string& status = "",
                     int priority = 0) {
    if (!mgr_) return false;

    std::stringstream xml;
    xml << "<presence"
        << xml_attr("from", from) << xml_attr("to", to);
    if (!type.empty()) xml << xml_attr("type", type);
    xml << ">";
    if (!show.empty()) xml << "<show>" << xml_escape(show) << "</show>";
    if (!status.empty())
      xml << "<status>" << xml_escape(status) << "</status>";
    if (priority != 0)
      xml << "<priority>" << priority << "</priority>";
    xml << "</presence>";

    std::string domain = to;
    auto at_pos = domain.find('@');
    if (at_pos != std::string::npos) {
      domain = domain.substr(at_pos + 1);
      auto sl = domain.find('/');
      if (sl != std::string::npos) domain = domain.substr(0, sl);
    }

    return mgr_->route_stanza(domain, xml.str());
  }

  // Send IQ to remote domain
  bool send_iq(const std::string& from, const std::string& to,
               const std::string& type, const std::string& id,
               const std::string& ns, const std::string& payload) {
    if (!mgr_) return false;

    std::stringstream xml;
    xml << "<iq"
        << xml_attr("from", from) << xml_attr("to", to)
        << xml_attr("type", type) << xml_attr("id", id) << ">";
    if (!payload.empty()) xml << payload;
    xml << "</iq>";

    std::string domain = to;
    auto at_pos = domain.find('@');
    if (at_pos != std::string::npos) {
      domain = domain.substr(at_pos + 1);
      auto sl = domain.find('/');
      if (sl != std::string::npos) domain = domain.substr(0, sl);
    }

    return mgr_->route_stanza(domain, xml.str());
  }

  // Close a connection
  void close_connection(const std::string& domain) {
    if (mgr_) mgr_->close_connection(domain);
  }

  // Check if connected
  bool is_connected(const std::string& domain) {
    if (!mgr_) return false;
    auto* conn = mgr_->get_connection(domain);
    return conn && conn->is_active();
  }

 private:
  S2SManager* mgr_;
};

// ============================================================================
// S2S Incoming Stream Handler
// ============================================================================
class S2SIncomingHandler {
 public:
  explicit S2SIncomingHandler(S2SManager* mgr) : mgr_(mgr) {}

  // Process incoming S2S stream data from a remote server
  std::string handle_stream(const std::string& from_domain,
                              const std::string& to_domain,
                              const std::string& stream_data) {
    if (!mgr_) return "";
    return mgr_->process_incoming_stream(from_domain, to_domain, stream_data);
  }

  // Handle stream open for incoming connection
  std::string handle_stream_open(const std::string& from_domain,
                                   const std::string& to_domain,
                                   const std::string& stream_id) {
    if (!mgr_) return "";
    S2SConnection* conn = mgr_->get_connection(from_domain);
    if (!conn) {
      mgr_->connect_to(from_domain);
      conn = mgr_->get_connection(from_domain);
    }
    if (!conn) return "";

    conn->direction = S2SDirection::INCOMING;
    conn->remote_stream_id = stream_id;
    return mgr_->get_stream_features(conn);
  }

  // Verify an incoming dialback request
  bool verify_dialback(const std::string& from_domain,
                        const std::string& to_domain,
                        const std::string& stream_id,
                        const std::string& key) {
    if (!mgr_) return false;
    return mgr_->verify_dialback_key(from_domain, to_domain, stream_id, key);
  }

  // Generate dialback result
  std::string generate_dialback_result(const std::string& from_domain,
                                         const std::string& to_domain,
                                         const std::string& stream_id,
                                         bool valid) {
    if (!mgr_) return "";
    return mgr_->generate_dialback_result(from_domain, to_domain, stream_id,
                                           valid);
  }

 private:
  S2SManager* mgr_;
};

// ============================================================================
// S2S DNS Resolver
// ============================================================================
class S2SDNSResolver {
 public:
  explicit S2SDNSResolver(S2SManager* mgr) : mgr_(mgr) {}

  // Resolve XMPP server address for a domain
  std::vector<DNSResult> resolve(const std::string& domain) {
    return mgr_ ? mgr_->resolve_srv(domain) : std::vector<DNSResult>{};
  }

  // Check if a domain has valid DNS records
  bool has_records(const std::string& domain) {
    auto results = resolve(domain);
    return !results.empty();
  }

  // Get the best address to connect to
  DNSResult get_best_address(const std::string& domain) {
    auto results = resolve(domain);
    if (results.empty()) return DNSResult{};

    // Sort by priority (lower = better), then by weight
    std::sort(results.begin(), results.end(),
              [](const DNSResult& a, const DNSResult& b) {
                if (a.priority != b.priority) return a.priority < b.priority;
                return a.weight > b.weight;
              });
    return results[0];
  }

  // Flush DNS cache
  void flush_cache() {
    if (mgr_) mgr_->flush_dns_cache();
  }

  void flush_cache(const std::string& domain) {
    if (mgr_) mgr_->flush_dns_cache(domain);
  }

 private:
  S2SManager* mgr_;
};

// ============================================================================
// S2S Federation Router - high-level routing interface
// ============================================================================
class S2SFederationRouter {
 public:
  S2SFederationRouter(S2SManager* mgr, XMPPServer* server)
      : mgr_(mgr), server_(server) {}

  // Route a message from local user to remote domain
  bool route_message(const XMPPMessage& msg) {
    if (!mgr_ || !server_) return false;

    std::string to_domain = msg.to.domain;
    if (to_domain == server_->config().domain) return false;  // local

    std::stringstream xml;
    xml << "<message"
        << xml_attr("from", msg.from.full())
        << xml_attr("to", msg.to.full())
        << xml_attr("type", msg.type);
    if (!msg.stanza_id.empty()) xml << xml_attr("id", msg.stanza_id);
    xml << ">";
    if (!msg.subject.empty())
      xml << "<subject>" << xml_escape(msg.subject) << "</subject>";
    if (!msg.body.empty())
      xml << "<body>" << xml_escape(msg.body) << "</body>";
    if (!msg.thread.empty())
      xml << "<thread>" << xml_escape(msg.thread) << "</thread>";
    xml << "</message>";

    return mgr_->route_stanza(to_domain, xml.str());
  }

  // Route presence from local user to remote domain
  bool route_presence(const XMPPPresence& pres) {
    if (!mgr_ || !server_) return false;

    std::string to_domain = pres.to.domain;
    if (to_domain == server_->config().domain) return false;

    std::stringstream xml;
    xml << "<presence"
        << xml_attr("from", pres.from.full())
        << xml_attr("to", pres.to.full());
    if (!pres.type.empty()) xml << xml_attr("type", pres.type);
    xml << ">";
    if (!pres.show.empty())
      xml << "<show>" << xml_escape(pres.show) << "</show>";
    if (!pres.status.empty())
      xml << "<status>" << xml_escape(pres.status) << "</status>";
    if (pres.priority != 0)
      xml << "<priority>" << pres.priority << "</priority>";
    xml << "</presence>";

    return mgr_->route_stanza(to_domain, xml.str());
  }

  // Route IQ to remote domain
  bool route_iq(const XMPPIQ& iq) {
    if (!mgr_ || !server_) return false;

    std::string to_domain = iq.to.domain;
    if (to_domain == server_->config().domain) return false;

    std::stringstream xml;
    xml << "<iq"
        << xml_attr("from", iq.from.full())
        << xml_attr("to", iq.to.full())
        << xml_attr("type", iq.type)
        << xml_attr("id", iq.id) << ">";
    if (!iq.ns.empty()) xml << "<query xmlns='" << xml_escape(iq.ns) << "'/>";
    xml << "</iq>";

    return mgr_->route_stanza(to_domain, xml.str());
  }

  // Handle incoming stanza from remote server for local delivery
  void handle_incoming_stanza(const std::string& from_domain,
                               const std::string& stanza_xml) {
    if (!mgr_ || !server_) return;

    std::string response = mgr_->process_incoming_stream(
        from_domain, server_->config().domain, stanza_xml);

    // If response contains stanzas for local delivery, they go to the server
    if (!response.empty() && server_) {
      // Server processes the stanza locally
      // (server would parse and call route_message/route_presence/route_iq)
    }
  }

  // Discover remote server features
  void discover_remote_server(const std::string& domain) {
    if (mgr_) mgr_->query_disco_info(domain);
  }

  // Check remote server version
  void query_remote_version(const std::string& domain) {
    if (mgr_) mgr_->query_version(domain);
  }

  // Ping remote server
  void ping_remote(const std::string& domain) {
    if (mgr_) mgr_->ping_remote_server(domain);
  }

  // Get federation statistics
  json get_stats() const { return mgr_ ? mgr_->get_stats() : json::object(); }

  // Get connected domains
  std::vector<std::string> connected_domains() const {
    return mgr_ ? mgr_->get_connected_domains() : std::vector<std::string>{};
  }

  // Check if federated with a domain
  bool is_federated_with(const std::string& domain) {
    if (!mgr_) return false;
    auto* conn = mgr_->get_connection(domain);
    return conn && conn->is_active();
  }

 private:
  S2SManager* mgr_;
  XMPPServer* server_;
};

// ============================================================================
// S2S ServerItem discovery (XEP-0030 disco#items for servers)
// ============================================================================
class S2SServerDiscovery {
 public:
  explicit S2SServerDiscovery(S2SManager* mgr) : mgr_(mgr) {}

  // Discover items on a remote server
  void discover_items(const std::string& domain) {
    if (!mgr_) return;
    auto* conn = mgr_->get_best_connection(domain);
    if (!conn || !conn->is_active()) return;

    std::string id = gen_id();
    std::stringstream xml;
    xml << "<iq type='get'"
        << xml_attr("id", id)
        << xml_attr("from", mgr_->local_domain_)
        << xml_attr("to", domain) << ">"
        << "<query xmlns='http://jabber.org/protocol/disco#items'/>"
        << "</iq>";
    mgr_->send_stanza(conn, xml.str());
  }

  // Discover server info
  void discover_info(const std::string& domain) {
    if (!mgr_) return;
    auto* conn = mgr_->get_best_connection(domain);
    if (!conn || !conn->is_active()) return;

    std::string id = gen_id();
    std::stringstream xml;
    xml << "<iq type='get'"
        << xml_attr("id", id)
        << xml_attr("from", mgr_->local_domain_)
        << xml_attr("to", domain) << ">"
        << "<query xmlns='http://jabber.org/protocol/disco#info'/>"
        << "</iq>";
    mgr_->send_stanza(conn, xml.str());
  }

 private:
  S2SManager* mgr_;
};

// ============================================================================
// S2S Pool Manager - connection pooling and reuse
// ============================================================================
class S2SPoolManager {
 public:
  explicit S2SPoolManager(S2SManager* mgr) : mgr_(mgr) {}

  // Get a connection from pool or create new
  S2SConnection* acquire(const std::string& domain) {
    return mgr_ ? mgr_->get_best_connection(domain) : nullptr;
  }

  // Return connection to pool
  void release(S2SConnection* conn) {
    if (mgr_) mgr_->recycle_connection(conn);
  }

  // Get pool stats per domain
  json get_pool_stats() const {
    json j;
    if (!mgr_) return j;
    auto domains = mgr_->get_connected_domains();
    for (auto& d : domains) {
      j[d]["active"] = true;
    }
    return j;
  }

  // Drain pool for a domain
  void drain(const std::string& domain) {
    if (mgr_) mgr_->close_connection(domain);
  }

  // Drain all pools
  void drain_all() {
    if (!mgr_) return;
    auto domains = mgr_->get_connected_domains();
    for (auto& d : domains) {
      mgr_->close_connection(d);
    }
  }

 private:
  S2SManager* mgr_;
};

// ============================================================================
// S2S Backoff Manager - exponential backoff for connection retry
// ============================================================================
class S2SBackoffManager {
 public:
  explicit S2SBackoffManager(S2SManager* mgr) : mgr_(mgr) {}

  // Record a failure and get backoff time
  int64_t record_failure(const std::string& domain) {
    auto it = failures_.find(domain);
    if (it == failures_.end()) {
      failures_[domain] = {1, nms()};
      return base_ms_;
    }

    it->second.count++;
    int64_t backoff = base_ms_ * (1LL << std::min(it->second.count - 1, 10));
    if (backoff > max_ms_) backoff = max_ms_;
    it->second.last_failure = nms();
    return backoff;
  }

  // Record success
  void record_success(const std::string& domain) { failures_.erase(domain); }

  // Can retry now?
  bool can_retry(const std::string& domain) {
    auto it = failures_.find(domain);
    if (it == failures_.end()) return true;
    int64_t backoff =
        base_ms_ *
        (1LL << std::min(it->second.count - 1, 10));
    if (backoff > max_ms_) backoff = max_ms_;
    return nms() - it->second.last_failure >= backoff;
  }

  // Get time until next retry
  int64_t retry_after_ms(const std::string& domain) {
    auto it = failures_.find(domain);
    if (it == failures_.end()) return 0;
    int64_t backoff =
        base_ms_ *
        (1LL << std::min(it->second.count - 1, 10));
    if (backoff > max_ms_) backoff = max_ms_;
    int64_t elapsed = nms() - it->second.last_failure;
    return std::max(0LL, backoff - elapsed);
  }

  void set_base_ms(int64_t ms) { base_ms_ = ms; }
  void set_max_ms(int64_t ms) { max_ms_ = ms; }
  void reset(const std::string& domain) { failures_.erase(domain); }
  void reset_all() { failures_.clear(); }

 private:
  struct FailureInfo {
    int count{0};
    int64_t last_failure{0};
  };
  S2SManager* mgr_;
  std::map<std::string, FailureInfo> failures_;
  int64_t base_ms_{S2SConstants::BACKOFF_BASE_MS};
  int64_t max_ms_{S2SConstants::BACKOFF_MAX_MS};
};

// ============================================================================
// S2S Stream ID Generator
// ============================================================================
class S2SStreamIDGenerator {
 public:
  std::string generate() {
    return "s2s-" + std::to_string(nms()) + "-" +
           std::to_string(counter_.fetch_add(1));
  }

  std::string generate_for_domain(const std::string& domain) {
    return "s2s-" + domain + "-" + std::to_string(nms()) + "-" +
           std::to_string(counter_.fetch_add(1));
  }

 private:
  static std::atomic<int64_t> counter_;
};

std::atomic<int64_t> S2SStreamIDGenerator::counter_{1};

// ============================================================================
// S2S Logging Facility
// ============================================================================
class S2SLogger {
 public:
  enum Level { ERROR = 0, WARN = 1, INFO = 2, DEBUG = 3, TRACE = 4 };

  explicit S2SLogger(int level = INFO) : level_(level) {}

  void log(Level lv, const std::string& domain, const std::string& msg) {
    if (lv > level_) return;
    const char* lv_str[] = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};
    fprintf(stderr, "[S2S] [%s] [%s] %s\n", lv_str[lv], domain.c_str(),
            msg.c_str());
  }

  void error(const std::string& domain, const std::string& msg) {
    log(ERROR, domain, msg);
  }
  void warn(const std::string& domain, const std::string& msg) {
    log(WARN, domain, msg);
  }
  void info(const std::string& domain, const std::string& msg) {
    log(INFO, domain, msg);
  }
  void debug(const std::string& domain, const std::string& msg) {
    log(DEBUG, domain, msg);
  }
  void trace(const std::string& domain, const std::string& msg) {
    log(TRACE, domain, msg);
  }

  void set_level(int lv) { level_ = lv; }

 private:
  int level_;
};

// ============================================================================
// S2S Configuration Helper
// ============================================================================
class S2SConfig {
 public:
  std::string local_domain;
  std::string dialback_secret;
  int s2s_port{5269};
  bool tls_required{true};
  bool sasl_external{true};
  bool dialback_enabled{true};
  bool compression_enabled{false};
  std::string cert_file;
  std::string key_file;
  std::string ca_file;
  std::vector<std::string> trusted_servers;
  int pool_max_conn{4};
  int pool_idle_timeout{300};
  int ping_interval{180};
  int max_retries{10};
  int64_t backoff_base_ms{1000};
  int64_t backoff_max_ms{300000};
  int log_level{1};

  void apply_to(S2SManager* mgr) const {
    if (!mgr) return;
    mgr->set_listen_port(s2s_port);
    mgr->set_tls_required(tls_required);
    mgr->set_sasl_external_enabled(sasl_external);
    mgr->set_dialback_enabled(dialback_enabled);
    mgr->set_compression_enabled(compression_enabled);
    mgr->set_certificate_file(cert_file, key_file);
    mgr->set_ca_file(ca_file);
    mgr->set_dialback_secret(dialback_secret);
    mgr->set_pool_max_conn_per_domain(pool_max_conn);
    mgr->set_log_level(log_level);
    for (auto& s : trusted_servers) mgr->add_trusted_server(s);
  }

  static S2SConfig from_json(const json& j) {
    S2SConfig c;
    c.local_domain = j.value("domain", "");
    c.dialback_secret = j.value("dialback_secret", gen_token(32));
    c.s2s_port = j.value("s2s_port", 5269);
    c.tls_required = j.value("tls_required", true);
    c.sasl_external = j.value("sasl_external", true);
    c.dialback_enabled = j.value("dialback_enabled", true);
    c.compression_enabled = j.value("compression", false);
    c.cert_file = j.value("cert_file", "");
    c.key_file = j.value("key_file", "");
    c.ca_file = j.value("ca_file", "");
    c.pool_max_conn = j.value("pool_max_conn", 4);
    c.pool_idle_timeout = j.value("pool_idle_timeout", 300);
    c.ping_interval = j.value("ping_interval", 180);
    c.max_retries = j.value("max_retries", 10);
    c.backoff_base_ms = j.value("backoff_base_ms", 1000);
    c.backoff_max_ms = j.value("backoff_max_ms", 300000);
    c.log_level = j.value("log_level", 1);
    if (j.contains("trusted_servers") && j["trusted_servers"].is_array()) {
      for (auto& s : j["trusted_servers"]) c.trusted_servers.push_back(s);
    }
    return c;
  }

  json to_json() const {
    json j;
    j["domain"] = local_domain;
    j["s2s_port"] = s2s_port;
    j["tls_required"] = tls_required;
    j["sasl_external"] = sasl_external;
    j["dialback_enabled"] = dialback_enabled;
    j["compression"] = compression_enabled;
    j["pool_max_conn"] = pool_max_conn;
    j["pool_idle_timeout"] = pool_idle_timeout;
    j["ping_interval"] = ping_interval;
    j["max_retries"] = max_retries;
    j["backoff_base_ms"] = backoff_base_ms;
    j["backoff_max_ms"] = backoff_max_ms;
    j["log_level"] = log_level;
    j["trusted_servers"] = trusted_servers;
    return j;
  }
};

// ============================================================================
// Public S2S API - exposed to XMPPServer and external callers
// ============================================================================

// Initialize S2S subsystem
bool s2s_init(const S2SConfig& config) {
  init_s2s_manager(config.local_domain, config.dialback_secret);
  if (!g_s2s_manager) return false;

  config.apply_to(g_s2s_manager);
  return g_s2s_manager->start();
}

// Shutdown S2S subsystem
void s2s_shutdown() { shutdown_s2s_manager(); }

// Get the global S2S manager
S2SManager* s2s_get_manager() { return g_s2s_manager; }

// Route a stanza through S2S
bool s2s_route_stanza(const std::string& to_domain,
                       const std::string& stanza_xml) {
  return g_s2s_manager ? g_s2s_manager->route_stanza(to_domain, stanza_xml)
                        : false;
}

// Process incoming S2S stream data
std::string s2s_process_incoming(const std::string& from_domain,
                                   const std::string& to_domain,
                                   const std::string& stream_data) {
  return g_s2s_manager ? g_s2s_manager->process_incoming_stream(
                             from_domain, to_domain, stream_data)
                        : "";
}

// Get federation statistics
json s2s_get_stats() {
  return g_s2s_manager ? g_s2s_manager->get_stats() : json::object();
}

// Check if federated with a domain
bool s2s_is_federated(const std::string& domain) {
  if (!g_s2s_manager) return false;
  auto* conn = g_s2s_manager->get_connection(domain);
  return conn && conn->is_active();
}

// Get connected remote domains
std::vector<std::string> s2s_connected_domains() {
  return g_s2s_manager ? g_s2s_manager->get_connected_domains()
                        : std::vector<std::string>{};
}

// Flush DNS cache
void s2s_flush_dns() {
  if (g_s2s_manager) g_s2s_manager->flush_dns_cache();
}

// ============================================================================
// S2S Factory - creates all S2S components from config
// ============================================================================
struct S2SContext {
  std::unique_ptr<S2SManager> manager;
  std::unique_ptr<S2SOutgoingManager> outgoing;
  std::unique_ptr<S2SIncomingHandler> incoming;
  std::unique_ptr<S2SDNSResolver> resolver;
  std::unique_ptr<S2SFederationRouter> router;
  std::unique_ptr<S2SPoolManager> pool;
  std::unique_ptr<S2SBackoffManager> backoff;
  std::unique_ptr<S2SStreamIDGenerator> stream_ids;
  std::unique_ptr<S2SServerDiscovery> discovery;
  std::unique_ptr<S2SLogger> logger;
};

S2SContext* create_s2s_context(const S2SConfig& config, XMPPServer* server) {
  auto* ctx = new S2SContext();
  ctx->manager = std::make_unique<S2SManager>(config.local_domain,
                                                config.dialback_secret);
  config.apply_to(ctx->manager.get());
  ctx->manager->start();

  ctx->outgoing =
      std::make_unique<S2SOutgoingManager>(ctx->manager.get());
  ctx->incoming =
      std::make_unique<S2SIncomingHandler>(ctx->manager.get());
  ctx->resolver =
      std::make_unique<S2SDNSResolver>(ctx->manager.get());
  ctx->router =
      std::make_unique<S2SFederationRouter>(ctx->manager.get(), server);
  ctx->pool =
      std::make_unique<S2SPoolManager>(ctx->manager.get());
  ctx->backoff =
      std::make_unique<S2SBackoffManager>(ctx->manager.get());
  ctx->stream_ids = std::make_unique<S2SStreamIDGenerator>();
  ctx->discovery =
      std::make_unique<S2SServerDiscovery>(ctx->manager.get());
  ctx->logger = std::make_unique<S2SLogger>(config.log_level);

  return ctx;
}

void destroy_s2s_context(S2SContext* ctx) {
  if (ctx) {
    ctx->manager->stop();
    delete ctx;
  }
}

// ============================================================================
// Integration helpers for XMPPServer
// These functions bridge XMPPServer's S2S stubs to this implementation
// ============================================================================

void XMPPServer_s2s_handle_stream(XMPPServer* server,
                                    const std::string& from,
                                    const std::string& to,
                                    const std::string& stream_id) {
  if (!g_s2s_manager) return;
  g_s2s_manager->process_incoming_stream(from, to,
                                           "<stream:stream from='" +
                                               xml_escape(from) +
                                               "' to='" + xml_escape(to) +
                                               "' id='" +
                                               xml_escape(stream_id) + "' "
                                               "xmlns='jabber:server' "
                                               "xmlns:stream='http://etherx."
                                               "jabber.org/streams' "
                                               "xmlns:db='jabber:server:"
                                               "dialback'>");
}

void XMPPServer_s2s_route_stanza(XMPPServer* server,
                                   const std::string& from_domain,
                                   const std::string& xml) {
  if (!g_s2s_manager) return;
  std::string to = extract_xml_attr(xml, "to");
  std::string domain = to;
  auto at_pos = domain.find('@');
  if (at_pos != std::string::npos) {
    domain = domain.substr(at_pos + 1);
    auto sl = domain.find('/');
    if (sl != std::string::npos) domain = domain.substr(0, sl);
  }
  g_s2s_manager->route_stanza(domain, xml);
}

int64_t XMPPServer_s2s_connection_count(XMPPServer* server) {
  return g_s2s_manager ? g_s2s_manager->connection_count() : 0;
}

}  // namespace progressive::xmpp

// ============================================================================
// XMPPServer S2S overrides - hook into the existing XMPPServer class
// ============================================================================

// Override s2s_connections() to use real S2S count
// (This would be done via a patching mechanism or at link time)

// Define the S2S handler bridge that XMPPServer::handle_s2s_stream will call
namespace {
struct S2SBridge {
  static std::string handle_stream(progressive::xmpp::XMPPServer* srv,
                                     const std::string& from,
                                     const std::string& to,
                                     const std::string& stream_data) {
    return progressive::xmpp::s2s_process_incoming(from, to, stream_data);
  }

  static void route_stanza(progressive::xmpp::XMPPServer* srv,
                            const std::string& from_domain,
                            const std::string& xml) {
    progressive::xmpp::XMPPServer_s2s_route_stanza(srv, from_domain, xml);
  }

  static int64_t connection_count(progressive::xmpp::XMPPServer* srv) {
    return progressive::xmpp::XMPPServer_s2s_connection_count(srv);
  }
};
}  // namespace
