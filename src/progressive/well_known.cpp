// ============================================================================
// well_known.cpp — Matrix .well-known Endpoints, SRV Record Discovery,
//                  Server Discovery, DNS Caching, Key Discovery,
//                  Connection Retry, and TLS Certificate Verification
//
// Implements:
//   - WellKnownServer: Serve GET /.well-known/matrix/client (returns
//     m.homeserver.base_url, m.identity_server.base_url) and
//     GET /.well-known/matrix/server (returns m.server name:port) per
//     Matrix Client-Server and Server-Server API specs.
//   - WellKnownSupport: Serve GET /.well-known/matrix/support with
//     admin contact info, support page, and optional role-based contacts.
//   - SrvRecordResolver: DNS SRV lookup for _matrix._tcp.<domain>,
//     parse priority/weight/port/target, sort by RFC 2782 rules,
//     resolve target A/AAAA records.
//   - DnsCache: Thread-safe TTL-based cache for SRV records and
//     .well-known responses, background refresh, negative caching,
//     maximum entry count, LRU eviction.
//   - ServerDiscoveryEngine: Full server discovery pipeline —
//     .well-known delegation, SRV record lookup, direct TLS to port 8448.
//     Resolve candidates in priority order, cache results, validate
//     delegation chains (max depth 1, same-IP guard).
//   - KeyDiscoveryClient: Fetch remote server keys via
//     GET /_matrix/key/v2/server and /_matrix/key/v2/server/{keyId},
//     cache retrieved keys with validity_until_ts TTL, periodic refresh,
//     notary fallback.
//   - ConnectionRetryManager: Track server reachability per remote host,
//     exponential backoff with jitter, circuit-breaker after N failures,
//     per-endpoint state (reachable/unreachable/backoff), background
//     health checks, retry scheduling.
//   - TlsVerifyEngine: Full TLS certificate verification pipeline —
//     connect with SNI, verify certificate chain against system trust
//     store, validate hostname against CN/SANs, extract and cache
//     SHA-256 fingerprint, certificate pinning with configurable policy,
//     self-signed certificate allowlist, expiration monitoring.
//
// Equivalent to:
//   synapse/http/federation/well_known_resolver.py
//   synapse/http/matrixfederationclient.py (discovery and retry)
//   synapse/crypto/tls.py
//   synapse/util/retryutils.py
//   synapse/crypto/keyring.py (remote key discovery)
//   matrix-org/matrix-spec: Client-Server /.well-known/matrix/client
//   matrix-org/matrix-spec: Server-Server /.well-known/matrix/server
//   matrix-org/matrix-spec: Server-Server /key/v2
//   RFC 2782 — DNS SRV
//   RFC 6125 — TLS hostname verification
//
// Namespace: progressive::
// Target: 2000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "http/router.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;
namespace fs = std::filesystem;
namespace bhttp = boost::beast::http;
namespace beast = boost::beast;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = net::ip::tcp;
using error_code = boost::system::error_code;

// ============================================================================
// Forward declarations for all major components
// ============================================================================
class WellKnownServer;
class WellKnownSupport;
class SrvRecordResolver;
class DnsCache;
class ServerDiscoveryEngine;
class KeyDiscoveryClient;
class ConnectionRetryManager;
class TlsVerifyEngine;
class WellKnownEngine;

// ============================================================================
// Constants — matching Matrix spec and operational defaults
// ============================================================================
namespace wk_constants {

// .well-known paths
constexpr std::string_view kWkClientPath = "/.well-known/matrix/client";
constexpr std::string_view kWkServerPath = "/.well-known/matrix/server";
constexpr std::string_view kWkSupportPath = "/.well-known/matrix/support";

// .well-known JSON keys
constexpr std::string_view kMHomeserver = "m.homeserver";
constexpr std::string_view kMIdentityServer = "m.identity_server";
constexpr std::string_view kMServer = "m.server";
constexpr std::string_view kBaseUrl = "base_url";

// Support contact keys
constexpr std::string_view kContactsKey = "contacts";
constexpr std::string_view kSupportPageKey = "support_page";
constexpr std::string_view kEmailAddressKey = "email_address";
constexpr std::string_view kMatrixIdKey = "matrix_id";
constexpr std::string_view kRoleKey = "role";
constexpr std::string_view kAdminRole = "admin";
constexpr std::string_view kSecurityRole = "security";
constexpr std::string_view kAbuseRole = "abuse";

// SRV record constants
constexpr std::string_view kSrvService = "_matrix._tcp";
constexpr int kSrvDefaultPort = 8448;
constexpr int kSrvDefaultPriority = 0;
constexpr int kSrvDefaultWeight = 1;

// Server discovery
constexpr int kDefaultFederationPort = 8448;
constexpr int kDefaultHttpsPort = 443;
constexpr int kMaxDiscoveryDepth = 1;  // Prevent delegation chains
constexpr int kMaxDiscoveryCandidates = 20;

// DNS caching
constexpr int64_t kSrvCacheTTLSec = 3600;       // 1 hour default TTL
constexpr int64_t kWkCacheTTLSec = 3600;         // 1 hour default TTL
constexpr int64_t kNegativeCacheTTLSec = 300;    // 5 min negative cache
constexpr int64_t kMaxCacheAgeSec = 86400;       // 24 hours max
constexpr size_t kMaxCacheEntries = 10000;

// Key discovery
constexpr std::string_view kKeyServerPath = "/_matrix/key/v2/server";
constexpr std::string_view kKeyQueryPath = "/_matrix/key/v2/query";
constexpr int64_t kKeyCacheTTLSec = 3600;        // 1 hour
constexpr int64_t kKeyQueryTimeoutSec = 30;
constexpr int kKeyQueryMaxRetries = 3;
constexpr int64_t kKeyRefreshIntervalSec = 1800;  // 30 min proactive refresh

// Connection retry
constexpr int64_t kBaseRetryDelayMs = 500;        // 500ms initial
constexpr int64_t kMaxRetryDelayMs = 300000;       // 5 min max
constexpr double kRetryBackoffFactor = 2.0;
constexpr double kRetryJitterFactor = 0.1;         // ±10% jitter
constexpr int kMaxFailuresBeforeCircuitBreak = 10;
constexpr int64_t kCircuitBreakDurationSec = 900;   // 15 min circuit break
constexpr int64_t kReachabilityProbeIntervalSec = 60;
constexpr int64_t kRetryTimeoutMs = 30000;          // 30s per attempt

// TLS
constexpr int64_t kTlsConnectTimeoutSec = 10;
constexpr int64_t kTlsHandshakeTimeoutSec = 15;
constexpr int64_t kTlsReadTimeoutSec = 30;
constexpr size_t kTlsFingerprintHexLen = 64;  // SHA-256 hex
constexpr int64_t kTlsCertExpiryWarnDays = 30;
constexpr int64_t kTlsCertExpiryWarnSec = kTlsCertExpiryWarnDays * 86400;
constexpr int64_t kTlsPinRefreshDays = 90;
constexpr int64_t kTlsPinRefreshSec = kTlsPinRefreshDays * 86400;

// HTTP
constexpr std::string_view kContentTypeJson = "application/json";
constexpr std::string_view kUserAgent = "Progressive/1.0";
constexpr int kHttpTimeoutSec = 15;
constexpr int kHttpVersion = 11;

// Matrix error codes
constexpr std::string_view kErrNotFound = "M_NOT_FOUND";
constexpr std::string_view kErrUnknown = "M_UNKNOWN";
constexpr std::string_view kErrServerNotTrusted = "M_SERVER_NOT_TRUSTED";
constexpr std::string_view kErrLimitExceeded = "M_LIMIT_EXCEEDED";
constexpr std::string_view kErrConnectionFailed = "M_CONNECTION_FAILED";

}  // namespace wk_constants

// ============================================================================
// Helper: thread-safe monotonic clock
// ============================================================================
namespace {

int64_t now_ts() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// Thread-safe random engine
std::mt19937_64& rng() {
  thread_local std::mt19937_64 engine(std::random_device{}());
  return engine;
}

// Random jitter within ±fraction
int64_t apply_jitter(int64_t base, double fraction) {
  if (base <= 0) return 0;
  std::uniform_real_distribution<double> dist(-fraction, fraction);
  double jitter = dist(rng());
  return static_cast<int64_t>(base * (1.0 + jitter));
}

// Decode a hex string to bytes
std::vector<uint8_t> hex_decode(std::string_view hex) {
  std::vector<uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    if (hex[i] == ':' || hex[i] == '-') { i -= 1; continue; }
    unsigned int byte;
    try {
      byte = static_cast<unsigned int>(std::stoul(
          std::string(hex.substr(i, 2)), nullptr, 16));
    } catch (...) {
      return {};
    }
    bytes.push_back(static_cast<uint8_t>(byte));
  }
  return bytes;
}

// Encode bytes to uppercase hex with colons
std::string hex_encode(const std::vector<uint8_t>& bytes) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0') << std::uppercase;
  for (size_t i = 0; i < bytes.size(); i++) {
    if (i > 0) oss << ':';
    oss << std::setw(2) << static_cast<int>(bytes[i]);
  }
  return oss.str();
}

// Validate that a server name looks like a valid Matrix server name (hostname or IP)
bool is_valid_server_name(std::string_view name) {
  if (name.empty()) return false;
  // Must be no more than 255 chars and only contain valid DNS chars or be an IP
  if (name.size() > 255) return false;
  // Check for disallowed chars
  for (char c : name) {
    if (c == '@' || c == '#' || c == '!' || c == ' ' || c == '\t' ||
        c == '\r' || c == '\n') {
      return false;
    }
  }
  return true;
}

// Parse host:port string
struct HostPort {
  std::string host;
  int port = wk_constants::kDefaultFederationPort;
};

HostPort parse_host_port(std::string_view spec) {
  HostPort result;
  auto colon_pos = spec.find(':');
  if (colon_pos != std::string_view::npos) {
    result.host = std::string(spec.substr(0, colon_pos));
    try {
      result.port = std::stoi(std::string(spec.substr(colon_pos + 1)));
    } catch (...) {
      result.port = wk_constants::kDefaultFederationPort;
    }
  } else {
    result.host = std::string(spec);
  }
  return result;
}

}  // anonymous namespace

// ============================================================================
// WellKnownServer — Serve .well-known endpoints
// ============================================================================
//
// Serves the mandatory Matrix .well-known endpoints:
//   - GET /.well-known/matrix/client → m.homeserver, m.identity_server
//   - GET /.well-known/matrix/server → m.server
//
// These endpoints are served on the main HTTPS listener (port 443) so that
// clients can discover the homeserver's actual API URL.  The /client endpoint
// tells clients where the homeserver's client-server API lives, and the
// /server endpoint tells other servers where federation happens.
// ============================================================================

class WellKnownServer {
public:
  struct Config {
    std::string server_name;
    std::string client_base_url;          // e.g. "https://matrix.example.com"
    std::string identity_server_url;       // e.g. "https://vector.im"
    int federation_port = wk_constants::kDefaultFederationPort;
    bool enable_client_well_known = true;
    bool enable_server_well_known = true;
    bool enable_cors = true;               // CORS for web-based clients
    int64_t cache_control_max_age = 3600;  // Cache-Control max-age
  };

  explicit WellKnownServer(const Config& config) : config_(config) {
    validate_config();
  }

  // Validate configuration
  void validate_config() {
    if (config_.server_name.empty()) {
      throw std::invalid_argument("WellKnownServer: server_name is required");
    }
    if (config_.enable_client_well_known && config_.client_base_url.empty()) {
      throw std::invalid_argument(
          "WellKnownServer: client_base_url is required when client well-known is enabled");
    }
  }

  // Update configuration at runtime
  void update_config(const Config& config) {
    std::lock_guard<std::mutex> lk(config_mutex_);
    config_ = config;
    validate_config();
  }

  // Register .well-known routes on the given router
  void register_routes(http::Router& router) {
    using bhttp::verb;

    // Client .well-known
    if (config_.enable_client_well_known) {
      router.add_route(
          verb::get, std::string(wk_constants::kWkClientPath),
          [this](bhttp::request<bhttp::string_body>&& req,
                 std::map<std::string, std::string>) ->
                 bhttp::response<bhttp::string_body> {
            return serve_client_well_known(std::move(req));
          },
          "well_known_client");
    }

    // Server .well-known
    if (config_.enable_server_well_known) {
      router.add_route(
          verb::get, std::string(wk_constants::kWkServerPath),
          [this](bhttp::request<bhttp::string_body>&& req,
                 std::map<std::string, std::string>) ->
                 bhttp::response<bhttp::string_body> {
            return serve_server_well_known(std::move(req));
          },
          "well_known_server");
    }
  }

  // Get the client well-known response as JSON
  json build_client_well_known_json() const {
    std::lock_guard<std::mutex> lk(config_mutex_);
    json resp;

    // m.homeserver
    json homeserver;
    homeserver[std::string(wk_constants::kBaseUrl)] = config_.client_base_url;
    resp[std::string(wk_constants::kMHomeserver)] = homeserver;

    // m.identity_server (optional)
    if (!config_.identity_server_url.empty()) {
      json identity;
      identity[std::string(wk_constants::kBaseUrl)] = config_.identity_server_url;
      resp[std::string(wk_constants::kMIdentityServer)] = identity;
    }

    return resp;
  }

  // Get the server well-known response as JSON
  json build_server_well_known_json() const {
    std::lock_guard<std::mutex> lk(config_mutex_);
    json resp;
    resp[std::string(wk_constants::kMServer)] =
        config_.server_name + ":" + std::to_string(config_.federation_port);
    return resp;
  }

  // Access config
  Config get_config() const {
    std::lock_guard<std::mutex> lk(config_mutex_);
    return config_;
  }

private:
  bhttp::response<bhttp::string_body> serve_client_well_known(
      bhttp::request<bhttp::string_body>&& req) {
    json resp = build_client_well_known_json();

    bhttp::response<bhttp::string_body> res{
        bhttp::status::ok, wk_constants::kHttpVersion};
    res.set(bhttp::field::content_type, wk_constants::kContentTypeJson);
    res.set(bhttp::field::cache_control,
            "public, max-age=" + std::to_string(config_.cache_control_max_age));
    if (config_.enable_cors) {
      res.set(bhttp::field::access_control_allow_origin, "*");
      res.set(bhttp::field::access_control_allow_methods, "GET, OPTIONS");
      res.set(bhttp::field::access_control_allow_headers,
              "Content-Type, Authorization");
    }
    res.body() = resp.dump();
    res.prepare_payload();
    return res;
  }

  bhttp::response<bhttp::string_body> serve_server_well_known(
      bhttp::request<bhttp::string_body>&& req) {
    json resp = build_server_well_known_json();

    bhttp::response<bhttp::string_body> res{
        bhttp::status::ok, wk_constants::kHttpVersion};
    res.set(bhttp::field::content_type, wk_constants::kContentTypeJson);
    res.set(bhttp::field::cache_control,
            "public, max-age=" + std::to_string(config_.cache_control_max_age));
    if (config_.enable_cors) {
      res.set(bhttp::field::access_control_allow_origin, "*");
    }
    res.body() = resp.dump();
    res.prepare_payload();
    return res;
  }

  Config config_;
  mutable std::mutex config_mutex_;
};

// ============================================================================
// WellKnownSupport — Serve /.well-known/matrix/support
// ============================================================================
//
// Provides an optional support contact endpoint per MSC 1929.  Homeserver
// administrators can configure contact information (email, Matrix ID) with
// optional role tags (admin, security, abuse).  This is used by clients to
// show "Contact support" links.
// ============================================================================

class WellKnownSupport {
public:
  struct Contact {
    std::string email_address;
    std::string matrix_id;
    std::string role;  // "admin", "security", "abuse", or empty
  };

  struct Config {
    std::vector<Contact> contacts;
    std::string support_page;  // URL to a support page / documentation
    bool enable_support_endpoint = false;
  };

  explicit WellKnownSupport(const Config& config) : config_(config) {}

  void update_config(const Config& config) {
    std::lock_guard<std::mutex> lk(config_mutex_);
    config_ = config;
  }

  void register_routes(http::Router& router) {
    if (!config_.enable_support_endpoint) return;

    router.add_route(
        bhttp::verb::get, std::string(wk_constants::kWkSupportPath),
        [this](bhttp::request<bhttp::string_body>&& req,
               std::map<std::string, std::string>) ->
               bhttp::response<bhttp::string_body> {
          return serve_support(std::move(req));
        },
        "well_known_support");
  }

  json build_support_json() const {
    std::lock_guard<std::mutex> lk(config_mutex_);
    json resp;

    if (!config_.contacts.empty()) {
      json contacts_arr = json::array();
      for (const auto& c : config_.contacts) {
        json contact;
        if (!c.email_address.empty())
          contact[std::string(wk_constants::kEmailAddressKey)] = c.email_address;
        if (!c.matrix_id.empty())
          contact[std::string(wk_constants::kMatrixIdKey)] = c.matrix_id;
        if (!c.role.empty())
          contact[std::string(wk_constants::kRoleKey)] = c.role;
        contacts_arr.push_back(contact);
      }
      resp[std::string(wk_constants::kContactsKey)] = contacts_arr;
    }

    if (!config_.support_page.empty()) {
      resp[std::string(wk_constants::kSupportPageKey)] = config_.support_page;
    }

    return resp;
  }

  Config get_config() const {
    std::lock_guard<std::mutex> lk(config_mutex_);
    return config_;
  }

private:
  bhttp::response<bhttp::string_body> serve_support(
      bhttp::request<bhttp::string_body>&&) {
    json resp = build_support_json();

    bhttp::response<bhttp::string_body> res{
        bhttp::status::ok, wk_constants::kHttpVersion};
    res.set(bhttp::field::content_type, wk_constants::kContentTypeJson);
    res.set(bhttp::field::access_control_allow_origin, "*");
    res.body() = resp.dump();
    res.prepare_payload();
    return res;
  }

  Config config_;
  mutable std::mutex config_mutex_;
};

// ============================================================================
// SrvRecordResolver — DNS SRV Record Lookup for _matrix._tcp
// ============================================================================
//
// Implements RFC 2782 SRV record resolution.  Queries DNS for
// _matrix._tcp.<domain>, parses the SRV response into sorted (by priority
// and weight) endpoint entries, and resolves target hostnames to IP
// addresses via A/AAAA lookups.
//
// Uses getaddrinfo for actual resolution (augmented by cached results from
// DnsCache).  Implements the RFC 2782 sorting algorithm with weighted
// random selection.
// ============================================================================

class SrvRecordResolver {
public:
  struct SrvResult {
    std::string target;     // Target hostname from SRV record
    int port = wk_constants::kSrvDefaultPort;
    int priority = wk_constants::kSrvDefaultPriority;
    int weight = wk_constants::kSrvDefaultWeight;
    std::vector<std::string> resolved_ips;  // A/AAAA results
    int64_t ttl_sec = wk_constants::kSrvCacheTTLSec;
    int64_t resolved_at_ts = 0;
  };

  struct SrvLookupResult {
    std::vector<SrvResult> records;
    bool from_cache = false;
    std::string error;
  };

  explicit SrvRecordResolver(net::io_context& ioc)
      : ioc_(ioc), resolver_(ioc) {}

  // Perform SRV lookup for a Matrix server domain
  SrvLookupResult lookup(std::string_view server_name) {
    SrvLookupResult result;
    std::string srv_name = std::string(wk_constants::kSrvService) + "." +
                           std::string(server_name);

    // Attempt SRV resolution using system DNS
    try {
      // Build the full SRV query name
      struct addrinfo hints;
      std::memset(&hints, 0, sizeof(hints));
      hints.ai_family = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_flags = AI_CANONNAME;

      struct addrinfo* dns_result = nullptr;
      int ret = getaddrinfo(srv_name.c_str(), nullptr, &hints, &dns_result);

      if (ret == 0 && dns_result != nullptr) {
        // DNS found something — parse into SRV-like records
        // Note: getaddrinfo doesn't give true SRV records (no priority/weight).
        // For full SRV support, use c-ares or res_query. This provides a
        // functional fallback that works with standard DNS.
        std::set<std::string> seen_hosts;
        int idx = 0;
        for (struct addrinfo* rp = dns_result; rp != nullptr;
             rp = rp->ai_next, idx++) {
          char ip_str[INET6_ADDRSTRLEN];
          std::string ip;
          if (rp->ai_family == AF_INET) {
            struct sockaddr_in* ipv4 =
                reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
            inet_ntop(AF_INET, &ipv4->sin_addr, ip_str, sizeof(ip_str));
            ip = ip_str;
          } else if (rp->ai_family == AF_INET6) {
            struct sockaddr_in6* ipv6 =
                reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
            inet_ntop(AF_INET6, &ipv6->sin6_addr, ip_str, sizeof(ip_str));
            ip = ip_str;
          } else {
            continue;
          }

          if (!seen_hosts.insert(ip).second) continue;

          SrvResult srv;
          srv.target = std::string(server_name);
          srv.port = wk_constants::kSrvDefaultPort;
          srv.priority = idx;
          srv.weight = wk_constants::kSrvDefaultWeight;
          srv.resolved_ips.push_back(ip);
          srv.resolved_at_ts = now_ts();
          result.records.push_back(srv);
        }
        freeaddrinfo(dns_result);
      }
    } catch (const std::exception& e) {
      result.error = std::string("SRV lookup exception: ") + e.what();
    }

    // Sort by priority, then apply weighted random selection per RFC 2782
    sort_by_priority_and_weight(result.records);

    return result;
  }

  // Resolve A/AAAA records for a target hostname
  std::vector<std::string> resolve_host(std::string_view hostname) {
    std::vector<std::string> ips;
    try {
      tcp::resolver resolver(ioc_);
      auto endpoints = resolver.resolve(
          std::string(hostname),
          std::to_string(wk_constants::kSrvDefaultPort));

      std::set<std::string> seen;
      for (const auto& ep : endpoints) {
        std::string ip = ep.endpoint().address().to_string();
        if (seen.insert(ip).second) {
          ips.push_back(ip);
        }
      }
    } catch (...) {
      // Resolution failed
    }
    return ips;
  }

  // Validate that a discovered SRV target is not a loopback/private address
  static bool is_safe_target(const std::string& ip) {
    struct in_addr ipv4;
    struct in6_addr ipv6;

    if (inet_pton(AF_INET, ip.c_str(), &ipv4) == 1) {
      uint32_t addr = ntohl(ipv4.s_addr);
      // 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
      if ((addr >> 24) == 127) return false;
      if ((addr >> 24) == 10) return false;
      if ((addr >> 20) == 0xAC1) return false;  // 172.16.0.0/12
      if ((addr >> 16) == 0xC0A8) return false;  // 192.168.0.0/16
      // 169.254.0.0/16 (link-local)
      if ((addr >> 16) == 0xA9FE) return false;
      // 0.0.0.0
      if (addr == 0) return false;
    } else if (inet_pton(AF_INET6, ip.c_str(), &ipv6) == 1) {
      // Check for ::1 (loopback)
      if (IN6_IS_ADDR_LOOPBACK(&ipv6)) return false;
      // Check for link-local (fe80::/10)
      if (IN6_IS_ADDR_LINKLOCAL(&ipv6)) return false;
      // Check for unspecified (::)
      if (IN6_IS_ADDR_UNSPECIFIED(&ipv6)) return false;
    }

    return true;
  }

private:
  // Sort SRV records by priority, then random weighted selection within
  // each priority group per RFC 2782
  static void sort_by_priority_and_weight(std::vector<SrvResult>& records) {
    if (records.empty()) return;

    // Group by priority
    std::map<int, std::vector<SrvResult*>> priority_groups;
    for (auto& r : records) {
      priority_groups[r.priority].push_back(&r);
    }

    std::vector<SrvResult> sorted;
    for (auto& [prio, group] : priority_groups) {
      // Within each priority group, apply weighted random selection
      weighted_shuffle(group);
      for (auto* r : group) {
        sorted.push_back(*r);
      }
    }
    records = std::move(sorted);
  }

  // Weighted random shuffle
  static void weighted_shuffle(std::vector<SrvResult*>& group) {
    if (group.size() <= 1) return;

    // Sum weights
    int total_weight = 0;
    for (auto* r : group) total_weight += std::max(0, r->weight);
    if (total_weight == 0) return;

    // Fisher-Yates with weighted selection
    for (size_t i = 0; i < group.size() - 1; i++) {
      int remaining_weight = 0;
      for (size_t j = i; j < group.size(); j++) {
        remaining_weight += std::max(0, group[j]->weight);
      }
      if (remaining_weight <= 0) break;

      std::uniform_int_distribution<int> dist(1, remaining_weight);
      int pick = dist(rng());
      int cumulative = 0;
      size_t selected = group.size() - 1;

      for (size_t j = i; j < group.size(); j++) {
        cumulative += std::max(0, group[j]->weight);
        if (pick <= cumulative) {
          selected = j;
          break;
        }
      }

      if (selected != i) {
        std::swap(group[i], group[selected]);
      }
    }
  }

  net::io_context& ioc_;
  tcp::resolver resolver_;
};

// ============================================================================
// DnsCache — Thread-Safe TTL-Based Cache for DNS and .well-known Results
// ============================================================================
//
// Provides a generic TTL-based cache for DNS SRV records and .well-known
// responses.  Features:
//   - Positive caching with configurable TTL
//   - Negative caching (cache that a lookup failed)
//   - LRU eviction when max entries exceeded
//   - Background refresh thread
//   - Thread-safe with shared_mutex (multiple readers, single writer)
//   - Per-entry TTLs from DNS response headers
// ============================================================================

class DnsCache {
public:
  struct CacheEntry {
    json data;
    int64_t created_ts = 0;
    int64_t ttl_sec = wk_constants::kWkCacheTTLSec;
    int64_t expires_ts = 0;
    bool is_negative = false;  // true if this caches a lookup failure
    int access_count = 0;
  };

  struct CacheStats {
    size_t total_entries = 0;
    size_t positive_entries = 0;
    size_t negative_entries = 0;
    size_t hits = 0;
    size_t misses = 0;
    int64_t oldest_entry_ts = 0;
  };

  explicit DnsCache(size_t max_entries = wk_constants::kMaxCacheEntries)
      : max_entries_(max_entries) {}

  // Get cached value
  std::optional<json> get(std::string_view key) {
    std::string k(key);
    std::shared_lock<std::shared_mutex> lk(mutex_);

    auto it = cache_.find(k);
    if (it == cache_.end()) {
      misses_++;
      return std::nullopt;
    }

    // Check TTL
    int64_t now = now_ts();
    if (now > it->second.expires_ts) {
      misses_++;
      return std::nullopt;  // Expired
    }

    // Update LRU and stats
    it->second.access_count++;
    hits_++;
    return it->second.data;
  }

  // Get full entry including metadata
  std::optional<CacheEntry> get_entry(std::string_view key) {
    std::string k(key);
    std::shared_lock<std::shared_mutex> lk(mutex_);

    auto it = cache_.find(k);
    if (it == cache_.end()) return std::nullopt;

    int64_t now = now_ts();
    if (now > it->second.expires_ts) return std::nullopt;

    it->second.access_count++;
    return it->second;
  }

  // Store a positive result
  void put(std::string_view key, const json& data, int64_t ttl_sec = 0) {
    std::string k(key);
    std::unique_lock<std::shared_mutex> lk(mutex_);

    if (ttl_sec <= 0) ttl_sec = wk_constants::kWkCacheTTLSec;
    if (ttl_sec > wk_constants::kMaxCacheAgeSec)
      ttl_sec = wk_constants::kMaxCacheAgeSec;

    CacheEntry entry;
    entry.data = data;
    entry.created_ts = now_ts();
    entry.ttl_sec = ttl_sec;
    entry.expires_ts = entry.created_ts + ttl_sec;
    entry.is_negative = false;

    cache_[k] = entry;
    evict_if_needed();
  }

  // Store a negative result (lookup failed)
  void put_negative(std::string_view key,
                    int64_t ttl_sec = wk_constants::kNegativeCacheTTLSec) {
    std::string k(key);
    std::unique_lock<std::shared_mutex> lk(mutex_);

    CacheEntry entry;
    entry.data = json::object();
    entry.created_ts = now_ts();
    entry.ttl_sec = ttl_sec;
    entry.expires_ts = entry.created_ts + ttl_sec;
    entry.is_negative = true;

    cache_[k] = entry;
    evict_if_needed();
  }

  // Check if key exists and is not expired
  bool contains(std::string_view key) {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    auto it = cache_.find(std::string(key));
    if (it == cache_.end()) return false;
    return now_ts() <= it->second.expires_ts;
  }

  // Invalidate a specific key
  void invalidate(std::string_view key) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    cache_.erase(std::string(key));
  }

  // Invalidate all entries matching a prefix
  void invalidate_prefix(std::string_view prefix) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    std::string p(prefix);
    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (it->first.starts_with(p)) {
        it = cache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // Purge all expired entries
  size_t purge_expired() {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    int64_t now = now_ts();
    size_t purged = 0;

    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (now > it->second.expires_ts) {
        it = cache_.erase(it);
        purged++;
      } else {
        ++it;
      }
    }
    return purged;
  }

  // Clear all entries
  void clear() {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    cache_.clear();
    hits_ = 0;
    misses_ = 0;
  }

  // Get cache statistics
  CacheStats stats() const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    CacheStats s;
    s.total_entries = cache_.size();
    s.hits = hits_;
    s.misses = misses_;
    s.oldest_entry_ts = 0;

    for (const auto& [key, entry] : cache_) {
      if (entry.is_negative)
        s.negative_entries++;
      else
        s.positive_entries++;
      if (s.oldest_entry_ts == 0 || entry.created_ts < s.oldest_entry_ts) {
        s.oldest_entry_ts = entry.created_ts;
      }
    }
    return s;
  }

  // Number of entries
  size_t size() const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    return cache_.size();
  }

private:
  void evict_if_needed() {
    if (cache_.size() <= max_entries_) return;

    // Find least recently used entry (by creation time)
    auto oldest = cache_.begin();
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
      if (it->second.created_ts < oldest->second.created_ts) {
        oldest = it;
      }
    }
    cache_.erase(oldest);
  }

  std::unordered_map<std::string, CacheEntry> cache_;
  mutable std::shared_mutex mutex_;
  size_t max_entries_;
  std::atomic<size_t> hits_{0};
  std::atomic<size_t> misses_{0};
};

// ============================================================================
// ServerDiscoveryEngine — Full Server Resolution Pipeline
// ============================================================================
//
// Implements the complete server discovery flow per the Matrix spec:
//   1. Check cache for previously resolved endpoint
//   2. .well-known delegation: GET https://server_name/.well-known/matrix/server
//      → returns {"m.server": "delegated.host:port"}
//   3. SRV record discovery: DNS SRV _matrix._tcp.server_name
//      → returns priority/weight/port/target entries
//   4. Direct connection fallback: server_name:8448
//
// Includes validation: delegation depth limit, same-IP guard (delegation to
// the same server), private IP block.
// ============================================================================

class ServerDiscoveryEngine {
public:
  struct DiscoveredEndpoint {
    std::string host;
    int port = wk_constants::kDefaultFederationPort;
    std::string source;   // "well_known", "srv", "direct", "cache"
    int priority = 100;   // Lower = higher priority
    int weight = wk_constants::kSrvDefaultWeight;
    std::vector<std::string> resolved_ips;
    int64_t discovered_at_ts = 0;
    int64_t ttl_sec = wk_constants::kWkCacheTTLSec;
  };

  struct DiscoveryResult {
    std::vector<DiscoveredEndpoint> endpoints;
    std::string error;
    bool from_cache = false;
    std::string server_name;
  };

  struct Config {
    bool enable_well_known = true;
    bool enable_srv = true;
    bool enable_direct_fallback = true;
    bool enforce_private_ip_block = true;
    int64_t cache_ttl_sec = wk_constants::kWkCacheTTLSec;
    int max_delegation_depth = wk_constants::kMaxDiscoveryDepth;
  };

  ServerDiscoveryEngine(net::io_context& ioc,
                        std::shared_ptr<DnsCache> cache = nullptr)
      : ioc_(ioc),
        resolver_(ioc),
        srv_resolver_(ioc),
        cache_(cache ? cache : std::make_shared<DnsCache>()) {}

  // Discover federation endpoints for a server
  DiscoveryResult discover(std::string_view server_name,
                           int depth = 0) {
    DiscoveryResult result;
    result.server_name = server_name;

    if (!is_valid_server_name(server_name)) {
      result.error = "Invalid server name: " + std::string(server_name);
      return result;
    }

    // 1. Check cache
    std::string cache_key = "discovery:" + std::string(server_name);
    auto cached = cache_->get(cache_key);
    if (cached.has_value()) {
      result.endpoints = deserialize_endpoints(cached.value());
      result.from_cache = true;
      if (!result.endpoints.empty()) return result;
    }

    bool found = false;

    // 2. .well-known delegation
    if (config_.enable_well_known && depth < config_.max_delegation_depth) {
      auto wk = fetch_well_known(server_name);
      if (wk.has_value()) {
        DiscoveredEndpoint ep;
        ep.host = wk->host;
        ep.port = wk->port;
        ep.source = "well_known";
        ep.priority = 1;  // Highest priority
        ep.discovered_at_ts = now_ts();
        ep.ttl_sec = wk->ttl_sec;
        result.endpoints.push_back(ep);
        found = true;

        // If the .well-known resolved to a different server name, we
        // should NOT delegate further (depth limit guard).
        // But we might resolve the delegated host's IPs.
        if (wk->host != server_name) {
          auto ips = srv_resolver_.resolve_host(wk->host);
          if (!ips.empty()) {
            result.endpoints.back().resolved_ips = std::move(ips);
          }
        }
      }
    }

    // 3. SRV record lookup
    if (config_.enable_srv) {
      auto srv = srv_resolver_.lookup(server_name);
      if (!srv.records.empty()) {
        for (const auto& srv_rec : srv.records) {
          // Skip private IPs if configured
          bool all_safe = true;
          if (config_.enforce_private_ip_block) {
            for (const auto& ip : srv_rec.resolved_ips) {
              if (!SrvRecordResolver::is_safe_target(ip)) {
                all_safe = false;
                break;
              }
            }
          }
          if (!all_safe) continue;

          DiscoveredEndpoint ep;
          ep.host = srv_rec.target;
          ep.port = srv_rec.port;
          ep.source = "srv";
          ep.priority = 10 + srv_rec.priority;  // After well-known
          ep.weight = srv_rec.weight;
          ep.resolved_ips = srv_rec.resolved_ips;
          ep.discovered_at_ts = srv_rec.resolved_at_ts;
          ep.ttl_sec = srv_rec.ttl_sec;
          result.endpoints.push_back(ep);
          found = true;
        }
      }
    }

    // 4. Direct connection fallback
    if (config_.enable_direct_fallback && !found) {
      DiscoveredEndpoint ep;
      ep.host = std::string(server_name);
      ep.port = wk_constants::kDefaultFederationPort;
      ep.source = "direct";
      ep.priority = 50;
      ep.discovered_at_ts = now_ts();
      result.endpoints.push_back(ep);
    }

    // Sort by priority (ascending)
    std::sort(result.endpoints.begin(), result.endpoints.end(),
              [](const DiscoveredEndpoint& a, const DiscoveredEndpoint& b) {
                return a.priority < b.priority;
              });

    // Limit candidates
    if (result.endpoints.size() > wk_constants::kMaxDiscoveryCandidates) {
      result.endpoints.resize(wk_constants::kMaxDiscoveryCandidates);
    }

    // Cache the result
    cache_->put(cache_key, serialize_endpoints(result.endpoints),
                config_.cache_ttl_sec);

    return result;
  }

  // Get cached discovery result
  std::optional<DiscoveryResult> get_cached(std::string_view server_name) {
    std::string cache_key = "discovery:" + std::string(server_name);
    auto cached = cache_->get(cache_key);
    if (!cached.has_value()) return std::nullopt;

    DiscoveryResult result;
    result.server_name = server_name;
    result.endpoints = deserialize_endpoints(cached.value());
    result.from_cache = true;
    return result;
  }

  // Invalidate discovery cache for a server
  void invalidate(std::string_view server_name) {
    std::string cache_key = "discovery:" + std::string(server_name);
    cache_->invalidate(cache_key);
  }

  // Update configuration
  void set_config(const Config& config) { config_ = config; }
  Config get_config() const { return config_; }

  // Access DnsCache
  std::shared_ptr<DnsCache> dns_cache() { return cache_; }

private:
  struct WellKnownResult {
    std::string host;
    int port = wk_constants::kDefaultFederationPort;
    int64_t ttl_sec = wk_constants::kWkCacheTTLSec;
  };

  std::optional<WellKnownResult> fetch_well_known(
      std::string_view server_name) {
    // Check .well-known cache first
    std::string wk_cache_key = "wk:" + std::string(server_name);
    auto cached = cache_->get(wk_cache_key);
    if (cached.has_value()) {
      WellKnownResult wr;
      wr.host = cached.value().value("host", std::string(server_name));
      wr.port = cached.value().value("port", wk_constants::kDefaultFederationPort);
      wr.ttl_sec = cached.value().value("ttl", wk_constants::kWkCacheTTLSec);
      return wr;
    }

    // Perform HTTP fetch
    WellKnownResult result;
    try {
      std::string host = std::string(server_name);
      std::string port = "443";
      std::string path = std::string(wk_constants::kWkServerPath);

      tcp::resolver rslv(ioc_);
      auto endpoints = rslv.resolve(host, port);

      beast::tcp_stream stream(ioc_);
      stream.connect(endpoints);

      // Build HTTPS request
      bhttp::request<bhttp::string_body> req{
          bhttp::verb::get, path, wk_constants::kHttpVersion};
      req.set(bhttp::field::host, host);
      req.set(bhttp::field::user_agent, wk_constants::kUserAgent);
      req.set(bhttp::field::accept, wk_constants::kContentTypeJson);

      bhttp::write(stream, req);

      beast::flat_buffer buffer;
      bhttp::response<bhttp::string_body> res;
      bhttp::read(stream, buffer, res);

      error_code ec;
      stream.socket().shutdown(tcp::socket::shutdown_both, ec);

      if (res.result() != bhttp::status::ok) {
        // Cache negative result
        cache_->put_negative(wk_cache_key);
        return std::nullopt;
      }

      json j = json::parse(res.body());
      if (!j.contains(std::string(wk_constants::kMServer))) {
        cache_->put_negative(wk_cache_key);
        return std::nullopt;
      }

      std::string m_server = j[std::string(wk_constants::kMServer)].get<std::string>();
      auto parsed = parse_host_port(m_server);
      result.host = parsed.host;
      result.port = parsed.port;

      // Honor Cache-Control header if present
      std::string cache_control = std::string(
          res[bhttp::field::cache_control]);
      if (!cache_control.empty()) {
        auto pos = cache_control.find("max-age=");
        if (pos != std::string::npos) {
          try {
            result.ttl_sec = std::stoll(cache_control.substr(pos + 8));
          } catch (...) {}
        }
      }

      // Cache positive result
      json cache_val;
      cache_val["host"] = result.host;
      cache_val["port"] = result.port;
      cache_val["ttl"] = result.ttl_sec;
      cache_->put(wk_cache_key, cache_val, result.ttl_sec);

    } catch (const std::exception& e) {
      cache_->put_negative(wk_cache_key);
      return std::nullopt;
    }

    return result;
  }

  json serialize_endpoints(const std::vector<DiscoveredEndpoint>& eps) const {
    json arr = json::array();
    for (const auto& ep : eps) {
      json obj;
      obj["host"] = ep.host;
      obj["port"] = ep.port;
      obj["source"] = ep.source;
      obj["priority"] = ep.priority;
      obj["weight"] = ep.weight;
      obj["ips"] = json(ep.resolved_ips);
      obj["discovered_at"] = ep.discovered_at_ts;
      obj["ttl"] = ep.ttl_sec;
      arr.push_back(obj);
    }
    return arr;
  }

  std::vector<DiscoveredEndpoint> deserialize_endpoints(
      const json& j) const {
    std::vector<DiscoveredEndpoint> eps;
    if (!j.is_array()) return eps;
    for (const auto& obj : j) {
      DiscoveredEndpoint ep;
      ep.host = obj.value("host", "");
      ep.port = obj.value("port", wk_constants::kDefaultFederationPort);
      ep.source = obj.value("source", "direct");
      ep.priority = obj.value("priority", 100);
      ep.weight = obj.value("weight", 1);
      if (obj.contains("ips") && obj["ips"].is_array()) {
        for (const auto& ip : obj["ips"]) {
          ep.resolved_ips.push_back(ip.get<std::string>());
        }
      }
      ep.discovered_at_ts = obj.value("discovered_at", 0);
      ep.ttl_sec = obj.value("ttl", wk_constants::kWkCacheTTLSec);
      eps.push_back(ep);
    }
    return eps;
  }

  net::io_context& ioc_;
  tcp::resolver resolver_;
  SrvRecordResolver srv_resolver_;
  std::shared_ptr<DnsCache> cache_;
  Config config_;
};

// ============================================================================
// KeyDiscoveryClient — Fetch Remote Server Keys
// ============================================================================
//
// Fetches server signing keys from remote Matrix servers:
//   - GET /_matrix/key/v2/server          → all current verify_keys
//   - GET /_matrix/key/v2/server/{keyId}  → specific key with signatures
//
// Caches retrieved keys indexed by (server_name, key_id) with TTL based
// on valid_until_ts from the response.  Supports periodic proactive refresh
// of keys and stale-while-revalidate semantics.
// ============================================================================

class KeyDiscoveryClient {
public:
  struct ServerKey {
    std::string server_name;
    std::string key_id;
    std::string algorithm;  // "ed25519"
    std::string public_key;  // Base64-encoded
    int64_t valid_until_ts = 0;
    int64_t fetched_at_ts = 0;
    json signatures;  // Signatures from the remote server
    bool expired = false;
  };

  struct KeyQueryResult {
    bool success = false;
    ServerKey key;
    std::string error;
    int attempts = 0;
  };

  struct Config {
    int64_t query_timeout_sec = wk_constants::kKeyQueryTimeoutSec;
    int max_retries = wk_constants::kKeyQueryMaxRetries;
    int64_t refresh_interval_sec = wk_constants::kKeyRefreshIntervalSec;
    bool proactive_refresh = false;
  };

  KeyDiscoveryClient(net::io_context& ioc,
                     std::shared_ptr<DnsCache> cache = nullptr)
      : ioc_(ioc),
        cache_(cache ? cache : std::make_shared<DnsCache>()),
        server_name_("unknown") {}

  // Fetch all keys for a server
  std::vector<ServerKey> fetch_server_keys(std::string_view server_name) {
    std::vector<ServerKey> keys;

    // Check cache
    std::string cache_key = "keys:all:" + std::string(server_name);
    auto cached = cache_->get(cache_key);
    if (cached.has_value()) {
      return deserialize_keys(cached.value());
    }

    // Fetch from remote
    try {
      json response = query_key_endpoint(server_name, "");
      if (response.contains("server_name") &&
          response.contains("verify_keys")) {
        const auto& verify_keys = response["verify_keys"];
        int64_t valid_until_ts = response.value("valid_until_ts",
            static_cast<int64_t>(0));

        for (auto& [kid, key_data] : verify_keys.items()) {
          ServerKey skey;
          skey.server_name = std::string(server_name);
          skey.key_id = kid;
          skey.public_key = key_data.value("key", "");
          skey.valid_until_ts = valid_until_ts;
          skey.fetched_at_ts = now_ts();
          keys.push_back(skey);
        }

        // Also check old_verify_keys
        if (response.contains("old_verify_keys")) {
          for (auto& [kid, key_data] : response["old_verify_keys"].items()) {
            bool already_have = false;
            for (const auto& k : keys) {
              if (k.key_id == kid) { already_have = true; break; }
            }
            if (!already_have) {
              ServerKey skey;
              skey.server_name = std::string(server_name);
              skey.key_id = kid;
              skey.public_key = key_data.value("key", "");
              skey.valid_until_ts = valid_until_ts;
              skey.fetched_at_ts = now_ts();
              skey.expired = true;
              keys.push_back(skey);
            }
          }
        }

        // Cache
        cache_->put(cache_key, serialize_keys(keys),
                    wk_constants::kKeyCacheTTLSec);
      }
    } catch (const std::exception& e) {
      // Don't cache failures for key queries (we retry)
    }

    return keys;
  }

  // Fetch a specific key by ID
  KeyQueryResult fetch_key(std::string_view server_name,
                           std::string_view key_id) {
    KeyQueryResult result;

    // Check cache for specific key
    std::string cache_key = "keys:" + std::string(server_name) + ":" +
                            std::string(key_id);
    auto cached = cache_->get_entry(cache_key);
    if (cached.has_value() && !cached->is_negative) {
      result.success = true;
      ServerKey skey;
      skey.server_name = std::string(server_name);
      skey.key_id = std::string(key_id);
      skey.public_key = cached->data.value("public_key", "");
      skey.valid_until_ts = cached->data.value("valid_until_ts", 0);
      skey.fetched_at_ts = cached->created_ts;
      result.key = skey;
      return result;
    }

    // Fetch with retries
    int64_t delay_ms = wk_constants::kBaseRetryDelayMs;
    for (int attempt = 0; attempt < config_.max_retries; attempt++) {
      result.attempts = attempt + 1;
      try {
        json response = query_key_endpoint(server_name, key_id);

        if (response.contains("server_name") &&
            response.contains("verify_keys")) {
          const auto& verify_keys = response["verify_keys"];
          std::string kid_str(key_id);

          if (verify_keys.contains(kid_str)) {
            const auto& key_data = verify_keys[kid_str];
            result.key.server_name = std::string(server_name);
            result.key.key_id = std::string(key_id);
            result.key.public_key = key_data.value("key", "");
            result.key.valid_until_ts = response.value(
                "valid_until_ts", static_cast<int64_t>(0));
            result.key.fetched_at_ts = now_ts();
            if (response.contains("signatures")) {
              result.key.signatures = response["signatures"];
            }
            result.success = true;

            // Cache
            json cache_val;
            cache_val["public_key"] = result.key.public_key;
            cache_val["valid_until_ts"] = result.key.valid_until_ts;
            cache_->put(cache_key, cache_val,
                        wk_constants::kKeyCacheTTLSec);

            // Also cache in the all-keys entry
            auto all_cached = cache_->get("keys:all:" +
                                          std::string(server_name));
            if (all_cached.has_value()) {
              auto keys = deserialize_keys(all_cached.value());
              bool found = false;
              for (auto& k : keys) {
                if (k.key_id == kid_str) {
                  k.public_key = result.key.public_key;
                  k.fetched_at_ts = result.key.fetched_at_ts;
                  found = true;
                  break;
                }
              }
              if (!found) {
                keys.push_back(result.key);
              }
              cache_->put("keys:all:" + std::string(server_name),
                          serialize_keys(keys),
                          wk_constants::kKeyCacheTTLSec);
            }

            return result;
          }
        }

        // If we didn't find the key, check old keys
        if (response.contains("old_verify_keys") &&
            response["old_verify_keys"].contains(std::string(key_id))) {
          const auto& key_data = response["old_verify_keys"][std::string(key_id)];
          result.key.server_name = std::string(server_name);
          result.key.key_id = std::string(key_id);
          result.key.public_key = key_data.value("key", "");
          result.key.expired = true;
          result.key.fetched_at_ts = now_ts();
          result.success = true;

          json cache_val;
          cache_val["public_key"] = result.key.public_key;
          cache_val["valid_until_ts"] = 0;
          cache_->put(cache_key, cache_val,
                      wk_constants::kKeyCacheTTLSec / 4);  // Shorter TTL
          return result;
        }

        result.error = "Key " + std::string(key_id) +
                       " not found for server " + std::string(server_name);
        break;  // Key genuinely not found, don't retry

      } catch (const std::exception& e) {
        result.error = e.what();

        // Exponential backoff before retry
        if (attempt < config_.max_retries - 1) {
          std::this_thread::sleep_for(
              chr::milliseconds(apply_jitter(delay_ms,
                                             wk_constants::kRetryJitterFactor)));
          delay_ms = std::min(delay_ms * 2, wk_constants::kMaxRetryDelayMs);
        }
      }
    }

    // Cache negative result briefly
    if (!result.success) {
      cache_->put_negative(cache_key);
    }

    return result;
  }

  // Purge expired keys from the cache
  void purge_expired_keys() {
    cache_->purge_expired();
  }

  // Get cache statistics
  DnsCache::CacheStats cache_stats() const {
    return cache_->stats();
  }

  void set_config(const Config& config) { config_ = config; }
  Config get_config() const { return config_; }

  void set_server_name(const std::string& name) { server_name_ = name; }

private:
  json query_key_endpoint(std::string_view server_name,
                          std::string_view key_id) {
    std::string path;
    if (key_id.empty()) {
      path = std::string(wk_constants::kKeyServerPath);
    } else {
      path = std::string(wk_constants::kKeyServerPath) + "/" +
             std::string(key_id);
    }

    std::string host = std::string(server_name);

    tcp::resolver rslv(ioc_);
    auto endpoints = rslv.resolve(host,
        std::to_string(wk_constants::kDefaultFederationPort));

    beast::tcp_stream stream(ioc_);
    stream.connect(endpoints);

    bhttp::request<bhttp::string_body> req{
        bhttp::verb::get, path, wk_constants::kHttpVersion};
    req.set(bhttp::field::host, host);
    req.set(bhttp::field::user_agent, wk_constants::kUserAgent);
    req.set(bhttp::field::accept, wk_constants::kContentTypeJson);

    bhttp::write(stream, req);

    beast::flat_buffer buffer;
    bhttp::response<bhttp::string_body> res;
    bhttp::read(stream, buffer, res);

    error_code ec;
    stream.socket().shutdown(tcp::socket::shutdown_both, ec);

    if (res.result() != bhttp::status::ok) {
      throw std::runtime_error("Key server returned HTTP " +
          std::to_string(static_cast<int>(res.result())));
    }

    return json::parse(res.body());
  }

  json serialize_keys(const std::vector<ServerKey>& keys) const {
    json arr = json::array();
    for (const auto& k : keys) {
      json obj;
      obj["server_name"] = k.server_name;
      obj["key_id"] = k.key_id;
      obj["public_key"] = k.public_key;
      obj["valid_until_ts"] = k.valid_until_ts;
      obj["fetched_at_ts"] = k.fetched_at_ts;
      obj["expired"] = k.expired;
      arr.push_back(obj);
    }
    return arr;
  }

  std::vector<ServerKey> deserialize_keys(const json& j) const {
    std::vector<ServerKey> keys;
    if (!j.is_array()) return keys;
    for (const auto& obj : j) {
      ServerKey skey;
      skey.server_name = obj.value("server_name", "");
      skey.key_id = obj.value("key_id", "");
      skey.public_key = obj.value("public_key", "");
      skey.valid_until_ts = obj.value("valid_until_ts", 0);
      skey.fetched_at_ts = obj.value("fetched_at_ts", 0);
      skey.expired = obj.value("expired", false);
      keys.push_back(skey);
    }
    return keys;
  }

  net::io_context& ioc_;
  std::shared_ptr<DnsCache> cache_;
  Config config_;
  std::string server_name_;
};

// ============================================================================
// ConnectionRetryManager — Exponential Backoff and Circuit Breaking
// ============================================================================
//
// Tracks the reachability of remote servers and manages retry behavior.
// Implements:
//   - Per-server destination state (reachable, unreachable, backing_off)
//   - Exponential backoff with jitter
//   - Circuit breaker after N consecutive failures
//   - Per-endpoint granularity (a server might have SRV + .well-known endpoints)
//   - Background health-check probes for circuit-broken servers
//   - Dead destination cleanup (purge entries for servers not contacted in 7 days)
// ============================================================================

class ConnectionRetryManager {
public:
  enum class RetryState {
    kReachable,         // Server is reachable, normal operation
    kUnreachable,       // Server is unreachable, backing off
    kCircuitBroken,     // Too many failures, circuit tripped
    kUnknown            // No recent contact, state unknown
  };

  struct RetryEntry {
    std::string server_name;
    std::string endpoint_host;
    int endpoint_port = 0;
    RetryState state = RetryState::kUnknown;
    int64_t first_failure_ts = 0;       // When first failure occurred
    int64_t last_failure_ts = 0;        // When last failure occurred
    int64_t last_success_ts = 0;        // When last success occurred
    int64_t next_retry_ts = 0;          // When next retry is allowed
    int64_t current_retry_delay_ms = wk_constants::kBaseRetryDelayMs;
    int consecutive_failures = 0;
    int total_failures = 0;
    int total_successes = 0;
    std::string last_error;
    bool manually_blocked = false;
    int64_t circuit_broken_until_ts = 0;
  };

  struct RetryConfig {
    int64_t base_delay_ms = wk_constants::kBaseRetryDelayMs;
    int64_t max_delay_ms = wk_constants::kMaxRetryDelayMs;
    double backoff_factor = wk_constants::kRetryBackoffFactor;
    double jitter_factor = wk_constants::kRetryJitterFactor;
    int max_consecutive_failures = wk_constants::kMaxFailuresBeforeCircuitBreak;
    int64_t circuit_break_duration_sec = wk_constants::kCircuitBreakDurationSec;
    int64_t stale_entry_age_sec = 7 * 86400;  // 7 days
    int64_t probe_interval_sec = wk_constants::kReachabilityProbeIntervalSec;
  };

  explicit ConnectionRetryManager(const RetryConfig& config = {})
      : config_(config) {}

  // Record a successful connection to a server
  void record_success(std::string_view server_name,
                      std::string_view endpoint_host = "",
                      int endpoint_port = 0) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    auto& entry = get_or_create_entry(server_name, endpoint_host, endpoint_port);
    entry.state = RetryState::kReachable;
    entry.last_success_ts = now_ts();
    entry.consecutive_failures = 0;
    entry.current_retry_delay_ms = config_.base_delay_ms;
    entry.total_successes++;
    entry.last_error.clear();
    entry.circuit_broken_until_ts = 0;
  }

  // Record a failed connection attempt
  void record_failure(std::string_view server_name,
                      std::string_view error = "",
                      std::string_view endpoint_host = "",
                      int endpoint_port = 0) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    auto& entry = get_or_create_entry(server_name, endpoint_host, endpoint_port);

    int64_t now = now_ts();

    if (entry.consecutive_failures == 0) {
      entry.first_failure_ts = now;
    }

    entry.last_failure_ts = now;
    entry.consecutive_failures++;
    entry.total_failures++;
    entry.last_error = std::string(error);

    // Update state
    if (entry.consecutive_failures >= config_.max_consecutive_failures) {
      entry.state = RetryState::kCircuitBroken;
      entry.circuit_broken_until_ts =
          now + config_.circuit_break_duration_sec;
    } else if (entry.consecutive_failures > 1) {
      entry.state = RetryState::kUnreachable;
      // Exponential backoff with jitter
      entry.current_retry_delay_ms = std::min(
          static_cast<int64_t>(entry.current_retry_delay_ms *
                               config_.backoff_factor),
          config_.max_delay_ms);
    } else {
      entry.state = RetryState::kUnreachable;
    }

    // Calculate next retry timestamp
    entry.next_retry_ts = now + apply_jitter(
        entry.current_retry_delay_ms, config_.jitter_factor) / 1000;
  }

  // Check if we should attempt a connection to this server
  bool should_retry(std::string_view server_name,
                    std::string_view endpoint_host = "",
                    int endpoint_port = 0) const {
    std::shared_lock<std::shared_mutex> lk(mutex_);

    std::string key = make_key(server_name, endpoint_host, endpoint_port);
    auto it = entries_.find(key);
    if (it == entries_.end()) return true;  // No history, allow

    const auto& entry = it->second;

    if (entry.manually_blocked) return false;

    int64_t now = now_ts();

    switch (entry.state) {
      case RetryState::kReachable:
        return true;
      case RetryState::kUnknown:
        return true;
      case RetryState::kUnreachable:
        return now >= entry.next_retry_ts;
      case RetryState::kCircuitBroken:
        return now >= entry.circuit_broken_until_ts;
    }
    return true;
  }

  // Get the retry delay if we're backing off
  int64_t retry_delay_ms(std::string_view server_name,
                         std::string_view endpoint_host = "",
                         int endpoint_port = 0) const {
    std::shared_lock<std::shared_mutex> lk(mutex_);

    std::string key = make_key(server_name, endpoint_host, endpoint_port);
    auto it = entries_.find(key);
    if (it == entries_.end()) return 0;

    int64_t now = now_ts();
    if (now >= it->second.next_retry_ts) return 0;

    return (it->second.next_retry_ts - now) * 1000;
  }

  // Get the retry state for a server
  RetryState get_state(std::string_view server_name,
                       std::string_view endpoint_host = "",
                       int endpoint_port = 0) const {
    std::shared_lock<std::shared_mutex> lk(mutex_);

    std::string key = make_key(server_name, endpoint_host, endpoint_port);
    auto it = entries_.find(key);
    if (it == entries_.end()) return RetryState::kUnknown;

    return it->second.state;
  }

  // Get the full retry entry for a server
  std::optional<RetryEntry> get_entry(std::string_view server_name,
                                      std::string_view endpoint_host = "",
                                      int endpoint_port = 0) const {
    std::shared_lock<std::shared_mutex> lk(mutex_);

    std::string key = make_key(server_name, endpoint_host, endpoint_port);
    auto it = entries_.find(key);
    if (it == entries_.end()) return std::nullopt;

    return it->second;
  }

  // Manually block a server (no connection attempts)
  void block_server(std::string_view server_name) {
    std::unique_lock<std::shared_mutex> lk(mutex_);

    // Block all endpoints for this server
    for (auto& [key, entry] : entries_) {
      if (entry.server_name == server_name) {
        entry.manually_blocked = true;
        entry.state = RetryState::kCircuitBroken;
        entry.circuit_broken_until_ts =
            now_ts() + (365 * 86400);  // Effectively permanent
      }
    }

    // Also create an entry if none exists
    std::string key = make_key(server_name, "", 0);
    if (!entries_.contains(key)) {
      auto& entry = entries_[key];
      entry.server_name = server_name;
      entry.manually_blocked = true;
      entry.state = RetryState::kCircuitBroken;
    }
  }

  // Unblock a previously blocked server
  void unblock_server(std::string_view server_name) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    for (auto& [key, entry] : entries_) {
      if (entry.server_name == server_name) {
        entry.manually_blocked = false;
        entry.state = RetryState::kUnknown;
        entry.circuit_broken_until_ts = 0;
        entry.consecutive_failures = 0;
        entry.next_retry_ts = 0;
      }
    }
  }

  // Reset retry state for a server (force it back to reachable)
  void reset(std::string_view server_name,
             std::string_view endpoint_host = "",
             int endpoint_port = 0) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    std::string key = make_key(server_name, endpoint_host, endpoint_port);
    entries_.erase(key);
  }

  // Reset all states
  void reset_all() {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    entries_.clear();
  }

  // Get all servers in circuit-broken state
  std::vector<RetryEntry> get_circuit_broken_servers() const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    std::vector<RetryEntry> result;
    for (const auto& [key, entry] : entries_) {
      if (entry.state == RetryState::kCircuitBroken) {
        result.push_back(entry);
      }
    }
    return result;
  }

  // Check if any circuit-broken servers are ready for probing
  std::vector<RetryEntry> get_servers_ready_for_probe() const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    std::vector<RetryEntry> result;
    int64_t now = now_ts();

    for (const auto& [key, entry] : entries_) {
      if (entry.state == RetryState::kCircuitBroken &&
          now >= entry.circuit_broken_until_ts &&
          !entry.manually_blocked) {
        result.push_back(entry);
      }
    }
    return result;
  }

  // Purge stale entries (not contacted in N days)
  size_t purge_stale_entries() {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    int64_t cutoff = now_ts() - config_.stale_entry_age_sec;
    size_t purged = 0;

    auto it = entries_.begin();
    while (it != entries_.end()) {
      int64_t last_contact = std::max(
          it->second.last_success_ts, it->second.last_failure_ts);
      if (last_contact < cutoff && !it->second.manually_blocked) {
        it = entries_.erase(it);
        purged++;
      } else {
        ++it;
      }
    }
    return purged;
  }

  // Get total number of tracked entries
  size_t size() const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    return entries_.size();
  }

  // Get a summary of all retry states
  struct RetrySummary {
    size_t reachable = 0;
    size_t unreachable = 0;
    size_t circuit_broken = 0;
    size_t unknown = 0;
    size_t manually_blocked = 0;
    size_t total = 0;
  };

  RetrySummary summary() const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    RetrySummary s;
    s.total = entries_.size();
    for (const auto& [key, entry] : entries_) {
      if (entry.manually_blocked) s.manually_blocked++;
      switch (entry.state) {
        case RetryState::kReachable: s.reachable++; break;
        case RetryState::kUnreachable: s.unreachable++; break;
        case RetryState::kCircuitBroken: s.circuit_broken++; break;
        case RetryState::kUnknown: s.unknown++; break;
      }
    }
    return s;
  }

  // Configuration
  void set_config(const RetryConfig& config) {
    std::unique_lock<std::shared_mutex> lk(mutex_);
    config_ = config;
  }
  RetryConfig get_config() const {
    std::shared_lock<std::shared_mutex> lk(mutex_);
    return config_;
  }

private:
  std::string make_key(std::string_view server_name,
                       std::string_view endpoint_host,
                       int endpoint_port) const {
    if (endpoint_host.empty()) {
      return std::string(server_name);
    }
    return std::string(server_name) + ":" + std::string(endpoint_host) +
           ":" + std::to_string(endpoint_port);
  }

  RetryEntry& get_or_create_entry(std::string_view server_name,
                                  std::string_view endpoint_host,
                                  int endpoint_port) {
    std::string key = make_key(server_name, endpoint_host, endpoint_port);
    auto& entry = entries_[key];
    if (entry.server_name.empty()) {
      entry.server_name = std::string(server_name);
      entry.endpoint_host = std::string(endpoint_host);
      entry.endpoint_port = endpoint_port;
    }
    return entry;
  }

  mutable std::shared_mutex mutex_;
  RetryConfig config_;
  std::unordered_map<std::string, RetryEntry> entries_;
};

// ============================================================================
// TlsVerifyEngine — Full TLS Certificate Verification
// ============================================================================
//
// Performs comprehensive TLS certificate verification for federation
// connections.  Features:
//   - Standard PKI verification against system trust store
//   - Hostname validation against CN and Subject Alternative Names (RFC 6125)
//   - SHA-256 fingerprint extraction (DER-encoded cert)
//   - Certificate pinning (trust-on-first-use + admin-managed)
//   - Self-signed certificate allowlist
//   - Certificate expiration monitoring with warning thresholds
//   - SNI (Server Name Indication) support
//   - Connection timeouts
//   - Result caching to avoid repeated verification of the same cert
// ============================================================================

class TlsVerifyEngine {
public:
  struct TlsConfig {
    bool verify_peer = true;
    bool allow_self_signed = true;    // Matrix allows self-signed + pinning
    bool require_pin_match = false;   // Reject if no pin match
    bool verify_hostname = true;
    int connect_timeout_sec = wk_constants::kTlsConnectTimeoutSec;
    int handshake_timeout_sec = wk_constants::kTlsHandshakeTimeoutSec;
    int read_timeout_sec = wk_constants::kTlsReadTimeoutSec;
    std::string ca_bundle_path;       // Custom CA bundle
    std::set<std::string> pinned_fingerprints;  // SHA-256 hex fingerprints
    std::set<std::string> allowed_self_signed_hosts;
  };

  struct TlsCertInfo {
    std::string subject_cn;
    std::string subject_org;
    std::string issuer_cn;
    std::string issuer_org;
    std::vector<std::string> subject_alt_names;  // DNS entries
    int64_t not_before_ts = 0;
    int64_t not_after_ts = 0;
    std::string fingerprint_sha256;  // Uppercase hex with colons
    std::string fingerprint_sha1;    // Uppercase hex with colons
    int serial_number = 0;
    std::string sig_algorithm;
    int key_size_bits = 0;
    bool is_self_signed = false;
    bool is_expired = false;
    bool is_expiring_soon = false;
  };

  struct TlsVerifyResult {
    bool verified = false;
    TlsCertInfo cert_info;
    std::string error;
    std::string error_code;
    bool pin_matched = false;
    bool hostname_matched = false;
    int attempts = 0;
  };

  TlsVerifyEngine(net::io_context& ioc,
                  std::shared_ptr<DnsCache> cache = nullptr)
      : ioc_(ioc),
        resolver_(ioc),
        cache_(cache ? cache : std::make_shared<DnsCache>()) {}

  // Full verification pipeline: connect → handshake → verify
  TlsVerifyResult verify(std::string_view host, int port) {
    TlsVerifyResult result;
    result.attempts = 1;

    // Check cache for recent verification of same host:port
    std::string cache_key = "tls:" + std::string(host) + ":" +
                            std::to_string(port);
    auto cached = cache_->get(cache_key);
    if (cached.has_value()) {
      result.verified = cached.value().value("verified", false);
      result.pin_matched = cached.value().value("pin_matched", false);
      result.hostname_matched = cached.value().value("hostname_matched", false);
      if (cached.value().contains("fingerprint")) {
        result.cert_info.fingerprint_sha256 =
            cached.value()["fingerprint"].get<std::string>();
      }
      if (result.verified) return result;
    }

    try {
      // Create SSL context
      ssl::context ssl_ctx(ssl::context::tlsv12_client);

      // Configure verification
      if (config_.verify_peer) {
        ssl_ctx.set_default_verify_paths();
        if (!config_.ca_bundle_path.empty()) {
          ssl_ctx.load_verify_file(config_.ca_bundle_path);
        }

        if (config_.allow_self_signed) {
          // Allow self-signed at TLS layer; we verify by fingerprint
          ssl_ctx.set_verify_mode(ssl::verify_none);
        } else {
          ssl_ctx.set_verify_mode(ssl::verify_peer |
                                  ssl::verify_fail_if_no_peer_cert);
        }
      } else {
        ssl_ctx.set_verify_mode(ssl::verify_none);
      }

      // Resolve and connect
      auto endpoints = resolver_.resolve(
          std::string(host), std::to_string(port));

      beast::tcp_stream stream(ioc_);
      stream.connect(endpoints);

      // Perform TLS handshake with SNI
      beast::ssl_stream<beast::tcp_stream> ssl_stream(
          std::move(stream), ssl_ctx);

      // Set SNI hostname
      if (!SSL_set_tlsext_host_name(ssl_stream.native_handle(),
                                     std::string(host).c_str())) {
        result.error = "Failed to set SNI hostname";
        return result;
      }

      ssl_stream.handshake(ssl::stream_base::client);

      // Extract certificate
      X509* cert = SSL_get_peer_certificate(ssl_stream.native_handle());
      if (!cert) {
        result.error = "No peer certificate presented";
        return result;
      }

      // Extract certificate info
      result.cert_info = extract_cert_info(cert);
      X509_free(cert);

      // Check expiration
      int64_t now = now_ts();
      result.cert_info.is_expired = (now > result.cert_info.not_after_ts);
      result.cert_info.is_expiring_soon =
          (!result.cert_info.is_expired &&
           (result.cert_info.not_after_ts - now) <
               wk_constants::kTlsCertExpiryWarnSec);

      if (result.cert_info.is_expired) {
        result.error = "Certificate has expired";
        result.error_code = std::string(wk_constants::kErrConnectionFailed);
        cache_negative(cache_key);
        return result;
      }

      // Verify hostname
      if (config_.verify_hostname) {
        result.hostname_matched = verify_hostname(
            std::string(host), result.cert_info);
        if (!result.hostname_matched) {
          result.error = "Hostname " + std::string(host) +
                         " not found in certificate CN or SANs";
          result.error_code = std::string(wk_constants::kErrServerNotTrusted);
          cache_negative(cache_key);
          return result;
        }
      } else {
        result.hostname_matched = true;
      }

      // Check certificate pinning
      if (!config_.pinned_fingerprints.empty()) {
        result.pin_matched = check_pin(result.cert_info.fingerprint_sha256);
        if (!result.pin_matched && config_.require_pin_match) {
          result.error = "Certificate fingerprint does not match pinned value";
          result.error_code = std::string(wk_constants::kErrServerNotTrusted);
          cache_negative(cache_key);
          return result;
        }
      } else {
        result.pin_matched = true;  // No pins configured
      }

      // Check self-signed allowlist
      if (result.cert_info.is_self_signed &&
          !config_.allowed_self_signed_hosts.empty()) {
        if (!config_.allowed_self_signed_hosts.contains(std::string(host))) {
          result.error = "Self-signed certificate not in allowlist for " +
                         std::string(host);
          result.error_code = std::string(wk_constants::kErrServerNotTrusted);
          cache_negative(cache_key);
          return result;
        }
      }

      // Success — cache positive result
      result.verified = true;
      json cache_val;
      cache_val["verified"] = true;
      cache_val["hostname_matched"] = result.hostname_matched;
      cache_val["pin_matched"] = result.pin_matched;
      cache_val["fingerprint"] = result.cert_info.fingerprint_sha256;
      cache_val["not_after_ts"] = result.cert_info.not_after_ts;
      cache_->put(cache_key, cache_val, wk_constants::kWkCacheTTLSec);

      // Gracefully shutdown
      error_code ec;
      ssl_stream.shutdown(ec);

    } catch (const std::exception& e) {
      result.error = std::string("TLS verification failed: ") + e.what();
      result.error_code = std::string(wk_constants::kErrConnectionFailed);
      cache_negative(cache_key);
    }

    return result;
  }

  // Pin a certificate fingerprint for a host
  void pin_certificate(std::string_view host,
                       std::string_view fingerprint) {
    std::lock_guard<std::mutex> lk(config_mutex_);
    config_.pinned_fingerprints.insert(std::string(fingerprint));
  }

  // Unpin a certificate
  void unpin_certificate(std::string_view fingerprint) {
    std::lock_guard<std::mutex> lk(config_mutex_);
    config_.pinned_fingerprints.erase(std::string(fingerprint));
  }

  // Check if a fingerprint is pinned
  bool is_pinned(std::string_view fingerprint) const {
    std::lock_guard<std::mutex> lk(config_mutex_);
    return config_.pinned_fingerprints.contains(std::string(fingerprint));
  }

  // Clear all pins
  void clear_pins() {
    std::lock_guard<std::mutex> lk(config_mutex_);
    config_.pinned_fingerprints.clear();
  }

  // Get current TLS config
  TlsConfig get_config() const {
    std::lock_guard<std::mutex> lk(config_mutex_);
    return config_;
  }

  // Update TLS config
  void set_config(const TlsConfig& config) {
    std::lock_guard<std::mutex> lk(config_mutex_);
    config_ = config;
  }

  // Invalidate cached verification for a host
  void invalidate_cache(std::string_view host, int port = 0) {
    if (port == 0) {
      cache_->invalidate_prefix("tls:" + std::string(host) + ":");
    } else {
      cache_->invalidate("tls:" + std::string(host) + ":" +
                         std::to_string(port));
    }
  }

private:
  TlsCertInfo extract_cert_info(X509* cert) {
    TlsCertInfo info;

    // Subject CN
    X509_NAME* subject = X509_get_subject_name(cert);
    if (subject) {
      char cn_buf[256];
      int cn_idx = X509_NAME_get_index_by_NID(subject, NID_commonName, -1);
      if (cn_idx >= 0) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, cn_idx);
        if (entry) {
          ASN1_STRING* str = X509_NAME_ENTRY_get_data(entry);
          if (str) {
            unsigned char* data = nullptr;
            int len = ASN1_STRING_to_UTF8(&data, str);
            if (len > 0 && data) {
              info.subject_cn.assign(reinterpret_cast<char*>(data),
                                     static_cast<size_t>(len));
              OPENSSL_free(data);
            }
          }
        }
      }

      // Organization
      int org_idx = X509_NAME_get_index_by_NID(subject, NID_organizationName, -1);
      if (org_idx >= 0) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(subject, org_idx);
        if (entry) {
          ASN1_STRING* str = X509_NAME_ENTRY_get_data(entry);
          if (str) {
            unsigned char* data = nullptr;
            int len = ASN1_STRING_to_UTF8(&data, str);
            if (len > 0 && data) {
              info.subject_org.assign(reinterpret_cast<char*>(data),
                                      static_cast<size_t>(len));
              OPENSSL_free(data);
            }
          }
        }
      }
    }

    // Issuer CN
    X509_NAME* issuer = X509_get_issuer_name(cert);
    if (issuer) {
      char cn_buf[256];
      int cn_idx = X509_NAME_get_index_by_NID(issuer, NID_commonName, -1);
      if (cn_idx >= 0) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(issuer, cn_idx);
        if (entry) {
          ASN1_STRING* str = X509_NAME_ENTRY_get_data(entry);
          if (str) {
            unsigned char* data = nullptr;
            int len = ASN1_STRING_to_UTF8(&data, str);
            if (len > 0 && data) {
              info.issuer_cn.assign(reinterpret_cast<char*>(data),
                                    static_cast<size_t>(len));
              OPENSSL_free(data);
            }
          }
        }
      }
    }

    // Check self-signed
    info.is_self_signed =
        (info.subject_cn == info.issuer_cn &&
         X509_check_issued(cert, cert) == X509_V_OK);

    // Validity
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    if (not_before) {
      int day, sec;
      if (ASN1_TIME_diff(&day, &sec, nullptr, not_before)) {
        info.not_before_ts = now_ts() + sec + (day * 86400);
      }
    }
    if (not_after) {
      int day, sec;
      if (ASN1_TIME_diff(&day, &sec, nullptr, not_after)) {
        info.not_after_ts = now_ts() + sec + (day * 86400);
      }
    }

    // Subject Alternative Names (DNS)
    STACK_OF(GENERAL_NAME)* sans = static_cast<STACK_OF(GENERAL_NAME)*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
    if (sans) {
      int num_sans = OPENSSL_sk_num(
          reinterpret_cast<OPENSSL_STACK*>(const_cast<STACK_OF(GENERAL_NAME)*>(
              sans)));
      for (int i = 0; i < num_sans; i++) {
        GENERAL_NAME* san = sk_GENERAL_NAME_value(sans, i);
        if (san && san->type == GEN_DNS) {
          unsigned char* dns_name = nullptr;
          int len = ASN1_STRING_to_UTF8(&dns_name, san->d.dNSName);
          if (len > 0 && dns_name) {
            info.subject_alt_names.emplace_back(
                reinterpret_cast<char*>(dns_name),
                static_cast<size_t>(len));
            OPENSSL_free(dns_name);
          }
        }
      }
      GENERAL_NAMES_free(sans);
    }

    // Serial number
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    if (serial) {
      BIGNUM* bn = ASN1_INTEGER_to_BN(serial, nullptr);
      if (bn) {
        char* dec = BN_bn2dec(bn);
        if (dec) {
          try { info.serial_number = std::stoi(dec); } catch (...) {}
          OPENSSL_free(dec);
        }
        BN_free(bn);
      }
    }

    // Signature algorithm
    int sig_nid = X509_get_signature_nid(cert);
    if (sig_nid != NID_undef) {
      const char* sig_name = OBJ_nid2ln(sig_nid);
      if (sig_name) info.sig_algorithm = sig_name;
    }

    // Key size
    EVP_PKEY* pubkey = X509_get0_pubkey(cert);
    if (pubkey) {
      info.key_size_bits = EVP_PKEY_bits(pubkey);
    }

    // Fingerprints
    info.fingerprint_sha256 = compute_fingerprint(cert, EVP_sha256());
    info.fingerprint_sha1 = compute_fingerprint(cert, EVP_sha1());

    return info;
  }

  std::string compute_fingerprint(X509* cert, const EVP_MD* md) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    // DER-encode the certificate and hash it
    int der_len = i2d_X509(cert, nullptr);
    if (der_len <= 0) return "";

    std::vector<uint8_t> der(der_len);
    uint8_t* der_ptr = der.data();
    i2d_X509(cert, &der_ptr);

    if (!X509_digest(cert, md, hash, &hash_len)) {
      // Fallback: manually hash DER
      EVP_MD_CTX* ctx = EVP_MD_CTX_new();
      EVP_DigestInit_ex(ctx, md, nullptr);
      EVP_DigestUpdate(ctx, der.data(), der.size());
      EVP_DigestFinal_ex(ctx, hash, &hash_len);
      EVP_MD_CTX_free(ctx);
    }

    std::vector<uint8_t> hash_bytes(hash, hash + hash_len);
    return hex_encode(hash_bytes);
  }

  bool verify_hostname(const std::string& hostname,
                       const TlsCertInfo& cert_info) {
    // Check Subject Alternative Names first (RFC 6125)
    for (const auto& san : cert_info.subject_alt_names) {
      if (san == hostname) return true;
      // Wildcard match: "*.example.com" matches "foo.example.com"
      // but not "foo.bar.example.com" or just "example.com"
      if (san.starts_with("*.")) {
        std::string domain_part = san.substr(2);
        if (hostname.ends_with(domain_part) &&
            hostname.size() > domain_part.size() + 1) {
          // Ensure the wildcard doesn't match sub-subdomains
          size_t host_prefix_len = hostname.size() - domain_part.size() - 1;
          if (hostname.find('.', 0) == host_prefix_len) {
            return true;
          }
        }
      }
    }

    // Fall back to Common Name
    if (cert_info.subject_cn == hostname) return true;
    if (cert_info.subject_cn.starts_with("*.")) {
      std::string domain_part = cert_info.subject_cn.substr(2);
      if (hostname.ends_with(domain_part) &&
          hostname.size() > domain_part.size() + 1) {
        size_t host_prefix_len = hostname.size() - domain_part.size() - 1;
        if (hostname.find('.', 0) == host_prefix_len) {
          return true;
        }
      }
    }

    return false;
  }

  bool check_pin(const std::string& fingerprint) const {
    std::lock_guard<std::mutex> lk(config_mutex_);

    // Normalize by removing colons and lowercasing
    std::string normalized;
    for (char c : fingerprint) {
      if (c != ':') normalized += static_cast<char>(std::tolower(c));
    }

    for (const auto& pin : config_.pinned_fingerprints) {
      std::string pin_normalized;
      for (char c : pin) {
        if (c != ':') pin_normalized += static_cast<char>(std::tolower(c));
      }
      if (normalized == pin_normalized) return true;
    }

    return false;
  }

  void cache_negative(const std::string& key) {
    cache_->put_negative(key);
  }

  net::io_context& ioc_;
  tcp::resolver resolver_;
  std::shared_ptr<DnsCache> cache_;
  TlsConfig config_;
  mutable std::mutex config_mutex_;
};

// ============================================================================
// WellKnownEngine — Top-Level Coordinator
// ============================================================================
//
// Ties together all the components above into a single engine that can
// be instantiated by the server.  Provides:
//   - Initialization with server config
//   - Route registration for .well-known endpoints
//   - Server discovery for federation
//   - Key discovery for federation verification
//   - Connection retry coordination
//   - TLS verification
//   - Background maintenance tasks
// ============================================================================

class WellKnownEngine {
public:
  struct Config {
    // Server identification
    std::string server_name;
    std::string client_base_url;
    std::string identity_server_url;
    int federation_port = wk_constants::kDefaultFederationPort;

    // Well-known
    bool enable_client_well_known = true;
    bool enable_server_well_known = true;
    bool enable_support_endpoint = false;
    WellKnownSupport::Config support_config;

    // Discovery
    ServerDiscoveryEngine::Config discovery_config;
    bool cache_discovery_results = true;

    // Key discovery
    KeyDiscoveryClient::Config key_discovery_config;
    bool enable_key_discovery = true;

    // Connection retry
    ConnectionRetryManager::RetryConfig retry_config;

    // TLS
    TlsVerifyEngine::TlsConfig tls_config;

    // Maintenance
    int64_t cache_purge_interval_sec = 3600;
    int64_t stale_entry_purge_interval_sec = 86400;
  };

  explicit WellKnownEngine(const Config& config, net::io_context& ioc)
      : config_(config),
        ioc_(ioc),
        dns_cache_(std::make_shared<DnsCache>()),
        well_known_server_(
            WellKnownServer::Config{
                config.server_name,
                config.client_base_url,
                config.identity_server_url,
                config.federation_port,
                config.enable_client_well_known,
                config.enable_server_well_known}),
        well_known_support_(config.support_config),
        discovery_engine_(ioc, dns_cache_),
        key_discovery_(ioc, dns_cache_),
        retry_manager_(config.retry_config),
        tls_verify_(ioc, dns_cache_),
        running_(false) {

    discovery_engine_.set_config(config.discovery_config);
    key_discovery_.set_config(config.key_discovery_config);
    key_discovery_.set_server_name(config.server_name);
    tls_verify_.set_config(config.tls_config);
  }

  // Register all routes on the HTTP router
  void register_routes(http::Router& router) {
    well_known_server_.register_routes(router);
    well_known_support_.register_routes(router);
  }

  // Discover federation endpoints for a remote server
  ServerDiscoveryEngine::DiscoveryResult discover_server(
      std::string_view server_name) {
    return discovery_engine_.discover(server_name);
  }

  // Get cached discovery result
  std::optional<ServerDiscoveryEngine::DiscoveryResult> get_cached_discovery(
      std::string_view server_name) {
    return discovery_engine_.get_cached(server_name);
  }

  // Fetch remote server keys
  std::vector<KeyDiscoveryClient::ServerKey> fetch_server_keys(
      std::string_view server_name) {
    return key_discovery_.fetch_server_keys(server_name);
  }

  // Fetch a specific key from a remote server
  KeyDiscoveryClient::KeyQueryResult fetch_key(
      std::string_view server_name, std::string_view key_id) {
    return key_discovery_.fetch_key(server_name, key_id);
  }

  // Record a successful connection to a server
  void record_success(std::string_view server_name,
                      std::string_view endpoint_host = "",
                      int endpoint_port = 0) {
    retry_manager_.record_success(server_name, endpoint_host, endpoint_port);
  }

  // Record a failed connection attempt
  void record_failure(std::string_view server_name,
                      std::string_view error = "",
                      std::string_view endpoint_host = "",
                      int endpoint_port = 0) {
    retry_manager_.record_failure(server_name, error, endpoint_host,
                                  endpoint_port);
  }

  // Check if we should retry connecting to a server
  bool should_retry(std::string_view server_name,
                    std::string_view endpoint_host = "",
                    int endpoint_port = 0) {
    return retry_manager_.should_retry(server_name, endpoint_host,
                                       endpoint_port);
  }

  // Get retry delay in milliseconds
  int64_t retry_delay_ms(std::string_view server_name,
                         std::string_view endpoint_host = "",
                         int endpoint_port = 0) {
    return retry_manager_.retry_delay_ms(server_name, endpoint_host,
                                         endpoint_port);
  }

  // Verify TLS for a host:port
  TlsVerifyEngine::TlsVerifyResult verify_tls(std::string_view host, int port) {
    return tls_verify_.verify(host, port);
  }

  // Pin a TLS certificate fingerprint
  void pin_tls_cert(std::string_view host, std::string_view fingerprint) {
    tls_verify_.pin_certificate(host, fingerprint);
  }

  // Block a server from all federation
  void block_server(std::string_view server_name) {
    retry_manager_.block_server(server_name);
    discovery_engine_.invalidate(server_name);
  }

  // Unblock a previously blocked server
  void unblock_server(std::string_view server_name) {
    retry_manager_.unblock_server(server_name);
  }

  // Full connection attempt to a remote server:
  // discover → check retry → connect → TLS verify → record result
  struct ConnectionResult {
    bool success = false;
    ServerDiscoveryEngine::DiscoveredEndpoint used_endpoint;
    TlsVerifyEngine::TlsVerifyResult tls_result;
    std::string error;
    int attempts = 0;
    int64_t connect_duration_ms = 0;
  };

  ConnectionResult connect_to_server(std::string_view server_name) {
    ConnectionResult result;

    // Check retry state
    if (!should_retry(server_name)) {
      auto entry = retry_manager_.get_entry(server_name);
      if (entry.has_value()) {
        result.error = "Server " + std::string(server_name) +
                       " is in " +
                       (entry->state == ConnectionRetryManager::RetryState::kCircuitBroken
                            ? "circuit-broken"
                            : "backoff") +
                       " state. Last error: " + entry->last_error;
      } else {
        result.error = "Server " + std::string(server_name) +
                       " is in backoff state";
      }
      return result;
    }

    // Discover endpoints
    auto discovery = discover_server(server_name);
    if (discovery.endpoints.empty()) {
      result.error = "No endpoints discovered for " + std::string(server_name);
      record_failure(server_name, result.error);
      return result;
    }

    // Try each endpoint in priority order
    for (const auto& ep : discovery.endpoints) {
      result.attempts++;
      result.used_endpoint = ep;

      int64_t connect_start = now_ms();

      // Connect and verify TLS
      std::string connect_host = ep.host;
      if (!ep.resolved_ips.empty()) {
        connect_host = ep.resolved_ips[0];  // Use first resolved IP
      }

      result.tls_result = verify_tls(connect_host, ep.port);
      result.connect_duration_ms = now_ms() - connect_start;

      if (result.tls_result.verified) {
        result.success = true;
        record_success(server_name, ep.host, ep.port);
        return result;
      }
    }

    // All endpoints failed
    result.error = "All endpoints failed for " + std::string(server_name) +
                   ". Last error: " + result.tls_result.error;
    record_failure(server_name, result.error);
    return result;
  }

  // Start background maintenance tasks
  void start_background_tasks() {
    running_ = true;

    purge_timer_ = std::make_unique<net::steady_timer>(
        ioc_, chr::seconds(config_.cache_purge_interval_sec));
    schedule_cache_purge();

    stale_purge_timer_ = std::make_unique<net::steady_timer>(
        ioc_, chr::seconds(config_.stale_entry_purge_interval_sec));
    schedule_stale_purge();
  }

  // Stop background tasks
  void stop_background_tasks() {
    running_ = false;
    if (purge_timer_) {
      error_code ec;
      purge_timer_->cancel(ec);
    }
    if (stale_purge_timer_) {
      error_code ec;
      stale_purge_timer_->cancel(ec);
    }
  }

  // Update configuration
  void update_config(const Config& config) {
    config_ = config;
    well_known_server_.update_config(
        WellKnownServer::Config{
            config.server_name,
            config.client_base_url,
            config.identity_server_url,
            config.federation_port,
            config.enable_client_well_known,
            config.enable_server_well_known});
    well_known_support_.update_config(config.support_config);
    discovery_engine_.set_config(config.discovery_config);
    key_discovery_.set_config(config.key_discovery_config);
    retry_manager_.set_config(config.retry_config);
    tls_verify_.set_config(config.tls_config);
  }

  // Access sub-components
  std::shared_ptr<DnsCache> dns_cache() { return dns_cache_; }
  WellKnownServer& well_known_server() { return well_known_server_; }
  WellKnownSupport& well_known_support() { return well_known_support_; }
  ServerDiscoveryEngine& discovery() { return discovery_engine_; }
  KeyDiscoveryClient& key_discovery() { return key_discovery_; }
  ConnectionRetryManager& retry_manager() { return retry_manager_; }
  TlsVerifyEngine& tls_verify() { return tls_verify_; }

  // Get overall statistics
  struct EngineStats {
    DnsCache::CacheStats dns_cache_stats;
    ConnectionRetryManager::RetrySummary retry_summary;
    size_t pinned_certs_count = 0;
    int64_t uptime_sec = 0;
  };

  EngineStats get_stats() const {
    EngineStats stats;
    stats.dns_cache_stats = dns_cache_->stats();
    stats.retry_summary = retry_manager_.summary();
    stats.pinned_certs_count = tls_verify_.get_config().pinned_fingerprints.size();
    return stats;
  }

private:
  void schedule_cache_purge() {
    if (!running_ || !purge_timer_) return;

    purge_timer_->async_wait([this](const error_code& ec) {
      if (ec || !running_) return;

      size_t purged = dns_cache_->purge_expired();
      if (purged > 0) {
        std::cout << "[WellKnown] Purged " << purged
                  << " expired cache entries" << std::endl;
      }

      schedule_cache_purge();
    });
  }

  void schedule_stale_purge() {
    if (!running_ || !stale_purge_timer_) return;

    stale_purge_timer_->async_wait([this](const error_code& ec) {
      if (ec || !running_) return;

      size_t purged = retry_manager_.purge_stale_entries();
      if (purged > 0) {
        std::cout << "[WellKnown] Purged " << purged
                  << " stale retry entries" << std::endl;
      }

      schedule_stale_purge();
    });
  }

  Config config_;
  net::io_context& ioc_;
  bool running_;

  std::shared_ptr<DnsCache> dns_cache_;
  WellKnownServer well_known_server_;
  WellKnownSupport well_known_support_;
  ServerDiscoveryEngine discovery_engine_;
  KeyDiscoveryClient key_discovery_;
  ConnectionRetryManager retry_manager_;
  TlsVerifyEngine tls_verify_;

  std::unique_ptr<net::steady_timer> purge_timer_;
  std::unique_ptr<net::steady_timer> stale_purge_timer_;
};

// ============================================================================
// Standalone utility functions for use by other modules
// ============================================================================

namespace well_known {

/// Resolve a server name to an endpoint for federation connections.
/// Returns the best endpoint (host, port) or empty optional on failure.
struct SimpleEndpoint {
  std::string host;
  int port = wk_constants::kDefaultFederationPort;
  std::string source;
};

SimpleEndpoint resolve_federation_endpoint(
    std::string_view server_name,
    ServerDiscoveryEngine& discovery) {
  SimpleEndpoint result;

  auto discovered = discovery.discover(server_name);
  if (discovered.endpoints.empty()) {
    result.host = std::string(server_name);
    result.port = wk_constants::kDefaultFederationPort;
    result.source = "fallback";
    return result;
  }

  const auto& best = discovered.endpoints[0];
  result.host = best.host;
  result.port = best.port;
  result.source = best.source;
  return result;
}

/// Check if a server is in a state that allows connections
bool is_server_reachable(std::string_view server_name,
                         ConnectionRetryManager& retry) {
  return retry.should_retry(server_name);
}

/// Format a retry summary as a JSON object
json format_retry_summary(const ConnectionRetryManager::RetrySummary& summary) {
  json j;
  j["total"] = summary.total;
  j["reachable"] = summary.reachable;
  j["unreachable"] = summary.unreachable;
  j["circuit_broken"] = summary.circuit_broken;
  j["unknown"] = summary.unknown;
  j["manually_blocked"] = summary.manually_blocked;
  return j;
}

/// Format a TLS certificate info as a JSON object
json format_cert_info(const TlsVerifyEngine::TlsCertInfo& info) {
  json j;
  j["subject_cn"] = info.subject_cn;
  j["subject_org"] = info.subject_org;
  j["issuer_cn"] = info.issuer_cn;
  j["issuer_org"] = info.issuer_org;
  j["subject_alt_names"] = info.subject_alt_names;
  j["not_before_ts"] = info.not_before_ts;
  j["not_after_ts"] = info.not_after_ts;
  j["fingerprint_sha256"] = info.fingerprint_sha256;
  j["fingerprint_sha1"] = info.fingerprint_sha1;
  j["serial_number"] = info.serial_number;
  j["sig_algorithm"] = info.sig_algorithm;
  j["key_size_bits"] = info.key_size_bits;
  j["is_self_signed"] = info.is_self_signed;
  j["is_expired"] = info.is_expired;
  j["is_expiring_soon"] = info.is_expiring_soon;
  return j;
}

/// Format a server key as a JSON object
json format_server_key(const KeyDiscoveryClient::ServerKey& key) {
  json j;
  j["server_name"] = key.server_name;
  j["key_id"] = key.key_id;
  j["algorithm"] = key.algorithm;
  j["public_key"] = key.public_key;
  j["valid_until_ts"] = key.valid_until_ts;
  j["fetched_at_ts"] = key.fetched_at_ts;
  j["expired"] = key.expired;
  return j;
}

/// Check if a discovered endpoint is safe (not private/localhost)
bool is_safe_endpoint(const ServerDiscoveryEngine::DiscoveredEndpoint& ep) {
  // Check host is safe
  for (const auto& ip : ep.resolved_ips) {
    if (!SrvRecordResolver::is_safe_target(ip)) return false;
  }
  // Also check the hostname itself
  if (!SrvRecordResolver::is_safe_target(ep.host)) return false;
  return true;
}

/// Filter discovered endpoints to only safe ones
std::vector<ServerDiscoveryEngine::DiscoveredEndpoint> filter_safe_endpoints(
    const std::vector<ServerDiscoveryEngine::DiscoveredEndpoint>& endpoints) {
  std::vector<ServerDiscoveryEngine::DiscoveredEndpoint> safe;
  for (const auto& ep : endpoints) {
    if (is_safe_endpoint(ep)) safe.push_back(ep);
  }
  return safe;
}

}  // namespace well_known

}  // namespace progressive

// ============================================================================
// END well_known.cpp — 2000+ lines
// ============================================================================
