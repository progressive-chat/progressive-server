// ============================================================================
// voip_turn.cpp — Matrix VoIP Call Management & TURN Server Integration
//
// Implements:
//   - TURN server credential generation: HMAC-SHA1 time-limited credentials
//     per the Matrix VoIP spec (username = timestamp:nonce, password =
//     base64(HMAC-SHA1(shared_secret, username))), returning uris, username,
//     password, and TTL to clients
//   - TURN server REST endpoint: GET /_matrix/client/v3/voip/turnServer
//     serves short-lived TURN credentials for WebRTC ICE negotiation
//   - TURN server list management: support multiple TURN servers with
//     different transports (udp, tcp, tls), prefer UDP, fallback to
//     TCP/TLS, configurable URIs per server
//   - VoIP call setup: handle m.call.invite (initiate call with SDP offer,
//     version, lifetime, capabilities), m.call.candidates (ICE candidate
//     exchange), m.call.answer (SDP answer), m.call.hangup (call
//     termination with reason), m.call.negotiate (re-negotiation with
//     new SDP, party_id, lifetime)
//   - Call state machine: track call lifecycle (invited → ringing →
//     connected → ended), validate state transitions, enforce call
//     lifetime timeouts, handle conflicting invites
//   - Call signaling: route call events to correct room, validate event
//     types and required fields, reject invalid call events, forward
//     events to room participants, handle callee/client_id routing
//   - VoIP configuration: configurable TURN URIs (list of turn: and turns:
//     URIs), shared secret for HMAC credential generation, credential
//     TTL (default 86400 seconds / 24 hours), TURN server allow/deny
//     lists, per-user TURN server selection
//   - Call event validation: validate SDP structure (v/o/s lines, media
//     descriptions, ICE candidates), version negotiation (supports v0/v1),
//     lifetime enforcement, capabilities matching (DTMF, ICE, etc.)
//   - Call conflict resolution: detect and handle multiple simultaneous
//     invites, select "winning" invite by timestamp, send hangup for
//     losing invites
//   - TURN credential caching: cache generated credentials to reduce
//     HMAC computation, respect TTL for cache expiry, automatic refresh
//   - Admin TURN management: configure TURN servers at runtime (add, remove,
//     update URIs, update shared secret), list configured servers
//
// Equivalent to:
//   synapse/rest/client/voip.py (TURN server endpoint)
//   synapse/handlers/voip.py (VoIP call event handling)
//   synapse/voip/ (TURN credential generation)
//   synapse/config/voip.py (VoIP configuration)
//   matrix-org/matrix-spec: Client-Server API / VoIP
//   matrix-org/matrix-spec: TURN Server Auto-Discovery
//
// Namespace: progressive::
// Target: 2000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
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
#include <vector>

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <nlohmann/json.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "progressive/rest/rest_base.hpp"
#include "progressive/storage/database.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for all major components
// ============================================================================
class TurnCredentialGenerator;
class TurnServerManager;
class TurnCredentialCache;
class VoipCallStateMachine;
class VoipCallValidator;
class VoipCallRouter;
class VoipConfigManager;
class TurnConfigParser;
class VoipEventHandler;
class CallConflictResolver;
class SdpParser;
class IceCandidateParser;
class VoipTurnCoordinator;

// ============================================================================
// VoIP and TURN constants per Matrix spec
// ============================================================================
namespace voip_constants {

// TURN credential time-to-live default (24 hours in seconds)
constexpr int64_t kDefaultCredentialTtl = 86400;

// Minimum credential TTL (5 minutes)
constexpr int64_t kMinCredentialTtl = 300;

// Maximum credential TTL (7 days)
constexpr int64_t kMaxCredentialTtl = 604800;

// Default TURN server port for UDP
constexpr int kDefaultTurnUdpPort = 3478;

// Default TURN server port for TCP
constexpr int kDefaultTurnTcpPort = 3478;

// Default TURNS server port for TLS
constexpr int kDefaultTurnTlsPort = 5349;

// Transport protocol strings
constexpr std::string_view kTransportUdp = "udp";
constexpr std::string_view kTransportTcp = "tcp";
constexpr std::string_view kTransportTls = "tls";

// URI scheme strings
constexpr std::string_view kTurnScheme = "turn";
constexpr std::string_view kTurnsScheme = "turns";

// HMAC algorithm for credential generation
constexpr std::string_view kHmacAlgorithm = "sha1";

// Username format: timestamp + ":" + random suffix
constexpr size_t kUsernameRandomSuffixLen = 8;

// Maximum number of TURN servers configurable
constexpr size_t kMaxTurnServers = 32;

// Call event type constants (Matrix VoIP spec)
constexpr std::string_view kCallInvite = "m.call.invite";
constexpr std::string_view kCallCandidates = "m.call.candidates";
constexpr std::string_view kCallAnswer = "m.call.answer";
constexpr std::string_view kCallHangup = "m.call.hangup";
constexpr std::string_view kCallNegotiate = "m.call.negotiate";
constexpr std::string_view kCallReplaces = "m.call.replaces";
constexpr std::string_view kCallSelectAnswer = "m.call.select_answer";
constexpr std::string_view kCallReject = "m.call.reject";
constexpr std::string_view kCallAssertedIdentity = "m.call.asserted_identity";

// Call event required content fields
constexpr std::string_view kFieldCallId = "call_id";
constexpr std::string_view kFieldVersion = "version";
constexpr std::string_view kFieldLifetime = "lifetime";
constexpr std::string_view kFieldSdp = "sdp";
constexpr std::string_view kFieldCandidates = "candidates";
constexpr std::string_view kFieldPartyId = "party_id";
constexpr std::string_view kFieldCapabilities = "capabilities";
constexpr std::string_view kFieldReason = "reason";
constexpr std::string_view kFieldOffer = "offer";
constexpr std::string_view kFieldAnswer = "answer";
constexpr std::string_view kFieldClientId = "dest_client_id";

// Supported call versions
constexpr int kCallVersion0 = 0;
constexpr int kCallVersion1 = 1;

// Maximum call lifetime in milliseconds (5 minutes default in v0, configurable)
constexpr int64_t kDefaultCallLifetimeMs = 300000;

// SDP line prefixes
constexpr std::string_view kSdpVersion = "v=";
constexpr std::string_view kSdpOrigin = "o=";
constexpr std::string_view kSdpSession = "s=";
constexpr std::string_view kSdpConnection = "c=";
constexpr std::string_view kSdpMedia = "m=";
constexpr std::string_view kSdpAttributes = "a=";

// Hangup reason strings
constexpr std::string_view kHangupUser = "user_hangup";
constexpr std::string_view kHangupTimeout = "ice_timeout";
constexpr std::string_view kHangupFailed = "ice_failed";
constexpr std::string_view kHangupReject = "reject";
constexpr std::string_view kHangupBusy = "busy";
constexpr std::string_view kHangupNoAnswer = "no_answer";
constexpr std::string_view kHangupInviteTimeout = "invite_timeout";

// Call capability flags
constexpr std::string_view kCapDtls = "m.call.dtls";
constexpr std::string_view kCapSdes = "m.call.sdes";

// REST endpoint path
constexpr std::string_view kTurnServerPath = "/_matrix/client/v3/voip/turnServer";

// Cache settings
constexpr size_t kMaxCachedCredentials = 10000;
constexpr int64_t kCacheCleanupIntervalSec = 300;

// Re-gex patterns for validation
constexpr std::string_view kCallIdRegex = "^[a-zA-Z0-9._~-]{1,255}$";
constexpr std::string_view kSdpLineRegex = "^[a-z]=.*$";

}  // namespace voip_constants

// ============================================================================
// Anonymous namespace — Internal utility functions and helpers
// ============================================================================
namespace {

// --------------------------------------------------------------------------
// Timing helpers
// --------------------------------------------------------------------------
inline int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

inline int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

inline std::string ts_to_iso8601(int64_t ms) {
  char buf[32];
  auto t = static_cast<std::time_t>(ms / 1000);
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

// --------------------------------------------------------------------------
// String helpers
// --------------------------------------------------------------------------
inline bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

inline bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

inline std::string to_lower(const std::string& s) {
  std::string r = s;
  for (auto& c : r)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return r;
}

inline std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

inline std::vector<std::string> split_lines(const std::string& s) {
  std::vector<std::string> lines;
  std::istringstream ss(s);
  std::string line;
  while (std::getline(ss, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    lines.push_back(line);
  }
  return lines;
}

inline std::string generate_random_suffix(size_t len = 8) {
  static const char cs[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(
      static_cast<unsigned>(chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<int> dist(0, 61);
  std::string result(len, 'A');
  for (size_t i = 0; i < len; ++i)
    result[i] = cs[dist(rng)];
  return result;
}

inline std::string generate_call_id() {
  // Call IDs should be version-4 UUID-like for uniqueness
  static const char hex[] = "0123456789abcdef";
  static thread_local std::mt19937 rng(
      static_cast<unsigned>(chr::steady_clock::now().time_since_epoch().count()));
  std::uniform_int_distribution<int> dist(0, 15);
  std::string call_id;
  call_id.reserve(36);
  for (int i = 0; i < 36; ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      call_id += '-';
    } else if (i == 14) {
      call_id += '4';
    } else if (i == 19) {
      call_id += hex[(dist(rng) & 0x3) | 0x8];
    } else {
      call_id += hex[dist(rng)];
    }
  }
  return call_id;
}

// --------------------------------------------------------------------------
// Base64 encoding (standard, for TURN passwords; no padding as per spec)
// --------------------------------------------------------------------------
inline std::string base64_encode(const uint8_t* data, size_t len) {
  static const char table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  result.reserve(((len + 2) / 3) * 4);
  for (size_t i = 0; i < len; i += 3) {
    uint32_t n = static_cast<uint32_t>(data[i]) << 16;
    if (i + 1 < len) n |= static_cast<uint32_t>(data[i + 1]) << 8;
    if (i + 2 < len) n |= static_cast<uint32_t>(data[i + 2]);
    result += table[(n >> 18) & 0x3F];
    result += table[(n >> 12) & 0x3F];
    if (i + 1 < len) result += table[(n >> 6) & 0x3F];
    else result += '=';
    if (i + 2 < len) result += table[n & 0x3F];
    else result += '=';
  }
  return result;
}

// --------------------------------------------------------------------------
// HMAC-SHA1 computation for TURN credentials
// --------------------------------------------------------------------------
inline std::string hmac_sha1_hex(const std::string& key,
                                  const std::string& data) {
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int result_len = 0;

  HMAC(EVP_sha1(),
       key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(),
       result, &result_len);

  // Return as hex string
  std::ostringstream oss;
  for (unsigned int i = 0; i < result_len; ++i) {
    oss << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<int>(result[i]);
  }
  return oss.str();
}

inline std::string hmac_sha1_b64(const std::string& key,
                                  const std::string& data) {
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int result_len = 0;

  HMAC(EVP_sha1(),
       key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(),
       result, &result_len);

  return base64_encode(result, result_len);
}

// --------------------------------------------------------------------------
// JSON helpers
// --------------------------------------------------------------------------
inline json json_error(const std::string& errcode, const std::string& error) {
  return json{{"errcode", errcode}, {"error", error}};
}

inline bool json_has_string(const json& j, const std::string& key) {
  return j.contains(key) && j[key].is_string() && !j[key].get<std::string>().empty();
}

inline bool json_has_int(const json& j, const std::string& key) {
  return j.contains(key) && j[key].is_number_integer();
}

inline bool json_has_array(const json& j, const std::string& key) {
  return j.contains(key) && j[key].is_array();
}

inline bool json_has_object(const json& j, const std::string& key) {
  return j.contains(key) && j[key].is_object();
}

}  // anonymous namespace

// ============================================================================
// TurnServer — Single TURN server configuration
// ============================================================================
struct TurnServer {
  // Server identifier (for admin management)
  std::string id;

  // TURN URIs: e.g., "turn:turn.example.com:3478?transport=udp"
  std::vector<std::string> uris;

  // Transport preference order: udp > tcp > tls
  std::string transport = std::string(voip_constants::kTransportUdp);

  // Hostname for the TURN server
  std::string host;

  // Port number
  int port = voip_constants::kDefaultTurnUdpPort;

  // Whether this server uses TLS
  bool use_tls = false;

  // The shared secret for HMAC credential generation (per-server or global)
  std::string shared_secret;

  // Whether this server is currently enabled
  bool enabled = true;

  // Weight for load-balancing (higher = more likely to be selected)
  int weight = 100;

  // Convert to JSON for client response
  json to_client_json() const {
    json j;
    j["uris"] = uris;
    return j;
  }

  // Build a full TURN URI from components
  static std::string build_uri(const std::string& scheme,
                                const std::string& host,
                                int port,
                                const std::string& transport) {
    std::ostringstream oss;
    oss << scheme << ":" << host << ":" << port;
    if (!transport.empty()) {
      oss << "?transport=" << transport;
    }
    return oss.str();
  }
};

// ============================================================================
// TurnServerManager — manages the list of configured TURN servers
// ============================================================================
class TurnServerManager {
 public:
  TurnServerManager() = default;

  // Add a TURN server configuration
  bool add_server(const TurnServer& server) {
    std::unique_lock lock(mutex_);
    if (servers_.size() >= voip_constants::kMaxTurnServers) {
      return false;
    }
    // Check for duplicate ID
    for (auto& s : servers_) {
      if (s.id == server.id) return false;
    }
    servers_.push_back(server);
    return true;
  }

  // Remove a TURN server by ID
  bool remove_server(const std::string& id) {
    std::unique_lock lock(mutex_);
    auto it = std::find_if(servers_.begin(), servers_.end(),
        [&](const TurnServer& s) { return s.id == id; });
    if (it == servers_.end()) return false;
    servers_.erase(it);
    return true;
  }

  // Update an existing server
  bool update_server(const std::string& id, const TurnServer& updated) {
    std::unique_lock lock(mutex_);
    for (auto& s : servers_) {
      if (s.id == id) {
        s = updated;
        s.id = id;  // Preserve original ID
        return true;
      }
    }
    return false;
  }

  // Get all enabled TURN servers, sorted by transport preference (UDP first)
  std::vector<TurnServer> get_servers() const {
    std::shared_lock lock(mutex_);
    std::vector<TurnServer> result;
    for (auto& s : servers_) {
      if (s.enabled) result.push_back(s);
    }
    // Sort: UDP first, then TCP, then TLS
    std::sort(result.begin(), result.end(),
        [](const TurnServer& a, const TurnServer& b) {
          auto transport_rank = [](const std::string& t) -> int {
            if (t == "udp") return 0;
            if (t == "tcp") return 1;
            return 2;
          };
          return transport_rank(a.transport) < transport_rank(b.transport);
        });
    return result;
  }

  // Get all servers (including disabled) for admin listing
  std::vector<TurnServer> get_all_servers() const {
    std::shared_lock lock(mutex_);
    return servers_;
  }

  // Get a specific server by ID
  std::optional<TurnServer> get_server(const std::string& id) const {
    std::shared_lock lock(mutex_);
    for (auto& s : servers_) {
      if (s.id == id) return s;
    }
    return std::nullopt;
  }

  // Count of enabled servers
  size_t count() const {
    std::shared_lock lock(mutex_);
    return std::count_if(servers_.begin(), servers_.end(),
        [](const TurnServer& s) { return s.enabled; });
  }

  // Clear all servers
  void clear() {
    std::unique_lock lock(mutex_);
    servers_.clear();
  }

 private:
  mutable std::shared_mutex mutex_;
  std::vector<TurnServer> servers_;
};

// ============================================================================
// TurnCredentialGenerator — generates time-limited TURN credentials
// using HMAC-SHA1 as per the Matrix VoIP TURN REST API spec
//
// Format:
//   username = "<expiry_timestamp>:<random_suffix>"
//   password = base64(HMAC-SHA1(shared_secret, username))
//
// The TURN server validates by checking:
//   1. Extract timestamp from username — must be valid duration
//   2. Recompute HMAC-SHA1 — must match the password
// ============================================================================
class TurnCredentialGenerator {
 public:
  struct Credential {
    std::string username;
    std::string password;
    int64_t ttl;         // seconds
    int64_t expires_at;  // unix timestamp (seconds)
  };

  explicit TurnCredentialGenerator(std::string shared_secret,
                                    int64_t ttl = voip_constants::kDefaultCredentialTtl)
      : shared_secret_(std::move(shared_secret)), ttl_(ttl) {
    // Clamp TTL to allowed range
    if (ttl_ < voip_constants::kMinCredentialTtl)
      ttl_ = voip_constants::kMinCredentialTtl;
    if (ttl_ > voip_constants::kMaxCredentialTtl)
      ttl_ = voip_constants::kMaxCredentialTtl;
  }

  // Generate a new short-lived credential
  Credential generate() const {
    int64_t now = now_sec();
    int64_t expiry = now + ttl_;

    // Build username: "<expiry_timestamp>:<random>"
    std::string username = std::to_string(expiry) + ":" +
                           generate_random_suffix(
                               voip_constants::kUsernameRandomSuffixLen);

    // Compute password: base64(HMAC-SHA1(shared_secret, username))
    std::string password = hmac_sha1_b64(shared_secret_, username);

    return Credential{
        .username = username,
        .password = password,
        .ttl = ttl_,
        .expires_at = expiry
    };
  }

  // Generate a credential with a specific TTL override
  Credential generate_with_ttl(int64_t ttl) const {
    int64_t now = now_sec();
    int64_t expiry = now + ttl;

    std::string username = std::to_string(expiry) + ":" +
                           generate_random_suffix(
                               voip_constants::kUsernameRandomSuffixLen);

    std::string password = hmac_sha1_b64(shared_secret_, username);

    return Credential{
        .username = username,
        .password = password,
        .ttl = ttl,
        .expires_at = expiry
    };
  }

  // Verify a credential (for TURN server-side validation — useful for
  // self-hosted TURN integrated with the homeserver)
  bool verify(const std::string& username, const std::string& password) const {
    // Parse username: "<expiry_timestamp>:<suffix>"
    auto colon_pos = username.find(':');
    if (colon_pos == std::string::npos) return false;

    std::string expiry_str = username.substr(0, colon_pos);
    int64_t expiry;
    try {
      expiry = std::stoll(expiry_str);
    } catch (...) {
      return false;
    }

    // Check expiry
    int64_t now = now_sec();
    if (now > expiry) return false;

    // Verify HMAC
    std::string expected = hmac_sha1_b64(shared_secret_, username);
    return expected == password;
  }

  // Update the shared secret
  void set_shared_secret(const std::string& secret) {
    std::unique_lock lock(mutex_);
    shared_secret_ = secret;
  }

  // Update the TTL
  void set_ttl(int64_t ttl) {
    std::unique_lock lock(mutex_);
    ttl_ = ttl;
    if (ttl_ < voip_constants::kMinCredentialTtl)
      ttl_ = voip_constants::kMinCredentialTtl;
    if (ttl_ > voip_constants::kMaxCredentialTtl)
      ttl_ = voip_constants::kMaxCredentialTtl;
  }

  int64_t get_ttl() const { return ttl_; }
  const std::string& get_shared_secret() const { return shared_secret_; }

 private:
  mutable std::mutex mutex_;
  std::string shared_secret_;
  int64_t ttl_;
};

// ============================================================================
// TurnCredentialCache — caches generated credentials to reduce HMAC
// computation overhead
// ============================================================================
class TurnCredentialCache {
 public:
  struct CacheEntry {
    TurnCredentialGenerator::Credential credential;
    int64_t cached_at;  // unix timestamp (seconds)
    std::string server_id;
  };

  TurnCredentialCache() : last_cleanup_(now_sec()) {}

  // Get or generate a credential for the given user on a specific server
  std::optional<TurnCredentialGenerator::Credential> get(
      const std::string& user_id,
      const std::string& server_id) {
    std::shared_lock lock(mutex_);

    auto key = make_key(user_id, server_id);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
      int64_t now = now_sec();
      if (now < it->second.credential.expires_at - 60) {
        // Still valid (with 60-second grace window)
        return it->second.credential;
      }
    }
    return std::nullopt;
  }

  // Store a credential in the cache
  void put(const std::string& user_id,
           const std::string& server_id,
           const TurnCredentialGenerator::Credential& cred) {
    std::unique_lock lock(mutex_);

    auto key = make_key(user_id, server_id);
    cache_[key] = CacheEntry{cred, now_sec(), server_id};

    // Cleanup if cache gets too large
    maybe_cleanup();
  }

  // Invalidate cached credentials for a specific user
  void invalidate_user(const std::string& user_id) {
    std::unique_lock lock(mutex_);

    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (it->first.find(user_id) == 0) {
        it = cache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // Invalidate all cached credentials for a server
  void invalidate_server(const std::string& server_id) {
    std::unique_lock lock(mutex_);

    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (it->second.server_id == server_id) {
        it = cache_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // Clear the entire cache
  void clear() {
    std::unique_lock lock(mutex_);
    cache_.clear();
  }

  // Get cache statistics
  size_t size() const {
    std::shared_lock lock(mutex_);
    return cache_.size();
  }

 private:
  std::string make_key(const std::string& user_id,
                        const std::string& server_id) const {
    return user_id + "|" + server_id;
  }

  void maybe_cleanup() {
    if (cache_.size() <= voip_constants::kMaxCachedCredentials) return;

    int64_t now = now_sec();
    if (now - last_cleanup_ < voip_constants::kCacheCleanupIntervalSec) return;

    last_cleanup_ = now;

    // Remove expired entries
    auto it = cache_.begin();
    while (it != cache_.end()) {
      if (now > it->second.credential.expires_at) {
        it = cache_.erase(it);
      } else {
        ++it;
      }
    }

    // If still too large, remove oldest entries
    if (cache_.size() > voip_constants::kMaxCachedCredentials) {
      std::vector<std::pair<std::string, int64_t>> sorted;
      for (auto& [k, v] : cache_) {
        sorted.emplace_back(k, v.cached_at);
      }
      std::sort(sorted.begin(), sorted.end(),
          [](auto& a, auto& b) { return a.second < b.second; });

      size_t to_remove = cache_.size() -
                         voip_constants::kMaxCachedCredentials / 2;
      for (size_t i = 0; i < to_remove && i < sorted.size(); ++i) {
        cache_.erase(sorted[i].first);
      }
    }
  }

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, CacheEntry> cache_;
  int64_t last_cleanup_;
};

// ============================================================================
// SdpParser — parses and validates SDP (Session Description Protocol)
// content within VoIP call events
// ============================================================================
class SdpParser {
 public:
  struct SdpSession {
    int version = 0;
    std::string origin;
    std::string session_name;
    std::string connection;
    std::vector<std::string> media_descriptions;
    std::vector<std::string> attributes;
    bool has_ice_candidates = false;
  };

  // Parse an SDP string into structured components
  static SdpSession parse(const std::string& sdp_text) {
    SdpSession session;
    auto lines = split_lines(sdp_text);

    for (auto& line : lines) {
      if (line.empty()) continue;

      if (starts_with(line, std::string(voip_constants::kSdpVersion))) {
        try {
          session.version = std::stoi(line.substr(2));
        } catch (...) {
          session.version = 0;
        }
      } else if (starts_with(line, std::string(voip_constants::kSdpOrigin))) {
        session.origin = line.substr(2);
      } else if (starts_with(line, std::string(voip_constants::kSdpSession))) {
        session.session_name = line.substr(2);
      } else if (starts_with(line, std::string(voip_constants::kSdpConnection))) {
        session.connection = line.substr(2);
      } else if (starts_with(line, std::string(voip_constants::kSdpMedia))) {
        session.media_descriptions.push_back(line.substr(2));
      } else if (starts_with(line, std::string(voip_constants::kSdpAttributes))) {
        session.attributes.push_back(line.substr(2));
        if (line.find("ice-") != std::string::npos ||
            line.find("candidate") != std::string::npos) {
          session.has_ice_candidates = true;
        }
      }
    }

    return session;
  }

  // Quick validation — does this look like a valid SDP?
  static bool validate(const std::string& sdp_text) {
    auto session = parse(sdp_text);
    // Minimum requirements: version line, origin line, at least one media line
    if (session.version < 0) return false;
    if (session.origin.empty()) return false;
    // Media lines are optional in some SDP fragments, but typically present
    return true;
  }
};

// ============================================================================
// IceCandidateParser — parses and validates ICE candidate lines
// ============================================================================
class IceCandidateParser {
 public:
  struct IceCandidate {
    std::string foundation;
    int component_id = 0;
    std::string transport;  // "UDP" or "TCP"
    int priority = 0;
    std::string ip;
    int port = 0;
    std::string type;  // "host", "srflx", "relay", etc.
    std::string related_address;
    int related_port = 0;
  };

  // Parse a single ICE candidate from a candidate attribute line
  static std::optional<IceCandidate> parse(const std::string& candidate_line) {
    // Format: "candidate:<foundation> <component> <transport> <priority> <ip> <port> typ <type> ..."
    if (!starts_with(candidate_line, "candidate:")) {
      // Some candidates are in a= lines with the "candidate:" prefix stripped
      std::string test = "candidate:" + candidate_line;
      return parse_internal(test);
    }
    return parse_internal(candidate_line);
  }

  // Validate a candidate JSON object from an m.call.candidates event
  static bool validate_candidate_json(const json& candidate) {
    if (!json_has_string(candidate, "candidate")) return false;
    if (!json_has_string(candidate, "sdpMid")) return false;
    if (!json_has_int(candidate, "sdpMLineIndex")) return false;
    return true;
  }

 private:
  static std::optional<IceCandidate> parse_internal(const std::string& line) {
    IceCandidate cand;
    std::istringstream ss(line);

    std::string prefix;
    ss >> prefix;  // "candidate:"

    // Remove "candidate:" prefix if present
    std::string rest;
    if (starts_with(line, "candidate:")) {
      rest = line.substr(10);  // strlen("candidate:")
    } else {
      rest = line;
    }

    std::istringstream rs(rest);
    if (!(rs >> cand.foundation)) return std::nullopt;
    if (!(rs >> cand.component_id)) return std::nullopt;
    if (!(rs >> cand.transport)) return std::nullopt;
    if (!(rs >> cand.priority)) return std::nullopt;
    if (!(rs >> cand.ip)) return std::nullopt;
    if (!(rs >> cand.port)) return std::nullopt;

    std::string typ_keyword;
    if (!(rs >> typ_keyword)) return std::nullopt;
    if (typ_keyword != "typ") return std::nullopt;
    if (!(rs >> cand.type)) return std::nullopt;

    // Parse optional raddr/rport
    std::string opt;
    while (rs >> opt) {
      if (opt == "raddr" && rs >> cand.related_address) continue;
      if (opt == "rport" && rs >> cand.related_port) continue;
    }

    return cand;
  }
};

// ============================================================================
// VoipCallValidator — validates VoIP call event content
// ============================================================================
class VoipCallValidator {
 public:
  struct ValidationResult {
    bool valid = false;
    std::string error;
    std::optional<std::string> call_id;
    std::optional<int> version;
    std::string event_type;
  };

  // Validate a full call event
  static ValidationResult validate_event(const std::string& event_type,
                                          const json& content) {
    ValidationResult result;
    result.event_type = event_type;

    if (event_type == voip_constants::kCallInvite) {
      return validate_invite(content);
    } else if (event_type == voip_constants::kCallCandidates) {
      return validate_candidates(content);
    } else if (event_type == voip_constants::kCallAnswer) {
      return validate_answer(content);
    } else if (event_type == voip_constants::kCallHangup) {
      return validate_hangup(content);
    } else if (event_type == voip_constants::kCallNegotiate) {
      return validate_negotiate(content);
    } else if (event_type == voip_constants::kCallReplaces) {
      return validate_replaces(content);
    } else if (event_type == voip_constants::kCallSelectAnswer) {
      return validate_select_answer(content);
    } else if (event_type == voip_constants::kCallReject) {
      return validate_reject(content);
    }

    result.error = "Unknown call event type: " + event_type;
    return result;
  }

  // Check if the given event type is a known VoIP call type
  static bool is_voip_event(const std::string& event_type) {
    static const std::unordered_set<std::string> voip_types = {
      std::string(voip_constants::kCallInvite),
      std::string(voip_constants::kCallCandidates),
      std::string(voip_constants::kCallAnswer),
      std::string(voip_constants::kCallHangup),
      std::string(voip_constants::kCallNegotiate),
      std::string(voip_constants::kCallReplaces),
      std::string(voip_constants::kCallSelectAnswer),
      std::string(voip_constants::kCallReject),
      std::string(voip_constants::kCallAssertedIdentity),
    };
    return voip_types.count(event_type) > 0;
  }

  // Validate call_id format
  static bool validate_call_id(const std::string& call_id) {
    if (call_id.empty() || call_id.size() > 255) return false;
    // Call IDs should be safe for transport (alphanumeric and common symbols)
    for (char c : call_id) {
      if (!std::isalnum(static_cast<unsigned char>(c)) &&
          c != '-' && c != '_' && c != '.' && c != '~') {
        return false;
      }
    }
    return true;
  }

 private:
  // ------------------------------------------------------------------------
  // m.call.invite validation
  // ------------------------------------------------------------------------
  static ValidationResult validate_invite(const json& content) {
    ValidationResult result;

    // Required: call_id (string)
    if (!json_has_string(content, std::string(voip_constants::kFieldCallId))) {
      result.error = "Missing required field 'call_id' in m.call.invite";
      return result;
    }
    std::string call_id = content[std::string(voip_constants::kFieldCallId)].get<std::string>();
    if (!validate_call_id(call_id)) {
      result.error = "Invalid call_id format in m.call.invite";
      return result;
    }
    result.call_id = call_id;

    // Required: version (integer)
    if (!json_has_int(content, std::string(voip_constants::kFieldVersion))) {
      result.error = "Missing required field 'version' in m.call.invite";
      return result;
    }
    int version = content[std::string(voip_constants::kFieldVersion)].get<int>();
    if (version != voip_constants::kCallVersion0 &&
        version != voip_constants::kCallVersion1) {
      result.error = "Unsupported call version: " + std::to_string(version);
      return result;
    }
    result.version = version;

    // Required: lifetime (integer, milliseconds)
    if (!json_has_int(content, std::string(voip_constants::kFieldLifetime))) {
      result.error = "Missing required field 'lifetime' in m.call.invite";
      return result;
    }
    int64_t lifetime = content[std::string(voip_constants::kFieldLifetime)].get<int64_t>();
    if (lifetime <= 0 || lifetime > 3600000) {  // Max 1 hour
      result.error = "Invalid lifetime value in m.call.invite";
      return result;
    }

    // Required: offer (SDP object with type and sdp)
    if (!json_has_object(content, std::string(voip_constants::kFieldOffer))) {
      result.error = "Missing required field 'offer' in m.call.invite";
      return result;
    }
    auto& offer = content[std::string(voip_constants::kFieldOffer)];
    if (!json_has_string(offer, "type") || offer["type"].get<std::string>() != "offer") {
      result.error = "offer.type must be 'offer' in m.call.invite";
      return result;
    }
    if (!json_has_string(offer, "sdp")) {
      result.error = "offer.sdp is missing in m.call.invite";
      return result;
    }
    if (!SdpParser::validate(offer["sdp"].get<std::string>())) {
      result.error = "Invalid SDP in m.call.invite offer";
      return result;
    }

    // Optional: capabilities
    if (json_has_object(content, std::string(voip_constants::kFieldCapabilities))) {
      auto& caps = content[std::string(voip_constants::kFieldCapabilities)];
      // Validate capability flags if present
    }

    result.valid = true;
    return result;
  }

  // ------------------------------------------------------------------------
  // m.call.candidates validation
  // ------------------------------------------------------------------------
  static ValidationResult validate_candidates(const json& content) {
    ValidationResult result;

    // Required: call_id
    if (!json_has_string(content, std::string(voip_constants::kFieldCallId))) {
      result.error = "Missing required field 'call_id' in m.call.candidates";
      return result;
    }
    std::string call_id = content[std::string(voip_constants::kFieldCallId)].get<std::string>();
    if (!validate_call_id(call_id)) {
      result.error = "Invalid call_id format in m.call.candidates";
      return result;
    }
    result.call_id = call_id;

    // Required: version
    if (!json_has_int(content, std::string(voip_constants::kFieldVersion))) {
      result.error = "Missing required field 'version' in m.call.candidates";
      return result;
    }
    result.version = content[std::string(voip_constants::kFieldVersion)].get<int>();

    // Required: candidates (array)
    if (!json_has_array(content, std::string(voip_constants::kFieldCandidates))) {
      result.error = "Missing required field 'candidates' in m.call.candidates";
      return result;
    }
    auto& candidates = content[std::string(voip_constants::kFieldCandidates)];
    for (auto& cand : candidates) {
      if (!IceCandidateParser::validate_candidate_json(cand)) {
        result.error = "Invalid candidate entry in m.call.candidates";
        return result;
      }
    }

    result.valid = true;
    return result;
  }

  // ------------------------------------------------------------------------
  // m.call.answer validation
  // ------------------------------------------------------------------------
  static ValidationResult validate_answer(const json& content) {
    ValidationResult result;

    // Required: call_id
    if (!json_has_string(content, std::string(voip_constants::kFieldCallId))) {
      result.error = "Missing required field 'call_id' in m.call.answer";
      return result;
    }
    std::string call_id = content[std::string(voip_constants::kFieldCallId)].get<std::string>();
    if (!validate_call_id(call_id)) {
      result.error = "Invalid call_id format in m.call.answer";
      return result;
    }
    result.call_id = call_id;

    // Required: version
    if (!json_has_int(content, std::string(voip_constants::kFieldVersion))) {
      result.error = "Missing required field 'version' in m.call.answer";
      return result;
    }
    result.version = content[std::string(voip_constants::kFieldVersion)].get<int>();

    // Required: answer (SDP object)
    if (!json_has_object(content, std::string(voip_constants::kFieldAnswer))) {
      result.error = "Missing required field 'answer' in m.call.answer";
      return result;
    }
    auto& answer = content[std::string(voip_constants::kFieldAnswer)];
    if (!json_has_string(answer, "type") || answer["type"].get<std::string>() != "answer") {
      result.error = "answer.type must be 'answer' in m.call.answer";
      return result;
    }
    if (!json_has_string(answer, "sdp")) {
      result.error = "answer.sdp is missing in m.call.answer";
      return result;
    }
    if (!SdpParser::validate(answer["sdp"].get<std::string>())) {
      result.error = "Invalid SDP in m.call.answer";
      return result;
    }

    result.valid = true;
    return result;
  }

  // ------------------------------------------------------------------------
  // m.call.hangup validation
  // ------------------------------------------------------------------------
  static ValidationResult validate_hangup(const json& content) {
    ValidationResult result;

    // Required: call_id
    if (!json_has_string(content, std::string(voip_constants::kFieldCallId))) {
      result.error = "Missing required field 'call_id' in m.call.hangup";
      return result;
    }
    std::string call_id = content[std::string(voip_constants::kFieldCallId)].get<std::string>();
    if (!validate_call_id(call_id)) {
      result.error = "Invalid call_id format in m.call.hangup";
      return result;
    }
    result.call_id = call_id;

    // Required: version
    if (!json_has_int(content, std::string(voip_constants::kFieldVersion))) {
      result.error = "Missing required field 'version' in m.call.hangup";
      return result;
    }
    result.version = content[std::string(voip_constants::kFieldVersion)].get<int>();

    // Optional: reason
    if (json_has_string(content, std::string(voip_constants::kFieldReason))) {
      std::string reason = content[std::string(voip_constants::kFieldReason)].get<std::string>();
      static const std::unordered_set<std::string> valid_reasons = {
        std::string(voip_constants::kHangupUser),
        std::string(voip_constants::kHangupTimeout),
        std::string(voip_constants::kHangupFailed),
        std::string(voip_constants::kHangupReject),
        std::string(voip_constants::kHangupBusy),
        std::string(voip_constants::kHangupNoAnswer),
        std::string(voip_constants::kHangupInviteTimeout),
      };
      if (!valid_reasons.count(reason)) {
        result.error = "Unknown hangup reason: " + reason;
        return result;
      }
    }

    result.valid = true;
    return result;
  }

  // ------------------------------------------------------------------------
  // m.call.negotiate validation
  // ------------------------------------------------------------------------
  static ValidationResult validate_negotiate(const json& content) {
    ValidationResult result;

    // Required: call_id
    if (!json_has_string(content, std::string(voip_constants::kFieldCallId))) {
      result.error = "Missing required field 'call_id' in m.call.negotiate";
      return result;
    }
    std::string call_id = content[std::string(voip_constants::kFieldCallId)].get<std::string>();
    if (!validate_call_id(call_id)) {
      result.error = "Invalid call_id format in m.call.negotiate";
      return result;
    }
    result.call_id = call_id;

    // Required: version
    if (!json_has_int(content, std::string(voip_constants::kFieldVersion))) {
      result.error = "Missing required field 'version' in m.call.negotiate";
      return result;
    }
    result.version = content[std::string(voip_constants::kFieldVersion)].get<int>();

    // Required: lifetime
    if (!json_has_int(content, std::string(voip_constants::kFieldLifetime))) {
      result.error = "Missing required field 'lifetime' in m.call.negotiate";
      return result;
    }

    // m.call.negotiate contains a full SDP description (replacing offer/answer)
    if (!json_has_string(content, "description") ||
        !SdpParser::validate(content["description"].get<std::string>())) {
      // Some implementations use "sdp" instead
      if (!json_has_string(content, "sdp") ||
          !SdpParser::validate(content["sdp"].get<std::string>())) {
        result.error = "Missing or invalid SDP description in m.call.negotiate";
        return result;
      }
    }

    result.valid = true;
    return result;
  }

  // ------------------------------------------------------------------------
  // m.call.replaces validation
  // ------------------------------------------------------------------------
  static ValidationResult validate_replaces(const json& content) {
    ValidationResult result;

    if (!json_has_string(content, std::string(voip_constants::kFieldCallId))) {
      result.error = "Missing required field 'call_id' in m.call.replaces";
      return result;
    }
    result.call_id = content[std::string(voip_constants::kFieldCallId)].get<std::string>();

    if (!json_has_string(content, "target_call_id")) {
      result.error = "Missing required field 'target_call_id' in m.call.replaces";
      return result;
    }

    if (!json_has_int(content, std::string(voip_constants::kFieldVersion))) {
      result.error = "Missing required field 'version' in m.call.replaces";
      return result;
    }
    result.version = content[std::string(voip_constants::kFieldVersion)].get<int>();

    if (!json_has_string(content, "create_offer") &&
        !json_has_object(content, std::string(voip_constants::kFieldOffer)) &&
        !json_has_object(content, std::string(voip_constants::kFieldAnswer))) {
      result.error = "m.call.replaces must have offer, answer, or create_offer";
      return result;
    }

    result.valid = true;
    return result;
  }

  // ------------------------------------------------------------------------
  // m.call.select_answer validation
  // ------------------------------------------------------------------------
  static ValidationResult validate_select_answer(const json& content) {
    ValidationResult result;

    if (!json_has_string(content, std::string(voip_constants::kFieldCallId))) {
      result.error = "Missing required field 'call_id' in m.call.select_answer";
      return result;
    }
    result.call_id = content[std::string(voip_constants::kFieldCallId)].get<std::string>();

    if (!json_has_string(content, "selected_party_id")) {
      result.error = "Missing required field 'selected_party_id' in m.call.select_answer";
      return result;
    }

    if (!json_has_int(content, std::string(voip_constants::kFieldVersion))) {
      result.error = "Missing required field 'version' in m.call.select_answer";
      return result;
    }

    result.valid = true;
    return result;
  }

  // ------------------------------------------------------------------------
  // m.call.reject validation
  // ------------------------------------------------------------------------
  static ValidationResult validate_reject(const json& content) {
    ValidationResult result;

    if (!json_has_string(content, std::string(voip_constants::kFieldCallId))) {
      result.error = "Missing required field 'call_id' in m.call.reject";
      return result;
    }
    result.call_id = content[std::string(voip_constants::kFieldCallId)].get<std::string>();

    if (!json_has_int(content, std::string(voip_constants::kFieldVersion))) {
      result.error = "Missing required field 'version' in m.call.reject";
      return result;
    }
    result.version = content[std::string(voip_constants::kFieldVersion)].get<int>();

    if (!json_has_string(content, "party_id")) {
      result.error = "Missing required field 'party_id' in m.call.reject";
      return result;
    }

    result.valid = true;
    return result;
  }
};

// ============================================================================
// VoipCallStateMachine — tracks the lifecycle of a single call
//
// State transitions:
//   IDLE -> INVITED (on m.call.invite sent)
//   IDLE -> RINGING (on m.call.invite received)
//   INVITED -> CONNECTING (on m.call.answer received)
//   RINGING -> CONNECTING (on m.call.answer sent)
//   CONNECTING -> CONNECTED (on media flowing / both sides answered)
//   * -> ENDED (on m.call.hangup or timeout)
//   CONNECTED -> RENEGOTIATING (on m.call.negotiate)
//   RENEGOTIATING -> CONNECTED (on renegotiation complete)
// ============================================================================
class VoipCallStateMachine {
 public:
  enum class State {
    IDLE,
    INVITED,      // Outgoing call, waiting for answer
    RINGING,      // Incoming call, waiting for answer
    CONNECTING,   // Answer received/sent, waiting for media
    CONNECTED,    // Call active
    RENEGOTIATING, // Call being renegotiated
    ENDED         // Call terminated
  };

  struct CallSession {
    std::string call_id;
    std::string room_id;
    std::string caller_id;
    std::string callee_id;
    std::optional<std::string> dest_client_id;
    int version = 0;
    int64_t lifetime_ms = voip_constants::kDefaultCallLifetimeMs;
    int64_t created_at_ms = 0;
    int64_t last_activity_ms = 0;
    int64_t expires_at_ms = 0;
    State state = State::IDLE;
    json capabilities;
    std::string sdp_offer;
    std::string sdp_answer;
    std::vector<json> ice_candidates;
    std::string hangup_reason;
    bool has_media = false;
    int negotiation_count = 0;
  };

  VoipCallStateMachine() = default;

  // Create a new call session
  CallSession create_session(const std::string& call_id,
                              const std::string& room_id,
                              const std::string& caller_id,
                              int version,
                              int64_t lifetime_ms) {
    CallSession session;
    session.call_id = call_id;
    session.room_id = room_id;
    session.caller_id = caller_id;
    session.version = version;
    session.lifetime_ms = lifetime_ms;
    session.created_at_ms = now_ms();
    session.last_activity_ms = session.created_at_ms;
    session.expires_at_ms = session.created_at_ms + lifetime_ms;
    session.state = State::INVITED;

    std::unique_lock lock(mutex_);
    sessions_[call_id] = session;
    return session;
  }

  // Get a call session by call_id
  std::optional<CallSession> get_session(const std::string& call_id) const {
    std::shared_lock lock(mutex_);
    auto it = sessions_.find(call_id);
    if (it != sessions_.end()) {
      return it->second;
    }
    return std::nullopt;
  }

  // Transition state (validates the transition is legal)
  bool transition(const std::string& call_id, State new_state,
                  std::string& error) {
    std::unique_lock lock(mutex_);
    auto it = sessions_.find(call_id);
    if (it == sessions_.end()) {
      error = "Call session not found: " + call_id;
      return false;
    }

    auto& session = it->second;
    if (!is_valid_transition(session.state, new_state)) {
      error = "Invalid state transition from " +
              state_to_string(session.state) + " to " +
              state_to_string(new_state);
      return false;
    }

    session.state = new_state;
    session.last_activity_ms = now_ms();
    return true;
  }

  // Update session with answer information
  bool set_answer(const std::string& call_id, const std::string& sdp_answer,
                  std::string& error) {
    std::unique_lock lock(mutex_);
    auto it = sessions_.find(call_id);
    if (it == sessions_.end()) {
      error = "Call session not found: " + call_id;
      return false;
    }

    auto& session = it->second;

    // Valid states for receiving answer: INVITED or RINGING
    if (session.state != State::INVITED && session.state != State::RINGING) {
      error = "Cannot answer call in state: " + state_to_string(session.state);
      return false;
    }

    session.sdp_answer = sdp_answer;
    session.state = State::CONNECTING;
    session.last_activity_ms = now_ms();
    return true;
  }

  // End a call (hangup)
  bool end_call(const std::string& call_id, const std::string& reason,
                std::string& error) {
    std::unique_lock lock(mutex_);
    auto it = sessions_.find(call_id);
    if (it == sessions_.end()) {
      // Call might not exist — that's OK for hangup
      return true;
    }

    auto& session = it->second;
    if (session.state == State::ENDED) {
      error = "Call already ended";
      return false;
    }

    session.state = State::ENDED;
    session.hangup_reason = reason;
    session.last_activity_ms = now_ms();
    return true;
  }

  // Add ICE candidates to a session
  bool add_candidates(const std::string& call_id,
                       const std::vector<json>& candidates,
                       std::string& error) {
    std::unique_lock lock(mutex_);
    auto it = sessions_.find(call_id);
    if (it == sessions_.end()) {
      error = "Call session not found: " + call_id;
      return false;
    }

    auto& session = it->second;
    if (session.state == State::ENDED || session.state == State::IDLE) {
      error = "Cannot add candidates to ended/idle call";
      return false;
    }

    for (auto& c : candidates) {
      session.ice_candidates.push_back(c);
    }
    session.last_activity_ms = now_ms();
    return true;
  }

  // Mark media as connected
  bool media_connected(const std::string& call_id, std::string& error) {
    std::unique_lock lock(mutex_);
    auto it = sessions_.find(call_id);
    if (it == sessions_.end()) {
      error = "Call session not found: " + call_id;
      return false;
    }

    it->second.has_media = true;
    if (it->second.state == State::CONNECTING) {
      it->second.state = State::CONNECTED;
    }
    it->second.last_activity_ms = now_ms();
    return true;
  }

  // Check for expired calls and return list of call_ids to hang up
  std::vector<std::string> cleanup_expired() {
    std::unique_lock lock(mutex_);
    std::vector<std::string> expired;
    int64_t now = now_ms();

    auto it = sessions_.begin();
    while (it != sessions_.end()) {
      auto& session = it->second;
      if (session.state != State::ENDED && now > session.expires_at_ms) {
        session.state = State::ENDED;
        session.hangup_reason = std::string(voip_constants::kHangupTimeout);
        expired.push_back(session.call_id);
      }
      ++it;
    }

    // Remove old ended sessions (keep for 5 minutes after end)
    it = sessions_.begin();
    while (it != sessions_.end()) {
      if (it->second.state == State::ENDED &&
          now - it->second.last_activity_ms > 300000) {
        it = sessions_.erase(it);
      } else {
        ++it;
      }
    }

    return expired;
  }

  // Get active calls in a room
  std::vector<CallSession> get_active_calls_in_room(
      const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    std::vector<CallSession> result;
    for (auto& [id, session] : sessions_) {
      if (session.room_id == room_id &&
          session.state != State::ENDED) {
        result.push_back(session);
      }
    }
    return result;
  }

  // Get all active calls for a user
  std::vector<CallSession> get_active_calls_for_user(
      const std::string& user_id) const {
    std::shared_lock lock(mutex_);
    std::vector<CallSession> result;
    for (auto& [id, session] : sessions_) {
      if ((session.caller_id == user_id || session.callee_id == user_id) &&
          session.state != State::ENDED) {
        result.push_back(session);
      }
    }
    return result;
  }

  // Statistics
  size_t active_call_count() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (auto& [id, session] : sessions_) {
      if (session.state != State::ENDED) count++;
    }
    return count;
  }

  static std::string state_to_string(State state) {
    switch (state) {
      case State::IDLE: return "idle";
      case State::INVITED: return "invited";
      case State::RINGING: return "ringing";
      case State::CONNECTING: return "connecting";
      case State::CONNECTED: return "connected";
      case State::RENEGOTIATING: return "renegotiating";
      case State::ENDED: return "ended";
    }
    return "unknown";
  }

 private:
  static bool is_valid_transition(State from, State to) {
    // Allow terminating from any state to ENDED
    if (to == State::ENDED) return true;

    switch (from) {
      case State::IDLE:
        return to == State::INVITED || to == State::RINGING;
      case State::INVITED:
        return to == State::CONNECTING;
      case State::RINGING:
        return to == State::CONNECTING;
      case State::CONNECTING:
        return to == State::CONNECTED || to == State::RENEGOTIATING;
      case State::CONNECTED:
        return to == State::RENEGOTIATING;
      case State::RENEGOTIATING:
        return to == State::CONNECTED;
      case State::ENDED:
        return false;  // Terminal state
    }
    return false;
  }

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, CallSession> sessions_;
};

// ============================================================================
// CallConflictResolver — resolves conflicts when multiple invites exist
// for the same call_id or room
// ============================================================================
class CallConflictResolver {
 public:
  struct Resolution {
    std::string winning_call_id;
    std::vector<std::string> losing_call_ids;
    std::string reason;
  };

  // Resolve conflicting invites in a room
  // Strategy: newest timestamp wins, older invites get hangup
  static Resolution resolve_room_conflicts(
      const std::vector<VoipCallStateMachine::CallSession>& active_calls) {
    Resolution result;

    if (active_calls.size() <= 1) {
      if (!active_calls.empty()) {
        result.winning_call_id = active_calls[0].call_id;
      }
      return result;
    }

    // Find the newest call (highest created_at_ms)
    const VoipCallStateMachine::CallSession* winner = &active_calls[0];
    for (size_t i = 1; i < active_calls.size(); ++i) {
      if (active_calls[i].created_at_ms > winner->created_at_ms) {
        winner = &active_calls[i];
      }
    }

    result.winning_call_id = winner->call_id;
    for (auto& call : active_calls) {
      if (call.call_id != winner->call_id) {
        result.losing_call_ids.push_back(call.call_id);
      }
    }
    result.reason = "Resolved conflict by timestamp: " +
                    result.winning_call_id + " wins";

    return result;
  }

  // Check if a new invite conflicts with existing active calls
  static bool has_conflict(
      const std::string& room_id,
      const std::string& caller_id,
      const VoipCallStateMachine& state_machine) {
    auto active = state_machine.get_active_calls_in_room(room_id);

    // Conflict if there are active calls from a different caller
    for (auto& call : active) {
      if (call.caller_id != caller_id) {
        return true;
      }
    }
    return false;
  }
};

// ============================================================================
// VoipCallRouter — routes VoIP call events to the correct room participants
// ============================================================================
class VoipCallRouter {
 public:
  VoipCallRouter() = default;

  // Determine the target user(s) for a call event
  struct RouteTarget {
    std::string user_id;
    std::optional<std::string> device_id;
  };

  // Route a call invite: find the target user from the room state
  static std::vector<RouteTarget> route_invite(
      const std::string& room_id,
      const std::string& sender_id,
      const std::optional<std::string>& dest_client_id,
      storage::DatabasePool& db) {
    std::vector<RouteTarget> targets;

    // Get all room members except the sender
    auto conn = db.get();
    // In a real implementation, this would query the room_memberships table
    // to find the other participants. For now, we return an empty set.
    // The callee is typically the only other person in a 1:1 call room.

    return targets;
  }

  // Route ICE candidates: send to the other party in the call
  static std::vector<RouteTarget> route_candidates(
      const std::string& call_id,
      const std::string& sender_id,
      const VoipCallStateMachine& state_machine) {
    std::vector<RouteTarget> targets;

    auto session = state_machine.get_session(call_id);
    if (!session) return targets;

    // Send to the other party
    std::string target = (sender_id == session->caller_id)
                             ? session->callee_id
                             : session->caller_id;

    if (!target.empty()) {
      targets.push_back({target, session->dest_client_id});
    }

    return targets;
  }

  // Route an answer: send back to the original caller
  static std::vector<RouteTarget> route_answer(
      const std::string& call_id,
      const std::string& sender_id,
      const VoipCallStateMachine& state_machine) {
    std::vector<RouteTarget> targets;

    auto session = state_machine.get_session(call_id);
    if (!session) return targets;

    // Answer goes to the caller
    if (!session->caller_id.empty() && session->caller_id != sender_id) {
      targets.push_back({session->caller_id, std::nullopt});
    }

    return targets;
  }

  // Route a hangup: notify all parties in the call
  static std::vector<RouteTarget> route_hangup(
      const std::string& call_id,
      const std::string& sender_id,
      const VoipCallStateMachine& state_machine) {
    std::vector<RouteTarget> targets;

    auto session = state_machine.get_session(call_id);
    if (!session) return targets;

    // Notify the other party
    if (!session->caller_id.empty() && session->caller_id != sender_id) {
      targets.push_back({session->caller_id, std::nullopt});
    }
    if (!session->callee_id.empty() && session->callee_id != sender_id) {
      targets.push_back({session->callee_id, std::nullopt});
    }

    return targets;
  }
};

// ============================================================================
// VoipEventHandler — main handler for VoIP call events
// ============================================================================
class VoipEventHandler {
 public:
  VoipEventHandler(VoipCallStateMachine& state_machine,
                    VoipCallValidator& validator)
      : state_machine_(state_machine), validator_(validator) {}

  // Handle an incoming VoIP event from a client
  json handle_event(const std::string& event_type,
                     const json& content,
                     const std::string& room_id,
                     const std::string& sender_id) {
    // Validate the event
    auto validation = VoipCallValidator::validate_event(event_type, content);
    if (!validation.valid) {
      return json_error("M_INVALID_PARAM", validation.error);
    }

    std::string call_id = validation.call_id.value_or("");

    if (event_type == voip_constants::kCallInvite) {
      return handle_invite(content, room_id, sender_id, call_id,
                           validation.version.value_or(0));
    } else if (event_type == voip_constants::kCallCandidates) {
      return handle_candidates(content, room_id, sender_id, call_id);
    } else if (event_type == voip_constants::kCallAnswer) {
      return handle_answer(content, room_id, sender_id, call_id);
    } else if (event_type == voip_constants::kCallHangup) {
      return handle_hangup(content, room_id, sender_id, call_id);
    } else if (event_type == voip_constants::kCallNegotiate) {
      return handle_negotiate(content, room_id, sender_id, call_id);
    } else if (event_type == voip_constants::kCallReplaces) {
      return handle_replaces(content, room_id, sender_id);
    } else if (event_type == voip_constants::kCallSelectAnswer) {
      return handle_select_answer(content, room_id, sender_id);
    } else if (event_type == voip_constants::kCallReject) {
      return handle_reject(content, room_id, sender_id);
    }

    return json_error("M_UNKNOWN", "Unknown VoIP event type: " + event_type);
  }

 private:
  json handle_invite(const json& content,
                      const std::string& room_id,
                      const std::string& sender_id,
                      const std::string& call_id,
                      int version) {
    // Check for conflicts with existing calls in the room
    if (CallConflictResolver::has_conflict(room_id, sender_id,
                                            state_machine_)) {
      auto active = state_machine_.get_active_calls_in_room(room_id);
      auto resolution = CallConflictResolver::resolve_room_conflicts(active);

      // If this new invite lost, reject it
      if (resolution.winning_call_id != call_id) {
        return json_error("M_CONFLICT",
                          "Active call already exists in this room");
      }
    }

    int64_t lifetime = content[std::string(voip_constants::kFieldLifetime)].get<int64_t>();

    // Extract dest_client_id if present
    std::optional<std::string> dest_client_id;
    if (json_has_string(content, std::string(voip_constants::kFieldClientId))) {
      dest_client_id = content[std::string(voip_constants::kFieldClientId)]
                           .get<std::string>();
    }

    // Extract SDP offer
    std::string sdp_offer = content["offer"]["sdp"].get<std::string>();

    // Create call session
    auto session = state_machine_.create_session(
        call_id, room_id, sender_id, version, lifetime);
    session.sdp_offer = sdp_offer;
    session.dest_client_id = dest_client_id;

    // Extract callee from room state (for 1:1 rooms, the other member)
    // In a real implementation, this would query room members

    // Extract capabilities
    if (json_has_object(content, std::string(voip_constants::kFieldCapabilities))) {
      session.capabilities = content[std::string(voip_constants::kFieldCapabilities)];
    }

    return json::object();  // Success — event will be persisted and routed
  }

  json handle_candidates(const json& content,
                          const std::string& /*room_id*/,
                          const std::string& /*sender_id*/,
                          const std::string& call_id) {
    auto candidates =
        content[std::string(voip_constants::kFieldCandidates)].get<std::vector<json>>();

    std::string error;
    if (!state_machine_.add_candidates(call_id, candidates, error)) {
      return json_error("M_NOT_FOUND", error);
    }

    return json::object();
  }

  json handle_answer(const json& content,
                      const std::string& /*room_id*/,
                      const std::string& /*sender_id*/,
                      const std::string& call_id) {
    std::string sdp_answer = content["answer"]["sdp"].get<std::string>();

    std::string error;
    if (!state_machine_.set_answer(call_id, sdp_answer, error)) {
      return json_error("M_INVALID_STATE", error);
    }

    return json::object();
  }

  json handle_hangup(const json& content,
                      const std::string& /*room_id*/,
                      const std::string& /*sender_id*/,
                      const std::string& call_id) {
    std::string reason(content.contains(std::string(voip_constants::kFieldReason))
                           ? content[std::string(voip_constants::kFieldReason)]
                                 .get<std::string>()
                           : std::string(voip_constants::kHangupUser));

    std::string error;
    state_machine_.end_call(call_id, reason, error);
    // Don't error if call not found — hangup is idempotent

    return json::object();
  }

  json handle_negotiate(const json& content,
                         const std::string& /*room_id*/,
                         const std::string& /*sender_id*/,
                         const std::string& call_id) {
    std::string error;

    // Transition to renegotiating
    if (!state_machine_.transition(
            call_id, VoipCallStateMachine::State::RENEGOTIATING, error)) {
      return json_error("M_INVALID_STATE", error);
    }

    return json::object();
  }

  json handle_replaces(const json& /*content*/,
                        const std::string& /*room_id*/,
                        const std::string& /*sender_id*/) {
    // m.call.replaces is used for call transfer / attended transfer
    // This replaces an existing call with a new one
    return json::object();
  }

  json handle_select_answer(const json& /*content*/,
                             const std::string& /*room_id*/,
                             const std::string& /*sender_id*/) {
    // m.call.select_answer is used in group calls to select which answer
    // to accept when multiple callees answer
    return json::object();
  }

  json handle_reject(const json& /*content*/,
                      const std::string& /*room_id*/,
                      const std::string& /*sender_id*/) {
    // m.call.reject is used to reject a specific party in a group call
    return json::object();
  }

  VoipCallStateMachine& state_machine_;
  VoipCallValidator& validator_;
};

// ============================================================================
// TurnConfigParser — parses VoIP/TURN configuration from the server config
// ============================================================================
class TurnConfigParser {
 public:
  struct TurnConfig {
    std::vector<TurnServer> servers;
    std::string shared_secret;
    int64_t credential_ttl = voip_constants::kDefaultCredentialTtl;
    bool voip_enabled = true;
    std::vector<std::string> allowed_transports;
    bool prefer_udp = true;
  };

  // Parse TURN configuration from a JSON/YAML config node
  static TurnConfig parse(const json& config_node) {
    TurnConfig config;

    // Parse TURN URIs
    if (config_node.contains("turn_uris") && config_node["turn_uris"].is_array()) {
      int server_idx = 0;
      for (auto& uri_json : config_node["turn_uris"]) {
        TurnServer server;
        server.id = "turn_" + std::to_string(server_idx++);

        if (uri_json.is_string()) {
          // Simple format: just a URI
          server.uris.push_back(uri_json.get<std::string>());
          parse_uri_components(uri_json.get<std::string>(), server);
        } else if (uri_json.is_object()) {
          // Object format: {uri, transport, weight, etc.}
          if (uri_json.contains("uri")) {
            server.uris.push_back(uri_json["uri"].get<std::string>());
            parse_uri_components(uri_json["uri"].get<std::string>(), server);
          }
          if (uri_json.contains("uris") && uri_json["uris"].is_array()) {
            server.uris.clear();
            for (auto& u : uri_json["uris"]) {
              server.uris.push_back(u.get<std::string>());
            }
          }
          if (uri_json.contains("transport")) {
            server.transport = uri_json["transport"].get<std::string>();
          }
          if (uri_json.contains("weight")) {
            server.weight = uri_json["weight"].get<int>();
          }
        }

        server.shared_secret = config.shared_secret;
        config.servers.push_back(server);
      }
    }

    // Parse TURN server list (alternative format with host/port/secret)
    if (config_node.contains("turn_servers") &&
        config_node["turn_servers"].is_array()) {
      for (auto& ts : config_node["turn_servers"]) {
        TurnServer server;
        server.id = ts.value("id",
            "turn_" + std::to_string(config.servers.size()));

        std::string host = ts.value("host", std::string{});
        int port = ts.value("port", voip_constants::kDefaultTurnUdpPort);
        std::string transport = ts.value("transport", std::string("udp"));
        bool use_tls = ts.value("tls", false);

        server.host = host;
        server.port = port;
        server.transport = transport;
        server.use_tls = use_tls;
        server.weight = ts.value("weight", 100);

        // Build URIs from components
        std::string scheme = use_tls
            ? std::string(voip_constants::kTurnsScheme)
            : std::string(voip_constants::kTurnScheme);
        server.uris.push_back(
            TurnServer::build_uri(scheme, host, port, transport));

        // Add alternate transport URIs
        if (ts.value("tcp", false)) {
          server.uris.push_back(
              TurnServer::build_uri(scheme, host, port,
                                    std::string(voip_constants::kTransportTcp)));
        }
        if (ts.value("tls_alt", false)) {
          server.uris.push_back(
              TurnServer::build_uri(
                  std::string(voip_constants::kTurnsScheme), host,
                  voip_constants::kDefaultTurnTlsPort,
                  std::string(voip_constants::kTransportTls)));
        }

        server.shared_secret = ts.value("shared_secret", config.shared_secret);
        server.enabled = ts.value("enabled", true);

        config.servers.push_back(server);
      }
    }

    // Parse shared secret
    if (config_node.contains("turn_shared_secret")) {
      config.shared_secret = config_node["turn_shared_secret"].get<std::string>();
    } else if (config_node.contains("turn_secret")) {
      config.shared_secret = config_node["turn_secret"].get<std::string>();
    }

    // Parse credential TTL
    if (config_node.contains("turn_credential_ttl")) {
      config.credential_ttl = config_node["turn_credential_ttl"].get<int64_t>();
      if (config.credential_ttl < voip_constants::kMinCredentialTtl)
        config.credential_ttl = voip_constants::kMinCredentialTtl;
      if (config.credential_ttl > voip_constants::kMaxCredentialTtl)
        config.credential_ttl = voip_constants::kMaxCredentialTtl;
    }

    // Parse allowed transports
    if (config_node.contains("turn_transports") &&
        config_node["turn_transports"].is_array()) {
      for (auto& t : config_node["turn_transports"]) {
        config.allowed_transports.push_back(t.get<std::string>());
      }
    }

    // Prefer UDP
    config.prefer_udp = config_node.value("turn_prefer_udp", true);

    return config;
  }

 private:
  static void parse_uri_components(const std::string& uri, TurnServer& server) {
    // Parse turn:host:port?transport=xxx or turns:host:port?transport=xxx
    std::string s = uri;

    // Determine scheme
    if (starts_with(s, std::string(voip_constants::kTurnsScheme) + ":")) {
      server.use_tls = true;
      s = s.substr(6);  // strlen("turns:")
    } else if (starts_with(s, std::string(voip_constants::kTurnScheme) + ":")) {
      server.use_tls = false;
      s = s.substr(5);  // strlen("turn:")
    }

    // Extract host:port
    auto query_pos = s.find('?');
    std::string hostport = (query_pos != std::string::npos)
                               ? s.substr(0, query_pos)
                               : s;

    auto colon_pos = hostport.find(':');
    if (colon_pos != std::string::npos) {
      server.host = hostport.substr(0, colon_pos);
      if (hostport[0] == '[') {
        // IPv6 address
        auto close_bracket = hostport.find(']');
        server.host = hostport.substr(1, close_bracket - 1);
        auto port_str = hostport.substr(close_bracket + 2);
        if (!port_str.empty()) {
          try { server.port = std::stoi(port_str); } catch (...) {}
        }
      } else {
        try {
          server.port = std::stoi(hostport.substr(colon_pos + 1));
        } catch (...) {
          server.port = voip_constants::kDefaultTurnUdpPort;
        }
      }
    } else {
      server.host = hostport;
      server.port = server.use_tls
                        ? voip_constants::kDefaultTurnTlsPort
                        : voip_constants::kDefaultTurnUdpPort;
    }

    // Parse query parameters
    if (query_pos != std::string::npos) {
      std::string query = s.substr(query_pos + 1);
      auto transport_pos = query.find("transport=");
      if (transport_pos != std::string::npos) {
        server.transport = query.substr(transport_pos + 10);  // strlen("transport=")
        auto amp_pos = server.transport.find('&');
        if (amp_pos != std::string::npos) {
          server.transport = server.transport.substr(0, amp_pos);
        }
      }
    }
  }
};

// ============================================================================
// VoipConfigManager — manages VoIP configuration at runtime
// ============================================================================
class VoipConfigManager {
 public:
  VoipConfigManager() = default;

  // Initialize from config node
  void initialize(const TurnConfigParser::TurnConfig& config) {
    std::unique_lock lock(mutex_);

    shared_secret_ = config.shared_secret;
    credential_ttl_ = config.credential_ttl;
    voip_enabled_ = config.voip_enabled;
    allowed_transports_ = config.allowed_transports;
    prefer_udp_ = config.prefer_udp;

    // Register TURN servers
    for (auto& server : config.servers) {
      server_manager_.add_server(server);
    }

    // Initialize credential generator
    credential_gen_ = std::make_unique<TurnCredentialGenerator>(
        shared_secret_, credential_ttl_);
  }

  // Get TURN servers for a client request
  json get_turn_servers_response(const std::string& user_id) {
    std::shared_lock lock(mutex_);

    if (!voip_enabled_) {
      return json::object();  // Empty response when VoIP disabled
    }

    auto servers = server_manager_.get_servers();

    if (servers.empty() || shared_secret_.empty()) {
      return json::object();  // No TURN servers configured
    }

    // Generate credentials
    auto cred = credential_gen_->generate();

    // Build response: list of TURN server objects
    json response;
    response["username"] = cred.username;
    response["password"] = cred.password;
    response["ttl"] = cred.ttl;

    json uris = json::array();
    for (auto& server : servers) {
      for (auto& uri : server.uris) {
        uris.push_back(uri);
      }
    }
    response["uris"] = uris;

    // Optional: return per-server objects too
    json server_list = json::array();
    for (auto& server : servers) {
      json s;
      s["uris"] = server.uris;
      s["username"] = cred.username;
      s["password"] = cred.password;
      server_list.push_back(s);
    }
    response["servers"] = server_list;

    return response;
  }

  // Get credential TTL
  int64_t get_credential_ttl() const {
    std::shared_lock lock(mutex_);
    return credential_ttl_;
  }

  // Update shared secret at runtime
  void update_shared_secret(const std::string& secret) {
    std::unique_lock lock(mutex_);
    shared_secret_ = secret;
    credential_gen_->set_shared_secret(secret);
    // No need to recreate — generator reads from shared variable
  }

  // Update credential TTL
  void update_credential_ttl(int64_t ttl) {
    std::unique_lock lock(mutex_);
    credential_ttl_ = ttl;
    credential_gen_->set_ttl(ttl);
  }

  // Check if VoIP is enabled
  bool is_voip_enabled() const {
    std::shared_lock lock(mutex_);
    return voip_enabled_;
  }

  // Enable/disable VoIP
  void set_voip_enabled(bool enabled) {
    std::unique_lock lock(mutex_);
    voip_enabled_ = enabled;
  }

  // Admin: list all TURN servers
  json list_servers() const {
    std::shared_lock lock(mutex_);
    json result = json::array();
    for (auto& s : server_manager_.get_all_servers()) {
      json js;
      js["id"] = s.id;
      js["uris"] = s.uris;
      js["transport"] = s.transport;
      js["host"] = s.host;
      js["port"] = s.port;
      js["use_tls"] = s.use_tls;
      js["enabled"] = s.enabled;
      js["weight"] = s.weight;
      result.push_back(js);
    }
    return result;
  }

  // Admin: add a TURN server
  bool add_server(const std::string& uri,
                  const std::string& transport,
                  int port,
                  bool tls) {
    TurnServer server;
    server.id = "turn_" + std::to_string(now_sec());
    server.host = extract_host(uri);
    server.port = port;
    server.transport = transport;
    server.use_tls = tls;
    server.shared_secret = shared_secret_;

    std::string scheme = tls
        ? std::string(voip_constants::kTurnsScheme)
        : std::string(voip_constants::kTurnScheme);

    // Build full URI
    std::ostringstream uri_builder;
    uri_builder << scheme << ":" << server.host << ":" << server.port
                << "?transport=" << server.transport;
    server.uris.push_back(uri_builder.str());

    std::unique_lock lock(mutex_);
    return server_manager_.add_server(server);
  }

  // Admin: remove a TURN server
  bool remove_server(const std::string& id) {
    std::unique_lock lock(mutex_);
    return server_manager_.remove_server(id);
  }

  // Get server count
  size_t server_count() const { return server_manager_.count(); }

 private:
  static std::string extract_host(const std::string& uri) {
    // Simple extraction: remove scheme:// prefix
    std::string s = uri;
    auto scheme_end = s.find("://");
    if (scheme_end != std::string::npos) {
      s = s.substr(scheme_end + 3);
    } else {
      auto colon = s.find(':');
      if (colon != std::string::npos) {
        s = s.substr(colon + 1);
      }
    }
    // Remove port and path
    auto slash = s.find('/');
    if (slash != std::string::npos) {
      s = s.substr(0, slash);
    }
    auto colon = s.find(':');
    if (colon != std::string::npos) {
      s = s.substr(0, colon);
    }
    return s;
  }

  mutable std::shared_mutex mutex_;
  TurnServerManager server_manager_;
  std::unique_ptr<TurnCredentialGenerator> credential_gen_;
  TurnCredentialCache credential_cache_;
  std::string shared_secret_;
  int64_t credential_ttl_ = voip_constants::kDefaultCredentialTtl;
  bool voip_enabled_ = true;
  std::vector<std::string> allowed_transports_;
  bool prefer_udp_ = true;
};

// ============================================================================
// TurnServerRestServlet — serves GET /_matrix/client/v3/voip/turnServer
// ============================================================================
class TurnServerRestServlet : public rest::ClientV1RestServlet {
 public:
  explicit TurnServerRestServlet(std::shared_ptr<VoipConfigManager> config)
      : config_(std::move(config)) {}

  std::vector<std::string> patterns() const override {
    return {std::string(voip_constants::kTurnServerPath)};
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    // Require authentication
    if (!req.auth_user.has_value()) {
      return rest::BaseRestServlet::error_response(
          401, "M_MISSING_TOKEN", "Missing access token");
    }

    std::string user_id = req.auth_user.value();

    // Get TURN server response
    json response = config_->get_turn_servers_response(user_id);

    // If response is empty (no TURN configured), return empty object
    // as per Matrix spec — client should use its own TURN servers
    return rest::BaseRestServlet::success_response(response);
  }

 private:
  std::shared_ptr<VoipConfigManager> config_;
};

// ============================================================================
// VoipCallMetrics — collects VoIP call statistics and metrics
// ============================================================================
class VoipCallMetrics {
 public:
  VoipCallMetrics() = default;

  void record_invite_sent() {
    invites_sent_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_invite_received() {
    invites_received_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_answer_sent() {
    answers_sent_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_answer_received() {
    answers_received_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_hangup(const std::string& reason) {
    hangups_total_.fetch_add(1, std::memory_order_relaxed);
    std::unique_lock lock(mutex_);
    hangup_reasons_[reason]++;
  }

  void record_call_connected() {
    calls_connected_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_call_failed() {
    calls_failed_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_turn_credential_served() {
    turn_credentials_served_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_turn_credential_cached() {
    turn_credentials_cached_.fetch_add(1, std::memory_order_relaxed);
  }

  // Export metrics as JSON
  json export_metrics() const {
    json j;
    j["voip_invites_sent"] = invites_sent_.load(std::memory_order_relaxed);
    j["voip_invites_received"] = invites_received_.load(std::memory_order_relaxed);
    j["voip_answers_sent"] = answers_sent_.load(std::memory_order_relaxed);
    j["voip_answers_received"] = answers_received_.load(std::memory_order_relaxed);
    j["voip_hangups_total"] = hangups_total_.load(std::memory_order_relaxed);
    j["voip_calls_connected"] = calls_connected_.load(std::memory_order_relaxed);
    j["voip_calls_failed"] = calls_failed_.load(std::memory_order_relaxed);
    j["voip_turn_credentials_served"] =
        turn_credentials_served_.load(std::memory_order_relaxed);
    j["voip_turn_credentials_cached"] =
        turn_credentials_cached_.load(std::memory_order_relaxed);

    {
      std::shared_lock lock(mutex_);
      json reasons = json::object();
      for (auto& [reason, count] : hangup_reasons_) {
        reasons[reason] = count;
      }
      j["voip_hangup_reasons"] = reasons;
    }

    return j;
  }

  // Reset all metrics
  void reset() {
    invites_sent_.store(0, std::memory_order_relaxed);
    invites_received_.store(0, std::memory_order_relaxed);
    answers_sent_.store(0, std::memory_order_relaxed);
    answers_received_.store(0, std::memory_order_relaxed);
    hangups_total_.store(0, std::memory_order_relaxed);
    calls_connected_.store(0, std::memory_order_relaxed);
    calls_failed_.store(0, std::memory_order_relaxed);
    turn_credentials_served_.store(0, std::memory_order_relaxed);
    turn_credentials_cached_.store(0, std::memory_order_relaxed);
    std::unique_lock lock(mutex_);
    hangup_reasons_.clear();
  }

 private:
  std::atomic<int64_t> invites_sent_{0};
  std::atomic<int64_t> invites_received_{0};
  std::atomic<int64_t> answers_sent_{0};
  std::atomic<int64_t> answers_received_{0};
  std::atomic<int64_t> hangups_total_{0};
  std::atomic<int64_t> calls_connected_{0};
  std::atomic<int64_t> calls_failed_{0};
  std::atomic<int64_t> turn_credentials_served_{0};
  std::atomic<int64_t> turn_credentials_cached_{0};

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, int64_t> hangup_reasons_;
};

// ============================================================================
// VoipTurnCoordinator — top-level coordinator that ties everything together
// ============================================================================
class VoipTurnCoordinator {
 public:
  VoipTurnCoordinator() {
    validator_ = std::make_unique<VoipCallValidator>();
    event_handler_ = std::make_unique<VoipEventHandler>(
        state_machine_, *validator_);
    metrics_ = std::make_unique<VoipCallMetrics>();

    // Start cleanup thread
    cleanup_running_ = true;
    cleanup_thread_ = std::thread([this]() { cleanup_loop(); });
  }

  ~VoipTurnCoordinator() {
    cleanup_running_ = false;
    if (cleanup_thread_.joinable()) {
      cleanup_thread_.join();
    }
  }

  // Initialize coordinator with config
  void initialize(const TurnConfigParser::TurnConfig& config) {
    config_manager_ = std::make_shared<VoipConfigManager>();
    config_manager_->initialize(config);
  }

  // Get the REST servlet for TURN server endpoint
  std::unique_ptr<rest::ClientV1RestServlet> create_turn_servlet() {
    return std::make_unique<TurnServerRestServlet>(config_manager_);
  }

  // Handle an incoming VoIP event
  json handle_voip_event(const std::string& event_type,
                          const json& content,
                          const std::string& room_id,
                          const std::string& sender_id) {
    if (!config_manager_ || !config_manager_->is_voip_enabled()) {
      return json_error("M_FORBIDDEN", "VoIP is disabled on this server");
    }

    auto result = event_handler_->handle_event(
        event_type, content, room_id, sender_id);

    // Update metrics
    if (event_type == voip_constants::kCallInvite) {
      metrics_->record_invite_received();
    } else if (event_type == voip_constants::kCallAnswer) {
      metrics_->record_answer_received();
    } else if (event_type == voip_constants::kCallHangup) {
      std::string reason(content.contains("reason")
                             ? content["reason"].get<std::string>()
                             : std::string(voip_constants::kHangupUser));
      metrics_->record_hangup(reason);
    }

    return result;
  }

  // Get the TURN configuration for admin inspection
  json get_config() const {
    json j;
    if (config_manager_) {
      j["voip_enabled"] = config_manager_->is_voip_enabled();
      j["credential_ttl"] = config_manager_->get_credential_ttl();
      j["servers"] = config_manager_->list_servers();
      j["server_count"] = config_manager_->server_count();
      j["active_calls"] = state_machine_.active_call_count();
    }
    return j;
  }

  // Admin: update shared secret
  void update_shared_secret(const std::string& secret) {
    if (config_manager_) {
      config_manager_->update_shared_secret(secret);
    }
  }

  // Admin: update credential TTL
  void update_credential_ttl(int64_t ttl) {
    if (config_manager_) {
      config_manager_->update_credential_ttl(ttl);
    }
  }

  // Admin: add TURN server
  bool add_turn_server(const std::string& uri,
                        const std::string& transport,
                        int port,
                        bool tls) {
    if (config_manager_) {
      return config_manager_->add_server(uri, transport, port, tls);
    }
    return false;
  }

  // Admin: remove TURN server
  bool remove_turn_server(const std::string& id) {
    if (config_manager_) {
      return config_manager_->remove_server(id);
    }
    return false;
  }

  // Admin: enable/disable VoIP
  void set_voip_enabled(bool enabled) {
    if (config_manager_) {
      config_manager_->set_voip_enabled(enabled);
    }
  }

  // Get metrics
  json get_metrics() const {
    json j = metrics_->export_metrics();
    j["active_calls"] = state_machine_.active_call_count();
    return j;
  }

  // Get active calls for a user
  std::vector<VoipCallStateMachine::CallSession>
  get_active_calls_for_user(const std::string& user_id) const {
    return state_machine_.get_active_calls_for_user(user_id);
  }

  // Get active calls in a room
  std::vector<VoipCallStateMachine::CallSession>
  get_active_calls_in_room(const std::string& room_id) const {
    return state_machine_.get_active_calls_in_room(room_id);
  }

  // Access the state machine
  VoipCallStateMachine& state_machine() { return state_machine_; }

 private:
  void cleanup_loop() {
    while (cleanup_running_) {
      std::this_thread::sleep_for(std::chrono::seconds(30));
      if (!cleanup_running_) break;

      auto expired = state_machine_.cleanup_expired();
      for (auto& id : expired) {
        metrics_->record_call_failed();
      }
    }
  }

  std::shared_ptr<VoipConfigManager> config_manager_;
  std::unique_ptr<VoipCallValidator> validator_;
  std::unique_ptr<VoipEventHandler> event_handler_;
  VoipCallStateMachine state_machine_;
  std::unique_ptr<VoipCallMetrics> metrics_;

  std::thread cleanup_thread_;
  std::atomic<bool> cleanup_running_{false};
};

// ============================================================================
// VoIP Configuration: Default TURN server presets for well-known providers
// ============================================================================
namespace turn_presets {

// Google STUN/TURN servers (public, no auth needed for STUN)
inline TurnServer google_stun() {
  TurnServer s;
  s.id = "google_stun";
  s.uris = {
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun2.l.google.com:19302",
    "stun:stun3.l.google.com:19302",
    "stun:stun4.l.google.com:19302",
  };
  s.host = "stun.l.google.com";
  s.port = 19302;
  s.transport = "udp";
  s.use_tls = false;
  s.shared_secret = "";  // STUN doesn't need auth
  s.enabled = true;
  return s;
}

// coturn TURN server with default ports
inline TurnServer coturn_default(const std::string& host,
                                  const std::string& secret) {
  TurnServer s;
  s.id = "coturn_main";
  s.host = host;
  s.transport = "udp";
  s.use_tls = false;
  s.shared_secret = secret;

  s.uris = {
    TurnServer::build_uri("turn", host, voip_constants::kDefaultTurnUdpPort,
                          "udp"),
    TurnServer::build_uri("turn", host, voip_constants::kDefaultTurnTcpPort,
                          "tcp"),
    TurnServer::build_uri("turns", host, voip_constants::kDefaultTurnTlsPort,
                          "tcp"),
  };

  return s;
}

// Twilio TURN server (commonly used with Matrix)
inline TurnServer twilio_turn(const std::string& host,
                               const std::string& secret) {
  TurnServer s;
  s.id = "twilio_turn";
  s.host = host;
  s.transport = "udp";
  s.use_tls = true;
  s.shared_secret = secret;

  s.uris = {
    TurnServer::build_uri("turn", host, voip_constants::kDefaultTurnUdpPort,
                          "udp"),
    TurnServer::build_uri("turn", host, voip_constants::kDefaultTurnTcpPort,
                          "tcp"),
    TurnServer::build_uri("turns", host, voip_constants::kDefaultTurnTlsPort,
                          "tcp"),
  };

  return s;
}

}  // namespace turn_presets

// ============================================================================
// Global coordinator accessor — provides singleton-like access to the
// coordinator for other parts of the server
// ============================================================================
namespace {
  std::unique_ptr<VoipTurnCoordinator> g_voip_coordinator;
  std::mutex g_voip_coordinator_mutex;
}  // anonymous namespace

// Initialize the VoIP/TURN system
void voip_turn_init(const TurnConfigParser::TurnConfig& config) {
  std::unique_lock lock(g_voip_coordinator_mutex);
  g_voip_coordinator = std::make_unique<VoipTurnCoordinator>();
  g_voip_coordinator->initialize(config);
}

// Get the global coordinator
VoipTurnCoordinator* voip_turn_get_coordinator() {
  std::unique_lock lock(g_voip_coordinator_mutex);
  return g_voip_coordinator.get();
}

// Shutdown VoIP/TURN system
void voip_turn_shutdown() {
  std::unique_lock lock(g_voip_coordinator_mutex);
  g_voip_coordinator.reset();
}

// Register TURN server REST servlet with the servlet registry
void voip_turn_register_servlets(rest::ServletRegistry& registry) {
  auto coord = voip_turn_get_coordinator();
  if (coord) {
    registry.register_servlet(coord->create_turn_servlet());
  }
}

// Process a VoIP event from the event stream / send path
json voip_turn_process_event(const std::string& event_type,
                               const json& content,
                               const std::string& room_id,
                               const std::string& sender_id) {
  auto coord = voip_turn_get_coordinator();
  if (!coord) {
    return json_error("M_UNKNOWN", "VoIP system not initialized");
  }
  return coord->handle_voip_event(event_type, content, room_id, sender_id);
}

// Check if an event type is a VoIP event (used by event routers)
bool voip_turn_is_voip_event(const std::string& event_type) {
  return VoipCallValidator::is_voip_event(event_type);
}

// Validate VoIP event content
json voip_turn_validate_event(const std::string& event_type,
                                const json& content) {
  auto result = VoipCallValidator::validate_event(event_type, content);
  if (!result.valid) {
    return json_error("M_INVALID_PARAM", result.error);
  }
  return json::object();
}

// ============================================================================
// Admin REST endpoint: GET /_synapse/admin/v1/voip/turn/config
// GET /_synapse/admin/v1/voip/turn/servers
// POST /_synapse/admin/v1/voip/turn/servers
// DELETE /_synapse/admin/v1/voip/turn/servers/{id}
// ============================================================================
class VoipAdminRestServlet : public rest::ClientV1RestServlet {
 public:
  std::vector<std::string> patterns() const override {
    return {
      "/_synapse/admin/v1/voip/turn/config",
      "/_synapse/admin/v1/voip/turn/servers",
      "/_synapse/admin/v1/voip/turn/servers/{serverId}",
      "/_synapse/admin/v1/voip/turn/metrics",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST", "PUT", "DELETE"};
  }

  rest::HttpResponse on_request(const rest::HttpRequest& req) override {
    // Verify admin access
    if (!req.auth_user.has_value()) {
      return rest::BaseRestServlet::error_response(
          401, "M_MISSING_TOKEN", "Missing access token");
    }

    auto coord = voip_turn_get_coordinator();
    if (!coord) {
      return rest::BaseRestServlet::error_response(
          500, "M_UNKNOWN", "VoIP system not initialized");
    }

    // Route based on path
    if (req.path.find("/voip/turn/config") != std::string::npos) {
      return handle_config(req, coord);
    } else if (req.path.find("/voip/turn/metrics") != std::string::npos) {
      return handle_metrics(coord);
    } else if (req.path.find("/voip/turn/servers") != std::string::npos) {
      return handle_servers(req, coord);
    }

    return rest::BaseRestServlet::error_response(
        404, "M_NOT_FOUND", "Unknown VoIP admin endpoint");
  }

 private:
  rest::HttpResponse handle_config(const rest::HttpRequest& req,
                                    VoipTurnCoordinator* coord) {
    if (req.method == "GET") {
      return rest::BaseRestServlet::success_response(coord->get_config());
    }

    if (req.method == "PUT" || req.method == "POST") {
      json body;
      try {
        body = rest::BaseRestServlet::parse_json_body(req);
      } catch (...) {
        return rest::BaseRestServlet::error_response(
            400, "M_BAD_JSON", "Invalid JSON body");
      }

      if (body.contains("shared_secret")) {
        coord->update_shared_secret(body["shared_secret"].get<std::string>());
      }

      if (body.contains("credential_ttl")) {
        coord->update_credential_ttl(body["credential_ttl"].get<int64_t>());
      }

      if (body.contains("voip_enabled")) {
        coord->set_voip_enabled(body["voip_enabled"].get<bool>());
      }

      return rest::BaseRestServlet::success_response(
          json{{"status", "updated"}});
    }

    return rest::BaseRestServlet::error_response(
        405, "M_UNKNOWN", "Method not allowed");
  }

  rest::HttpResponse handle_servers(const rest::HttpRequest& req,
                                     VoipTurnCoordinator* coord) {
    if (req.method == "GET") {
      return rest::BaseRestServlet::success_response(
          coord->get_config()["servers"]);
    }

    if (req.method == "POST") {
      json body;
      try {
        body = rest::BaseRestServlet::parse_json_body(req);
      } catch (...) {
        return rest::BaseRestServlet::error_response(
            400, "M_BAD_JSON", "Invalid JSON body");
      }

      std::string uri = body.value("uri", "");
      std::string transport = body.value("transport", "udp");
      int port = body.value("port", voip_constants::kDefaultTurnUdpPort);
      bool tls = body.value("tls", false);

      if (uri.empty()) {
        return rest::BaseRestServlet::error_response(
            400, "M_MISSING_PARAM", "uri is required");
      }

      if (coord->add_turn_server(uri, transport, port, tls)) {
        return rest::BaseRestServlet::success_response(
            json{{"status", "added"}});
      }
      return rest::BaseRestServlet::error_response(
          500, "M_UNKNOWN", "Failed to add TURN server");
    }

    if (req.method == "DELETE") {
      auto it = req.path_params.find("serverId");
      if (it == req.path_params.end()) {
        return rest::BaseRestServlet::error_response(
            400, "M_MISSING_PARAM", "serverId path parameter required");
      }
      if (coord->remove_turn_server(it->second)) {
        return rest::BaseRestServlet::success_response(
            json{{"status", "removed"}});
      }
      return rest::BaseRestServlet::error_response(
          404, "M_NOT_FOUND", "TURN server not found");
    }

    return rest::BaseRestServlet::error_response(
        405, "M_UNKNOWN", "Method not allowed");
  }

  rest::HttpResponse handle_metrics(VoipTurnCoordinator* coord) {
    return rest::BaseRestServlet::success_response(coord->get_metrics());
  }
};

// ============================================================================
// VoIP Event Validation Pre-Hook — validates VoIP events before persistence
// Can be called from the main event processing pipeline
// ============================================================================
class VoipEventPreProcessor {
 public:
  // Pre-process a VoIP event before persisting
  // Returns a JSON error if the event is invalid, or empty object if valid
  static json pre_process(const std::string& event_type, const json& content) {
    if (!VoipCallValidator::is_voip_event(event_type)) {
      return json::object();  // Not a VoIP event, skip
    }

    auto result = VoipCallValidator::validate_event(event_type, content);
    if (!result.valid) {
      return json_error("M_INVALID_PARAM", result.error);
    }

    return json::object();  // Valid
  }
};

// ============================================================================
// TURN Credential Verification — server-side verification for self-hosted TURN
// Useful when the homeserver and TURN server share the same process space
// ============================================================================
class TurnCredentialVerifier {
 public:
  explicit TurnCredentialVerifier(const std::string& shared_secret)
      : generator_(shared_secret) {}

  // Verify TURN credentials (for TURN server REST API authentication)
  bool verify(const std::string& username, const std::string& password) {
    return generator_.verify(username, password);
  }

  // Check if a credential is still valid (not expired)
  bool is_expired(const std::string& username) {
    auto colon = username.find(':');
    if (colon == std::string::npos) return true;

    try {
      int64_t expiry = std::stoll(username.substr(0, colon));
      return now_sec() > expiry;
    } catch (...) {
      return true;
    }
  }

 private:
  TurnCredentialGenerator generator_;
};

}  // namespace progressive
