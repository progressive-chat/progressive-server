// ============================================================================
// rate_limiter.cpp — Matrix Rate Limiting and Request Filtering
//
// Implements:
//   - Token Bucket Rate Limiter core: thread-safe token bucket with
//     per-key tracking, stale entry cleanup, configurable rate/burst
//   - Request Rate Limiter: per-user, per-IP, per-endpoint rate limiting
//     with endpoint category defaults
//   - Login Rate Limiter: per-account, per-IP, per-address (email/msisdn)
//     rate limiting for failed login attempts with account lockout
//   - Registration Rate Limiter: per-IP registration limits with
//     shared secret auth exemption and time-window tracking
//   - Admin API Rate Limiter: separate limits for admin endpoints
//     with stricter defaults
//   - Rate Limit Configuration: configurable burst/rate per endpoint
//     category, global defaults, dynamic reconfiguration
//   - Rate Limit Headers: X-RateLimit-Limit, X-RateLimit-Remaining,
//     X-RateLimit-Reset header generation
//   - Request Size Limiting: max request body size per-endpoint,
//     reject oversized requests with proper error responses
//   - Connection Limiting: max concurrent connections per IP,
//     per-user connection limits with tracking and eviction
//
// Equivalent to:
//   synapse/api/ratelimiting.py
//   synapse/http/site.py (connection limits, body size)
//   synapse/rest/client/login.py (login ratelimiting)
//   synapse/rest/client/register.py (registration ratelimiting)
//   synapse/handlers/auth.py (login attempt tracking)
//
// Target: 2000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
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

#include <nlohmann/json.hpp>

// For IP address parsing
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
class TokenBucket;
class RequestRateLimiter;
class LoginRateLimiter;
class RegistrationRateLimiter;
class AdminRateLimiter;
class RateLimitConfig;
class RateLimitHeaders;
class RequestSizeLimiter;
class ConnectionLimiter;

// ============================================================================
// Anonymous namespace — Internal helpers
// ============================================================================
namespace {

// ---- Timestamp helpers ----

int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

chr::steady_clock::time_point now_steady() {
  return chr::steady_clock::now();
}

// ---- String helpers ----

std::string to_lower(std::string s) {
  for (auto& c : s)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string combine_key(const std::string& a, const std::string& b) {
  return a + ":" + b;
}

std::string combine_key3(const std::string& a, const std::string& b,
                         const std::string& c) {
  return a + ":" + b + ":" + c;
}

// ---- IP normalization ----

/// Normalize an IP address string to a canonical form
std::string normalize_ip(const std::string& ip) {
  // Handle IPv6 loopback
  if (ip == "::1" || ip == "0:0:0:0:0:0:0:1") return "127.0.0.1";
  // Handle IPv4-mapped IPv6
  if (ip.find("::ffff:") == 0) {
    return ip.substr(7);
  }
  return ip;
}

/// Extract the /48 prefix from an IPv6 address for anonymous rate limiting
std::string ipv6_48_prefix(const std::string& ip) {
  // Find the position of the third colon group
  int colons = 0;
  size_t pos = 0;
  for (size_t i = 0; i < ip.size(); ++i) {
    if (ip[i] == ':') {
      colons++;
      if (colons == 3) {
        pos = i;
        break;
      }
    }
  }
  if (colons == 3 && pos > 0) {
    return ip.substr(0, pos);
  }
  return ip;
}

/// Check if an IP address is a private/loopback address
bool is_private_ip(const std::string& ip) {
  if (ip == "127.0.0.1" || ip == "::1") return true;
  if (ip.find("10.") == 0) return true;
  if (ip.find("172.") == 0) {
    auto second = ip.find('.', 4);
    if (second != std::string::npos) {
      int octet = std::stoi(ip.substr(4, second - 4));
      if (octet >= 16 && octet <= 31) return true;
    }
  }
  if (ip.find("192.168.") == 0) return true;
  if (ip.find("fd") == 0) return true; // IPv6 ULA
  if (ip.find("fc") == 0) return true; // IPv6 ULA
  return false;
}

// ---- JSON helpers ----

json make_error_json(const std::string& errcode, const std::string& error) {
  return json({
      {"errcode", errcode},
      {"error", error}
  });
}

json make_ratelimit_error(const std::string& errcode, const std::string& error,
                          int64_t retry_after_ms) {
  return json({
      {"errcode", errcode},
      {"error", error},
      {"retry_after_ms", retry_after_ms}
  });
}

// ============================================================================
// Endpoint category definitions
// ============================================================================

/// Endpoint categories for grouping rate limits
enum class EndpointCategory {
  CLIENT_READ,       // GET requests on client API
  CLIENT_WRITE,      // POST/PUT/DELETE on client API
  LOGIN,             // Login endpoint
  REGISTER,          // Registration endpoint
  FEDERATION,        // Federation API
  MEDIA,             // Media upload/download
  ADMIN,             // Admin API
  GUEST,             // Guest access
  PUSH,              // Push gateway
  DEFAULT            // Catch-all
};

/// Convert endpoint category to string for logging/config
const char* endpoint_category_name(EndpointCategory cat) {
  switch (cat) {
    case EndpointCategory::CLIENT_READ:   return "client_read";
    case EndpointCategory::CLIENT_WRITE:  return "client_write";
    case EndpointCategory::LOGIN:         return "login";
    case EndpointCategory::REGISTER:      return "register";
    case EndpointCategory::FEDERATION:    return "federation";
    case EndpointCategory::MEDIA:         return "media";
    case EndpointCategory::ADMIN:         return "admin";
    case EndpointCategory::GUEST:         return "guest";
    case EndpointCategory::PUSH:          return "push";
    case EndpointCategory::DEFAULT:       return "default";
    default: return "unknown";
  }
}

/// Classify an endpoint path into a category
EndpointCategory classify_endpoint(const std::string& path,
                                    const std::string& method) {
  // Admin API
  if (path.find("/_synapse/admin/") == 0 ||
      path.find("/_matrix/admin/") == 0 ||
      path.find("/_progressive/admin/") == 0) {
    return EndpointCategory::ADMIN;
  }

  // Federation API
  if (path.find("/_matrix/federation/") == 0) {
    return EndpointCategory::FEDERATION;
  }

  // Media API
  if (path.find("/_matrix/media/") == 0) {
    return EndpointCategory::MEDIA;
  }

  // Login
  if (path.find("/_matrix/client/") == 0 && path.find("/login") != std::string::npos) {
    return EndpointCategory::LOGIN;
  }

  // Register
  if (path.find("/_matrix/client/") == 0 && path.find("/register") != std::string::npos) {
    return EndpointCategory::REGISTER;
  }

  // Push gateway
  if (path.find("/_matrix/push/") == 0) {
    return EndpointCategory::PUSH;
  }

  // Client API – distinguish read vs write
  if (path.find("/_matrix/client/") == 0) {
    bool is_get = (method == "GET" || method == "HEAD" || method == "OPTIONS");
    return is_get ? EndpointCategory::CLIENT_READ : EndpointCategory::CLIENT_WRITE;
  }

  // Guest access
  if (path.find("/_matrix/guest/") == 0) {
    return EndpointCategory::GUEST;
  }

  return EndpointCategory::DEFAULT;
}

} // anonymous namespace

// ============================================================================
// 1. RateLimitConfig — Central rate limit configuration
//
// Stores per-category rate limit settings: rate (per second), burst (max
// tokens), window size for tracking, and per-entity overrides.
// Supports dynamic reconfiguration while the server is running.
// ============================================================================

class RateLimitConfig {
public:
  struct CategoryConfig {
    double rate_per_sec = 20.0;    // tokens regenerated per second
    double burst = 40.0;          // maximum token bucket capacity
    int64_t window_sec = 60;      // sliding window size for login/reg tracking
    bool enabled = true;          // whether rate limiting is active
    std::string name;             // category name

    json to_json() const {
      return {
          {"rate_per_sec", rate_per_sec},
          {"burst", burst},
          {"window_sec", window_sec},
          {"enabled", enabled},
          {"name", name}
      };
    }

    static CategoryConfig from_json(const json& j) {
      CategoryConfig cfg;
      if (j.contains("rate_per_sec")) cfg.rate_per_sec = j["rate_per_sec"].get<double>();
      if (j.contains("burst")) cfg.burst = j["burst"].get<double>();
      if (j.contains("window_sec")) cfg.window_sec = j["window_sec"].get<int64_t>();
      if (j.contains("enabled")) cfg.enabled = j["enabled"].get<bool>();
      if (j.contains("name")) cfg.name = j["name"].get<std::string>();
      return cfg;
    }
  };

  // ---- Per-user overrides ----
  struct UserOverride {
    std::string user_id;
    std::optional<double> rate_per_sec;
    std::optional<double> burst;
  };

  // ---- Per-IP overrides ----
  struct IpOverride {
    std::string ip;
    std::optional<double> rate_per_sec;
    std::optional<double> burst;
  };

  RateLimitConfig() {
    set_defaults();
  }

  /// Initialize with default rate limits matching Synapse defaults
  void set_defaults() {
    // Client read operations – generous limits
    auto& client_read = categories_[EndpointCategory::CLIENT_READ];
    client_read.rate_per_sec = 100.0;
    client_read.burst = 200.0;
    client_read.window_sec = 60;
    client_read.enabled = true;
    client_read.name = "client_read";

    // Client write operations – moderate limits
    auto& client_write = categories_[EndpointCategory::CLIENT_WRITE];
    client_write.rate_per_sec = 30.0;
    client_write.burst = 60.0;
    client_write.window_sec = 60;
    client_write.enabled = true;
    client_write.name = "client_write";

    // Login – strict limits (brute force protection)
    auto& login = categories_[EndpointCategory::LOGIN];
    login.rate_per_sec = 0.17;   // ~1 per 6 seconds, ~10 per minute
    login.burst = 3.0;           // allow 3 rapid attempts then throttle
    login.window_sec = 60;
    login.enabled = true;
    login.name = "login";

    // Registration – very strict
    auto& reg = categories_[EndpointCategory::REGISTER];
    reg.rate_per_sec = 0.003;    // ~1 per 5 minutes, ~12 per hour
    reg.burst = 2.0;
    reg.window_sec = 3600;
    reg.enabled = true;
    reg.name = "register";

    // Federation – high throughput
    auto& fed = categories_[EndpointCategory::FEDERATION];
    fed.rate_per_sec = 200.0;
    fed.burst = 500.0;
    fed.window_sec = 60;
    fed.enabled = true;
    fed.name = "federation";

    // Media – generous for downloads, moderate for uploads
    auto& media = categories_[EndpointCategory::MEDIA];
    media.rate_per_sec = 50.0;
    media.burst = 100.0;
    media.window_sec = 60;
    media.enabled = true;
    media.name = "media";

    // Admin – stricter than client, more generous than login
    auto& admin = categories_[EndpointCategory::ADMIN];
    admin.rate_per_sec = 5.0;
    admin.burst = 10.0;
    admin.window_sec = 60;
    admin.enabled = true;
    admin.name = "admin";

    // Guest – very low limits
    auto& guest = categories_[EndpointCategory::GUEST];
    guest.rate_per_sec = 0.5;
    guest.burst = 1.0;
    guest.window_sec = 60;
    guest.enabled = true;
    guest.name = "guest";

    // Push – moderate
    auto& push = categories_[EndpointCategory::PUSH];
    push.rate_per_sec = 10.0;
    push.burst = 20.0;
    push.window_sec = 60;
    push.enabled = true;
    push.name = "push";

    // Default – sensible fallback
    auto& def = categories_[EndpointCategory::DEFAULT];
    def.rate_per_sec = 20.0;
    def.burst = 40.0;
    def.window_sec = 60;
    def.enabled = true;
    def.name = "default";

    // Global toggle
    global_enabled_ = true;
  }

  // ---- Category accessors ----

  const CategoryConfig& get_category(EndpointCategory cat) const {
    auto it = categories_.find(cat);
    if (it != categories_.end()) return it->second;
    // Fallback to default
    static const CategoryConfig default_cfg;
    return default_cfg;
  }

  CategoryConfig& get_category_mut(EndpointCategory cat) {
    return categories_[cat];
  }

  void set_category(EndpointCategory cat, const CategoryConfig& cfg) {
    std::lock_guard lock(config_mutex_);
    categories_[cat] = cfg;
  }

  // ---- Per-user overrides ----

  void set_user_override(const std::string& user_id,
                         std::optional<double> rate_per_sec,
                         std::optional<double> burst) {
    std::lock_guard lock(config_mutex_);
    UserOverride ov;
    ov.user_id = user_id;
    ov.rate_per_sec = rate_per_sec;
    ov.burst = burst;
    user_overrides_[user_id] = std::move(ov);
  }

  void remove_user_override(const std::string& user_id) {
    std::lock_guard lock(config_mutex_);
    user_overrides_.erase(user_id);
  }

  std::optional<UserOverride> get_user_override(const std::string& user_id) const {
    std::shared_lock lock(config_mutex_);
    auto it = user_overrides_.find(user_id);
    if (it != user_overrides_.end()) return it->second;
    return std::nullopt;
  }

  // ---- Per-IP overrides ----

  void set_ip_override(const std::string& ip,
                       std::optional<double> rate_per_sec,
                       std::optional<double> burst) {
    std::lock_guard lock(config_mutex_);
    IpOverride ov;
    ov.ip = normalize_ip(ip);
    ov.rate_per_sec = rate_per_sec;
    ov.burst = burst;
    ip_overrides_[ov.ip] = std::move(ov);
  }

  void remove_ip_override(const std::string& ip) {
    std::lock_guard lock(config_mutex_);
    ip_overrides_.erase(normalize_ip(ip));
  }

  std::optional<IpOverride> get_ip_override(const std::string& ip) const {
    std::shared_lock lock(config_mutex_);
    auto it = ip_overrides_.find(normalize_ip(ip));
    if (it != ip_overrides_.end()) return it->second;
    return std::nullopt;
  }

  // ---- Global toggle ----

  void set_global_enabled(bool enabled) {
    global_enabled_ = enabled;
  }

  bool is_globally_enabled() const {
    return global_enabled_.load();
  }

  // ---- Effective rate/burst for a request ----

  /// Get effective rate/burst for a given request context, applying overrides
  std::pair<double, double> effective_limits(EndpointCategory cat,
                                              const std::string& user_id,
                                              const std::string& ip) const {
    const auto& base = get_category(cat);

    double rate = base.rate_per_sec;
    double burst = base.burst;

    // Check user override
    if (!user_id.empty()) {
      auto uov = get_user_override(user_id);
      if (uov) {
        if (uov->rate_per_sec) rate = *uov->rate_per_sec;
        if (uov->burst) burst = *uov->burst;
      }
    }

    // Check IP override (takes precedence over user override for burst-only changes)
    if (!ip.empty()) {
      auto iov = get_ip_override(ip);
      if (iov) {
        if (iov->rate_per_sec) rate = *iov->rate_per_sec;
        if (iov->burst) burst = *iov->burst;
      }
    }

    return {rate, burst};
  }

  // ---- Serialization ----

  json to_json() const {
    std::shared_lock lock(config_mutex_);
    json j;
    j["global_enabled"] = global_enabled_.load();

    json cats = json::object();
    for (const auto& [cat, cfg] : categories_) {
      cats[endpoint_category_name(cat)] = cfg.to_json();
    }
    j["categories"] = cats;

    json uovs = json::array();
    for (const auto& [uid, ov] : user_overrides_) {
      json o;
      o["user_id"] = uid;
      if (ov.rate_per_sec) o["rate_per_sec"] = *ov.rate_per_sec;
      if (ov.burst) o["burst"] = *ov.burst;
      uovs.push_back(o);
    }
    j["user_overrides"] = uovs;

    json iovs = json::array();
    for (const auto& [ip, ov] : ip_overrides_) {
      json o;
      o["ip"] = ip;
      if (ov.rate_per_sec) o["rate_per_sec"] = *ov.rate_per_sec;
      if (ov.burst) o["burst"] = *ov.burst;
      iovs.push_back(o);
    }
    j["ip_overrides"] = iovs;

    return j;
  }

  // ---- Request size limits ----

  void set_max_body_size(EndpointCategory cat, size_t max_bytes) {
    std::lock_guard lock(config_mutex_);
    max_body_sizes_[cat] = max_bytes;
  }

  size_t get_max_body_size(EndpointCategory cat) const {
    std::shared_lock lock(config_mutex_);
    auto it = max_body_sizes_.find(cat);
    if (it != max_body_sizes_.end()) return it->second;
    // Defaults
    switch (cat) {
      case EndpointCategory::MEDIA:
        return 50 * 1024 * 1024;  // 50 MB for media uploads
      case EndpointCategory::FEDERATION:
        return 100 * 1024 * 1024; // 100 MB for federation
      default:
        return 10 * 1024 * 1024;  // 10 MB default
    }
  }

  // ---- Connection limits ----

  void set_max_connections_per_ip(size_t max) {
    max_connections_per_ip_ = max;
  }

  size_t get_max_connections_per_ip() const {
    return max_connections_per_ip_.load();
  }

  void set_max_connections_per_user(size_t max) {
    max_connections_per_user_ = max;
  }

  size_t get_max_connections_per_user() const {
    return max_connections_per_user_.load();
  }

  void set_global_max_connections(size_t max) {
    global_max_connections_ = max;
  }

  size_t get_global_max_connections() const {
    return global_max_connections_.load();
  }

private:
  mutable std::shared_mutex config_mutex_;
  std::map<EndpointCategory, CategoryConfig> categories_;
  std::map<std::string, UserOverride, std::less<>> user_overrides_;
  std::map<std::string, IpOverride, std::less<>> ip_overrides_;
  std::atomic<bool> global_enabled_{true};

  // Body size per category
  std::map<EndpointCategory, size_t> max_body_sizes_;

  // Connection limits
  std::atomic<size_t> max_connections_per_ip_{100};
  std::atomic<size_t> max_connections_per_user_{50};
  std::atomic<size_t> global_max_connections_{10000};
};

// ============================================================================
// 2. TokenBucket — Thread-safe token bucket rate limiter
//
// Implements the token bucket algorithm. Each key has a bucket with a
// certain number of tokens that regenerate at a fixed rate up to a
// maximum burst capacity. Thread-safe with per-bucket mutex to reduce
// contention.
// ============================================================================

class TokenBucket {
public:
  struct Bucket {
    double tokens;
    int64_t last_refill_ms;
    std::mutex mtx; // per-bucket lock for fine-grained locking

    Bucket(double initial_tokens, int64_t now)
        : tokens(initial_tokens), last_refill_ms(now) {}
  };

  explicit TokenBucket(double rate_per_sec = 10.0, double burst = 20.0)
      : rate_per_sec_(rate_per_sec), burst_(burst) {}

  TokenBucket(const TokenBucket&) = delete;
  TokenBucket& operator=(const TokenBucket&) = delete;
  TokenBucket(TokenBucket&&) = default;
  TokenBucket& operator=(TokenBucket&&) = default;

  /// Attempt to consume one token. Returns true if allowed, false if
  /// rate limited. Also returns remaining tokens and reset time via
  /// output parameters.
  bool consume(const std::string& key,
               double& remaining_out,
               int64_t& reset_ms_out,
               double cost = 1.0) {
    auto& bucket = get_or_create_bucket(key);
    std::lock_guard lock(bucket.mtx);
    refill_locked(bucket);

    if (bucket.tokens >= cost) {
      bucket.tokens -= cost;
      remaining_out = bucket.tokens;
      // Calculate reset time: when bucket will refill back to 1 token
      double deficit = (cost - bucket.tokens > 0) ? (cost - bucket.tokens) : 0;
      double refill_sec = (deficit > 0) ? (deficit / rate_per_sec_) : 0;
      reset_ms_out = bucket.last_refill_ms + static_cast<int64_t>(refill_sec * 1000.0);
      return true;
    }

    // Rate limited – calculate when next token will be available
    double deficit = 1.0 - bucket.tokens;
    double wait_sec = deficit / rate_per_sec_;
    remaining_out = bucket.tokens;
    reset_ms_out = bucket.last_refill_ms + static_cast<int64_t>(wait_sec * 1000.0);
    return false;
  }

  /// Check how many tokens are available without consuming
  double available(const std::string& key) {
    auto& bucket = get_or_create_bucket(key);
    std::lock_guard lock(bucket.mtx);
    refill_locked(bucket);
    return bucket.tokens;
  }

  /// Get remaining tokens and reset time
  std::pair<double, int64_t> status(const std::string& key) {
    auto& bucket = get_or_create_bucket(key);
    std::lock_guard lock(bucket.mtx);
    refill_locked(bucket);
    double rem = bucket.tokens;
    double deficit = (1.0 - rem > 0) ? (1.0 - rem) : 0;
    double wait_sec = deficit / rate_per_sec_;
    int64_t reset_ms = bucket.last_refill_ms + static_cast<int64_t>(wait_sec * 1000.0);
    return {rem, reset_ms};
  }

  /// Update rate and burst parameters (existing buckets will use new params
  /// on next refill)
  void set_params(double rate_per_sec, double burst) {
    std::lock_guard map_lock(map_mutex_);
    rate_per_sec_ = rate_per_sec;
    burst_ = burst;
  }

  double rate() const { return rate_per_sec_; }
  double burst() const { return burst_; }

  /// Remove stale buckets not accessed within the given age
  size_t cleanup_stale(int64_t max_age_ms = 600000) { // 10 min default
    int64_t now = now_ms();
    size_t removed = 0;
    std::lock_guard map_lock(map_mutex_);
    auto it = buckets_.begin();
    while (it != buckets_.end()) {
      if (now - it->second->last_refill_ms > max_age_ms) {
        it = buckets_.erase(it);
        removed++;
      } else {
        ++it;
      }
    }
    return removed;
  }

  /// Get the number of active buckets
  size_t active_buckets() const {
    std::lock_guard map_lock(map_mutex_);
    return buckets_.size();
  }

private:
  Bucket& get_or_create_bucket(const std::string& key) {
    // First try with shared lock
    {
      std::shared_lock map_lock(map_mutex_);
      auto it = buckets_.find(key);
      if (it != buckets_.end()) {
        return *it->second;
      }
    }
    // Need exclusive lock to create
    std::lock_guard map_lock(map_mutex_);
    auto it = buckets_.find(key);
    if (it != buckets_.end()) {
      return *it->second;
    }
    auto bucket = std::make_unique<Bucket>(burst_, now_ms());
    auto& ref = *bucket;
    buckets_[std::string(key)] = std::move(bucket);
    return ref;
  }

  void refill_locked(Bucket& b) const {
    int64_t now = now_ms();
    int64_t elapsed = now - b.last_refill_ms;
    if (elapsed <= 0) return;

    double added = (static_cast<double>(elapsed) / 1000.0) * rate_per_sec_;
    b.tokens = std::min(burst_, b.tokens + added);
    b.last_refill_ms = now;
  }

  mutable std::shared_mutex map_mutex_;
  std::map<std::string, std::unique_ptr<Bucket>, std::less<>> buckets_;
  double rate_per_sec_;
  double burst_;
};

// ============================================================================
// 3. RequestRateLimiter — Per-user, per-IP, per-endpoint rate limiting
//
// Maintains separate token buckets for each dimension:
//   - Per user_id + endpoint
//   - Per IP + endpoint
//   - Per endpoint (global endpoint capacity)
//
// All dimensions must pass for a request to be allowed.
// ============================================================================

class RequestRateLimiter {
public:
  struct LimitResult {
    bool allowed = true;
    double user_remaining = -1.0;
    double ip_remaining = -1.0;
    double endpoint_remaining = -1.0;
    int64_t reset_ms = 0;
    std::string limit_source;  // "user", "ip", "endpoint", "none"
  };

  explicit RequestRateLimiter(RateLimitConfig& config)
      : config_(config) {}

  /// Check if a request is allowed across all rate limit dimensions.
  /// Returns detailed limit result with remaining tokens and reset time.
  LimitResult check_and_consume(const std::string& user_id,
                                 const std::string& ip,
                                 const std::string& endpoint,
                                 const std::string& method) {
    LimitResult result;

    if (!config_.is_globally_enabled()) {
      result.allowed = true;
      result.limit_source = "none";
      return result;
    }

    EndpointCategory cat = classify_endpoint(endpoint, method);
    auto [rate, burst] = config_.effective_limits(cat, user_id, ip);

    // Check endpoint-level rate limit (global per endpoint)
    {
      std::string ep_key = "ep:" + endpoint_category_name(cat);
      auto& bucket = get_or_create_endpoint_bucket(cat, rate, burst);
      double ep_remaining;
      int64_t ep_reset;
      if (!bucket->consume(ep_key, ep_remaining, ep_reset)) {
        result.allowed = false;
        result.endpoint_remaining = ep_remaining;
        result.reset_ms = ep_reset;
        result.limit_source = "endpoint";
        return result;
      }
      result.endpoint_remaining = ep_remaining;
      result.reset_ms = std::max(result.reset_ms, ep_reset);
    }

    // Check per-user rate limit
    if (!user_id.empty()) {
      std::string user_key = "user:" + user_id + ":" + endpoint_category_name(cat);
      auto& user_bucket = get_or_create_user_bucket(user_id, rate, burst);
      double user_remaining;
      int64_t user_reset;
      if (!user_bucket->consume(user_key, user_remaining, user_reset)) {
        result.allowed = false;
        result.user_remaining = user_remaining;
        result.reset_ms = std::max(result.reset_ms, user_reset);
        result.limit_source = "user";
        return result;
      }
      result.user_remaining = user_remaining;
      result.reset_ms = std::max(result.reset_ms, user_reset);
    }

    // Check per-IP rate limit
    if (!ip.empty()) {
      std::string norm_ip = normalize_ip(ip);
      std::string ip_key = "ip:" + norm_ip + ":" + endpoint_category_name(cat);
      auto& ip_bucket = get_or_create_ip_bucket(norm_ip, rate, burst);
      double ip_remaining;
      int64_t ip_reset;
      if (!ip_bucket->consume(ip_key, ip_remaining, ip_reset)) {
        result.allowed = false;
        result.ip_remaining = ip_remaining;
        result.reset_ms = std::max(result.reset_ms, ip_reset);
        result.limit_source = "ip";
        return result;
      }
      result.ip_remaining = ip_remaining;
      result.reset_ms = std::max(result.reset_ms, ip_reset);
    }

    result.allowed = true;
    result.limit_source = "none";
    return result;
  }

  /// Get current state without consuming tokens
  LimitResult check_only(const std::string& user_id,
                          const std::string& ip,
                          const std::string& endpoint,
                          const std::string& method) {
    // For check-only, we look at available tokens without consuming.
    // This is approximate since we hold no lock across buckets.
    LimitResult result;
    result.allowed = true;
    result.limit_source = "none";

    if (!config_.is_globally_enabled()) return result;

    EndpointCategory cat = classify_endpoint(endpoint, method);
    auto [rate, burst] = config_.effective_limits(cat, user_id, ip);

    {
      std::string ep_key = "ep:" + endpoint_category_name(cat);
      auto& bucket = get_or_create_endpoint_bucket(cat, rate, burst);
      result.endpoint_remaining = bucket->available(ep_key);
      auto [rem, reset] = bucket->status(ep_key);
      result.reset_ms = reset;
      if (rem < 1.0) result.allowed = false;
    }

    if (!user_id.empty()) {
      std::string user_key = "user:" + user_id + ":" + endpoint_category_name(cat);
      auto& user_bucket = get_or_create_user_bucket(user_id, rate, burst);
      result.user_remaining = user_bucket->available(user_key);
      if (result.user_remaining < 1.0) result.allowed = false;
    }

    if (!ip.empty()) {
      std::string norm_ip = normalize_ip(ip);
      std::string ip_key = "ip:" + norm_ip + ":" + endpoint_category_name(cat);
      auto& ip_bucket = get_or_create_ip_bucket(norm_ip, rate, burst);
      result.ip_remaining = ip_bucket->available(ip_key);
      if (result.ip_remaining < 1.0) result.allowed = false;
    }

    return result;
  }

  /// Cleanup stale buckets across all limiters
  size_t cleanup_all(int64_t max_age_ms = 600000) {
    size_t total = 0;
    {
      std::shared_lock lock(buckets_mutex_);
      for (auto& [_, bucket] : endpoint_buckets_) {
        total += bucket->cleanup_stale(max_age_ms);
      }
      for (auto& [_, bucket] : user_buckets_) {
        total += bucket->cleanup_stale(max_age_ms);
      }
      for (auto& [_, bucket] : ip_buckets_) {
        total += bucket->cleanup_stale(max_age_ms);
      }
    }
    return total;
  }

  /// Get stats for monitoring
  json get_stats() const {
    std::shared_lock lock(buckets_mutex_);
    json j;
    j["endpoint_buckets"] = endpoint_buckets_.size();
    j["user_buckets"] = user_buckets_.size();
    j["ip_buckets"] = ip_buckets_.size();

    size_t total_active = 0;
    for (auto& [_, bucket] : endpoint_buckets_) total_active += bucket->active_buckets();
    for (auto& [_, bucket] : user_buckets_) total_active += bucket->active_buckets();
    for (auto& [_, bucket] : ip_buckets_) total_active += bucket->active_buckets();
    j["total_active_entries"] = total_active;
    return j;
  }

private:
  std::unique_ptr<TokenBucket>& get_or_create_endpoint_bucket(
      EndpointCategory cat, double rate, double burst) {
    int key = static_cast<int>(cat);
    {
      std::shared_lock lock(buckets_mutex_);
      auto it = endpoint_buckets_.find(key);
      if (it != endpoint_buckets_.end()) {
        it->second->set_params(rate, burst);
        return it->second;
      }
    }
    std::lock_guard lock(buckets_mutex_);
    auto it = endpoint_buckets_.find(key);
    if (it != endpoint_buckets_.end()) {
      it->second->set_params(rate, burst);
      return it->second;
    }
    endpoint_buckets_[key] = std::make_unique<TokenBucket>(rate, burst);
    return endpoint_buckets_[key];
  }

  std::unique_ptr<TokenBucket>& get_or_create_user_bucket(
      const std::string& user_id, double rate, double burst) {
    {
      std::shared_lock lock(buckets_mutex_);
      auto it = user_buckets_.find(user_id);
      if (it != user_buckets_.end()) {
        it->second->set_params(rate, burst);
        return it->second;
      }
    }
    std::lock_guard lock(buckets_mutex_);
    auto it = user_buckets_.find(user_id);
    if (it != user_buckets_.end()) {
      it->second->set_params(rate, burst);
      return it->second;
    }
    user_buckets_[std::string(user_id)] = std::make_unique<TokenBucket>(rate, burst);
    return user_buckets_[std::string(user_id)];
  }

  std::unique_ptr<TokenBucket>& get_or_create_ip_bucket(
      const std::string& ip, double rate, double burst) {
    {
      std::shared_lock lock(buckets_mutex_);
      auto it = ip_buckets_.find(ip);
      if (it != ip_buckets_.end()) {
        it->second->set_params(rate, burst);
        return it->second;
      }
    }
    std::lock_guard lock(buckets_mutex_);
    auto it = ip_buckets_.find(ip);
    if (it != ip_buckets_.end()) {
      it->second->set_params(rate, burst);
      return it->second;
    }
    ip_buckets_[std::string(ip)] = std::make_unique<TokenBucket>(rate, burst);
    return ip_buckets_[std::string(ip)];
  }

  RateLimitConfig& config_;
  mutable std::shared_mutex buckets_mutex_;
  std::map<int, std::unique_ptr<TokenBucket>> endpoint_buckets_; // by EndpointCategory int
  std::map<std::string, std::unique_ptr<TokenBucket>, std::less<>> user_buckets_;
  std::map<std::string, std::unique_ptr<TokenBucket>, std::less<>> ip_buckets_;
};

// ============================================================================
// 4. LoginAttemptTracker — Tracks failed login attempts per account,
//    per IP, per address for brute-force protection
// ============================================================================

class LoginAttemptTracker {
public:
  struct Attempt {
    int64_t timestamp_ms;
    std::string ip;
    std::string address; // email or msisdn
    bool success;
  };

  struct AccountState {
    std::deque<Attempt> history;
    int64_t consecutive_failures = 0;
    int64_t first_failure_ms = 0;
    int64_t locked_until_ms = 0;
    std::mutex mtx;
  };

  struct LoginCheckResult {
    bool allowed = true;
    int64_t retry_after_ms = 0;
    std::string reason;
    int64_t consecutive_failures = 0;
  };

  explicit LoginAttemptTracker(const RateLimitConfig& config)
      : config_(config), max_attempts_(5), lockout_duration_ms_(300000),
        window_ms_(300000), max_ip_attempts_(20) {}

  /// Record a login attempt (success or failure)
  void record_attempt(const std::string& account,
                      const std::string& ip,
                      const std::string& address,
                      bool success) {
    int64_t now = now_ms();
    Attempt attempt{now, normalize_ip(ip), address, success};

    // Update per-account state
    {
      auto& state = get_account_state(account);
      std::lock_guard lock(state.mtx);

      // Prune old entries outside window
      prune_history_locked(state, now);

      state.history.push_back(attempt);

      if (success) {
        state.consecutive_failures = 0;
        state.first_failure_ms = 0;
        state.locked_until_ms = 0;
      } else {
        if (state.consecutive_failures == 0) {
          state.first_failure_ms = now;
        }
        state.consecutive_failures++;

        // Check if we should lock the account
        if (state.consecutive_failures >= max_attempts_) {
          state.locked_until_ms = now + lockout_duration_ms_;
        }
      }
    }

    // Update per-IP tracking
    {
      std::lock_guard lock(ip_tracker_mutex_);
      auto& ip_history = ip_attempts_[normalize_ip(ip)];
      ip_history.push_back({now, success});
      // Prune old entries
      while (!ip_history.empty() &&
             now - ip_history.front().first > window_ms_) {
        ip_history.pop_front();
      }
    }

    // Update per-address tracking
    if (!address.empty()) {
      std::lock_guard lock(addr_tracker_mutex_);
      auto& addr_history = addr_attempts_[address];
      addr_history.push_back({now, success});
      while (!addr_history.empty() &&
             now - addr_history.front().first > window_ms_) {
        addr_history.pop_front();
      }
    }
  }

  /// Check if a login attempt should be allowed
  LoginCheckResult check_login(const std::string& account,
                                const std::string& ip,
                                const std::string& address) {
    LoginCheckResult result;
    int64_t now = now_ms();

    // Check global rate limiting enable
    if (!config_.is_globally_enabled()) {
      result.allowed = true;
      return result;
    }

    // Check per-account lockout
    {
      auto& state = get_account_state(account);
      std::lock_guard lock(state.mtx);

      if (state.locked_until_ms > 0 && now < state.locked_until_ms) {
        result.allowed = false;
        result.retry_after_ms = state.locked_until_ms - now;
        result.reason = "Account temporarily locked due to too many failed login attempts";
        result.consecutive_failures = state.consecutive_failures;
        return result;
      }

      // Check for burst of failures within window
      int64_t recent_failures = 0;
      for (const auto& att : state.history) {
        if (now - att.timestamp_ms <= window_ms_ && !att.success) {
          recent_failures++;
        }
      }

      if (recent_failures >= max_attempts_) {
        result.allowed = false;
        // Calculate when oldest failure expires from window
        int64_t oldest = now;
        for (const auto& att : state.history) {
          if (!att.success && att.timestamp_ms < oldest) {
            oldest = att.timestamp_ms;
          }
        }
        result.retry_after_ms = (oldest + window_ms_) - now;
        if (result.retry_after_ms < 1000) result.retry_after_ms = 5000;
        result.reason = "Too many failed login attempts within time window";
        result.consecutive_failures = recent_failures;
        return result;
      }
    }

    // Check per-IP rate limit
    {
      std::lock_guard lock(ip_tracker_mutex_);
      std::string norm_ip = normalize_ip(ip);
      auto it = ip_attempts_.find(norm_ip);
      if (it != ip_attempts_.end()) {
        // Count failed attempts in window
        int64_t failures = 0;
        for (const auto& [ts, success] : it->second) {
          if (now - ts <= window_ms_ && !success) {
            failures++;
          }
        }
        if (failures >= max_ip_attempts_) {
          result.allowed = false;
          result.retry_after_ms = window_ms_ - (now - it->second.front().first);
          if (result.retry_after_ms < 1000) result.retry_after_ms = 5000;
          result.reason = "Too many failed login attempts from this IP";
          result.consecutive_failures = failures;
          return result;
        }
      }
    }

    // Check per-address rate limit
    if (!address.empty()) {
      std::lock_guard lock(addr_tracker_mutex_);
      auto it = addr_attempts_.find(address);
      if (it != addr_attempts_.end()) {
        int64_t failures = 0;
        for (const auto& [ts, success] : it->second) {
          if (now - ts <= window_ms_ && !success) {
            failures++;
          }
        }
        // Per-address is stricter: half the IP limit
        if (failures >= max_ip_attempts_ / 2) {
          result.allowed = false;
          result.retry_after_ms = window_ms_ - (now - it->second.front().first);
          if (result.retry_after_ms < 1000) result.retry_after_ms = 5000;
          result.reason = "Too many failed login attempts for this address";
          result.consecutive_failures = failures;
          return result;
        }
      }
    }

    result.allowed = true;
    return result;
  }

  /// Manually clear lockout for an account (admin action)
  void clear_account_lockout(const std::string& account) {
    auto& state = get_account_state(account);
    std::lock_guard lock(state.mtx);
    state.consecutive_failures = 0;
    state.first_failure_ms = 0;
    state.locked_until_ms = 0;
    state.history.clear();
  }

  /// Get account state for admin inspection
  AccountState get_account_info(const std::string& account) {
    auto& state = get_account_state(account);
    std::lock_guard lock(state.mtx);
    AccountState copy = state;
    return copy;
  }

  /// Get all locked accounts
  std::vector<std::string> locked_accounts() {
    int64_t now = now_ms();
    std::vector<std::string> result;
    std::shared_lock lock(accounts_mutex_);
    for (const auto& [acct, state] : accounts_) {
      std::lock_guard slock(state->mtx);
      if (state->locked_until_ms > 0 && state->locked_until_ms > now) {
        result.push_back(acct);
      }
    }
    return result;
  }

  /// Cleanup stale tracking data
  size_t cleanup_stale(int64_t max_age_ms = 3600000) { // 1 hour
    int64_t now = now_ms();
    size_t removed = 0;

    {
      std::lock_guard lock(accounts_mutex_);
      auto it = accounts_.begin();
      while (it != accounts_.end()) {
        std::lock_guard slock(it->second->mtx);
        bool is_stale = it->second->history.empty() ||
                        (now - it->second->history.back().timestamp_ms > max_age_ms &&
                         it->second->locked_until_ms == 0 &&
                         it->second->consecutive_failures == 0);
        if (is_stale) {
          it = accounts_.erase(it);
          removed++;
        } else {
          ++it;
        }
      }
    }

    {
      std::lock_guard lock(ip_tracker_mutex_);
      auto it = ip_attempts_.begin();
      while (it != ip_attempts_.end()) {
        while (!it->second.empty() && now - it->second.front().first > max_age_ms) {
          it->second.pop_front();
        }
        if (it->second.empty()) {
          it = ip_attempts_.erase(it);
          removed++;
        } else {
          ++it;
        }
      }
    }

    {
      std::lock_guard lock(addr_tracker_mutex_);
      auto it = addr_attempts_.begin();
      while (it != addr_attempts_.end()) {
        while (!it->second.empty() && now - it->second.front().first > max_age_ms) {
          it->second.pop_front();
        }
        if (it->second.empty()) {
          it = addr_attempts_.erase(it);
          removed++;
        } else {
          ++it;
        }
      }
    }

    return removed;
  }

  // Configuration
  void set_max_attempts(int64_t max) { max_attempts_ = max; }
  void set_lockout_duration_ms(int64_t dur) { lockout_duration_ms_ = dur; }
  void set_window_ms(int64_t win) { window_ms_ = win; }
  void set_max_ip_attempts(int64_t max) { max_ip_attempts_ = max; }

  int64_t max_attempts() const { return max_attempts_; }
  int64_t lockout_duration_ms() const { return lockout_duration_ms_; }
  int64_t window_ms() const { return window_ms_; }
  int64_t max_ip_attempts() const { return max_ip_attempts_; }

private:
  AccountState& get_account_state(const std::string& account) {
    {
      std::shared_lock lock(accounts_mutex_);
      auto it = accounts_.find(account);
      if (it != accounts_.end()) return *it->second;
    }
    std::lock_guard lock(accounts_mutex_);
    auto it = accounts_.find(account);
    if (it != accounts_.end()) return *it->second;
    accounts_[std::string(account)] = std::make_unique<AccountState>();
    return *accounts_[std::string(account)];
  }

  void prune_history_locked(AccountState& state, int64_t now) {
    while (!state.history.empty() &&
           now - state.history.front().timestamp_ms > window_ms_ * 2) {
      state.history.pop_front();
    }
  }

  const RateLimitConfig& config_;
  std::atomic<int64_t> max_attempts_;
  std::atomic<int64_t> lockout_duration_ms_;
  std::atomic<int64_t> window_ms_;
  std::atomic<int64_t> max_ip_attempts_;

  mutable std::shared_mutex accounts_mutex_;
  std::map<std::string, std::unique_ptr<AccountState>, std::less<>> accounts_;

  mutable std::mutex ip_tracker_mutex_;
  std::map<std::string, std::deque<std::pair<int64_t, bool>>, std::less<>> ip_attempts_;

  mutable std::mutex addr_tracker_mutex_;
  std::map<std::string, std::deque<std::pair<int64_t, bool>>, std::less<>> addr_attempts_;
};

// ============================================================================
// 5. LoginRateLimiter — High-level login rate limit coordinator
//
// Combines token-bucket rate limiting with login attempt tracking
// for comprehensive brute-force protection.
// ============================================================================

class LoginRateLimiter {
public:
  explicit LoginRateLimiter(RateLimitConfig& config)
      : config_(config),
        attempt_tracker_(config),
        token_bucket_(0.17, 3.0) {}  // Default ~1 per 6s, burst 3

  /// Check if a login should be allowed. Returns result with details.
  /// The record_attempt should be called after the actual login
  /// attempt is processed.
  LoginAttemptTracker::LoginCheckResult check_login(
      const std::string& account,
      const std::string& ip,
      const std::string& address) {

    LoginAttemptTracker::LoginCheckResult result;

    if (!config_.is_globally_enabled()) {
      result.allowed = true;
      return result;
    }

    // 1. Check login attempt tracker first (account lockouts, per-IP, per-address)
    result = attempt_tracker_.check_login(account, ip, address);
    if (!result.allowed) return result;

    // 2. Check per-account token bucket rate limit
    double remaining;
    int64_t reset_ms;
    if (!token_bucket_.consume("acct:" + account, remaining, reset_ms)) {
      result.allowed = false;
      result.retry_after_ms = std::max<int64_t>(reset_ms - now_ms(), 1000);
      result.reason = "Login rate limit exceeded for this account";
      return result;
    }

    // 3. Check per-IP token bucket
    std::string norm_ip = normalize_ip(ip);
    // Use a separate bucket for per-IP login rates
    {
      std::lock_guard lock(ip_bucket_mutex_);
      auto& bucket = get_ip_bucket_locked(norm_ip);
      if (!bucket.consume("ip_login:" + norm_ip, remaining, reset_ms)) {
        result.allowed = false;
        result.retry_after_ms = std::max<int64_t>(reset_ms - now_ms(), 1000);
        result.reason = "Login rate limit exceeded for this IP";
        return result;
      }
    }

    result.allowed = true;
    return result;
  }

  /// Record the result of a login attempt
  void record_attempt(const std::string& account,
                      const std::string& ip,
                      const std::string& address,
                      bool success) {
    attempt_tracker_.record_attempt(account, ip, address, success);
  }

  /// Admin: clear lockout for an account
  void clear_lockout(const std::string& account) {
    attempt_tracker_.clear_account_lockout(account);
  }

  /// Admin: get locked accounts
  std::vector<std::string> locked_accounts() {
    return attempt_tracker_.locked_accounts();
  }

  /// Admin: get account info
  LoginAttemptTracker::AccountState get_account_info(const std::string& account) {
    return attempt_tracker_.get_account_info(account);
  }

  /// Cleanup stale tracking data
  size_t cleanup_stale() {
    return attempt_tracker_.cleanup_stale();
  }

  /// Update token bucket parameters
  void set_rate(double rate, double burst) {
    token_bucket_.set_params(rate, burst);
  }

  /// Configure login attempt tracking
  void configure_attempt_tracking(int64_t max_attempts,
                                   int64_t lockout_duration_ms,
                                   int64_t window_ms,
                                   int64_t max_ip_attempts) {
    attempt_tracker_.set_max_attempts(max_attempts);
    attempt_tracker_.set_lockout_duration_ms(lockout_duration_ms);
    attempt_tracker_.set_window_ms(window_ms);
    attempt_tracker_.set_max_ip_attempts(max_ip_attempts);
  }

private:
  TokenBucket& get_ip_bucket_locked(const std::string& ip) {
    auto it = ip_buckets_.find(ip);
    if (it != ip_buckets_.end()) return *it->second;
    ip_buckets_[std::string(ip)] = std::make_unique<TokenBucket>(0.17, 3.0);
    return *ip_buckets_[std::string(ip)];
  }

  RateLimitConfig& config_;
  LoginAttemptTracker attempt_tracker_;
  TokenBucket token_bucket_;  // Per-account rate limiting

  std::mutex ip_bucket_mutex_;
  std::map<std::string, std::unique_ptr<TokenBucket>, std::less<>> ip_buckets_;
};

// ============================================================================
// 6. RegistrationRateLimiter — Per-IP registration limits
//
// Prevents registration abuse by limiting registrations per IP within
// configurable time windows. Supports shared secret auth exemption
// for trusted registrations (e.g., from appservices or internal tools).
// ============================================================================

class RegistrationRateLimiter {
public:
  struct RegistrationRecord {
    int64_t timestamp_ms;
    std::string ip;
    std::string username;
    bool success;
  };

  struct RegCheckResult {
    bool allowed = true;
    int64_t retry_after_ms = 0;
    std::string reason;
    int64_t recent_registrations = 0;
    int64_t max_registrations = 5;
  };

  explicit RegistrationRateLimiter(const RateLimitConfig& config)
      : config_(config),
        max_per_ip_hour_(5),
        max_per_ip_day_(20),
        window_hour_ms_(3600000),
        window_day_ms_(86400000) {}

  /// Check if a registration should be allowed
  RegCheckResult check_registration(const std::string& ip,
                                     const std::string& username,
                                     bool is_shared_secret = false) {
    RegCheckResult result;

    if (!config_.is_globally_enabled()) {
      result.allowed = true;
      return result;
    }

    // Shared secret auth is exempt from rate limiting
    if (is_shared_secret) {
      result.allowed = true;
      return result;
    }

    std::string norm_ip = normalize_ip(ip);
    int64_t now = now_ms();

    std::lock_guard lock(mutex_);

    // Count recent registrations from this IP in the hour window
    int64_t hour_count = 0;
    int64_t day_count = 0;
    int64_t oldest_hour_ts = now;
    int64_t oldest_day_ts = now;

    auto it = ip_records_.find(norm_ip);
    if (it != ip_records_.end()) {
      for (const auto& rec : it->second) {
        int64_t age = now - rec.timestamp_ms;
        if (age < window_day_ms_) {
          day_count++;
          if (rec.timestamp_ms < oldest_day_ts) oldest_day_ts = rec.timestamp_ms;
        }
        if (age < window_hour_ms_) {
          hour_count++;
          if (rec.timestamp_ms < oldest_hour_ts) oldest_hour_ts = rec.timestamp_ms;
        }
      }
    }

    result.recent_registrations = hour_count;
    result.max_registrations = max_per_ip_hour_;

    // Check hour limit
    if (hour_count >= max_per_ip_hour_) {
      result.allowed = false;
      result.retry_after_ms = (oldest_hour_ts + window_hour_ms_) - now;
      if (result.retry_after_ms < 1000) result.retry_after_ms = 5000;
      result.reason = "Too many registrations from this IP in the last hour";
      return result;
    }

    // Check day limit
    if (day_count >= max_per_ip_day_) {
      result.allowed = false;
      result.retry_after_ms = (oldest_day_ts + window_day_ms_) - now;
      if (result.retry_after_ms < 1000) result.retry_after_ms = 30000;
      result.reason = "Too many registrations from this IP in the last 24 hours";
      return result;
    }

    // Check global per-minute burst (use a separate token bucket)
    {
      std::string global_key = "global_reg";
      double remaining;
      int64_t reset;
      if (!global_bucket_.consume(global_key, remaining, reset)) {
        result.allowed = false;
        result.retry_after_ms = std::max<int64_t>(reset - now, 1000);
        result.reason = "Global registration rate limit exceeded";
        return result;
      }
    }

    result.allowed = true;
    return result;
  }

  /// Record a registration attempt
  void record_registration(const std::string& ip,
                           const std::string& username,
                           bool success) {
    std::string norm_ip = normalize_ip(ip);
    int64_t now = now_ms();

    std::lock_guard lock(mutex_);
    ip_records_[norm_ip].push_back({now, norm_ip, username, success});

    // Prune old records
    auto& records = ip_records_[norm_ip];
    while (!records.empty() &&
           now - records.front().timestamp_ms > window_day_ms_ * 2) {
      records.pop_front();
    }
  }

  /// Admin: clear registration records for an IP
  void clear_ip(const std::string& ip) {
    std::lock_guard lock(mutex_);
    ip_records_.erase(normalize_ip(ip));
  }

  /// Get registration stats for an IP
  RegCheckResult get_ip_stats(const std::string& ip) {
    std::string norm_ip = normalize_ip(ip);
    int64_t now = now_ms();
    RegCheckResult result;

    std::lock_guard lock(mutex_);
    auto it = ip_records_.find(norm_ip);
    if (it != ip_records_.end()) {
      for (const auto& rec : it->second) {
        int64_t age = now - rec.timestamp_ms;
        if (age < window_hour_ms_) result.recent_registrations++;
      }
    }
    result.max_registrations = max_per_ip_hour_;
    result.allowed = result.recent_registrations < max_per_ip_hour_;
    return result;
  }

  /// Cleanup stale records
  size_t cleanup_stale() {
    int64_t now = now_ms();
    size_t removed = 0;
    std::lock_guard lock(mutex_);
    auto it = ip_records_.begin();
    while (it != ip_records_.end()) {
      auto& records = it->second;
      while (!records.empty() && now - records.front().timestamp_ms > window_day_ms_ * 2) {
        records.pop_front();
      }
      if (records.empty()) {
        it = ip_records_.erase(it);
        removed++;
      } else {
        ++it;
      }
    }
    return removed;
  }

  // Configuration
  void set_max_per_ip_hour(int64_t max) { max_per_ip_hour_ = max; }
  void set_max_per_ip_day(int64_t max) { max_per_ip_day_ = max; }
  void set_window_hour_ms(int64_t ms) { window_hour_ms_ = ms; }
  void set_window_day_ms(int64_t ms) { window_day_ms_ = ms; }

  int64_t max_per_ip_hour() const { return max_per_ip_hour_; }
  int64_t max_per_ip_day() const { return max_per_ip_day_; }

private:
  const RateLimitConfig& config_;
  std::atomic<int64_t> max_per_ip_hour_;
  std::atomic<int64_t> max_per_ip_day_;
  std::atomic<int64_t> window_hour_ms_;
  std::atomic<int64_t> window_day_ms_;

  std::mutex mutex_;
  std::map<std::string, std::deque<RegistrationRecord>, std::less<>> ip_records_;
  TokenBucket global_bucket_{0.05, 3.0}; // Global: 3 per minute
};

// ============================================================================
// 7. AdminRateLimiter — Separate stricter limits for admin endpoints
//
// Admin API endpoints have different rate limit profiles than client
// endpoints. Admin access is typically lower volume but more sensitive.
// ============================================================================

class AdminRateLimiter {
public:
  struct AdminLimitResult {
    bool allowed = true;
    double remaining = -1.0;
    int64_t reset_ms = 0;
    std::string reason;
  };

  explicit AdminRateLimiter(RateLimitConfig& config)
      : config_(config),
        admin_bucket_(5.0, 10.0) {} // Default: 5/s, burst 10

  /// Check if an admin request is allowed
  AdminLimitResult check_admin_request(const std::string& user_id,
                                        const std::string& ip) {
    AdminLimitResult result;

    if (!config_.is_globally_enabled()) {
      result.allowed = true;
      return result;
    }

    auto [rate, burst] = config_.effective_limits(
        EndpointCategory::ADMIN, user_id, ip);

    // Update bucket params if needed
    admin_bucket_.set_params(rate, burst);

    // Check per-user admin rate
    if (!user_id.empty()) {
      double remaining;
      int64_t reset;
      std::string key = "admin_user:" + user_id;
      if (!admin_bucket_.consume(key, remaining, reset)) {
        result.allowed = false;
        result.remaining = remaining;
        result.reset_ms = reset;
        result.reason = "Admin API rate limit exceeded for user";
        return result;
      }
      result.remaining = remaining;
      result.reset_ms = reset;
    }

    // Check per-IP admin rate
    if (!ip.empty()) {
      std::string norm_ip = normalize_ip(ip);
      double remaining;
      int64_t reset;
      std::string key = "admin_ip:" + norm_ip;
      // Per-IP admin requests use even stricter limits
      {
        std::lock_guard lock(ip_bucket_mutex_);
        auto& bucket = get_admin_ip_bucket_locked(norm_ip, rate * 0.5, burst * 0.5);
        if (!bucket.consume(key, remaining, reset)) {
          result.allowed = false;
          result.remaining = remaining;
          result.reset_ms = std::max(result.reset_ms, reset);
          result.reason = "Admin API rate limit exceeded for IP";
          return result;
        }
      }
    }

    result.allowed = true;
    return result;
  }

  /// Set admin rate limit parameters
  void set_admin_rate(double rate, double burst) {
    admin_bucket_.set_params(rate, burst);
  }

private:
  TokenBucket& get_admin_ip_bucket_locked(const std::string& ip,
                                           double rate, double burst) {
    auto it = admin_ip_buckets_.find(ip);
    if (it != admin_ip_buckets_.end()) {
      it->second->set_params(rate, burst);
      return *it->second;
    }
    admin_ip_buckets_[std::string(ip)] = std::make_unique<TokenBucket>(rate, burst);
    return *admin_ip_buckets_[std::string(ip)];
  }

  RateLimitConfig& config_;
  TokenBucket admin_bucket_;

  std::mutex ip_bucket_mutex_;
  std::map<std::string, std::unique_ptr<TokenBucket>, std::less<>> admin_ip_buckets_;
};

// ============================================================================
// 8. RateLimitHeaders — Generate standard rate limit response headers
//
// Implements the IETF draft for RateLimit headers:
//   X-RateLimit-Limit: maximum requests allowed
//   X-RateLimit-Remaining: remaining requests in window
//   X-RateLimit-Reset: time when the limit resets (UTC epoch seconds)
//   Retry-After: seconds to wait before retrying (when limited)
// ============================================================================

class RateLimitHeaders {
public:
  struct HeaderInfo {
    int64_t limit = 0;
    int64_t remaining = 0;
    int64_t reset_epoch_sec = 0;
    int64_t retry_after_ms = 0;
  };

  /// Build header info from a token bucket check result
  static HeaderInfo from_bucket(double rate, double burst,
                                 double remaining_tokens,
                                 int64_t reset_ms) {
    HeaderInfo info;
    info.limit = static_cast<int64_t>(std::ceil(burst));
    info.remaining = static_cast<int64_t>(std::max(0.0, std::floor(remaining_tokens)));
    info.reset_epoch_sec = reset_ms / 1000;
    // If limited, calculate retry-after
    if (remaining_tokens < 1.0) {
      int64_t now = now_ms();
      info.retry_after_ms = std::max<int64_t>(reset_ms - now, 1000);
    }
    return info;
  }

  /// Build header info from a per-minute window
  static HeaderInfo from_window(int64_t max_requests,
                                 int64_t remaining_requests,
                                 int64_t window_start_ms,
                                 int64_t window_duration_ms) {
    HeaderInfo info;
    info.limit = max_requests;
    info.remaining = remaining_requests;
    info.reset_epoch_sec = (window_start_ms + window_duration_ms) / 1000;
    if (remaining_requests <= 0) {
      int64_t now = now_ms();
      info.retry_after_ms = std::max<int64_t>(
          (window_start_ms + window_duration_ms) - now, 1000);
    }
    return info;
  }

  /// Build header info from a login check result
  static HeaderInfo from_login_check(
      const LoginAttemptTracker::LoginCheckResult& check,
      int64_t max_attempts) {
    HeaderInfo info;
    info.limit = max_attempts;
    info.remaining = std::max<int64_t>(0, max_attempts - check.consecutive_failures);
    info.reset_epoch_sec = now_sec() + (check.retry_after_ms / 1000);
    info.retry_after_ms = check.retry_after_ms;
    return info;
  }

  /// Build header info from a registration check
  static HeaderInfo from_reg_check(
      const RegistrationRateLimiter::RegCheckResult& check) {
    HeaderInfo info;
    info.limit = check.max_registrations;
    info.remaining = std::max<int64_t>(0, info.limit - check.recent_registrations);
    info.reset_epoch_sec = now_sec() + (check.retry_after_ms / 1000);
    info.retry_after_ms = check.retry_after_ms;
    return info;
  }

  /// Generate HTTP header map from HeaderInfo
  static std::map<std::string, std::string> to_headers(const HeaderInfo& info) {
    std::map<std::string, std::string> headers;
    headers["X-RateLimit-Limit"] = std::to_string(info.limit);
    headers["X-RateLimit-Remaining"] = std::to_string(info.remaining);
    headers["X-RateLimit-Reset"] = std::to_string(info.reset_epoch_sec);
    if (info.retry_after_ms > 0) {
      int64_t retry_sec = (info.retry_after_ms + 999) / 1000; // Ceiling
      headers["Retry-After"] = std::to_string(retry_sec);
    }
    return headers;
  }

  /// Merge multiple HeaderInfo objects (take most restrictive)
  static HeaderInfo merge(const std::vector<HeaderInfo>& infos) {
    HeaderInfo merged;
    int64_t min_remaining = std::numeric_limits<int64_t>::max();
    int64_t max_retry = 0;
    int64_t latest_reset = 0;

    for (const auto& info : infos) {
      merged.limit = std::max(merged.limit, info.limit);
      min_remaining = std::min(min_remaining, info.remaining);
      max_retry = std::max(max_retry, info.retry_after_ms);
      latest_reset = std::max(latest_reset, info.reset_epoch_sec);
    }
    merged.remaining = min_remaining;
    merged.reset_epoch_sec = latest_reset;
    merged.retry_after_ms = max_retry;
    return merged;
  }
};

// ============================================================================
// 9. RequestSizeLimiter — Maximum request body size enforcement
//
// Rejects requests whose body exceeds configured limits per endpoint
// category. Returns proper HTTP 413 Payload Too Large responses.
// ============================================================================

class RequestSizeLimiter {
public:
  struct SizeCheckResult {
    bool allowed = true;
    size_t max_bytes = 0;
    size_t received_bytes = 0;
    std::string error_message;
  };

  explicit RequestSizeLimiter(RateLimitConfig& config)
      : config_(config) {}

  /// Check if a request body size is within limits for the given endpoint
  SizeCheckResult check_size(const std::string& endpoint,
                              const std::string& method,
                              size_t content_length) {
    SizeCheckResult result;
    EndpointCategory cat = classify_endpoint(endpoint, method);
    result.max_bytes = config_.get_max_body_size(cat);

    if (content_length > result.max_bytes) {
      result.allowed = false;
      result.received_bytes = content_length;
      std::ostringstream oss;
      oss << "Request body too large: " << content_length
          << " bytes exceeds maximum " << result.max_bytes
          << " bytes for endpoint category "
          << endpoint_category_name(cat);
      result.error_message = oss.str();
      return result;
    }

    result.received_bytes = content_length;
    return result;
  }

  /// Set max body size for a specific endpoint category
  void set_max_size(EndpointCategory cat, size_t max_bytes) {
    config_.set_max_body_size(cat, max_bytes);
  }

  /// Get max body size for a category
  size_t get_max_size(EndpointCategory cat) const {
    return config_.get_max_body_size(cat);
  }

  /// Generate error response for oversized request
  static json make_error_response(const SizeCheckResult& check) {
    return json({
        {"errcode", "M_TOO_LARGE"},
        {"error", check.error_message},
        {"max_size_bytes", check.max_bytes},
        {"received_bytes", check.received_bytes}
    });
  }

private:
  RateLimitConfig& config_;
};

// ============================================================================
// 10. ConnectionLimiter — Per-IP and per-user connection limits
//
// Tracks active connections and rejects new connections when limits
// are exceeded. Uses reference counting for accurate tracking.
// ============================================================================

class ConnectionLimiter {
public:
  struct ConnectionInfo {
    std::string ip;
    std::string user_id;
    int64_t established_ms;
    uint64_t connection_id;
  };

  struct ConnCheckResult {
    bool allowed = true;
    std::string reason;
    uint64_t assigned_id = 0;
  };

  explicit ConnectionLimiter(RateLimitConfig& config)
      : config_(config), next_id_(1) {}

  /// Attempt to register a new connection. Returns result with assigned
  /// connection ID if allowed.
  ConnCheckResult try_connect(const std::string& ip,
                               const std::string& user_id) {
    ConnCheckResult result;

    if (!config_.is_globally_enabled()) {
      // Even when rate limiting is off, we may want to enforce connection
      // limits for DoS protection
    }

    std::string norm_ip = normalize_ip(ip);

    std::lock_guard lock(mutex_);

    // Check global connection limit
    if (config_.get_global_max_connections() > 0 &&
        total_connections_ >= config_.get_global_max_connections()) {
      result.allowed = false;
      result.reason = "Server at maximum connection capacity";
      return result;
    }

    // Check per-IP connection limit
    auto ip_it = ip_connections_.find(norm_ip);
    size_t ip_count = (ip_it != ip_connections_.end()) ? ip_it->second.size() : 0;
    if (ip_count >= config_.get_max_connections_per_ip()) {
      result.allowed = false;
      result.reason = "Too many connections from this IP address";
      return result;
    }

    // Check per-user connection limit
    if (!user_id.empty()) {
      auto user_it = user_connections_.find(user_id);
      size_t user_count = (user_it != user_connections_.end()) ? user_it->second.size() : 0;
      if (user_count >= config_.get_max_connections_per_user()) {
        result.allowed = false;
        result.reason = "Too many connections for this user";
        return result;
      }
    }

    // All limits pass – register the connection
    uint64_t id = next_id_++;
    result.assigned_id = id;

    ConnectionInfo info;
    info.ip = norm_ip;
    info.user_id = user_id;
    info.established_ms = now_ms();
    info.connection_id = id;

    ip_connections_[norm_ip].push_back(info);
    if (!user_id.empty()) {
      user_connections_[user_id].push_back(info);
    }
    all_connections_[id] = info;
    total_connections_++;

    return result;
  }

  /// Unregister a connection when it closes
  void disconnect(uint64_t connection_id) {
    std::lock_guard lock(mutex_);

    auto it = all_connections_.find(connection_id);
    if (it == all_connections_.end()) return;

    const auto& info = it->second;

    // Remove from IP list
    auto ip_it = ip_connections_.find(info.ip);
    if (ip_it != ip_connections_.end()) {
      auto& list = ip_it->second;
      list.erase(
          std::remove_if(list.begin(), list.end(),
              [connection_id](const ConnectionInfo& ci) {
                return ci.connection_id == connection_id;
              }),
          list.end());
      if (list.empty()) {
        ip_connections_.erase(ip_it);
      }
    }

    // Remove from user list
    if (!info.user_id.empty()) {
      auto user_it = user_connections_.find(info.user_id);
      if (user_it != user_connections_.end()) {
        auto& list = user_it->second;
        list.erase(
            std::remove_if(list.begin(), list.end(),
                [connection_id](const ConnectionInfo& ci) {
                  return ci.connection_id == connection_id;
                }),
            list.end());
        if (list.empty()) {
          user_connections_.erase(user_it);
        }
      }
    }

    all_connections_.erase(it);
    total_connections_--;
  }

  /// Get current connection counts
  size_t total_connections() const {
    return total_connections_.load();
  }

  size_t connections_for_ip(const std::string& ip) const {
    std::string norm_ip = normalize_ip(ip);
    std::lock_guard lock(mutex_);
    auto it = ip_connections_.find(norm_ip);
    return (it != ip_connections_.end()) ? it->second.size() : 0;
  }

  size_t connections_for_user(const std::string& user_id) const {
    std::lock_guard lock(mutex_);
    auto it = user_connections_.find(user_id);
    return (it != user_connections_.end()) ? it->second.size() : 0;
  }

  /// Get all connections for monitoring
  std::vector<ConnectionInfo> get_all_connections() const {
    std::lock_guard lock(mutex_);
    std::vector<ConnectionInfo> result;
    result.reserve(all_connections_.size());
    for (const auto& [id, info] : all_connections_) {
      result.push_back(info);
    }
    return result;
  }

  /// Forcibly disconnect all connections from an IP (admin action)
  std::vector<uint64_t> disconnect_ip(const std::string& ip) {
    std::string norm_ip = normalize_ip(ip);
    std::lock_guard lock(mutex_);
    std::vector<uint64_t> disconnected;

    auto it = ip_connections_.find(norm_ip);
    if (it != ip_connections_.end()) {
      for (const auto& info : it->second) {
        disconnected.push_back(info.connection_id);
        all_connections_.erase(info.connection_id);
        if (!info.user_id.empty()) {
          auto uit = user_connections_.find(info.user_id);
          if (uit != user_connections_.end()) {
            auto& ulist = uit->second;
            ulist.erase(
                std::remove_if(ulist.begin(), ulist.end(),
                    [&info](const ConnectionInfo& ci) {
                      return ci.connection_id == info.connection_id;
                    }),
                ulist.end());
            if (ulist.empty()) user_connections_.erase(uit);
          }
        }
        total_connections_--;
      }
      ip_connections_.erase(it);
    }

    return disconnected;
  }

  /// Get connection stats
  json get_stats() const {
    std::lock_guard lock(mutex_);
    json j;
    j["total_connections"] = total_connections_.load();
    j["unique_ips"] = ip_connections_.size();
    j["unique_users"] = user_connections_.size();

    // Top 10 IPs by connection count
    std::vector<std::pair<std::string, size_t>> top_ips;
    for (const auto& [ip, conns] : ip_connections_) {
      top_ips.emplace_back(ip, conns.size());
    }
    std::sort(top_ips.begin(), top_ips.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    json top = json::array();
    for (size_t i = 0; i < std::min<size_t>(top_ips.size(), 10); ++i) {
      top.push_back({
          {"ip", top_ips[i].first},
          {"connections", top_ips[i].second}
      });
    }
    j["top_ips"] = top;

    return j;
  }

private:
  RateLimitConfig& config_;
  std::atomic<uint64_t> next_id_;
  std::atomic<size_t> total_connections_{0};

  mutable std::mutex mutex_;
  std::map<std::string, std::vector<ConnectionInfo>, std::less<>> ip_connections_;
  std::map<std::string, std::vector<ConnectionInfo>, std::less<>> user_connections_;
  std::map<uint64_t, ConnectionInfo> all_connections_;
};

// ============================================================================
// 11. RateLimiter — Top-level coordinator
//
// The main facade that brings together all rate limiting components.
// Provides a simple interface for the HTTP layer to check and enforce
// rate limits on incoming requests.
// ============================================================================

class RateLimiter {
public:
  RateLimiter()
      : config_(std::make_shared<RateLimitConfig>()),
        request_limiter_(std::make_unique<RequestRateLimiter>(*config_)),
        login_limiter_(std::make_unique<LoginRateLimiter>(*config_)),
        registration_limiter_(std::make_unique<RegistrationRateLimiter>(*config_)),
        admin_limiter_(std::make_unique<AdminRateLimiter>(*config_)),
        size_limiter_(std::make_unique<RequestSizeLimiter>(*config_)),
        conn_limiter_(std::make_unique<ConnectionLimiter>(*config_)),
        enforce_enabled_(true) {}

  RateLimiter(const RateLimiter&) = delete;
  RateLimiter& operator=(const RateLimiter&) = delete;

  // ==========================================================================
  // Request check — main entry point for rate limiting a request
  // ==========================================================================

  struct RequestContext {
    std::string user_id;
    std::string ip;
    std::string endpoint;
    std::string method;
    size_t content_length = 0;
    bool is_admin = false;
    bool is_login = false;
    bool is_register = false;
    bool is_shared_secret = false;  // Exempts registration limits
  };

  struct RateLimitResult {
    bool allowed = true;
    int http_status = 200;
    json error_body;
    std::map<std::string, std::string> headers;
    int64_t retry_after_ms = 0;

    // Rate limit details for observability
    std::string limit_source;
    double remaining = -1;
    int64_t reset_ms = 0;
  };

  /// Check a full request against all applicable rate limits
  RateLimitResult check_request(const RequestContext& ctx) {
    RateLimitResult result;

    if (!enforce_enabled_) {
      result.allowed = true;
      result.headers = build_no_limit_headers();
      return result;
    }

    // 1. Connection limit check (always enforced)
    // (Connection tracking is done separately via try_connect/disconnect)

    // 2. Request size check
    {
      auto size_check = size_limiter_->check_size(
          ctx.endpoint, ctx.method, ctx.content_length);
      if (!size_check.allowed) {
        result.allowed = false;
        result.http_status = 413;
        result.error_body = RequestSizeLimiter::make_error_response(size_check);
        result.limit_source = "size";
        return result;
      }
    }

    // 3. Admin-specific rate limiting
    if (ctx.is_admin || classify_endpoint(ctx.endpoint, ctx.method) == EndpointCategory::ADMIN) {
      auto admin_check = admin_limiter_->check_admin_request(ctx.user_id, ctx.ip);
      if (!admin_check.allowed) {
        result.allowed = false;
        result.http_status = 429;
        result.error_body = make_ratelimit_error(
            "M_LIMIT_EXCEEDED",
            admin_check.reason,
            std::max<int64_t>(admin_check.reset_ms - now_ms(), 1000));
        result.retry_after_ms = admin_check.reset_ms - now_ms();
        result.limit_source = "admin";
        result.remaining = admin_check.remaining;
        result.reset_ms = admin_check.reset_ms;

        auto hinfo = RateLimitHeaders::from_bucket(
            10.0, 20.0, admin_check.remaining, admin_check.reset_ms);
        result.headers = RateLimitHeaders::to_headers(hinfo);
        return result;
      }
    }

    // 4. Login-specific rate limiting
    if (ctx.is_login) {
      // (Login checks are complex and use LoginRateLimiter, handled separately)
      // For now, use general request limiter but more strictly
    }

    // 5. Registration-specific rate limiting
    if (ctx.is_register) {
      auto reg_check = registration_limiter_->check_registration(
          ctx.ip, ctx.user_id, ctx.is_shared_secret);
      if (!reg_check.allowed) {
        result.allowed = false;
        result.http_status = 429;
        result.error_body = make_ratelimit_error(
            "M_LIMIT_EXCEEDED",
            reg_check.reason,
            reg_check.retry_after_ms);
        result.retry_after_ms = reg_check.retry_after_ms;
        result.limit_source = "registration";

        auto hinfo = RateLimitHeaders::from_reg_check(reg_check);
        result.headers = RateLimitHeaders::to_headers(hinfo);
        return result;
      }
    }

    // 6. General request rate limiting (all dimensions)
    {
      auto req_check = request_limiter_->check_and_consume(
          ctx.user_id, ctx.ip, ctx.endpoint, ctx.method);

      if (!req_check.allowed) {
        result.allowed = false;
        result.http_status = 429;
        std::string err_msg = "Too many requests";
        if (req_check.limit_source == "user") {
          err_msg = "Too many requests from this user";
        } else if (req_check.limit_source == "ip") {
          err_msg = "Too many requests from this IP";
        } else if (req_check.limit_source == "endpoint") {
          err_msg = "Too many requests to this endpoint";
        }
        result.error_body = make_ratelimit_error(
            "M_LIMIT_EXCEEDED",
            err_msg,
            std::max<int64_t>(req_check.reset_ms - now_ms(), 1000));
        result.retry_after_ms = req_check.reset_ms - now_ms();
        result.limit_source = req_check.limit_source;

        // Build rate limit headers
        EndpointCategory cat = classify_endpoint(ctx.endpoint, ctx.method);
        auto [rate, burst] = config_->effective_limits(cat, ctx.user_id, ctx.ip);

        std::vector<RateLimitHeaders::HeaderInfo> hinfos;
        if (req_check.user_remaining >= 0) {
          hinfos.push_back(RateLimitHeaders::from_bucket(
              rate, burst, req_check.user_remaining, req_check.reset_ms));
        }
        if (req_check.ip_remaining >= 0) {
          hinfos.push_back(RateLimitHeaders::from_bucket(
              rate, burst, req_check.ip_remaining, req_check.reset_ms));
        }
        result.headers = RateLimitHeaders::to_headers(
            RateLimitHeaders::merge(hinfos));

        if (req_check.remaining > 0) {
          result.remaining = req_check.remaining;
          result.reset_ms = req_check.reset_ms;
        }

        return result;
      }

      // Request allowed – add informational headers
      EndpointCategory cat = classify_endpoint(ctx.endpoint, ctx.method);
      auto [rate, burst] = config_->effective_limits(cat, ctx.user_id, ctx.ip);

      RateLimitHeaders::HeaderInfo hinfo;
      hinfo.limit = static_cast<int64_t>(std::ceil(burst));
      hinfo.remaining = static_cast<int64_t>(std::max(0.0,
          std::min({req_check.user_remaining >= 0 ? req_check.user_remaining : 1e9,
                    req_check.ip_remaining >= 0 ? req_check.ip_remaining : 1e9,
                    req_check.endpoint_remaining >= 0 ? req_check.endpoint_remaining : 1e9})));
      hinfo.reset_epoch_sec = req_check.reset_ms / 1000;
      result.headers = RateLimitHeaders::to_headers(hinfo);
      result.remaining = hinfo.remaining;
      result.reset_ms = req_check.reset_ms;
    }

    result.allowed = true;
    return result;
  }

  // ==========================================================================
  // Login rate limiting — specialized interface
  // ==========================================================================

  /// Check if a login attempt should be allowed (before processing)
  LoginAttemptTracker::LoginCheckResult check_login(
      const std::string& account,
      const std::string& ip,
      const std::string& address) {
    if (!enforce_enabled_) return {true, 0, "", 0};
    return login_limiter_->check_login(account, ip, address);
  }

  /// Record the result of a login attempt
  void record_login_attempt(const std::string& account,
                            const std::string& ip,
                            const std::string& address,
                            bool success) {
    login_limiter_->record_attempt(account, ip, address, success);
  }

  // ==========================================================================
  // Registration rate limiting — specialized interface
  // ==========================================================================

  RegistrationRateLimiter::RegCheckResult check_registration(
      const std::string& ip,
      const std::string& username,
      bool is_shared_secret = false) {
    if (!enforce_enabled_) return {true, 0, "", 0, 0};
    return registration_limiter_->check_registration(ip, username, is_shared_secret);
  }

  void record_registration(const std::string& ip,
                           const std::string& username,
                           bool success) {
    registration_limiter_->record_registration(ip, username, success);
  }

  // ==========================================================================
  // Connection tracking
  // ==========================================================================

  ConnectionLimiter::ConnCheckResult try_connect(const std::string& ip,
                                                   const std::string& user_id) {
    return conn_limiter_->try_connect(ip, user_id);
  }

  void disconnect(uint64_t connection_id) {
    conn_limiter_->disconnect(connection_id);
  }

  // ==========================================================================
  // Request size checking
  // ==========================================================================

  RequestSizeLimiter::SizeCheckResult check_body_size(
      const std::string& endpoint,
      const std::string& method,
      size_t content_length) {
    return size_limiter_->check_size(endpoint, method, content_length);
  }

  // ==========================================================================
  // Dynamic configuration
  // ==========================================================================

  void set_enabled(bool enabled) {
    enforce_enabled_ = enabled;
    config_->set_global_enabled(enabled);
  }

  bool is_enabled() const {
    return enforce_enabled_;
  }

  /// Update rate limits for a category
  void set_category_limits(EndpointCategory cat,
                           double rate_per_sec,
                           double burst,
                           int64_t window_sec = 60) {
    RateLimitConfig::CategoryConfig cfg;
    cfg.rate_per_sec = rate_per_sec;
    cfg.burst = burst;
    cfg.window_sec = window_sec;
    cfg.enabled = true;
    cfg.name = endpoint_category_name(cat);
    config_->set_category(cat, cfg);
  }

  /// Set per-user override
  void set_user_override(const std::string& user_id,
                         std::optional<double> rate_per_sec,
                         std::optional<double> burst) {
    config_->set_user_override(user_id, rate_per_sec, burst);
  }

  /// Remove per-user override
  void remove_user_override(const std::string& user_id) {
    config_->remove_user_override(user_id);
  }

  /// Set max body size for a category
  void set_max_body_size(EndpointCategory cat, size_t max_bytes) {
    size_limiter_->set_max_size(cat, max_bytes);
  }

  /// Configure login attempt limits
  void configure_login_limits(int64_t max_attempts,
                               int64_t lockout_ms,
                               int64_t window_ms,
                               int64_t max_ip_attempts) {
    login_limiter_->configure_attempt_tracking(
        max_attempts, lockout_ms, window_ms, max_ip_attempts);
  }

  /// Set connection limits
  void set_connection_limits(size_t per_ip, size_t per_user, size_t global_max) {
    config_->set_max_connections_per_ip(per_ip);
    config_->set_max_connections_per_user(per_user);
    config_->set_global_max_connections(global_max);
  }

  // ==========================================================================
  // Admin operations
  // ==========================================================================

  /// Clear login lockout for an account
  void admin_clear_lockout(const std::string& account) {
    login_limiter_->clear_lockout(account);
  }

  /// Clear registration records for an IP
  void admin_clear_reg_ip(const std::string& ip) {
    registration_limiter_->clear_ip(ip);
  }

  /// Get all locked accounts
  std::vector<std::string> admin_locked_accounts() {
    return login_limiter_->locked_accounts();
  }

  /// Get connection stats
  json admin_connection_stats() {
    return conn_limiter_->get_stats();
  }

  /// Forcibly disconnect all connections from an IP
  std::vector<uint64_t> admin_disconnect_ip(const std::string& ip) {
    return conn_limiter_->disconnect_ip(ip);
  }

  /// Get rate limit stats
  json admin_rate_limit_stats() {
    json j;
    j["config"] = config_->to_json();
    j["request_limiter"] = request_limiter_->get_stats();
    j["connections"] = conn_limiter_->get_stats();
    j["locked_accounts"] = login_limiter_->locked_accounts();
    return j;
  }

  // ==========================================================================
  // Periodic maintenance
  // ==========================================================================

  /// Periodic cleanup of stale rate limit entries (call every ~5 minutes)
  size_t cleanup() {
    size_t total = 0;
    total += request_limiter_->cleanup_all();
    total += login_limiter_->cleanup_stale();
    total += registration_limiter_->cleanup_stale();
    return total;
  }

  // ==========================================================================
  // Access to sub-components for advanced use
  // ==========================================================================

  RateLimitConfig& config() { return *config_; }
  const RateLimitConfig& config() const { return *config_; }
  RequestRateLimiter& request_limiter() { return *request_limiter_; }
  LoginRateLimiter& login() { return *login_limiter_; }
  RegistrationRateLimiter& registration() { return *registration_limiter_; }
  AdminRateLimiter& admin() { return *admin_limiter_; }
  RequestSizeLimiter& size_limiter() { return *size_limiter_; }
  ConnectionLimiter& connections() { return *conn_limiter_; }

private:
  static std::map<std::string, std::string> build_no_limit_headers() {
    std::map<std::string, std::string> headers;
    headers["X-RateLimit-Limit"] = "unlimited";
    headers["X-RateLimit-Remaining"] = "unlimited";
    headers["X-RateLimit-Reset"] = "0";
    return headers;
  }

  std::shared_ptr<RateLimitConfig> config_;
  std::unique_ptr<RequestRateLimiter> request_limiter_;
  std::unique_ptr<LoginRateLimiter> login_limiter_;
  std::unique_ptr<RegistrationRateLimiter> registration_limiter_;
  std::unique_ptr<AdminRateLimiter> admin_limiter_;
  std::unique_ptr<RequestSizeLimiter> size_limiter_;
  std::unique_ptr<ConnectionLimiter> conn_limiter_;
  std::atomic<bool> enforce_enabled_{true};
};

// ============================================================================
// 12. Global rate limiter instance management
//
// Provides ergonomic access to a shared RateLimiter instance for the
// entire server process with thread-safe lazy initialization.
// ============================================================================

namespace {

/// Thread-safe once-flag for lazy construction
std::once_flag g_rate_limiter_init_flag;

/// The global rate limiter instance
std::unique_ptr<RateLimiter> g_rate_limiter;

} // anonymous namespace

/// Get (or create) the global rate limiter instance
RateLimiter& rate_limiter() {
  std::call_once(g_rate_limiter_init_flag, []() {
    g_rate_limiter = std::make_unique<RateLimiter>();
  });
  return *g_rate_limiter;
}

/// Initialize the rate limiter with custom configuration
void init_rate_limiter(std::shared_ptr<RateLimitConfig> custom_config) {
  std::call_once(g_rate_limiter_init_flag, [&custom_config]() {
    // Create with custom config
    g_rate_limiter = std::make_unique<RateLimiter>();
    // Replace the default config
    // (This is a simplified approach; in production you'd pass config to ctor)
  });
  // If already initialized, update config on the existing instance
  if (g_rate_limiter) {
    // Apply custom config overrides...
  }
}

/// Shutdown and cleanup the rate limiter
void shutdown_rate_limiter() {
  if (g_rate_limiter) {
    g_rate_limiter->cleanup();
    g_rate_limiter.reset();
  }
}

// ============================================================================
// 13. HTTP integration helpers
//
// Convenience functions for use in HTTP request handlers that check
// rate limits and inject response headers.
// ============================================================================

/// Shortcut: check a request and return a result, or set 429 response
/// headers directly on an HTTP response object.
/// Returns true if request is allowed, false if rate limited.
/// Caller should use the returned headers for the response.
struct RateLimitHttpResult {
  bool allowed;
  int status_code;         // 200 or 429
  json error_json;
  std::map<std::string, std::string> response_headers;

  /// Get the Retry-After in seconds for the response
  int64_t retry_after_sec() const {
    auto it = response_headers.find("Retry-After");
    if (it != response_headers.end()) {
      try {
        return std::stoll(it->second);
      } catch (...) {
        return 1;
      }
    }
    return 0;
  }
};

/// Check rate limits for a standard Matrix client API request
RateLimitHttpResult check_client_request(
    const std::string& user_id,
    const std::string& ip,
    const std::string& endpoint,
    const std::string& method,
    size_t content_length = 0) {

  RateLimiter::RequestContext ctx;
  ctx.user_id = user_id;
  ctx.ip = ip;
  ctx.endpoint = endpoint;
  ctx.method = method;
  ctx.content_length = content_length;
  ctx.is_login = (endpoint.find("/login") != std::string::npos &&
                  endpoint.find("/_matrix/client/") != std::string::npos);
  ctx.is_register = (endpoint.find("/register") != std::string::npos &&
                     endpoint.find("/_matrix/client/") != std::string::npos);
  ctx.is_admin = (endpoint.find("/_synapse/admin/") != std::string::npos ||
                  endpoint.find("/_progressive/admin/") != std::string::npos);

  auto result = rate_limiter().check_request(ctx);

  RateLimitHttpResult http_result;
  http_result.allowed = result.allowed;
  http_result.status_code = result.http_status;
  http_result.error_json = result.error_body;
  http_result.response_headers = result.headers;
  return http_result;
}

/// Check rate limits for a login attempt
RateLimitHttpResult check_login_request(
    const std::string& account,
    const std::string& ip,
    const std::string& address,
    const std::string& endpoint) {

  // First check general rate limits
  auto general = check_client_request("", ip, endpoint, "POST");
  if (!general.allowed) return general;

  // Then check login-specific limits
  auto login_check = rate_limiter().check_login(account, ip, address);

  RateLimitHttpResult http_result;
  if (!login_check.allowed) {
    http_result.allowed = false;
    http_result.status_code = 429;
    http_result.error_json = make_ratelimit_error(
        "M_LIMIT_EXCEEDED",
        login_check.reason,
        login_check.retry_after_ms);

    auto hinfo = RateLimitHeaders::from_login_check(
        login_check, 5);
    http_result.response_headers = RateLimitHeaders::to_headers(hinfo);
  } else {
    http_result.allowed = true;
    http_result.status_code = 200;
    http_result.response_headers = general.response_headers;
  }
  return http_result;
}

/// Check rate limits for a registration attempt
RateLimitHttpResult check_registration_request(
    const std::string& ip,
    const std::string& username,
    bool is_shared_secret,
    const std::string& endpoint) {

  auto reg_check = rate_limiter().check_registration(
      ip, username, is_shared_secret);

  RateLimitHttpResult http_result;
  if (!reg_check.allowed) {
    http_result.allowed = false;
    http_result.status_code = 429;
    http_result.error_json = make_ratelimit_error(
        "M_LIMIT_EXCEEDED",
        reg_check.reason,
        reg_check.retry_after_ms);

    auto hinfo = RateLimitHeaders::from_reg_check(reg_check);
    http_result.response_headers = RateLimitHeaders::to_headers(hinfo);
  } else {
    http_result.allowed = true;
    http_result.status_code = 200;
  }
  return http_result;
}

/// Check rate limits for a federation request
RateLimitHttpResult check_federation_request(
    const std::string& origin_server,
    const std::string& ip,
    const std::string& endpoint,
    const std::string& method,
    size_t content_length = 0) {

  RateLimiter::RequestContext ctx;
  ctx.user_id = origin_server; // Use server name as user_id for federation
  ctx.ip = ip;
  ctx.endpoint = endpoint;
  ctx.method = method;
  ctx.content_length = content_length;

  auto result = rate_limiter().check_request(ctx);

  RateLimitHttpResult http_result;
  http_result.allowed = result.allowed;
  http_result.status_code = result.http_status;
  http_result.error_json = result.error_body;
  http_result.response_headers = result.headers;
  return http_result;
}

/// Check rate limits for an admin API request
RateLimitHttpResult check_admin_request(
    const std::string& user_id,
    const std::string& ip,
    const std::string& endpoint,
    const std::string& method,
    size_t content_length = 0) {

  RateLimiter::RequestContext ctx;
  ctx.user_id = user_id;
  ctx.ip = ip;
  ctx.endpoint = endpoint;
  ctx.method = method;
  ctx.content_length = content_length;
  ctx.is_admin = true;

  auto result = rate_limiter().check_request(ctx);

  RateLimitHttpResult http_result;
  http_result.allowed = result.allowed;
  http_result.status_code = result.http_status;
  http_result.error_json = result.error_body;
  http_result.response_headers = result.headers;
  return http_result;
}

} // namespace progressive
