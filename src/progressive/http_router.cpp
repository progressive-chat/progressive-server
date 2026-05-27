// ============================================================================
// http_router.cpp — Matrix HTTP Request Router, Middleware Pipeline,
//                   REST Servlet Dispatch, Request/Response Processing
//
// Implements:
//   - HTTPRouter: Central request dispatcher that bridges Boost.Beast HTTP
//     with the internal progressive::rest servlet infrastructure.
//   - MiddlewarePipeline: Pluggable middleware chain supporting auth, rate
//     limiting, CORS header injection, request/response logging, body size
//     enforcement, content-type validation, and custom middleware.
//   - Path Parameter Extraction: Regex-based pattern matching with named
//     parameter extraction from URL path templates ({paramName} syntax).
//   - Query Parameter Parsing: Full query string parsing with typed
//     extractors (integer, string, boolean, float, array, JSON).
//   - Request Body JSON Parsing: Parse application/json bodies with
//     comprehensive error handling, malformed JSON detection, and
//     size-limit enforcement.
//   - Error Handling: Standard Matrix error responses (M_NOT_FOUND,
//     M_UNKNOWN, M_MISSING_TOKEN, M_UNKNOWN_TOKEN, M_BAD_JSON,
//     M_NOT_JSON, M_LIMIT_EXCEEDED, M_UNSUPPORTED_METHOD, etc.)
//     with proper HTTP status codes and JSON error bodies.
//   - CORS Support: Full CORS preflight handling, configurable origin
//     allowlist, method/header allowlists, max-age support.
//   - Auth Middleware: Access token validation via AuthHelper,
//     guest access support, appservice authentication, admin check.
//   - Rate Limit Middleware: Per-user, per-IP, per-endpoint rate
//     limiting with token bucket algorithm, configurable burst/rate,
//     rate limit headers (X-RateLimit-*).
//   - Logging Middleware: Structured request/response logging with
//     timing, status codes, user context, and configurable log levels.
//   - Servlet Registration: Register REST servlets by path pattern,
//     HTTP method, and handler; automatic method routing within servlets.
//   - Media Endpoint Handling: Content repository upload, download,
//     thumbnail generation dispatch with proper content-type handling.
//   - Well-Known Endpoints: /.well-known/matrix/client and /server
//     endpoint dispatching.
//   - Federation Endpoints: Server-to-server API routing for /_matrix/federation/.
//   - Health Check: /health and /_matrix/health endpoint support.
//   - Metrics: Basic request counting, timing histograms, status code
//     counters for observability.
//
// Equivalent to:
//   synapse/http/server.py (listener/site setup)
//   synapse/http/servlet.py (servlet routing)
//   synapse/http/site.py (request handling)
//   synapse/http/matrixfederationclient.py (federation routing)
//   synapse/rest/__init__.py (servlet registration)
//   synapse/http/additional_resource.py (extra endpoints)
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
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

#include <nlohmann/json.hpp>

#include "progressive/http/router.hpp"
#include "progressive/rest/rest_base.hpp"
#include "progressive/rest/client/client_auth.hpp"
#include "progressive/rest/client/client_room.hpp"
#include "progressive/rest/client/client_devices.hpp"
#include "progressive/rest/admin/admin_rest.hpp"
#include "progressive/storage/database.hpp"

// ============================================================================
// Namespace
// ============================================================================

namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// Typedefs for readability
using rest::BaseRestServlet;
using rest::ClientV1RestServlet;
using rest::HttpRequest;
using rest::HttpResponse;
using rest::AuthHelper;
using rest::Requester;
using rest::ServletRegistry;
using storage::DatabasePool;

// Forward declarations for classes defined in this file
class TokenBucket;
class RateLimitConfig;
class MiddlewareChain;
class HttpRouterImpl;
class RequestLogger;
class CorsHandler;
class QueryParamParser;
class PathParamExtractor;
class JsonBodyParser;

// ============================================================================
// Constants
// ============================================================================

namespace router_constants {

// Default maximum request body size (50 MB)
constexpr size_t kDefaultMaxBodySize = 50 * 1024 * 1024;

// Default rate limit: 100 requests per second, burst 200
constexpr double kDefaultRate = 100.0;
constexpr double kDefaultBurst = 200.0;

// Login/registration rate limits (more restrictive)
constexpr double kLoginRate = 5.0;
constexpr double kLoginBurst = 10.0;

// Admin API rate limits
constexpr double kAdminRate = 50.0;
constexpr double kAdminBurst = 100.0;

// Federation rate limits
constexpr double kFederationRate = 200.0;
constexpr double kFederationBurst = 500.0;

// Media upload limits
constexpr double kMediaRate = 10.0;
constexpr double kMediaBurst = 20.0;

// Rate limit window (seconds)
constexpr double kRateLimitWindowSec = 1.0;

// Cleanup interval for stale rate limit entries (seconds)
constexpr int64_t kCleanupIntervalSec = 300;

// Maximum concurrent requests (global)
constexpr int64_t kMaxConcurrentRequests = 5000;

// CORS max age (seconds)
constexpr int64_t kCorsMaxAge = 86400;

// Allowed HTTP methods
const std::vector<std::string> kAllowedMethods = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"
};

// Allowed CORS headers
const std::vector<std::string> kAllowedHeaders = {
    "Content-Type", "Authorization", "X-Requested-With",
    "Accept", "Origin", "User-Agent"
};

// Exposed CORS headers
const std::vector<std::string> kExposedHeaders = {
    "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset",
    "Retry-After"
};

// Matrix error codes
constexpr const char* kErrNotFound = "M_NOT_FOUND";
constexpr const char* kErrUnknown = "M_UNKNOWN";
constexpr const char* kErrMissingToken = "M_MISSING_TOKEN";
constexpr const char* kErrUnknownToken = "M_UNKNOWN_TOKEN";
constexpr const char* kErrBadJson = "M_BAD_JSON";
constexpr const char* kErrNotJson = "M_NOT_JSON";
constexpr const char* kErrLimitExceeded = "M_LIMIT_EXCEEDED";
constexpr const char* kErrUnsupportedMethod = "M_UNSUPPORTED";
constexpr const char* kErrForbidden = "M_FORBIDDEN";
constexpr const char* kErrInvalidParam = "M_INVALID_PARAM";
constexpr const char* kErrTooLarge = "M_TOO_LARGE";
constexpr const char* kErrGuestForbidden = "M_GUEST_ACCESS_FORBIDDEN";
constexpr const char* kErrUserDeactivated = "M_USER_DEACTIVATED";
constexpr const char* kErrConsentNotGiven = "M_CONSENT_NOT_GIVEN";

// Server header value
constexpr const char* kServerHeader = "Progressive/1.0";

} // namespace router_constants

// ============================================================================
// Utility: URL Decode
// ============================================================================

namespace {

std::string url_decode(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    for (size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '%' && i + 2 < str.size()) {
            int hi = 0, lo = 0;
            char c = str[i + 1];
            if (c >= '0' && c <= '9') hi = c - '0';
            else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
            else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
            else { result += str[i]; continue; }
            c = str[i + 2];
            if (c >= '0' && c <= '9') lo = c - '0';
            else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
            else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
            else { result += str[i]; continue; }
            result += static_cast<char>((hi << 4) | lo);
            i += 2;
        } else if (str[i] == '+') {
            result += ' ';
        } else {
            result += str[i];
        }
    }
    return result;
}

// --------------------------------------------------------------------------
// Utility: Trim whitespace
// --------------------------------------------------------------------------

std::string trim(const std::string& s) {
    auto start = s.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\n\r\f\v");
    return s.substr(start, end - start + 1);
}

// --------------------------------------------------------------------------
// Utility: String to lowercase
// --------------------------------------------------------------------------

std::string to_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return r;
}

// --------------------------------------------------------------------------
// Utility: Check if string starts with prefix
// --------------------------------------------------------------------------

bool starts_with(const std::string& s, const std::string& prefix) {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

// --------------------------------------------------------------------------
// Utility: Get current timestamp in milliseconds
// --------------------------------------------------------------------------

int64_t now_ms() {
    return chr::duration_cast<chr::milliseconds>(
               chr::system_clock::now().time_since_epoch())
        .count();
}

// --------------------------------------------------------------------------
// Utility: Get current timestamp in seconds (double precision)
// --------------------------------------------------------------------------

double now_sec() {
    return chr::duration_cast<chr::microseconds>(
               chr::steady_clock::now().time_since_epoch())
               .count() / 1e6;
}

// --------------------------------------------------------------------------
// Utility: HTTP verb enum to string
// --------------------------------------------------------------------------

std::string verb_to_string(boost::beast::http::verb v) {
    switch (v) {
        case boost::beast::http::verb::get: return "GET";
        case boost::beast::http::verb::post: return "POST";
        case boost::beast::http::verb::put: return "PUT";
        case boost::beast::http::verb::delete_: return "DELETE";
        case boost::beast::http::verb::patch: return "PATCH";
        case boost::beast::http::verb::head: return "HEAD";
        case boost::beast::http::verb::options: return "OPTIONS";
        default: return "UNKNOWN";
    }
}

// --------------------------------------------------------------------------
// Utility: String to HTTP verb
// --------------------------------------------------------------------------

boost::beast::http::verb string_to_verb(const std::string& method) {
    if (method == "GET") return boost::beast::http::verb::get;
    if (method == "POST") return boost::beast::http::verb::post;
    if (method == "PUT") return boost::beast::http::verb::put;
    if (method == "DELETE") return boost::beast::http::verb::delete_;
    if (method == "PATCH") return boost::beast::http::verb::patch;
    if (method == "HEAD") return boost::beast::http::verb::head;
    if (method == "OPTIONS") return boost::beast::http::verb::options;
    return boost::beast::http::verb::unknown;
}

} // anonymous namespace

// ============================================================================
// TokenBucket — Thread-safe token bucket rate limiter
// ============================================================================

class TokenBucket {
public:
    TokenBucket(double rate, double burst)
        : rate_(rate), burst_(burst), tokens_(burst),
          last_update_(chr::steady_clock::now()) {}

    // Try to consume one token. Returns true if allowed.
    bool consume() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = chr::steady_clock::now();
        double elapsed = chr::duration_cast<chr::microseconds>(
                             now - last_update_).count() / 1e6;
        tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
        last_update_ = now;
        if (tokens_ >= 1.0) {
            tokens_ -= 1.0;
            return true;
        }
        return false;
    }

    // Try to consume N tokens. Returns true if allowed.
    bool consume_n(double n) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = chr::steady_clock::now();
        double elapsed = chr::duration_cast<chr::microseconds>(
                             now - last_update_).count() / 1e6;
        tokens_ = std::min(burst_, tokens_ + elapsed * rate_);
        last_update_ = now;
        if (tokens_ >= n) {
            tokens_ -= n;
            return true;
        }
        return false;
    }

    // Get current token count (for diagnostics)
    double tokens() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return tokens_;
    }

    // Get rate config
    double rate() const { return rate_; }
    double burst() const { return burst_; }

    // Reconfigure rate limits
    void reconfigure(double rate, double burst) {
        std::lock_guard<std::mutex> lock(mutex_);
        rate_ = rate;
        burst_ = burst;
        tokens_ = std::min(tokens_, burst_);
    }

private:
    mutable std::mutex mutex_;
    double rate_;
    double burst_;
    double tokens_;
    chr::steady_clock::time_point last_update_;
};

// ============================================================================
// RateLimitConfig — Configuration for rate limiting
// ============================================================================

class RateLimitConfig {
public:
    struct EndpointCategory {
        double rate;
        double burst;
        std::string name;
    };

    RateLimitConfig() {
        // Default categories
        categories_["default"]      = {router_constants::kDefaultRate,
                                       router_constants::kDefaultBurst, "default"};
        categories_["login"]        = {router_constants::kLoginRate,
                                       router_constants::kLoginBurst, "login"};
        categories_["register"]     = {router_constants::kLoginRate,
                                       router_constants::kLoginBurst, "register"};
        categories_["admin"]        = {router_constants::kAdminRate,
                                       router_constants::kAdminBurst, "admin"};
        categories_["federation"]   = {router_constants::kFederationRate,
                                       router_constants::kFederationBurst, "federation"};
        categories_["media_upload"] = {router_constants::kMediaRate,
                                       router_constants::kMediaBurst, "media_upload"};
        categories_["media_download"] = {router_constants::kDefaultRate,
                                          router_constants::kDefaultBurst,
                                          "media_download"};
        categories_["sync"]         = {50.0, 100.0, "sync"};
        categories_["search"]       = {20.0, 40.0, "search"};
    }

    // Get category for an endpoint path
    std::string categorize(const std::string& path) const {
        if (starts_with(path, "/_matrix/client/v3/login") ||
            starts_with(path, "/_matrix/client/v1/login")) {
            return "login";
        }
        if (starts_with(path, "/_matrix/client/v3/register") ||
            starts_with(path, "/_matrix/client/v1/register")) {
            return "register";
        }
        if (starts_with(path, "/_synapse/admin/")) {
            return "admin";
        }
        if (starts_with(path, "/_matrix/federation/")) {
            return "federation";
        }
        if (starts_with(path, "/_matrix/media/v3/upload") ||
            starts_with(path, "/_matrix/media/v1/upload")) {
            return "media_upload";
        }
        if (starts_with(path, "/_matrix/media/")) {
            return "media_download";
        }
        if (starts_with(path, "/_matrix/client/v3/sync") ||
            starts_with(path, "/_matrix/client/v1/sync")) {
            return "sync";
        }
        if (starts_with(path, "/_matrix/client/v3/search") ||
            starts_with(path, "/_matrix/client/v1/search")) {
            return "search";
        }
        return "default";
    }

    // Get rate limits for a category
    std::pair<double, double> get(const std::string& category) const {
        auto it = categories_.find(category);
        if (it != categories_.end()) {
            return {it->second.rate, it->second.burst};
        }
        return {router_constants::kDefaultRate,
                router_constants::kDefaultBurst};
    }

    // Reconfigure a category
    void set(const std::string& category, double rate, double burst) {
        categories_[category] = {rate, burst, category};
    }

    // List all categories
    std::map<std::string, EndpointCategory> all() const {
        return categories_;
    }

private:
    std::map<std::string, EndpointCategory> categories_;
};

// ============================================================================
// RateLimiter — Multi-key rate limiter
// ============================================================================

class RateLimiter {
public:
    explicit RateLimiter(const RateLimitConfig& config)
        : config_(config), last_cleanup_(now_sec()) {}

    // Check if a request is allowed for (key, category).
    // Returns true if allowed, false if rate limited.
    bool allow(const std::string& key, const std::string& category) {
        auto [rate, burst] = config_.get(category);
        std::string bucket_key = category + ":" + key;

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = buckets_.find(bucket_key);
        if (it == buckets_.end()) {
            auto bucket = std::make_unique<TokenBucket>(rate, burst);
            bool ok = bucket->consume();
            buckets_[bucket_key] = std::move(bucket);
            return ok;
        }
        // Update rate/burst if category config changed
        it->second->reconfigure(rate, burst);
        bool ok = it->second->consume();

        // Periodic cleanup of stale entries
        double now = now_sec();
        if (now - last_cleanup_ > router_constants::kCleanupIntervalSec) {
            cleanup_stale();
            last_cleanup_ = now;
        }

        return ok;
    }

    // Get remaining tokens for diagnostics
    double remaining(const std::string& key, const std::string& category) const {
        std::string bucket_key = category + ":" + key;
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = buckets_.find(bucket_key);
        if (it != buckets_.end()) {
            return it->second->tokens();
        }
        return config_.get(category).second; // full burst
    }

    // Get limit for category
    double limit(const std::string& category) const {
        return config_.get(category).first;
    }

    // Get burst for category
    double burst(const std::string& category) const {
        return config_.get(category).second;
    }

    // Clear all buckets
    void clear() {
        std::lock_guard<std::mutex> lock(mutex_);
        buckets_.clear();
    }

    // Get bucket count
    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return buckets_.size();
    }

private:
    void cleanup_stale() {
        // Remove buckets that are at full burst (unused)
        auto it = buckets_.begin();
        while (it != buckets_.end()) {
            auto [rate, burst] = config_.get(
                it->first.substr(0, it->first.find(':')));
            if (it->second->tokens() >= burst * 0.99) {
                it = buckets_.erase(it);
            } else {
                ++it;
            }
        }
    }

    mutable std::mutex mutex_;
    const RateLimitConfig& config_;
    std::map<std::string, std::unique_ptr<TokenBucket>> buckets_;
    double last_cleanup_;
};

// ============================================================================
// ConnectionTracker — Track active connections per IP/user
// ============================================================================

class ConnectionTracker {
public:
    ConnectionTracker(int64_t max_per_ip = 100, int64_t max_per_user = 200,
                      int64_t max_total = router_constants::kMaxConcurrentRequests)
        : max_per_ip_(max_per_ip), max_per_user_(max_per_user),
          max_total_(max_total) {}

    // Try to acquire a connection slot. Returns true if allowed.
    bool acquire(const std::string& client_ip,
                 const std::optional<std::string>& user_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (total_connections_ >= max_total_) {
            return false;
        }
        // Check per-IP limit
        if (ip_connections_[client_ip] >= max_per_ip_) {
            return false;
        }
        // Check per-user limit
        if (user_id.has_value() &&
            user_connections_[*user_id] >= max_per_user_) {
            return false;
        }
        total_connections_++;
        ip_connections_[client_ip]++;
        if (user_id.has_value()) {
            user_connections_[*user_id]++;
        }
        return true;
    }

    // Release a connection slot
    void release(const std::string& client_ip,
                 const std::optional<std::string>& user_id) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (total_connections_ > 0) total_connections_--;
        auto it = ip_connections_.find(client_ip);
        if (it != ip_connections_.end()) {
            if (it->second > 0) it->second--;
            if (it->second == 0) ip_connections_.erase(it);
        }
        if (user_id.has_value()) {
            auto uit = user_connections_.find(*user_id);
            if (uit != user_connections_.end()) {
                if (uit->second > 0) uit->second--;
                if (uit->second == 0) user_connections_.erase(uit);
            }
        }
    }

    // Get current connection counts
    int64_t total() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return total_connections_;
    }

    int64_t per_ip(const std::string& ip) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = ip_connections_.find(ip);
        return it != ip_connections_.end() ? it->second : 0;
    }

private:
    mutable std::mutex mutex_;
    int64_t max_per_ip_;
    int64_t max_per_user_;
    int64_t max_total_;
    int64_t total_connections_{0};
    std::map<std::string, int64_t> ip_connections_;
    std::map<std::string, int64_t> user_connections_;
};

// ============================================================================
// RequestMetrics — Basic request metrics collection
// ============================================================================

class RequestMetrics {
public:
    struct Snapshot {
        int64_t total_requests;
        int64_t status_2xx;
        int64_t status_3xx;
        int64_t status_4xx;
        int64_t status_5xx;
        double avg_latency_ms;
        double p50_latency_ms;
        double p99_latency_ms;
        int64_t rate_limited;
        int64_t auth_failures;
        int64_t active_connections;
    };

    void record_request(int status_code, double latency_ms) {
        total_requests_++;
        if (status_code >= 200 && status_code < 300) status_2xx_++;
        else if (status_code >= 300 && status_code < 400) status_3xx_++;
        else if (status_code >= 400 && status_code < 500) status_4xx_++;
        else if (status_code >= 500) status_5xx_++;

        // Keep a rolling window of latencies (last 1000)
        std::lock_guard<std::mutex> lock(mutex_);
        latencies_.push_back(latency_ms);
        sum_latency_ += latency_ms;
        if (latencies_.size() > 1000) {
            sum_latency_ -= latencies_.front();
            latencies_.pop_front();
        }
    }

    void record_rate_limited() { rate_limited_++; }
    void record_auth_failure() { auth_failures_++; }

    Snapshot snapshot() const {
        Snapshot s;
        s.total_requests = total_requests_.load();
        s.status_2xx = status_2xx_.load();
        s.status_3xx = status_3xx_.load();
        s.status_4xx = status_4xx_.load();
        s.status_5xx = status_5xx_.load();
        s.rate_limited = rate_limited_.load();
        s.auth_failures = auth_failures_.load();
        s.active_connections = 0; // set externally

        std::lock_guard<std::mutex> lock(mutex_);
        if (!latencies_.empty()) {
            s.avg_latency_ms = sum_latency_ / latencies_.size();
            // Compute p50 and p99 from sorted copy
            std::vector<double> sorted(latencies_.begin(), latencies_.end());
            std::sort(sorted.begin(), sorted.end());
            size_t p50_idx = sorted.size() * 50 / 100;
            size_t p99_idx = sorted.size() * 99 / 100;
            if (p50_idx >= sorted.size()) p50_idx = sorted.size() - 1;
            if (p99_idx >= sorted.size()) p99_idx = sorted.size() - 1;
            s.p50_latency_ms = sorted.empty() ? 0 : sorted[p50_idx];
            s.p99_latency_ms = sorted.empty() ? 0 : sorted[p99_idx];
        }
        return s;
    }

    void reset() {
        total_requests_ = 0;
        status_2xx_ = 0; status_3xx_ = 0;
        status_4xx_ = 0; status_5xx_ = 0;
        rate_limited_ = 0; auth_failures_ = 0;
        std::lock_guard<std::mutex> lock(mutex_);
        latencies_.clear();
        sum_latency_ = 0;
    }

private:
    std::atomic<int64_t> total_requests_{0};
    std::atomic<int64_t> status_2xx_{0};
    std::atomic<int64_t> status_3xx_{0};
    std::atomic<int64_t> status_4xx_{0};
    std::atomic<int64_t> status_5xx_{0};
    std::atomic<int64_t> rate_limited_{0};
    std::atomic<int64_t> auth_failures_{0};

    mutable std::mutex mutex_;
    std::deque<double> latencies_;
    double sum_latency_{0};
};

// ============================================================================
// PathParamExtractor — Extract named parameters from URL path patterns
// ============================================================================

class PathParamExtractor {
public:
    // Compile a path pattern like "/rooms/{roomId}/send/{eventType}/{txnId}"
    // into a regex and a list of parameter names.
    struct CompiledPattern {
        std::regex regex;
        std::vector<std::string> param_names;
        std::string original;
    };

    static CompiledPattern compile(const std::string& pattern) {
        CompiledPattern result;
        result.original = pattern;

        std::string re_str;
        size_t pos = 0;
        while (pos < pattern.size()) {
            if (pattern[pos] == '{') {
                auto end = pattern.find('}', pos);
                if (end == std::string::npos) {
                    // Malformed pattern — treat rest as literal
                    re_str += pattern.substr(pos);
                    break;
                }
                std::string param_name = pattern.substr(pos + 1, end - pos - 1);
                result.param_names.push_back(param_name);
                // Match one or more non-slash characters for the parameter
                re_str += "([^/]+)";
                pos = end + 1;
            } else if (pattern[pos] == '.') {
                re_str += "\\.";
                pos++;
            } else if (pattern[pos] == '*') {
                // Wildcard: match zero or more of any character
                re_str += ".*";
                pos++;
            } else if (pattern[pos] == '?' ||
                       pattern[pos] == '+' ||
                       pattern[pos] == '[' ||
                       pattern[pos] == ']' ||
                       pattern[pos] == '(' ||
                       pattern[pos] == ')' ||
                       pattern[pos] == '\\' ||
                       pattern[pos] == '^' ||
                       pattern[pos] == '$' ||
                       pattern[pos] == '|') {
                re_str += '\\';
                re_str += pattern[pos];
                pos++;
            } else {
                re_str += pattern[pos];
                pos++;
            }
        }
        re_str = "^" + re_str + "$";
        result.regex = std::regex(re_str, std::regex::optimize);
        return result;
    }

    // Try to match a path against a compiled pattern.
    // Returns map of parameter name -> value if matched, nullopt otherwise.
    static std::optional<std::map<std::string, std::string>>
    match(const CompiledPattern& compiled, const std::string& path) {
        std::smatch match_result;
        if (!std::regex_match(path, match_result, compiled.regex)) {
            return std::nullopt;
        }
        std::map<std::string, std::string> params;
        for (size_t i = 0;
             i < compiled.param_names.size() && i + 1 < match_result.size();
             ++i) {
            params[compiled.param_names[i]] =
                url_decode(match_result[i + 1].str());
        }
        return params;
    }

    // Extract query parameters from a full target URI string.
    // Handles the "?key=value&key2=value2" portion after the path.
    static std::map<std::string, std::string>
    extract_query_params(const std::string& target) {
        std::map<std::string, std::string> params;
        auto query_pos = target.find('?');
        if (query_pos == std::string::npos) {
            return params;
        }
        std::string query = target.substr(query_pos + 1);

        size_t pos = 0;
        while (pos < query.size()) {
            // Find next '&' or end of string
            auto amp_pos = query.find('&', pos);
            std::string pair;
            if (amp_pos == std::string::npos) {
                pair = query.substr(pos);
                pos = query.size();
            } else {
                pair = query.substr(pos, amp_pos - pos);
                pos = amp_pos + 1;
            }

            // Split on '='
            auto eq_pos = pair.find('=');
            if (eq_pos == std::string::npos) {
                // Key with no value
                params[url_decode(pair)] = "";
            } else {
                std::string key = url_decode(pair.substr(0, eq_pos));
                std::string value = url_decode(pair.substr(eq_pos + 1));
                params[key] = value;
            }
        }
        return params;
    }
};

// ============================================================================
// QueryParamParser — Typed query parameter parsing
// ============================================================================

class QueryParamParser {
public:
    explicit QueryParamParser(const std::map<std::string, std::string>& params)
        : params_(params) {}

    // Parse a string parameter
    std::optional<std::string> get_string(const std::string& name) const {
        auto it = params_.find(name);
        if (it != params_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    // Parse a string parameter with default
    std::string get_string_or(const std::string& name,
                              const std::string& default_val) const {
        auto it = params_.find(name);
        return it != params_.end() ? it->second : default_val;
    }

    // Parse an integer parameter
    std::optional<int64_t> get_int(const std::string& name) const {
        auto val = get_string(name);
        if (!val.has_value()) return std::nullopt;
        try {
            return std::stoll(*val);
        } catch (...) {
            return std::nullopt;
        }
    }

    // Parse an integer parameter with default
    int64_t get_int_or(const std::string& name, int64_t default_val) const {
        auto val = get_int(name);
        return val.value_or(default_val);
    }

    // Parse a float/double parameter
    std::optional<double> get_double(const std::string& name) const {
        auto val = get_string(name);
        if (!val.has_value()) return std::nullopt;
        try {
            return std::stod(*val);
        } catch (...) {
            return std::nullopt;
        }
    }

    // Parse a boolean parameter (true/1/yes vs false/0/no)
    std::optional<bool> get_bool(const std::string& name) const {
        auto val = get_string(name);
        if (!val.has_value()) return std::nullopt;
        std::string lower = to_lower(trim(*val));
        if (lower == "true" || lower == "1" || lower == "yes" ||
            lower == "on") {
            return true;
        }
        if (lower == "false" || lower == "0" || lower == "no" ||
            lower == "off") {
            return false;
        }
        return std::nullopt;
    }

    // Parse a boolean parameter with default
    bool get_bool_or(const std::string& name, bool default_val) const {
        auto val = get_bool(name);
        return val.value_or(default_val);
    }

    // Parse a comma-separated list parameter
    std::vector<std::string> get_list(const std::string& name) const {
        auto val = get_string(name);
        if (!val.has_value() || val->empty()) return {};
        std::vector<std::string> result;
        std::stringstream ss(*val);
        std::string item;
        while (std::getline(ss, item, ',')) {
            item = trim(item);
            if (!item.empty()) {
                result.push_back(item);
            }
        }
        return result;
    }

    // Check if a parameter exists
    bool has(const std::string& name) const {
        return params_.find(name) != params_.end();
    }

    // Get all raw parameters
    const std::map<std::string, std::string>& all() const {
        return params_;
    }

private:
    const std::map<std::string, std::string>& params_;
};

// ============================================================================
// JsonBodyParser — Parse and validate JSON request bodies
// ============================================================================

class JsonBodyParser {
public:
    struct ParseResult {
        json data;
        std::optional<std::string> error;
        bool success{false};
    };

    // Parse JSON from a request body string with size limit enforcement.
    static ParseResult parse(const std::string& body,
                             size_t max_size = router_constants::kDefaultMaxBodySize,
                             bool allow_empty = false) {
        ParseResult result;

        // Check size
        if (body.size() > max_size) {
            result.error = "Request body too large (max " +
                           std::to_string(max_size) + " bytes)";
            result.success = false;
            return result;
        }

        // Handle empty body
        if (body.empty()) {
            if (allow_empty) {
                result.data = json::object();
                result.success = true;
                return result;
            }
            result.error = "Empty request body";
            result.success = false;
            return result;
        }

        // Parse JSON
        try {
            result.data = json::parse(body);
            result.success = true;
        } catch (const json::parse_error& e) {
            result.error = std::string("Malformed JSON: ") + e.what();
            result.success = false;
        } catch (const std::exception& e) {
            result.error = std::string("JSON parse error: ") + e.what();
            result.success = false;
        }

        return result;
    }

    // Parse JSON from a request, extracting the body field from the content.
    // Returns the parsed JSON or an error response.
    static std::pair<std::optional<json>, std::optional<HttpResponse>>
    parse_or_error(const HttpRequest& req,
                   size_t max_size = router_constants::kDefaultMaxBodySize,
                   bool allow_empty = false) {
        // Check content type
        auto ct_it = req.headers.find("content-type");
        bool is_json = false;
        if (ct_it != req.headers.end()) {
            std::string ct = to_lower(ct_it->second);
            is_json = (ct.find("application/json") != std::string::npos);
        }

        if (!is_json && !req.body.empty()) {
            HttpResponse err = error_response(
                400, router_constants::kErrNotJson,
                "Content-Type must be application/json");
            return {std::nullopt, err};
        }

        auto result = parse(req.body, max_size, allow_empty);
        if (!result.success) {
            HttpResponse err = error_response(
                400, router_constants::kErrBadJson,
                result.error.value_or("Failed to parse request body"));
            return {std::nullopt, err};
        }

        return {result.data, std::nullopt};
    }

private:
    static HttpResponse error_response(int code, const std::string& errcode,
                                        const std::string& error) {
        HttpResponse res;
        res.code = code;
        res.body = {{"errcode", errcode}, {"error", error}};
        res.content_type = "application/json";
        return res;
    }
};

// ============================================================================
// CorsHandler — CORS header injection and preflight handling
// ============================================================================

class CorsHandler {
public:
    struct Config {
        std::vector<std::string> allowed_origins;
        std::vector<std::string> allowed_methods;
        std::vector<std::string> allowed_headers;
        std::vector<std::string> exposed_headers;
        int64_t max_age_sec;
        bool allow_credentials;
    };

    explicit CorsHandler(const Config& config) : config_(config) {}

    // Check if an origin is allowed
    bool is_origin_allowed(const std::string& origin) const {
        if (config_.allowed_origins.empty()) return true;
        if (config_.allowed_origins.size() == 1 &&
            config_.allowed_origins[0] == "*") {
            return true;
        }
        for (const auto& allowed : config_.allowed_origins) {
            if (allowed == origin) return true;
            // Simple wildcard matching: "*.example.com"
            if (starts_with(allowed, "*.")) {
                std::string suffix = allowed.substr(1); // "*.example.com" -> ".example.com"
                if (origin.size() >= suffix.size() &&
                    origin.compare(origin.size() - suffix.size(),
                                   suffix.size(), suffix) == 0) {
                    return true;
                }
            }
        }
        return false;
    }

    // Inject CORS headers into a response
    void inject(HttpResponse& res, const std::string& origin,
                const std::string& method) {
        // Access-Control-Allow-Origin
        if (config_.allowed_origins.size() == 1 &&
            config_.allowed_origins[0] == "*") {
            res.headers["Access-Control-Allow-Origin"] = "*";
        } else if (is_origin_allowed(origin)) {
            res.headers["Access-Control-Allow-Origin"] = origin;
            if (config_.allow_credentials) {
                res.headers["Access-Control-Allow-Credentials"] = "true";
            }
        }

        // Access-Control-Allow-Methods
        std::string methods_str;
        for (size_t i = 0; i < config_.allowed_methods.size(); ++i) {
            if (i > 0) methods_str += ", ";
            methods_str += config_.allowed_methods[i];
        }
        res.headers["Access-Control-Allow-Methods"] = methods_str;

        // Access-Control-Allow-Headers
        std::string headers_str;
        for (size_t i = 0; i < config_.allowed_headers.size(); ++i) {
            if (i > 0) headers_str += ", ";
            headers_str += config_.allowed_headers[i];
        }
        res.headers["Access-Control-Allow-Headers"] = headers_str;

        // Access-Control-Expose-Headers
        std::string exposed_str;
        for (size_t i = 0; i < config_.exposed_headers.size(); ++i) {
            if (i > 0) exposed_str += ", ";
            exposed_str += config_.exposed_headers[i];
        }
        if (!exposed_str.empty()) {
            res.headers["Access-Control-Expose-Headers"] = exposed_str;
        }

        // Access-Control-Max-Age
        res.headers["Access-Control-Max-Age"] =
            std::to_string(config_.max_age_sec);
    }

    // Handle a CORS preflight (OPTIONS) request
    HttpResponse handle_preflight(const std::string& origin,
                                   const std::string& request_method,
                                   const std::string& request_headers) {
        HttpResponse res;
        res.code = 200;
        res.body = json::object();

        inject(res, origin, request_method);
        return res;
    }

    static CorsHandler create_default() {
        Config c;
        c.allowed_origins = {"*"};
        c.allowed_methods = router_constants::kAllowedMethods;
        c.allowed_headers = router_constants::kAllowedHeaders;
        c.exposed_headers = router_constants::kExposedHeaders;
        c.max_age_sec = router_constants::kCorsMaxAge;
        c.allow_credentials = true;
        return CorsHandler(c);
    }

private:
    Config config_;
};

// ============================================================================
// RequestLogger — Structured request/response logging
// ============================================================================

class RequestLogger {
public:
    enum class Level {
        DEBUG = 0,
        INFO = 1,
        WARNING = 2,
        ERROR = 3,
        OFF = 4
    };

    struct Config {
        Level level{Level::INFO};
        bool log_headers{false};
        bool log_bodies{false};
        size_t max_body_log_len{1024};
        bool include_timing{true};
        std::string log_format{"json"}; // "json" or "text"
        std::ostream* output_stream{&std::cerr};
    };

    explicit RequestLogger(const Config& config) : config_(config) {}

    // Log an incoming request
    void log_request(const std::string& request_id,
                     const std::string& method,
                     const std::string& path,
                     const std::string& client_ip,
                     const std::optional<std::string>& user_id,
                     const std::map<std::string, std::string>& headers) {
        if (config_.level > Level::INFO) return;

        auto now = chr::system_clock::now();
        auto time_t = chr::system_clock::to_time_t(now);
        auto ms = chr::duration_cast<chr::milliseconds>(
                      now.time_since_epoch()) % 1000;

        std::stringstream ss;
        if (config_.log_format == "json") {
            json entry;
            entry["type"] = "request";
            entry["request_id"] = request_id;
            entry["method"] = method;
            entry["path"] = path;
            entry["client_ip"] = client_ip;
            if (user_id.has_value()) entry["user_id"] = *user_id;
            entry["timestamp_ms"] = chr::duration_cast<chr::milliseconds>(
                now.time_since_epoch()).count();

            if (config_.log_headers && !headers.empty()) {
                json hdrs = json::object();
                for (const auto& [k, v] : headers) {
                    // Redact sensitive headers
                    std::string lk = to_lower(k);
                    if (lk == "authorization" || lk.find("token") != std::string::npos) {
                        hdrs[k] = "[REDACTED]";
                    } else {
                        hdrs[k] = v;
                    }
                }
                entry["headers"] = hdrs;
            }
            ss << entry.dump();
        } else {
            // Text format
            std::tm tm{};
            localtime_r(&time_t, &tm);
            ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S.")
               << std::setfill('0') << std::setw(3) << ms.count()
               << " [" << request_id << "] "
               << method << " " << path
               << " from " << client_ip;
            if (user_id.has_value()) {
                ss << " user=" << *user_id;
            }
        }

        std::lock_guard<std::mutex> lock(mutex_);
        (*config_.output_stream) << ss.str() << std::endl;
    }

    // Log a completed response
    void log_response(const std::string& request_id,
                      int status_code,
                      double latency_ms,
                      size_t response_size,
                      const std::optional<std::string>& error_info) {
        if (config_.level > Level::INFO) return;

        auto now = chr::system_clock::now();

        std::stringstream ss;
        if (config_.log_format == "json") {
            json entry;
            entry["type"] = "response";
            entry["request_id"] = request_id;
            entry["status_code"] = status_code;
            entry["response_size"] = response_size;
            if (config_.include_timing) {
                entry["latency_ms"] = latency_ms;
            }
            if (error_info.has_value()) {
                entry["error"] = *error_info;
            }
            entry["timestamp_ms"] = chr::duration_cast<chr::milliseconds>(
                now.time_since_epoch()).count();
            ss << entry.dump();
        } else {
            ss << "  [" << request_id << "] -> " << status_code;
            if (config_.include_timing) {
                ss << " in " << std::fixed << std::setprecision(2)
                   << latency_ms << "ms";
            }
            if (error_info.has_value()) {
                ss << " error=" << *error_info;
            }
            ss << " size=" << response_size;
        }

        std::lock_guard<std::mutex> lock(mutex_);
        (*config_.output_stream) << ss.str() << std::endl;
    }

    // Log an error
    void log_error(const std::string& request_id,
                   const std::string& message,
                   const std::string& detail = "") {
        if (config_.level > Level::ERROR) return;

        std::stringstream ss;
        if (config_.log_format == "json") {
            json entry;
            entry["type"] = "error";
            entry["request_id"] = request_id;
            entry["message"] = message;
            if (!detail.empty()) entry["detail"] = detail;
            ss << entry.dump();
        } else {
            ss << "  [" << request_id << "] ERROR: " << message;
            if (!detail.empty()) ss << " (" << detail << ")";
        }

        std::lock_guard<std::mutex> lock(mutex_);
        (*config_.output_stream) << ss.str() << std::endl;
    }

    // Generate a unique request ID
    static std::string generate_request_id() {
        static std::atomic<int64_t> counter{0};
        auto now = chr::system_clock::now().time_since_epoch().count();
        auto n = counter.fetch_add(1, std::memory_order_relaxed);
        std::stringstream ss;
        ss << std::hex << now << "-" << n;
        return ss.str();
    }

private:
    Config config_;
    mutable std::mutex mutex_;
};

// ============================================================================
// AuthMiddleware — Request authentication and authorization
// ============================================================================

class AuthMiddleware {
public:
    explicit AuthMiddleware(DatabasePool& db) : db_(db), auth_helper_(db) {}

    // Authenticate a request and return Requester info.
    // Returns (requester, error_response).
    // If error_response is set, the request should be rejected.
    struct AuthResult {
        std::optional<Requester> requester;
        std::optional<HttpResponse> error;
    };

    AuthResult authenticate(const HttpRequest& req, bool require_auth = true) {
        AuthResult result;

        // Check for access token in Authorization header or query parameter
        std::optional<std::string> token;

        // Bearer token in Authorization header
        auto auth_it = req.headers.find("authorization");
        if (auth_it == req.headers.end()) {
            auth_it = req.headers.find("Authorization");
        }
        if (auth_it != req.headers.end()) {
            std::string auth_val = auth_it->second;
            if (starts_with(auth_val, "Bearer ")) {
                token = auth_val.substr(7);
            }
        }

        // Query parameter access_token fallback
        if (!token.has_value()) {
            auto qp_it = req.query_params.find("access_token");
            if (qp_it != req.query_params.end()) {
                token = qp_it->second;
            }
        }

        // If no token and auth is required, return error
        if (!token.has_value()) {
            if (require_auth) {
                result.error = error_response(
                    401, router_constants::kErrMissingToken,
                    "Missing access token");
            } else {
                // Create an anonymous/guest requester
                Requester anon;
                anon.user_id = "";
                anon.is_guest = true;
                result.requester = anon;
            }
            return result;
        }

        // Validate token
        auto requester = auth_helper_.get_user_by_access_token(*token);
        if (!requester.has_value()) {
            result.error = error_response(
                401, router_constants::kErrUnknownToken,
                "Unrecognised access token");
            return result;
        }

        // Check if user is allowed
        if (!auth_helper_.check_user_allowed(*requester)) {
            if (requester->shadow_banned) {
                // Shadow-banned users get a fake 403
                result.error = error_response(
                    403, router_constants::kErrForbidden,
                    "Access denied");
            } else {
                result.error = error_response(
                    403, router_constants::kErrUserDeactivated,
                    "User account has been deactivated");
            }
            return result;
        }

        // Check guest access for authenticated endpoints
        if (require_auth && requester->is_guest) {
            // Guests may be allowed on some endpoints (like /sync)
            // This is checked per-servlet; we just pass the requester through
            result.requester = requester;
            return result;
        }

        result.requester = requester;
        return result;
    }

    // Check if a requester has admin access
    AuthResult require_admin(const HttpRequest& req) {
        auto auth_result = authenticate(req, true);
        if (auth_result.error.has_value()) return auth_result;

        if (!auth_result.requester->is_admin) {
            auth_result.error = error_response(
                403, router_constants::kErrForbidden,
                "You are not a server admin");
            auth_result.requester = std::nullopt;
        }
        return auth_result;
    }

    // Check appservice authentication
    std::optional<Requester> authenticate_appservice(const HttpRequest& req) {
        // Appservice auth uses hs_token in query params
        auto qp_it = req.query_params.find("access_token");
        if (qp_it == req.query_params.end()) {
            qp_it = req.query_params.find("hs_token");
        }
        if (qp_it == req.query_params.end()) {
            return std::nullopt;
        }

        // Look up appservice by token
        // For now, create a special appservice requester
        // In production, this would validate against registered appservices
        Requester as;
        as.user_id = qp_it->second; // placeholder
        as.is_admin = true;
        as.app_service_id = qp_it->second;
        return as;
    }

private:
    DatabasePool& db_;
    AuthHelper auth_helper_;

    static HttpResponse error_response(int code, const std::string& errcode,
                                        const std::string& error) {
        HttpResponse res;
        res.code = code;
        res.body = {{"errcode", errcode}, {"error", error}};
        res.content_type = "application/json";
        return res;
    }
};

// ============================================================================
// MiddlewareChain — Pluggable middleware pipeline
// ============================================================================

enum class MiddlewarePhase {
    PRE_AUTH,     // Before authentication (CORS, body limits)
    POST_AUTH,    // After authentication (rate limiting)
    PRE_HANDLER,  // Before servlet handler
    POST_HANDLER, // After servlet handler (logging, metrics)
};

// Middleware function: takes a request and returns either a response
// (to short-circuit) or nullopt (to continue the chain).
using MiddlewareFunc = std::function<std::optional<HttpResponse>(
    HttpRequest& req, const std::optional<Requester>& requester)>;

struct MiddlewareEntry {
    std::string name;
    MiddlewarePhase phase;
    MiddlewareFunc handler;
    int priority{0}; // Higher priority = earlier execution
};

class MiddlewareChain {
public:
    // Add middleware
    void add(const std::string& name, MiddlewarePhase phase,
             MiddlewareFunc handler, int priority = 0) {
        middlewares_.push_back({name, phase, std::move(handler), priority});
    }

    // Execute middleware for a given phase in priority order.
    // Returns a response to short-circuit, or nullopt to continue.
    std::optional<HttpResponse> execute(MiddlewarePhase phase,
                                         HttpRequest& req,
                                         const std::optional<Requester>& requester) {
        // Collect entries for this phase and sort by priority
        std::vector<MiddlewareEntry*> entries;
        for (auto& mw : middlewares_) {
            if (mw.phase == phase) {
                entries.push_back(&mw);
            }
        }
        std::sort(entries.begin(), entries.end(),
                  [](const MiddlewareEntry* a, const MiddlewareEntry* b) {
                      return a->priority > b->priority;
                  });

        for (auto* mw : entries) {
            auto result = mw->handler(req, requester);
            if (result.has_value()) {
                return result; // Short-circuit
            }
        }
        return std::nullopt;
    }

    // Remove middleware by name
    bool remove(const std::string& name) {
        auto it = std::remove_if(middlewares_.begin(), middlewares_.end(),
                                  [&name](const MiddlewareEntry& e) {
                                      return e.name == name;
                                  });
        if (it != middlewares_.end()) {
            middlewares_.erase(it, middlewares_.end());
            return true;
        }
        return false;
    }

    // List all middleware
    std::vector<std::string> list() const {
        std::vector<std::string> names;
        for (const auto& mw : middlewares_) {
            names.push_back(mw.name);
        }
        return names;
    }

    // Clear all middleware
    void clear() { middlewares_.clear(); }

private:
    std::vector<MiddlewareEntry> middlewares_;
};

// ============================================================================
// ServletRoute — A registered servlet with compiled pattern
// ============================================================================

struct ServletRoute {
    std::unique_ptr<BaseRestServlet> servlet;
    PathParamExtractor::CompiledPattern compiled_pattern;
    std::vector<std::string> http_methods; // Methods this servlet accepts
    std::string original_pattern;
    int priority{0}; // Routes with higher priority are checked first

    // Match against a path and method
    std::optional<std::map<std::string, std::string>>
    match(const std::string& path, const std::string& method) const {
        // Check method first (fast path)
        bool method_ok = false;
        for (const auto& m : http_methods) {
            if (m == method || m == "OPTIONS") {
                method_ok = true;
                break;
            }
        }
        if (!method_ok) return std::nullopt;

        return PathParamExtractor::match(compiled_pattern, path);
    }
};

// ============================================================================
// ServletManager — Register and dispatch to REST servlets
// ============================================================================

class ServletManager {
public:
    explicit ServletManager(DatabasePool& db) : db_(db) {}

    // Register a servlet
    void register_servlet(std::unique_ptr<BaseRestServlet> servlet) {
        auto patterns = servlet->patterns();
        auto methods = servlet->methods();
        // Determine priority: more specific (longer) patterns get higher priority
        // Also, patterns without wildcard params get priority over those with them

        for (const auto& pattern : patterns) {
            ServletRoute route;
            route.servlet = std::unique_ptr<BaseRestServlet>(
                // We can't clone the servlet, so for patterns that share a
                // servlet we need a different approach. The ServletRegistry
                // from rest_base.hpp handles this per-pattern.
                // Here we register each pattern with the same servlet ptr.
                nullptr // placeholder; real registration uses separate instances
            );
            route.compiled_pattern = PathParamExtractor::compile(pattern);
            route.http_methods = methods;
            route.original_pattern = pattern;

            // Priority: longer patterns first, exact matches before param matches
            route.priority = static_cast<int>(pattern.size() * 10);
            // Penalize patterns with parameters
            bool has_params = pattern.find('{') != std::string::npos;
            if (has_params) route.priority -= 5;

            routes_.push_back(std::move(route));
        }

        // Store the servlet for actual dispatch
        servlets_.push_back(std::move(servlet));

        // Sort routes by priority
        std::sort(routes_.begin(), routes_.end(),
                  [](const ServletRoute& a, const ServletRoute& b) {
                      return a.priority > b.priority;
                  });
    }

    // Register using the rest_base ServletRegistry pattern
    void register_servlets_from_registry(ServletRegistry& registry) {
        // The ServletRegistry in rest_base.hpp has its own routing mechanism.
        // We integrate by wrapping it: for each pattern in our routes, we
        // try the registry first if our servlet chain doesn't handle it.
        // This is handled at the HttpRouter level.
    }

    // Route a request to the appropriate servlet
    struct RouteResult {
        std::optional<HttpResponse> response;
        std::map<std::string, std::string> path_params;
        bool matched{false};
    };

    RouteResult route(const HttpRequest& req) {
        RouteResult result;
        std::string path = req.path;
        std::string method = req.method;

        // Try each route
        for (auto& route : routes_) {
            auto params = route.match(path, method);
            if (params.has_value()) {
                result.path_params = std::move(*params);
                result.matched = true;
                return result; // servlet dispatch is done externally
            }
        }

        // Try the servlet-based approach: iterate over all registered servlets
        for (auto& servlet : servlets_) {
            auto patterns = servlet->patterns();
            auto methods = servlet->methods();

            // Check method
            bool method_ok = false;
            for (const auto& m : methods) {
                if (m == method) { method_ok = true; break; }
            }
            if (!method_ok) continue;

            // Try each pattern
            for (const auto& pattern : patterns) {
                auto compiled = PathParamExtractor::compile(pattern);
                auto params = PathParamExtractor::match(compiled, path);
                if (params.has_value()) {
                    result.path_params = std::move(*params);
                    result.matched = true;
                    return result;
                }
            }
        }

        return result;
    }

    // Get the number of registered routes
    size_t route_count() const { return routes_.size(); }
    size_t servlet_count() const { return servlets_.size(); }

    // Get all registered servlets
    const std::vector<std::unique_ptr<BaseRestServlet>>& servlets() const {
        return servlets_;
    }

private:
    DatabasePool& db_;
    std::vector<ServletRoute> routes_;
    std::vector<std::unique_ptr<BaseRestServlet>> servlets_;
};

// ============================================================================
// HttpRouterImpl — The main HTTP router implementation
// ============================================================================

class HttpRouterImpl {
public:
    struct Config {
        // Rate limiting
        bool rate_limit_enabled{true};
        RateLimitConfig rate_limit_config;

        // CORS
        CorsHandler::Config cors_config;

        // Logging
        RequestLogger::Config log_config;

        // Body size limits
        size_t max_body_size{router_constants::kDefaultMaxBodySize};
        size_t max_upload_size{100 * 1024 * 1024}; // 100 MB for uploads

        // Connection limits
        int64_t max_connections_per_ip{100};
        int64_t max_connections_per_user{200};
        int64_t max_total_connections{
            router_constants::kMaxConcurrentRequests};

        // Features
        bool enable_metrics{true};
        bool enable_request_id{true};
        bool strict_cors{false};
        bool enable_compression{false};

        // Server identity
        std::string server_name{"localhost"};
        std::string server_version{"Progressive/1.0"};
    };

    explicit HttpRouterImpl(DatabasePool& db, const Config& config = Config{})
        : db_(db),
          config_(config),
          rate_limiter_(config.rate_limit_config),
          connection_tracker_(config.max_connections_per_ip,
                              config.max_connections_per_user,
                              config.max_total_connections),
          cors_handler_(config.cors_config),
          request_logger_(config.log_config),
          auth_middleware_(db),
          servlet_manager_(db) {
        // Set up default middleware pipeline
        setup_default_middleware();
    }

    // ----------------------------------------------------------------------
    // Main request entry point: converts Boost.Beast request to internal
    // format, runs through middleware pipeline, dispatches to servlet,
    // and converts response back to Boost.Beast format.
    // ----------------------------------------------------------------------
    boost::beast::http::response<boost::beast::http::string_body>
    handle(boost::beast::http::request<boost::beast::http::string_body>&& req) {
        auto start_time = chr::steady_clock::now();
        std::string request_id;

        if (config_.enable_request_id) {
            request_id = RequestLogger::generate_request_id();
        }

        // ------------------------------------------------------------------
        // Step 1: Convert Boost.Beast request to internal HttpRequest
        // ------------------------------------------------------------------
        HttpRequest internal_req = beast_to_internal(req);

        // ------------------------------------------------------------------
        // Step 2: Connection tracking (pre-middleware)
        // ------------------------------------------------------------------
        std::optional<std::string> user_id_early;
        if (!connection_tracker_.acquire(internal_req.client_ip,
                                          user_id_early)) {
            // Too many connections; reject
            auto res = make_beast_error(
                boost::beast::http::status::service_unavailable,
                router_constants::kErrLimitExceeded,
                "Too many concurrent connections",
                request_id);
            inject_cors_headers(res, internal_req);
            record_metrics(503, start_time);
            return res;
        }

        // RAII guard for connection release
        struct ConnectionGuard {
            ConnectionTracker& tracker;
            std::string ip;
            std::optional<std::string> uid;
            ~ConnectionGuard() { tracker.release(ip, uid); }
            void set_user(const std::string& u) { uid = u; }
        } conn_guard{connection_tracker_, internal_req.client_ip,
                      std::nullopt};

        // ------------------------------------------------------------------
        // Step 3: Log the incoming request
        // ------------------------------------------------------------------
        std::optional<std::string> log_user_id;
        {
            auto auth_it = internal_req.headers.find("authorization");
            if (auth_it == internal_req.headers.end()) {
                auth_it = internal_req.headers.find("Authorization");
            }
            if (auth_it != internal_req.headers.end() &&
                starts_with(auth_it->second, "Bearer ")) {
                // Don't log the token, just note that auth is present
                log_user_id = "[authenticated]";
            }
        }
        request_logger_.log_request(request_id, internal_req.method,
                                     internal_req.path,
                                     internal_req.client_ip,
                                     log_user_id,
                                     internal_req.headers);

        try {
            // --------------------------------------------------------------
            // Step 4: Pre-auth middleware (CORS preflight, body limits, etc.)
            // --------------------------------------------------------------
            {
                std::optional<Requester> empty_req;
                auto mw_result = middleware_chain_.execute(
                    MiddlewarePhase::PRE_AUTH, internal_req, empty_req);
                if (mw_result.has_value()) {
                    auto res = internal_to_beast(*mw_result, request_id);
                    inject_cors_headers(res, internal_req);
                    auto elapsed = chr::duration_cast<chr::microseconds>(
                        chr::steady_clock::now() - start_time).count() / 1e3;
                    request_logger_.log_response(
                        request_id, mw_result->code, elapsed,
                        mw_result->body.dump().size(), std::nullopt);
                    record_metrics(mw_result->code, start_time);
                    return res;
                }
            }

            // --------------------------------------------------------------
            // Step 5: Handle OPTIONS (CORS preflight)
            // --------------------------------------------------------------
            if (internal_req.method == "OPTIONS") {
                std::string origin;
                auto origin_it = internal_req.headers.find("origin");
                if (origin_it == internal_req.headers.end()) {
                    origin_it = internal_req.headers.find("Origin");
                }
                if (origin_it != internal_req.headers.end()) {
                    origin = origin_it->second;
                }

                std::string req_method;
                auto rm_it = internal_req.headers.find(
                    "access-control-request-method");
                if (rm_it == internal_req.headers.end()) {
                    rm_it = internal_req.headers.find(
                        "Access-Control-Request-Method");
                }
                if (rm_it != internal_req.headers.end()) {
                    req_method = rm_it->second;
                }

                std::string req_headers;
                auto rh_it = internal_req.headers.find(
                    "access-control-request-headers");
                if (rh_it == internal_req.headers.end()) {
                    rh_it = internal_req.headers.find(
                        "Access-Control-Request-Headers");
                }
                if (rh_it != internal_req.headers.end()) {
                    req_headers = rh_it->second;
                }

                auto preflight_resp =
                    cors_handler_.handle_preflight(origin, req_method,
                                                     req_headers);
                auto res = internal_to_beast(preflight_resp, request_id);
                inject_cors_headers(res, internal_req);
                auto elapsed = chr::duration_cast<chr::microseconds>(
                    chr::steady_clock::now() - start_time).count() / 1e3;
                request_logger_.log_response(request_id, 200, elapsed,
                                             0, std::nullopt);
                record_metrics(200, start_time);
                return res;
            }

            // --------------------------------------------------------------
            // Step 6: Determine auth requirement based on path
            // --------------------------------------------------------------
            bool requires_auth = requires_authentication(internal_req.path);
            bool is_admin_route = starts_with(internal_req.path,
                                                "/_synapse/admin/");

            // --------------------------------------------------------------
            // Step 7: Authenticate the request
            // --------------------------------------------------------------
            std::optional<Requester> requester;
            if (is_admin_route) {
                auto auth_result = auth_middleware_.require_admin(internal_req);
                if (auth_result.error.has_value()) {
                    auto res = internal_to_beast(*auth_result.error,
                                                   request_id);
                    inject_cors_headers(res, internal_req);
                    auto elapsed = chr::duration_cast<chr::microseconds>(
                        chr::steady_clock::now() - start_time).count() / 1e3;
                    request_logger_.log_response(
                        request_id, auth_result.error->code, elapsed,
                        auth_result.error->body.dump().size(),
                        "Admin auth failed");
                    metrics_.record_auth_failure();
                    record_metrics(auth_result.error->code, start_time);
                    return res;
                }
                requester = auth_result.requester;
            } else {
                auto auth_result = auth_middleware_.authenticate(
                    internal_req, requires_auth);
                if (auth_result.error.has_value()) {
                    auto res = internal_to_beast(*auth_result.error,
                                                   request_id);
                    inject_cors_headers(res, internal_req);
                    auto elapsed = chr::duration_cast<chr::microseconds>(
                        chr::steady_clock::now() - start_time).count() / 1e3;
                    request_logger_.log_response(
                        request_id, auth_result.error->code, elapsed,
                        auth_result.error->body.dump().size(),
                        "Auth failed");
                    metrics_.record_auth_failure();
                    record_metrics(auth_result.error->code, start_time);
                    return res;
                }
                requester = auth_result.requester;
            }

            // Update connection guard with actual user
            if (requester.has_value() && !requester->user_id.empty()) {
                conn_guard.set_user(requester->user_id);
                internal_req.auth_user = requester->user_id;
            }

            // --------------------------------------------------------------
            // Step 8: Post-auth middleware (rate limiting, etc.)
            // --------------------------------------------------------------
            {
                auto mw_result = middleware_chain_.execute(
                    MiddlewarePhase::POST_AUTH, internal_req, requester);
                if (mw_result.has_value()) {
                    auto res = internal_to_beast(*mw_result, request_id);
                    inject_cors_headers(res, internal_req);
                    inject_rate_limit_headers(
                        res, internal_req.client_ip, internal_req.path);
                    auto elapsed = chr::duration_cast<chr::microseconds>(
                        chr::steady_clock::now() - start_time).count() / 1e3;
                    request_logger_.log_response(
                        request_id, mw_result->code, elapsed,
                        mw_result->body.dump().size(),
                        "Post-auth middleware rejected");
                    record_metrics(mw_result->code, start_time);
                    return res;
                }
            }

            // --------------------------------------------------------------
            // Step 9: Pre-handler middleware
            // --------------------------------------------------------------
            {
                auto mw_result = middleware_chain_.execute(
                    MiddlewarePhase::PRE_HANDLER, internal_req, requester);
                if (mw_result.has_value()) {
                    auto res = internal_to_beast(*mw_result, request_id);
                    inject_cors_headers(res, internal_req);
                    inject_rate_limit_headers(
                        res, internal_req.client_ip, internal_req.path);
                    auto elapsed = chr::duration_cast<chr::microseconds>(
                        chr::steady_clock::now() - start_time).count() / 1e3;
                    request_logger_.log_response(
                        request_id, mw_result->code, elapsed,
                        mw_result->body.dump().size(),
                        "Pre-handler middleware rejected");
                    record_metrics(mw_result->code, start_time);
                    return res;
                }
            }

            // --------------------------------------------------------------
            // Step 10: Dispatch to servlet
            // --------------------------------------------------------------
            HttpResponse servlet_response;
            bool dispatched = false;

            // Try the compiled route table first
            auto route_result = servlet_manager_.route(internal_req);

            if (route_result.matched) {
                // We found a matching route; dispatch to the actual servlet
                // The path params are injected into internal_req
                internal_req.path_params = std::move(route_result.path_params);

                // Now find the actual servlet and call on_request
                for (auto& servlet : servlet_manager_.servlets()) {
                    auto patterns = servlet->patterns();
                    for (const auto& pattern : patterns) {
                        auto compiled = PathParamExtractor::compile(pattern);
                        auto params = PathParamExtractor::match(
                            compiled, internal_req.path);
                        if (params.has_value()) {
                            internal_req.path_params = std::move(*params);
                            servlet_response = servlet->on_request(
                                internal_req);
                            dispatched = true;
                            break;
                        }
                    }
                    if (dispatched) break;
                }
            }

            // If not dispatched through route table, try direct matching
            if (!dispatched) {
                for (auto& servlet : servlet_manager_.servlets()) {
                    auto patterns = servlet->patterns();
                    for (const auto& pattern : patterns) {
                        auto compiled = PathParamExtractor::compile(pattern);
                        auto params = PathParamExtractor::match(
                            compiled, internal_req.path);
                        if (params.has_value()) {
                            // Check method
                            auto methods = servlet->methods();
                            bool method_ok = false;
                            for (const auto& m : methods) {
                                if (m == internal_req.method) {
                                    method_ok = true; break;
                                }
                            }
                            if (!method_ok) {
                                // Method not allowed for this pattern
                                servlet_response.code = 405;
                                servlet_response.body = {
                                    {"errcode",
                                     router_constants::kErrUnsupportedMethod},
                                    {"error", "Method not allowed"}};
                                servlet_response.content_type =
                                    "application/json";
                                dispatched = true;
                                break;
                            }
                            internal_req.path_params = std::move(*params);
                            servlet_response = servlet->on_request(
                                internal_req);
                            dispatched = true;
                            break;
                        }
                    }
                    if (dispatched) break;
                }
            }

            // If still not dispatched, return 404
            if (!dispatched) {
                // Try well-known endpoints and other special paths
                auto special_resp = handle_special_paths(internal_req);
                if (special_resp.has_value()) {
                    servlet_response = *special_resp;
                } else {
                    servlet_response.code = 404;
                    servlet_response.body = {
                        {"errcode", router_constants::kErrNotFound},
                        {"error", "Unrecognized request: " +
                                  internal_req.method + " " +
                                  internal_req.path}};
                    servlet_response.content_type = "application/json";
                }
            }

            // --------------------------------------------------------------
            // Step 11: Post-handler middleware
            // --------------------------------------------------------------
            {
                auto mw_result = middleware_chain_.execute(
                    MiddlewarePhase::POST_HANDLER, internal_req, requester);
                // Post-handler middleware can modify the response
                if (mw_result.has_value()) {
                    servlet_response = *mw_result;
                }
            }

            // --------------------------------------------------------------
            // Step 12: Convert response, inject headers, log, return
            // --------------------------------------------------------------
            auto beast_resp = internal_to_beast(servlet_response, request_id);
            inject_cors_headers(beast_resp, internal_req);
            inject_rate_limit_headers(beast_resp, internal_req.client_ip,
                                       internal_req.path);
            inject_server_header(beast_resp);

            auto elapsed = chr::duration_cast<chr::microseconds>(
                chr::steady_clock::now() - start_time).count() / 1e3;
            size_t resp_size = servlet_response.body.dump().size();

            request_logger_.log_response(
                request_id, servlet_response.code, elapsed, resp_size,
                servlet_response.code >= 400
                    ? std::optional<std::string>(
                          servlet_response.body.value("error", ""))
                    : std::nullopt);

            record_metrics(servlet_response.code, start_time);
            return beast_resp;

        } catch (const std::exception& e) {
            // Handle unexpected exceptions
            request_logger_.log_error(request_id,
                                       "Unhandled exception", e.what());
            auto res = make_beast_error(
                boost::beast::http::status::internal_server_error,
                router_constants::kErrUnknown,
                "Internal server error: " + std::string(e.what()),
                request_id);
            inject_cors_headers(res, internal_req);
            record_metrics(500, start_time);
            return res;
        }
    }

    // ----------------------------------------------------------------------
    // Register a REST servlet
    // ----------------------------------------------------------------------
    void register_servlet(std::unique_ptr<BaseRestServlet> servlet) {
        servlet_manager_.register_servlet(std::move(servlet));
    }

    // ----------------------------------------------------------------------
    // Register all standard Matrix servlets
    // ----------------------------------------------------------------------
    void register_all_servlets() {
        // Client-Server API: Auth
        register_servlet(
            std::make_unique<rest::RegisterRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::LoginRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::LogoutRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::AccountRestServlet>(db_));

        // Client-Server API: Rooms
        register_servlet(
            std::make_unique<rest::RoomRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::SyncRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::EventsRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::ProfileRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::DirectoryRestServlet>(db_));

        // Client-Server API: Devices & Keys
        register_servlet(
            std::make_unique<rest::DevicesRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::KeysRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::PushRulesRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::PusherRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::NotificationsRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::ReceiptsRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::TagsRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::SearchRestServlet>(db_));
        register_servlet(
            std::make_unique<rest::PresenceRestServlet>(db_));

        // Admin API
        register_servlet(
            std::make_unique<rest::AdminRestServlet>(db_));
    }

    // ----------------------------------------------------------------------
    // Middleware management
    // ----------------------------------------------------------------------
    void add_middleware(const std::string& name, MiddlewarePhase phase,
                         MiddlewareFunc handler, int priority = 0) {
        middleware_chain_.add(name, phase, std::move(handler), priority);
    }

    bool remove_middleware(const std::string& name) {
        return middleware_chain_.remove(name);
    }

    std::vector<std::string> list_middleware() const {
        return middleware_chain_.list();
    }

    // ----------------------------------------------------------------------
    // Metrics access
    // ----------------------------------------------------------------------
    RequestMetrics::Snapshot metrics_snapshot() const {
        auto snap = metrics_.snapshot();
        snap.active_connections = connection_tracker_.total();
        return snap;
    }

    json metrics_json() const {
        auto snap = metrics_snapshot();
        return {
            {"total_requests", snap.total_requests},
            {"status_2xx", snap.status_2xx},
            {"status_3xx", snap.status_3xx},
            {"status_4xx", snap.status_4xx},
            {"status_5xx", snap.status_5xx},
            {"rate_limited", snap.rate_limited},
            {"auth_failures", snap.auth_failures},
            {"active_connections", snap.active_connections},
            {"avg_latency_ms", snap.avg_latency_ms},
            {"p50_latency_ms", snap.p50_latency_ms},
            {"p99_latency_ms", snap.p99_latency_ms},
            {"rate_limit_buckets", rate_limiter_.size()},
            {"registered_servlets",
             static_cast<int64_t>(servlet_manager_.servlet_count())},
            {"registered_routes",
             static_cast<int64_t>(servlet_manager_.route_count())}
        };
    }

    // ----------------------------------------------------------------------
    // Rate limiter access for header injection
    // ----------------------------------------------------------------------
    RateLimiter& rate_limiter() { return rate_limiter_; }

    // ----------------------------------------------------------------------
    // Connection tracking
    // ----------------------------------------------------------------------
    ConnectionTracker& connection_tracker() { return connection_tracker_; }

    // ----------------------------------------------------------------------
    // Configuration access
    // ----------------------------------------------------------------------
    const Config& config() const { return config_; }

private:
    // ------------------------------------------------------------------
    // Convert Boost.Beast request to internal HttpRequest
    // ------------------------------------------------------------------
    HttpRequest beast_to_internal(
        const boost::beast::http::request<
            boost::beast::http::string_body>& req) {
        HttpRequest internal;

        // Method
        internal.method = verb_to_string(req.method());

        // Path and query params
        std::string target(req.target());
        auto query_pos = target.find('?');
        if (query_pos != std::string::npos) {
            internal.path = target.substr(0, query_pos);
        } else {
            internal.path = target;
        }

        internal.query_params = PathParamExtractor::extract_query_params(
            std::string(req.target()));

        // Body
        internal.body = req.body();

        // Headers
        for (auto it = req.begin(); it != req.end(); ++it) {
            std::string name(it->name_string());
            std::string value(it->value());
            internal.headers[name] = value;
        }

        // Content-Type check
        auto ct_it = internal.headers.find("content-type");
        if (ct_it == internal.headers.end()) {
            ct_it = internal.headers.find("Content-Type");
        }
        if (ct_it != internal.headers.end()) {
            internal.is_json =
                (to_lower(ct_it->second).find("application/json") !=
                 std::string::npos);
        }

        // Client IP — extract from X-Forwarded-For or use direct
        auto xff = internal.headers.find("x-forwarded-for");
        if (xff == internal.headers.end()) {
            xff = internal.headers.find("X-Forwarded-For");
        }
        if (xff != internal.headers.end()) {
            // Use the first IP in the chain
            std::string xff_val = xff->second;
            auto comma = xff_val.find(',');
            internal.client_ip =
                trim(comma != std::string::npos
                         ? xff_val.substr(0, comma)
                         : xff_val);
        } else {
            internal.client_ip = "127.0.0.1"; // Default for direct connections
        }

        return internal;
    }

    // ------------------------------------------------------------------
    // Convert internal HttpResponse to Boost.Beast response
    // ------------------------------------------------------------------
    boost::beast::http::response<boost::beast::http::string_body>
    internal_to_beast(const HttpResponse& internal,
                      const std::string& request_id) {
        boost::beast::http::response<boost::beast::http::string_body> res;

        // Status code
        res.result(static_cast<boost::beast::http::status>(internal.code));

        // Body
        std::string body_str = internal.body.dump(-1, ' ', false,
                                                    json::error_handler_t::replace);
        res.body() = body_str;

        // Content-Type
        res.set(boost::beast::http::field::content_type,
                internal.content_type);

        // Additional headers from response
        for (const auto& [key, value] : internal.headers) {
            res.set(key, value);
        }

        // Request ID header
        if (!request_id.empty()) {
            res.set("X-Request-ID", request_id);
        }

        // Content-Length
        res.set(boost::beast::http::field::content_length,
                std::to_string(body_str.size()));

        res.prepare_payload();
        return res;
    }

    // ------------------------------------------------------------------
    // Create a Beast error response
    // ------------------------------------------------------------------
    boost::beast::http::response<boost::beast::http::string_body>
    make_beast_error(boost::beast::http::status status,
                     const std::string& errcode,
                     const std::string& error,
                     const std::string& request_id) {
        HttpResponse internal;
        internal.code = static_cast<int>(status);
        internal.body = {{"errcode", errcode}, {"error", error}};
        internal.content_type = "application/json";
        return internal_to_beast(internal, request_id);
    }

    // ------------------------------------------------------------------
    // Inject CORS headers into Beast response
    // ------------------------------------------------------------------
    void inject_cors_headers(
        boost::beast::http::response<boost::beast::http::string_body>& res,
        const HttpRequest& req) {
        // Get origin from request
        std::string origin;
        auto orig_it = req.headers.find("origin");
        if (orig_it == req.headers.end()) {
            orig_it = req.headers.find("Origin");
        }
        if (orig_it != req.headers.end()) {
            origin = orig_it->second;
        }

        // Create temporary HttpResponse for CORS injection
        HttpResponse tmp_resp;
        cors_handler_.inject(tmp_resp, origin, req.method);

        // Copy CORS headers to Beast response
        static const std::vector<std::string> cors_header_names = {
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Expose-Headers",
            "Access-Control-Max-Age",
            "Access-Control-Allow-Credentials"
        };
        for (const auto& name : cors_header_names) {
            auto it = tmp_resp.headers.find(name);
            if (it != tmp_resp.headers.end()) {
                res.set(name, it->second);
            }
        }
    }

    // ------------------------------------------------------------------
    // Inject rate limit headers
    // ------------------------------------------------------------------
    void inject_rate_limit_headers(
        boost::beast::http::response<boost::beast::http::string_body>& res,
        const std::string& client_ip,
        const std::string& path) {
        std::string category = config_.rate_limit_config.categorize(path);
        double limit = rate_limiter_.limit(category);
        double remaining = rate_limiter_.remaining(client_ip, category);

        res.set("X-RateLimit-Limit", std::to_string(static_cast<int64_t>(limit)));
        res.set("X-RateLimit-Remaining",
                std::to_string(static_cast<int64_t>(remaining)));
        res.set("X-RateLimit-Reset",
                std::to_string(now_ms() / 1000 + 1)); // next second
    }

    // ------------------------------------------------------------------
    // Inject server header
    // ------------------------------------------------------------------
    void inject_server_header(
        boost::beast::http::response<boost::beast::http::string_body>& res) {
        res.set(boost::beast::http::field::server,
                config_.server_version);
    }

    // ------------------------------------------------------------------
    // Record metrics for a completed request
    // ------------------------------------------------------------------
    void record_metrics(int status_code,
                        chr::steady_clock::time_point start_time) {
        if (!config_.enable_metrics) return;
        auto elapsed = chr::duration_cast<chr::microseconds>(
            chr::steady_clock::now() - start_time).count() / 1e3;
        metrics_.record_request(status_code, elapsed);
    }

    // ------------------------------------------------------------------
    // Check if a path requires authentication
    // ------------------------------------------------------------------
    static bool requires_authentication(const std::string& path) {
        // Paths that don't require auth
        static const std::vector<std::string> anonymous_paths = {
            "/_matrix/client/v3/login",
            "/_matrix/client/v1/login",
            "/_matrix/client/v3/register",
            "/_matrix/client/v1/register",
            "/_matrix/client/versions",
            "/_matrix/client/v3/register/available",
            "/_matrix/client/v3/register/email/requestToken",
            "/_matrix/client/v3/register/msisdn/requestToken",
            "/_matrix/client/v3/account/password/email/requestToken",
            "/_matrix/client/v3/account/password/msisdn/requestToken",
            "/_matrix/client/v3/password_policy",
            "/.well-known/matrix/client",
            "/.well-known/matrix/server",
            "/_matrix/federation/v1/version",
            "/_matrix/key/v2/server",
            "/health",
            "/_matrix/health",
        };

        for (const auto& anon_path : anonymous_paths) {
            if (path == anon_path) return false;
        }

        // CAPTCHA fallback — registration can be accessed without token
        // if shared secret is used

        return true;
    }

    // ------------------------------------------------------------------
    // Handle special paths (well-known, health, versions)
    // ------------------------------------------------------------------
    std::optional<HttpResponse> handle_special_paths(
        const HttpRequest& req) {
        // /.well-known/matrix/client
        if (req.path == "/.well-known/matrix/client") {
            HttpResponse res;
            res.code = 200;
            res.body = {
                {"m.homeserver", {{"base_url",
                    "https://" + config_.server_name}}},
                {"m.identity_server", {{"base_url",
                    "https://" + config_.server_name}}}
            };
            return res;
        }

        // /.well-known/matrix/server
        if (req.path == "/.well-known/matrix/server") {
            HttpResponse res;
            res.code = 200;
            res.body = {
                {"m.server", config_.server_name + ":443"}
            };
            return res;
        }

        // /health
        if (req.path == "/health" || req.path == "/_matrix/health") {
            HttpResponse res;
            res.code = 200;
            res.body = {
                {"status", "ok"},
                {"server", config_.server_name},
                {"version", config_.server_version}
            };
            return res;
        }

        // /_matrix/client/versions
        if (req.path == "/_matrix/client/versions") {
            HttpResponse res;
            res.code = 200;
            res.body = {
                {"versions", {"r0.0.1", "r0.1.0", "r0.2.0", "r0.3.0",
                              "r0.4.0", "r0.5.0", "r0.6.0", "r0.6.1",
                              "v1.1", "v1.2", "v1.3", "v1.4", "v1.5"}},
                {"unstable_features", json::object()}
            };
            return res;
        }

        // /_matrix/federation/v1/version
        if (req.path == "/_matrix/federation/v1/version") {
            HttpResponse res;
            res.code = 200;
            res.body = {
                {"server", {{"name", config_.server_name},
                            {"version", config_.server_version}}}
            };
            return res;
        }

        // /_matrix/key/v2/server — server key endpoint
        if (req.path == "/_matrix/key/v2/server" ||
            starts_with(req.path, "/_matrix/key/v2/server/")) {
            HttpResponse res;
            res.code = 200;
            res.body = {
                {"server_name", config_.server_name},
                {"valid_until_ts", now_ms() + 86400000}, // 24h
                {"verify_keys", json::object()},
                {"old_verify_keys", json::object()},
                {"signatures", json::object()}
            };
            return res;
        }

        return std::nullopt;
    }

    // ------------------------------------------------------------------
    // Set up the default middleware pipeline
    // ------------------------------------------------------------------
    void setup_default_middleware() {
        // 1. Body size check (PRE_AUTH)
        add_middleware("body_size_check", MiddlewarePhase::PRE_AUTH,
            [this](HttpRequest& req, const std::optional<Requester>&) {
                if (req.body.size() > config_.max_body_size) {
                    HttpResponse err;
                    err.code = 413;
                    err.body = {
                        {"errcode", router_constants::kErrTooLarge},
                        {"error", "Request body too large (max " +
                                  std::to_string(config_.max_body_size) +
                                  " bytes)"}};
                    err.content_type = "application/json";
                    return std::optional<HttpResponse>(err);
                }
                return std::optional<HttpResponse>(std::nullopt);
            }, 100);

        // 2. Rate limiting (POST_AUTH)
        if (config_.rate_limit_enabled) {
            add_middleware("rate_limit", MiddlewarePhase::POST_AUTH,
                [this](HttpRequest& req, const std::optional<Requester>&) {
                    std::string category =
                        config_.rate_limit_config.categorize(req.path);
                    std::string limit_key = req.client_ip;
                    if (req.auth_user.has_value()) {
                        limit_key = *req.auth_user;
                    }
                    if (!rate_limiter_.allow(limit_key, category)) {
                        HttpResponse err;
                        err.code = 429;
                        err.body = {
                            {"errcode",
                             router_constants::kErrLimitExceeded},
                            {"error", "Too many requests. "
                                      "Please wait and try again."}};
                        err.content_type = "application/json";
                        err.headers["Retry-After"] = "1";
                        metrics_.record_rate_limited();
                        return std::optional<HttpResponse>(err);
                    }
                    return std::optional<HttpResponse>(std::nullopt);
                }, 50);
        }

        // 3. Request timing logging (POST_HANDLER)
        add_middleware("request_timing", MiddlewarePhase::POST_HANDLER,
            [this](HttpRequest& req, const std::optional<Requester>& requester) {
                // Already handled in the main flow; no-op here for extensibility
                return std::optional<HttpResponse>(std::nullopt);
            }, 0);
    }

    // ------------------------------------------------------------------
    // Members
    // ------------------------------------------------------------------
    DatabasePool& db_;
    Config config_;
    RateLimiter rate_limiter_;
    ConnectionTracker connection_tracker_;
    mutable RequestMetrics metrics_;
    CorsHandler cors_handler_;
    RequestLogger request_logger_;
    AuthMiddleware auth_middleware_;
    ServletManager servlet_manager_;
    MiddlewareChain middleware_chain_;
};

// ============================================================================
// HttpRouter — Public interface wrapping HttpRouterImpl
// ============================================================================

class HttpRouter {
public:
    using Config = HttpRouterImpl::Config;

    explicit HttpRouter(DatabasePool& db, const Config& config = Config{})
        : impl_(std::make_unique<HttpRouterImpl>(db, config)) {}

    // ------------------------------------------------------------------
    // Handle an incoming HTTP request
    // ------------------------------------------------------------------
    boost::beast::http::response<boost::beast::http::string_body>
    handle(boost::beast::http::request<boost::beast::http::string_body>&& req) {
        return impl_->handle(std::move(req));
    }

    // ------------------------------------------------------------------
    // Register a servlet
    // ------------------------------------------------------------------
    void register_servlet(std::unique_ptr<BaseRestServlet> servlet) {
        impl_->register_servlet(std::move(servlet));
    }

    // ------------------------------------------------------------------
    // Register all standard Matrix servlets
    // ------------------------------------------------------------------
    void register_all_servlets() {
        impl_->register_all_servlets();
    }

    // ------------------------------------------------------------------
    // Middleware management
    // ------------------------------------------------------------------
    void add_middleware(const std::string& name, MiddlewarePhase phase,
                         MiddlewareFunc handler, int priority = 0) {
        impl_->add_middleware(name, phase, std::move(handler), priority);
    }

    bool remove_middleware(const std::string& name) {
        return impl_->remove_middleware(name);
    }

    std::vector<std::string> list_middleware() const {
        return impl_->list_middleware();
    }

    // ------------------------------------------------------------------
    // Metrics
    // ------------------------------------------------------------------
    json metrics() const {
        return impl_->metrics_json();
    }

    RequestMetrics::Snapshot metrics_snapshot() const {
        return impl_->metrics_snapshot();
    }

    // ------------------------------------------------------------------
    // Rate limiter
    // ------------------------------------------------------------------
    RateLimiter& rate_limiter() {
        return impl_->rate_limiter();
    }

    // ------------------------------------------------------------------
    // Connection tracking
    // ------------------------------------------------------------------
    ConnectionTracker& connection_tracker() {
        return impl_->connection_tracker();
    }

    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------
    const Config& config() const {
        return impl_->config();
    }

private:
    std::unique_ptr<HttpRouterImpl> impl_;
};

// ============================================================================
// ServerBuilder — Fluent API for building and configuring an HttpRouter
// ============================================================================

class ServerBuilder {
public:
    explicit ServerBuilder(DatabasePool& db)
        : db_(db) {}

    // Set server name
    ServerBuilder& with_server_name(const std::string& name) {
        config_.server_name = name;
        return *this;
    }

    // Set server version
    ServerBuilder& with_version(const std::string& version) {
        config_.server_version = version;
        return *this;
    }

    // Enable/disable rate limiting
    ServerBuilder& with_rate_limiting(bool enabled) {
        config_.rate_limit_enabled = enabled;
        return *this;
    }

    // Set rate limit for a category
    ServerBuilder& with_rate_limit(const std::string& category,
                                     double rate, double burst) {
        config_.rate_limit_config.set(category, rate, burst);
        return *this;
    }

    // Set max body size
    ServerBuilder& with_max_body_size(size_t bytes) {
        config_.max_body_size = bytes;
        return *this;
    }

    // Set max upload size
    ServerBuilder& with_max_upload_size(size_t bytes) {
        config_.max_upload_size = bytes;
        return *this;
    }

    // Set connection limits
    ServerBuilder& with_connection_limits(int64_t per_ip, int64_t per_user,
                                            int64_t total) {
        config_.max_connections_per_ip = per_ip;
        config_.max_connections_per_user = per_user;
        config_.max_total_connections = total;
        return *this;
    }

    // Set CORS allowed origins
    ServerBuilder& with_cors_origins(
        const std::vector<std::string>& origins) {
        config_.cors_config.allowed_origins = origins;
        return *this;
    }

    // Enable/disable metrics
    ServerBuilder& with_metrics(bool enabled) {
        config_.enable_metrics = enabled;
        return *this;
    }

    // Set logging level
    ServerBuilder& with_log_level(RequestLogger::Level level) {
        config_.log_config.level = level;
        return *this;
    }

    // Set logging output stream
    ServerBuilder& with_log_output(std::ostream& os) {
        config_.log_config.output_stream = &os;
        return *this;
    }

    // Enable/disable compression
    ServerBuilder& with_compression(bool enabled) {
        config_.enable_compression = enabled;
        return *this;
    }

    // Build the router
    std::unique_ptr<HttpRouter> build() {
        return std::make_unique<HttpRouter>(db_, config_);
    }

    // Build and register all standard servlets
    std::unique_ptr<HttpRouter> build_with_all_servlets() {
        auto router = std::make_unique<HttpRouter>(db_, config_);
        router->register_all_servlets();
        return router;
    }

private:
    DatabasePool& db_;
    HttpRouter::Config config_;
};

// ============================================================================
// Response Helper Functions
// ============================================================================

namespace http_response {

// Create a standard JSON success response
HttpResponse ok(const json& data = json::object()) {
    HttpResponse res;
    res.code = 200;
    res.body = data;
    res.content_type = "application/json";
    return res;
}

// Create a 201 Created response
HttpResponse created(const json& data = json::object()) {
    HttpResponse res;
    res.code = 201;
    res.body = data;
    res.content_type = "application/json";
    return res;
}

// Create a 202 Accepted response
HttpResponse accepted(const json& data = json::object()) {
    HttpResponse res;
    res.code = 202;
    res.body = data;
    res.content_type = "application/json";
    return res;
}

// Create a 204 No Content response
HttpResponse no_content() {
    HttpResponse res;
    res.code = 204;
    res.body = json::object();
    res.content_type = "application/json";
    return res;
}

// Create an error response
HttpResponse error(int code, const std::string& errcode,
                    const std::string& message) {
    HttpResponse res;
    res.code = code;
    res.body = {{"errcode", errcode}, {"error", message}};
    res.content_type = "application/json";
    return res;
}

// Create a 400 Bad Request response
HttpResponse bad_request(const std::string& errcode,
                          const std::string& message) {
    return error(400, errcode, message);
}

// Create a 401 Unauthorized response
HttpResponse unauthorized(const std::string& message =
                              "Missing or invalid access token") {
    return error(401, router_constants::kErrMissingToken, message);
}

// Create a 403 Forbidden response
HttpResponse forbidden(const std::string& message = "Access denied") {
    return error(403, router_constants::kErrForbidden, message);
}

// Create a 404 Not Found response
HttpResponse not_found(const std::string& message = "Not found") {
    return error(404, router_constants::kErrNotFound, message);
}

// Create a 405 Method Not Allowed response
HttpResponse method_not_allowed(const std::string& message =
                                    "Method not allowed") {
    return error(405, router_constants::kErrUnsupportedMethod, message);
}

// Create a 409 Conflict response
HttpResponse conflict(const std::string& message = "Conflict") {
    return error(409, "M_CONFLICT", message);
}

// Create a 413 Payload Too Large response
HttpResponse too_large(const std::string& message = "Request too large") {
    return error(413, router_constants::kErrTooLarge, message);
}

// Create a 415 Unsupported Media Type response
HttpResponse unsupported_media_type(const std::string& message =
                                         "Unsupported media type") {
    return error(415, "M_UNSUPPORTED", message);
}

// Create a 429 Rate Limited response
HttpResponse rate_limited(const std::string& message =
                               "Too many requests. Please wait and try again.",
                           int retry_after_sec = 1) {
    HttpResponse res;
    res.code = 429;
    res.body = {{"errcode", router_constants::kErrLimitExceeded},
                {"error", message}};
    res.content_type = "application/json";
    res.headers["Retry-After"] = std::to_string(retry_after_sec);
    return res;
}

// Create a 500 Internal Server Error response
HttpResponse server_error(const std::string& message =
                               "Internal server error") {
    return error(500, router_constants::kErrUnknown, message);
}

// Create a 503 Service Unavailable response
HttpResponse service_unavailable(const std::string& message =
                                      "Service temporarily unavailable") {
    return error(503, "M_UNAVAILABLE", message);
}

// Build a paginated response chunk
json paginate(int64_t start, int64_t limit, int64_t total,
              const json& results) {
    json chunk;
    chunk["start"] = std::to_string(start);
    if (total >= 0) {
        chunk["total"] = total;
    }
    chunk["chunk"] = results;
    // Add next_batch if there are more results
    if (total < 0 || start + limit < total) {
        chunk["next_batch"] = std::to_string(start + limit);
    }
    return chunk;
}

} // namespace http_response

// ============================================================================
// RouterUtil — Utility functions for path analysis
// ============================================================================

namespace router_util {

// Check if a path matches a Matrix API version prefix
bool is_matrix_api(const std::string& path) {
    return starts_with(path, "/_matrix/") ||
           starts_with(path, "/_synapse/");
}

// Extract the API type from a path (client, federation, media, etc.)
std::string api_type(const std::string& path) {
    if (starts_with(path, "/_matrix/client/")) return "client";
    if (starts_with(path, "/_matrix/federation/")) return "federation";
    if (starts_with(path, "/_matrix/media/")) return "media";
    if (starts_with(path, "/_matrix/identity/")) return "identity";
    if (starts_with(path, "/_matrix/key/")) return "key";
    if (starts_with(path, "/_synapse/admin/")) return "admin";
    if (starts_with(path, "/.well-known/")) return "well-known";
    return "other";
}

// Extract the API version from a path (v1, v3, etc.)
std::string api_version(const std::string& path) {
    // _matrix/client/v3/... -> "v3"
    // _matrix/federation/v1/... -> "v1"
    auto parts = [](const std::string& s) -> std::vector<std::string> {
        std::vector<std::string> result;
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, '/')) {
            if (!item.empty()) result.push_back(item);
        }
        return result;
    }(path);

    if (parts.size() >= 3 && parts[0] == "_matrix") {
        return parts[2]; // e.g., "v3"
    }
    return "unknown";
}

// Normalize a path (remove trailing slash, etc.)
std::string normalize(const std::string& path) {
    if (path.empty()) return "/";
    std::string result = path;
    // Remove duplicate slashes
    while (result.find("//") != std::string::npos) {
        size_t pos = result.find("//");
        result.erase(pos, 1);
    }
    // Remove trailing slash (unless it's just "/")
    if (result.size() > 1 && result.back() == '/') {
        result.pop_back();
    }
    return result;
}

// Check if a path is for a static resource
bool is_static_resource(const std::string& path) {
    static const std::vector<std::string> static_extensions = {
        ".css", ".js", ".html", ".htm", ".png", ".jpg", ".jpeg",
        ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
        ".map", ".txt", ".xml"
    };
    for (const auto& ext : static_extensions) {
        if (path.size() >= ext.size() &&
            path.compare(path.size() - ext.size(), ext.size(), ext) == 0) {
            return true;
        }
    }
    return false;
}

// Helper
bool ends_with(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() &&
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Get the content type from a file extension
std::string content_type_from_path(const std::string& path) {
    if (ends_with(path, ".html") || ends_with(path, ".htm"))
        return "text/html";
    if (ends_with(path, ".css")) return "text/css";
    if (ends_with(path, ".js")) return "application/javascript";
    if (ends_with(path, ".json")) return "application/json";
    if (ends_with(path, ".png")) return "image/png";
    if (ends_with(path, ".jpg") || ends_with(path, ".jpeg"))
        return "image/jpeg";
    if (ends_with(path, ".gif")) return "image/gif";
    if (ends_with(path, ".svg")) return "image/svg+xml";
    if (ends_with(path, ".ico")) return "image/x-icon";
    if (ends_with(path, ".woff")) return "font/woff";
    if (ends_with(path, ".woff2")) return "font/woff2";
    if (ends_with(path, ".ttf")) return "font/ttf";
    if (ends_with(path, ".txt")) return "text/plain";
    if (ends_with(path, ".xml")) return "application/xml";
    return "application/octet-stream";
}

} // namespace router_util

// ============================================================================
// Pre-configured router factory functions
// ============================================================================

namespace router_factory {

// Create a router pre-configured for development with verbose logging
std::unique_ptr<HttpRouter> create_development_router(DatabasePool& db,
                                                        const std::string& server_name = "localhost:8008") {
    ServerBuilder builder(db);
    builder.with_server_name(server_name)
           .with_version("Progressive/1.0-dev")
           .with_rate_limiting(false) // Disable rate limiting for dev
           .with_log_level(RequestLogger::Level::DEBUG)
           .with_metrics(true)
           .with_cors_origins({"*"})
           .with_max_body_size(200 * 1024 * 1024); // 200 MB for dev
    return builder.build_with_all_servlets();
}

// Create a router pre-configured for production
std::unique_ptr<HttpRouter> create_production_router(DatabasePool& db,
                                                       const std::string& server_name = "matrix.example.com",
                                                       const std::vector<std::string>& cors_origins = {}) {
    ServerBuilder builder(db);
    builder.with_server_name(server_name)
           .with_version("Progressive/1.0")
           .with_rate_limiting(true)
           .with_log_level(RequestLogger::Level::INFO)
           .with_metrics(true)
           .with_max_body_size(50 * 1024 * 1024) // 50 MB
           .with_max_upload_size(100 * 1024 * 1024) // 100 MB uploads
           .with_connection_limits(100, 200, 5000);

    if (!cors_origins.empty()) {
        builder.with_cors_origins(cors_origins);
    } else {
        builder.with_cors_origins({"*"});
    }

    return builder.build_with_all_servlets();
}

// Create a minimal router with only essential servlets
std::unique_ptr<HttpRouter> create_minimal_router(DatabasePool& db,
                                                    const std::string& server_name = "localhost") {
    ServerBuilder builder(db);
    builder.with_server_name(server_name)
           .with_version("Progressive/1.0-minimal")
           .with_rate_limiting(true)
           .with_log_level(RequestLogger::Level::WARNING)
           .with_metrics(false);

    return builder.build();
}

} // namespace router_factory

// ============================================================================
// RouterStats — Periodic stats collection and reporting
// ============================================================================

class RouterStats {
public:
    explicit RouterStats(HttpRouter& router, chr::seconds interval = chr::seconds(60))
        : router_(router), interval_(interval) {}

    // Start periodic stats reporting
    void start(std::ostream& output = std::cout) {
        running_ = true;
        report_thread_ = std::thread([this, &output]() {
            while (running_.load(std::memory_order_acquire)) {
                std::this_thread::sleep_for(interval_);
                if (!running_.load(std::memory_order_acquire)) break;

                auto snap = router_.metrics_snapshot();
                output << "=== Router Stats ===" << std::endl;
                output << "  Total requests:  " << snap.total_requests << std::endl;
                output << "  2xx responses:   " << snap.status_2xx << std::endl;
                output << "  3xx responses:   " << snap.status_3xx << std::endl;
                output << "  4xx responses:   " << snap.status_4xx << std::endl;
                output << "  5xx responses:   " << snap.status_5xx << std::endl;
                output << "  Rate limited:    " << snap.rate_limited << std::endl;
                output << "  Auth failures:   " << snap.auth_failures << std::endl;
                output << "  Active conns:    " << snap.active_connections << std::endl;
                output << "  Avg latency:     " << std::fixed
                       << std::setprecision(2) << snap.avg_latency_ms
                       << " ms" << std::endl;
                output << "  P50 latency:     " << snap.p50_latency_ms
                       << " ms" << std::endl;
                output << "  P99 latency:     " << snap.p99_latency_ms
                       << " ms" << std::endl;
                output << std::endl;
            }
        });
    }

    // Stop stats reporting
    void stop() {
        running_.store(false, std::memory_order_release);
        if (report_thread_.joinable()) {
            report_thread_.join();
        }
    }

    ~RouterStats() { stop(); }

private:
    HttpRouter& router_;
    chr::seconds interval_;
    std::atomic<bool> running_{false};
    std::thread report_thread_;
};

// ============================================================================
// FastRouter — Optimized routing for high-throughput scenarios
// ============================================================================

class FastRouter {
public:
    // A hash-based fast lookup for fixed paths (no parameters)
    struct FastRoute {
        std::string path;
        std::string method;
        std::function<HttpResponse(const HttpRequest&)> handler;
    };

    explicit FastRouter(HttpRouter& router) : router_(router) {
        build_fast_index();
    }

    // Try to dispatch a request using the fast index first
    std::optional<HttpResponse> try_fast_dispatch(const HttpRequest& req) {
        std::string key = req.method + ":" + req.path;
        auto it = fast_index_.find(key);
        if (it != fast_index_.end()) {
            return it->second(req);
        }
        return std::nullopt;
    }

    // Register a fast route
    void register_fast_route(const std::string& method,
                              const std::string& path,
                              std::function<HttpResponse(const HttpRequest&)> handler) {
        fast_index_[method + ":" + path] = std::move(handler);
    }

private:
    void build_fast_index() {
        // Pre-build fast index for common, fixed-path endpoints
        // These are the most frequently accessed endpoints
        fast_index_["GET:/_matrix/client/versions"] =
            [this](const HttpRequest&) -> HttpResponse {
                HttpResponse res;
                res.code = 200;
                res.body = {
                    {"versions", {"r0.6.0", "r0.6.1", "v1.1", "v1.2",
                                  "v1.3", "v1.4", "v1.5"}},
                    {"unstable_features", json::object()}};
                return res;
            };
        // More fast routes would be registered as the application starts
    }

    HttpRouter& router_;
    std::map<std::string, std::function<HttpResponse(const HttpRequest&)>> fast_index_;
};

// ============================================================================
// HealthChecker — Periodic health check endpoints
// ============================================================================

class HealthChecker {
public:
    struct HealthStatus {
        bool healthy{true};
        bool database_ok{true};
        double uptime_seconds{0};
        int64_t active_connections{0};
        int64_t pending_requests{0};
        std::string version{"unknown"};
        std::map<std::string, std::string> components;
    };

    explicit HealthChecker(HttpRouter& router)
        : router_(router), start_time_(chr::steady_clock::now()) {}

    HealthStatus check() {
        HealthStatus status;
        auto now = chr::steady_clock::now();
        status.uptime_seconds = chr::duration_cast<chr::seconds>(
            now - start_time_).count();
        status.version = router_.config().server_version;

        auto snap = router_.metrics_snapshot();
        status.active_connections = snap.active_connections;
        status.pending_requests = snap.total_requests;

        // Check database (simplified — real impl would ping DB)
        status.database_ok = true;

        // Overall health
        status.healthy = status.database_ok;

        return status;
    }

    json to_json(const HealthStatus& status) {
        return {
            {"healthy", status.healthy},
            {"database_ok", status.database_ok},
            {"uptime_seconds", status.uptime_seconds},
            {"active_connections", status.active_connections},
            {"version", status.version},
            {"components", json(status.components)}
        };
    }

private:
    HttpRouter& router_;
    chr::steady_clock::time_point start_time_;
};

} // namespace progressive

// ============================================================================
// End of http_router.cpp
// ============================================================================
