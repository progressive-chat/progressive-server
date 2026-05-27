// policy_manager.cpp - Matrix rate limiting, retention policies, and GDPR/consent management
// Implements comprehensive policy enforcement for the Progressive Matrix server
// Equivalent to synapse/api/ratelimiting.py + synapse/handlers/admin.py (portions)
// + synapse/rest/admin/_base.py (portions) + synapse/storage/databases/main/room.py (retention)

#include "../json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <deque>
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
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace progressive::server {

// ============================================================================
// Forward declarations
// ============================================================================
using json = nlohmann::json;

// ============================================================================
// Utility: CIDR parsing and matching
// ============================================================================
namespace {

// Parse an IPv4 address into four octets
bool parse_ipv4(const std::string& ip, uint8_t out[4]) {
    std::istringstream iss(ip);
    std::string octet;
    for (int i = 0; i < 4; ++i) {
        if (!std::getline(iss, octet, '.')) return false;
        try {
            int val = std::stoi(octet);
            if (val < 0 || val > 255) return false;
            out[i] = static_cast<uint8_t>(val);
        } catch (...) { return false; }
    }
    return true;
}

// Parse an IPv6 address into 8 hextets (returns -1 on failure)
bool parse_ipv6(const std::string& ip, uint16_t out[8]) {
    std::memset(out, 0, 8 * sizeof(uint16_t));
    std::string expanded;
    // Handle :: abbreviation
    size_t dc = ip.find("::");
    if (dc != std::string::npos) {
        std::string left = ip.substr(0, dc);
        std::string right = ip.substr(dc + 2);
        // Count groups on left side
        int left_groups = 0;
        for (char c : left) if (c == ':') left_groups++;
        if (!left.empty()) left_groups++;
        int right_groups = 0;
        for (char c : right) if (c == ':') right_groups++;
        if (!right.empty()) right_groups++;
        int missing = 8 - left_groups - right_groups;
        expanded = left;
        for (int i = 0; i < missing; ++i) expanded += ":0";
        if (!left.empty() && !right.empty()) expanded += ":";
        expanded += right;
    } else {
        expanded = ip;
    }
    if (expanded.empty()) { // "::" means all zeros
        return true;
    }
    std::istringstream iss(expanded);
    std::string hextet;
    for (int i = 0; i < 8; ++i) {
        if (!std::getline(iss, hextet, ':')) return false;
        try {
            out[i] = static_cast<uint16_t>(std::stoul(hextet, nullptr, 16));
        } catch (...) { return false; }
    }
    return true;
}

// Check if an IP matches a CIDR range
bool ip_matches_cidr(const std::string& ip, const std::string& cidr) {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) {
        // Exact match
        return ip == cidr;
    }
    std::string range_ip = cidr.substr(0, slash);
    int prefix = std::stoi(cidr.substr(slash + 1));
    if (prefix < 0 || prefix > 128) return false;

    bool ip_is_v4 = (ip.find(':') == std::string::npos);
    bool range_is_v4 = (range_ip.find(':') == std::string::npos);

    if (ip_is_v4 && range_is_v4) {
        uint8_t ip_oct[4], range_oct[4];
        if (!parse_ipv4(ip, ip_oct) || !parse_ipv4(range_ip, range_oct)) return false;
        uint32_t ip_int = (uint32_t(ip_oct[0]) << 24) |
                          (uint32_t(ip_oct[1]) << 16) |
                          (uint32_t(ip_oct[2]) << 8)  |
                          (uint32_t(ip_oct[3]));
        uint32_t range_int = (uint32_t(range_oct[0]) << 24) |
                             (uint32_t(range_oct[1]) << 16) |
                             (uint32_t(range_oct[2]) << 8)  |
                             (uint32_t(range_oct[3]));
        uint32_t mask = (prefix == 0) ? 0 : (~uint32_t(0) << (32 - prefix));
        return (ip_int & mask) == (range_int & mask);
    } else if (!ip_is_v4 && !range_is_v4) {
        uint16_t ip_h[8], range_h[8];
        if (!parse_ipv6(ip, ip_h) || !parse_ipv6(range_ip, range_h)) return false;
        // Build 128-bit mask
        for (int i = 0; i < 8; ++i) {
            int bits = std::min(16, prefix - i * 16);
            if (bits <= 0) return true;
            uint16_t mask = (bits == 16) ? 0xFFFF : (uint16_t(~0) << (16 - bits));
            if ((ip_h[i] & mask) != (range_h[i] & mask)) return false;
        }
        return true;
    }
    return false;
}

// Current time in milliseconds since epoch
int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Current time in seconds since epoch
int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// Base62 encoding for generating IDs
std::string base62_encode(uint64_t num) {
    static const char* chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if (num == 0) return "0";
    std::string result;
    while (num > 0) {
        result = chars[num % 62] + result;
        num /= 62;
    }
    return result;
}

// Generate a unique job ID
std::string generate_job_id() {
    static std::atomic<uint64_t> counter{0};
    uint64_t ts = static_cast<uint64_t>(now_ms());
    uint64_t seq = counter.fetch_add(1, std::memory_order_relaxed);
    return base62_encode(ts) + "_" + base62_encode(seq);
}

} // anonymous namespace

// ============================================================================
// SECTION 1: Rate Limiting Engine
// Implements token bucket, sliding window, and concurrent request limiting.
// ============================================================================

// --------------------------------------------------------------------------
// TokenBucket - Classic token bucket algorithm for rate limiting
// Tokens replenish at a steady rate; each request consumes one or more tokens.
// --------------------------------------------------------------------------
class TokenBucket {
public:
    TokenBucket() = default;

    // Initialize the bucket: max_tokens is burst capacity, refill_rate
    // is tokens added per second.
    TokenBucket(int64_t max_tokens, double refill_rate)
        : max_tokens_(max_tokens)
        , refill_rate_(refill_rate)
        , tokens_(max_tokens)
        , last_refill_(now_ms()) {}

    // Attempt to consume `count` tokens. Returns true if successful.
    bool try_consume(int64_t count = 1, int64_t current_time_ms = 0) {
        std::lock_guard<std::mutex> lock(mu_);
        if (current_time_ms == 0) current_time_ms = now_ms();
        refill(current_time_ms);
        if (tokens_ >= count) {
            tokens_ -= count;
            total_consumed_ += count;
            return true;
        }
        total_rejected_++;
        return false;
    }

    // Refill tokens but don't consume.
    void refill(int64_t current_time_ms = 0) {
        if (current_time_ms == 0) current_time_ms = now_ms();
        int64_t elapsed_ms = current_time_ms - last_refill_;
        if (elapsed_ms <= 0) return;
        double new_tokens = (double(elapsed_ms) / 1000.0) * refill_rate_;
        tokens_ = std::min(max_tokens_, tokens_ + static_cast<int64_t>(new_tokens));
        last_refill_ = current_time_ms;
    }

    // How many tokens available now
    int64_t available() {
        std::lock_guard<std::mutex> lock(mu_);
        refill();
        return tokens_;
    }

    // Update configuration
    void reconfigure(int64_t max_tokens, double refill_rate) {
        std::lock_guard<std::mutex> lock(mu_);
        max_tokens_ = max_tokens;
        refill_rate_ = refill_rate;
        tokens_ = std::min(tokens_, max_tokens_);
    }

    // Statistics
    struct Stats {
        int64_t total_consumed = 0;
        int64_t total_rejected = 0;
        int64_t tokens_available = 0;
        int64_t max_tokens = 0;
        double refill_rate = 0.0;
    };
    Stats stats() {
        std::lock_guard<std::mutex> lock(mu_);
        refill();
        return Stats{total_consumed_, total_rejected_, tokens_, max_tokens_, refill_rate_};
    }

private:
    std::mutex mu_;
    int64_t max_tokens_ = 100;
    double refill_rate_ = 10.0;
    int64_t tokens_ = 100;
    int64_t last_refill_ = 0;
    int64_t total_consumed_ = 0;
    int64_t total_rejected_ = 0;
};

// --------------------------------------------------------------------------
// SlidingWindow - Counts events within a moving time window.
// More precise than token bucket for strict "N requests per interval".
// --------------------------------------------------------------------------
class SlidingWindow {
public:
    SlidingWindow() = default;

    SlidingWindow(int64_t window_ms, int64_t max_events)
        : window_ms_(window_ms)
        , max_events_(max_events) {}

    // Check if an event can be accepted now. Returns true if allowed.
    bool try_accept(int64_t current_time_ms = 0) {
        std::lock_guard<std::mutex> lock(mu_);
        if (current_time_ms == 0) current_time_ms = now_ms();
        prune(current_time_ms);
        if (static_cast<int64_t>(timestamps_.size()) < max_events_) {
            timestamps_.push_back(current_time_ms);
            total_accepted_++;
            return true;
        }
        total_rejected_++;
        return false;
    }

    // How many events in the current window
    int64_t count(int64_t current_time_ms = 0) {
        std::lock_guard<std::mutex> lock(mu_);
        if (current_time_ms == 0) current_time_ms = now_ms();
        prune(current_time_ms);
        return static_cast<int64_t>(timestamps_.size());
    }

    // Time until next slot opens (in ms), 0 if available now
    int64_t retry_after_ms(int64_t current_time_ms = 0) {
        std::lock_guard<std::mutex> lock(mu_);
        if (current_time_ms == 0) current_time_ms = now_ms();
        prune(current_time_ms);
        if (static_cast<int64_t>(timestamps_.size()) < max_events_) return 0;
        if (timestamps_.empty()) return 0;
        int64_t oldest = timestamps_.front();
        return std::max(int64_t(0), oldest + window_ms_ - current_time_ms);
    }

    void reconfigure(int64_t window_ms, int64_t max_events) {
        std::lock_guard<std::mutex> lock(mu_);
        window_ms_ = window_ms;
        max_events_ = max_events;
    }

    struct Stats {
        int64_t total_accepted = 0;
        int64_t total_rejected = 0;
        int64_t current_count = 0;
        int64_t window_ms = 0;
        int64_t max_events = 0;
    };
    Stats stats() {
        std::lock_guard<std::mutex> lock(mu_);
        int64_t ct = now_ms();
        prune(ct);
        return Stats{total_accepted_, total_rejected_,
                     static_cast<int64_t>(timestamps_.size()), window_ms_, max_events_};
    }

private:
    void prune(int64_t current_time_ms) {
        int64_t cutoff = current_time_ms - window_ms_;
        while (!timestamps_.empty() && timestamps_.front() < cutoff) {
            timestamps_.pop_front();
        }
    }

    std::mutex mu_;
    int64_t window_ms_ = 1000;
    int64_t max_events_ = 10;
    std::deque<int64_t> timestamps_;
    int64_t total_accepted_ = 0;
    int64_t total_rejected_ = 0;
};

// --------------------------------------------------------------------------
// ConcurrentRequestLimiter - Limits how many requests can be in-flight
// at the same time for a given key (user, IP, etc.)
// --------------------------------------------------------------------------
class ConcurrentRequestLimiter {
public:
    ConcurrentRequestLimiter() = default;

    explicit ConcurrentRequestLimiter(int64_t max_concurrent)
        : max_concurrent_(max_concurrent) {}

    // Try to acquire a slot. Returns a handle ID if successful, -1 if denied.
    int64_t try_acquire() {
        std::lock_guard<std::mutex> lock(mu_);
        if (current_requests_ < max_concurrent_) {
            int64_t handle = next_handle_++;
            active_handles_.insert(handle);
            current_requests_++;
            total_acquired_++;
            return handle;
        }
        total_rejected_++;
        return -1;
    }

    // Release a previously acquired slot.
    void release(int64_t handle) {
        std::lock_guard<std::mutex> lock(mu_);
        auto it = active_handles_.find(handle);
        if (it != active_handles_.end()) {
            active_handles_.erase(it);
            current_requests_--;
        }
    }

    int64_t current() {
        std::lock_guard<std::mutex> lock(mu_);
        return current_requests_;
    }

    int64_t max_allowed() const { return max_concurrent_; }

    void reconfigure(int64_t max_concurrent) {
        std::lock_guard<std::mutex> lock(mu_);
        max_concurrent_ = max_concurrent;
    }

    struct Stats {
        int64_t total_acquired = 0;
        int64_t total_rejected = 0;
        int64_t current_requests = 0;
        int64_t max_concurrent = 0;
    };
    Stats stats() {
        std::lock_guard<std::mutex> lock(mu_);
        return Stats{total_acquired_, total_rejected_,
                     current_requests_, max_concurrent_};
    }

private:
    std::mutex mu_;
    int64_t max_concurrent_ = 100;
    int64_t current_requests_ = 0;
    int64_t next_handle_ = 1;
    int64_t total_acquired_ = 0;
    int64_t total_rejected_ = 0;
    std::unordered_set<int64_t> active_handles_;
};

// --------------------------------------------------------------------------
// RateLimiterKey - composite key for lookup (user_id, ip, endpoint, etc.)
// --------------------------------------------------------------------------
struct RateLimiterKey {
    std::string scope;    // "user", "ip", "endpoint", "global"
    std::string identifier; // the user_id, IP, endpoint path, or empty for global

    bool operator==(const RateLimiterKey& o) const {
        return scope == o.scope && identifier == o.identifier;
    }
};

struct RateLimiterKeyHash {
    std::size_t operator()(const RateLimiterKey& k) const {
        std::size_t h1 = std::hash<std::string>{}(k.scope);
        std::size_t h2 = std::hash<std::string>{}(k.identifier);
        return h1 ^ (h2 << 1);
    }
};

// --------------------------------------------------------------------------
// RateLimitResult - outcome of a rate limit check
// --------------------------------------------------------------------------
struct RateLimitResult {
    bool allowed = true;
    int64_t retry_after_ms = 0;
    std::string reason;
    int64_t tokens_remaining = -1;
    int64_t limit_max = -1;
};

// --------------------------------------------------------------------------
// CombinedRateLimiter - orchestrates token bucket + sliding window +
// concurrency for a single key. Exposes a simple "check" interface.
// --------------------------------------------------------------------------
class CombinedRateLimiter {
public:
    CombinedRateLimiter() = default;

    CombinedRateLimiter(int64_t max_burst, double refill_rate,
                        int64_t window_ms, int64_t window_max,
                        int64_t max_concurrent)
        : bucket_(max_burst, refill_rate)
        , window_(window_ms, window_max)
        , concurrency_(max_concurrent) {
        has_bucket_ = true;
        has_window_ = true;
        has_concurrency_ = (max_concurrent > 0);
    }

    // Check all limits. Returns result with allowed=false if any limit hit.
    RateLimitResult check(bool long_running = false) {
        RateLimitResult result;

        // Check concurrency first (most expensive to wait)
        int64_t concurrency_handle = -1;
        if (has_concurrency_) {
            concurrency_handle = concurrency_.try_acquire();
            if (concurrency_handle < 0) {
                result.allowed = false;
                result.retry_after_ms = 100; // retry shortly for concurrency
                result.reason = "Too many concurrent requests";
                result.limit_max = concurrency_.max_allowed();
                return result;
            }
        }

        // Check sliding window
        if (has_window_) {
            if (!window_.try_accept()) {
                result.allowed = false;
                result.retry_after_ms = window_.retry_after_ms();
                result.reason = "Rate limit exceeded (sliding window)";
                result.limit_max = window_.stats().max_events;
                if (concurrency_handle >= 0) concurrency_.release(concurrency_handle);
                return result;
            }
        }

        // Check token bucket
        if (has_bucket_) {
            if (!bucket_.try_consume(1)) {
                result.allowed = false;
                // Estimate retry based on refill rate
                double refill = bucket_.stats().refill_rate;
                if (refill > 0) {
                    result.retry_after_ms = static_cast<int64_t>((1.0 / refill) * 1000.0);
                } else {
                    result.retry_after_ms = 1000;
                }
                result.reason = "Rate limit exceeded (token bucket)";
                result.limit_max = bucket_.stats().max_tokens;
                if (has_window_) {
                    // We already accepted the window event - can't undo easily
                    // For fairness, just note it
                }
                if (concurrency_handle >= 0) concurrency_.release(concurrency_handle);
                return result;
            }
            result.tokens_remaining = bucket_.available();
        }

        result.allowed = true;
        if (has_bucket_) {
            result.limit_max = bucket_.stats().max_tokens;
            result.tokens_remaining = bucket_.available();
        }
        return result;
    }

    // Release a concurrency slot (call when request completes)
    void release_concurrency(int64_t handle) {
        if (handle >= 0 && has_concurrency_) {
            concurrency_.release(handle);
        }
    }

    void reconfigure(int64_t max_burst, double refill_rate,
                     int64_t window_ms, int64_t window_max,
                     int64_t max_concurrent) {
        bucket_.reconfigure(max_burst, refill_rate);
        window_.reconfigure(window_ms, window_max);
        concurrency_.reconfigure(max_concurrent);
        has_bucket_ = true;
        has_window_ = true;
        has_concurrency_ = (max_concurrent > 0);
    }

    json stats_json() {
        auto bs = bucket_.stats();
        auto ws = window_.stats();
        auto cs = concurrency_.stats();
        return json::object({
            {"token_bucket", {
                {"consumed", bs.total_consumed},
                {"rejected", bs.total_rejected},
                {"available", bs.tokens_available},
                {"max", bs.max_tokens},
                {"refill_rate", bs.refill_rate}
            }},
            {"sliding_window", {
                {"accepted", ws.total_accepted},
                {"rejected", ws.total_rejected},
                {"current_count", ws.current_count},
                {"window_ms", ws.window_ms},
                {"max_events", ws.max_events}
            }},
            {"concurrency", {
                {"acquired", cs.total_acquired},
                {"rejected", cs.total_rejected},
                {"current", cs.current_requests},
                {"max", cs.max_concurrent}
            }}
        });
    }

private:
    TokenBucket bucket_;
    SlidingWindow window_;
    ConcurrentRequestLimiter concurrency_;
    bool has_bucket_ = false;
    bool has_window_ = false;
    bool has_concurrency_ = false;
};

// ============================================================================
// SECTION 2: Rate Limit Configuration
// Per-endpoint, per-user, per-IP configurations with burst/rate tuning.
// ============================================================================

// --------------------------------------------------------------------------
// RateLimitConfig - Configuration for a single rate limit rule
// --------------------------------------------------------------------------
struct RateLimitConfigEntry {
    std::string name;                 // human-readable name
    std::string match_endpoint;       // regex pattern to match endpoints
    std::string match_method;         // HTTP method or "*" for all
    int64_t per_second = 0;          // sustained rate per second
    int64_t burst_count = 0;         // max burst
    int64_t window_ms = 0;           // sliding window duration
    int64_t window_max = 0;          // max events in window
    int64_t max_concurrent = 0;      // max concurrent requests
    bool enabled = true;
};

// --------------------------------------------------------------------------
// RateLimitOverride - Per-user exemption from rate limits
// --------------------------------------------------------------------------
struct RateLimitOverride {
    std::string user_id;
    int64_t per_second = 0;    // 0 means no limit (exempt)
    int64_t burst_count = 0;
    int64_t max_concurrent = 0;
    std::string reason;
    int64_t created_at = 0;
    int64_t expires_at = 0;    // 0 means never expires
    bool active = true;
};

// --------------------------------------------------------------------------
// EndpointRateLimit - Maps endpoint patterns to rate limiters
// --------------------------------------------------------------------------
struct EndpointRateLimiter {
    std::regex pattern;
    std::string method;  // "GET", "POST", etc., or "*"
    std::shared_ptr<CombinedRateLimiter> limiter;
};

// ============================================================================
// SECTION 3: Message Retention Policies
// Per-room min/max lifetime and auto-purge configuration.
// ============================================================================

enum class RetentionAction {
    DELETE = 0,
    ARCHIVE = 1,
    SOFT_DELETE = 2,
};

struct RetentionPolicy {
    std::string room_id;            // room ID or "*" for default
    int64_t max_lifetime_ms = 0;    // 0 means no max (keep forever)
    int64_t min_lifetime_ms = 0;    // 0 means no min (delete immediately if desired)
    RetentionAction action = RetentionAction::DELETE;
    int64_t created_at = 0;
    int64_t updated_at = 0;
    bool enabled = true;
    std::string created_by;
};

// ============================================================================
// SECTION 4: Purge Jobs
// Scheduled purge jobs for retention enforcement.
// ============================================================================

enum class PurgeJobState {
    PENDING = 0,
    RUNNING = 1,
    COMPLETED = 2,
    FAILED = 3,
    CANCELLED = 4,
};

struct PurgeJob {
    std::string job_id;
    std::string room_id;               // target room or "*" for all
    std::string filter_query;          // additional SQL filter
    int64_t cutoff_timestamp = 0;      // events older than this get purged
    int64_t total_events = 0;          // total events to process
    int64_t processed_events = 0;      // events processed so far
    int64_t deleted_events = 0;        // events successfully deleted
    int64_t created_at = 0;
    int64_t started_at = 0;
    int64_t completed_at = 0;
    PurgeJobState state = PurgeJobState::PENDING;
    std::string error_message;
    int64_t batch_size = 1000;
    int64_t progress_percent = 0;
};

// ============================================================================
// SECTION 5: GDPR Data Export
// Export all user data as JSON (ZIP-ready structure).
// ============================================================================

struct GdprExportRequest {
    std::string user_id;
    std::string request_id;
    int64_t requested_at = 0;
    int64_t completed_at = 0;
    std::string status;  // "pending", "processing", "completed", "failed"
    std::string output_path;
    std::string error;
};

// ============================================================================
// SECTION 6: GDPR Data Erasure
// Right-to-be-forgotten: fully erase user data.
// ============================================================================

struct GdprErasureRequest {
    std::string user_id;
    std::string request_id;
    int64_t requested_at = 0;
    int64_t completed_at = 0;
    std::string status;  // "pending", "processing", "completed", "failed"
    bool erase_events = false;      // also redact all user's events
    bool erase_media = false;       // also delete uploaded media
    std::string error;
};

// ============================================================================
// SECTION 7: Consent Management
// Server notice consent and privacy policy versioning.
// ============================================================================

struct PrivacyPolicy {
    std::string version;          // e.g. "1.0", "2024-05-01"
    std::string scope;            // "privacy_policy", "terms_of_service", "cookie_policy"
    std::string language;         // "en", "de", etc.
    std::string title;
    std::string content;          // full policy text
    std::string url;              // link to hosted version
    int64_t published_at = 0;
    int64_t effective_at = 0;    // when this version becomes required
    bool active = true;
};

struct ConsentRecord {
    std::string user_id;
    std::string policy_version;
    std::string scope;           // "privacy_policy", "terms_of_service", "cookie_policy"
    int64_t consented_at = 0;
    std::string ip_address;
    std::string user_agent;
    bool explicit_consent = true; // true = checked a box, false = implied by usage
};

// ============================================================================
// SECTION 8: Account Validity
// Temporary accounts that expire and can be renewed.
// ============================================================================

struct AccountValidityRecord {
    std::string user_id;
    int64_t created_at = 0;
    int64_t expires_at = 0;        // 0 = never expires
    int64_t renewed_at = 0;
    int64_t renewal_count = 0;
    bool expired_notified = false;
    std::string created_by;        // who created this account (admin or registration)
};

// ============================================================================
// SECTION 9: IP Range Blocking
// Block connections from specified CIDR ranges.
// ============================================================================

struct IpBlockEntry {
    std::string cidr;
    std::string reason;
    int64_t blocked_at = 0;
    int64_t expires_at = 0;    // 0 = permanent
    bool active = true;
    std::string blocked_by;
    int64_t hit_count = 0;
};

// ============================================================================
// SECTION 10: Connection Throttling
// Slow down excessive connections from a single source.
// ============================================================================

struct ConnectionThrottleEntry {
    std::string ip;
    int64_t connection_count = 0;
    int64_t last_connection_at = 0;
    int64_t throttle_until = 0;     // 0 = not throttled
    int64_t total_throttled = 0;
    int64_t throttle_duration_ms = 5000;
    int64_t max_connections = 50;
};

// ============================================================================
// SECTION 11: Request Prioritization
// Prioritize sync requests over batch/background requests.
// ============================================================================

enum class RequestPriority {
    HIGH = 0,     // sync, keys/claim, send
    MEDIUM = 1,   // room reads, profile, search
    LOW = 2,      // batch, admin, media downloads
    BACKGROUND = 3 // purge jobs, backfill, maintenance
};

struct PriorityQueueEntry {
    int64_t arrival_time;
    RequestPriority priority;
    std::function<void()> task;
    std::string description;

    // Priority queue comparator: higher priority (lower enum) first
    bool operator<(const PriorityQueueEntry& o) const {
        if (priority != o.priority) return static_cast<int>(priority) > static_cast<int>(o.priority);
        return arrival_time > o.arrival_time;  // older first within same priority
    }
};

// ============================================================================
// SECTION 12: Caching Policies
// TTL-based cache for common queries.
// ============================================================================

struct CacheEntry {
    json value;
    int64_t expires_at = 0;
    int64_t created_at = 0;
    int64_t hit_count = 0;
    int64_t size_bytes = 0;
};

// ============================================================================
// SECTION 13: Rate Limit Event Reporting
// Log and monitor rate limit hits for observability.
// ============================================================================

struct RateLimitEvent {
    int64_t timestamp;
    std::string scope;       // "user", "ip", "endpoint"
    std::string identifier;
    std::string endpoint;
    std::string method;
    std::string limit_type;  // "token_bucket", "sliding_window", "concurrency"
    int64_t retry_after_ms;
    int64_t limit_value;
    std::string client_ip;
    std::string user_agent;
};

// ============================================================================
// PolicyManager - Main orchestrator class
// ============================================================================

class PolicyManager {
public:
    PolicyManager() {
        initialize_defaults();
        start_maintenance_thread();
    }

    ~PolicyManager() {
        shutdown_ = true;
        if (maintenance_thread_.joinable()) {
            maintenance_thread_.join();
        }
        stop_priority_workers();
    }

    // ========================================================================
    // Rate Limiting Engine API
    // ========================================================================

    // Check if a request is allowed. Returns RateLimitResult.
    RateLimitResult check_rate_limit(
        const std::string& user_id,
        const std::string& client_ip,
        const std::string& endpoint,
        const std::string& method,
        bool is_sync = false)
    {
        // First check if user has an override (exemption)
        if (!user_id.empty()) {
            auto override = get_rate_limit_override(user_id);
            if (override.has_value() && override->active) {
                // Exempt users return allowed
                RateLimitResult r;
                r.allowed = true;
                r.tokens_remaining = -1; // unlimited
                r.limit_max = -1;
                return r;
            }
        }

        // Check IP-level rate limiting
        RateLimitResult ip_result = check_ip_rate_limit(client_ip, endpoint, method);
        if (!ip_result.allowed) {
            log_rate_limit_hit("ip", client_ip, endpoint, method, "token_bucket",
                               ip_result.retry_after_ms, ip_result.limit_max, client_ip, "");
            return ip_result;
        }

        // Check user-level rate limiting
        if (!user_id.empty()) {
            RateLimitResult user_result = check_user_rate_limit(user_id, endpoint, method, is_sync);
            if (!user_result.allowed) {
                log_rate_limit_hit("user", user_id, endpoint, method, "sliding_window",
                                   user_result.retry_after_ms, user_result.limit_max, client_ip, "");
                return user_result;
            }
        }

        // Check endpoint-specific rate limiting
        RateLimitResult endpoint_result = check_endpoint_rate_limit(endpoint, method);
        if (!endpoint_result.allowed) {
            log_rate_limit_hit("endpoint", endpoint, endpoint, method, "token_bucket",
                               endpoint_result.retry_after_ms, endpoint_result.limit_max, client_ip, "");
            return endpoint_result;
        }

        // Global limit check
        RateLimitResult global_result = check_global_rate_limit();
        if (!global_result.allowed) {
            log_rate_limit_hit("global", "global", endpoint, method, "token_bucket",
                               global_result.retry_after_ms, global_result.limit_max, client_ip, "");
            return global_result;
        }

        RateLimitResult allowed;
        allowed.allowed = true;
        allowed.tokens_remaining = -1;
        allowed.limit_max = -1;
        return allowed;
    }

    // ========================================================================
    // Rate Limit Configuration
    // ========================================================================

    void configure_rate_limit_endpoint(const RateLimitConfigEntry& entry) {
        std::unique_lock lock(config_mutex_);
        auto it = rate_limit_configs_.find(entry.name);
        if (it != rate_limit_configs_.end()) {
            // Update existing
            it->second = entry;
        } else {
            rate_limit_configs_[entry.name] = entry;
        }
        rebuild_endpoint_limiters();
    }

    void remove_rate_limit_config(const std::string& name) {
        std::unique_lock lock(config_mutex_);
        rate_limit_configs_.erase(name);
        rebuild_endpoint_limiters();
    }

    json get_rate_limit_configs() {
        std::shared_lock lock(config_mutex_);
        json arr = json::array();
        for (const auto& [name, entry] : rate_limit_configs_) {
            arr.push_back({
                {"name", entry.name},
                {"match_endpoint", entry.match_endpoint},
                {"match_method", entry.match_method},
                {"per_second", entry.per_second},
                {"burst_count", entry.burst_count},
                {"window_ms", entry.window_ms},
                {"window_max", entry.window_max},
                {"max_concurrent", entry.max_concurrent},
                {"enabled", entry.enabled}
            });
        }
        return arr;
    }

    // ========================================================================
    // Rate Limit Override API (Section 12)
    // ========================================================================

    void set_rate_limit_override(const std::string& user_id,
                                 int64_t per_second, int64_t burst_count,
                                 int64_t max_concurrent, const std::string& reason,
                                 int64_t expires_at = 0) {
        std::unique_lock lock(override_mutex_);
        RateLimitOverride ov;
        ov.user_id = user_id;
        ov.per_second = per_second;
        ov.burst_count = burst_count;
        ov.max_concurrent = max_concurrent;
        ov.reason = reason;
        ov.created_at = now_sec();
        ov.expires_at = expires_at;
        ov.active = true;
        rate_limit_overrides_[user_id] = ov;
    }

    void remove_rate_limit_override(const std::string& user_id) {
        std::unique_lock lock(override_mutex_);
        rate_limit_overrides_.erase(user_id);
    }

    std::optional<RateLimitOverride> get_rate_limit_override(const std::string& user_id) {
        std::shared_lock lock(override_mutex_);
        auto it = rate_limit_overrides_.find(user_id);
        if (it != rate_limit_overrides_.end()) {
            // Check expiration
            if (it->second.expires_at > 0 && it->second.expires_at < now_sec()) {
                // Expired - remove lazily
                return std::nullopt;
            }
            return it->second;
        }
        return std::nullopt;
    }

    json get_all_rate_limit_overrides() {
        std::shared_lock lock(override_mutex_);
        json arr = json::array();
        for (const auto& [uid, ov] : rate_limit_overrides_) {
            arr.push_back({
                {"user_id", ov.user_id},
                {"per_second", ov.per_second},
                {"burst_count", ov.burst_count},
                {"max_concurrent", ov.max_concurrent},
                {"reason", ov.reason},
                {"created_at", ov.created_at},
                {"expires_at", ov.expires_at},
                {"active", ov.active}
            });
        }
        return arr;
    }

    // ========================================================================
    // IP Range Blocking API (Section 13)
    // ========================================================================

    void block_ip_range(const std::string& cidr, const std::string& reason,
                        const std::string& blocked_by, int64_t expires_at = 0) {
        std::unique_lock lock(ip_block_mutex_);
        IpBlockEntry entry;
        entry.cidr = cidr;
        entry.reason = reason;
        entry.blocked_by = blocked_by;
        entry.blocked_at = now_sec();
        entry.expires_at = expires_at;
        entry.active = true;
        ip_blocks_[cidr] = entry;
    }

    void unblock_ip_range(const std::string& cidr) {
        std::unique_lock lock(ip_block_mutex_);
        ip_blocks_.erase(cidr);
    }

    bool is_ip_blocked(const std::string& ip) {
        std::shared_lock lock(ip_block_mutex_);
        int64_t now = now_sec();
        for (auto& [cidr, entry] : ip_blocks_) {
            if (!entry.active) continue;
            if (entry.expires_at > 0 && entry.expires_at < now) continue;
            if (ip_matches_cidr(ip, cidr)) {
                entry.hit_count++;
                return true;
            }
        }
        return false;
    }

    json get_ip_blocks() {
        std::shared_lock lock(ip_block_mutex_);
        json arr = json::array();
        int64_t now = now_sec();
        for (const auto& [cidr, entry] : ip_blocks_) {
            json e = {
                {"cidr", entry.cidr},
                {"reason", entry.reason},
                {"blocked_at", entry.blocked_at},
                {"blocked_by", entry.blocked_by},
                {"hit_count", entry.hit_count},
                {"active", entry.active},
                {"expires_at", entry.expires_at}
            };
            if (entry.expires_at > 0) {
                e["remaining_seconds"] = std::max(int64_t(0), entry.expires_at - now);
            }
            arr.push_back(e);
        }
        return arr;
    }

    // ========================================================================
    // Connection Throttling API (Section 14)
    // ========================================================================

    bool check_connection_throttle(const std::string& ip) {
        std::unique_lock lock(throttle_mutex_);
        int64_t now = now_ms();
        auto it = connection_throttles_.find(ip);
        if (it == connection_throttles_.end()) {
            ConnectionThrottleEntry entry;
            entry.ip = ip;
            entry.connection_count = 1;
            entry.last_connection_at = now;
            entry.max_connections = default_max_connections_;
            entry.throttle_duration_ms = default_throttle_duration_ms_;
            connection_throttles_[ip] = entry;
            return true;
        }

        ConnectionThrottleEntry& entry = it->second;

        // Check if currently throttled
        if (entry.throttle_until > 0 && now < entry.throttle_until) {
            entry.total_throttled++;
            return false;
        }

        // Reset throttle if expired
        if (entry.throttle_until > 0 && now >= entry.throttle_until) {
            entry.throttle_until = 0;
            entry.connection_count = 0;
        }

        // Increment connection count
        entry.connection_count++;
        entry.last_connection_at = now;

        // Check if exceeding max connections
        if (entry.connection_count > entry.max_connections) {
            // Apply throttling
            entry.throttle_until = now + entry.throttle_duration_ms;
            entry.total_throttled++;
            // Calculate backoff: exponential up to 60 seconds
            int64_t multiplier = std::min(int64_t(12), entry.total_throttled / 10 + 1);
            entry.throttle_duration_ms = entry.throttle_duration_ms * multiplier;
            if (entry.throttle_duration_ms > 60000) entry.throttle_duration_ms = 60000;
            return false;
        }

        return true;
    }

    void release_connection(const std::string& ip) {
        std::unique_lock lock(throttle_mutex_);
        auto it = connection_throttles_.find(ip);
        if (it != connection_throttles_.end()) {
            if (it->second.connection_count > 0) {
                it->second.connection_count--;
            }
        }
    }

    void configure_connection_throttle(int64_t max_connections, int64_t duration_ms) {
        std::unique_lock lock(throttle_mutex_);
        default_max_connections_ = max_connections;
        default_throttle_duration_ms_ = duration_ms;
        // Update existing entries
        for (auto& [ip, entry] : connection_throttles_) {
            entry.max_connections = max_connections;
            entry.throttle_duration_ms = duration_ms;
        }
    }

    json get_connection_throttle_stats() {
        std::shared_lock lock(throttle_mutex_);
        json arr = json::array();
        int64_t now = now_ms();
        for (const auto& [ip, entry] : connection_throttles_) {
            bool throttled = (entry.throttle_until > 0 && now < entry.throttle_until);
            arr.push_back({
                {"ip", entry.ip},
                {"connections", entry.connection_count},
                {"max_allowed", entry.max_connections},
                {"throttled", throttled},
                {"total_throttled", entry.total_throttled},
                {"throttle_remaining_ms", throttled ? (entry.throttle_until - now) : 0}
            });
        }
        return arr;
    }

    // ========================================================================
    // Request Prioritization API (Section 15)
    // ========================================================================

    void enqueue_priority_task(const std::string& description,
                               RequestPriority priority,
                               std::function<void()> task) {
        PriorityQueueEntry entry;
        entry.arrival_time = now_ms();
        entry.priority = priority;
        entry.task = std::move(task);
        entry.description = description;

        {
            std::unique_lock lock(priority_mutex_);
            priority_queue_.push(std::move(entry));
            total_enqueued_++;
        }
        priority_cv_.notify_one();
    }

    json get_priority_queue_stats() {
        std::unique_lock lock(priority_mutex_);
        return json::object({
            {"queue_size", priority_queue_.size()},
            {"total_enqueued", total_enqueued_},
            {"total_processed", total_processed_},
            {"workers_active", workers_running_}
        });
    }

    // ========================================================================
    // Caching Policies API (Section 16)
    // ========================================================================

    void cache_set(const std::string& key, const json& value, int64_t ttl_ms) {
        std::unique_lock lock(cache_mutex_);
        CacheEntry entry;
        int64_t now = now_ms();
        entry.value = value;
        entry.created_at = now;
        entry.expires_at = now + ttl_ms;
        entry.size_bytes = value.dump().size();
        entry.hit_count = 0;
        cache_[key] = entry;

        // Enforce maximum cache size
        enforce_cache_size_limit();
    }

    std::optional<json> cache_get(const std::string& key) {
        std::unique_lock lock(cache_mutex_);
        auto it = cache_.find(key);
        if (it == cache_.end()) {
            cache_misses_++;
            return std::nullopt;
        }
        int64_t now = now_ms();
        if (now > it->second.expires_at) {
            cache_.erase(it);
            cache_misses_++;
            cache_evictions_ttl_++;
            return std::nullopt;
        }
        it->second.hit_count++;
        cache_hits_++;
        return it->second.value;
    }

    void cache_invalidate(const std::string& key) {
        std::unique_lock lock(cache_mutex_);
        cache_.erase(key);
    }

    void cache_clear() {
        std::unique_lock lock(cache_mutex_);
        cache_.clear();
        cache_hits_ = 0;
        cache_misses_ = 0;
        cache_evictions_ttl_ = 0;
    }

    void cache_set_max_size(int64_t max_entries, int64_t max_bytes) {
        std::unique_lock lock(cache_mutex_);
        cache_max_entries_ = max_entries;
        cache_max_bytes_ = max_bytes;
        enforce_cache_size_limit();
    }

    json cache_stats() {
        std::unique_lock lock(cache_mutex_);
        int64_t total_bytes = 0;
        for (const auto& [k, entry] : cache_) {
            total_bytes += entry.size_bytes;
        }
        return json::object({
            {"entries", cache_.size()},
            {"max_entries", cache_max_entries_},
            {"total_bytes", total_bytes},
            {"max_bytes", cache_max_bytes_},
            {"hits", cache_hits_},
            {"misses", cache_misses_},
            {"evictions_ttl", cache_evictions_ttl_},
            {"evictions_size", cache_evictions_size_},
            {"hit_ratio", cache_hits_ + cache_misses_ > 0 ?
                (double(cache_hits_) / double(cache_hits_ + cache_misses_)) : 0.0}
        });
    }

    // ========================================================================
    // Event Size Limits API (Section 17)
    // ========================================================================

    void set_event_size_limit(int64_t max_bytes) {
        max_event_size_bytes_.store(max_bytes, std::memory_order_relaxed);
    }

    int64_t get_event_size_limit() {
        return max_event_size_bytes_.load(std::memory_order_relaxed);
    }

    bool is_event_too_large(const std::string& event_json) {
        int64_t limit = max_event_size_bytes_.load(std::memory_order_relaxed);
        if (limit <= 0) return false;
        return static_cast<int64_t>(event_json.size()) > limit;
    }

    bool is_event_too_large(size_t size_bytes) {
        int64_t limit = max_event_size_bytes_.load(std::memory_order_relaxed);
        if (limit <= 0) return false;
        return static_cast<int64_t>(size_bytes) > limit;
    }

    // ========================================================================
    // Throttle Error Responses API (Section 18)
    // ========================================================================

    json build_rate_limit_error(int64_t retry_after_ms, const std::string& reason,
                                 int64_t limit_max = -1) {
        json error;
        error["errcode"] = "M_LIMIT_EXCEEDED";
        error["error"] = reason;
        error["retry_after_ms"] = retry_after_ms;
        if (limit_max >= 0) {
            error["limit_max"] = limit_max;
        }
        return error;
    }

    HttpResponse build_429_response(int64_t retry_after_ms, const std::string& reason,
                                     int64_t limit_max = -1) {
        HttpResponse resp;
        resp.code = 429;
        resp.body = build_rate_limit_error(retry_after_ms, reason, limit_max);
        resp.headers["Retry-After"] = std::to_string(
            static_cast<int64_t>(std::ceil(retry_after_ms / 1000.0)));
        resp.headers["X-RateLimit-Retry-After-Ms"] = std::to_string(retry_after_ms);
        return resp;
    }

    // ========================================================================
    // Rate Limit Event Reporting API (Section 19)
    // ========================================================================

    void log_rate_limit_hit(const std::string& scope, const std::string& identifier,
                            const std::string& endpoint, const std::string& method,
                            const std::string& limit_type, int64_t retry_after_ms,
                            int64_t limit_value, const std::string& client_ip,
                            const std::string& user_agent) {
        RateLimitEvent ev;
        ev.timestamp = now_ms();
        ev.scope = scope;
        ev.identifier = identifier;
        ev.endpoint = endpoint;
        ev.method = method;
        ev.limit_type = limit_type;
        ev.retry_after_ms = retry_after_ms;
        ev.limit_value = limit_value;
        ev.client_ip = client_ip;
        ev.user_agent = user_agent;

        {
            std::unique_lock lock(event_log_mutex_);
            rate_limit_events_.push_back(ev);
            // Keep only last N events
            while (rate_limit_events_.size() > max_rate_limit_events_stored_) {
                rate_limit_events_.pop_front();
            }
        }

        // Increment aggregated counters
        std::string agg_key = scope + ":" + identifier;
        {
            std::unique_lock lock(agg_mutex_);
            rate_limit_hit_counts_[agg_key]++;
            total_rate_limit_hits_++;
        }

        // Log to console/logger
        if (rate_limit_logging_enabled_) {
            std::cerr << "[RATE_LIMIT] " << scope << "=" << identifier
                      << " endpoint=" << endpoint << " method=" << method
                      << " type=" << limit_type << " retry_ms=" << retry_after_ms
                      << " ip=" << client_ip << std::endl;
        }
    }

    json get_rate_limit_events(int64_t limit = 100) {
        std::shared_lock lock(event_log_mutex_);
        json arr = json::array();
        auto it = rate_limit_events_.rbegin();
        for (int64_t i = 0; i < limit && it != rate_limit_events_.rend(); ++i, ++it) {
            arr.push_back({
                {"timestamp", it->timestamp},
                {"scope", it->scope},
                {"identifier", it->identifier},
                {"endpoint", it->endpoint},
                {"method", it->method},
                {"limit_type", it->limit_type},
                {"retry_after_ms", it->retry_after_ms},
                {"limit_value", it->limit_value},
                {"client_ip", it->client_ip},
                {"user_agent", it->user_agent}
            });
        }
        return arr;
    }

    json get_rate_limit_aggregates() {
        std::shared_lock lock(agg_mutex_);
        json obj = json::object();
        for (const auto& [key, count] : rate_limit_hit_counts_) {
            obj[key] = count;
        }
        obj["total"] = total_rate_limit_hits_;
        return obj;
    }

    void reset_rate_limit_counters() {
        std::unique_lock lock(agg_mutex_);
        rate_limit_hit_counts_.clear();
        total_rate_limit_hits_ = 0;
    }

    void set_rate_limit_logging(bool enabled) {
        rate_limit_logging_enabled_ = enabled;
    }

    // ========================================================================
    // Message Retention Policies API (Section 3)
    // ========================================================================

    void set_retention_policy(const RetentionPolicy& policy) {
        std::unique_lock lock(retention_mutex_);
        std::string key = policy.room_id.empty() ? "*" : policy.room_id;
        retention_policies_[key] = policy;
    }

    void remove_retention_policy(const std::string& room_id) {
        std::unique_lock lock(retention_mutex_);
        retention_policies_.erase(room_id);
    }

    std::optional<RetentionPolicy> get_retention_policy(const std::string& room_id) {
        std::shared_lock lock(retention_mutex_);
        // Check room-specific first
        auto it = retention_policies_.find(room_id);
        if (it != retention_policies_.end() && it->second.enabled) {
            return it->second;
        }
        // Fall back to default
        it = retention_policies_.find("*");
        if (it != retention_policies_.end() && it->second.enabled) {
            return it->second;
        }
        return std::nullopt;
    }

    json get_all_retention_policies() {
        std::shared_lock lock(retention_mutex_);
        json arr = json::array();
        for (const auto& [rid, policy] : retention_policies_) {
            arr.push_back({
                {"room_id", rid},
                {"max_lifetime_ms", policy.max_lifetime_ms},
                {"min_lifetime_ms", policy.min_lifetime_ms},
                {"action", static_cast<int>(policy.action)},
                {"enabled", policy.enabled},
                {"created_by", policy.created_by},
                {"created_at", policy.created_at},
                {"updated_at", policy.updated_at}
            });
        }
        return arr;
    }

    // ========================================================================
    // Purge Jobs API (Section 4)
    // ========================================================================

    std::string schedule_purge(const std::string& room_id, int64_t cutoff_timestamp,
                               int64_t batch_size = 1000) {
        PurgeJob job;
        job.job_id = generate_job_id();
        job.room_id = room_id;
        job.cutoff_timestamp = cutoff_timestamp;
        job.batch_size = batch_size;
        job.created_at = now_sec();
        job.state = PurgeJobState::PENDING;

        {
            std::unique_lock lock(purge_mutex_);
            purge_jobs_[job.job_id] = job;
        }

        // Enqueue the purge as a background task
        enqueue_priority_task("Purge job " + job.job_id, RequestPriority::BACKGROUND,
            [this, job_id = job.job_id]() {
                execute_purge_job(job_id);
            });

        return job.job_id;
    }

    void execute_purge_job(const std::string& job_id) {
        std::unique_lock lock(purge_mutex_);
        auto it = purge_jobs_.find(job_id);
        if (it == purge_jobs_.end()) return;

        PurgeJob& job = it->second;
        job.state = PurgeJobState::RUNNING;
        job.started_at = now_sec();
        lock.unlock();

        try {
            // Simulate purge operation in batches
            // In production, this would query the database for events older than
            // cutoff_timestamp and delete/redact them in batches.
            int64_t simulated_total = 5000; // placeholder
            {
                std::unique_lock lock2(purge_mutex_);
                auto it2 = purge_jobs_.find(job_id);
                if (it2 != purge_jobs_.end()) {
                    it2->second.total_events = simulated_total;
                }
            }

            for (int64_t batch = 0; batch < simulated_total; batch += job.batch_size) {
                if (shutdown_) break;

                // Check if cancelled
                {
                    std::unique_lock lock2(purge_mutex_);
                    auto it2 = purge_jobs_.find(job_id);
                    if (it2 == purge_jobs_.end() || it2->second.state == PurgeJobState::CANCELLED) {
                        return;
                    }
                }

                int64_t batch_count = std::min(job.batch_size, simulated_total - batch);

                // Simulate processing delay
                std::this_thread::sleep_for(std::chrono::milliseconds(10));

                {
                    std::unique_lock lock2(purge_mutex_);
                    auto it2 = purge_jobs_.find(job_id);
                    if (it2 != purge_jobs_.end()) {
                        it2->second.processed_events += batch_count;
                        it2->second.deleted_events += batch_count;
                        if (it2->second.total_events > 0) {
                            it2->second.progress_percent =
                                (it2->second.processed_events * 100) / it2->second.total_events;
                        }
                    }
                }
            }

            // Mark completed
            {
                std::unique_lock lock2(purge_mutex_);
                auto it2 = purge_jobs_.find(job_id);
                if (it2 != purge_jobs_.end()) {
                    it2->second.state = PurgeJobState::COMPLETED;
                    it2->second.completed_at = now_sec();
                    it2->second.progress_percent = 100;
                }
            }
        } catch (const std::exception& e) {
            std::unique_lock lock2(purge_mutex_);
            auto it2 = purge_jobs_.find(job_id);
            if (it2 != purge_jobs_.end()) {
                it2->second.state = PurgeJobState::FAILED;
                it2->second.error_message = e.what();
                it2->second.completed_at = now_sec();
            }
        }
    }

    void cancel_purge_job(const std::string& job_id) {
        std::unique_lock lock(purge_mutex_);
        auto it = purge_jobs_.find(job_id);
        if (it != purge_jobs_.end()) {
            it->second.state = PurgeJobState::CANCELLED;
            it->second.completed_at = now_sec();
        }
    }

    std::optional<PurgeJob> get_purge_job(const std::string& job_id) {
        std::shared_lock lock(purge_mutex_);
        auto it = purge_jobs_.find(job_id);
        if (it != purge_jobs_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    json get_all_purge_jobs() {
        std::shared_lock lock(purge_mutex_);
        json arr = json::array();
        for (const auto& [jid, job] : purge_jobs_) {
            arr.push_back({
                {"job_id", job.job_id},
                {"room_id", job.room_id},
                {"cutoff_timestamp", job.cutoff_timestamp},
                {"state", static_cast<int>(job.state)},
                {"total_events", job.total_events},
                {"processed_events", job.processed_events},
                {"deleted_events", job.deleted_events},
                {"progress_percent", job.progress_percent},
                {"created_at", job.created_at},
                {"started_at", job.started_at},
                {"completed_at", job.completed_at},
                {"error_message", job.error_message}
            });
        }
        return arr;
    }

    // ========================================================================
    // GDPR Data Export API (Section 5)
    // ========================================================================

    std::string request_gdpr_export(const std::string& user_id, const std::string& output_dir) {
        GdprExportRequest req;
        req.user_id = user_id;
        req.request_id = generate_job_id();
        req.requested_at = now_sec();
        req.status = "pending";
        req.output_path = output_dir + "/gdpr_export_" + user_id + "_" + req.request_id + ".json";

        {
            std::unique_lock lock(gdpr_mutex_);
            gdpr_exports_[req.request_id] = req;
        }

        // Process asynchronously
        enqueue_priority_task("GDPR export for " + user_id, RequestPriority.BACKGROUND,
            [this, req_id = req.request_id]() {
                execute_gdpr_export(req_id);
            });

        return req.request_id;
    }

    void execute_gdpr_export(const std::string& request_id) {
        std::unique_lock lock(gdpr_mutex_);
        auto it = gdpr_exports_.find(request_id);
        if (it == gdpr_exports_.end()) return;

        GdprExportRequest& req = it->second;
        req.status = "processing";
        std::string user_id = req.user_id;
        std::string output_path = req.output_path;
        lock.unlock();

        try {
            // Build comprehensive user data export
            json export_data = json::object();

            // Account information
            export_data["account"] = {
                {"user_id", user_id},
                {"export_date", now_sec()},
                {"request_id", request_id},
                {"format_version", "1.0"}
            };

            // Profile information
            export_data["profile"] = json::object({
                {"display_name", ""},    // placeholder - would query DB
                {"avatar_url", ""},
                {"status_msg", ""}
            });

            // Room memberships
            export_data["rooms"] = json::array();
            // In production: query all rooms user is a member of
            json room1 = json::object({
                {"room_id", "!example:server"},
                {"membership", "join"},
                {"join_date", now_sec() - 86400 * 30},
                {"display_name", "Example Room"}
            });
            export_data["rooms"].push_back(room1);

            // Sent events (sample - in production, paginate through DB)
            export_data["events"] = json::array();
            // Placeholder: structured as an array of event objects
            export_data["events"].push_back({
                {"event_id", "$example_event_1:server"},
                {"room_id", "!example:server"},
                {"type", "m.room.message"},
                {"origin_server_ts", now_sec() - 86400 * 7},
                {"content", json::object({
                    {"msgtype", "m.text"},
                    {"body", "[REDACTED: user message content]"}
                })}
            });

            // Device and session information
            export_data["devices"] = json::array();
            export_data["devices"].push_back({
                {"device_id", "DEVICE_EXAMPLE"},
                {"display_name", "User's Browser"},
                {"last_seen_ip", "192.168.1.1"},
                {"last_seen_ts", now_sec() - 3600}
            });

            // Third-party connections (if any)
            export_data["connections"] = json::object({
                {"irc", json::array()},
                {"xmpp", json::array()},
                {"lemmy", json::array()}
            });

            // Media references
            export_data["media"] = json::array();
            // Placeholder: list of media uploads

            // Consent records
            {
                auto consent_records = get_user_consent_records(user_id);
                json consent_arr = json::array();
                for (const auto& cr : consent_records) {
                    consent_arr.push_back({
                        {"scope", cr.scope},
                        {"version", cr.policy_version},
                        {"consented_at", cr.consented_at},
                        {"ip", cr.ip_address},
                        {"user_agent", cr.user_agent}
                    });
                }
                export_data["consent_records"] = consent_arr;
            }

            // Write to file
            std::filesystem::path dir = std::filesystem::path(output_path).parent_path();
            if (!std::filesystem::exists(dir)) {
                std::filesystem::create_directories(dir);
            }

            std::ofstream out(output_path);
            if (!out.is_open()) {
                throw std::runtime_error("Failed to open output file: " + output_path);
            }
            out << export_data.dump(2); // Pretty-print with indent 2
            out.close();

            // Update status
            {
                std::unique_lock lock2(gdpr_mutex_);
                auto it2 = gdpr_exports_.find(request_id);
                if (it2 != gdpr_exports_.end()) {
                    it2->second.status = "completed";
                    it2->second.completed_at = now_sec();
                }
            }
        } catch (const std::exception& e) {
            std::unique_lock lock2(gdpr_mutex_);
            auto it2 = gdpr_exports_.find(request_id);
            if (it2 != gdpr_exports_.end()) {
                it2->second.status = "failed";
                it2->second.error = e.what();
                it2->second.completed_at = now_sec();
            }
        }
    }

    std::optional<GdprExportRequest> get_gdpr_export_status(const std::string& request_id) {
        std::shared_lock lock(gdpr_mutex_);
        auto it = gdpr_exports_.find(request_id);
        if (it != gdpr_exports_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    json get_all_gdpr_exports() {
        std::shared_lock lock(gdpr_mutex_);
        json arr = json::array();
        for (const auto& [rid, req] : gdpr_exports_) {
            arr.push_back({
                {"request_id", req.request_id},
                {"user_id", req.user_id},
                {"status", req.status},
                {"requested_at", req.requested_at},
                {"completed_at", req.completed_at},
                {"output_path", req.output_path},
                {"error", req.error}
            });
        }
        return arr;
    }

    // ========================================================================
    // GDPR Data Erasure API (Section 6)
    // ========================================================================

    std::string request_gdpr_erasure(const std::string& user_id,
                                     bool erase_events = false,
                                     bool erase_media = false) {
        GdprErasureRequest req;
        req.user_id = user_id;
        req.request_id = generate_job_id();
        req.requested_at = now_sec();
        req.status = "pending";
        req.erase_events = erase_events;
        req.erase_media = erase_media;

        {
            std::unique_lock lock(gdpr_erasure_mutex_);
            gdpr_erasures_[req.request_id] = req;
        }

        // Process asynchronously
        enqueue_priority_task("GDPR erasure for " + user_id, RequestPriority.BACKGROUND,
            [this, req_id = req.request_id]() {
                execute_gdpr_erasure(req_id);
            });

        return req.request_id;
    }

    void execute_gdpr_erasure(const std::string& request_id) {
        std::unique_lock lock(gdpr_erasure_mutex_);
        auto it = gdpr_erasures_.find(request_id);
        if (it == gdpr_erasures_.end()) return;

        GdprErasureRequest& req = it->second;
        req.status = "processing";
        std::string user_id = req.user_id;
        bool erase_events = req.erase_events;
        bool erase_media = req.erase_media;
        lock.unlock();

        try {
            // Step 1: Deactivate the user account
            // In production: UPDATE users SET deactivated=1 WHERE name=?
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // Step 2: Remove profile data
            // In production: DELETE FROM profiles WHERE user_id=?
            std::this_thread::sleep_for(std::chrono::milliseconds(50));

            // Step 3: Remove device and session data
            // In production: DELETE FROM devices WHERE user_id=?
            //                DELETE FROM access_tokens WHERE user_id=?
            std::this_thread::sleep_for(std::chrono::milliseconds(50));

            // Step 4: Remove consent records
            {
                std::unique_lock consent_lock(consent_mutex_);
                erase_user_consent_unsafe(user_id);
            }

            // Step 5: Optionally redact all events
            if (erase_events) {
                // In production: Redact all events authored by this user
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }

            // Step 6: Optionally delete all media
            if (erase_media) {
                // In production: DELETE FROM media WHERE user_id=?
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            // Step 7: Remove rate limit overrides
            remove_rate_limit_override(user_id);

            // Step 8: Remove account validity records
            {
                std::unique_lock validity_lock(account_validity_mutex_);
                account_validity_.erase(user_id);
            }

            // Mark completed
            {
                std::unique_lock lock2(gdpr_erasure_mutex_);
                auto it2 = gdpr_erasures_.find(request_id);
                if (it2 != gdpr_erasures_.end()) {
                    it2->second.status = "completed";
                    it2->second.completed_at = now_sec();
                }
            }
        } catch (const std::exception& e) {
            std::unique_lock lock2(gdpr_erasure_mutex_);
            auto it2 = gdpr_erasures_.find(request_id);
            if (it2 != gdpr_erasures_.end()) {
                it2->second.status = "failed";
                it2->second.error = e.what();
                it2->second.completed_at = now_sec();
            }
        }
    }

    std::optional<GdprErasureRequest> get_gdpr_erasure_status(const std::string& request_id) {
        std::shared_lock lock(gdpr_erasure_mutex_);
        auto it = gdpr_erasures_.find(request_id);
        if (it != gdpr_erasures_.end()) {
            return it->second;
        }
        return std::nullopt;
    }

    json get_all_gdpr_erasures() {
        std::shared_lock lock(gdpr_erasure_mutex_);
        json arr = json::array();
        for (const auto& [rid, req] : gdpr_erasures_) {
            arr.push_back({
                {"request_id", req.request_id},
                {"user_id", req.user_id},
                {"status", req.status},
                {"requested_at", req.requested_at},
                {"completed_at", req.completed_at},
                {"erase_events", req.erase_events},
                {"erase_media", req.erase_media},
                {"error", req.error}
            });
        }
        return arr;
    }

    // ========================================================================
    // Consent Management API (Section 7)
    // ========================================================================

    void publish_privacy_policy(const PrivacyPolicy& policy) {
        std::unique_lock lock(consent_mutex_);
        std::string key = policy.scope + ":" + policy.version + ":" + policy.language;
        privacy_policies_[key] = policy;
    }

    void deprecate_privacy_policy(const std::string& scope, const std::string& version,
                                   const std::string& language) {
        std::unique_lock lock(consent_mutex_);
        std::string key = scope + ":" + version + ":" + language;
        auto it = privacy_policies_.find(key);
        if (it != privacy_policies_.end()) {
            it->second.active = false;
        }
    }

    std::optional<PrivacyPolicy> get_active_privacy_policy(const std::string& scope,
                                                            const std::string& language) {
        std::shared_lock lock(consent_mutex_);
        std::optional<PrivacyPolicy> best;
        int64_t best_effective = 0;

        for (const auto& [key, policy] : privacy_policies_) {
            if (!policy.active) continue;
            if (policy.scope != scope) continue;
            if (policy.language != language && policy.language != "all") continue;
            if (policy.effective_at > now_sec()) continue; // not yet effective

            if (policy.effective_at > best_effective) {
                best = policy;
                best_effective = policy.effective_at;
            }
        }
        return best;
    }

    json get_all_privacy_policies() {
        std::shared_lock lock(consent_mutex_);
        json arr = json::array();
        for (const auto& [key, policy] : privacy_policies_) {
            arr.push_back({
                {"version", policy.version},
                {"scope", policy.scope},
                {"language", policy.language},
                {"title", policy.title},
                {"url", policy.url},
                {"published_at", policy.published_at},
                {"effective_at", policy.effective_at},
                {"active", policy.active}
            });
        }
        return arr;
    }

    // ========================================================================
    // Consent Tracking API (Section 8)
    // ========================================================================

    void record_consent(const std::string& user_id, const std::string& scope,
                        const std::string& policy_version, const std::string& ip_address,
                        const std::string& user_agent, bool explicit_consent = true) {
        std::unique_lock lock(consent_mutex_);
        ConsentRecord record;
        record.user_id = user_id;
        record.scope = scope;
        record.policy_version = policy_version;
        record.consented_at = now_sec();
        record.ip_address = ip_address;
        record.user_agent = user_agent;
        record.explicit_consent = explicit_consent;

        std::string key = user_id + ":" + scope + ":" + policy_version;
        consent_records_[key] = record;
    }

    bool has_user_consented(const std::string& user_id, const std::string& scope,
                            const std::string& minimum_version = "") {
        std::shared_lock lock(consent_mutex_);
        std::string prefix = user_id + ":" + scope + ":";
        for (const auto& [key, record] : consent_records_) {
            if (key.starts_with(prefix)) {
                if (minimum_version.empty()) return true;
                // Simple string comparison; in production, use semver or date-based comparison
                if (record.policy_version >= minimum_version) return true;
            }
        }
        return false;
    }

    std::vector<ConsentRecord> get_user_consent_records(const std::string& user_id) {
        std::shared_lock lock(consent_mutex_);
        std::vector<ConsentRecord> result;
        std::string prefix = user_id + ":";
        for (const auto& [key, record] : consent_records_) {
            if (key.starts_with(prefix)) {
                result.push_back(record);
            }
        }
        // Sort by consented_at descending
        std::sort(result.begin(), result.end(),
                  [](const ConsentRecord& a, const ConsentRecord& b) {
                      return a.consented_at > b.consented_at;
                  });
        return result;
    }

    void erase_user_consent_unsafe(const std::string& user_id) {
        // NOTE: caller must hold consent_mutex_
        std::string prefix = user_id + ":";
        auto it = consent_records_.begin();
        while (it != consent_records_.end()) {
            if (it->first.starts_with(prefix)) {
                it = consent_records_.erase(it);
            } else {
                ++it;
            }
        }
    }

    json get_consent_report() {
        std::shared_lock lock(consent_mutex_);
        // Group by scope and version
        std::map<std::string, int64_t> counts;
        std::set<std::string> consented_users;
        for (const auto& [key, record] : consent_records_) {
            std::string scope_version = record.scope + "@" + record.policy_version;
            counts[scope_version]++;
            consented_users.insert(record.user_id);
        }
        json report;
        report["total_records"] = consent_records_.size();
        report["unique_users"] = consented_users.size();
        json by_policy = json::object();
        for (const auto& [sv, cnt] : counts) {
            by_policy[sv] = cnt;
        }
        report["by_policy"] = by_policy;
        return report;
    }

    // ========================================================================
    // Consent Enforcement API (Section 9)
    // ========================================================================

    bool check_consent_and_block(const std::string& user_id, const std::string& scope,
                                  const std::string& required_version = "") {
        if (!consent_enforcement_enabled_) return true;

        if (user_id.empty()) return true; // unauthenticated requests pass through

        bool has_consented = has_user_consented(user_id, scope, required_version);
        if (!has_consented) {
            // Log enforcement block
            std::cerr << "[CONSENT_BLOCK] User " << user_id
                      << " blocked from scope=" << scope
                      << " (requires version >= " << required_version << ")" << std::endl;
        }
        return has_consented;
    }

    HttpResponse build_consent_required_response(const std::string& scope,
                                                   const std::string& policy_url = "",
                                                   const std::string& policy_version = "") {
        HttpResponse resp;
        resp.code = 403;
        resp.body = json::object({
            {"errcode", "M_CONSENT_NOT_GIVEN"},
            {"error", "User has not given consent for " + scope},
            {"consent_uri", policy_url.empty() ? "/_matrix/consent?v=" + policy_version : policy_url},
            {"required_version", policy_version},
            {"scope", scope}
        });
        return resp;
    }

    void set_consent_enforcement(bool enabled) {
        consent_enforcement_enabled_ = enabled;
    }

    bool is_consent_enforcement_enabled() {
        return consent_enforcement_enabled_;
    }

    // ========================================================================
    // Account Validity API (Section 10)
    // ========================================================================

    void set_account_validity(const std::string& user_id, int64_t expires_at,
                              const std::string& created_by = "") {
        std::unique_lock lock(account_validity_mutex_);
        AccountValidityRecord rec;
        rec.user_id = user_id;
        rec.created_at = now_sec();
        rec.expires_at = expires_at;
        rec.created_by = created_by;
        account_validity_[user_id] = rec;
    }

    void remove_account_validity(const std::string& user_id) {
        std::unique_lock lock(account_validity_mutex_);
        account_validity_.erase(user_id);
    }

    bool is_account_expired(const std::string& user_id) {
        std::shared_lock lock(account_validity_mutex_);
        auto it = account_validity_.find(user_id);
        if (it == account_validity_.end()) return false;
        if (it->second.expires_at == 0) return false; // never expires
        return now_sec() > it->second.expires_at;
    }

    int64_t account_expires_in(const std::string& user_id) {
        std::shared_lock lock(account_validity_mutex_);
        auto it = account_validity_.find(user_id);
        if (it == account_validity_.end()) return -1; // no record
        if (it->second.expires_at == 0) return -2;    // never expires
        int64_t remaining = it->second.expires_at - now_sec();
        return remaining;
    }

    std::optional<AccountValidityRecord> get_account_validity(const std::string& user_id) {
        std::shared_lock lock(account_validity_mutex_);
        auto it = account_validity_.find(user_id);
        if (it != account_validity_.end()) return it->second;
        return std::nullopt;
    }

    json get_all_account_validity() {
        std::shared_lock lock(account_validity_mutex_);
        json arr = json::array();
        for (const auto& [uid, rec] : account_validity_) {
            int64_t remaining = 0;
            if (rec.expires_at > 0) remaining = rec.expires_at - now_sec();
            arr.push_back({
                {"user_id", rec.user_id},
                {"created_at", rec.created_at},
                {"expires_at", rec.expires_at},
                {"remaining_seconds", remaining},
                {"expired", remaining < 0 && rec.expires_at > 0},
                {"renewal_count", rec.renewal_count},
                {"renewed_at", rec.renewed_at},
                {"created_by", rec.created_by}
            });
        }
        return arr;
    }

    // ========================================================================
    // Account Renewal API (Section 11)
    // ========================================================================

    bool renew_account(const std::string& user_id, int64_t additional_seconds) {
        std::unique_lock lock(account_validity_mutex_);
        auto it = account_validity_.find(user_id);
        if (it == account_validity_.end()) {
            // Create a new validity record
            AccountValidityRecord rec;
            rec.user_id = user_id;
            rec.created_at = now_sec();
            rec.expires_at = now_sec() + additional_seconds;
            rec.renewed_at = now_sec();
            rec.renewal_count = 1;
            account_validity_[user_id] = rec;
            return true;
        }

        AccountValidityRecord& rec = it->second;
        if (rec.expires_at == 0) {
            // Account never expires, no renewal needed
            return true;
        }

        // If already expired, start from now
        int64_t base = std::max(now_sec(), rec.expires_at);
        rec.expires_at = base + additional_seconds;
        rec.renewed_at = now_sec();
        rec.renewal_count++;
        rec.expired_notified = false;
        return true;
    }

    // ========================================================================
    // Maintenance: Check for expired accounts and retention violations
    // ========================================================================

    void run_maintenance_cycle() {
        int64_t now = now_sec();

        // Check for expired accounts
        {
            std::shared_lock lock(account_validity_mutex_);
            for (const auto& [uid, rec] : account_validity_) {
                if (rec.expires_at > 0 && rec.expires_at < now && !rec.expired_notified) {
                    // In production: deactivate account, send notification
                    std::cerr << "[ACCOUNT_EXPIRED] User " << uid
                              << " expired at " << rec.expires_at << std::endl;
                }
            }
        }

        // Check for IP blocks that have expired
        {
            std::unique_lock lock(ip_block_mutex_);
            auto it = ip_blocks_.begin();
            while (it != ip_blocks_.end()) {
                if (it->second.expires_at > 0 && it->second.expires_at < now) {
                    it->second.active = false;
                }
                ++it;
            }
        }

        // Clean up old rate limit events
        {
            std::unique_lock lock(event_log_mutex_);
            int64_t cutoff = now_ms() - (3600 * 1000); // 1 hour ago
            while (!rate_limit_events_.empty() && rate_limit_events_.front().timestamp < cutoff) {
                rate_limit_events_.pop_front();
            }
        }

        // Evict expired cache entries
        {
            std::unique_lock lock(cache_mutex_);
            auto it = cache_.begin();
            while (it != cache_.end()) {
                if (now_ms() > it->second.expires_at) {
                    cache_evictions_ttl_++;
                    it = cache_.erase(it);
                } else {
                    ++it;
                }
            }
        }
    }

    // ========================================================================
    // Admin API for Rate Limit Management (Section 20)
    // ========================================================================

    json get_full_status() {
        json status;
        status["rate_limits"] = json::object({
            {"configs", get_rate_limit_configs()},
            {"overrides", get_all_rate_limit_overrides()},
            {"events_recent", get_rate_limit_events(20)},
            {"aggregates", get_rate_limit_aggregates()}
        });
        status["retention"] = json::object({
            {"policies", get_all_retention_policies()},
            {"purge_jobs", get_all_purge_jobs()}
        });
        status["gdpr"] = json::object({
            {"exports", get_all_gdpr_exports()},
            {"erasures", get_all_gdpr_erasures()}
        });
        status["consent"] = json::object({
            {"policies", get_all_privacy_policies()},
            {"report", get_consent_report()},
            {"enforcement_enabled", consent_enforcement_enabled_}
        });
        status["accounts"] = json::object({
            {"validity", get_all_account_validity()}
        });
        status["ip_blocks"] = get_ip_blocks();
        status["connection_throttle"] = get_connection_throttle_stats();
        status["priority_queue"] = get_priority_queue_stats();
        status["cache"] = cache_stats();
        status["event_size_limit"] = get_event_size_limit();

        return status;
    }

    // Reset all state (for testing/admin)
    void reset_all() {
        {
            std::unique_lock lock(config_mutex_);
            rate_limit_configs_.clear();
            endpoint_limiters_.clear();
        }
        {
            std::unique_lock lock(override_mutex_);
            rate_limit_overrides_.clear();
        }
        {
            std::unique_lock lock(retention_mutex_);
            retention_policies_.clear();
        }
        {
            std::unique_lock lock(purge_mutex_);
            purge_jobs_.clear();
        }
        {
            std::unique_lock lock(gdpr_mutex_);
            gdpr_exports_.clear();
        }
        {
            std::unique_lock lock(gdpr_erasure_mutex_);
            gdpr_erasures_.clear();
        }
        {
            std::unique_lock lock(consent_mutex_);
            privacy_policies_.clear();
            consent_records_.clear();
        }
        {
            std::unique_lock lock(account_validity_mutex_);
            account_validity_.clear();
        }
        {
            std::unique_lock lock(ip_block_mutex_);
            ip_blocks_.clear();
        }
        {
            std::unique_lock lock(throttle_mutex_);
            connection_throttles_.clear();
        }
        reset_rate_limit_counters();
        cache_clear();
    }

private:
    // ========================================================================
    // Internal: Initialize default rate limit configurations
    // ========================================================================

    void initialize_defaults() {
        // Default endpoint rate limits (aligned with Matrix spec defaults)
        RateLimitConfigEntry login_limit;
        login_limit.name = "login";
        login_limit.match_endpoint = "/_matrix/client/r0/login";
        login_limit.match_method = "POST";
        login_limit.per_second = 0;
        login_limit.burst_count = 5;
        login_limit.window_ms = 60000;
        login_limit.window_max = 10;
        login_limit.max_concurrent = 5;
        login_limit.enabled = true;
        rate_limit_configs_["login"] = login_limit;

        RateLimitConfigEntry register_limit;
        register_limit.name = "register";
        register_limit.match_endpoint = "/_matrix/client/r0/register";
        register_limit.match_method = "POST";
        register_limit.per_second = 0;
        register_limit.burst_count = 1;
        register_limit.window_ms = 3600000; // 1 hour
        register_limit.window_max = 3;
        register_limit.max_concurrent = 2;
        register_limit.enabled = true;
        rate_limit_configs_["register"] = register_limit;

        RateLimitConfigEntry message_send;
        message_send.name = "message_send";
        message_send.match_endpoint = "/_matrix/client/r0/rooms/.*/send/.*";
        message_send.match_method = "PUT";
        message_send.per_second = 10;
        message_send.burst_count = 30;
        message_send.window_ms = 1000;
        message_send.window_max = 30;
        message_send.max_concurrent = 20;
        message_send.enabled = true;
        rate_limit_configs_["message_send"] = message_send;

        RateLimitConfigEntry sync_limit;
        sync_limit.name = "sync";
        sync_limit.match_endpoint = "/_matrix/client/r0/sync";
        sync_limit.match_method = "GET";
        sync_limit.per_second = 2;
        sync_limit.burst_count = 5;
        sync_limit.window_ms = 1000;
        sync_limit.window_max = 5;
        sync_limit.max_concurrent = 50;
        sync_limit.enabled = true;
        rate_limit_configs_["sync"] = sync_limit;

        RateLimitConfigEntry default_limit;
        default_limit.name = "default";
        default_limit.match_endpoint = ".*";
        default_limit.match_method = "*";
        default_limit.per_second = 50;
        default_limit.burst_count = 100;
        default_limit.window_ms = 1000;
        default_limit.window_max = 100;
        default_limit.max_concurrent = 100;
        default_limit.enabled = true;
        rate_limit_configs_["default"] = default_limit;

        rebuild_endpoint_limiters();
    }

    void rebuild_endpoint_limiters() {
        std::vector<EndpointRateLimiter> new_limiters;
        for (const auto& [name, entry] : rate_limit_configs_) {
            if (!entry.enabled) continue;

            EndpointRateLimiter el;
            try {
                el.pattern = std::regex(entry.match_endpoint);
            } catch (const std::regex_error&) {
                // Fallback to match-all
                el.pattern = std::regex(".*");
            }
            el.method = entry.match_method;
            el.limiter = std::make_shared<CombinedRateLimiter>(
                entry.burst_count,
                static_cast<double>(entry.per_second),
                entry.window_ms,
                entry.window_max,
                entry.max_concurrent
            );
            new_limiters.push_back(std::move(el));
        }
        endpoint_limiters_ = std::move(new_limiters);
    }

    RateLimitResult check_endpoint_rate_limit(const std::string& endpoint,
                                               const std::string& method) {
        std::shared_lock lock(config_mutex_);
        for (auto& el : endpoint_limiters_) {
            if (el.method != "*" && el.method != method) continue;
            if (std::regex_match(endpoint, el.pattern)) {
                auto result = el.limiter->check();
                if (!result.allowed) {
                    result.reason = "Endpoint rate limit: " + endpoint;
                }
                return result;
            }
        }
        // No matching endpoint limit found, allow
        return RateLimitResult{};
    }

    RateLimitResult check_user_rate_limit(const std::string& user_id,
                                           const std::string& endpoint,
                                           const std::string& method,
                                           bool is_sync) {
        std::string key = "user:" + user_id;
        std::shared_ptr<CombinedRateLimiter> limiter;

        {
            std::unique_lock lock(user_limit_mutex_);
            auto it = user_limiters_.find(key);
            if (it == user_limiters_.end()) {
                // Create a per-user limiter with defaults
                int64_t burst = is_sync ? 5 : 30;
                double rate = is_sync ? 2.0 : 10.0;
                int64_t window_ms = 1000;
                int64_t window_max = is_sync ? 5 : 30;
                int64_t max_concurrent = 20;

                limiter = std::make_shared<CombinedRateLimiter>(
                    burst, rate, window_ms, window_max, max_concurrent);
                user_limiters_[key] = limiter;
            } else {
                limiter = it->second;
            }
        }

        return limiter->check(is_sync);
    }

    RateLimitResult check_ip_rate_limit(const std::string& ip,
                                         const std::string& endpoint,
                                         const std::string& method) {
        std::string key = "ip:" + ip;
        std::shared_ptr<CombinedRateLimiter> limiter;

        {
            std::unique_lock lock(ip_limit_mutex_);
            auto it = ip_limiters_.find(key);
            if (it == ip_limiters_.end()) {
                limiter = std::make_shared<CombinedRateLimiter>(
                    100, 50.0, 1000, 100, 50);
                ip_limiters_[key] = limiter;
            } else {
                limiter = it->second;
            }
        }

        return limiter->check();
    }

    RateLimitResult check_global_rate_limit() {
        return global_limiter_.check();
    }

    // ========================================================================
    // Internal: Cache management
    // ========================================================================

    void enforce_cache_size_limit() {
        // Evict oldest entries if cache exceeds max entries
        while (static_cast<int64_t>(cache_.size()) > cache_max_entries_) {
            // Find entry with earliest creation time
            auto oldest = cache_.begin();
            for (auto it = cache_.begin(); it != cache_.end(); ++it) {
                if (it->second.created_at < oldest->second.created_at) {
                    oldest = it;
                }
            }
            cache_.erase(oldest);
            cache_evictions_size_++;
        }

        // Evict if total bytes exceed limit
        if (cache_max_bytes_ > 0) {
            int64_t total_bytes = 0;
            for (const auto& [k, entry] : cache_) total_bytes += entry.size_bytes;

            while (total_bytes > cache_max_bytes_ && !cache_.empty()) {
                auto oldest = cache_.begin();
                for (auto it = cache_.begin(); it != cache_.end(); ++it) {
                    if (it->second.created_at < oldest->second.created_at) {
                        oldest = it;
                    }
                }
                total_bytes -= oldest->second.size_bytes;
                cache_.erase(oldest);
                cache_evictions_size_++;
            }
        }
    }

    // ========================================================================
    // Internal: Priority worker thread pool
    // ========================================================================

    void start_priority_workers() {
        int num_workers = std::max(1, static_cast<int>(std::thread::hardware_concurrency()) / 2);
        for (int i = 0; i < num_workers; ++i) {
            workers_.emplace_back(&PolicyManager::priority_worker_loop, this);
        }
    }

    void stop_priority_workers() {
        {
            std::unique_lock lock(priority_mutex_);
            workers_running_ = false;
        }
        priority_cv_.notify_all();
        for (auto& w : workers_) {
            if (w.joinable()) w.join();
        }
        workers_.clear();
    }

    void priority_worker_loop() {
        while (true) {
            PriorityQueueEntry entry;
            {
                std::unique_lock lock(priority_mutex_);
                priority_cv_.wait(lock, [this]() {
                    return !priority_queue_.empty() || !workers_running_;
                });

                if (!workers_running_ && priority_queue_.empty()) {
                    return;
                }

                if (priority_queue_.empty()) continue;

                entry = priority_queue_.top();
                priority_queue_.pop();
            }

            // Execute the task
            try {
                entry.task();
            } catch (const std::exception& e) {
                std::cerr << "[PRIORITY_WORKER] Task failed: " << entry.description
                          << " - " << e.what() << std::endl;
            }

            total_processed_++;
        }
    }

    // ========================================================================
    // Internal: Maintenance thread
    // ========================================================================

    void start_maintenance_thread() {
        start_priority_workers();
        maintenance_thread_ = std::thread([this]() {
            while (!shutdown_) {
                std::this_thread::sleep_for(std::chrono::seconds(60));
                if (shutdown_) break;
                run_maintenance_cycle();
            }
        });
    }

    // ========================================================================
    // Member variables
    // ========================================================================

    // Rate limit configuration
    std::shared_mutex config_mutex_;
    std::map<std::string, RateLimitConfigEntry> rate_limit_configs_;
    std::vector<EndpointRateLimiter> endpoint_limiters_;

    // Rate limit overrides
    std::shared_mutex override_mutex_;
    std::unordered_map<std::string, RateLimitOverride> rate_limit_overrides_;

    // Per-user and per-IP rate limiters
    std::mutex user_limit_mutex_;
    std::unordered_map<std::string, std::shared_ptr<CombinedRateLimiter>> user_limiters_;

    std::mutex ip_limit_mutex_;
    std::unordered_map<std::string, std::shared_ptr<CombinedRateLimiter>> ip_limiters_;

    // Global rate limiter
    CombinedRateLimiter global_limiter_{1000, 500.0, 1000, 1000, 500};

    // Retention policies
    std::shared_mutex retention_mutex_;
    std::unordered_map<std::string, RetentionPolicy> retention_policies_;

    // Purge jobs
    std::shared_mutex purge_mutex_;
    std::unordered_map<std::string, PurgeJob> purge_jobs_;

    // GDPR data exports
    std::shared_mutex gdpr_mutex_;
    std::unordered_map<std::string, GdprExportRequest> gdpr_exports_;

    // GDPR data erasures
    std::shared_mutex gdpr_erasure_mutex_;
    std::unordered_map<std::string, GdprErasureRequest> gdpr_erasures_;

    // Consent management
    std::shared_mutex consent_mutex_;
    std::unordered_map<std::string, PrivacyPolicy> privacy_policies_;
    std::unordered_map<std::string, ConsentRecord> consent_records_;
    bool consent_enforcement_enabled_ = false;

    // Account validity
    std::shared_mutex account_validity_mutex_;
    std::unordered_map<std::string, AccountValidityRecord> account_validity_;

    // IP range blocking
    mutable std::shared_mutex ip_block_mutex_;
    std::unordered_map<std::string, IpBlockEntry> ip_blocks_;

    // Connection throttling
    std::shared_mutex throttle_mutex_;
    std::unordered_map<std::string, ConnectionThrottleEntry> connection_throttles_;
    int64_t default_max_connections_ = 100;
    int64_t default_throttle_duration_ms_ = 5000;

    // Request prioritization
    std::mutex priority_mutex_;
    std::priority_queue<PriorityQueueEntry> priority_queue_;
    std::condition_variable priority_cv_;
    std::vector<std::thread> workers_;
    std::atomic<int64_t> total_enqueued_{0};
    std::atomic<int64_t> total_processed_{0};
    bool workers_running_ = true;

    // Caching policies
    std::mutex cache_mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;
    int64_t cache_max_entries_ = 10000;
    int64_t cache_max_bytes_ = 100 * 1024 * 1024; // 100 MB
    int64_t cache_hits_ = 0;
    int64_t cache_misses_ = 0;
    int64_t cache_evictions_ttl_ = 0;
    int64_t cache_evictions_size_ = 0;

    // Event size limits
    std::atomic<int64_t> max_event_size_bytes_{65536}; // 64KB default

    // Rate limit event reporting
    std::shared_mutex event_log_mutex_;
    std::deque<RateLimitEvent> rate_limit_events_;
    int64_t max_rate_limit_events_stored_ = 10000;
    bool rate_limit_logging_enabled_ = true;

    std::mutex agg_mutex_;
    std::unordered_map<std::string, int64_t> rate_limit_hit_counts_;
    int64_t total_rate_limit_hits_ = 0;

    // Maintenance
    std::thread maintenance_thread_;
    std::atomic<bool> shutdown_{false};

    // JSON utility for building error responses
    json json_;
};

// ============================================================================
// Global singleton accessor
// ============================================================================

static std::unique_ptr<PolicyManager> g_policy_manager;
static std::once_flag g_policy_manager_init;

PolicyManager& policy_manager() {
    std::call_once(g_policy_manager_init, []() {
        g_policy_manager = std::make_unique<PolicyManager>();
    });
    return *g_policy_manager;
}

// ============================================================================
// Convenience free functions for external callers
// ============================================================================

bool is_ip_blocked(const std::string& ip) {
    return policy_manager().is_ip_blocked(ip);
}

RateLimitResult check_rate_limit(const std::string& user_id, const std::string& client_ip,
                                  const std::string& endpoint, const std::string& method) {
    return policy_manager().check_rate_limit(user_id, client_ip, endpoint, method);
}

HttpResponse build_rate_limited_response(int64_t retry_after_ms, const std::string& reason) {
    return policy_manager().build_429_response(retry_after_ms, reason);
}

bool check_event_size(const std::string& event_json) {
    return !policy_manager().is_event_too_large(event_json);
}

bool check_event_size(size_t size_bytes) {
    return !policy_manager().is_event_too_large(size_bytes);
}

json get_policy_manager_status() {
    return policy_manager().get_full_status();
}

void reset_policy_manager() {
    policy_manager().reset_all();
}

// Connection management
bool throttle_check(const std::string& ip) {
    return policy_manager().check_connection_throttle(ip);
}

void throttle_release(const std::string& ip) {
    policy_manager().release_connection(ip);
}

// Consent
bool consent_check(const std::string& user_id, const std::string& scope) {
    return policy_manager().check_consent_and_block(user_id, scope);
}

void consent_record(const std::string& user_id, const std::string& scope,
                    const std::string& version, const std::string& ip,
                    const std::string& ua) {
    policy_manager().record_consent(user_id, scope, version, ip, ua, true);
}

// GDPR
std::string gdpr_request_export(const std::string& user_id, const std::string& outdir) {
    return policy_manager().request_gdpr_export(user_id, outdir);
}

std::string gdpr_request_erasure(const std::string& user_id, bool events, bool media) {
    return policy_manager().request_gdpr_erasure(user_id, events, media);
}

// Account management
bool account_is_expired(const std::string& user_id) {
    return policy_manager().is_account_expired(user_id);
}

bool account_renew(const std::string& user_id, int64_t seconds) {
    return policy_manager().renew_account(user_id, seconds);
}

void account_set_validity(const std::string& user_id, int64_t expires_at) {
    policy_manager().set_account_validity(user_id, expires_at);
}

// Cache
std::optional<json> cache_fetch(const std::string& key) {
    return policy_manager().cache_get(key);
}

void cache_store(const std::string& key, const json& value, int64_t ttl_ms) {
    policy_manager().cache_set(key, value, ttl_ms);
}

// Retention
void set_room_retention(const std::string& room_id, int64_t max_lifetime_ms) {
    RetentionPolicy policy;
    policy.room_id = room_id;
    policy.max_lifetime_ms = max_lifetime_ms;
    policy.enabled = true;
    policy.created_at = now_sec();
    policy_manager().set_retention_policy(policy);
}

// IP blocks
void block_ip(const std::string& cidr, const std::string& reason, const std::string& by) {
    policy_manager().block_ip_range(cidr, reason, by);
}

void unblock_ip(const std::string& cidr) {
    policy_manager().unblock_ip_range(cidr);
}

// ============================================================================
// Additional PolicyManager methods: Batch rate limiting, event size
// validation response, retention auto-purge scheduler, rate limit header
// injection, and extended admin management.
// ============================================================================

// --------------------------------------------------------------------------
// BatchRateLimitChecker: Check multiple endpoints at once for bulk operations
// --------------------------------------------------------------------------
class BatchRateLimitChecker {
public:
    struct BatchEntry {
        std::string user_id;
        std::string client_ip;
        std::string endpoint;
        std::string method;
        bool is_sync = false;
    };

    struct BatchResult {
        bool all_allowed = true;
        std::vector<RateLimitResult> results;
        std::string blocking_endpoint;
        int64_t max_retry_ms = 0;
    };

    BatchResult check_batch(const std::vector<BatchEntry>& entries) {
        BatchResult batch_result;
        batch_result.all_allowed = true;

        for (const auto& entry : entries) {
            RateLimitResult r = policy_manager().check_rate_limit(
                entry.user_id, entry.client_ip, entry.endpoint, entry.method, entry.is_sync);
            batch_result.results.push_back(r);
            if (!r.allowed) {
                batch_result.all_allowed = false;
                batch_result.blocking_endpoint = entry.endpoint;
                batch_result.max_retry_ms = std::max(batch_result.max_retry_ms, r.retry_after_ms);
            }
        }

        return batch_result;
    }
};

// --------------------------------------------------------------------------
// build_event_size_error: Generate a 413 Payload Too Large response
// --------------------------------------------------------------------------
HttpResponse build_event_size_error(size_t actual_size, int64_t limit) {
    HttpResponse resp;
    resp.code = 413;
    resp.body = json::object({
        {"errcode", "M_TOO_LARGE"},
        {"error", "Event too large: " + std::to_string(actual_size) +
                  " bytes exceeds limit of " + std::to_string(limit) + " bytes"},
        {"actual_size", actual_size},
        {"max_size", limit}
    });
    resp.headers["Content-Type"] = "application/json";
    return resp;
}

// --------------------------------------------------------------------------
// inject_rate_limit_headers: Add X-RateLimit-* headers to a response
// --------------------------------------------------------------------------
void inject_rate_limit_headers(HttpResponse& resp, const RateLimitResult& rl_result) {
    if (rl_result.limit_max >= 0) {
        resp.headers["X-RateLimit-Limit"] = std::to_string(rl_result.limit_max);
    }
    if (rl_result.tokens_remaining >= 0) {
        resp.headers["X-RateLimit-Remaining"] = std::to_string(rl_result.tokens_remaining);
    }
    if (!rl_result.allowed && rl_result.retry_after_ms > 0) {
        resp.headers["X-RateLimit-Reset-After"] = std::to_string(rl_result.retry_after_ms);
        resp.headers["Retry-After"] = std::to_string(
            static_cast<int64_t>(std::ceil(rl_result.retry_after_ms / 1000.0)));
    }
}

// --------------------------------------------------------------------------
// RetentionAutoPurgeScheduler: Automatically trigger purges for rooms
// whose messages exceed max_lifetime.
// --------------------------------------------------------------------------
class RetentionAutoPurgeScheduler {
public:
    explicit RetentionAutoPurgeScheduler(PolicyManager& pm) : pm_(pm) {}

    // Scan all retention policies and schedule purges for rooms with expired
    // messages. Returns the number of purge jobs scheduled.
    int64_t scan_and_schedule() {
        int64_t scheduled = 0;
        json policies = pm_.get_all_retention_policies();
        int64_t now = now_sec();

        for (const auto& policy_json : policies) {
            if (!policy_json.value("enabled", false)) continue;

            int64_t max_lifetime_ms = policy_json.value("max_lifetime_ms", static_cast<int64_t>(0));
            if (max_lifetime_ms <= 0) continue;

            std::string room_id = policy_json.value("room_id", "*");
            int64_t cutoff = now - (max_lifetime_ms / 1000);

            // Check if we already have a running purge for this room
            json purge_jobs = pm_.get_all_purge_jobs();
            bool already_running = false;
            for (const auto& job : purge_jobs) {
                int state_val = job.value("state", 0);
                if (state_val == static_cast<int>(PurgeJobState::PENDING) ||
                    state_val == static_cast<int>(PurgeJobState::RUNNING)) {
                    std::string job_room = job.value("room_id", "");
                    if (job_room == room_id) {
                        already_running = true;
                        break;
                    }
                }
            }

            if (!already_running) {
                pm_.schedule_purge(room_id, cutoff, 500);
                scheduled++;
            }
        }

        return scheduled;
    }

private:
    PolicyManager& pm_;
};

// --------------------------------------------------------------------------
// Detailed GDPR export: List all user rooms and events from database
// (simulated with placeholder data for comprehensive structure)
// --------------------------------------------------------------------------
json build_detailed_gdpr_export(const std::string& user_id) {
    json export_data = json::object();

    // Metadata
    export_data["export_metadata"] = {
        {"user_id", user_id},
        {"export_timestamp", now_sec()},
        {"format_version", "1.0.0"},
        {"server_name", "progressive-server"},
        {"export_id", generate_job_id()}
    };

    // Account details
    export_data["account"] = {
        {"user_id", user_id},
        {"display_name", ""},
        {"avatar_url", ""},
        {"creation_ts", now_sec() - 86400 * 365},
        {"is_guest", false},
        {"is_admin", false},
        {"deactivated", false}
    };

    // Profile
    export_data["profile"] = {
        {"display_name_history", json::array({
            {{"name", "Original Name"}, {"set_at", now_sec() - 86400 * 200}},
            {{"name", "Updated Name"}, {"set_at", now_sec() - 86400 * 50}}
        })},
        {"avatar_url_history", json::array()},
        {"status_messages", json::array()}
    };

    // Rooms (membership history)
    json rooms = json::array();
    for (int i = 0; i < 5; ++i) {
        json room;
        room["room_id"] = "!room_" + std::to_string(i) + ":server";
        room["room_name"] = "Room " + std::to_string(i);
        room["membership"] = (i < 4) ? "join" : "leave";
        room["join_date"] = now_sec() - 86400 * (30 + i * 10);
        room["topic"] = "Topic for room " + std::to_string(i);
        room["canonical_alias"] = "#room" + std::to_string(i) + ":server";
        rooms.push_back(room);
    }
    export_data["rooms"] = rooms;

    // Events (user's messages, redactions, reactions)
    json events = json::array();
    for (int i = 0; i < 50; ++i) {
        json event;
        event["event_id"] = "$event_" + base62_encode(static_cast<uint64_t>(i)) + ":server";
        event["room_id"] = "!room_" + std::to_string(i % 5) + ":server";
        event["type"] = "m.room.message";
        event["origin_server_ts"] = now_sec() - 86400 * i;
        event["content"] = {
            {"msgtype", "m.text"},
            {"body", "Message number " + std::to_string(i)}
        };
        events.push_back(event);
    }
    export_data["events"] = events;

    // Devices and sessions
    json devices = json::array();
    devices.push_back({
        {"device_id", "DEVICE_BROWSER"},
        {"display_name", "Chrome on Linux"},
        {"last_seen_ip", "10.0.0.1"},
        {"last_seen_ts", now_sec() - 3600},
        {"user_agent", "Mozilla/5.0"}
    });
    devices.push_back({
        {"device_id", "DEVICE_MOBILE"},
        {"display_name", "Element Android"},
        {"last_seen_ip", "10.0.0.2"},
        {"last_seen_ts", now_sec() - 86400},
        {"user_agent", "Element/1.6.0"}
    });
    export_data["devices"] = devices;

    // End-to-end encryption keys
    export_data["e2e_keys"] = {
        {"device_keys", json::array()},
        {"one_time_keys_count", 50},
        {"cross_signing_keys", json::object({
            {"master_key", json::object()},
            {"self_signing_key", json::object()},
            {"user_signing_key", json::object()}
        })}
    };

    // Push rules and notification settings
    export_data["push_rules"] = {
        {"global", json::object({
            {"override", json::array()},
            {"content", json::array()},
            {"room", json::array()},
            {"sender", json::array()},
            {"underride", json::array()}
        })}
    };

    // Third-party protocol connections
    json connections = json::object();
    connections["irc"] = json::array({
        {{"network", "freenode"}, {"nickname", "user_nick"}, {"channels", json::array({"#channel1", "#channel2"})}}
    });
    connections["xmpp"] = json::array({
        {{"jid", "user@xmpp.example.com"}, {"roster", json::array()}}
    });
    connections["lemmy"] = json::array();
    export_data["connections"] = connections;

    // Consent records
    auto consent_records = policy_manager().get_user_consent_records(user_id);
    json consent_arr = json::array();
    for (const auto& cr : consent_records) {
        consent_arr.push_back({
            {"scope", cr.scope},
            {"version", cr.policy_version},
            {"consented_at", cr.consented_at},
            {"ip", cr.ip_address},
            {"user_agent", cr.user_agent},
            {"explicit", cr.explicit_consent}
        });
    }
    export_data["consent_records"] = consent_arr;

    // Uploaded media references
    json media = json::array();
    for (int i = 0; i < 10; ++i) {
        media.push_back({
            {"media_id", "media_" + base62_encode(static_cast<uint64_t>(i))},
            {"media_type", i % 2 == 0 ? "image/png" : "application/pdf"},
            {"upload_name", "file_" + std::to_string(i) + (i % 2 == 0 ? ".png" : ".pdf")},
            {"uploaded_at", now_sec() - 86400 * i},
            {"size_bytes", 1024 * (i + 1) * 100}
        });
    }
    export_data["media"] = media;

    return export_data;
}

// --------------------------------------------------------------------------
// Admin API handler for policy management via REST
// --------------------------------------------------------------------------
json handle_admin_policy_request(const std::string& method, const std::string& subpath,
                                  const json& body) {
    json response;

    if (subpath == "/rate_limits/config" && method == "GET") {
        response = policy_manager().get_rate_limit_configs();
    } else if (subpath == "/rate_limits/config" && method == "POST") {
        RateLimitConfigEntry entry;
        entry.name = body.value("name", "");
        entry.match_endpoint = body.value("match_endpoint", ".*");
        entry.match_method = body.value("match_method", "*");
        entry.per_second = body.value("per_second", static_cast<int64_t>(0));
        entry.burst_count = body.value("burst_count", static_cast<int64_t>(0));
        entry.window_ms = body.value("window_ms", static_cast<int64_t>(0));
        entry.window_max = body.value("window_max", static_cast<int64_t>(0));
        entry.max_concurrent = body.value("max_concurrent", static_cast<int64_t>(0));
        entry.enabled = body.value("enabled", true);
        policy_manager().configure_rate_limit_endpoint(entry);
        response["status"] = "ok";
        response["name"] = entry.name;
    } else if (subpath == "/rate_limits/config" && method == "DELETE") {
        std::string name = body.value("name", "");
        policy_manager().remove_rate_limit_config(name);
        response["status"] = "ok";
    } else if (subpath == "/rate_limits/overrides" && method == "GET") {
        response = policy_manager().get_all_rate_limit_overrides();
    } else if (subpath == "/rate_limits/overrides" && method == "POST") {
        std::string uid = body.value("user_id", "");
        int64_t per_sec = body.value("per_second", static_cast<int64_t>(0));
        int64_t burst = body.value("burst_count", static_cast<int64_t>(0));
        int64_t max_conc = body.value("max_concurrent", static_cast<int64_t>(0));
        std::string reason = body.value("reason", "");
        int64_t expires = body.value("expires_at", static_cast<int64_t>(0));
        policy_manager().set_rate_limit_override(uid, per_sec, burst, max_conc, reason, expires);
        response["status"] = "ok";
    } else if (subpath == "/rate_limits/overrides" && method == "DELETE") {
        std::string uid = body.value("user_id", "");
        policy_manager().remove_rate_limit_override(uid);
        response["status"] = "ok";
    } else if (subpath == "/rate_limits/events" && method == "GET") {
        int64_t limit = body.value("limit", static_cast<int64_t>(100));
        response = policy_manager().get_rate_limit_events(limit);
    } else if (subpath == "/rate_limits/aggregates" && method == "GET") {
        response = policy_manager().get_rate_limit_aggregates();
    } else if (subpath == "/rate_limits/aggregates" && method == "DELETE") {
        policy_manager().reset_rate_limit_counters();
        response["status"] = "ok";
    } else if (subpath == "/rate_limits/logging" && method == "POST") {
        bool enabled = body.value("enabled", true);
        policy_manager().set_rate_limit_logging(enabled);
        response["status"] = "ok";
    } else if (subpath == "/ip_blocks" && method == "GET") {
        response = policy_manager().get_ip_blocks();
    } else if (subpath == "/ip_blocks" && method == "POST") {
        std::string cidr = body.value("cidr", "");
        std::string reason = body.value("reason", "");
        std::string by = body.value("blocked_by", "admin");
        int64_t expires = body.value("expires_at", static_cast<int64_t>(0));
        policy_manager().block_ip_range(cidr, reason, by, expires);
        response["status"] = "ok";
    } else if (subpath == "/ip_blocks" && method == "DELETE") {
        std::string cidr = body.value("cidr", "");
        policy_manager().unblock_ip_range(cidr);
        response["status"] = "ok";
    } else if (subpath == "/connection_throttle" && method == "GET") {
        response = policy_manager().get_connection_throttle_stats();
    } else if (subpath == "/connection_throttle" && method == "POST") {
        int64_t max_conn = body.value("max_connections", static_cast<int64_t>(100));
        int64_t duration = body.value("duration_ms", static_cast<int64_t>(5000));
        policy_manager().configure_connection_throttle(max_conn, duration);
        response["status"] = "ok";
    } else if (subpath == "/retention_policies" && method == "GET") {
        response = policy_manager().get_all_retention_policies();
    } else if (subpath == "/retention_policies" && method == "POST") {
        RetentionPolicy pol;
        pol.room_id = body.value("room_id", "*");
        pol.max_lifetime_ms = body.value("max_lifetime_ms", static_cast<int64_t>(0));
        pol.min_lifetime_ms = body.value("min_lifetime_ms", static_cast<int64_t>(0));
        pol.enabled = body.value("enabled", true);
        pol.created_by = body.value("created_by", "admin");
        pol.created_at = now_sec();
        pol.updated_at = now_sec();
        int action_val = body.value("action", 0);
        pol.action = static_cast<RetentionAction>(action_val);
        policy_manager().set_retention_policy(pol);
        response["status"] = "ok";
    } else if (subpath == "/retention_policies" && method == "DELETE") {
        std::string rid = body.value("room_id", "");
        policy_manager().remove_retention_policy(rid);
        response["status"] = "ok";
    } else if (subpath == "/purge_jobs" && method == "GET") {
        response = policy_manager().get_all_purge_jobs();
    } else if (subpath == "/purge_jobs" && method == "POST") {
        std::string rid = body.value("room_id", "*");
        int64_t cutoff = body.value("cutoff_timestamp", now_sec() - 86400 * 30);
        int64_t batch = body.value("batch_size", static_cast<int64_t>(1000));
        std::string job_id = policy_manager().schedule_purge(rid, cutoff, batch);
        response["status"] = "ok";
        response["job_id"] = job_id;
    } else if (subpath == "/purge_jobs/cancel" && method == "POST") {
        std::string jid = body.value("job_id", "");
        policy_manager().cancel_purge_job(jid);
        response["status"] = "ok";
    } else if (subpath == "/purge_jobs/schedule_auto" && method == "POST") {
        RetentionAutoPurgeScheduler scheduler(policy_manager());
        int64_t scheduled = scheduler.scan_and_schedule();
        response["status"] = "ok";
        response["scheduled_jobs"] = scheduled;
    } else if (subpath == "/gdpr/exports" && method == "GET") {
        response = policy_manager().get_all_gdpr_exports();
    } else if (subpath == "/gdpr/exports" && method == "POST") {
        std::string uid = body.value("user_id", "");
        std::string dir = body.value("output_dir", "/tmp/gdpr_exports");
        std::string req_id = policy_manager().request_gdpr_export(uid, dir);
        response["status"] = "ok";
        response["request_id"] = req_id;
    } else if (subpath == "/gdpr/erasures" && method == "GET") {
        response = policy_manager().get_all_gdpr_erasures();
    } else if (subpath == "/gdpr/erasures" && method == "POST") {
        std::string uid = body.value("user_id", "");
        bool erase_events = body.value("erase_events", false);
        bool erase_media = body.value("erase_media", false);
        std::string req_id = policy_manager().request_gdpr_erasure(uid, erase_events, erase_media);
        response["status"] = "ok";
        response["request_id"] = req_id;
    } else if (subpath == "/consent/policies" && method == "GET") {
        response = policy_manager().get_all_privacy_policies();
    } else if (subpath == "/consent/policies" && method == "POST") {
        PrivacyPolicy pol;
        pol.version = body.value("version", "1.0");
        pol.scope = body.value("scope", "privacy_policy");
        pol.language = body.value("language", "en");
        pol.title = body.value("title", "");
        pol.content = body.value("content", "");
        pol.url = body.value("url", "");
        pol.published_at = now_sec();
        pol.effective_at = body.value("effective_at", now_sec());
        pol.active = true;
        policy_manager().publish_privacy_policy(pol);
        response["status"] = "ok";
    } else if (subpath == "/consent/report" && method == "GET") {
        response = policy_manager().get_consent_report();
    } else if (subpath == "/consent/enforcement" && method == "POST") {
        bool enabled = body.value("enabled", true);
        policy_manager().set_consent_enforcement(enabled);
        response["status"] = "ok";
    } else if (subpath == "/accounts/validity" && method == "GET") {
        response = policy_manager().get_all_account_validity();
    } else if (subpath == "/accounts/validity" && method == "POST") {
        std::string uid = body.value("user_id", "");
        int64_t expires = body.value("expires_at", now_sec() + 86400 * 365);
        std::string by = body.value("created_by", "admin");
        policy_manager().set_account_validity(uid, expires, by);
        response["status"] = "ok";
    } else if (subpath == "/accounts/renew" && method == "POST") {
        std::string uid = body.value("user_id", "");
        int64_t seconds = body.value("additional_seconds", static_cast<int64_t>(86400 * 30));
        bool ok = policy_manager().renew_account(uid, seconds);
        response["status"] = ok ? "ok" : "not_found";
    } else if (subpath == "/cache" && method == "GET") {
        response = policy_manager().cache_stats();
    } else if (subpath == "/cache" && method == "POST") {
        int64_t max_entries = body.value("max_entries", static_cast<int64_t>(10000));
        int64_t max_bytes = body.value("max_bytes", static_cast<int64_t>(100 * 1024 * 1024));
        policy_manager().cache_set_max_size(max_entries, max_bytes);
        response["status"] = "ok";
    } else if (subpath == "/cache" && method == "DELETE") {
        policy_manager().cache_clear();
        response["status"] = "ok";
    } else if (subpath == "/event_size_limit" && method == "GET") {
        response["max_bytes"] = policy_manager().get_event_size_limit();
    } else if (subpath == "/event_size_limit" && method == "POST") {
        int64_t limit = body.value("max_bytes", static_cast<int64_t>(65536));
        policy_manager().set_event_size_limit(limit);
        response["status"] = "ok";
    } else if (subpath == "/priority_queue" && method == "GET") {
        response = policy_manager().get_priority_queue_stats();
    } else if (subpath == "/full_status" && method == "GET") {
        response = policy_manager().get_full_status();
    } else if (subpath == "/reset" && method == "POST") {
        policy_manager().reset_all();
        response["status"] = "ok";
    } else {
        response["errcode"] = "M_UNRECOGNIZED";
        response["error"] = "Unknown admin policy endpoint: " + subpath;
    }

    return response;
}

// --------------------------------------------------------------------------
// Simple in-memory event size statistics tracking
// --------------------------------------------------------------------------
class EventSizeTracker {
public:
    void record_event(size_t size_bytes, bool accepted) {
        std::unique_lock lock(mu_);
        total_events_++;
        total_bytes_ += size_bytes;
        if (accepted) {
            accepted_events_++;
            accepted_bytes_ += size_bytes;
            if (size_bytes > max_accepted_size_) max_accepted_size_ = size_bytes;
            if (min_accepted_size_ == 0 || size_bytes < min_accepted_size_) min_accepted_size_ = size_bytes;
        } else {
            rejected_events_++;
            rejected_bytes_ += size_bytes;
            if (size_bytes > max_rejected_size_) max_rejected_size_ = size_bytes;
            if (min_rejected_size_ == 0 || size_bytes < min_rejected_size_) min_rejected_size_ = size_bytes;
        }

        // Track size distribution
        std::string bucket = size_bucket(size_bytes);
        size_distribution_[bucket]++;
    }

    json stats() {
        std::unique_lock lock(mu_);
        return json::object({
            {"total_events", total_events_},
            {"total_bytes", total_bytes_},
            {"accepted_events", accepted_events_},
            {"accepted_bytes", accepted_bytes_},
            {"rejected_events", rejected_events_},
            {"rejected_bytes", rejected_bytes_},
            {"avg_accepted_size", accepted_events_ > 0 ? (accepted_bytes_ / accepted_events_) : 0},
            {"max_accepted_size", max_accepted_size_},
            {"min_accepted_size", min_accepted_size_},
            {"max_rejected_size", max_rejected_size_},
            {"min_rejected_size", min_rejected_size_},
            {"size_distribution", size_distribution_}
        });
    }

private:
    static std::string size_bucket(size_t bytes) {
        if (bytes <= 1024) return "0-1KB";
        if (bytes <= 10240) return "1KB-10KB";
        if (bytes <= 65536) return "10KB-64KB";
        if (bytes <= 262144) return "64KB-256KB";
        if (bytes <= 1048576) return "256KB-1MB";
        return ">1MB";
    }

    std::mutex mu_;
    int64_t total_events_ = 0;
    int64_t total_bytes_ = 0;
    int64_t accepted_events_ = 0;
    int64_t accepted_bytes_ = 0;
    int64_t rejected_events_ = 0;
    int64_t rejected_bytes_ = 0;
    size_t max_accepted_size_ = 0;
    size_t min_accepted_size_ = 0;
    size_t max_rejected_size_ = 0;
    size_t min_rejected_size_ = 0;
    std::map<std::string, int64_t> size_distribution_;
};

// Global event size tracker
static EventSizeTracker g_event_size_tracker;

void track_event_size(size_t size_bytes, bool accepted) {
    g_event_size_tracker.record_event(size_bytes, accepted);
}

json get_event_size_stats() {
    return g_event_size_tracker.stats();
}

// --------------------------------------------------------------------------
// End-to-end rate limit check with detailed diagnostics
// --------------------------------------------------------------------------
struct RateLimitDiagnostics {
    RateLimitResult result;
    int64_t elapsed_us = 0;
    bool ip_blocked = false;
    bool has_override = false;
    std::string matched_endpoint_rule;
    std::string matched_user_rule;
    json limiter_states;
};

RateLimitDiagnostics check_rate_limit_diagnostics(
    const std::string& user_id, const std::string& client_ip,
    const std::string& endpoint, const std::string& method)
{
    auto start = std::chrono::high_resolution_clock::now();

    RateLimitDiagnostics diag;

    diag.ip_blocked = is_ip_blocked(client_ip);
    if (diag.ip_blocked) {
        diag.result.allowed = false;
        diag.result.reason = "IP range blocked";
        diag.result.retry_after_ms = -1; // indefinite
        auto end = std::chrono::high_resolution_clock::now();
        diag.elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        return diag;
    }

    auto override = policy_manager().get_rate_limit_override(user_id);
    diag.has_override = override.has_value() && override->active;

    diag.result = policy_manager().check_rate_limit(user_id, client_ip, endpoint, method);

    auto end = std::chrono::high_resolution_clock::now();
    diag.elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    return diag;
}

// End of policy_manager.cpp
} // namespace progressive::server
