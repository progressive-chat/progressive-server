// dos_protection.cpp - Matrix comprehensive DoS protection, rate limiting,
// connection throttling, and IP blocking
// Implements: token bucket + sliding window rate limiter, concurrent request
// limiter, IP/user/endpoint rate limiting, connection throttling, CIDR IP
// blocking, DNSBL integration, request prioritization, 429 response generation,
// rate limit headers injection, event reporting, admin API, overrides & whitelist,
// global config, synchrotron-specific limits, and full metrics.
// Namespace: progressive::server
//
// Equivalent coverage (conceptually):
//   synapse/api/ratelimiting.py
//   synapse/util/ratelimitutils.py
//   synapse/http/site.py (connection throttling)
//   synapse/util/caches/ (request prioritization concepts)
//   + custom DoS hardening beyond Synapse

#include "../json.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <bitset>
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
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

// ---------------------------------------------------------------------------
// 3rd-party / platform includes used for lower-level socket / DNSBL work
// ---------------------------------------------------------------------------
#if defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace progressive::server {

// ============================================================================
// Convenience alias
// ============================================================================
using json = nlohmann::json;

// ============================================================================
// SECTION 0: Utility / Helpers
// ============================================================================

namespace {

// --------------------------------------------------------------------------
// Time helpers
// --------------------------------------------------------------------------
int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t now_sec() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

int64_t steady_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// --------------------------------------------------------------------------
// Fast case-insensitive ASCII compare
// --------------------------------------------------------------------------
bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char ca = a[i] >= 'A' && a[i] <= 'Z' ? a[i] + 32 : a[i];
        char cb = b[i] >= 'A' && b[i] <= 'Z' ? b[i] + 32 : b[i];
        if (ca != cb) return false;
    }
    return true;
}

// --------------------------------------------------------------------------
// DNS resolution helper (used by DNSBL)
// --------------------------------------------------------------------------
std::vector<std::string> dns_resolve(const std::string& hostname) {
    std::vector<std::string> results;
#if defined(__linux__) || defined(__APPLE__)
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int err = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (err != 0) return results;
    for (struct addrinfo* rp = res; rp != nullptr; rp = rp->ai_next) {
        char buf[INET6_ADDRSTRLEN] = {};
        if (rp->ai_family == AF_INET) {
            auto* s = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
            inet_ntop(AF_INET, &s->sin_addr, buf, sizeof(buf));
        } else if (rp->ai_family == AF_INET6) {
            auto* s = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
            inet_ntop(AF_INET6, &s->sin6_addr, buf, sizeof(buf));
        } else {
            continue;
        }
        results.emplace_back(buf);
    }
    freeaddrinfo(res);
#endif
    return results;
}

// --------------------------------------------------------------------------
// Simple string trim
// --------------------------------------------------------------------------
std::string trim(const std::string& s) {
    const char* ws = " \t\n\r\f\v";
    auto start = s.find_first_not_of(ws);
    auto end   = s.find_last_not_of(ws);
    if (start == std::string::npos) return {};
    return s.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string tok;
    while (std::getline(iss, tok, delim)) {
        if (!tok.empty()) out.push_back(trim(tok));
    }
    return out;
}

// --------------------------------------------------------------------------
// CIDR IP Address Parsing & Matching
// --------------------------------------------------------------------------

// Parse an IPv4 address into four octets.
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

// Parse an IPv6 address into 8 hextets.
bool parse_ipv6(const std::string& ip, uint16_t out[8]) {
    std::memset(out, 0, 8 * sizeof(uint16_t));
    std::string expanded;
    size_t dc = ip.find("::");
    if (dc != std::string::npos) {
        std::string left = ip.substr(0, dc);
        std::string right = (dc + 2 < ip.size()) ? ip.substr(dc + 2) : "";
        int left_groups = 0;
        for (char c : left) if (c == ':') left_groups++;
        if (!left.empty()) left_groups++;
        int right_groups = 0;
        for (char c : right) if (c == ':') right_groups++;
        if (!right.empty()) right_groups++;
        int missing = 8 - left_groups - right_groups;
        if (missing < 0) return false;
        expanded = left;
        for (int i = 0; i < missing; ++i) expanded += ":0";
        if (!left.empty() && !right.empty()) expanded += ":";
        expanded += right;
    } else {
        expanded = ip;
    }
    if (expanded.empty()) return true; // "::"
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

// Check if an IP matches a CIDR range.
bool ip_matches_cidr(const std::string& ip, const std::string& cidr) {
    size_t slash = cidr.find('/');
    if (slash == std::string::npos) return ip == cidr;  // exact match

    std::string range_ip = cidr.substr(0, slash);
    int prefix = 0;
    try { prefix = std::stoi(cidr.substr(slash + 1)); }
    catch (...) { return false; }
    if (prefix < 0 || prefix > 128) return false;

    bool ip_is_v4    = (ip.find(':') == std::string::npos);
    bool range_is_v4 = (range_ip.find(':') == std::string::npos);

    if (ip_is_v4 && range_is_v4) {
        uint8_t io[4], ro[4];
        if (!parse_ipv4(ip, io) || !parse_ipv4(range_ip, ro)) return false;
        uint32_t ip_int    = (uint32_t(io[0]) << 24) | (uint32_t(io[1]) << 16)
                           | (uint32_t(io[2]) << 8)  | uint32_t(io[3]);
        uint32_t range_int = (uint32_t(ro[0]) << 24) | (uint32_t(ro[1]) << 16)
                           | (uint32_t(ro[2]) << 8)  | uint32_t(ro[3]);
        uint32_t mask = (prefix == 0) ? 0 : (~uint32_t(0) << (32 - prefix));
        return (ip_int & mask) == (range_int & mask);
    }
    if (!ip_is_v4 && !range_is_v4) {
        uint16_t ih[8], rh[8];
        if (!parse_ipv6(ip, ih) || !parse_ipv6(range_ip, rh)) return false;
        for (int i = 0; i < 8; ++i) {
            int bits = std::min(16, prefix - i * 16);
            if (bits <= 0) return true;
            uint16_t mask = (bits == 16) ? 0xFFFF : (uint16_t(~0) << (16 - bits));
            if ((ih[i] & mask) != (rh[i] & mask)) return false;
        }
        return true;
    }
    return false;
}

// --------------------------------------------------------------------------
// Base62 encoding for compact IDs
// --------------------------------------------------------------------------
std::string base62_encode(uint64_t num) {
    static const char* chars =
        "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if (num == 0) return "0";
    std::string result;
    while (num > 0) {
        result = chars[num % 62] + result;
        num /= 62;
    }
    return result;
}

// --------------------------------------------------------------------------
// Generate globally unique event/report IDs
// --------------------------------------------------------------------------
static std::atomic<uint64_t> g_id_counter{0};
std::string generate_event_id() {
    uint64_t ts  = static_cast<uint64_t>(now_ms());
    uint64_t seq = g_id_counter.fetch_add(1, std::memory_order_relaxed);
    return base62_encode(ts) + "_" + base62_encode(seq);
}

// --------------------------------------------------------------------------
// Simple bloom filter for fast negative lookups (IP whitelist / blocklist)
// --------------------------------------------------------------------------
class BloomFilter {
public:
    explicit BloomFilter(size_t size_bits = 65536, uint8_t num_hashes = 4)
        : num_hashes_(num_hashes), bits_(size_bits) {}

    void insert(const std::string& key) {
        std::lock_guard<std::mutex> lk(mu_);
        size_t bits = bits_.size();
        std::hash<std::string> h;
        uint64_t hv = h(key);
        for (uint8_t i = 0; i < num_hashes_; ++i) {
            uint64_t idx = (hv ^ (uint64_t(i) * 0x9E3779B97F4A7C15ULL)) % bits;
            bits_.set(idx);
        }
    }

    bool probably_contains(const std::string& key) const {
        std::lock_guard<std::mutex> lk(mu_);
        size_t bits = bits_.size();
        std::hash<std::string> h;
        uint64_t hv = h(key);
        for (uint8_t i = 0; i < num_hashes_; ++i) {
            uint64_t idx = (hv ^ (uint64_t(i) * 0x9E3779B97F4A7C15ULL)) % bits;
            if (!bits_.test(idx)) return false;
        }
        return true;
    }

    void clear() {
        std::lock_guard<std::mutex> lk(mu_);
        bits_.reset();
    }

    size_t size_bits() const { return bits_.size(); }

private:
    mutable std::mutex mu_;
    uint8_t num_hashes_;
    std::bitset<65536> bits_; // fixed size for predictable memory
};

}  // anonymous namespace

// ============================================================================
// SECTION 1: Token Bucket Rate Limiter
// Classic token bucket algorithm with per-key statistics and reconfiguration.
// ============================================================================

class TokenBucket {
public:
    TokenBucket() = default;

    TokenBucket(int64_t max_tokens, double refill_rate,
                std::string name = "")
        : max_tokens_(max_tokens)
        , refill_rate_(refill_rate)
        , tokens_(static_cast<double>(max_tokens))
        , last_refill_(now_ms())
        , name_(std::move(name)) {}

    // Consume `count` tokens. Returns true if allowed.
    bool try_consume(int64_t count = 1, int64_t current_ms = 0) {
        std::lock_guard<std::mutex> lk(mu_);
        if (current_ms == 0) current_ms = now_ms();
        _refill(current_ms);
        if (tokens_ >= static_cast<double>(count)) {
            tokens_ -= static_cast<double>(count);
            total_consumed_ += count;
            total_requests_++;
            return true;
        }
        total_rejected_++;
        total_requests_++;
        return false;
    }

    // Non-consuming check: how many tokens available?
    double available(int64_t current_ms = 0) {
        std::lock_guard<std::mutex> lk(mu_);
        if (current_ms == 0) current_ms = now_ms();
        _refill(current_ms);
        return tokens_;
    }

    // Time in ms until the next token becomes available (for Retry-After).
    int64_t retry_after_ms() {
        std::lock_guard<std::mutex> lk(mu_);
        int64_t now = now_ms();
        _refill(now);
        if (tokens_ >= 1.0) return 0;
        if (refill_rate_ <= 0.0) return 60000; // effectively infinite wait
        double needed = 1.0 - tokens_;
        return static_cast<int64_t>((needed / refill_rate_) * 1000.0) + 1;
    }

    // Reconfigure at runtime.
    void reconfigure(int64_t max_tokens, double refill_rate) {
        std::lock_guard<std::mutex> lk(mu_);
        max_tokens_  = max_tokens;
        refill_rate_ = refill_rate;
        if (tokens_ > static_cast<double>(max_tokens_))
            tokens_ = static_cast<double>(max_tokens_);
    }

    // Set name for metrics
    void set_name(const std::string& name) { name_ = name; }
    const std::string& name() const { return name_; }

    struct Stats {
        int64_t  total_consumed  = 0;
        int64_t  total_rejected  = 0;
        int64_t  total_requests  = 0;
        double   tokens_available = 0.0;
        int64_t  max_tokens      = 0;
        double   refill_rate     = 0.0;
        int64_t  last_refill_ms  = 0;
        std::string name;
    };

    Stats stats() {
        std::lock_guard<std::mutex> lk(mu_);
        int64_t now = now_ms();
        _refill(now);
        return Stats{total_consumed_, total_rejected_, total_requests_,
                     tokens_, max_tokens_, refill_rate_, last_refill_, name_};
    }

    void reset_stats() {
        std::lock_guard<std::mutex> lk(mu_);
        total_consumed_ = 0;
        total_rejected_ = 0;
        total_requests_ = 0;
    }

private:
    void _refill(int64_t current_ms) {
        if (current_ms <= last_refill_) return;
        int64_t elapsed = current_ms - last_refill_;
        tokens_ += (static_cast<double>(elapsed) / 1000.0) * refill_rate_;
        if (tokens_ > static_cast<double>(max_tokens_))
            tokens_ = static_cast<double>(max_tokens_);
        last_refill_ = current_ms;
    }

    std::mutex mu_;
    int64_t  max_tokens_   = 100;
    double   refill_rate_  = 10.0;
    double   tokens_       = 100.0;
    int64_t  last_refill_  = 0;
    int64_t  total_consumed_ = 0;
    int64_t  total_rejected_ = 0;
    int64_t  total_requests_ = 0;
    std::string name_;
};

// ============================================================================
// SECTION 2: Sliding Window Rate Limiter
// Strict "N requests per T milliseconds" window.  Timestamps stored in a
// deque; old entries pruned on each check.
// ============================================================================

class SlidingWindow {
public:
    SlidingWindow() = default;

    SlidingWindow(int64_t window_ms, int64_t max_events,
                  std::string name = "")
        : window_ms_(window_ms), max_events_(max_events),
          name_(std::move(name)) {}

    // Returns true if the event is accepted (under limit).
    bool try_accept(int64_t current_ms = 0) {
        std::lock_guard<std::mutex> lk(mu_);
        if (current_ms == 0) current_ms = now_ms();
        _prune(current_ms);
        total_requests_++;
        if (static_cast<int64_t>(timestamps_.size()) < max_events_) {
            timestamps_.push_back(current_ms);
            total_accepted_++;
            return true;
        }
        total_rejected_++;
        return false;
    }

    // Current count within the window.
    int64_t count(int64_t current_ms = 0) {
        std::lock_guard<std::mutex> lk(mu_);
        if (current_ms == 0) current_ms = now_ms();
        _prune(current_ms);
        return static_cast<int64_t>(timestamps_.size());
    }

    // Milliseconds until the next slot opens (0 = now).
    int64_t retry_after_ms(int64_t current_ms = 0) {
        std::lock_guard<std::mutex> lk(mu_);
        if (current_ms == 0) current_ms = now_ms();
        _prune(current_ms);
        if (static_cast<int64_t>(timestamps_.size()) < max_events_) return 0;
        if (timestamps_.empty()) return 0;
        int64_t oldest = timestamps_.front();
        return std::max(int64_t(0), oldest + window_ms_ - current_ms);
    }

    // Reconfigure at runtime.
    void reconfigure(int64_t window_ms, int64_t max_events) {
        std::lock_guard<std::mutex> lk(mu_);
        window_ms_  = window_ms;
        max_events_ = max_events;
    }

    const std::string& name() const { return name_; }

    struct Stats {
        int64_t total_accepted  = 0;
        int64_t total_rejected  = 0;
        int64_t total_requests  = 0;
        int64_t current_count   = 0;
        int64_t window_ms       = 0;
        int64_t max_events      = 0;
        std::string name;
    };

    Stats stats() {
        std::lock_guard<std::mutex> lk(mu_);
        int64_t now = now_ms();
        _prune(now);
        return Stats{total_accepted_, total_rejected_, total_requests_,
                     static_cast<int64_t>(timestamps_.size()),
                     window_ms_, max_events_, name_};
    }

    void reset_stats() {
        std::lock_guard<std::mutex> lk(mu_);
        total_accepted_ = 0;
        total_rejected_ = 0;
        total_requests_ = 0;
    }

private:
    void _prune(int64_t current_ms) {
        int64_t cutoff = current_ms - window_ms_;
        while (!timestamps_.empty() && timestamps_.front() < cutoff) {
            timestamps_.pop_front();
        }
    }

    std::mutex mu_;
    int64_t window_ms_  = 1000;
    int64_t max_events_ = 10;
    std::deque<int64_t> timestamps_;
    int64_t total_accepted_ = 0;
    int64_t total_rejected_ = 0;
    int64_t total_requests_ = 0;
    std::string name_;
};

// ============================================================================
// SECTION 3: Concurrent Request Limiter
// Bounds the number of in-flight requests sharing a key (IP, user, etc.).
// ============================================================================

class ConcurrentRequestLimiter {
public:
    ConcurrentRequestLimiter() = default;

    explicit ConcurrentRequestLimiter(int64_t max_concurrent,
                                      std::string name = "")
        : max_concurrent_(max_concurrent), name_(std::move(name)) {}

    // Acquire a slot. Returns handle >= 0 on success, -1 if denied.
    int64_t try_acquire() {
        std::lock_guard<std::mutex> lk(mu_);
        total_requests_++;
        if (current_ < max_concurrent_) {
            int64_t handle = next_handle_++;
            active_.insert(handle);
            current_++;
            total_acquired_++;
            return handle;
        }
        total_rejected_++;
        return -1;
    }

    // Release a previously acquired slot.
    void release(int64_t handle) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = active_.find(handle);
        if (it != active_.end()) {
            active_.erase(it);
            if (current_ > 0) current_--;
        }
    }

    int64_t current() const { return current_.load(); }

    int64_t max_allowed() const { return max_concurrent_; }

    void reconfigure(int64_t max_concurrent) {
        std::lock_guard<std::mutex> lk(mu_);
        max_concurrent_ = max_concurrent;
    }

    struct Stats {
        int64_t total_acquired  = 0;
        int64_t total_rejected  = 0;
        int64_t total_requests  = 0;
        int64_t current_requests = 0;
        int64_t max_concurrent  = 0;
        std::string name;
    };

    Stats stats() {
        std::lock_guard<std::mutex> lk(mu_);
        return Stats{total_acquired_, total_rejected_, total_requests_,
                     current_, max_concurrent_, name_};
    }

    void reset_stats() {
        std::lock_guard<std::mutex> lk(mu_);
        total_acquired_ = 0;
        total_rejected_ = 0;
        total_requests_ = 0;
    }

private:
    std::mutex mu_;
    int64_t max_concurrent_ = 100;
    std::atomic<int64_t> current_{0};
    int64_t next_handle_      = 1;
    int64_t total_acquired_   = 0;
    int64_t total_rejected_   = 0;
    int64_t total_requests_   = 0;
    std::unordered_set<int64_t> active_;
    std::string name_;
};

// ============================================================================
// SECTION 4: Rate Limit Result & Config Structures
// ============================================================================

struct RateLimitResult {
    bool      allowed          = true;
    int64_t   retry_after_ms   = 0;
    std::string reason;
    int64_t   limit_max        = -1;
    int64_t   limit_remaining  = -1;
    int64_t   limit_reset_ms   = 0;    // absolute timestamp when limit resets
    std::string limit_type;          // "token_bucket", "sliding_window", "concurrency"
};

struct RateLimitEntry {
    std::string name;
    std::string match_endpoint;  // regex
    std::string match_method;    // HTTP method or "*"
    int64_t per_second     = 0;
    int64_t burst_count    = 0;
    int64_t window_ms      = 0;
    int64_t window_max     = 0;
    int64_t max_concurrent = 0;
    bool    enabled        = true;
    bool    is_global      = false;   // applies to all endpoints
    int64_t priority       = 0;       // lower = higher priority match
};

struct RateLimitOverride {
    std::string user_id;
    int64_t per_second     = 0; // 0 = unlimited / exempt
    int64_t burst_count    = 0;
    int64_t max_concurrent = 0;
    std::string reason;
    int64_t created_at     = 0;
    int64_t expires_at     = 0;
    bool    active         = true;
};

struct RateLimitWhitelistEntry {
    std::string ip_or_cidr;
    std::string note;
    int64_t added_at = 0;
    bool    active   = true;
};

// ============================================================================
// SECTION 5: Combined Rate Limiter (Token + Window + Concurrency)
// Orchestrates all three limiter types for a single scope.
// ============================================================================

class CombinedRateLimiter {
public:
    CombinedRateLimiter() = default;

    CombinedRateLimiter(int64_t  max_burst,    double refill_rate,
                        int64_t  window_ms,    int64_t window_max,
                        int64_t  max_concurrent, std::string name = "")
        : bucket_(max_burst, refill_rate, name + "_token")
        , window_(window_ms, window_max, name + "_window")
        , concurrency_(max_concurrent, name + "_concur")
        , has_bucket_(true)
        , has_window_(true)
        , has_concurrency_(max_concurrent > 0) {}

    // Main check entry point.  Returns full RateLimitResult.
    RateLimitResult check(bool is_long_running = false) {
        RateLimitResult result;

        // 1. Concurrency (fail-fast if no slots)
        int64_t conc_handle = -1;
        if (has_concurrency_) {
            conc_handle = concurrency_.try_acquire();
            if (conc_handle < 0) {
                result.allowed        = false;
                result.retry_after_ms = 100;
                result.reason         = "Too many concurrent requests";
                result.limit_max      = concurrency_.max_allowed();
                result.limit_type     = "concurrency";
                return result;
            }
        }

        // 2. Sliding window
        if (has_window_) {
            if (!window_.try_accept()) {
                result.allowed        = false;
                result.retry_after_ms = window_.retry_after_ms();
                result.reason         = "Rate limit exceeded (sliding window)";
                result.limit_max      = window_.stats().max_events;
                result.limit_type     = "sliding_window";
                if (conc_handle >= 0) concurrency_.release(conc_handle);
                return result;
            }
        }

        // 3. Token bucket
        if (has_bucket_) {
            if (!bucket_.try_consume(1)) {
                result.allowed        = false;
                result.retry_after_ms = bucket_.retry_after_ms();
                result.reason         = "Rate limit exceeded (token bucket)";
                result.limit_max      = bucket_.stats().max_tokens;
                result.limit_type     = "token_bucket";
                if (conc_handle >= 0) concurrency_.release(conc_handle);
                return result;
            }
            result.limit_remaining = static_cast<int64_t>(bucket_.available());
            result.limit_max       = bucket_.stats().max_tokens;
        }

        result.allowed       = true;
        result.limit_type    = "combined";
        result.retry_after_ms = 0;

        // Store concurrency handle for later release via release_concurrency()
        _last_conc_handle = conc_handle;
        return result;
    }

    // Call when request processing completes to free concurrency slot.
    void release_concurrency() {
        if (_last_conc_handle >= 0 && has_concurrency_) {
            concurrency_.release(_last_conc_handle);
            _last_conc_handle = -1;
        }
    }

    void reconfigure(int64_t max_burst,  double refill_rate,
                     int64_t window_ms,  int64_t window_max,
                     int64_t max_concurrent) {
        bucket_.reconfigure(max_burst, refill_rate);
        window_.reconfigure(window_ms, window_max);
        concurrency_.reconfigure(max_concurrent);
        has_bucket_      = true;
        has_window_      = true;
        has_concurrency_ = (max_concurrent > 0);
    }

    void reset_stats() {
        bucket_.reset_stats();
        window_.reset_stats();
        concurrency_.reset_stats();
    }

    json stats_json() const {
        auto bs = bucket_.stats();
        auto ws = window_.stats();
        auto cs = concurrency_.stats();
        return json::object({
            {"token_bucket", {
                {"consumed",      bs.total_consumed},
                {"rejected",      bs.total_rejected},
                {"total_requests",bs.total_requests},
                {"available",     bs.tokens_available},
                {"max",           bs.max_tokens},
                {"refill_rate",   bs.refill_rate},
                {"name",          bs.name}
            }},
            {"sliding_window", {
                {"accepted",      ws.total_accepted},
                {"rejected",      ws.total_rejected},
                {"total_requests",ws.total_requests},
                {"current_count", ws.current_count},
                {"window_ms",     ws.window_ms},
                {"max_events",    ws.max_events},
                {"name",          ws.name}
            }},
            {"concurrency", {
                {"acquired",      cs.total_acquired},
                {"rejected",      cs.total_rejected},
                {"total_requests",cs.total_requests},
                {"current",       cs.current_requests},
                {"max",           cs.max_concurrent},
                {"name",          cs.name}
            }}
        });
    }

    TokenBucket&               bucket()       { return bucket_; }
    SlidingWindow&             window()       { return window_; }
    ConcurrentRequestLimiter&  concurrency()  { return concurrency_; }

private:
    TokenBucket               bucket_;
    SlidingWindow             window_;
    ConcurrentRequestLimiter  concurrency_;
    bool has_bucket_      = false;
    bool has_window_      = false;
    bool has_concurrency_ = false;
    int64_t _last_conc_handle = -1;
};

// ============================================================================
// SECTION 6: Connection Throttler
// Tracks connection rates per IP.  When an IP opens too many connections
// quickly, subsequent connections are delayed (sleep) or outright rejected.
// Also supports "slow-loris" style slow-read detection.
// ============================================================================

struct ConnectionRecord {
    int64_t connection_count    = 0;
    int64_t last_connection_ms  = 0;
    int64_t throttle_until_ms   = 0;
    int64_t total_throttled     = 0;
    int64_t total_connections   = 0;
    std::deque<int64_t> recent_connection_times; // sliding window
};

class ConnectionThrottler {
public:
    struct Config {
        int64_t max_connections_per_window  = 50;    // max connections in window
        int64_t connection_window_ms        = 10000; // 10 sec window
        int64_t throttle_duration_ms        = 30000; // how long to throttle
        int64_t min_connection_interval_ms  = 10;    // minimum ms between connections
        bool    enabled                     = true;
        int64_t max_throttle_entries        = 100000;
    };

    explicit ConnectionThrottler(const Config& cfg = {}) : config_(cfg) {}

    // Check an incoming connection from IP. Returns true if allowed,
    // false if it should be rejected/delayed.
    // delay_ms output: how long to wait before accepting (0 = no delay).
    bool check_connection(const std::string& ip, int64_t& delay_ms) {
        delay_ms = 0;
        if (!config_.enabled) return true;

        std::lock_guard<std::mutex> lk(mu_);
        int64_t now = now_ms();

        auto it = connections_.find(ip);
        if (it == connections_.end()) {
            // First connection from this IP
            if (connections_.size() >= static_cast<size_t>(config_.max_throttle_entries)) {
                // Too many tracked IPs - reject new ones to bound memory
                total_rejected_++;
                return false;
            }
            ConnectionRecord rec;
            rec.connection_count    = 1;
            rec.last_connection_ms  = now;
            rec.total_connections   = 1;
            rec.recent_connection_times.push_back(now);
            connections_.emplace(ip, std::move(rec));
            total_allowed_++;
            return true;
        }

        ConnectionRecord& rec = it->second;

        // Check if currently throttled
        if (rec.throttle_until_ms > 0 && now < rec.throttle_until_ms) {
            delay_ms = rec.throttle_until_ms - now;
            rec.total_throttled++;
            total_throttled_++;
            return false;
        }
        // Reset throttle flag if expired
        if (rec.throttle_until_ms > 0 && now >= rec.throttle_until_ms) {
            rec.throttle_until_ms = 0;
        }

        // Enforce minimum connection interval
        int64_t elapsed = now - rec.last_connection_ms;
        if (elapsed < config_.min_connection_interval_ms) {
            delay_ms = config_.min_connection_interval_ms - elapsed;
            rec.total_throttled++;
            total_throttled_++;
            return false;
        }

        // Prune old entries from the sliding window
        int64_t cutoff = now - config_.connection_window_ms;
        while (!rec.recent_connection_times.empty() &&
               rec.recent_connection_times.front() < cutoff) {
            rec.recent_connection_times.pop_front();
        }

        // Check if window is full
        if (static_cast<int64_t>(rec.recent_connection_times.size()) >=
            config_.max_connections_per_window) {
            // Throttle this IP
            rec.throttle_until_ms = now + config_.throttle_duration_ms;
            delay_ms = config_.throttle_duration_ms;
            rec.total_throttled++;
            total_throttled_++;
            return false;
        }

        // Accept the connection
        rec.connection_count++;
        rec.last_connection_ms = now;
        rec.total_connections++;
        rec.recent_connection_times.push_back(now);
        total_allowed_++;
        return true;
    }

    // Periodic cleanup of stale entries
    void cleanup(int64_t max_age_ms = 600000) { // 10 min default
        std::lock_guard<std::mutex> lk(mu_);
        int64_t now = now_ms();
        auto it = connections_.begin();
        while (it != connections_.end()) {
            if (now - it->second.last_connection_ms > max_age_ms &&
                (it->second.throttle_until_ms == 0 || now >= it->second.throttle_until_ms)) {
                it = connections_.erase(it);
            } else {
                ++it;
            }
        }
    }

    // Remove a specific IP's tracking data (e.g., after whitelist addition)
    void remove_ip(const std::string& ip) {
        std::lock_guard<std::mutex> lk(mu_);
        connections_.erase(ip);
    }

    void reconfigure(const Config& cfg) {
        std::lock_guard<std::mutex> lk(mu_);
        config_ = cfg;
    }

    const Config& config() const { return config_; }

    struct Stats {
        int64_t total_allowed    = 0;
        int64_t total_throttled  = 0;
        int64_t total_rejected   = 0;
        size_t  tracked_ips      = 0;
    };

    Stats stats() {
        std::lock_guard<std::mutex> lk(mu_);
        return Stats{total_allowed_, total_throttled_, total_rejected_,
                     connections_.size()};
    }

    // Detailed stats for admin API
    json detailed_stats_json() {
        std::lock_guard<std::mutex> lk(mu_);
        json j;
        j["total_allowed"]   = total_allowed_;
        j["total_throttled"] = total_throttled_;
        j["total_rejected"]  = total_rejected_;
        j["tracked_ips"]     = connections_.size();
        j["config"] = {
            {"max_connections_per_window", config_.max_connections_per_window},
            {"connection_window_ms",       config_.connection_window_ms},
            {"throttle_duration_ms",       config_.throttle_duration_ms},
            {"min_connection_interval_ms", config_.min_connection_interval_ms},
            {"enabled",                    config_.enabled}
        };
        // Top throttled IPs (up to 50)
        json top = json::array();
        std::vector<std::pair<std::string, const ConnectionRecord*>> entries;
        for (auto& [ip, rec] : connections_)
            entries.emplace_back(ip, &rec);
        std::sort(entries.begin(), entries.end(),
                  [](auto& a, auto& b) {
                      return a.second->total_throttled > b.second->total_throttled;
                  });
        size_t max_show = std::min(entries.size(), size_t(50));
        for (size_t i = 0; i < max_show; ++i) {
            auto& [ip, rec] = entries[i];
            top.push_back({
                {"ip", ip},
                {"total_throttled",   rec->total_throttled},
                {"total_connections", rec->total_connections},
                {"throttle_until_ms", rec->throttle_until_ms},
                {"connection_count",  rec->connection_count}
            });
        }
        j["top_throttled"] = top;
        return j;
    }

private:
    Config config_;
    std::mutex mu_;
    std::unordered_map<std::string, ConnectionRecord> connections_;
    int64_t total_allowed_   = 0;
    int64_t total_throttled_ = 0;
    int64_t total_rejected_  = 0;
};

// ============================================================================
// SECTION 7: IP Range Blocker (CIDR-based)
// Maintains a list of CIDR blocks to block outright.  Supports expiry.
// ============================================================================

struct IpBlockEntry {
    std::string cidr;
    std::string reason;
    int64_t blocked_at  = 0;
    int64_t expires_at  = 0;  // 0 = permanent
    bool    active      = true;
    std::string blocked_by;
    int64_t hit_count   = 0;
    std::string id;           // unique ID for admin lookup
};

class IpRangeBlocker {
public:
    IpRangeBlocker() = default;

    // Add a CIDR block. Returns the entry ID.
    std::string add_block(const std::string& cidr,
                          const std::string& reason,
                          const std::string& blocked_by,
                          int64_t expires_at = 0) {
        std::unique_lock lock(mu_);
        IpBlockEntry entry;
        entry.cidr       = cidr;
        entry.reason     = reason;
        entry.blocked_at = now_ms();
        entry.expires_at = expires_at;
        entry.blocked_by = blocked_by;
        entry.id         = generate_event_id();
        // Deduplicate: if same CIDR already exists active, update it
        for (auto& e : blocks_) {
            if (e.cidr == cidr && e.active) {
                e.reason     = reason;
                e.expires_at = expires_at;
                e.blocked_by = blocked_by;
                return e.id;
            }
        }
        blocks_.push_back(std::move(entry));
        _rebuild_bloom();
        return blocks_.back().id;
    }

    // Remove a block by CIDR or ID.
    bool remove_block(const std::string& cidr_or_id) {
        std::unique_lock lock(mu_);
        for (auto it = blocks_.begin(); it != blocks_.end(); ++it) {
            if (it->cidr == cidr_or_id || it->id == cidr_or_id) {
                it->active = false;
                _rebuild_bloom();
                return true;
            }
        }
        return false;
    }

    // Permanently delete a block entry
    bool delete_block(const std::string& cidr_or_id) {
        std::unique_lock lock(mu_);
        auto it = std::find_if(blocks_.begin(), blocks_.end(),
            [&](const IpBlockEntry& e) {
                return (e.cidr == cidr_or_id || e.id == cidr_or_id);
            });
        if (it != blocks_.end()) {
            blocks_.erase(it);
            _rebuild_bloom();
            return true;
        }
        return false;
    }

    // Check if an IP is blocked.  Returns a pair (blocked, reason).
    std::pair<bool, std::string> is_blocked(const std::string& ip) {
        std::shared_lock lock(mu_);
        // Fast bloom-filter negative check
        if (!bloom_filter_.probably_contains(ip)) return {false, ""};
        // Linear scan (CIDR matching is too complex for bloom exact answer)
        for (auto& entry : blocks_) {
            if (!entry.active) continue;
            if (entry.expires_at > 0 && now_ms() >= entry.expires_at) continue;
            if (ip_matches_cidr(ip, entry.cidr)) {
                entry.hit_count++; // mutable in shared_lock is safe for atomics/trivial
                return {true, entry.reason};
            }
        }
        return {false, ""};
    }

    // List all blocks (for admin API)
    std::vector<IpBlockEntry> list_blocks(bool active_only = true) {
        std::shared_lock lock(mu_);
        std::vector<IpBlockEntry> result;
        for (auto& e : blocks_) {
            if (active_only && !e.active) continue;
            result.push_back(e);
        }
        return result;
    }

    // Count of active blocks
    size_t block_count() {
        std::shared_lock lock(mu_);
        size_t cnt = 0;
        for (auto& e : blocks_)
            if (e.active) cnt++;
        return cnt;
    }

    // Purge expired blocks
    void purge_expired() {
        std::unique_lock lock(mu_);
        int64_t now = now_ms();
        bool changed = false;
        for (auto& e : blocks_) {
            if (e.expires_at > 0 && now >= e.expires_at && e.active) {
                e.active = false;
                changed = true;
            }
        }
        if (changed) _rebuild_bloom();
    }

    // Load blocks from JSON
    void load_from_json(const json& j) {
        std::unique_lock lock(mu_);
        blocks_.clear();
        for (auto& item : j) {
            IpBlockEntry e;
            e.cidr       = item.value("cidr", "");
            e.reason     = item.value("reason", "");
            e.blocked_at = item.value("blocked_at", now_ms());
            e.expires_at = item.value("expires_at", 0LL);
            e.active     = item.value("active", true);
            e.blocked_by = item.value("blocked_by", "config");
            e.hit_count  = item.value("hit_count", 0LL);
            e.id         = item.value("id", generate_event_id());
            if (!e.cidr.empty()) blocks_.push_back(std::move(e));
        }
        _rebuild_bloom();
    }

    // Serialize to JSON
    json to_json() {
        std::shared_lock lock(mu_);
        json arr = json::array();
        for (auto& e : blocks_) {
            arr.push_back({
                {"id",         e.id},
                {"cidr",       e.cidr},
                {"reason",     e.reason},
                {"blocked_at", e.blocked_at},
                {"expires_at", e.expires_at},
                {"active",     e.active},
                {"blocked_by", e.blocked_by},
                {"hit_count",  e.hit_count}
            });
        }
        return arr;
    }

    struct Stats {
        size_t total_blocks    = 0;
        size_t active_blocks   = 0;
        int64_t total_hits     = 0;
    };

    Stats stats() {
        std::shared_lock lock(mu_);
        Stats s;
        for (auto& e : blocks_) {
            s.total_blocks++;
            if (e.active) s.active_blocks++;
            s.total_hits += e.hit_count;
        }
        return s;
    }

private:
    void _rebuild_bloom() {
        bloom_filter_.clear();
        for (auto& e : blocks_) {
            if (!e.active) continue;
            // Insert the CIDR base IP (best-effort for bloom)
            size_t slash = e.cidr.find('/');
            std::string base_ip = (slash != std::string::npos)
                                  ? e.cidr.substr(0, slash) : e.cidr;
            bloom_filter_.insert(base_ip);
        }
    }

    mutable std::shared_mutex mu_;
    std::vector<IpBlockEntry> blocks_;
    BloomFilter bloom_filter_;
};

// ============================================================================
// SECTION 8: DNSBL (DNS-based Blocklist) Integration
// Queries well-known DNSBL services to check if an IP is listed.
// ============================================================================

struct DnsblProvider {
    std::string name;
    std::string zone;             // e.g. "zen.spamhaus.org"
    std::string lookup_suffix;    // appended to reversed IP
    bool enabled = true;
    int64_t cache_ttl_ms = 3600000; // 1 hour
};

class DnsblChecker {
public:
    explicit DnsblChecker(std::vector<DnsblProvider> providers = {})
        : providers_(providers.empty() ? _default_providers() : std::move(providers))
    {
        // Start background cache expiry thread
        cache_thread_ = std::thread([this] { _cache_expiry_loop(); });
    }

    ~DnsblChecker() {
        shutdown_ = true;
        if (cache_thread_.joinable()) cache_thread_.join();
    }

    // Check if an IP is listed on any DNSBL.  Returns (listed, provider_name, details).
    struct DnsblResult {
        bool listed = false;
        std::string provider;
        std::string return_code; // A record returned by DNSBL
        std::string details;
    };

    DnsblResult check(const std::string& ip, bool force_refresh = false) {
        // Check cache first (unless force_refresh)
        if (!force_refresh) {
            std::shared_lock lk(cache_mu_);
            auto it = cache_.find(ip);
            if (it != cache_.end()) {
                int64_t now = now_ms();
                if (now < it->second.expires_at) {
                    return it->second.result;
                }
            }
        }

        DnsblResult worst;
        for (auto& prov : providers_) {
            if (!prov.enabled) continue;
            auto res = _query_provider(prov, ip);
            if (res.listed) {
                worst = res; // return first hit, or worst
                break;
            }
        }

        // Cache result
        {
            std::unique_lock lk(cache_mu_);
            CacheEntry entry;
            entry.result     = worst;
            entry.expires_at = now_ms() + providers_.empty() ? 3600000 : providers_[0].cache_ttl_ms;
            cache_[ip] = entry;
        }
        return worst;
    }

    // Reload providers list
    void set_providers(const std::vector<DnsblProvider>& providers) {
        std::unique_lock lk(cache_mu_);
        providers_ = providers;
        cache_.clear(); // invalidate cache on provider change
    }

    std::vector<DnsblProvider> get_providers() {
        std::shared_lock lk(cache_mu_);
        return providers_;
    }

    // Clear DNSBL cache
    void clear_cache() {
        std::unique_lock lk(cache_mu_);
        cache_.clear();
    }

    // Stats
    json stats_json() {
        std::shared_lock lk(cache_mu_);
        return json::object({
            {"cache_size", cache_.size()},
            {"providers",  providers_.size()},
            {"total_checks", total_checks_.load()},
            {"total_listed", total_listed_.load()}
        });
    }

private:
    static std::vector<DnsblProvider> _default_providers() {
        return {
            {"spamhaus_zen", "zen.spamhaus.org", "", true, 3600000},
            {"barracuda",    "b.barracudacentral.org", "", true, 3600000},
            {"spamcop",      "bl.spamcop.net", "", true, 3600000},
            {"sorbs",        "dnsbl.sorbs.net", "", false, 3600000}, // off by default
        };
    }

    DnsblResult _query_provider(const DnsblProvider& prov, const std::string& ip) {
        DnsblResult res;
        res.provider = prov.name;
        total_checks_++;

        // Build reversed-IP query hostname
        std::string reversed = _reverse_ip(ip);
        if (reversed.empty()) return res;

        std::string query = reversed + "." + prov.zone;

        auto addrs = dns_resolve(query);
        if (addrs.empty()) return res; // NXDOMAIN = not listed

        // Listed - any A record response means listed
        res.listed      = true;
        res.return_code = addrs.front();
        res.details     = "Listed on " + prov.name + " with code " + res.return_code;
        total_listed_++;
        return res;
    }

    std::string _reverse_ip(const std::string& ip) {
        if (ip.find(':') == std::string::npos) {
            // IPv4
            uint8_t oct[4];
            if (!parse_ipv4(ip, oct)) return "";
            return std::to_string(oct[3]) + "." +
                   std::to_string(oct[2]) + "." +
                   std::to_string(oct[1]) + "." +
                   std::to_string(oct[0]);
        }
        // IPv6 (nibble format - lengthy but correct)
        uint16_t h[8];
        if (!parse_ipv6(ip, h)) return "";
        std::string out;
        for (int i = 7; i >= 0; --i) {
            for (int nibble = 3; nibble >= 0; --nibble) {
                out += std::string(1, "0123456789abcdef"[(h[i] >> (nibble * 4)) & 0xF]);
                out += ".";
            }
        }
        return out;
    }

    void _cache_expiry_loop() {
        while (!shutdown_) {
            std::this_thread::sleep_for(std::chrono::seconds(60));
            std::unique_lock lk(cache_mu_);
            int64_t now = now_ms();
            auto it = cache_.begin();
            while (it != cache_.end()) {
                if (now >= it->second.expires_at)
                    it = cache_.erase(it);
                else
                    ++it;
            }
        }
    }

    struct CacheEntry {
        DnsblResult result;
        int64_t     expires_at = 0;
    };

    std::vector<DnsblProvider> providers_;
    std::shared_mutex cache_mu_;
    std::unordered_map<std::string, CacheEntry> cache_;
    std::thread cache_thread_;
    std::atomic<bool> shutdown_{false};
    std::atomic<int64_t> total_checks_{0};
    std::atomic<int64_t> total_listed_{0};
};

// ============================================================================
// SECTION 9: Request Prioritization System
// Categorizes incoming requests and applies priority-aware scheduling.
// ============================================================================

enum class RequestPriority : uint8_t {
    CRITICAL  = 0,  // admin emergency, health checks
    HIGH      = 1,  // sync, keys/claim, send
    MEDIUM    = 2,  // room reads, profile, search, membership
    LOW       = 3,  // batch, admin reports, media downloads
    BACKGROUND = 4  // purge jobs, backfill, maintenance
};

struct PrioritizedRequest {
    int64_t          arrival_ms;
    RequestPriority  priority;
    std::string      description;
    std::string      endpoint;
    std::string      method;
    std::string      user_id;
    std::string      client_ip;
    std::function<void()> callback; // the actual work
    std::string      id;
};

struct PriorityQueueCmp {
    bool operator()(const PrioritizedRequest& a,
                    const PrioritizedRequest& b) const {
        if (a.priority != b.priority)
            return static_cast<uint8_t>(a.priority) > static_cast<uint8_t>(b.priority);
        return a.arrival_ms > b.arrival_ms; // older first
    }
};

class RequestPrioritizer {
public:
    struct Config {
        int64_t max_queue_size         = 10000;
        int64_t high_water_mark        = 8000;  // start shedding LOW/BACKGROUND
        int64_t critical_water_mark    = 9500;  // only CRITICAL/HIGH accepted
        int64_t worker_threads         = 4;
        bool    enabled                = true;
        int64_t queue_timeout_ms       = 30000; // max time in queue before reject
    };

    explicit RequestPrioritizer(const Config& cfg = {})
        : config_(cfg) {
        _start_workers();
    }

    ~RequestPrioritizer() {
        _stop_workers();
    }

    // Enqueue a request. Returns true if accepted, false if rejected.
    bool enqueue(RequestPriority priority,
                 const std::string& description,
                 std::function<void()> callback,
                 const std::string& endpoint = "",
                 const std::string& method   = "",
                 const std::string& user_id  = "",
                 const std::string& client_ip = "") {
        if (!config_.enabled) {
            // Passthrough mode: execute immediately
            callback();
            return true;
        }

        std::unique_lock lk(mu_);
        int64_t qsize = static_cast<int64_t>(queue_.size());

        // Watermark-based shedding
        if (qsize >= config_.critical_water_mark) {
            if (priority != RequestPriority::CRITICAL &&
                priority != RequestPriority::HIGH) {
                total_shed_++;
                return false;
            }
        } else if (qsize >= config_.high_water_mark) {
            if (priority == RequestPriority::LOW ||
                priority == RequestPriority::BACKGROUND) {
                total_shed_++;
                return false;
            }
        }

        if (qsize >= config_.max_queue_size) {
            total_shed_++;
            return false;
        }

        PrioritizedRequest req;
        req.arrival_ms  = now_ms();
        req.priority    = priority;
        req.description = description;
        req.endpoint    = endpoint;
        req.method      = method;
        req.user_id     = user_id;
        req.client_ip   = client_ip;
        req.callback    = std::move(callback);
        req.id          = generate_event_id();

        queue_.push(std::move(req));
        total_enqueued_++;
        lk.unlock();
        cv_.notify_one();
        return true;
    }

    // Map endpoint+method to priority.
    static RequestPriority classify(const std::string& endpoint,
                                     const std::string& method) {
        // Synchrotron sync endpoints get HIGH priority
        if (endpoint.find("/_matrix/client/r0/sync") != std::string::npos ||
            endpoint.find("/_matrix/client/v3/sync") != std::string::npos ||
            endpoint.find("/_synchrotron/") != std::string::npos) {
            return RequestPriority::HIGH;
        }
        // Keys endpoints
        if (endpoint.find("/_matrix/client/r0/keys/") != std::string::npos ||
            endpoint.find("/_matrix/client/v3/keys/") != std::string::npos) {
            return RequestPriority::HIGH;
        }
        // Send message
        if ((endpoint.find("/send/") != std::string::npos ||
             endpoint.find("/state/") != std::string::npos) &&
            method == "PUT") {
            return RequestPriority::HIGH;
        }
        // Room reads
        if (endpoint.find("/messages") != std::string::npos ||
            endpoint.find("/state")  != std::string::npos ||
            endpoint.find("/members") != std::string::npos ||
            endpoint.find("/joined_rooms") != std::string::npos) {
            return RequestPriority::MEDIUM;
        }
        // Profile / directory
        if (endpoint.find("/profile") != std::string::npos ||
            endpoint.find("/publicRooms") != std::string::npos ||
            endpoint.find("/search") != std::string::npos) {
            return RequestPriority::MEDIUM;
        }
        // Admin endpoints
        if (endpoint.find("/_synapse/admin") != std::string::npos ||
            endpoint.find("/_matrix/admin") != std::string::npos) {
            return (method == "DELETE" || method == "POST")
                       ? RequestPriority::CRITICAL
                       : RequestPriority::LOW;
        }
        // Health check
        if (endpoint == "/health" || endpoint == "/healthz" ||
            endpoint == "/_matrix/federation/v1/version") {
            return RequestPriority::CRITICAL;
        }
        // Media downloads
        if (endpoint.find("/_matrix/media/") != std::string::npos) {
            return (method == "GET") ? RequestPriority::LOW : RequestPriority::MEDIUM;
        }
        // Default
        return RequestPriority::MEDIUM;
    }

    struct Stats {
        int64_t total_enqueued  = 0;
        int64_t total_processed = 0;
        int64_t total_shed      = 0;
        int64_t queue_size      = 0;
        json    per_priority;
    };

    Stats stats() {
        std::lock_guard lk(mu_);
        Stats s;
        s.total_enqueued  = total_enqueued_;
        s.total_processed = total_processed_;
        s.total_shed      = total_shed_;
        s.queue_size      = static_cast<int64_t>(queue_.size());
        json pp;
        for (int i = 0; i <= static_cast<int>(RequestPriority::BACKGROUND); ++i) {
            auto p = static_cast<RequestPriority>(i);
            std::string name;
            switch (p) {
                case RequestPriority::CRITICAL:   name = "critical"; break;
                case RequestPriority::HIGH:       name = "high"; break;
                case RequestPriority::MEDIUM:     name = "medium"; break;
                case RequestPriority::LOW:        name = "low"; break;
                case RequestPriority::BACKGROUND: name = "background"; break;
            }
            pp[name] = {
                {"enqueued",  priority_enqueued_[i].load()},
                {"processed", priority_processed_[i].load()},
                {"shed",      priority_shed_[i].load()}
            };
        }
        s.per_priority = pp;
        return s;
    }

    void reconfigure(const Config& cfg) {
        std::lock_guard lk(mu_);
        config_ = cfg;
        _adjust_workers();
    }

    const Config& config() const { return config_; }

private:
    void _start_workers() {
        for (int64_t i = 0; i < config_.worker_threads; ++i)
            _add_worker();
    }

    void _add_worker() {
        workers_.emplace_back([this] {
            while (!shutdown_) {
                PrioritizedRequest req;
                {
                    std::unique_lock lk(mu_);
                    cv_.wait(lk, [this] {
                        return !queue_.empty() || shutdown_;
                    });
                    if (shutdown_ && queue_.empty()) return;
                    if (queue_.empty()) continue;

                    // Check timeout
                    int64_t now = now_ms();
                    while (!queue_.empty()) {
                        auto& top = const_cast<PrioritizedRequest&>(queue_.top());
                        if (now - top.arrival_ms > config_.queue_timeout_ms) {
                            // Timed out - shed it
                            queue_.pop();
                            total_shed_++;
                            priority_shed_[static_cast<uint8_t>(top.priority)]++;
                            total_timed_out_++;
                            continue;
                        }
                        break;
                    }
                    if (queue_.empty()) continue;

                    req = queue_.top();
                    queue_.pop();
                }

                // Execute the request
                try {
                    if (req.callback) req.callback();
                } catch (const std::exception& e) {
                    // Log but don't crash -- callback should handle its own errors
                }

                priority_processed_[static_cast<uint8_t>(req.priority)]++;
                total_processed_++;
            }
        });
    }

    void _adjust_workers() {
        int64_t target = config_.worker_threads;
        while (static_cast<int64_t>(workers_.size()) > target && !workers_.empty()) {
            // Cannot easily remove a running thread without complex shutdown
            // In practice, workers will exit on shutdown
            break;
        }
        while (static_cast<int64_t>(workers_.size()) < target) {
            _add_worker();
        }
    }

    void _stop_workers() {
        {
            std::lock_guard lk(mu_);
            shutdown_ = true;
        }
        cv_.notify_all();
        for (auto& t : workers_) {
            if (t.joinable()) t.join();
        }
        workers_.clear();
    }

    Config config_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::priority_queue<PrioritizedRequest,
                        std::vector<PrioritizedRequest>,
                        PriorityQueueCmp> queue_;
    std::vector<std::thread> workers_;
    std::atomic<bool> shutdown_{false};

    // Counters
    int64_t total_enqueued_  = 0;
    int64_t total_processed_ = 0;
    int64_t total_shed_      = 0;
    int64_t total_timed_out_ = 0;
    std::array<std::atomic<int64_t>, 5> priority_enqueued_{};
    std::array<std::atomic<int64_t>, 5> priority_processed_{};
    std::array<std::atomic<int64_t>, 5> priority_shed_{};
};

// ============================================================================
// SECTION 10: Rate Limit Event Reporter
// Captures structured events when rate limits are hit for observability.
// ============================================================================

struct RateLimitEvent {
    std::string event_id;
    int64_t timestamp;
    std::string scope;        // "ip", "user", "endpoint", "global"
    std::string identifier;
    std::string endpoint;
    std::string method;
    std::string limit_type;   // "token_bucket", "sliding_window", "concurrency"
    int64_t retry_after_ms;
    int64_t limit_value;
    std::string client_ip;
    std::string user_agent;
    std::string reason;
};

class RateLimitEventReporter {
public:
    struct Config {
        size_t  max_events_in_memory = 10000;
        bool    enabled              = true;
        bool    log_to_stdout        = false;
        std::function<void(const RateLimitEvent&)> external_sink; // optional callback
    };

    explicit RateLimitEventReporter(const Config& cfg = {}) : config_(cfg) {}

    void report(RateLimitEvent event) {
        if (!config_.enabled) return;

        event.event_id  = generate_event_id();
        event.timestamp = now_ms();

        {
            std::lock_guard lk(mu_);
            events_.push_back(event);
            while (events_.size() > config_.max_events_in_memory) {
                events_.pop_front();
            }
        }

        // Optional stdout logging
        if (config_.log_to_stdout) {
            std::cerr << "[RATELIMIT] " << event.scope << ":" << event.identifier
                      << " endpoint=" << event.endpoint
                      << " type=" << event.limit_type
                      << " retry_after_ms=" << event.retry_after_ms
                      << " ip=" << event.client_ip
                      << " reason=" << event.reason << "\n";
        }

        // External sink
        if (config_.external_sink) {
            config_.external_sink(event);
        }

        total_events_++;
        scope_counter_[event.scope]++;
        type_counter_[event.limit_type]++;
    }

    // Query recent events (for admin API)
    std::vector<RateLimitEvent> recent_events(size_t max_count = 100) {
        std::lock_guard lk(mu_);
        std::vector<RateLimitEvent> result;
        auto it = events_.rbegin();
        size_t n = 0;
        for (; it != events_.rend() && n < max_count; ++it, ++n)
            result.push_back(*it);
        return result;
    }

    // Serialize events to JSON
    json events_json(size_t max_count = 100) {
        auto evs = recent_events(max_count);
        json arr = json::array();
        for (auto& e : evs) {
            arr.push_back({
                {"event_id",       e.event_id},
                {"timestamp",      e.timestamp},
                {"scope",          e.scope},
                {"identifier",     e.identifier},
                {"endpoint",       e.endpoint},
                {"method",         e.method},
                {"limit_type",     e.limit_type},
                {"retry_after_ms", e.retry_after_ms},
                {"limit_value",    e.limit_value},
                {"client_ip",      e.client_ip},
                {"user_agent",     e.user_agent},
                {"reason",         e.reason}
            });
        }
        return arr;
    }

    // Aggregated statistics
    json stats_json() {
        std::lock_guard lk(mu_);
        json j;
        j["total_events"] = total_events_.load();
        json scopes;
        for (auto& [k, v] : scope_counter_)
            scopes[k] = v.load();
        j["by_scope"] = scopes;
        json types;
        for (auto& [k, v] : type_counter_)
            types[k] = v.load();
        j["by_type"] = types;
        j["events_in_memory"] = events_.size();
        j["config"] = {
            {"max_events_in_memory", config_.max_events_in_memory},
            {"enabled",              config_.enabled}
        };
        return j;
    }

    void clear_events() {
        std::lock_guard lk(mu_);
        events_.clear();
    }

    void reconfigure(const Config& cfg) {
        config_ = cfg;
    }

private:
    Config config_;
    mutable std::mutex mu_;
    std::deque<RateLimitEvent> events_;
    std::atomic<int64_t> total_events_{0};
    std::unordered_map<std::string, std::atomic<int64_t>> scope_counter_;
    std::unordered_map<std::string, std::atomic<int64_t>> type_counter_;
};

// ============================================================================
// SECTION 11: 429 Response Generator
// Builds proper HTTP 429 Too Many Requests responses with Retry-After
// header and Matrix-standard error body.
// ============================================================================

class RateLimitResponseGenerator {
public:
    // Generate the JSON body for a standard Matrix 429 error.
    static json generate_error_body(const std::string& reason,
                                     int64_t retry_after_ms,
                                     const std::string& errcode = "M_LIMIT_EXCEEDED") {
        return json::object({
            {"errcode",        errcode},
            {"error",          reason},
            {"retry_after_ms", retry_after_ms}
        });
    }

    // Generate a full set of rate-limit response headers
    struct RateLimitHeaders {
        std::string retry_after;              // "Retry-After: <seconds>"
        std::string x_ratelimit_limit;        // "X-RateLimit-Limit: <max>"
        std::string x_ratelimit_remaining;    // "X-RateLimit-Remaining: <remaining>"
        std::string x_ratelimit_reset;        // "X-RateLimit-Reset: <epoch seconds>"
        std::string x_ratelimit_retry_after;  // "X-RateLimit-Retry-After: <ms>"
    };

    static RateLimitHeaders generate_headers(const RateLimitResult& result) {
        RateLimitHeaders h;
        int64_t retry_sec = (result.retry_after_ms + 999) / 1000;
        h.retry_after = std::to_string(retry_sec > 0 ? retry_sec : 1);

        if (result.limit_max >= 0)
            h.x_ratelimit_limit = std::to_string(result.limit_max);
        else
            h.x_ratelimit_limit = "";

        if (result.limit_remaining >= 0)
            h.x_ratelimit_remaining = std::to_string(result.limit_remaining);

        if (result.limit_reset_ms > 0)
            h.x_ratelimit_reset = std::to_string(result.limit_reset_ms / 1000);

        h.x_ratelimit_retry_after = std::to_string(result.retry_after_ms);

        return h;
    }

    // Inject rate limit headers into a JSON response (for proxy response building)
    static json inject_headers_json(const RateLimitHeaders& headers,
                                     const json& body) {
        json resp;
        resp["status"]  = 429;
        resp["body"]    = body;
        resp["headers"] = json::object();
        if (!headers.retry_after.empty())
            resp["headers"]["Retry-After"] = headers.retry_after;
        if (!headers.x_ratelimit_limit.empty())
            resp["headers"]["X-RateLimit-Limit"] = headers.x_ratelimit_limit;
        if (!headers.x_ratelimit_remaining.empty())
            resp["headers"]["X-RateLimit-Remaining"] = headers.x_ratelimit_remaining;
        if (!headers.x_ratelimit_reset.empty())
            resp["headers"]["X-RateLimit-Reset"] = headers.x_ratelimit_reset;
        if (!headers.x_ratelimit_retry_after.empty())
            resp["headers"]["X-RateLimit-Retry-After"] = headers.x_ratelimit_retry_after;
        return resp;
    }

    // Convenience: generate full 429 response from a RateLimitResult.
    static json generate_429_response(const RateLimitResult& result) {
        auto body    = generate_error_body(result.reason, result.retry_after_ms);
        auto headers = generate_headers(result);
        return inject_headers_json(headers, body);
    }
};

// ============================================================================
// SECTION 12: Rate Limit Metrics Collector
// Tracks cumulative and per-key metrics for monitoring dashboards.
// ============================================================================

class RateLimitMetrics {
public:
    void record_allowed(const std::string& scope) {
        total_allowed_++;
        scope_allowed_[scope]++;
    }

    void record_rejected(const std::string& scope,
                         const std::string& limit_type) {
        total_rejected_++;
        scope_rejected_[scope]++;
        type_rejected_[limit_type]++;
    }

    void record_whitelist_pass(const std::string& scope) {
        whitelist_passes_++;
    }

    void record_override_pass(const std::string& user_id) {
        override_passes_++;
    }

    void record_connection_throttled(const std::string& ip) {
        total_connections_throttled_++;
    }

    void record_ip_blocked(const std::string& cidr, const std::string& ip) {
        total_ip_blocks_hit_++;
    }

    // Periodic snapshot for Prometheus-style metrics
    struct Snapshot {
        int64_t total_allowed;
        int64_t total_rejected;
        double  reject_ratio;
        int64_t whitelist_passes;
        int64_t override_passes;
        int64_t connections_throttled;
        int64_t ip_blocks_hit;
        std::unordered_map<std::string, int64_t> scope_allowed;
        std::unordered_map<std::string, int64_t> scope_rejected;
        std::unordered_map<std::string, int64_t> type_rejected;
        int64_t timestamp_ms;
    };

    Snapshot snapshot() {
        Snapshot s;
        s.timestamp_ms          = now_ms();
        s.total_allowed         = total_allowed_.load();
        s.total_rejected        = total_rejected_.load();
        int64_t total = s.total_allowed + s.total_rejected;
        s.reject_ratio          = total > 0 ? (double)s.total_rejected / total : 0.0;
        s.whitelist_passes      = whitelist_passes_.load();
        s.override_passes       = override_passes_.load();
        s.connections_throttled = total_connections_throttled_.load();
        s.ip_blocks_hit         = total_ip_blocks_hit_.load();

        {
            std::shared_lock lk(mu_);
            for (auto& [k, v] : scope_allowed_)  s.scope_allowed[k]  = v.load();
            for (auto& [k, v] : scope_rejected_) s.scope_rejected[k] = v.load();
            for (auto& [k, v] : type_rejected_)  s.type_rejected[k]  = v.load();
        }

        // Store snapshot history (keep last 100)
        {
            std::lock_guard lk(hist_mu_);
            history_.push_back(s);
            while (history_.size() > 100) history_.pop_front();
        }

        return s;
    }

    // JSON representation for admin API
    json snapshot_json() {
        auto s = snapshot();
        json j;
        j["timestamp_ms"]          = s.timestamp_ms;
        j["total_allowed"]         = s.total_allowed;
        j["total_rejected"]        = s.total_rejected;
        j["reject_ratio"]          = s.reject_ratio;
        j["whitelist_passes"]      = s.whitelist_passes;
        j["override_passes"]       = s.override_passes;
        j["connections_throttled"] = s.connections_throttled;
        j["ip_blocks_hit"]         = s.ip_blocks_hit;

        json sa;
        for (auto& [k, v] : s.scope_allowed) sa[k] = v;
        j["scope_allowed"]  = sa;
        json sr;
        for (auto& [k, v] : s.scope_rejected) sr[k] = v;
        j["scope_rejected"] = sr;
        json tr;
        for (auto& [k, v] : s.type_rejected) tr[k] = v;
        j["type_rejected"]  = tr;

        return j;
    }

    // Get history of snapshots
    std::vector<Snapshot> snapshot_history(size_t max = 100) {
        std::lock_guard lk(hist_mu_);
        std::vector<Snapshot> result;
        auto it = history_.rbegin();
        size_t n = 0;
        for (; it != history_.rend() && n < max; ++it, ++n)
            result.push_back(*it);
        std::reverse(result.begin(), result.end());
        return result;
    }

private:
    std::atomic<int64_t> total_allowed_{0};
    std::atomic<int64_t> total_rejected_{0};
    std::atomic<int64_t> whitelist_passes_{0};
    std::atomic<int64_t> override_passes_{0};
    std::atomic<int64_t> total_connections_throttled_{0};
    std::atomic<int64_t> total_ip_blocks_hit_{0};

    mutable std::shared_mutex mu_;
    std::unordered_map<std::string, std::atomic<int64_t>> scope_allowed_;
    std::unordered_map<std::string, std::atomic<int64_t>> scope_rejected_;
    std::unordered_map<std::string, std::atomic<int64_t>> type_rejected_;

    std::mutex hist_mu_;
    std::deque<Snapshot> history_;
};

// ============================================================================
// SECTION 13: Synchrotron-Specific Rate Limits
// Fine-grained limits for the sliding sync / synchrotron endpoint which
// is both the most critical and most resource-intensive endpoint.
// ============================================================================

struct SynchrotronRateLimitConfig {
    // Sustained token bucket rate
    double   tokens_per_second       = 2.0;    // syncs per second
    int64_t  burst_tokens            = 5;      // max burst
    // Per-room limits inside a sync response
    int64_t  max_rooms_per_sync      = 1000;
    int64_t  max_timeline_events     = 100;
    // Long-poll timeout bounds
    int64_t  min_timeout_ms          = 5000;
    int64_t  max_timeout_ms          = 120000;
    // Connection duration tracking
    int64_t  max_sync_connections_per_user = 5;
    int64_t  sync_connection_timeout_ms    = 300000; // 5 min
    // Adaptive backoff
    bool     enable_adaptive_backoff = true;
    double   backoff_multiplier      = 2.0;
    int64_t  max_backoff_ms          = 60000;
    // Staggered sync (startup flood prevention)
    bool     enable_stagger          = true;
    int64_t  stagger_window_ms       = 30000;
    // Metrics
    bool     enable_sync_metrics     = true;
};

class SynchrotronRateLimiter {
public:
    explicit SynchrotronRateLimiter(const SynchrotronRateLimitConfig& cfg = {})
        : config_(cfg)
        , token_bucket_(cfg.burst_tokens, cfg.tokens_per_second, "synchrotron")
        , window_(cfg.stagger_window_ms, cfg.burst_tokens, "synchrotron_stagger")
        , concurrency_(cfg.max_sync_connections_per_user, "synchrotron_concur") {}

    // Check a sync request. Returns result with specific synchrotron info.
    RateLimitResult check_sync(const std::string& user_id,
                                const std::string& client_ip,
                                int64_t requested_timeout_ms,
                                int64_t room_count_hint = 0) {
        RateLimitResult result;

        // 1. Enforce timeout bounds
        if (requested_timeout_ms < config_.min_timeout_ms) {
            result.allowed        = false;
            result.reason         = "Sync timeout below minimum";
            result.retry_after_ms = 0; // can retry immediately with valid timeout
            result.limit_type     = "synchrotron_timeout";
            return result;
        }
        if (requested_timeout_ms > config_.max_timeout_ms) {
            // Clamp, don't reject — but note it
            requested_timeout_ms = config_.max_timeout_ms;
        }

        // 2. Check concurrent sync connections per user
        if (config_.max_sync_connections_per_user > 0) {
            int64_t handle = concurrency_.try_acquire();
            if (handle < 0) {
                result.allowed        = false;
                result.reason         = "Too many concurrent sync connections";
                result.retry_after_ms = 5000;
                result.limit_max      = config_.max_sync_connections_per_user;
                result.limit_type     = "synchrotron_concurrency";
                return result;
            }
            // Store handle for release on sync completion
            _last_conc_handle = handle;
        }

        // 3. Token bucket check
        if (!token_bucket_.try_consume(1)) {
            result.allowed        = false;
            result.reason         = "Sync rate limit exceeded";
            result.retry_after_ms = token_bucket_.retry_after_ms();
            result.limit_max      = token_bucket_.stats().max_tokens;
            result.limit_type     = "synchrotron_token";
            if (_last_conc_handle >= 0) concurrency_.release(_last_conc_handle);
            return result;
        }

        // 4. Stagger window (startup flood prevention)
        if (config_.enable_stagger) {
            if (!window_.try_accept()) {
                result.allowed        = false;
                result.reason         = "Sync stagger - too many syncs in window";
                result.retry_after_ms = window_.retry_after_ms();
                result.limit_max      = config_.burst_tokens;
                result.limit_type     = "synchrotron_stagger";
                if (_last_conc_handle >= 0) concurrency_.release(_last_conc_handle);
                return result;
            }
        }

        // 5. Room count enforcement
        if (room_count_hint > config_.max_rooms_per_sync) {
            result.allowed       = true; // Still allow, but should be noted
            result.reason        = "Room count hint exceeds max_rooms_per_sync";
        }

        result.allowed       = true;
        result.limit_type    = "synchrotron";
        result.limit_max     = config_.burst_tokens;
        result.limit_remaining = static_cast<int64_t>(token_bucket_.available());

        // Track active sync
        {
            std::lock_guard lk(sync_mu_);
            active_syncs_[user_id]++;
            sync_start_times_[user_id] = now_ms();
        }

        return result;
    }

    // Call when sync completes (connection closed or response sent).
    void sync_completed(const std::string& user_id) {
        if (_last_conc_handle >= 0) {
            concurrency_.release(_last_conc_handle);
            _last_conc_handle = -1;
        }
        std::lock_guard lk(sync_mu_);
        auto it = active_syncs_.find(user_id);
        if (it != active_syncs_.end() && it->second > 0) {
            it->second--;
            if (it->second == 0) {
                sync_start_times_.erase(user_id);
            }
        }
    }

    // Adaptive backoff: compute recommended sync timeout based on server load.
    int64_t adaptive_timeout(int64_t base_timeout_ms) {
        if (!config_.enable_adaptive_backoff) return base_timeout_ms;

        double load_factor = _compute_load_factor();
        double delay = base_timeout_ms;
        if (load_factor > 0.7) {
            delay *= config_.backoff_multiplier;
        }
        if (load_factor > 0.9) {
            delay *= config_.backoff_multiplier;
        }
        return std::min(static_cast<int64_t>(delay), config_.max_backoff_ms);
    }

    // Reconfigure at runtime
    void reconfigure(const SynchrotronRateLimitConfig& cfg) {
        config_ = cfg;
        token_bucket_.reconfigure(cfg.burst_tokens, cfg.tokens_per_second);
        window_.reconfigure(cfg.stagger_window_ms, cfg.burst_tokens);
        concurrency_.reconfigure(cfg.max_sync_connections_per_user);
    }

    const SynchrotronRateLimitConfig& config() const { return config_; }

    json stats_json() {
        json j;
        j["token_bucket"] = json::object({
            {"consumed",      token_bucket_.stats().total_consumed},
            {"rejected",      token_bucket_.stats().total_rejected},
            {"available",     token_bucket_.stats().tokens_available},
            {"max",           token_bucket_.stats().max_tokens}
        });
        j["stagger_window"] = json::object({
            {"accepted",      window_.stats().total_accepted},
            {"rejected",      window_.stats().total_rejected},
            {"current_count", window_.stats().current_count},
            {"window_ms",     window_.stats().window_ms},
            {"max_events",    window_.stats().max_events}
        });
        j["concurrency"] = json::object({
            {"acquired",      concurrency_.stats().total_acquired},
            {"rejected",      concurrency_.stats().total_rejected},
            {"current",       concurrency_.stats().current_requests},
            {"max",           concurrency_.stats().max_concurrent}
        });

        std::lock_guard lk(sync_mu_);
        j["active_syncs"] = active_syncs_.size();
        json as = json::array();
        for (auto& [uid, cnt] : active_syncs_) {
            if (cnt > 0) {
                as.push_back({
                    {"user_id", uid},
                    {"count",   cnt},
                    {"started_ms", sync_start_times_[uid]}
                });
            }
        }
        j["active_sync_details"] = as;
        j["config"] = {
            {"tokens_per_second",             config_.tokens_per_second},
            {"burst_tokens",                  config_.burst_tokens},
            {"max_rooms_per_sync",            config_.max_rooms_per_sync},
            {"max_sync_connections_per_user", config_.max_sync_connections_per_user},
            {"enable_adaptive_backoff",       config_.enable_adaptive_backoff},
            {"enable_stagger",                config_.enable_stagger}
        };

        return j;
    }

private:
    double _compute_load_factor() {
        auto cs = concurrency_.stats();
        if (cs.max_concurrent == 0) return 0.0;
        return static_cast<double>(cs.current_requests) / cs.max_concurrent;
    }

    SynchrotronRateLimitConfig config_;
    TokenBucket               token_bucket_;
    SlidingWindow             window_;
    ConcurrentRequestLimiter  concurrency_;
    int64_t _last_conc_handle = -1;

    std::mutex sync_mu_;
    std::unordered_map<std::string, int64_t> active_syncs_;
    std::unordered_map<std::string, int64_t> sync_start_times_;
};

// ============================================================================
// SECTION 14: Global Rate Limiting Configuration Manager
// Holds and validates the entire rate limit configuration tree.
// ============================================================================

struct GlobalRateLimitConfig {
    // Default limits applied when no specific rule matches
    struct Defaults {
        int64_t per_second          = 100;
        int64_t burst_count         = 200;
        int64_t window_ms           = 1000;
        int64_t window_max          = 50;
        int64_t max_concurrent      = 100;
    } defaults;

    // IP-level limits (stricter than user-level)
    struct IpLimits {
        int64_t per_second          = 20;
        int64_t burst_count         = 40;
        int64_t window_ms           = 1000;
        int64_t window_max          = 10;
        int64_t max_concurrent      = 20;
    } ip_limits;

    // User-level limits
    struct UserLimits {
        int64_t per_second          = 50;
        int64_t burst_count         = 100;
        int64_t window_ms           = 1000;
        int64_t window_max          = 25;
        int64_t max_concurrent      = 50;
    } user_limits;

    // Global system-wide cap
    struct GlobalCap {
        int64_t per_second          = 5000;
        int64_t burst_count         = 10000;
        int64_t window_ms           = 1000;
        int64_t window_max          = 2000;
        int64_t max_concurrent      = 5000;
    } global_cap;

    // Per-endpoint overrides
    std::vector<RateLimitEntry> endpoint_rules;

    // User overrides (exemptions / custom limits)
    std::vector<RateLimitOverride> user_overrides;

    // Whitelist
    std::vector<RateLimitWhitelistEntry> whitelist;

    // Connection throttling
    ConnectionThrottler::Config connection_throttle;

    // DNSBL
    std::vector<DnsblProvider> dnsbl_providers;

    // Synchrotron
    SynchrotronRateLimitConfig synchrotron;

    // Priority
    RequestPrioritizer::Config prioritizer;

    // Reporter
    RateLimitEventReporter::Config reporter;

    // Feature toggles
    bool enable_ip_blocking       = true;
    bool enable_dnsbl             = false;
    bool enable_connection_throttle = true;
    bool enable_request_priority  = true;

    // Load from JSON config
    static GlobalRateLimitConfig from_json(const json& j) {
        GlobalRateLimitConfig cfg;

        if (j.contains("defaults")) {
            auto& d = j["defaults"];
            cfg.defaults.per_second     = d.value("per_second",      cfg.defaults.per_second);
            cfg.defaults.burst_count    = d.value("burst_count",    cfg.defaults.burst_count);
            cfg.defaults.window_ms      = d.value("window_ms",      cfg.defaults.window_ms);
            cfg.defaults.window_max     = d.value("window_max",     cfg.defaults.window_max);
            cfg.defaults.max_concurrent = d.value("max_concurrent", cfg.defaults.max_concurrent);
        }
        if (j.contains("ip_limits")) {
            auto& il = j["ip_limits"];
            cfg.ip_limits.per_second     = il.value("per_second",     cfg.ip_limits.per_second);
            cfg.ip_limits.burst_count    = il.value("burst_count",   cfg.ip_limits.burst_count);
            cfg.ip_limits.window_ms      = il.value("window_ms",     cfg.ip_limits.window_ms);
            cfg.ip_limits.window_max     = il.value("window_max",    cfg.ip_limits.window_max);
            cfg.ip_limits.max_concurrent = il.value("max_concurrent",cfg.ip_limits.max_concurrent);
        }
        if (j.contains("user_limits")) {
            auto& ul = j["user_limits"];
            cfg.user_limits.per_second     = ul.value("per_second",     cfg.user_limits.per_second);
            cfg.user_limits.burst_count    = ul.value("burst_count",   cfg.user_limits.burst_count);
            cfg.user_limits.window_ms      = ul.value("window_ms",     cfg.user_limits.window_ms);
            cfg.user_limits.window_max     = ul.value("window_max",    cfg.user_limits.window_max);
            cfg.user_limits.max_concurrent = ul.value("max_concurrent",cfg.user_limits.max_concurrent);
        }
        if (j.contains("global_cap")) {
            auto& gc = j["global_cap"];
            cfg.global_cap.per_second     = gc.value("per_second",     cfg.global_cap.per_second);
            cfg.global_cap.burst_count    = gc.value("burst_count",   cfg.global_cap.burst_count);
            cfg.global_cap.window_ms      = gc.value("window_ms",     cfg.global_cap.window_ms);
            cfg.global_cap.window_max     = gc.value("window_max",    cfg.global_cap.window_max);
            cfg.global_cap.max_concurrent = gc.value("max_concurrent",cfg.global_cap.max_concurrent);
        }

        if (j.contains("endpoint_rules")) {
            for (auto& rule : j["endpoint_rules"]) {
                RateLimitEntry e;
                e.name           = rule.value("name", "");
                e.match_endpoint = rule.value("match_endpoint", ".*");
                e.match_method   = rule.value("match_method", "*");
                e.per_second     = rule.value("per_second", 0LL);
                e.burst_count    = rule.value("burst_count", 0LL);
                e.window_ms      = rule.value("window_ms", 0LL);
                e.window_max     = rule.value("window_max", 0LL);
                e.max_concurrent = rule.value("max_concurrent", 0LL);
                e.enabled        = rule.value("enabled", true);
                e.is_global      = rule.value("is_global", false);
                e.priority       = rule.value("priority", 0LL);
                if (!e.name.empty()) cfg.endpoint_rules.push_back(std::move(e));
            }
        }

        if (j.contains("user_overrides")) {
            for (auto& ov : j["user_overrides"]) {
                RateLimitOverride o;
                o.user_id        = ov.value("user_id", "");
                o.per_second     = ov.value("per_second", 0LL);
                o.burst_count    = ov.value("burst_count", 0LL);
                o.max_concurrent = ov.value("max_concurrent", 0LL);
                o.reason         = ov.value("reason", "");
                o.expires_at     = ov.value("expires_at", 0LL);
                o.active         = ov.value("active", true);
                if (!o.user_id.empty()) cfg.user_overrides.push_back(std::move(o));
            }
        }

        if (j.contains("whitelist")) {
            for (auto& wl : j["whitelist"]) {
                RateLimitWhitelistEntry w;
                w.ip_or_cidr = wl.value("ip_or_cidr", "");
                w.note       = wl.value("note", "");
                w.active     = wl.value("active", true);
                if (!w.ip_or_cidr.empty()) cfg.whitelist.push_back(std::move(w));
            }
        }

        if (j.contains("connection_throttle")) {
            auto& ct = j["connection_throttle"];
            cfg.connection_throttle.max_connections_per_window =
                ct.value("max_connections_per_window", cfg.connection_throttle.max_connections_per_window);
            cfg.connection_throttle.connection_window_ms =
                ct.value("connection_window_ms", cfg.connection_throttle.connection_window_ms);
            cfg.connection_throttle.throttle_duration_ms =
                ct.value("throttle_duration_ms", cfg.connection_throttle.throttle_duration_ms);
            cfg.connection_throttle.min_connection_interval_ms =
                ct.value("min_connection_interval_ms", cfg.connection_throttle.min_connection_interval_ms);
            cfg.connection_throttle.enabled =
                ct.value("enabled", cfg.connection_throttle.enabled);
        }

        // Feature toggles
        cfg.enable_ip_blocking         = j.value("enable_ip_blocking",         cfg.enable_ip_blocking);
        cfg.enable_dnsbl               = j.value("enable_dnsbl",               cfg.enable_dnsbl);
        cfg.enable_connection_throttle = j.value("enable_connection_throttle", cfg.enable_connection_throttle);
        cfg.enable_request_priority    = j.value("enable_request_priority",    cfg.enable_request_priority);

        return cfg;
    }

    // Serialize to JSON
    json to_json() const {
        return json::object({
            {"defaults", {
                {"per_second",     defaults.per_second},
                {"burst_count",    defaults.burst_count},
                {"window_ms",      defaults.window_ms},
                {"window_max",     defaults.window_max},
                {"max_concurrent", defaults.max_concurrent}
            }},
            {"ip_limits", {
                {"per_second",     ip_limits.per_second},
                {"burst_count",    ip_limits.burst_count},
                {"window_ms",      ip_limits.window_ms},
                {"window_max",     ip_limits.window_max},
                {"max_concurrent", ip_limits.max_concurrent}
            }},
            {"user_limits", {
                {"per_second",     user_limits.per_second},
                {"burst_count",    user_limits.burst_count},
                {"window_ms",      user_limits.window_ms},
                {"window_max",     user_limits.window_max},
                {"max_concurrent", user_limits.max_concurrent}
            }},
            {"global_cap", {
                {"per_second",     global_cap.per_second},
                {"burst_count",    global_cap.burst_count},
                {"window_ms",      global_cap.window_ms},
                {"window_max",     global_cap.window_max},
                {"max_concurrent", global_cap.max_concurrent}
            }},
            {"enable_ip_blocking",         enable_ip_blocking},
            {"enable_dnsbl",               enable_dnsbl},
            {"enable_connection_throttle", enable_connection_throttle},
            {"enable_request_priority",    enable_request_priority}
        });
    }
};

// ============================================================================
// SECTION 15: DoS Protection Manager - Main Orchestrator
// Coordinates all DoS protection subsystems.  This is the primary entry point
// that the server uses to gate every incoming request.
// ============================================================================

class DoSProtectionManager {
public:
    DoSProtectionManager()
        : global_limiter_(config_.global_cap.burst_count,
                          config_.global_cap.per_second,
                          config_.global_cap.window_ms,
                          config_.global_cap.window_max,
                          config_.global_cap.max_concurrent,
                          "global")
        , throttler_(config_.connection_throttle)
        , dnsbl_(config_.dnsbl_providers)
        , prioritizer_(config_.prioritizer)
        , reporter_(config_.reporter)
        , synchrotron_(config_.synchrotron)
    {
        _start_maintenance();
    }

    ~DoSProtectionManager() {
        shutdown_ = true;
        if (maintenance_thread_.joinable())
            maintenance_thread_.join();
    }

    // ========================================================================
    // Primary Request Gate
    // Called for every incoming HTTP request BEFORE routing.
    // Returns a RateLimitResult. If !allowed, the caller must return 429.
    // ========================================================================
    RateLimitResult check_request(
        const std::string& user_id,
        const std::string& client_ip,
        const std::string& endpoint,
        const std::string& method,
        const std::string& user_agent = "")
    {
        // ------------------------------------------------------------------
        // 0. Connection throttling check (coarse gate)
        // ------------------------------------------------------------------
        if (config_.enable_connection_throttle) {
            int64_t delay = 0;
            if (!throttler_.check_connection(client_ip, delay)) {
                RateLimitResult r;
                r.allowed        = false;
                r.reason         = "Connection throttled";
                r.retry_after_ms = delay;
                r.limit_type     = "connection_throttle";
                metrics_.record_rejected("connection", "throttle");
                reporter_.report(_make_event("connection", client_ip, endpoint,
                                              method, "connection_throttle",
                                              delay, 0, client_ip, user_agent,
                                              "Connection throttled"));
                return r;
            }
        }

        // ------------------------------------------------------------------
        // 1. IP block check
        // ------------------------------------------------------------------
        if (config_.enable_ip_blocking) {
            auto [blocked, reason] = ip_blocker_.is_blocked(client_ip);
            if (blocked) {
                RateLimitResult r;
                r.allowed        = false;
                r.reason         = "IP blocked: " + reason;
                r.retry_after_ms = 86400000; // 24h
                r.limit_type     = "ip_block";
                metrics_.record_ip_blocked(reason, client_ip);
                metrics_.record_rejected("ip_block", "block");
                reporter_.report(_make_event("ip_block", client_ip, endpoint, method,
                                              "ip_block", r.retry_after_ms, 0,
                                              client_ip, user_agent, reason));
                return r;
            }
        }

        // ------------------------------------------------------------------
        // 2. DNSBL check (if enabled)
        // ------------------------------------------------------------------
        if (config_.enable_dnsbl) {
            auto dnsbl_res = dnsbl_.check(client_ip);
            if (dnsbl_res.listed) {
                RateLimitResult r;
                r.allowed        = false;
                r.reason         = "IP listed on DNSBL: " + dnsbl_res.provider;
                r.retry_after_ms = 3600000; // 1h
                r.limit_type     = "dnsbl";
                metrics_.record_rejected("dnsbl", "dnsbl");
                reporter_.report(_make_event("dnsbl", client_ip, endpoint, method,
                                              "dnsbl", r.retry_after_ms, 0,
                                              client_ip, user_agent,
                                              dnsbl_res.details));
                return r;
            }
        }

        // ------------------------------------------------------------------
        // 3. Whitelist check
        // ------------------------------------------------------------------
        if (_is_whitelisted(client_ip) || (!user_id.empty() && _is_whitelisted(user_id))) {
            RateLimitResult r;
            r.allowed = true;
            r.limit_type = "whitelist";
            metrics_.record_whitelist_pass("ip_or_user");
            return r;
        }

        // ------------------------------------------------------------------
        // 4. User override check (exemptions or custom limits)
        // ------------------------------------------------------------------
        auto override = _get_user_override(user_id);
        if (override.has_value()) {
            if (override->per_second == 0 && override->burst_count == 0 &&
                override->max_concurrent == 0) {
                // Fully exempt
                RateLimitResult r;
                r.allowed = true;
                r.limit_type = "override_exempt";
                metrics_.record_override_pass(user_id);
                return r;
            }
            // Custom limits - apply these instead
            RateLimitResult r = _check_custom_limits(user_id, client_ip, endpoint,
                                                      method, *override);
            if (!r.allowed) {
                reporter_.report(_make_event("user", user_id, endpoint, method,
                                              r.limit_type, r.retry_after_ms,
                                              r.limit_max, client_ip, user_agent,
                                              r.reason));
            }
            return r;
        }

        // ------------------------------------------------------------------
        // 5. Global system cap
        // ------------------------------------------------------------------
        RateLimitResult global_res = global_limiter_.check(false);
        if (!global_res.allowed) {
            metrics_.record_rejected("global", global_res.limit_type);
            reporter_.report(_make_event("global", "", endpoint, method,
                                          global_res.limit_type,
                                          global_res.retry_after_ms,
                                          global_res.limit_max,
                                          client_ip, user_agent, global_res.reason));
            return global_res;
        }

        // ------------------------------------------------------------------
        // 6. IP-level rate limiting
        // ------------------------------------------------------------------
        RateLimitResult ip_res = _check_ip_rate_limit(client_ip, endpoint, method);
        if (!ip_res.allowed) {
            metrics_.record_rejected("ip", ip_res.limit_type);
            reporter_.report(_make_event("ip", client_ip, endpoint, method,
                                          ip_res.limit_type,
                                          ip_res.retry_after_ms,
                                          ip_res.limit_max,
                                          client_ip, user_agent, ip_res.reason));
            return ip_res;
        }

        // ------------------------------------------------------------------
        // 7. User-level rate limiting
        // ------------------------------------------------------------------
        if (!user_id.empty()) {
            RateLimitResult user_res = _check_user_rate_limit(user_id, endpoint, method);
            if (!user_res.allowed) {
                metrics_.record_rejected("user", user_res.limit_type);
                reporter_.report(_make_event("user", user_id, endpoint, method,
                                              user_res.limit_type,
                                              user_res.retry_after_ms,
                                              user_res.limit_max,
                                              client_ip, user_agent, user_res.reason));
                return user_res;
            }
        }

        // ------------------------------------------------------------------
        // 8. Per-endpoint rate limiting (most specific rule wins)
        // ------------------------------------------------------------------
        RateLimitResult ep_res = _check_endpoint_rate_limit(endpoint, method, client_ip);
        if (!ep_res.allowed) {
            metrics_.record_rejected("endpoint", ep_res.limit_type);
            reporter_.report(_make_event("endpoint", endpoint, endpoint, method,
                                          ep_res.limit_type,
                                          ep_res.retry_after_ms,
                                          ep_res.limit_max,
                                          client_ip, user_agent, ep_res.reason));
            return ep_res;
        }

        // ------------------------------------------------------------------
        // Success
        // ------------------------------------------------------------------
        metrics_.record_allowed("request");
        return ep_res; // carries limit_remaining etc from endpoint check
    }

    // ========================================================================
    // Synchrotron-Specific Check
    // ========================================================================
    RateLimitResult check_synchrotron(
        const std::string& user_id,
        const std::string& client_ip,
        int64_t requested_timeout_ms,
        int64_t room_count_hint = 0)
    {
        // First run normal checks
        RateLimitResult base = check_request(user_id, client_ip,
                                              "/_synchrotron/sync", "GET");
        if (!base.allowed) return base;

        // Then synchrotron-specific checks
        RateLimitResult sync_res = synchrotron_.check_sync(
            user_id, client_ip, requested_timeout_ms, room_count_hint);

        if (!sync_res.allowed) {
            metrics_.record_rejected("synchrotron", sync_res.limit_type);
            reporter_.report(_make_event("synchrotron", user_id,
                                          "/_synchrotron/sync", "GET",
                                          sync_res.limit_type,
                                          sync_res.retry_after_ms,
                                          sync_res.limit_max,
                                          client_ip, "", sync_res.reason));
        } else {
            metrics_.record_allowed("synchrotron");
        }

        return sync_res;
    }

    // Release synchrotron connection
    void synchrotron_completed(const std::string& user_id) {
        synchrotron_.sync_completed(user_id);
    }

    // ========================================================================
    // Request Prioritization Passthrough
    // ========================================================================
    bool enqueue_prioritized(
        const std::string& endpoint,
        const std::string& method,
        const std::string& user_id,
        const std::string& client_ip,
        std::function<void()> callback,
        const std::string& description = "")
    {
        auto priority = RequestPrioritizer::classify(endpoint, method);
        return prioritizer_.enqueue(priority, description,
                                     std::move(callback),
                                     endpoint, method, user_id, client_ip);
    }

    // ========================================================================
    // Admin API: Rate Limit Configuration
    // ========================================================================

    // Get full configuration
    json get_config() { return config_.to_json(); }

    // Update configuration at runtime
    void update_config(const json& j) {
        std::unique_lock lk(config_mu_);
        config_ = GlobalRateLimitConfig::from_json(j);
        _apply_config();
    }

    // Get specific endpoint rules
    json get_endpoint_rules() {
        std::shared_lock lk(config_mu_);
        json arr = json::array();
        for (auto& r : config_.endpoint_rules) {
            arr.push_back({
                {"name",           r.name},
                {"match_endpoint", r.match_endpoint},
                {"match_method",   r.match_method},
                {"per_second",     r.per_second},
                {"burst_count",    r.burst_count},
                {"window_ms",      r.window_ms},
                {"window_max",     r.window_max},
                {"max_concurrent", r.max_concurrent},
                {"enabled",        r.enabled},
                {"is_global",      r.is_global},
                {"priority",       r.priority}
            });
        }
        return arr;
    }

    // Add endpoint rule
    void add_endpoint_rule(const RateLimitEntry& rule) {
        std::unique_lock lk(config_mu_);
        config_.endpoint_rules.push_back(rule);
        _rebuild_endpoint_matchers();
    }

    // Remove endpoint rule
    bool remove_endpoint_rule(const std::string& name) {
        std::unique_lock lk(config_mu_);
        auto it = std::find_if(config_.endpoint_rules.begin(),
                                config_.endpoint_rules.end(),
            [&](const RateLimitEntry& e) { return e.name == name; });
        if (it != config_.endpoint_rules.end()) {
            config_.endpoint_rules.erase(it);
            _rebuild_endpoint_matchers();
            return true;
        }
        return false;
    }

    // ========================================================================
    // Admin API: Rate Limit Overrides
    // ========================================================================

    json get_overrides() {
        std::shared_lock lk(config_mu_);
        json arr = json::array();
        for (auto& o : config_.user_overrides) {
            arr.push_back({
                {"user_id",        o.user_id},
                {"per_second",     o.per_second},
                {"burst_count",    o.burst_count},
                {"max_concurrent", o.max_concurrent},
                {"reason",         o.reason},
                {"created_at",     o.created_at},
                {"expires_at",     o.expires_at},
                {"active",         o.active}
            });
        }
        return arr;
    }

    void add_override(const RateLimitOverride& ov) {
        std::unique_lock lk(config_mu_);
        // Remove existing override for same user
        config_.user_overrides.erase(
            std::remove_if(config_.user_overrides.begin(),
                           config_.user_overrides.end(),
                           [&](const RateLimitOverride& o) {
                               return o.user_id == ov.user_id;
                           }),
            config_.user_overrides.end());
        RateLimitOverride o = ov;
        o.created_at = now_ms();
        config_.user_overrides.push_back(std::move(o));
        _rebuild_override_map();
    }

    bool remove_override(const std::string& user_id) {
        std::unique_lock lk(config_mu_);
        auto it = std::find_if(config_.user_overrides.begin(),
                                config_.user_overrides.end(),
            [&](const RateLimitOverride& o) { return o.user_id == user_id; });
        if (it != config_.user_overrides.end()) {
            it->active = false;
            _rebuild_override_map();
            return true;
        }
        return false;
    }

    // ========================================================================
    // Admin API: IP Whitelist
    // ========================================================================

    json get_whitelist() {
        std::shared_lock lk(config_mu_);
        json arr = json::array();
        for (auto& w : config_.whitelist) {
            arr.push_back({
                {"ip_or_cidr", w.ip_or_cidr},
                {"note",       w.note},
                {"added_at",   w.added_at},
                {"active",     w.active}
            });
        }
        return arr;
    }

    void add_whitelist(const std::string& ip_or_cidr, const std::string& note = "") {
        std::unique_lock lk(config_mu_);
        RateLimitWhitelistEntry w;
        w.ip_or_cidr = ip_or_cidr;
        w.note       = note;
        w.added_at   = now_ms();
        w.active     = true;
        config_.whitelist.push_back(std::move(w));
        _rebuild_whitelist_cache();
    }

    bool remove_whitelist(const std::string& ip_or_cidr) {
        std::unique_lock lk(config_mu_);
        auto it = std::find_if(config_.whitelist.begin(),
                                config_.whitelist.end(),
            [&](const RateLimitWhitelistEntry& w) {
                return w.ip_or_cidr == ip_or_cidr;
            });
        if (it != config_.whitelist.end()) {
            it->active = false;
            _rebuild_whitelist_cache();
            return true;
        }
        return false;
    }

    // ========================================================================
    // Admin API: IP Blocking
    // ========================================================================

    std::string block_ip(const std::string& cidr,
                         const std::string& reason = "",
                         const std::string& blocked_by = "admin",
                         int64_t expires_at = 0) {
        return ip_blocker_.add_block(cidr, reason, blocked_by, expires_at);
    }

    bool unblock_ip(const std::string& cidr_or_id) {
        return ip_blocker_.remove_block(cidr_or_id);
    }

    bool delete_ip_block(const std::string& cidr_or_id) {
        return ip_blocker_.delete_block(cidr_or_id);
    }

    json get_ip_blocks() { return ip_blocker_.to_json(); }

    json get_ip_block_stats() {
        auto st = ip_blocker_.stats();
        return json::object({
            {"total_blocks",  st.total_blocks},
            {"active_blocks", st.active_blocks},
            {"total_hits",    st.total_hits}
        });
    }

    // ========================================================================
    // Admin API: DNSBL
    // ========================================================================

    json get_dnsbl_status() { return dnsbl_.stats_json(); }

    void dnsbl_clear_cache() { dnsbl_.clear_cache(); }

    // ========================================================================
    // Admin API: Rate Limit Events
    // ========================================================================

    json get_recent_events(size_t max = 100) {
        return reporter_.events_json(max);
    }

    json get_event_stats() { return reporter_.stats_json(); }

    void clear_events() { reporter_.clear_events(); }

    // ========================================================================
    // Admin API: Metrics
    // ========================================================================

    json get_metrics() { return metrics_.snapshot_json(); }

    json get_metrics_history(size_t max = 100) {
        auto history = metrics_.snapshot_history(max);
        json arr = json::array();
        for (auto& h : history) {
            arr.push_back({
                {"timestamp_ms",          h.timestamp_ms},
                {"total_allowed",         h.total_allowed},
                {"total_rejected",        h.total_rejected},
                {"reject_ratio",          h.reject_ratio},
                {"whitelist_passes",      h.whitelist_passes},
                {"override_passes",       h.override_passes},
                {"connections_throttled", h.connections_throttled},
                {"ip_blocks_hit",         h.ip_blocks_hit}
            });
        }
        return arr;
    }

    // ========================================================================
    // Admin API: Connection Throttling
    // ========================================================================

    json get_connection_throttle_stats() {
        return throttler_.detailed_stats_json();
    }

    void reset_connection_throttle(const std::string& ip = "") {
        if (ip.empty()) {
            // Reset all via reconfigure
            auto cfg = throttler_.config();
            throttler_.reconfigure(cfg);
        } else {
            throttler_.remove_ip(ip);
        }
    }

    // ========================================================================
    // Admin API: Synchrotron Stats
    // ========================================================================

    json get_synchrotron_stats() { return synchrotron_.stats_json(); }

    // ========================================================================
    // Admin API: Prioritizer Stats
    // ========================================================================

    json get_prioritizer_stats() {
        auto st = prioritizer_.stats();
        json j;
        j["total_enqueued"]   = st.total_enqueued;
        j["total_processed"]  = st.total_processed;
        j["total_shed"]       = st.total_shed;
        j["queue_size"]       = st.queue_size;
        j["per_priority"]     = st.per_priority;
        return j;
    }

    // ========================================================================
    // Admin API: Comprehensive System Status
    // ========================================================================

    json get_system_status() {
        json j;
        j["config"]                    = config_.to_json();
        j["metrics"]                   = metrics_.snapshot_json();
        j["ip_blocks"]                 = get_ip_block_stats();
        j["connection_throttle"]       = get_connection_throttle_stats();
        j["dnsbl"]                     = dnsbl_.stats_json();
        j["prioritizer"]               = get_prioritizer_stats();
        j["synchrotron"]               = synchrotron_.stats_json();
        j["event_reporter"]            = reporter_.stats_json();
        j["global_limiter"]            = global_limiter_.stats_json();
        j["ip_limiter_count"]          = ip_limiters_.size();
        j["user_limiter_count"]        = user_limiters_.size();
        j["endpoint_matcher_count"]    = endpoint_matchers_.size();
        j["timestamp_ms"]              = now_ms();
        return j;
    }

    // ========================================================================
    // 429 Response Generation Helper
    // ========================================================================

    static json generate_429(const RateLimitResult& result) {
        return RateLimitResponseGenerator::generate_429_response(result);
    }

    static RateLimitResponseGenerator::RateLimitHeaders
    generate_rate_limit_headers(const RateLimitResult& result) {
        return RateLimitResponseGenerator::generate_headers(result);
    }

private:
    // -----------------------------------------------------------------------
    // Internal: IP rate limit check
    // -----------------------------------------------------------------------
    RateLimitResult _check_ip_rate_limit(const std::string& ip,
                                          const std::string& endpoint,
                                          const std::string& method) {
        auto limiter = _get_or_create_ip_limiter(ip);
        return limiter->check(false);
    }

    std::shared_ptr<CombinedRateLimiter> _get_or_create_ip_limiter(
        const std::string& ip)
    {
        {
            std::shared_lock lk(ip_limiter_mu_);
            auto it = ip_limiters_.find(ip);
            if (it != ip_limiters_.end()) return it->second;
        }
        std::unique_lock lk(ip_limiter_mu_);
        auto it = ip_limiters_.find(ip);
        if (it != ip_limiters_.end()) return it->second;

        auto limiter = std::make_shared<CombinedRateLimiter>(
            config_.ip_limits.burst_count,
            config_.ip_limits.per_second,
            config_.ip_limits.window_ms,
            config_.ip_limits.window_max,
            config_.ip_limits.max_concurrent,
            "ip:" + ip);
        ip_limiters_[ip] = limiter;
        return limiter;
    }

    // -----------------------------------------------------------------------
    // Internal: User rate limit check
    // -----------------------------------------------------------------------
    RateLimitResult _check_user_rate_limit(const std::string& user_id,
                                            const std::string& endpoint,
                                            const std::string& method) {
        auto limiter = _get_or_create_user_limiter(user_id);
        return limiter->check(false);
    }

    std::shared_ptr<CombinedRateLimiter> _get_or_create_user_limiter(
        const std::string& user_id)
    {
        {
            std::shared_lock lk(user_limiter_mu_);
            auto it = user_limiters_.find(user_id);
            if (it != user_limiters_.end()) return it->second;
        }
        std::unique_lock lk(user_limiter_mu_);
        auto it = user_limiters_.find(user_id);
        if (it != user_limiters_.end()) return it->second;

        auto limiter = std::make_shared<CombinedRateLimiter>(
            config_.user_limits.burst_count,
            config_.user_limits.per_second,
            config_.user_limits.window_ms,
            config_.user_limits.window_max,
            config_.user_limits.max_concurrent,
            "user:" + user_id);
        user_limiters_[user_id] = limiter;
        return limiter;
    }

    // -----------------------------------------------------------------------
    // Internal: Endpoint rate limit check
    // -----------------------------------------------------------------------
    RateLimitResult _check_endpoint_rate_limit(const std::string& endpoint,
                                                const std::string& method,
                                                const std::string& ip) {
        std::shared_lock lk(ep_mu_);
        for (auto& matcher : endpoint_matchers_) {
            if (matcher.method != "*" && !iequals(matcher.method, method))
                continue;
            if (matcher.regex && std::regex_search(endpoint, *matcher.regex)) {
                std::string key = endpoint + ":" + ip;
                auto limiter = _get_or_create_ep_limiter_nolock(key, matcher.entry);
                return limiter->check(false);
            }
        }
        // No specific rule matched => allow (already checked global/ip/user)
        RateLimitResult r;
        r.allowed       = true;
        r.limit_type    = "endpoint_default";
        r.limit_remaining = -1;
        return r;
    }

    std::shared_ptr<CombinedRateLimiter> _get_or_create_ep_limiter_nolock(
        const std::string& key, const RateLimitEntry& entry)
    {
        auto it = ep_limiters_.find(key);
        if (it != ep_limiters_.end()) return it->second;

        auto limiter = std::make_shared<CombinedRateLimiter>(
            entry.burst_count > 0 ? entry.burst_count : config_.defaults.burst_count,
            entry.per_second  > 0 ? entry.per_second  : config_.defaults.per_second,
            entry.window_ms   > 0 ? entry.window_ms   : config_.defaults.window_ms,
            entry.window_max  > 0 ? entry.window_max  : config_.defaults.window_max,
            entry.max_concurrent > 0 ? entry.max_concurrent : config_.defaults.max_concurrent,
            "ep:" + entry.name + ":" + key);
        ep_limiters_[key] = limiter;
        return limiter;
    }

    // -----------------------------------------------------------------------
    // Whitelist helpers
    // -----------------------------------------------------------------------
    bool _is_whitelisted(const std::string& id) {
        std::shared_lock lk(whitelist_mu_);
        for (auto& w : whitelist_cache_) {
            if (ip_matches_cidr(id, w.ip_or_cidr)) return true;
            if (id == w.ip_or_cidr) return true;
        }
        return false;
    }

    void _rebuild_whitelist_cache() {
        std::unique_lock lk(whitelist_mu_);
        whitelist_cache_.clear();
        for (auto& w : config_.whitelist) {
            if (w.active) whitelist_cache_.push_back(w);
        }
    }

    // -----------------------------------------------------------------------
    // Override helpers
    // -----------------------------------------------------------------------
    std::optional<RateLimitOverride> _get_user_override(const std::string& user_id) {
        if (user_id.empty()) return std::nullopt;
        std::shared_lock lk(override_mu_);
        auto it = override_map_.find(user_id);
        if (it != override_map_.end()) {
            auto& ov = it->second;
            if (ov.active && (ov.expires_at == 0 || now_ms() < ov.expires_at))
                return ov;
        }
        return std::nullopt;
    }

    void _rebuild_override_map() {
        std::unique_lock lk(override_mu_);
        override_map_.clear();
        for (auto& o : config_.user_overrides) {
            if (o.active && (o.expires_at == 0 || now_ms() < o.expires_at))
                override_map_[o.user_id] = o;
        }
    }

    RateLimitResult _check_custom_limits(const std::string& user_id,
                                          const std::string& ip,
                                          const std::string& endpoint,
                                          const std::string& method,
                                          const RateLimitOverride& ov) {
        auto limiter = _get_or_create_override_limiter(ov);
        return limiter->check(false);
    }

    std::shared_ptr<CombinedRateLimiter> _get_or_create_override_limiter(
        const RateLimitOverride& ov)
    {
        std::string key = "override:" + ov.user_id;
        {
            std::shared_lock lk(override_limiter_mu_);
            auto it = override_limiters_.find(key);
            if (it != override_limiters_.end()) return it->second;
        }
        std::unique_lock lk(override_limiter_mu_);
        auto it = override_limiters_.find(key);
        if (it != override_limiters_.end()) return it->second;

        int64_t burst    = ov.burst_count    > 0 ? ov.burst_count    : config_.user_limits.burst_count;
        double  rate     = ov.per_second     > 0 ? ov.per_second     : config_.user_limits.per_second;
        int64_t win_ms   = config_.user_limits.window_ms;
        int64_t win_max  = config_.user_limits.window_max;
        int64_t concur   = ov.max_concurrent > 0 ? ov.max_concurrent : config_.user_limits.max_concurrent;

        auto limiter = std::make_shared<CombinedRateLimiter>(
            burst, rate, win_ms, win_max, concur, key);
        override_limiters_[key] = limiter;
        return limiter;
    }

    // -----------------------------------------------------------------------
    // Endpoint matchers
    // -----------------------------------------------------------------------
    struct EndpointMatcher {
        std::shared_ptr<std::regex> regex;
        std::string method;
        RateLimitEntry entry;
    };

    void _rebuild_endpoint_matchers() {
        std::unique_lock lk(ep_mu_);
        endpoint_matchers_.clear();
        for (auto& r : config_.endpoint_rules) {
            if (!r.enabled) continue;
            EndpointMatcher m;
            try {
                m.regex = std::make_shared<std::regex>(r.match_endpoint,
                    std::regex::ECMAScript | std::regex::optimize);
            } catch (...) {
                continue; // skip invalid regex
            }
            m.method = r.match_method;
            m.entry  = r;
            endpoint_matchers_.push_back(std::move(m));
        }
        // Sort by priority (lower = higher priority)
        std::sort(endpoint_matchers_.begin(), endpoint_matchers_.end(),
                  [](const EndpointMatcher& a, const EndpointMatcher& b) {
                      return a.entry.priority < b.entry.priority;
                  });
    }

    // -----------------------------------------------------------------------
    // Apply full config
    // -----------------------------------------------------------------------
    void _apply_config() {
        global_limiter_.reconfigure(
            config_.global_cap.burst_count,
            config_.global_cap.per_second,
            config_.global_cap.window_ms,
            config_.global_cap.window_max,
            config_.global_cap.max_concurrent);

        throttler_.reconfigure(config_.connection_throttle);
        dnsbl_.set_providers(config_.dnsbl_providers);
        prioritizer_.reconfigure(config_.prioritizer);
        synchrotron_.reconfigure(config_.synchrotron);
        reporter_.reconfigure(config_.reporter);

        _rebuild_endpoint_matchers();
        _rebuild_override_map();
        _rebuild_whitelist_cache();
    }

    // -----------------------------------------------------------------------
    // Event factory
    // -----------------------------------------------------------------------
    RateLimitEvent _make_event(const std::string& scope,
                                const std::string& identifier,
                                const std::string& endpoint,
                                const std::string& method,
                                const std::string& limit_type,
                                int64_t retry_after_ms,
                                int64_t limit_value,
                                const std::string& client_ip,
                                const std::string& user_agent,
                                const std::string& reason) {
        RateLimitEvent e;
        e.scope          = scope;
        e.identifier     = identifier;
        e.endpoint       = endpoint;
        e.method         = method;
        e.limit_type     = limit_type;
        e.retry_after_ms = retry_after_ms;
        e.limit_value    = limit_value;
        e.client_ip      = client_ip;
        e.user_agent     = user_agent;
        e.reason         = reason;
        return e;
    }

    // -----------------------------------------------------------------------
    // Periodic maintenance (cleanup stale limiters, expire blocks, etc.)
    // -----------------------------------------------------------------------
    void _start_maintenance() {
        maintenance_thread_ = std::thread([this] {
            while (!shutdown_) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                _maintenance_tick();
            }
        });
    }

    void _maintenance_tick() {
        // Purge expired IP blocks
        ip_blocker_.purge_expired();

        // Cleanup connection throttler
        throttler_.cleanup(600000); // 10 min

        // Cleanup stale IP limiters (haven't been used in 5 min)
        {
            std::unique_lock lk(ip_limiter_mu_);
            int64_t now = now_ms();
            // Just cap size; full LRU would need access tracking
            if (ip_limiters_.size() > 50000) {
                // Simple: clear all (they'll be recreated on demand)
                ip_limiters_.clear();
            }
        }

        // Cleanup stale user limiters
        {
            std::unique_lock lk(user_limiter_mu_);
            if (user_limiters_.size() > 100000) {
                user_limiters_.clear();
            }
        }

        // Cleanup stale endpoint limiters
        {
            std::unique_lock lk(ep_mu_);
            if (ep_limiters_.size() > 50000) {
                ep_limiters_.clear();
            }
        }

        // Collect metrics snapshot
        metrics_.snapshot();

        // Rebuild override map (expire old ones)
        _rebuild_override_map();
    }

    // ========================================================================
    // Configuration
    // ========================================================================
    GlobalRateLimitConfig config_;
    mutable std::shared_mutex config_mu_;

    // ========================================================================
    // Core limiters
    // ========================================================================
    CombinedRateLimiter global_limiter_;

    std::shared_mutex ip_limiter_mu_;
    std::unordered_map<std::string, std::shared_ptr<CombinedRateLimiter>>
        ip_limiters_;

    std::shared_mutex user_limiter_mu_;
    std::unordered_map<std::string, std::shared_ptr<CombinedRateLimiter>>
        user_limiters_;

    std::shared_mutex ep_mu_;
    std::vector<EndpointMatcher> endpoint_matchers_;
    std::unordered_map<std::string, std::shared_ptr<CombinedRateLimiter>>
        ep_limiters_;

    // ========================================================================
    // Override limiters
    // ========================================================================
    std::shared_mutex override_mu_;
    std::unordered_map<std::string, RateLimitOverride> override_map_;

    std::shared_mutex override_limiter_mu_;
    std::unordered_map<std::string, std::shared_ptr<CombinedRateLimiter>>
        override_limiters_;

    // ========================================================================
    // Whitelist cache
    // ========================================================================
    std::shared_mutex whitelist_mu_;
    std::vector<RateLimitWhitelistEntry> whitelist_cache_;

    // ========================================================================
    // Subsystems
    // ========================================================================
    ConnectionThrottler       throttler_;
    IpRangeBlocker            ip_blocker_;
    DnsblChecker              dnsbl_;
    RequestPrioritizer        prioritizer_;
    RateLimitEventReporter    reporter_;
    SynchrotronRateLimiter    synchrotron_;
    RateLimitMetrics          metrics_;

    // ========================================================================
    // Maintenance
    // ========================================================================
    std::thread maintenance_thread_;
    std::atomic<bool> shutdown_{false};
};

// ============================================================================
// SECTION 16: Global Singleton Accessor
// Provides a process-wide singleton for easy access from anywhere in the
// server.  The server initializes it once on startup.
// ============================================================================

namespace {

std::mutex g_dos_protection_mutex;
std::unique_ptr<DoSProtectionManager> g_dos_protection_instance;

} // anonymous namespace

// Initialize (call once at startup)
void init_dos_protection() {
    std::lock_guard lk(g_dos_protection_mutex);
    if (!g_dos_protection_instance) {
        g_dos_protection_instance = std::make_unique<DoSProtectionManager>();
    }
}

// Initialize with custom config
void init_dos_protection_with_config(const json& config_json) {
    std::lock_guard lk(g_dos_protection_mutex);
    auto mgr = std::make_unique<DoSProtectionManager>();
    mgr->update_config(config_json);
    g_dos_protection_instance = std::move(mgr);
}

// Access the singleton
DoSProtectionManager& dos_protection() {
    if (!g_dos_protection_instance) {
        // Auto-initialize if not done explicitly
        init_dos_protection();
    }
    return *g_dos_protection_instance;
}

// Check if initialized
bool dos_protection_initialized() {
    std::lock_guard lk(g_dos_protection_mutex);
    return g_dos_protection_instance != nullptr;
}

// Shutdown
void shutdown_dos_protection() {
    std::lock_guard lk(g_dos_protection_mutex);
    g_dos_protection_instance.reset();
}

// ============================================================================
// SECTION 17: Convenience free functions for rapid integration
// ============================================================================

RateLimitResult check_rate_limit(const std::string& user_id,
                                  const std::string& client_ip,
                                  const std::string& endpoint,
                                  const std::string& method,
                                  const std::string& user_agent) {
    return dos_protection().check_request(user_id, client_ip,
                                           endpoint, method, user_agent);
}

json generate_429_response(const RateLimitResult& result) {
    return DoSProtectionManager::generate_429(result);
}

// ============================================================================
// SECTION 18: Config validation utility
// ============================================================================

json validate_rate_limit_config(const json& cfg) {
    json errors = json::array();
    json warnings = json::array();

    auto check_positive = [&](const std::string& path, int64_t val) {
        if (val < 0) {
            errors.push_back({{"path", path}, {"error", "must be non-negative"}, {"value", val}});
        }
    };

    auto check_positive_double = [&](const std::string& path, double val) {
        if (val < 0.0) {
            errors.push_back({{"path", path}, {"error", "must be non-negative"}, {"value", val}});
        }
    };

    if (cfg.contains("defaults")) {
        auto& d = cfg["defaults"];
        check_positive("defaults.per_second", d.value("per_second", 0LL));
        check_positive("defaults.burst_count", d.value("burst_count", 0LL));
        check_positive("defaults.window_ms", d.value("window_ms", 0LL));
        check_positive("defaults.window_max", d.value("window_max", 0LL));
        check_positive("defaults.max_concurrent", d.value("max_concurrent", 0LL));
    }

    if (cfg.contains("ip_limits")) {
        auto& il = cfg["ip_limits"];
        check_positive("ip_limits.per_second", il.value("per_second", 0LL));
        check_positive("ip_limits.burst_count", il.value("burst_count", 0LL));
    }

    if (cfg.contains("user_limits")) {
        auto& ul = cfg["user_limits"];
        check_positive("user_limits.per_second", ul.value("per_second", 0LL));
        check_positive("user_limits.burst_count", ul.value("burst_count", 0LL));
    }

    if (cfg.contains("global_cap")) {
        auto& gc = cfg["global_cap"];
        check_positive("global_cap.per_second", gc.value("per_second", 0LL));
        check_positive("global_cap.max_concurrent", gc.value("max_concurrent", 0LL));
        if (gc.value("max_concurrent", 0LL) < 10 && gc.value("max_concurrent", 0LL) > 0) {
            warnings.push_back({{"path", "global_cap.max_concurrent"},
                                {"warning", "very low global concurrency cap (< 10)"}});
        }
    }

    // Validate endpoint rules regex
    if (cfg.contains("endpoint_rules")) {
        for (size_t i = 0; i < cfg["endpoint_rules"].size(); ++i) {
            auto& rule = cfg["endpoint_rules"][i];
            std::string pattern = rule.value("match_endpoint", "");
            if (!pattern.empty()) {
                try {
                    std::regex re(pattern);
                } catch (const std::regex_error& e) {
                    errors.push_back({
                        {"path", "endpoint_rules[" + std::to_string(i) + "].match_endpoint"},
                        {"error", "invalid regex: " + std::string(e.what())},
                        {"value", pattern}
                    });
                }
            }
        }
    }

    return json::object({
        {"valid",   errors.empty()},
        {"errors",   errors},
        {"warnings", warnings}
    });
}

}  // namespace progressive::server
