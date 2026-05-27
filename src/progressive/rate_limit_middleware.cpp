/**
 * progressive-server — Rate Limit Middleware
 * 
 * Implements multi-strategy rate limiting:
 *   - Token Bucket (burst-tolerant, steady refill)
 *   - Sliding Window Log (precise, higher memory)
 *   - Sliding Window Counter (approximate, low memory)
 *   - Fixed Window (simple, reset-aligned)
 *   - Leaky Bucket (constant outflow)
 *
 * Supports per-user, per-IP, and composite (user+IP) keys.
 * Thread-safe with fine-grained per-bucket locking.
 * Includes automatic eviction, metrics export, and JSON configuration.
 *
 * Namespace: progressive::
 */

#include <algorithm>
#include <any>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <numeric>
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
#include <syncstream>
#include <system_error>
#include <thread>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

// ---------------------------------------------------------------------------
// Progressive namespace
// ---------------------------------------------------------------------------

namespace progressive {
namespace detail {

// ==========================================================================
// Utility types and helpers
// ==========================================================================

/// Clock type used throughout rate limiting — steady monotonic clock.
using clock_type        = std::chrono::steady_clock;
using time_point        = clock_type::time_point;
using duration_ns       = std::chrono::nanoseconds;
using duration_us       = std::chrono::microseconds;
using duration_ms       = std::chrono::milliseconds;
using duration_s        = std::chrono::seconds;
using high_res_clock    = std::chrono::high_resolution_clock;

// ---------------------------------------------------------------------------
// Compact wall-clock timestamp cache (avoids repeated syscalls)
// ---------------------------------------------------------------------------

class wall_clock_cache {
public:
    static wall_clock_cache& instance() {
        static wall_clock_cache wc;
        return wc;
    }

    time_point now() noexcept {
        // Fast-path: return cached value if within the coarse granularity
        auto cached = cached_.load(std::memory_order_relaxed);
        auto cur    = clock_type::now();
        if (cur - cached > refresh_interval_) {
            cached_.store(cur, std::memory_order_relaxed);
            return cur;
        }
        return cached;
    }

    void set_refresh_interval(duration_ns d) noexcept { refresh_interval_ = d; }

private:
    wall_clock_cache() : cached_(clock_type::now()) {}
    std::atomic<time_point> cached_;
    duration_ns refresh_interval_{duration_us{100}};  // 100 µs granularity
};

// ---------------------------------------------------------------------------
// Fowler–Noll–Vo hash for efficient string→size_t (non-crypto)
// ---------------------------------------------------------------------------

inline std::size_t fnv1a_hash(std::string_view sv) noexcept {
    constexpr std::size_t offset_basis = 14695981039346656037ULL;
    constexpr std::size_t prime        = 1099511628211ULL;
    std::size_t h = offset_basis;
    for (unsigned char c : sv) {
        h ^= static_cast<std::size_t>(c);
        h *= prime;
    }
    return h;
}

// ---------------------------------------------------------------------------
// IPv4 / IPv6 canonicalisation
// ---------------------------------------------------------------------------

inline std::string canonicalise_ip(std::string_view raw) {
    // Minimal: trim brackets from IPv6, strip leading zeros, lowercase.
    std::string out;
    out.reserve(raw.size());
    bool in_bracket = false;
    for (char c : raw) {
        if (c == '[') { in_bracket = true; continue; }
        if (c == ']') { in_bracket = false; continue; }
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

// ==========================================================================
// Rate-limit key types
// ==========================================================================

enum class key_type : uint8_t {
    ip,
    user,
    composite,   // user + ip
    global,
    endpoint,
    custom
};

/// A compact key used as the map index.
struct rate_limit_key {
    key_type    type{key_type::ip};
    std::string ip;
    std::string user;
    std::string endpoint;
    std::string custom_label;

    std::size_t hash() const noexcept {
        std::size_t h = static_cast<std::size_t>(type);
        h ^= fnv1a_hash(ip)    + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= fnv1a_hash(user)  + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= fnv1a_hash(endpoint) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= fnv1a_hash(custom_label) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }

    bool operator==(const rate_limit_key& rhs) const noexcept {
        return type == rhs.type && ip == rhs.ip && user == rhs.user
            && endpoint == rhs.endpoint && custom_label == rhs.custom_label;
    }
};

} // namespace detail
} // namespace progressive

// Inject hash into std namespace
template <>
struct std::hash<progressive::detail::rate_limit_key> {
    std::size_t operator()(const progressive::detail::rate_limit_key& k) const noexcept {
        return k.hash();
    }
};

namespace progressive {
namespace detail {

// ==========================================================================
// Rate-limit strategy enumeration
// ==========================================================================

enum class strategy : uint8_t {
    token_bucket,
    sliding_window_log,
    sliding_window_counter,
    fixed_window,
    leaky_bucket
};

/// Human-readable name for each strategy.
inline const char* strategy_name(strategy s) noexcept {
    switch (s) {
        case strategy::token_bucket:            return "token_bucket";
        case strategy::sliding_window_log:       return "sliding_window_log";
        case strategy::sliding_window_counter:   return "sliding_window_counter";
        case strategy::fixed_window:             return "fixed_window";
        case strategy::leaky_bucket:             return "leaky_bucket";
    }
    return "unknown";
}

inline std::optional<strategy> strategy_from_string(std::string_view sv) {
    if (sv == "token_bucket")            return strategy::token_bucket;
    if (sv == "sliding_window_log")      return strategy::sliding_window_log;
    if (sv == "sliding_window_counter")  return strategy::sliding_window_counter;
    if (sv == "fixed_window")            return strategy::fixed_window;
    if (sv == "leaky_bucket")            return strategy::leaky_bucket;
    return std::nullopt;
}

// ==========================================================================
// Rate-limit result
// ==========================================================================

enum class limit_result : uint8_t {
    allowed,
    throttled,
    blocked,
    error
};

struct rate_limit_decision {
    limit_result    result{limit_result::allowed};
    int64_t         remaining{0};
    duration_ms     retry_after{0};
    duration_ms     reset_in{0};
    int64_t         limit{0};
    std::string     reason;
};

// ==========================================================================
// Per-strategy configuration types
// ==========================================================================

struct token_bucket_config {
    int64_t   capacity{100};        // max tokens
    int64_t   refill_rate{10};      // tokens per second
    int64_t   refill_period_ms{100}; // how often we add tokens
    int64_t   initial_tokens{100};
    int64_t   cost_per_request{1};
    bool      allow_burst{true};
};

struct sliding_window_log_config {
    int64_t   max_requests{100};
    duration_ms window_size{60'000};   // 60 s
    bool      strict_ordering{false};
};

struct sliding_window_counter_config {
    int64_t   max_requests{100};
    duration_ms window_size{60'000};
    int64_t   sub_window_count{6};   // sub-windows for accuracy
};

struct fixed_window_config {
    int64_t   max_requests{100};
    duration_ms window_size{60'000};
    bool      align_to_clock{true};
};

struct leaky_bucket_config {
    int64_t   capacity{100};
    int64_t   outflow_rate{10};       // requests per second drained
    duration_ms outflow_period{100};
};

/// Variant config — one per strategy.
using strategy_config = std::variant<
    token_bucket_config,
    sliding_window_log_config,
    sliding_window_counter_config,
    fixed_window_config,
    leaky_bucket_config
>;

// ==========================================================================
// Bucket state base
// ==========================================================================

struct bucket_state {
    alignas(64) std::atomic<int64_t> total_requests{0};
    alignas(64) std::atomic<int64_t> total_allowed{0};
    alignas(64) std::atomic<int64_t> total_throttled{0};
    alignas(64) std::atomic<int64_t> total_blocked{0};
    std::atomic<time_point>       last_access{};
    std::atomic<time_point>       created_at{};
    mutable std::mutex            mtx;  // per-bucket lock

    bucket_state() {
        auto now = wall_clock_cache::instance().now();
        last_access.store(now, std::memory_order_relaxed);
        created_at.store(now, std::memory_order_relaxed);
    }

    void touch() noexcept {
        last_access.store(wall_clock_cache::instance().now(),
                          std::memory_order_relaxed);
    }
};

// ==========================================================================
// Token bucket state
// ==========================================================================

struct token_bucket_state : bucket_state {
    double                        tokens{0.0};
    time_point                    last_refill{};
    token_bucket_config           cfg;

    void init(const token_bucket_config& c) {
        cfg = c;
        tokens = static_cast<double>(c.initial_tokens);
        last_refill = wall_clock_cache::instance().now();
    }
};

// ==========================================================================
// Sliding-window log state
// ==========================================================================

struct sliding_window_log_state : bucket_state {
    std::deque<time_point>        timestamps;
    sliding_window_log_config     cfg;
};

// ==========================================================================
// Sliding-window counter state
// ==========================================================================

struct sliding_window_counter_state : bucket_state {
    // circular buffer of per-sub-window counters
    std::vector<int64_t>          sub_counters;
    int64_t                       current_sub_index{0};
    time_point                    current_sub_start{};
    sliding_window_counter_config cfg;
};

// ==========================================================================
// Fixed-window state
// ==========================================================================

struct fixed_window_state : bucket_state {
    int64_t                       counter{0};
    time_point                    window_start{};
    fixed_window_config           cfg;
};

// ==========================================================================
// Leaky bucket state
// ==========================================================================

struct leaky_bucket_state : bucket_state {
    double                        water_level{0.0};
    time_point                    last_leak{};
    leaky_bucket_config           cfg;

    void init(const leaky_bucket_config& c) {
        cfg = c;
        water_level = 0.0;
        last_leak = wall_clock_cache::instance().now();
    }
};

// ==========================================================================
// Unified bucket variant
// ==========================================================================

using bucket_variant = std::variant<
    token_bucket_state,
    sliding_window_log_state,
    sliding_window_counter_state,
    fixed_window_state,
    leaky_bucket_state
>;

// ==========================================================================
// Rate-limit rule definition
// ==========================================================================

struct rate_limit_rule {
    std::string            name;
    strategy               strat{strategy::token_bucket};
    strategy_config        config;
    key_type               ktype{key_type::ip};
    std::regex             path_pattern;        // which endpoints
    std::vector<std::string> path_patterns_raw;
    bool                   enabled{true};
    int                    priority{0};         // lower = evaluated first
    int64_t                default_cost{1};
    std::map<std::string, int64_t> endpoint_costs;  // endpoint -> cost
    duration_ms            block_duration{0};   // 0 = don't block, just throttle
    std::string            description;
};

// ==========================================================================
// Global metrics
// ==========================================================================

struct rate_limit_metrics {
    std::atomic<int64_t> total_decisions{0};
    std::atomic<int64_t> total_allowed{0};
    std::atomic<int64_t> total_throttled{0};
    std::atomic<int64_t> total_blocked{0};
    std::atomic<int64_t> total_errors{0};
    std::atomic<int64_t> active_buckets{0};
    std::atomic<int64_t> evicted_buckets{0};
    std::atomic<int64_t> stale_hits{0};

    void record(limit_result r) noexcept {
        total_decisions.fetch_add(1, std::memory_order_relaxed);
        switch (r) {
            case limit_result::allowed:   total_allowed.fetch_add(1, std::memory_order_relaxed);   break;
            case limit_result::throttled: total_throttled.fetch_add(1, std::memory_order_relaxed); break;
            case limit_result::blocked:   total_blocked.fetch_add(1, std::memory_order_relaxed);   break;
            case limit_result::error:     total_errors.fetch_add(1, std::memory_order_relaxed);     break;
        }
    }
};

// ==========================================================================
// Eviction policy helpers
// ==========================================================================

enum class eviction_policy : uint8_t {
    lru,       // least-recently-used
    ttl,       // time-to-live since creation
    idle,      // idle since last access
    none
};

struct eviction_config {
    eviction_policy policy{eviction_policy::idle};
    duration_ms     max_idle{300'000};     // 5 min
    duration_ms     max_ttl{3'600'000};    // 1 hour
    int64_t         max_buckets{1'000'000};
    int64_t         high_water_mark{800'000};  // start evicting at 80 %
    duration_ms     eviction_interval{30'000}; // every 30 s
};

// ==========================================================================
// Forward declaration for the main store
// ==========================================================================

class rate_limit_store;

// ==========================================================================
// Core algorithm implementations
// ==========================================================================

namespace algorithm {

// ---------------------------------------------------------------------------
// Token bucket: refill then try to consume.
// Returns remaining tokens after (potential) consumption.
// ---------------------------------------------------------------------------

inline std::pair<limit_result, double> token_bucket_consume(
    token_bucket_state& st, int64_t cost) noexcept
{
    auto now = wall_clock_cache::instance().now();
    std::lock_guard<std::mutex> lk(st.mtx);

    // Refill
    auto elapsed_ms = std::chrono::duration_cast<duration_ms>(now - st.last_refill);
    if (elapsed_ms.count() > 0 && st.cfg.refill_period_ms > 0) {
        double periods = static_cast<double>(elapsed_ms.count())
                       / static_cast<double>(st.cfg.refill_period_ms);
        double tokens_per_period =
            static_cast<double>(st.cfg.refill_rate) * st.cfg.refill_period_ms / 1000.0;
        st.tokens += periods * tokens_per_period;
        if (st.tokens > static_cast<double>(st.cfg.capacity)) {
            st.tokens = static_cast<double>(st.cfg.capacity);
        }
        // Advance refill time proportionally
        int64_t whole_periods = static_cast<int64_t>(periods);
        st.last_refill += duration_ms(whole_periods * st.cfg.refill_period_ms);
        if (st.last_refill > now) st.last_refill = now;
    }

    double cost_d = static_cast<double>(cost);
    if (st.tokens >= cost_d) {
        st.tokens -= cost_d;
        st.total_allowed.fetch_add(1, std::memory_order_relaxed);
        st.touch();
        return {limit_result::allowed, st.tokens};
    }

    st.total_throttled.fetch_add(1, std::memory_order_relaxed);
    st.touch();
    return {limit_result::throttled, st.tokens};
}

// ---------------------------------------------------------------------------
// Sliding window log: evict old timestamps, count remaining, decide.
// ---------------------------------------------------------------------------

inline limit_result sliding_window_log_check(
    sliding_window_log_state& st) noexcept
{
    auto now = wall_clock_cache::instance().now();
    std::lock_guard<std::mutex> lk(st.mtx);

    auto window_start = now - st.cfg.window_size;

    // Evict expired timestamps
    while (!st.timestamps.empty() && st.timestamps.front() <= window_start) {
        st.timestamps.pop_front();
    }

    if (static_cast<int64_t>(st.timestamps.size()) < st.cfg.max_requests) {
        st.timestamps.push_back(now);
        st.total_allowed.fetch_add(1, std::memory_order_relaxed);
        st.touch();
        return limit_result::allowed;
    }

    st.total_throttled.fetch_add(1, std::memory_order_relaxed);
    st.touch();
    return limit_result::throttled;
}

// ---------------------------------------------------------------------------
// Sliding window counter: approximate sliding window using sub-windows.
// ---------------------------------------------------------------------------

inline limit_result sliding_window_counter_check(
    sliding_window_counter_state& st) noexcept
{
    auto now = wall_clock_cache::instance().now();
    std::lock_guard<std::mutex> lk(st.mtx);

    auto sub_dur = st.cfg.window_size / st.cfg.sub_window_count;
    auto window_start = now - st.cfg.window_size;

    // Advance sub-window pointer
    if (now >= st.current_sub_start + sub_dur) {
        int64_t steps = static_cast<int64_t>(
            std::chrono::duration_cast<duration_ns>(now - st.current_sub_start).count()
            / std::chrono::duration_cast<duration_ns>(sub_dur).count());
        for (int64_t i = 0; i < steps && i < st.cfg.sub_window_count; ++i) {
            st.current_sub_index = (st.current_sub_index + 1) % st.cfg.sub_window_count;
            st.sub_counters[st.current_sub_index] = 0;
        }
        st.current_sub_start += sub_dur * steps;
        if (st.current_sub_start > now) st.current_sub_start = now;
    }

    // Count across all sub-windows (approximation)
    int64_t total = 0;
    for (auto c : st.sub_counters) total += c;

    if (total < st.cfg.max_requests) {
        st.sub_counters[st.current_sub_index]++;
        st.total_allowed.fetch_add(1, std::memory_order_relaxed);
        st.touch();
        return limit_result::allowed;
    }

    st.total_throttled.fetch_add(1, std::memory_order_relaxed);
    st.touch();
    return limit_result::throttled;
}

// ---------------------------------------------------------------------------
// Fixed window: simple counter with periodic reset.
// ---------------------------------------------------------------------------

inline limit_result fixed_window_check(fixed_window_state& st) noexcept
{
    auto now = wall_clock_cache::instance().now();
    std::lock_guard<std::mutex> lk(st.mtx);

    // Reset window if expired
    if (now - st.window_start >= st.cfg.window_size) {
        if (st.cfg.align_to_clock) {
            // Align to epoch
            auto ms = std::chrono::duration_cast<duration_ms>(
                now.time_since_epoch()).count();
            auto win_ms = std::chrono::duration_cast<duration_ms>(
                st.cfg.window_size).count();
            int64_t aligned = (ms / win_ms) * win_ms;
            st.window_start = time_point{} + duration_ms(aligned);
        } else {
            st.window_start = now;
        }
        st.counter = 0;
    }

    if (st.counter < st.cfg.max_requests) {
        ++st.counter;
        st.total_allowed.fetch_add(1, std::memory_order_relaxed);
        st.touch();
        return limit_result::allowed;
    }

    st.total_throttled.fetch_add(1, std::memory_order_relaxed);
    st.touch();
    return limit_result::throttled;
}

// ---------------------------------------------------------------------------
// Leaky bucket: water drains at constant rate, request adds water.
// ---------------------------------------------------------------------------

inline std::pair<limit_result, double> leaky_bucket_check(
    leaky_bucket_state& st, int64_t cost) noexcept
{
    auto now = wall_clock_cache::instance().now();
    std::lock_guard<std::mutex> lk(st.mtx);

    // Drain water
    auto elapsed_ms = std::chrono::duration_cast<duration_ms>(now - st.last_leak);
    if (elapsed_ms.count() > 0 && st.cfg.outflow_period.count() > 0) {
        double periods = static_cast<double>(elapsed_ms.count())
                       / static_cast<double>(st.cfg.outflow_period.count());
        double drain_per_period =
            static_cast<double>(st.cfg.outflow_rate)
            * st.cfg.outflow_period.count() / 1000.0;
        st.water_level -= periods * drain_per_period;
        if (st.water_level < 0.0) st.water_level = 0.0;
        int64_t whole = static_cast<int64_t>(periods);
        st.last_leak += st.cfg.outflow_period * whole;
        if (st.last_leak > now) st.last_leak = now;
    }

    double cost_d = static_cast<double>(cost);
    if (st.water_level + cost_d <= static_cast<double>(st.cfg.capacity)) {
        st.water_level += cost_d;
        st.total_allowed.fetch_add(1, std::memory_order_relaxed);
        st.touch();
        return {limit_result::allowed, st.water_level};
    }

    st.total_throttled.fetch_add(1, std::memory_order_relaxed);
    st.touch();
    return {limit_result::throttled, st.water_level};
}

// ---------------------------------------------------------------------------
// Retry-after calculation
// ---------------------------------------------------------------------------

inline duration_ms token_bucket_retry_after(const token_bucket_state& st,
                                              int64_t cost) noexcept
{
    double deficit = static_cast<double>(cost) - st.tokens;
    if (deficit <= 0.0) return duration_ms{0};
    double seconds_needed = deficit / static_cast<double>(st.cfg.refill_rate);
    return duration_ms{static_cast<int64_t>(seconds_needed * 1000.0) + 1};
}

inline duration_ms fixed_window_retry_after(const fixed_window_state& st) noexcept
{
    auto now = wall_clock_cache::instance().now();
    auto remaining = st.cfg.window_size - (now - st.window_start);
    if (remaining.count() <= 0) return duration_ms{0};
    return std::chrono::duration_cast<duration_ms>(remaining);
}

inline duration_ms leaky_bucket_retry_after(const leaky_bucket_state& st,
                                              int64_t cost) noexcept
{
    double excess = (st.water_level + cost) - static_cast<double>(st.cfg.capacity);
    if (excess <= 0.0) return duration_ms{0};
    double seconds = excess / static_cast<double>(st.cfg.outflow_rate);
    return duration_ms{static_cast<int64_t>(seconds * 1000.0) + 1};
}

} // namespace algorithm

// ==========================================================================
// Rate-limit store: thread-safe container for all buckets
// ==========================================================================

class rate_limit_store {
public:
    using bucket_map = std::unordered_map<rate_limit_key,
                                           std::unique_ptr<bucket_variant>>;

    rate_limit_store() = default;

    explicit rate_limit_store(const eviction_config& ec) : eviction_cfg_(ec) {}

    ~rate_limit_store() {
        stop_eviction_thread();
    }

    // -----------------------------------------------------------------------
    // Bucket retrieval / creation
    // -----------------------------------------------------------------------

    template <typename State, typename Config>
    State& get_or_create(const rate_limit_key& key,
                         strategy s,
                         const Config& cfg)
    {
        // Fast-path: read lock
        {
            std::shared_lock<std::shared_mutex> rlk(mutex_);
            auto it = buckets_.find(key);
            if (it != buckets_.end()) {
                auto& bv = *it->second;
                return *std::get_if<State>(&bv);
            }
        }
        // Slow-path: write lock
        {
            std::unique_lock<std::shared_mutex> wlk(mutex_);
            // Double-check
            auto it = buckets_.find(key);
            if (it != buckets_.end()) {
                auto& bv = *it->second;
                return *std::get_if<State>(&bv);
            }

            // Evict if over high-water mark
            if (eviction_cfg_.policy != eviction_policy::none
                && static_cast<int64_t>(buckets_.size()) >= eviction_cfg_.high_water_mark)
            {
                evict_locked(eviction_cfg_.high_water_mark / 10);
            }

            auto uniq = std::make_unique<bucket_variant>(std::in_place_type<State>);
            auto& state = std::get<State>(*uniq);
            if constexpr (std::is_same_v<State, token_bucket_state>) {
                state.init(cfg);
            } else if constexpr (std::is_same_v<State, leaky_bucket_state>) {
                state.init(cfg);
            } else if constexpr (std::is_same_v<State, sliding_window_counter_state>) {
                state.cfg = cfg;
                state.sub_counters.resize(cfg.sub_window_count, 0);
                state.current_sub_index = 0;
                state.current_sub_start = wall_clock_cache::instance().now();
            } else if constexpr (std::is_same_v<State, fixed_window_state>) {
                state.cfg = cfg;
                state.window_start = wall_clock_cache::instance().now();
            } else if constexpr (std::is_same_v<State, sliding_window_log_state>) {
                state.cfg = cfg;
            }

            auto [inserted_it, ok] = buckets_.try_emplace(key, std::move(uniq));
            metrics_.active_buckets.store(
                static_cast<int64_t>(buckets_.size()), std::memory_order_relaxed);
            return std::get<State>(*inserted_it->second);
        }
    }

    // -----------------------------------------------------------------------
    // Eviction
    // -----------------------------------------------------------------------

    void evict_locked(int64_t count) {
        if (buckets_.empty()) return;

        auto now = wall_clock_cache::instance().now();
        std::vector<rate_limit_key> to_remove;
        to_remove.reserve(static_cast<std::size_t>(count));

        switch (eviction_cfg_.policy) {
            case eviction_policy::idle: {
                // Collect keys with last_access older than max_idle
                for (auto& [k, bv] : buckets_) {
                    auto last = std::visit([](auto& s) {
                        return s.last_access.load(std::memory_order_relaxed);
                    }, *bv);
                    if (now - last > eviction_cfg_.max_idle) {
                        to_remove.push_back(k);
                        if (static_cast<int64_t>(to_remove.size()) >= count) break;
                    }
                }
                break;
            }
            case eviction_policy::ttl: {
                for (auto& [k, bv] : buckets_) {
                    auto created = std::visit([](auto& s) {
                        return s.created_at.load(std::memory_order_relaxed);
                    }, *bv);
                    if (now - created > eviction_cfg_.max_ttl) {
                        to_remove.push_back(k);
                        if (static_cast<int64_t>(to_remove.size()) >= count) break;
                    }
                }
                break;
            }
            case eviction_policy::lru: {
                // Sort buckets by last_access, evict oldest
                using pair_t = std::pair<time_point, rate_limit_key>;
                std::vector<pair_t> candidates;
                candidates.reserve(buckets_.size());
                for (auto& [k, bv] : buckets_) {
                    auto last = std::visit([](auto& s) {
                        return s.last_access.load(std::memory_order_relaxed);
                    }, *bv);
                    candidates.emplace_back(last, k);
                }
                std::sort(candidates.begin(), candidates.end(),
                          [](const pair_t& a, const pair_t& b) {
                              return a.first < b.first;
                          });
                for (int64_t i = 0; i < count && i < static_cast<int64_t>(candidates.size()); ++i) {
                    to_remove.push_back(candidates[static_cast<std::size_t>(i)].second);
                }
                break;
            }
            default:
                break;
        }

        for (auto& k : to_remove) {
            // aggregate stats before throwing away
            auto it = buckets_.find(k);
            if (it != buckets_.end()) {
                std::visit([&](auto& s) {
                    (void)s; // stats are atomic, no need to harvest here
                }, *it->second);
            }
            buckets_.erase(k);
        }
        metrics_.evicted_buckets.fetch_add(
            static_cast<int64_t>(to_remove.size()), std::memory_order_relaxed);
        metrics_.active_buckets.store(
            static_cast<int64_t>(buckets_.size()), std::memory_order_relaxed);
    }

    void evict(int64_t count) {
        std::unique_lock<std::shared_mutex> wlk(mutex_);
        evict_locked(count);
    }

    // -----------------------------------------------------------------------
    // Background eviction thread
    // -----------------------------------------------------------------------

    void start_eviction_thread() {
        if (eviction_cfg_.policy == eviction_policy::none) return;
        stop_eviction_thread();
        eviction_running_.store(true, std::memory_order_release);
        eviction_thread_ = std::thread([this] {
            while (eviction_running_.load(std::memory_order_acquire)) {
                std::unique_lock lk(eviction_cv_mutex_);
                eviction_cv_.wait_for(lk, std::chrono::milliseconds(
                    eviction_cfg_.eviction_interval.count()),
                    [this] { return !eviction_running_.load(std::memory_order_acquire); });
                if (!eviction_running_.load(std::memory_order_acquire)) break;
                lk.unlock();
                evict(eviction_cfg_.max_buckets / 20); // 5% per pass
            }
        });
    }

    void stop_eviction_thread() {
        eviction_running_.store(false, std::memory_order_release);
        eviction_cv_.notify_all();
        if (eviction_thread_.joinable()) {
            eviction_thread_.join();
        }
    }

    // -----------------------------------------------------------------------
    // Size / stats
    // -----------------------------------------------------------------------

    int64_t size() const {
        std::shared_lock<std::shared_mutex> rlk(mutex_);
        return static_cast<int64_t>(buckets_.size());
    }

    const rate_limit_metrics& metrics() const noexcept { return metrics_; }
    rate_limit_metrics& metrics() noexcept { return metrics_; }

    // -----------------------------------------------------------------------
    // Snapshot for monitoring
    // -----------------------------------------------------------------------

    struct bucket_snapshot {
        rate_limit_key  key;
        strategy        strat;
        int64_t         allowed;
        int64_t         throttled;
        int64_t         blocked;
        time_point      last_access;
    };

    std::vector<bucket_snapshot> snapshot(int64_t max_items = 100) const {
        std::vector<bucket_snapshot> result;
        result.reserve(static_cast<std::size_t>(max_items));
        std::shared_lock<std::shared_mutex> rlk(mutex_);
        for (auto& [k, bv] : buckets_) {
            if (static_cast<int64_t>(result.size()) >= max_items) break;
            bucket_snapshot snap;
            snap.key = k;
            std::visit([&](auto& s) {
                using T = std::decay_t<decltype(s)>;
                if constexpr (std::is_same_v<T, token_bucket_state>)
                    snap.strat = strategy::token_bucket;
                else if constexpr (std::is_same_v<T, sliding_window_log_state>)
                    snap.strat = strategy::sliding_window_log;
                else if constexpr (std::is_same_v<T, sliding_window_counter_state>)
                    snap.strat = strategy::sliding_window_counter;
                else if constexpr (std::is_same_v<T, fixed_window_state>)
                    snap.strat = strategy::fixed_window;
                else if constexpr (std::is_same_v<T, leaky_bucket_state>)
                    snap.strat = strategy::leaky_bucket;
                snap.allowed     = s.total_allowed.load(std::memory_order_relaxed);
                snap.throttled   = s.total_throttled.load(std::memory_order_relaxed);
                snap.blocked     = s.total_blocked.load(std::memory_order_relaxed);
                snap.last_access = s.last_access.load(std::memory_order_relaxed);
            }, *bv);
            result.push_back(std::move(snap));
        }
        return result;
    }

private:
    mutable std::shared_mutex  mutex_;
    bucket_map                  buckets_;
    eviction_config             eviction_cfg_;
    rate_limit_metrics          metrics_;

    // Background eviction
    std::atomic<bool>           eviction_running_{false};
    std::thread                 eviction_thread_;
    std::mutex                  eviction_cv_mutex_;
    std::condition_variable     eviction_cv_;
};

// ==========================================================================
// Block list (post-throttle persistent block)
// ==========================================================================

class block_list {
public:
    struct block_entry {
        rate_limit_key  key;
        time_point      blocked_at;
        time_point      expires_at;
        std::string     reason;
    };

    void add(const rate_limit_key& key, duration_ms duration,
             std::string_view reason)
    {
        std::unique_lock lk(mutex_);
        auto now = wall_clock_cache::instance().now();
        block_entry entry{key, now, now + duration, std::string(reason)};
        blocks_[key] = std::move(entry);
    }

    bool is_blocked(const rate_limit_key& key) const {
        std::shared_lock lk(mutex_);
        auto it = blocks_.find(key);
        if (it == blocks_.end()) return false;
        auto now = wall_clock_cache::instance().now();
        if (now >= it->second.expires_at) return false; // expired
        return true;
    }

    std::optional<block_entry> get(const rate_limit_key& key) const {
        std::shared_lock lk(mutex_);
        auto it = blocks_.find(key);
        if (it == blocks_.end()) return std::nullopt;
        return it->second;
    }

    void purge_expired() {
        std::unique_lock lk(mutex_);
        auto now = wall_clock_cache::instance().now();
        for (auto it = blocks_.begin(); it != blocks_.end(); ) {
            if (now >= it->second.expires_at)
                it = blocks_.erase(it);
            else
                ++it;
        }
    }

    int64_t size() const {
        std::shared_lock lk(mutex_);
        return static_cast<int64_t>(blocks_.size());
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<rate_limit_key, block_entry> blocks_;
};

// ==========================================================================
// Cost resolver: per-endpoint or default cost
// ==========================================================================

class cost_resolver {
public:
    cost_resolver(const rate_limit_rule& rule) : rule_(rule) {}

    int64_t resolve(std::string_view endpoint) const {
        auto it = rule_.endpoint_costs.find(std::string(endpoint));
        if (it != rule_.endpoint_costs.end()) return it->second;
        return rule_.default_cost;
    }

private:
    const rate_limit_rule& rule_;
};

} // namespace detail

// ==========================================================================
// Public API types
// ==========================================================================

using detail::strategy;
using detail::strategy_name;
using detail::strategy_from_string;
using detail::limit_result;
using detail::rate_limit_decision;
using detail::rate_limit_key;
using detail::key_type;
using detail::rate_limit_rule;
using detail::rate_limit_metrics;
using detail::eviction_policy;
using detail::eviction_config;

using detail::token_bucket_config;
using detail::sliding_window_log_config;
using detail::sliding_window_counter_config;
using detail::fixed_window_config;
using detail::leaky_bucket_config;
using detail::strategy_config;

using detail::duration_ns;
using detail::duration_us;
using detail::duration_ms;
using detail::duration_s;
using detail::time_point;
using detail::clock_type;

using detail::token_bucket_state;
using detail::sliding_window_log_state;
using detail::sliding_window_counter_state;
using detail::fixed_window_state;
using detail::leaky_bucket_state;

using detail::bucket_state;
using detail::bucket_variant;
using detail::rate_limit_store;
using detail::block_list;
using detail::cost_resolver;

// ==========================================================================
// Main middleware class
// ==========================================================================

class rate_limit_middleware {
public:
    // -----------------------------------------------------------------------
    // Construction
    // -----------------------------------------------------------------------

    rate_limit_middleware() {
        store_ = std::make_shared<detail::rate_limit_store>();
    }

    explicit rate_limit_middleware(const eviction_config& ec) {
        store_ = std::make_shared<detail::rate_limit_store>(ec);
        store_->start_eviction_thread();
    }

    ~rate_limit_middleware() {
        if (store_) store_->stop_eviction_thread();
    }

    // Non-copyable, movable
    rate_limit_middleware(const rate_limit_middleware&) = delete;
    rate_limit_middleware& operator=(const rate_limit_middleware&) = delete;
    rate_limit_middleware(rate_limit_middleware&&) = default;
    rate_limit_middleware& operator=(rate_limit_middleware&&) = default;

    // -----------------------------------------------------------------------
    // Rule management
    // -----------------------------------------------------------------------

    /// Add a rate-limit rule. Rules are evaluated in priority order (lower first).
    /// Returns rule index for later removal.
    int add_rule(const rate_limit_rule& rule) {
        std::unique_lock lk(rules_mutex_);
        int idx = next_rule_id_++;
        auto inserted = rules_.emplace(idx, rule);
        rebuild_sorted_rules();
        return idx;
    }

    int add_rule(rate_limit_rule&& rule) {
        std::unique_lock lk(rules_mutex_);
        int idx = next_rule_id_++;
        auto inserted = rules_.emplace(idx, std::move(rule));
        rebuild_sorted_rules();
        return idx;
    }

    bool remove_rule(int rule_id) {
        std::unique_lock lk(rules_mutex_);
        auto it = rules_.find(rule_id);
        if (it == rules_.end()) return false;
        rules_.erase(it);
        rebuild_sorted_rules();
        return true;
    }

    void clear_rules() {
        std::unique_lock lk(rules_mutex_);
        rules_.clear();
        sorted_rules_.clear();
    }

    std::vector<rate_limit_rule> get_rules() const {
        std::shared_lock lk(rules_mutex_);
        return sorted_rules_;
    }

    // -----------------------------------------------------------------------
    // Decision: check a request against all matching rules
    // -----------------------------------------------------------------------

    /// Check a request given its IP, optional user, endpoint path, and cost.
    /// Returns the most restrictive decision across all matching rules.
    rate_limit_decision check(std::string_view ip,
                               std::string_view user,
                               std::string_view endpoint,
                               int64_t cost = 1,
                               std::string_view custom_label = "")
    {
        rate_limit_decision final_decision;
        final_decision.result    = limit_result::allowed;
        final_decision.remaining = std::numeric_limits<int64_t>::max();
        final_decision.limit     = std::numeric_limits<int64_t>::max();

        auto rules = get_sorted_rules();

        for (auto& rule : rules) {
            if (!rule.enabled) continue;

            // Check endpoint pattern
            if (!rule.path_patterns_raw.empty()) {
                bool matched = false;
                std::string ep_str(endpoint);
                for (auto& pat : rule.path_patterns_raw) {
                    try {
                        std::regex re(pat);
                        if (std::regex_match(ep_str, re)) {
                            matched = true;
                            break;
                        }
                    } catch (...) {
                        // Skip invalid patterns
                    }
                }
                if (!matched) continue;
            }

            int64_t effective_cost = cost > 0 ? cost : rule.default_cost;
            if (effective_cost <= 0) effective_cost = 1;

            // Build key
            rate_limit_key key = build_key(rule.ktype, ip, user, endpoint,
                                            custom_label);

            // Check block list first
            if (rule.block_duration.count() > 0 && block_list_.is_blocked(key)) {
                auto blk_entry = block_list_.get(key);
                rate_limit_decision blocked;
                blocked.result     = limit_result::blocked;
                blocked.remaining  = 0;
                blocked.limit      = 0;
                if (blk_entry) {
                    auto now = detail::wall_clock_cache::instance().now();
                    auto remain = blk_entry->expires_at - now;
                    blocked.retry_after = std::chrono::duration_cast<duration_ms>(remain);
                    blocked.reason = blk_entry->reason;
                }
                metrics_.record(limit_result::blocked);
                return blocked;
            }

            // Dispatch to strategy
            auto decision = dispatch_check(rule, key, effective_cost);

            // If blocked/throttled and block_duration set, add to block list
            if (decision.result != limit_result::allowed
                && rule.block_duration.count() > 0)
            {
                block_list_.add(key, rule.block_duration,
                                std::string(decision.reason));
                if (rule.block_duration.count() > 0 && decision.result == limit_result::throttled) {
                    decision.result = limit_result::blocked;
                }
            }

            metrics_.record(decision.result);

            // Merge: more restrictive wins
            if (decision.result != limit_result::allowed) {
                final_decision = decision;
                // Short-circuit: once blocked/throttled, don't check further
                // (more restrictive = block > throttle > allowed)
            } else {
                final_decision.remaining = std::min(final_decision.remaining,
                                                     decision.remaining);
                final_decision.limit     = std::min(final_decision.limit,
                                                     decision.limit);
                if (decision.reset_in < final_decision.reset_in
                    || final_decision.reset_in.count() == 0)
                {
                    final_decision.reset_in = decision.reset_in;
                }
            }
        }

        return final_decision;
    }

    /// Convenience overload
    rate_limit_decision check(std::string_view ip, std::string_view endpoint) {
        return check(ip, "", endpoint, 1, "");
    }

    // -----------------------------------------------------------------------
    // Metrics & monitoring
    // -----------------------------------------------------------------------

    const rate_limit_metrics& metrics() const noexcept { return metrics_; }

    int64_t active_buckets() const { return store_->size(); }
    int64_t blocked_count() const { return block_list_.size(); }

    /// Dump JSON-ish metrics string
    std::string metrics_json() const {
        auto& m = metrics_;
        std::ostringstream oss;
        oss << "{\"total_decisions\":" << m.total_decisions.load()
            << ",\"total_allowed\":" << m.total_allowed.load()
            << ",\"total_throttled\":" << m.total_throttled.load()
            << ",\"total_blocked\":" << m.total_blocked.load()
            << ",\"total_errors\":" << m.total_errors.load()
            << ",\"active_buckets\":" << active_buckets()
            << ",\"evicted_buckets\":" << m.evicted_buckets.load()
            << ",\"blocked_now\":" << blocked_count()
            << "}";
        return oss.str();
    }

    /// Reset all metrics
    void reset_metrics() {
        metrics_.total_decisions.store(0);
        metrics_.total_allowed.store(0);
        metrics_.total_throttled.store(0);
        metrics_.total_blocked.store(0);
        metrics_.total_errors.store(0);
        metrics_.evicted_buckets.store(0);
    }

    // -----------------------------------------------------------------------
    // Store access (for testing / direct manipulation)
    // -----------------------------------------------------------------------

    std::shared_ptr<detail::rate_limit_store> store() { return store_; }
    detail::block_list& block_list() { return block_list_; }

    // -----------------------------------------------------------------------
    // Eviction control
    // -----------------------------------------------------------------------

    void set_eviction_config(const eviction_config& ec) {
        store_->stop_eviction_thread();
        // Create new store with new config — move buckets?
        // For simplicity, set the config and restart thread.
        // Real impl would migrate.
        eviction_config_ = ec;
        store_->start_eviction_thread();
    }

    void evict_now(int64_t count) {
        store_->evict(count);
        block_list_.purge_expired();
    }

    // -----------------------------------------------------------------------
    // Serialisation: load / save rules as JSON
    // -----------------------------------------------------------------------

    std::string rules_to_json() const {
        auto rules = get_rules();
        std::ostringstream oss;
        oss << "[\n";
        for (std::size_t i = 0; i < rules.size(); ++i) {
            if (i > 0) oss << ",\n";
            oss << rule_to_json(rules[i]);
        }
        oss << "\n]";
        return oss.str();
    }

    static std::string rule_to_json(const rate_limit_rule& r) {
        std::ostringstream oss;
        oss << "  {\n"
            << "    \"name\": \"" << escape_json(r.name) << "\",\n"
            << "    \"strategy\": \"" << strategy_name(r.strat) << "\",\n"
            << "    \"key_type\": \"" << key_type_name(r.ktype) << "\",\n"
            << "    \"enabled\": " << (r.enabled ? "true" : "false") << ",\n"
            << "    \"priority\": " << r.priority << ",\n"
            << "    \"default_cost\": " << r.default_cost << ",\n";

        // Strategy-specific config
        std::visit([&](const auto& cfg) {
            using T = std::decay_t<decltype(cfg)>;
            if constexpr (std::is_same_v<T, token_bucket_config>) {
                oss << "    \"capacity\": " << cfg.capacity << ",\n"
                    << "    \"refill_rate\": " << cfg.refill_rate << ",\n"
                    << "    \"refill_period_ms\": " << cfg.refill_period_ms << ",\n"
                    << "    \"initial_tokens\": " << cfg.initial_tokens << ",\n"
                    << "    \"cost_per_request\": " << cfg.cost_per_request << ",\n"
                    << "    \"allow_burst\": " << (cfg.allow_burst ? "true" : "false") << ",\n";
            } else if constexpr (std::is_same_v<T, sliding_window_log_config>) {
                oss << "    \"max_requests\": " << cfg.max_requests << ",\n"
                    << "    \"window_size_ms\": " << cfg.window_size.count() << ",\n";
            } else if constexpr (std::is_same_v<T, sliding_window_counter_config>) {
                oss << "    \"max_requests\": " << cfg.max_requests << ",\n"
                    << "    \"window_size_ms\": " << cfg.window_size.count() << ",\n"
                    << "    \"sub_window_count\": " << cfg.sub_window_count << ",\n";
            } else if constexpr (std::is_same_v<T, fixed_window_config>) {
                oss << "    \"max_requests\": " << cfg.max_requests << ",\n"
                    << "    \"window_size_ms\": " << cfg.window_size.count() << ",\n";
            } else if constexpr (std::is_same_v<T, leaky_bucket_config>) {
                oss << "    \"capacity\": " << cfg.capacity << ",\n"
                    << "    \"outflow_rate\": " << cfg.outflow_rate << ",\n"
                    << "    \"outflow_period_ms\": " << cfg.outflow_period.count() << ",\n";
            }
        }, r.config);

        oss << "    \"path_patterns\": [";
        for (std::size_t j = 0; j < r.path_patterns_raw.size(); ++j) {
            if (j > 0) oss << ", ";
            oss << "\"" << escape_json(r.path_patterns_raw[j]) << "\"";
        }
        oss << "],\n";

        oss << "    \"block_duration_ms\": " << r.block_duration.count() << ",\n"
            << "    \"description\": \"" << escape_json(r.description) << "\"\n"
            << "  }";
        return oss.str();
    }

    // -----------------------------------------------------------------------
    // Configuration loading helpers
    // -----------------------------------------------------------------------

    /// Configure common preset: "strict_api", "relaxed_web", "login_protect"
    void apply_preset(std::string_view preset_name) {
        if (preset_name == "strict_api") {
            rate_limit_rule r;
            r.name     = "strict_api_default";
            r.strat    = strategy::token_bucket;
            r.ktype    = key_type::ip;
            r.priority = 10;
            r.enabled  = true;
            r.default_cost = 1;
            r.block_duration = duration_ms{60'000};
            r.description = "Strict API rate limit: 100 req/s with burst";
            token_bucket_config cfg;
            cfg.capacity       = 200;
            cfg.refill_rate    = 100;
            cfg.refill_period_ms = 100;
            cfg.initial_tokens = 200;
            r.config = std::move(cfg);
            add_rule(std::move(r));
        }
        else if (preset_name == "relaxed_web") {
            rate_limit_rule r;
            r.name     = "relaxed_web_default";
            r.strat    = strategy::sliding_window_counter;
            r.ktype    = key_type::ip;
            r.priority = 50;
            r.enabled  = true;
            r.default_cost = 1;
            sliding_window_counter_config cfg;
            cfg.max_requests    = 1000;
            cfg.window_size     = duration_ms{60'000};
            cfg.sub_window_count = 10;
            r.config = std::move(cfg);
            add_rule(std::move(r));
        }
        else if (preset_name == "login_protect") {
            rate_limit_rule r;
            r.name     = "login_protection";
            r.strat    = strategy::fixed_window;
            r.ktype    = key_type::composite;
            r.priority = 1;
            r.enabled  = true;
            r.default_cost = 1;
            r.block_duration = duration_ms{300'000};
            r.description = "Login brute-force protection: 5 attempts per minute";
            fixed_window_config cfg;
            cfg.max_requests = 5;
            cfg.window_size  = duration_ms{60'000};
            r.config = std::move(cfg);
            r.path_patterns_raw = {"/api/login", "/api/auth"};
            add_rule(std::move(r));
        }
        else if (preset_name == "per_user_tiered") {
            // High-priority user-based token bucket
            rate_limit_rule r;
            r.name     = "user_tiered_limit";
            r.strat    = strategy::token_bucket;
            r.ktype    = key_type::user;
            r.priority = 5;
            r.enabled  = true;
            r.default_cost = 1;
            token_bucket_config cfg;
            cfg.capacity        = 500;
            cfg.refill_rate     = 50;
            cfg.refill_period_ms = 200;
            cfg.initial_tokens  = 500;
            r.config = std::move(cfg);
            add_rule(std::move(r));
        }
        else if (preset_name == "global_leaky") {
            rate_limit_rule r;
            r.name     = "global_leaky_limit";
            r.strat    = strategy::leaky_bucket;
            r.ktype    = key_type::global;
            r.priority = 100;
            r.enabled  = true;
            r.default_cost = 1;
            leaky_bucket_config cfg;
            cfg.capacity     = 10000;
            cfg.outflow_rate = 2000;
            cfg.outflow_period = duration_ms{100};
            r.config = std::move(cfg);
            r.description = "Global leaky bucket: smooths out traffic spikes";
            add_rule(std::move(r));
        }
    }

private:
    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    static rate_limit_key build_key(key_type ktype,
                                     std::string_view ip,
                                     std::string_view user,
                                     std::string_view endpoint,
                                     std::string_view custom_label)
    {
        rate_limit_key key;
        key.type    = ktype;
        key.ip      = detail::canonicalise_ip(ip);
        key.user    = std::string(user);
        key.endpoint = std::string(endpoint);
        key.custom_label = std::string(custom_label);
        return key;
    }

    rate_limit_decision dispatch_check(const rate_limit_rule& rule,
                                        const rate_limit_key& key,
                                        int64_t cost)
    {
        rate_limit_decision decision;
        decision.result = limit_result::error;

        switch (rule.strat) {
            case strategy::token_bucket: {
                auto& cfg = std::get<token_bucket_config>(rule.config);
                auto& st  = store_->get_or_create<token_bucket_state>(
                    key, strategy::token_bucket, cfg);
                auto [res, remaining] = detail::algorithm::token_bucket_consume(st, cost);
                decision.result     = res;
                decision.remaining  = static_cast<int64_t>(remaining);
                decision.limit      = cfg.capacity;
                decision.retry_after = (res == limit_result::allowed)
                    ? duration_ms{0}
                    : detail::algorithm::token_bucket_retry_after(st, cost);
                decision.reason     = (res == limit_result::allowed)
                    ? "ok" : "token_bucket_rate_limited";
                break;
            }
            case strategy::sliding_window_log: {
                auto& cfg = std::get<sliding_window_log_config>(rule.config);
                auto& st  = store_->get_or_create<sliding_window_log_state>(
                    key, strategy::sliding_window_log, cfg);
                auto res  = detail::algorithm::sliding_window_log_check(st);
                decision.result    = res;
                decision.remaining = cfg.max_requests;
                decision.limit     = cfg.max_requests;
                // approximate retry: wait for oldest entry to expire
                if (res != limit_result::allowed && !st.timestamps.empty()) {
                    auto now = detail::wall_clock_cache::instance().now();
                    auto oldest = st.timestamps.front();
                    auto retry  = cfg.window_size - (now - oldest);
                    decision.retry_after = std::chrono::duration_cast<duration_ms>(retry);
                }
                decision.reason = (res == limit_result::allowed)
                    ? "ok" : "sliding_window_log_rate_limited";
                break;
            }
            case strategy::sliding_window_counter: {
                auto& cfg = std::get<sliding_window_counter_config>(rule.config);
                auto& st  = store_->get_or_create<sliding_window_counter_state>(
                    key, strategy::sliding_window_counter, cfg);
                auto res  = detail::algorithm::sliding_window_counter_check(st);
                decision.result    = res;
                decision.remaining = cfg.max_requests;
                decision.limit     = cfg.max_requests;
                decision.retry_after = duration_ms{cfg.window_size.count() / cfg.sub_window_count};
                decision.reason = (res == limit_result::allowed)
                    ? "ok" : "sliding_window_counter_rate_limited";
                break;
            }
            case strategy::fixed_window: {
                auto& cfg = std::get<fixed_window_config>(rule.config);
                auto& st  = store_->get_or_create<fixed_window_state>(
                    key, strategy::fixed_window, cfg);
                auto res  = detail::algorithm::fixed_window_check(st);
                decision.result    = res;
                decision.remaining = cfg.max_requests - st.counter;
                decision.limit     = cfg.max_requests;
                decision.retry_after = detail::algorithm::fixed_window_retry_after(st);
                decision.reset_in = std::chrono::duration_cast<duration_ms>(
                    st.cfg.window_size - (detail::wall_clock_cache::instance().now() - st.window_start));
                decision.reason = (res == limit_result::allowed)
                    ? "ok" : "fixed_window_rate_limited";
                break;
            }
            case strategy::leaky_bucket: {
                auto& cfg = std::get<leaky_bucket_config>(rule.config);
                auto& st  = store_->get_or_create<leaky_bucket_state>(
                    key, strategy::leaky_bucket, cfg);
                auto [res, water] = detail::algorithm::leaky_bucket_check(st, cost);
                decision.result    = res;
                decision.remaining = cfg.capacity - static_cast<int64_t>(water);
                decision.limit     = cfg.capacity;
                decision.retry_after = detail::algorithm::leaky_bucket_retry_after(st, cost);
                decision.reason = (res == limit_result::allowed)
                    ? "ok" : "leaky_bucket_rate_limited";
                break;
            }
        }

        return decision;
    }

    std::vector<rate_limit_rule> get_sorted_rules() const {
        std::shared_lock lk(rules_mutex_);
        return sorted_rules_;
    }

    void rebuild_sorted_rules() {
        sorted_rules_.clear();
        sorted_rules_.reserve(rules_.size());
        for (auto& [id, rule] : rules_) {
            sorted_rules_.push_back(rule);
        }
        std::sort(sorted_rules_.begin(), sorted_rules_.end(),
                  [](const rate_limit_rule& a, const rate_limit_rule& b) {
                      return a.priority < b.priority;
                  });
    }

    static const char* key_type_name(key_type kt) noexcept {
        switch (kt) {
            case key_type::ip:        return "ip";
            case key_type::user:      return "user";
            case key_type::composite: return "composite";
            case key_type::global:    return "global";
            case key_type::endpoint:  return "endpoint";
            case key_type::custom:    return "custom";
        }
        return "unknown";
    }

    static std::string escape_json(std::string_view sv) {
        std::string out;
        out.reserve(sv.size() + 16);
        for (char c : sv) {
            switch (c) {
                case '"':  out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n";  break;
                case '\r': out += "\\r";  break;
                case '\t': out += "\\t";  break;
                default:   out.push_back(c);
            }
        }
        return out;
    }

    // -----------------------------------------------------------------------
    // Data
    // -----------------------------------------------------------------------

    std::shared_ptr<detail::rate_limit_store> store_;
    detail::block_list                        block_list_;
    rate_limit_metrics                        metrics_;
    eviction_config                           eviction_config_;

    mutable std::shared_mutex                 rules_mutex_;
    std::map<int, rate_limit_rule>            rules_;
    std::vector<rate_limit_rule>              sorted_rules_;
    int                                       next_rule_id_{1};
};

// ==========================================================================
// Rate-limit header injection helper
// ==========================================================================

/// Produce standard rate-limit HTTP headers from a decision.
struct rate_limit_headers {
    std::string limit;
    std::string remaining;
    std::string reset;
    std::string retry_after;
};

inline rate_limit_headers make_headers(const rate_limit_decision& d) {
    rate_limit_headers h;
    if (d.limit >= 0)          h.limit      = std::to_string(d.limit);
    if (d.remaining >= 0)      h.remaining  = std::to_string(d.remaining);
    if (d.reset_in.count() > 0) h.reset      = std::to_string(d.reset_in.count());
    if (d.retry_after.count() > 0) h.retry_after = std::to_string(d.retry_after.count());
    return h;
}

// ==========================================================================
// Pre-built rule factories
// ==========================================================================

namespace rules {

inline rate_limit_rule per_ip_token_bucket(
    std::string name,
    int64_t capacity, int64_t refill_per_sec,
    int priority = 10,
    std::vector<std::string> paths = {})
{
    rate_limit_rule r;
    r.name      = std::move(name);
    r.strat     = strategy::token_bucket;
    r.ktype     = key_type::ip;
    r.priority  = priority;
    r.enabled   = true;
    r.path_patterns_raw = std::move(paths);
    token_bucket_config cfg;
    cfg.capacity        = capacity;
    cfg.refill_rate     = refill_per_sec;
    cfg.refill_period_ms = 100;
    cfg.initial_tokens  = capacity;
    cfg.cost_per_request = 1;
    r.config = std::move(cfg);
    return r;
}

inline rate_limit_rule per_user_fixed_window(
    std::string name,
    int64_t max_req, duration_ms window,
    int priority = 5,
    std::vector<std::string> paths = {})
{
    rate_limit_rule r;
    r.name      = std::move(name);
    r.strat     = strategy::fixed_window;
    r.ktype     = key_type::user;
    r.priority  = priority;
    r.enabled   = true;
    r.path_patterns_raw = std::move(paths);
    fixed_window_config cfg;
    cfg.max_requests = max_req;
    cfg.window_size  = window;
    r.config = std::move(cfg);
    return r;
}

inline rate_limit_rule per_ip_sliding_window(
    std::string name,
    int64_t max_req, duration_ms window, int64_t sub_windows = 6,
    int priority = 20,
    std::vector<std::string> paths = {})
{
    rate_limit_rule r;
    r.name      = std::move(name);
    r.strat     = strategy::sliding_window_counter;
    r.ktype     = key_type::ip;
    r.priority  = priority;
    r.enabled   = true;
    r.path_patterns_raw = std::move(paths);
    sliding_window_counter_config cfg;
    cfg.max_requests     = max_req;
    cfg.window_size      = window;
    cfg.sub_window_count = sub_windows;
    r.config = std::move(cfg);
    return r;
}

inline rate_limit_rule global_leaky_bucket(
    std::string name,
    int64_t capacity, int64_t outflow_per_sec,
    int priority = 100)
{
    rate_limit_rule r;
    r.name      = std::move(name);
    r.strat     = strategy::leaky_bucket;
    r.ktype     = key_type::global;
    r.priority  = priority;
    r.enabled   = true;
    leaky_bucket_config cfg;
    cfg.capacity      = capacity;
    cfg.outflow_rate  = outflow_per_sec;
    cfg.outflow_period = duration_ms{100};
    r.config = std::move(cfg);
    return r;
}

inline rate_limit_rule composite_login_protect(
    std::string name,
    int64_t max_attempts, duration_ms window, duration_ms block_for)
{
    rate_limit_rule r;
    r.name      = std::move(name);
    r.strat     = strategy::fixed_window;
    r.ktype     = key_type::composite;
    r.priority  = 1;
    r.enabled   = true;
    r.block_duration = block_for;
    r.path_patterns_raw = {"/api/login", "/api/auth/login", "/api/signin"};
    fixed_window_config cfg;
    cfg.max_requests = max_attempts;
    cfg.window_size  = window;
    r.config = std::move(cfg);
    return r;
}

} // namespace rules

// ==========================================================================
// Testing / debugging helpers
// ==========================================================================

inline void print_decision(const rate_limit_decision& d, std::ostream& os = std::cout) {
    const char* result_str = "unknown";
    switch (d.result) {
        case limit_result::allowed:   result_str = "ALLOWED";   break;
        case limit_result::throttled: result_str = "THROTTLED"; break;
        case limit_result::blocked:   result_str = "BLOCKED";   break;
        case limit_result::error:     result_str = "ERROR";     break;
    }
    os << "decision: " << result_str
       << " | remaining=" << d.remaining
       << " | limit=" << d.limit
       << " | retry_after=" << d.retry_after.count() << "ms"
       << " | reset_in=" << d.reset_in.count() << "ms"
       << " | reason=" << d.reason << "\n";
}

// ==========================================================================
// Benchmark / stress-test stub
// ==========================================================================

struct benchmark_result {
    int64_t total_checks;
    int64_t allowed;
    int64_t throttled;
    int64_t blocked;
    duration_ms elapsed;
    double   checks_per_sec;
};

inline benchmark_result run_benchmark(
    rate_limit_middleware& mw,
    int64_t num_checks,
    int thread_count = 4)
{
    std::vector<std::thread> threads;
    std::atomic<int64_t> checks_done{0};
    std::atomic<int64_t> local_allowed{0};
    std::atomic<int64_t> local_throttled{0};
    std::atomic<int64_t> local_blocked{0};

    auto start = detail::high_res_clock::now();

    auto worker = [&](int tid) {
        std::string ip = "192.168.1." + std::to_string(tid % 255);
        std::string user = "user_" + std::to_string(tid);
        for (int64_t i = 0; i < num_checks / thread_count; ++i) {
            auto d = mw.check(ip, user, "/api/test", 1, "");
            switch (d.result) {
                case limit_result::allowed:   local_allowed.fetch_add(1); break;
                case limit_result::throttled: local_throttled.fetch_add(1); break;
                case limit_result::blocked:   local_blocked.fetch_add(1); break;
                default: break;
            }
            checks_done.fetch_add(1);
        }
    };

    for (int t = 0; t < thread_count; ++t) {
        threads.emplace_back(worker, t);
    }
    for (auto& t : threads) t.join();

    auto end = detail::high_res_clock::now();
    auto elapsed = std::chrono::duration_cast<duration_ms>(end - start);

    benchmark_result br;
    br.total_checks   = checks_done.load();
    br.allowed        = local_allowed.load();
    br.throttled      = local_throttled.load();
    br.blocked        = local_blocked.load();
    br.elapsed        = elapsed;
    br.checks_per_sec = br.total_checks / (static_cast<double>(elapsed.count()) / 1000.0);
    return br;
}

inline void print_benchmark(const benchmark_result& br, std::ostream& os = std::cout) {
    os << "Benchmark: " << br.total_checks << " checks in "
       << br.elapsed.count() << " ms = ";
    os.precision(1);
    os << std::fixed << br.checks_per_sec << " checks/sec\n";
    os << "  allowed=" << br.allowed
       << "  throttled=" << br.throttled
       << "  blocked=" << br.blocked << "\n";
}

// ==========================================================================
// Configuration file loader
// ==========================================================================

/// Load rate-limit rules from a simple key-value config file.
/// Format (one rule per block, separated by blank line):
///   name=my_rule
///   strategy=token_bucket
///   key_type=ip
///   priority=10
///   capacity=200
///   refill_rate=100
///   paths=/api/v1/.*,/api/v2/.*
///
/// Returns number of rules loaded, or -1 on error.
inline int load_rules_from_file(rate_limit_middleware& mw,
                                 const std::filesystem::path& filepath,
                                 std::string& error_out)
{
    std::ifstream ifs(filepath);
    if (!ifs.is_open()) {
        error_out = std::string("Cannot open file: ") + filepath.string();
        return -1;
    }

    std::string line;
    std::map<std::string, std::string> current;
    int loaded = 0;

    auto flush_rule = [&]() -> bool {
        if (current.empty()) return true;
        rate_limit_rule r;

        auto find_or = [&](const std::string& key, const std::string& def) -> std::string {
            auto it = current.find(key);
            return (it != current.end()) ? it->second : def;
        };

        r.name = find_or("name", "unnamed");
        r.enabled = find_or("enabled", "true") == "true";
        r.priority = std::stoi(find_or("priority", "10"));
        r.default_cost = std::stoi(find_or("default_cost", "1"));

        // key_type
        auto kt_str = find_or("key_type", "ip");
        if (kt_str == "user") r.ktype = key_type::user;
        else if (kt_str == "composite") r.ktype = key_type::composite;
        else if (kt_str == "global") r.ktype = key_type::global;
        else r.ktype = key_type::ip;

        // strategy
        auto s_str = find_or("strategy", "token_bucket");
        auto s = strategy_from_string(s_str);
        if (!s) {
            error_out = std::string("Unknown strategy: ") + s_str;
            return false;
        }
        r.strat = *s;

        // Block duration
        if (current.count("block_duration_ms")) {
            r.block_duration = duration_ms{std::stoll(current["block_duration_ms"])};
        }

        // Paths
        if (current.count("paths")) {
            auto paths_str = current["paths"];
            std::istringstream pss(paths_str);
            std::string token;
            while (std::getline(pss, token, ',')) {
                if (!token.empty()) r.path_patterns_raw.push_back(token);
            }
        }

        // Strategy-specific
        switch (r.strat) {
            case strategy::token_bucket: {
                token_bucket_config cfg;
                if (current.count("capacity"))    cfg.capacity = std::stoll(current["capacity"]);
                if (current.count("refill_rate")) cfg.refill_rate = std::stoll(current["refill_rate"]);
                if (current.count("refill_period_ms"))
                    cfg.refill_period_ms = std::stoll(current["refill_period_ms"]);
                if (current.count("initial_tokens"))
                    cfg.initial_tokens = std::stoll(current["initial_tokens"]);
                if (current.count("cost_per_request"))
                    cfg.cost_per_request = std::stoll(current["cost_per_request"]);
                r.config = std::move(cfg);
                break;
            }
            case strategy::sliding_window_log:
            case strategy::sliding_window_counter:
            case strategy::fixed_window: {
                // common fields
                int64_t max_req = 100;
                int64_t win_ms  = 60'000;
                if (current.count("max_requests")) max_req = std::stoll(current["max_requests"]);
                if (current.count("window_size_ms")) win_ms = std::stoll(current["window_size_ms"]);

                if (r.strat == strategy::sliding_window_log) {
                    sliding_window_log_config cfg;
                    cfg.max_requests = max_req;
                    cfg.window_size = duration_ms{win_ms};
                    r.config = std::move(cfg);
                } else if (r.strat == strategy::sliding_window_counter) {
                    sliding_window_counter_config cfg;
                    cfg.max_requests = max_req;
                    cfg.window_size = duration_ms{win_ms};
                    if (current.count("sub_window_count"))
                        cfg.sub_window_count = std::stoll(current["sub_window_count"]);
                    r.config = std::move(cfg);
                } else {
                    fixed_window_config cfg;
                    cfg.max_requests = max_req;
                    cfg.window_size = duration_ms{win_ms};
                    r.config = std::move(cfg);
                }
                break;
            }
            case strategy::leaky_bucket: {
                leaky_bucket_config cfg;
                if (current.count("capacity")) cfg.capacity = std::stoll(current["capacity"]);
                if (current.count("outflow_rate")) cfg.outflow_rate = std::stoll(current["outflow_rate"]);
                if (current.count("outflow_period_ms"))
                    cfg.outflow_period = duration_ms{std::stoll(current["outflow_period_ms"])};
                r.config = std::move(cfg);
                break;
            }
        }

        mw.add_rule(std::move(r));
        ++loaded;
        current.clear();
        return true;
    };

    while (std::getline(ifs, line)) {
        // Trim
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty() || line[0] == '#') {
            if (!current.empty()) {
                if (!flush_rule()) return -1;
            }
            continue;
        }
        auto eq = line.find('=');
        if (eq != std::string::npos) {
            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);
            // trim key/val
            key.erase(key.find_last_not_of(" \t") + 1);
            val.erase(0, val.find_first_not_of(" \t"));
            current[key] = val;
        }
    }
    if (!current.empty()) {
        if (!flush_rule()) return -1;
    }
    return loaded;
}

// ==========================================================================
// Convenience: create a fully configured middleware in one call
// ==========================================================================

struct middleware_options {
    eviction_config                 eviction;
    std::vector<rate_limit_rule>    rules;
    std::vector<std::string>        presets;
    bool                            start_eviction_thread{true};
};

inline std::unique_ptr<rate_limit_middleware> create_middleware(
    const middleware_options& opts)
{
    auto mw = std::make_unique<rate_limit_middleware>(opts.eviction);
    for (auto& preset : opts.presets) {
        mw->apply_preset(preset);
    }
    for (auto& rule : opts.rules) {
        mw->add_rule(rule);
    }
    if (opts.start_eviction_thread) {
        mw->store()->start_eviction_thread();
    }
    return mw;
}

// ==========================================================================
// Statistics collector (periodic snapshotting)
// ==========================================================================

class rate_limit_statistics {
public:
    struct snapshot {
        time_point      timestamp;
        rate_limit_metrics metrics;
        int64_t         active_buckets;
        int64_t         blocked_entries;
        double          throttle_rate;
    };

    explicit rate_limit_statistics(rate_limit_middleware* mw)
        : mw_(mw) {}

    snapshot capture() const {
        snapshot s;
        s.timestamp       = detail::wall_clock_cache::instance().now();
        auto& m           = mw_->metrics();
        s.metrics.total_decisions.store(m.total_decisions.load());
        s.metrics.total_allowed.store(m.total_allowed.load());
        s.metrics.total_throttled.store(m.total_throttled.load());
        s.metrics.total_blocked.store(m.total_blocked.load());
        s.metrics.total_errors.store(m.total_errors.load());
        s.metrics.active_buckets.store(m.active_buckets.load());
        s.metrics.evicted_buckets.store(m.evicted_buckets.load());
        s.active_buckets  = mw_->active_buckets();
        s.blocked_entries = mw_->blocked_count();
        int64_t total = s.metrics.total_decisions.load();
        int64_t throttled = s.metrics.total_throttled.load();
        int64_t blocked = s.metrics.total_blocked.load();
        s.throttle_rate = (total > 0)
            ? static_cast<double>(throttled + blocked) / static_cast<double>(total)
            : 0.0;
        return s;
    }

    std::string snapshot_json(const snapshot& s) const {
        std::ostringstream oss;
        oss << "{\"total_decisions\":" << s.metrics.total_decisions.load()
            << ",\"total_allowed\":" << s.metrics.total_allowed.load()
            << ",\"total_throttled\":" << s.metrics.total_throttled.load()
            << ",\"total_blocked\":" << s.metrics.total_blocked.load()
            << ",\"active_buckets\":" << s.active_buckets
            << ",\"blocked_entries\":" << s.blocked_entries
            << ",\"throttle_rate\":";
        oss.precision(4);
        oss << std::fixed << s.throttle_rate << "}";
        return oss.str();
    }

private:
    rate_limit_middleware* mw_;
};

// ==========================================================================
// Dynamic rule evaluator (for scripting / embedded Lua-like logic)
// ==========================================================================

class dynamic_rule_evaluator {
public:
    using eval_func = std::function<std::optional<rate_limit_decision>(
        std::string_view ip,
        std::string_view user,
        std::string_view endpoint,
        const std::map<std::string, std::string>& headers)>;

    void register_evaluator(std::string name, eval_func fn) {
        std::unique_lock lk(mutex_);
        evaluators_[std::move(name)] = std::move(fn);
    }

    void unregister_evaluator(const std::string& name) {
        std::unique_lock lk(mutex_);
        evaluators_.erase(name);
    }

    std::optional<rate_limit_decision> evaluate(
        std::string_view ip,
        std::string_view user,
        std::string_view endpoint,
        const std::map<std::string, std::string>& headers) const
    {
        std::shared_lock lk(mutex_);
        for (auto& [name, fn] : evaluators_) {
            auto d = fn(ip, user, endpoint, headers);
            if (d.has_value()) return d;
        }
        return std::nullopt;
    }

private:
    mutable std::shared_mutex mutex_;
    std::map<std::string, eval_func> evaluators_;  // ordered by name
};

// ==========================================================================
// Warmup / pre-allocation helper
// ==========================================================================

inline void warmup_store(detail::rate_limit_store& store,
                          const std::vector<rate_limit_key>& keys,
                          const token_bucket_config& cfg)
{
    for (auto& key : keys) {
        store.get_or_create<detail::token_bucket_state>(
            key, strategy::token_bucket, cfg);
    }
}

// ==========================================================================
// Utility: human-readable duration
// ==========================================================================

inline std::string duration_to_string(duration_ms d) {
    auto total_sec = d.count() / 1000;
    auto mins = total_sec / 60;
    auto secs = total_sec % 60;
    if (mins > 0)
        return std::to_string(mins) + "m" + std::to_string(secs) + "s";
    return std::to_string(secs) + "s";
}

// ==========================================================================
// Utility: parse duration string like "5m", "30s", "2h"
// ==========================================================================

inline std::optional<duration_ms> parse_duration(std::string_view sv) {
    if (sv.empty()) return std::nullopt;
    int64_t multiplier = 1;
    std::size_t pos = sv.size();

    // Suffix
    if (sv.back() == 's' || sv.back() == 'S') {
        multiplier = 1000;
        --pos;
    } else if (sv.size() >= 2 && (sv.substr(sv.size() - 2) == "ms" || sv.substr(sv.size() - 2) == "MS")) {
        multiplier = 1;
        pos -= 2;
    } else if (sv.back() == 'm' || sv.back() == 'M') {
        multiplier = 60'000;
        --pos;
    } else if (sv.back() == 'h' || sv.back() == 'H') {
        multiplier = 3'600'000;
        --pos;
    }

    std::string_view num_part = sv.substr(0, pos);
    int64_t val = 0;
    auto [ptr, ec] = std::from_chars(num_part.data(), num_part.data() + num_part.size(), val);
    if (ec == std::errc{}) {
        return duration_ms{val * multiplier};
    }
    return std::nullopt;
}

// ==========================================================================
// Integration: callbacks / hooks for server frameworks
// ==========================================================================

/// Pre-request hook signature
using pre_request_hook = std::function<std::optional<rate_limit_decision>(
    std::string_view method,
    std::string_view path,
    std::string_view ip,
    std::string_view user)>;

/// Post-decision hook (for logging, alerting)
using post_decision_hook = std::function<void(
    const rate_limit_decision&,
    std::string_view ip,
    std::string_view path)>;

class hook_registry {
public:
    void add_pre_request(pre_request_hook h) {
        std::unique_lock lk(mutex_);
        pre_hooks_.push_back(std::move(h));
    }

    void add_post_decision(post_decision_hook h) {
        std::unique_lock lk(mutex_);
        post_hooks_.push_back(std::move(h));
    }

    void run_pre_hooks(std::string_view method, std::string_view path,
                       std::string_view ip, std::string_view user,
                       std::optional<rate_limit_decision>& early_out) const
    {
        std::shared_lock lk(mutex_);
        for (auto& h : pre_hooks_) {
            auto d = h(method, path, ip, user);
            if (d.has_value()) {
                early_out = std::move(d);
                return;
            }
        }
    }

    void run_post_hooks(const rate_limit_decision& d,
                        std::string_view ip,
                        std::string_view path) const
    {
        std::shared_lock lk(mutex_);
        for (auto& h : post_hooks_) {
            h(d, ip, path);
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::vector<pre_request_hook>  pre_hooks_;
    std::vector<post_decision_hook> post_hooks_;
};

// ==========================================================================
// Circuit-breaker integration (pause all rate limiting)
// ==========================================================================

class circuit_breaker {
public:
    enum class state : uint8_t { closed, open, half_open };

    circuit_breaker() = default;

    void open() {
        state_.store(state::open, std::memory_order_release);
        opened_at_.store(detail::wall_clock_cache::instance().now(),
                         std::memory_order_relaxed);
    }

    void close() {
        state_.store(state::closed, std::memory_order_release);
    }

    void half_open() {
        state_.store(state::half_open, std::memory_order_release);
    }

    state current_state() const {
        return state_.load(std::memory_order_acquire);
    }

    /// If circuit is open, return an "allowed" decision to bypass rate limiting
    std::optional<rate_limit_decision> bypass_decision() const {
        if (state_.load(std::memory_order_acquire) == state::open) {
            rate_limit_decision d;
            d.result    = limit_result::allowed;
            d.reason    = "circuit_breaker_open_bypass";
            d.remaining = -1;
            d.limit     = -1;
            return d;
        }
        return std::nullopt;
    }

private:
    std::atomic<state>      state_{state::closed};
    std::atomic<time_point> opened_at_{};
};

// ==========================================================================
// Enhanced middleware with circuit breaker and hooks
// ==========================================================================

class rate_limit_middleware_v2 : public rate_limit_middleware {
public:
    using rate_limit_middleware::rate_limit_middleware;

    /// Check with circuit breaker bypass, pre-hooks, and post-hooks.
    rate_limit_decision check_with_hooks(
        std::string_view method,
        std::string_view path,
        std::string_view ip,
        std::string_view user,
        int64_t cost = 1,
        const std::map<std::string, std::string>& headers = {})
    {
        // Circuit breaker bypass
        if (auto bypass = circuit_breaker_.bypass_decision()) {
            return *bypass;
        }

        // Dynamic evaluators
        if (auto dyn = dynamic_evaluator_.evaluate(ip, user, path, headers)) {
            hooks_.run_post_hooks(*dyn, ip, path);
            return *dyn;
        }

        // Pre-request hooks (can short-circuit)
        std::optional<rate_limit_decision> early;
        hooks_.run_pre_hooks(method, path, ip, user, early);
        if (early.has_value()) {
            hooks_.run_post_hooks(*early, ip, path);
            return *early;
        }

        // Standard check
        auto decision = check(ip, user, path, cost);

        // Post-decision hooks
        hooks_.run_post_hooks(decision, ip, path);

        return decision;
    }

    circuit_breaker& breaker() { return circuit_breaker_; }
    hook_registry& hooks() { return hooks_; }
    dynamic_rule_evaluator& dynamic_evaluator() { return dynamic_evaluator_; }

private:
    circuit_breaker         circuit_breaker_;
    hook_registry           hooks_;
    dynamic_rule_evaluator  dynamic_evaluator_;
};

// ==========================================================================
// Adaptive rate limiting: auto-tune based on system load
// ==========================================================================

class adaptive_rate_limiter {
public:
    struct adaptive_config {
        double  cpu_threshold{0.85};       // fraction of CPU usage
        double  memory_threshold{0.90};    // fraction of memory usage
        double  scale_down_factor{0.5};    // multiply limits by this
        double  scale_up_factor{1.2};
        duration_ms evaluation_interval{5'000};
        int64_t min_capacity{10};
        int64_t max_capacity{1'000'000};
    };

    adaptive_rate_limiter(rate_limit_middleware* mw,
                           const adaptive_config& cfg)
        : mw_(mw), cfg_(cfg) {}

    /// Call periodically with current system metrics.
    void evaluate(double cpu_usage_fraction, double memory_usage_fraction) {
        auto now = detail::wall_clock_cache::instance().now();
        if (now - last_eval_ < cfg_.evaluation_interval) return;
        last_eval_ = now;

        bool under_pressure = (cpu_usage_fraction > cfg_.cpu_threshold)
                           || (memory_usage_fraction > cfg_.memory_threshold);

        if (under_pressure && !scaled_down_) {
            scale_limits(cfg_.scale_down_factor);
            scaled_down_ = true;
        } else if (!under_pressure && scaled_down_) {
            scale_limits(cfg_.scale_up_factor);
            scaled_down_ = false;
        }
    }

    bool is_scaled_down() const noexcept { return scaled_down_; }

private:
    void scale_limits(double factor) {
        auto rules = mw_->get_rules();
        for (auto& rule : rules) {
            // Scale numeric limits
            std::visit([&](auto& cfg) {
                using T = std::decay_t<decltype(cfg)>;
                if constexpr (std::is_same_v<T, token_bucket_config>) {
                    cfg.capacity = clamp_scale(cfg.capacity, factor);
                    cfg.refill_rate = clamp_scale(cfg.refill_rate, factor);
                } else if constexpr (std::is_same_v<T, sliding_window_log_config>) {
                    cfg.max_requests = clamp_scale(cfg.max_requests, factor);
                } else if constexpr (std::is_same_v<T, sliding_window_counter_config>) {
                    cfg.max_requests = clamp_scale(cfg.max_requests, factor);
                } else if constexpr (std::is_same_v<T, fixed_window_config>) {
                    cfg.max_requests = clamp_scale(cfg.max_requests, factor);
                } else if constexpr (std::is_same_v<T, leaky_bucket_config>) {
                    cfg.capacity = clamp_scale(cfg.capacity, factor);
                    cfg.outflow_rate = clamp_scale(cfg.outflow_rate, factor);
                }
            }, rule.config);
            // Remove old rule and re-add
            // (We need rule IDs for this — simplified here)
        }
    }

    int64_t clamp_scale(int64_t val, double factor) const {
        double scaled = static_cast<double>(val) * factor;
        if (scaled < static_cast<double>(cfg_.min_capacity))
            return cfg_.min_capacity;
        if (scaled > static_cast<double>(cfg_.max_capacity))
            return cfg_.max_capacity;
        return static_cast<int64_t>(scaled);
    }

    rate_limit_middleware* mw_;
    adaptive_config        cfg_;
    time_point             last_eval_{};
    bool                   scaled_down_{false};
};

// ==========================================================================
// Rate-limit response builder (for HTTP responses)
// ==========================================================================

struct rate_limit_response {
    int         http_status{200};
    std::string body;
    rate_limit_headers headers;
};

inline rate_limit_response build_response(const rate_limit_decision& d) {
    rate_limit_response resp;
    resp.headers = make_headers(d);

    switch (d.result) {
        case limit_result::allowed:
            resp.http_status = 200;
            resp.body = R"({"status":"ok"})";
            break;
        case limit_result::throttled:
            resp.http_status = 429;
            {
                std::ostringstream b;
                b << "{\"status\":\"throttled\",\"retry_after_ms\":" << d.retry_after.count()
                  << ",\"reason\":\"" << d.reason << "\"}";
                resp.body = b.str();
            }
            break;
        case limit_result::blocked:
            resp.http_status = 429;
            {
                std::ostringstream b;
                b << "{\"status\":\"blocked\",\"retry_after_ms\":" << d.retry_after.count()
                  << ",\"reason\":\"" << d.reason << "\"}";
                resp.body = b.str();
            }
            break;
        case limit_result::error:
            resp.http_status = 500;
            resp.body = R"({"status":"error","reason":"internal_rate_limit_error"})";
            break;
    }
    return resp;
}

// ==========================================================================
// Per-endpoint cost overrides manager
// ==========================================================================

class endpoint_cost_manager {
public:
    void set_cost(std::string endpoint, int64_t cost) {
        std::unique_lock lk(mutex_);
        costs_[std::move(endpoint)] = cost;
    }

    int64_t get_cost(std::string_view endpoint, int64_t default_cost = 1) const {
        std::shared_lock lk(mutex_);
        auto it = costs_.find(std::string(endpoint));
        return (it != costs_.end()) ? it->second : default_cost;
    }

    void clear() {
        std::unique_lock lk(mutex_);
        costs_.clear();
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, int64_t> costs_;
};

// ==========================================================================
// IP whitelist / blacklist
// ==========================================================================

class ip_list {
public:
    enum class mode : uint8_t { whitelist, blacklist };

    explicit ip_list(mode m = mode::whitelist) : mode_(m) {}

    void add(std::string ip_or_cidr) {
        std::unique_lock lk(mutex_);
        entries_.insert(std::move(ip_or_cidr));
    }

    void remove(const std::string& ip_or_cidr) {
        std::unique_lock lk(mutex_);
        entries_.erase(ip_or_cidr);
    }

    bool matches(std::string_view ip) const {
        std::shared_lock lk(mutex_);
        // Exact match or prefix match for CIDR (simplified)
        for (auto& entry : entries_) {
            if (ip == entry) return true;
            // Simple CIDR /24 check
            auto slash = entry.find('/');
            if (slash != std::string::npos) {
                auto prefix = entry.substr(0, slash);
                auto bits   = std::stoi(entry.substr(slash + 1));
                if (bits >= 8 && ip.substr(0, prefix.size()) == prefix)
                    return true;
            }
        }
        return false;
    }

    mode get_mode() const noexcept { return mode_; }

    /// Returns true if the IP should be allowed (whitelist match or not blacklisted)
    bool is_allowed(std::string_view ip) const {
        bool match = matches(ip);
        if (mode_ == mode::whitelist) return match;
        return !match;
    }

private:
    mode mode_;
    mutable std::shared_mutex mutex_;
    std::set<std::string> entries_;
};

} // namespace progressive

// ==========================================================================
// Self-contained example usage / smoke test (compile with -DPROGRESSIVE_STANDALONE)
// ==========================================================================

#ifdef PROGRESSIVE_STANDALONE

#include <cassert>
#include <cstdio>

int main() {
    using namespace progressive;

    std::cout << "=== Progressive Rate-Limit Middleware — Standalone Test ===\n\n";

    // 1. Create middleware with presets
    eviction_config ec;
    ec.policy          = eviction_policy::idle;
    ec.max_idle        = duration_ms{600'000};
    ec.max_buckets     = 100'000;
    ec.high_water_mark = 80'000;

    auto mw = std::make_unique<rate_limit_middleware>(ec);
    mw->apply_preset("strict_api");
    mw->apply_preset("login_protect");
    mw->store()->start_eviction_thread();

    std::cout << "Loaded " << mw->get_rules().size() << " rules.\n";

    // 2. Simulate requests
    const char* test_ip   = "192.168.1.100";
    const char* test_user = "alice";

    std::cout << "\n--- Normal API requests ---\n";
    for (int i = 0; i < 5; ++i) {
        auto d = mw->check(test_ip, test_user, "/api/v1/data", 1, "");
        print_decision(d);
    }

    std::cout << "\n--- Login attempts (should trigger block after 5) ---\n";
    for (int i = 0; i < 7; ++i) {
        auto d = mw->check(test_ip, test_user, "/api/login", 1, "");
        print_decision(d);
    }

    // 3. Metrics
    std::cout << "\n--- Metrics ---\n";
    std::cout << mw->metrics_json() << "\n";

    // 4. Add a custom rule
    auto custom_rule = rules::per_ip_token_bucket(
        "custom_endpoint", 50, 5, 15,
        {"/api/vip/.*"}
    );
    mw->add_rule(std::move(custom_rule));

    std::cout << "\n--- Custom endpoint test ---\n";
    for (int i = 0; i < 5; ++i) {
        auto d = mw->check("10.0.0.5", "", "/api/vip/action", 1, "");
        print_decision(d);
    }

    // 5. Benchmark
    std::cout << "\n--- Benchmark (10k checks, 4 threads) ---\n";
    auto bench = run_benchmark(*mw, 10'000, 4);
    print_benchmark(bench);

    // 6. Export rules as JSON
    std::cout << "\n--- Rules JSON ---\n";
    std::cout << mw->rules_to_json() << "\n";

    // 7. Pause via circuit breaker
    rate_limit_middleware_v2 mw2(ec);
    mw2.apply_preset("strict_api");
    mw2.breaker().open();
    auto bypassed = mw2.check(test_ip, test_user, "/api/test");
    std::cout << "\n--- Circuit breaker bypass ---\n";
    print_decision(bypassed);
    assert(bypassed.result == limit_result::allowed);
    std::cout << "PASSED: Circuit breaker bypass works.\n";

    // 8. Duration parsing
    auto d1 = parse_duration("5s");
    auto d2 = parse_duration("2m");
    auto d3 = parse_duration("100ms");
    std::cout << "\n--- Duration parsing ---\n";
    if (d1) std::cout << "5s = " << d1->count() << "ms\n";
    if (d2) std::cout << "2m = " << d2->count() << "ms\n";
    if (d3) std::cout << "100ms = " << d3->count() << "ms\n";

    // 9. Leaky bucket test
    std::cout << "\n--- Leaky bucket ---\n";
    rate_limit_middleware mw3;
    mw3.apply_preset("global_leaky");
    for (int i = 0; i < 10; ++i) {
        auto d = mw3.check("127.0.0.1", "", "/api/test");
        print_decision(d);
    }

    // 10. Sliding window log test
    std::cout << "\n--- Sliding window log ---\n";
    rate_limit_middleware mw4;
    rate_limit_rule sw_rule;
    sw_rule.name = "test_sliding_log";
    sw_rule.strat = strategy::sliding_window_log;
    sw_rule.ktype = key_type::ip;
    sw_rule.priority = 1;
    sliding_window_log_config swcfg;
    swcfg.max_requests = 3;
    swcfg.window_size = duration_ms{5000};
    sw_rule.config = swcfg;
    mw4.add_rule(std::move(sw_rule));
    for (int i = 0; i < 5; ++i) {
        auto d = mw4.check("10.10.10.1", "", "/api/test");
        print_decision(d);
    }

    // Wait a bit for eviction thread (just for clean shutdown)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    mw->store()->stop_eviction_thread();
    mw2.store()->stop_eviction_thread();

    std::cout << "\n=== All tests passed ===\n";
    return 0;
}

#endif // PROGRESSIVE_STANDALONE
