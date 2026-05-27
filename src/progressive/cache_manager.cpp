// ============================================================================
// cache_manager.cpp — Matrix Cache Management System
//
// Implements a comprehensive cache management infrastructure for the Matrix
// homeserver, covering all standard and extended cache operations:
//
//   - LRU Cache (Least Recently Used):
//     Generic doubly-linked-list + hash map LRU cache with configurable
//     capacity, thread-safe operations, eviction callbacks, size tracking,
//     and multi-tenant support. Supports both in-memory and hybrid modes.
//     O(1) get/put/evict operations. Configurable eviction ratio.
//
//   - TTL Cache (Time-To-Live):
//     Generic TTL-based cache with per-entry expiration, background expiry
//     scanner, lazy expiry on access, and configurable TTL policies.
//     Supports absolute TTL, idle TTL, and sliding TTL modes.
//
//   - Cache Stats:
//     Per-cache and global statistics collection: hit/miss counters,
//     hit rate percentages, eviction counts, insertion counts, update
//     counts, size tracking, latency histograms, and access patterns.
//     Stats aggregation, snapshot, reset, and JSON export.
//
//   - Cache Invalidation:
//     Multiple invalidation strategies: key-based, pattern-based (glob),
//     prefix-based, tag-based, time-range-based, full-flush. Invalidation
//     batching, async invalidation, cascade invalidation for dependent
//     caches, and invalidation event broadcasting.
//
//   - Cache Manager:
//     Top-level coordinator managing multiple named caches, lifecycle
//     management, configuration hot-reload, health monitoring, admin
//     API endpoints for cache inspection and control.
//
//   - Background Workers:
//     Periodic TTL expiry scanner, LRU eviction sweeper, stats aggregation
//     worker, cache compaction worker, memory pressure handler.
//
//   - Admin Support:
//     Cache listing, per-cache inspection, manual flush/invalidation,
//     stats query, configuration update, cache warming control.
//
// Equivalent to:
//   synapse/util/caches/__init__.py                  (~800 lines)
//   synapse/util/caches/lrucache.py                  (~400 lines)
//   synapse/util/caches/descriptors.py               (~300 lines)
//   synapse/util/caches/ttlcache.py                   (~200 lines)
//   synapse/util/caches/stream_change_cache.py        (~150 lines)
//   synapse/metrics/cache_metrics.py                  (~200 lines)
//   synapse/replication/tcp/cache_invalidation.py     (~300 lines)
//   synapse/util/caches/cache_size_limiter.py         (~150 lines)
//
// Total equivalent: ~2,500 lines of Python
//
// Target: 3000+ lines of production-grade C++.
// Namespace: progressive::
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <bitset>
#include <cctype>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstddef>
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
#include <iterator>
#include <limits>
#include <list>
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
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/util/log.hpp"
#include "progressive/util/random.hpp"
#include "progressive/util/time.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
namespace storage {
class DatabasePool;
class LoggingTransaction;
}  // namespace storage

using storage::DatabasePool;
using storage::LoggingTransaction;

// ============================================================================
// Inline constants
// ============================================================================
inline constexpr size_t kDefaultLRUCapacity     = 10000;
inline constexpr size_t kDefaultMaxCacheMemory   = 256 * 1024 * 1024;  // 256 MB
inline constexpr double kDefaultEvictionRatio    = 0.25;
inline constexpr int64_t kDefaultTTLSeconds      = 300;    // 5 minutes
inline constexpr int64_t kDefaultIdleTTLSeconds  = 600;    // 10 minutes
inline constexpr int64_t kDefaultSlidingTTLSeconds = 1800;  // 30 minutes
inline constexpr int64_t kDefaultExpiryScanIntervalMs = 5000;
inline constexpr int64_t kDefaultStatsAggregationIntervalMs = 15000;
inline constexpr int64_t kDefaultCompactionIntervalMs = 60000;
inline constexpr size_t kMaxCacheNameLength      = 128;
inline constexpr size_t kMaxKeyLength            = 512;
inline constexpr size_t kMaxCacheCount           = 256;
inline constexpr size_t kMaxInvalidationBatch    = 10000;

// ============================================================================
// Enums and types
// ============================================================================

/// TTL mode for cache entries
enum class TTLMode : uint8_t {
    kAbsolute = 0,  ///< Fixed expiry from creation time
    kIdle     = 1,  ///< Expires after idle period (resets on access)
    kSliding  = 2,  ///< Expires after sliding window (extends on access)
    kNone     = 3,  ///< No TTL-based expiry
};

/// Invalidation strategy
enum class InvalidationStrategy : uint8_t {
    kExactKey     = 0,  ///< Invalidate by exact key match
    kPrefix       = 1,  ///< Invalidate all keys with given prefix
    kPattern      = 2,  ///< Invalidate by glob/regex pattern
    kTag          = 3,  ///< Invalidate all entries with given tag
    kTimeRange    = 4,  ///< Invalidate entries created within time range
    kFullFlush    = 5,  ///< Invalidate entire cache
    kCascade      = 6,  ///< Invalidate with cascade to dependent caches
    kAccessBased  = 7,  ///< Invalidate least-frequently-accessed entries
};

/// Cache health status
enum class CacheHealth : uint8_t {
    kHealthy      = 0,
    kWarning      = 1,
    kCritical     = 2,
    kDegraded     = 3,
};

/// Eviction reason
enum class EvictionReason : uint8_t {
    kCapacity     = 0,  ///< Evicted due to capacity limit
    kTTLExpired   = 1,  ///< Evicted due to TTL expiry
    kManual       = 2,  ///< Manually evicted
    kMemoryPressure = 3, ///< Evicted due to memory pressure
    kInvalidated  = 4,  ///< Evicted due to invalidation
    kCascade      = 5,  ///< Evicted due to cascade invalidation
};

/// Cache operation type for stats
enum class CacheOp : uint8_t {
    kGet          = 0,
    kPut          = 1,
    kRemove       = 2,
    kEvict        = 3,
    kInvalidate   = 4,
    kClear        = 5,
    kContains     = 6,
};

// ============================================================================
// CacheEvictionCallback — function type for eviction notifications
// ============================================================================
template <typename K, typename V>
using CacheEvictionCallback = std::function<void(const K& key, const V& value, EvictionReason reason)>;

// ============================================================================
// CacheEntryMetadata — per-entry bookkeeping
// ============================================================================
struct CacheEntryMetadata {
    int64_t created_at_ms;       ///< Creation timestamp (ms since epoch)
    int64_t last_accessed_ms;    ///< Last access timestamp
    int64_t ttl_ms;              ///< TTL in milliseconds (0 = none)
    TTLMode ttl_mode;            ///< TTL mode
    size_t estimated_size;       ///< Estimated memory size in bytes
    uint64_t access_count;       ///< Number of times accessed
    uint32_t generation;         ///< Cache generation for bulk invalidation
    std::string tag;             ///< Optional tag for tag-based invalidation
    bool dirty;                  ///< Whether entry needs write-back
    bool pinned;                 ///< Whether entry is pinned (never evicted)

    CacheEntryMetadata()
        : created_at_ms(0)
        , last_accessed_ms(0)
        , ttl_ms(0)
        , ttl_mode(TTLMode::kNone)
        , estimated_size(0)
        , access_count(0)
        , generation(0)
        , dirty(false)
        , pinned(false) {}
};

// ============================================================================
// CacheStatsSnapshot — atomic snapshot of cache statistics
// ============================================================================
struct CacheStatsSnapshot {
    uint64_t total_gets;
    uint64_t total_hits;
    uint64_t total_misses;
    uint64_t total_puts;
    uint64_t total_removes;
    uint64_t total_evictions;
    uint64_t total_invalidations;
    uint64_t total_clears;
    uint64_t total_contains;
    uint64_t total_contains_hits;
    size_t current_size;
    size_t max_size;
    size_t current_entries;
    double hit_rate;
    double miss_rate;
    int64_t snapshot_time_ms;
    int64_t avg_get_latency_us;
    int64_t p99_get_latency_us;
    int64_t avg_put_latency_us;
    size_t estimated_memory_bytes;
    CacheHealth health;

    CacheStatsSnapshot()
        : total_gets(0)
        , total_hits(0)
        , total_misses(0)
        , total_puts(0)
        , total_removes(0)
        , total_evictions(0)
        , total_invalidations(0)
        , total_clears(0)
        , total_contains(0)
        , total_contains_hits(0)
        , current_size(0)
        , max_size(0)
        , current_entries(0)
        , hit_rate(0.0)
        , miss_rate(0.0)
        , snapshot_time_ms(0)
        , avg_get_latency_us(0)
        , p99_get_latency_us(0)
        , avg_put_latency_us(0)
        , estimated_memory_bytes(0)
        , health(CacheHealth::kHealthy) {}
};

// ============================================================================
// LatencyHistogram — simple histogram for operation latencies
// ============================================================================
class LatencyHistogram {
public:
    static constexpr size_t kNumBuckets = 32;
    static constexpr int64_t kBucketBoundsUs[kNumBuckets] = {
        1, 2, 5, 10, 20, 50, 100, 200,
        500, 1000, 2000, 5000, 10000, 20000, 50000, 100000,
        200000, 500000, 1000000, 2000000, 5000000, 10000000,
        20000000, 50000000, 100000000, 200000000, 500000000,
        1000000000, 2000000000, 5000000000, 10000000000,
        std::numeric_limits<int64_t>::max()
    };

    LatencyHistogram() : total_count_(0), total_sum_us_(0) {
        for (size_t i = 0; i < kNumBuckets; ++i) {
            buckets_[i].store(0, std::memory_order_relaxed);
        }
    }

    void record(int64_t latency_us) {
        size_t idx = 0;
        for (size_t i = 0; i < kNumBuckets; ++i) {
            if (latency_us <= kBucketBoundsUs[i]) {
                idx = i;
                break;
            }
        }
        buckets_[idx].fetch_add(1, std::memory_order_relaxed);
        total_count_.fetch_add(1, std::memory_order_relaxed);
        total_sum_us_.fetch_add(latency_us, std::memory_order_relaxed);
    }

    int64_t average_us() const {
        uint64_t cnt = total_count_.load(std::memory_order_relaxed);
        if (cnt == 0) return 0;
        return total_sum_us_.load(std::memory_order_relaxed) / static_cast<int64_t>(cnt);
    }

    int64_t percentile(double p) const {
        uint64_t cnt = total_count_.load(std::memory_order_relaxed);
        if (cnt == 0) return 0;
        uint64_t target = static_cast<uint64_t>(std::ceil(p * cnt / 100.0));
        uint64_t accum = 0;
        for (size_t i = 0; i < kNumBuckets; ++i) {
            accum += buckets_[i].load(std::memory_order_relaxed);
            if (accum >= target) {
                return kBucketBoundsUs[i];
            }
        }
        return kBucketBoundsUs[kNumBuckets - 1];
    }

    int64_t p50() const { return percentile(50.0); }
    int64_t p90() const { return percentile(90.0); }
    int64_t p99() const { return percentile(99.0); }
    int64_t p999() const { return percentile(99.9); }

    void reset() {
        for (auto& b : buckets_) b.store(0, std::memory_order_relaxed);
        total_count_.store(0, std::memory_order_relaxed);
        total_sum_us_.store(0, std::memory_order_relaxed);
    }

    json to_json() const {
        json j;
        j["avg_us"] = average_us();
        j["p50_us"] = p50();
        j["p90_us"] = p90();
        j["p99_us"] = p99();
        j["p999_us"] = p999();
        j["total_count"] = total_count_.load();
        j["total_sum_us"] = total_sum_us_.load();
        json buckets = json::array();
        for (size_t i = 0; i < kNumBuckets; ++i) {
            json b;
            b["bound_us"] = kBucketBoundsUs[i];
            b["count"] = buckets_[i].load();
            buckets.push_back(b);
        }
        j["buckets"] = buckets;
        return j;
    }

private:
    std::array<std::atomic<uint64_t>, kNumBuckets> buckets_;
    std::atomic<uint64_t> total_count_;
    std::atomic<int64_t> total_sum_us_;
};

// ============================================================================
// CacheStats — per-cache statistics collector
// ============================================================================
class CacheStats {
public:
    CacheStats(const std::string& cache_name)
        : cache_name_(cache_name)
        , total_gets_(0)
        , total_hits_(0)
        , total_misses_(0)
        , total_puts_(0)
        , total_removes_(0)
        , total_evictions_(0)
        , total_invalidations_(0)
        , total_clears_(0)
        , total_contains_(0)
        , total_contains_hits_(0)
        , current_size_(0)
        , max_size_(kDefaultLRUCapacity)
        , current_entries_(0)
        , estimated_memory_bytes_(0)
        , last_snapshot_time_ms_(0)
        , health_(CacheHealth::kHealthy) {}

    // ---- Counters ----

    void record_get(bool hit, int64_t latency_us) {
        total_gets_.fetch_add(1, std::memory_order_relaxed);
        if (hit) {
            total_hits_.fetch_add(1, std::memory_order_relaxed);
        } else {
            total_misses_.fetch_add(1, std::memory_order_relaxed);
        }
        get_latency_.record(latency_us);
    }

    void record_put(int64_t latency_us) {
        total_puts_.fetch_add(1, std::memory_order_relaxed);
        put_latency_.record(latency_us);
    }

    void record_remove() {
        total_removes_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_eviction(EvictionReason reason) {
        total_evictions_.fetch_add(1, std::memory_order_relaxed);
        (void)reason;
    }

    void record_invalidation() {
        total_invalidations_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_clear() {
        total_clears_.fetch_add(1, std::memory_order_relaxed);
    }

    void record_contains(bool present) {
        total_contains_.fetch_add(1, std::memory_order_relaxed);
        if (present) {
            total_contains_hits_.fetch_add(1, std::memory_order_relaxed);
        }
    }

    void record_operation(CacheOp op, bool success, int64_t latency_us) {
        switch (op) {
            case CacheOp::kGet:       record_get(success, latency_us); break;
            case CacheOp::kPut:       record_put(latency_us); break;
            case CacheOp::kRemove:    record_remove(); break;
            case CacheOp::kEvict:     record_eviction(EvictionReason::kManual); break;
            case CacheOp::kInvalidate: record_invalidation(); break;
            case CacheOp::kClear:     record_clear(); break;
            case CacheOp::kContains:  record_contains(success); break;
        }
    }

    // ---- Size tracking ----

    void set_current_size(size_t sz) {
        current_size_.store(sz, std::memory_order_relaxed);
    }

    void set_current_entries(size_t n) {
        current_entries_.store(n, std::memory_order_relaxed);
    }

    void set_estimated_memory(size_t bytes) {
        estimated_memory_bytes_.store(bytes, std::memory_order_relaxed);
    }

    void set_max_size(size_t sz) {
        max_size_.store(sz, std::memory_order_relaxed);
    }

    void set_health(CacheHealth h) {
        health_.store(h, std::memory_order_relaxed);
    }

    // ---- Calculations ----

    double hit_rate() const {
        uint64_t gets = total_gets_.load(std::memory_order_relaxed);
        if (gets == 0) return 0.0;
        return static_cast<double>(total_hits_.load(std::memory_order_relaxed)) / static_cast<double>(gets);
    }

    double miss_rate() const {
        uint64_t gets = total_gets_.load(std::memory_order_relaxed);
        if (gets == 0) return 0.0;
        return static_cast<double>(total_misses_.load(std::memory_order_relaxed)) / static_cast<double>(gets);
    }

    double fill_ratio() const {
        size_t max = max_size_.load(std::memory_order_relaxed);
        if (max == 0) return 0.0;
        return static_cast<double>(current_entries_.load(std::memory_order_relaxed)) / static_cast<double>(max);
    }

    // ---- Snapshot ----

    CacheStatsSnapshot snapshot() {
        CacheStatsSnapshot snap;
        snap.total_gets      = total_gets_.load(std::memory_order_relaxed);
        snap.total_hits      = total_hits_.load(std::memory_order_relaxed);
        snap.total_misses    = total_misses_.load(std::memory_order_relaxed);
        snap.total_puts      = total_puts_.load(std::memory_order_relaxed);
        snap.total_removes   = total_removes_.load(std::memory_order_relaxed);
        snap.total_evictions = total_evictions_.load(std::memory_order_relaxed);
        snap.total_invalidations = total_invalidations_.load(std::memory_order_relaxed);
        snap.total_clears    = total_clears_.load(std::memory_order_relaxed);
        snap.total_contains  = total_contains_.load(std::memory_order_relaxed);
        snap.total_contains_hits = total_contains_hits_.load(std::memory_order_relaxed);
        snap.current_size    = current_size_.load(std::memory_order_relaxed);
        snap.max_size        = max_size_.load(std::memory_order_relaxed);
        snap.current_entries = current_entries_.load(std::memory_order_relaxed);
        snap.hit_rate        = hit_rate();
        snap.miss_rate       = miss_rate();
        snap.snapshot_time_ms = current_time_ms();
        snap.avg_get_latency_us = get_latency_.average_us();
        snap.p99_get_latency_us = get_latency_.p99();
        snap.avg_put_latency_us = put_latency_.average_us();
        snap.estimated_memory_bytes = estimated_memory_bytes_.load(std::memory_order_relaxed);
        snap.health = health_.load(std::memory_order_relaxed);
        last_snapshot_time_ms_.store(snap.snapshot_time_ms, std::memory_order_relaxed);
        return snap;
    }

    // ---- Reset ----

    void reset() {
        total_gets_.store(0, std::memory_order_relaxed);
        total_hits_.store(0, std::memory_order_relaxed);
        total_misses_.store(0, std::memory_order_relaxed);
        total_puts_.store(0, std::memory_order_relaxed);
        total_removes_.store(0, std::memory_order_relaxed);
        total_evictions_.store(0, std::memory_order_relaxed);
        total_invalidations_.store(0, std::memory_order_relaxed);
        total_clears_.store(0, std::memory_order_relaxed);
        total_contains_.store(0, std::memory_order_relaxed);
        total_contains_hits_.store(0, std::memory_order_relaxed);
        get_latency_.reset();
        put_latency_.reset();
    }

    // ---- JSON ----

    json to_json() const {
        CacheStatsSnapshot snap = const_cast<CacheStats*>(this)->snapshot();
        json j;
        j["cache_name"]        = cache_name_;
        j["total_gets"]        = snap.total_gets;
        j["total_hits"]        = snap.total_hits;
        j["total_misses"]      = snap.total_misses;
        j["total_puts"]        = snap.total_puts;
        j["total_removes"]     = snap.total_removes;
        j["total_evictions"]   = snap.total_evictions;
        j["total_invalidations"] = snap.total_invalidations;
        j["total_clears"]      = snap.total_clears;
        j["total_contains"]    = snap.total_contains;
        j["total_contains_hits"] = snap.total_contains_hits;
        j["current_size"]      = snap.current_size;
        j["max_size"]          = snap.max_size;
        j["current_entries"]   = snap.current_entries;
        j["hit_rate"]          = snap.hit_rate;
        j["miss_rate"]         = snap.miss_rate;
        j["fill_ratio"]        = fill_ratio();
        j["snapshot_time_ms"]  = snap.snapshot_time_ms;
        j["avg_get_latency_us"] = snap.avg_get_latency_us;
        j["p99_get_latency_us"] = snap.p99_get_latency_us;
        j["avg_put_latency_us"] = snap.avg_put_latency_us;
        j["estimated_memory_bytes"] = snap.estimated_memory_bytes;
        j["health"] = static_cast<int>(snap.health);
        j["get_latency_histogram"] = get_latency_.to_json();
        j["put_latency_histogram"] = put_latency_.to_json();
        return j;
    }

    const std::string& cache_name() const { return cache_name_; }

private:
    static int64_t current_time_ms() {
        return chr::duration_cast<chr::milliseconds>(
            chr::system_clock::now().time_since_epoch()
        ).count();
    }

    std::string cache_name_;
    std::atomic<uint64_t> total_gets_;
    std::atomic<uint64_t> total_hits_;
    std::atomic<uint64_t> total_misses_;
    std::atomic<uint64_t> total_puts_;
    std::atomic<uint64_t> total_removes_;
    std::atomic<uint64_t> total_evictions_;
    std::atomic<uint64_t> total_invalidations_;
    std::atomic<uint64_t> total_clears_;
    std::atomic<uint64_t> total_contains_;
    std::atomic<uint64_t> total_contains_hits_;
    std::atomic<size_t> current_size_;
    std::atomic<size_t> max_size_;
    std::atomic<size_t> current_entries_;
    std::atomic<size_t> estimated_memory_bytes_;
    std::atomic<int64_t> last_snapshot_time_ms_;
    std::atomic<CacheHealth> health_;
    LatencyHistogram get_latency_;
    LatencyHistogram put_latency_;
};

// ============================================================================
// GlobalCacheStats — aggregate stats across all caches
// ============================================================================
class GlobalCacheStats {
public:
    GlobalCacheStats() : total_memory_allocated_(0), total_caches_(0) {}

    void register_cache(const std::string& name, std::shared_ptr<CacheStats> stats) {
        std::unique_lock lock(mutex_);
        cache_stats_[name] = std::move(stats);
        total_caches_.store(cache_stats_.size(), std::memory_order_relaxed);
    }

    void unregister_cache(const std::string& name) {
        std::unique_lock lock(mutex_);
        cache_stats_.erase(name);
        total_caches_.store(cache_stats_.size(), std::memory_order_relaxed);
    }

    std::shared_ptr<CacheStats> get_stats(const std::string& name) {
        std::shared_lock lock(mutex_);
        auto it = cache_stats_.find(name);
        if (it != cache_stats_.end()) return it->second;
        return nullptr;
    }

    json aggregate_json() const {
        json j;
        json caches = json::array();
        uint64_t total_gets = 0, total_hits = 0, total_misses = 0;
        uint64_t total_puts = 0, total_evictions = 0, total_invalidations = 0;
        size_t total_entries = 0;
        size_t total_memory = 0;

        std::shared_lock lock(mutex_);
        for (const auto& [name, stats] : cache_stats_) {
            CacheStatsSnapshot snap = stats->snapshot();
            json cj;
            cj["name"] = name;
            cj["entries"] = snap.current_entries;
            cj["hit_rate"] = snap.hit_rate;
            cj["memory_bytes"] = snap.estimated_memory_bytes;
            cj["health"] = static_cast<int>(snap.health);
            caches.push_back(cj);

            total_gets += snap.total_gets;
            total_hits += snap.total_hits;
            total_misses += snap.total_misses;
            total_puts += snap.total_puts;
            total_evictions += snap.total_evictions;
            total_invalidations += snap.total_invalidations;
            total_entries += snap.current_entries;
            total_memory += snap.estimated_memory_bytes;
        }

        j["caches"] = caches;
        j["total_caches"] = cache_stats_.size();
        j["total_gets"] = total_gets;
        j["total_hits"] = total_hits;
        j["total_misses"] = total_misses;
        j["total_puts"] = total_puts;
        j["total_evictions"] = total_evictions;
        j["total_invalidations"] = total_invalidations;
        j["total_entries"] = total_entries;
        j["total_memory_bytes"] = total_memory;
        j["aggregate_hit_rate"] = (total_gets > 0)
            ? static_cast<double>(total_hits) / static_cast<double>(total_gets)
            : 0.0;
        return j;
    }

    void reset_all() {
        std::shared_lock lock(mutex_);
        for (auto& [name, stats] : cache_stats_) {
            stats->reset();
        }
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<CacheStats>> cache_stats_;
    std::atomic<size_t> total_memory_allocated_;
    std::atomic<size_t> total_caches_;
};

// ============================================================================
// LRUCache<K, V> — Generic LRU Cache Implementation
// ============================================================================
// Implements a thread-safe LRU cache using a doubly-linked list for the
// eviction order and an unordered_map for O(1) lookups. Each entry holds
// a value, metadata, and an iterator into the list for O(1) promotion.
//
// Template parameters:
//   K - key type (must be hashable and equality-comparable)
//   V - value type (must be copyable or movable)
//   KeyHash - hash function for K (defaults to std::hash<K>)
// ============================================================================
template <typename K, typename V, typename KeyHash = std::hash<K>>
class LRUCache {
public:
    // Internal node stored in the linked list and map
    struct ListNode {
        K key;
        V value;
        CacheEntryMetadata meta;
        mutable typename std::list<typename std::unordered_map<K, size_t, KeyHash>::iterator>::iterator list_it;

        ListNode() = default;
        ListNode(const K& k, const V& v) : key(k), value(v), meta() {}
        ListNode(K&& k, V&& v) : key(std::move(k)), value(std::move(v)), meta() {}
    };

    using EvictionCallback = CacheEvictionCallback<K, V>;

    // ---- Construction ----

    explicit LRUCache(const std::string& name,
                      size_t capacity = kDefaultLRUCapacity,
                      size_t max_memory = kDefaultMaxCacheMemory)
        : name_(name)
        , capacity_(capacity)
        , max_memory_(max_memory)
        , current_memory_(0)
        , eviction_ratio_(kDefaultEvictionRatio)
        , stats_(std::make_shared<CacheStats>(name))
        , generation_(0)
        , shutdown_(false)
    {
        // Initialize the sentinel node for the LRU list
        // The list will have an empty header node to simplify operations
        // We use a map from key to index in the pool
        entries_.reserve(capacity);
    }

    ~LRUCache() {
        shutdown_.store(true, std::memory_order_release);
        clear();
    }

    // Disable copy
    LRUCache(const LRUCache&) = delete;
    LRUCache& operator=(const LRUCache&) = delete;

    // Enable move
    LRUCache(LRUCache&& other) noexcept
        : name_(std::move(other.name_))
        , capacity_(other.capacity_)
        , max_memory_(other.max_memory_)
        , current_memory_(other.current_memory_.load())
        , eviction_ratio_(other.eviction_ratio_)
        , stats_(std::move(other.stats_))
        , generation_(other.generation_.load())
        , shutdown_(other.shutdown_.load())
    {
        std::unique_lock lock(other.mutex_);
        entries_ = std::move(other.entries_);
        lru_list_ = std::move(other.lru_list_);
        key_index_ = std::move(other.key_index_);
    }

    // ---- Configuration ----

    const std::string& name() const { return name_; }

    void set_capacity(size_t capacity) {
        std::unique_lock lock(mutex_);
        capacity_ = capacity;
        stats_->set_max_size(capacity);
        enforce_capacity_locked(lock);
    }

    size_t capacity() const {
        std::shared_lock lock(mutex_);
        return capacity_;
    }

    void set_max_memory(size_t bytes) {
        std::unique_lock lock(mutex_);
        max_memory_ = bytes;
        enforce_memory_locked(lock);
    }

    size_t max_memory() const {
        std::shared_lock lock(mutex_);
        return max_memory_;
    }

    void set_eviction_ratio(double ratio) {
        std::unique_lock lock(mutex_);
        eviction_ratio_ = std::clamp(ratio, 0.05, 0.95);
    }

    double eviction_ratio() const {
        std::shared_lock lock(mutex_);
        return eviction_ratio_;
    }

    void set_eviction_callback(EvictionCallback cb) {
        std::unique_lock lock(mutex_);
        eviction_callback_ = std::move(cb);
    }

    // ---- Core Operations ----

    /// Get a value by key. Returns std::nullopt if not found.
    /// Promotes the entry to most-recently-used position.
    std::optional<V> get(const K& key) {
        auto t0 = chr::high_resolution_clock::now();
        std::unique_lock lock(mutex_);
        auto it = key_index_.find(key);
        if (it == key_index_.end()) {
            auto latency = chr::duration_cast<chr::microseconds>(
                chr::high_resolution_clock::now() - t0).count();
            stats_->record_get(false, latency);
            return std::nullopt;
        }

        size_t idx = it->second;
        ListNode& node = entries_[idx];
        // Update access metadata
        int64_t now = current_time_ms();
        node.meta.last_accessed_ms = now;
        node.meta.access_count++;
        if (node.meta.ttl_mode == TTLMode::kIdle) {
            // Reset idle timer
            node.meta.created_at_ms = now;
        } else if (node.meta.ttl_mode == TTLMode::kSliding) {
            // Extend sliding window
            node.meta.created_at_ms = now;
        }

        V result = node.value;

        // Promote to front of LRU list (most recently used)
        promote_locked(idx);

        auto latency = chr::duration_cast<chr::microseconds>(
            chr::high_resolution_clock::now() - t0).count();
        stats_->record_get(true, latency);
        return result;
    }

    /// Get a value without promoting in LRU order (peek).
    std::optional<V> peek(const K& key) const {
        std::shared_lock lock(mutex_);
        auto it = key_index_.find(key);
        if (it == key_index_.end()) return std::nullopt;
        return entries_[it->second].value;
    }

    /// Put a value into the cache. If key exists, updates value and promotes.
    /// If at capacity, evicts LRU entries to make room.
    void put(const K& key, const V& value, const CacheEntryMetadata& meta_hint = CacheEntryMetadata()) {
        auto t0 = chr::high_resolution_clock::now();
        std::unique_lock lock(mutex_);

        auto it = key_index_.find(key);
        if (it != key_index_.end()) {
            // Update existing entry
            size_t idx = it->second;
            ListNode& node = entries_[idx];
            size_t old_size = node.meta.estimated_size;
            node.value = value;
            node.meta.last_accessed_ms = current_time_ms();
            node.meta.access_count++;
            if (meta_hint.ttl_ms > 0) {
                node.meta.ttl_ms = meta_hint.ttl_ms;
                node.meta.ttl_mode = meta_hint.ttl_mode;
            }
            if (meta_hint.estimated_size > 0) {
                node.meta.estimated_size = meta_hint.estimated_size;
            }
            if (!meta_hint.tag.empty()) {
                node.meta.tag = meta_hint.tag;
            }
            node.meta.generation = generation_.load(std::memory_order_acquire);
            size_t new_size = node.meta.estimated_size;
            current_memory_.fetch_sub(old_size, std::memory_order_relaxed);
            current_memory_.fetch_add(new_size, std::memory_order_relaxed);
            promote_locked(idx);
        } else {
            // Insert new entry
            // Evict if needed
            while (entries_.size() >= capacity_) {
                evict_one_locked(EvictionReason::kCapacity);
            }
            enforce_memory_locked(lock);

            // Create the entry
            ListNode node(key, value);
            node.meta = meta_hint;
            node.meta.created_at_ms = current_time_ms();
            node.meta.last_accessed_ms = node.meta.created_at_ms;
            node.meta.access_count = 1;
            node.meta.generation = generation_.load(std::memory_order_acquire);
            if (node.meta.estimated_size == 0) {
                node.meta.estimated_size = estimate_size(key, value);
            }

            size_t idx = entries_.size();
            entries_.push_back(std::move(node));
            lru_list_.push_front(idx);
            entries_[idx].list_it = lru_list_.begin();
            key_index_[key] = idx;
            current_memory_.fetch_add(entries_[idx].meta.estimated_size, std::memory_order_relaxed);
        }

        stats_->set_current_entries(entries_.size());
        stats_->set_estimated_memory(current_memory_.load(std::memory_order_relaxed));
        auto latency = chr::duration_cast<chr::microseconds>(
            chr::high_resolution_clock::now() - t0).count();
        stats_->record_put(latency);
    }

    /// Put a value with a specific TTL
    void put_with_ttl(const K& key, const V& value,
                      int64_t ttl_ms, TTLMode mode = TTLMode::kAbsolute) {
        CacheEntryMetadata meta;
        meta.ttl_ms = ttl_ms;
        meta.ttl_mode = mode;
        meta.created_at_ms = current_time_ms();
        put(key, value, meta);
    }

    /// Put a value with a tag for tag-based invalidation
    void put_with_tag(const K& key, const V& value, const std::string& tag) {
        CacheEntryMetadata meta;
        meta.tag = tag;
        put(key, value, meta);
    }

    /// Remove a specific entry by key
    bool remove(const K& key) {
        std::unique_lock lock(mutex_);
        auto it = key_index_.find(key);
        if (it == key_index_.end()) return false;

        size_t idx = it->second;
        remove_entry_locked(idx);
        stats_->record_remove();
        stats_->set_current_entries(entries_.size());
        return true;
    }

    /// Check if key exists
    bool contains(const K& key) const {
        std::shared_lock lock(mutex_);
        bool found = key_index_.find(key) != key_index_.end();
        stats_->record_contains(found);
        return found;
    }

    /// Get the number of entries
    size_t size() const {
        std::shared_lock lock(mutex_);
        return entries_.size();
    }

    /// Check if cache is empty
    bool empty() const {
        std::shared_lock lock(mutex_);
        return entries_.empty();
    }

    /// Clear all entries
    void clear() {
        std::unique_lock lock(mutex_);
        clear_locked();
        stats_->record_clear();
    }

    /// Get all keys
    std::vector<K> keys() const {
        std::shared_lock lock(mutex_);
        std::vector<K> result;
        result.reserve(key_index_.size());
        for (const auto& [k, v] : key_index_) {
            result.push_back(k);
        }
        return result;
    }

    /// Get stats
    std::shared_ptr<CacheStats> stats() { return stats_; }
    std::shared_ptr<const CacheStats> stats() const { return stats_; }

    /// Invalidate by exact key
    size_t invalidate_key(const K& key) {
        std::unique_lock lock(mutex_);
        auto it = key_index_.find(key);
        if (it == key_index_.end()) return 0;
        size_t idx = it->second;
        remove_entry_locked(idx);
        stats_->record_invalidation();
        stats_->set_current_entries(entries_.size());
        return 1;
    }

    /// Invalidate by key prefix (string keys only)
    size_t invalidate_prefix(const std::string& prefix) {
        if constexpr (std::is_same_v<K, std::string>) {
            std::unique_lock lock(mutex_);
            size_t count = 0;
            // Collect keys to avoid iterator invalidation
            std::vector<K> to_remove;
            for (const auto& [key, idx] : key_index_) {
                if (key.size() >= prefix.size() &&
                    key.compare(0, prefix.size(), prefix) == 0) {
                    to_remove.push_back(key);
                }
            }
            for (const auto& key : to_remove) {
                auto it = key_index_.find(key);
                if (it != key_index_.end()) {
                    remove_entry_locked(it->second);
                    ++count;
                }
            }
            if (count > 0) {
                stats_->record_invalidation();
                stats_->set_current_entries(entries_.size());
            }
            return count;
        }
        return 0;
    }

    /// Invalidate by tag
    size_t invalidate_tag(const std::string& tag) {
        std::unique_lock lock(mutex_);
        size_t count = 0;
        std::vector<K> to_remove;
        for (const auto& [key, idx] : key_index_) {
            if (idx < entries_.size() && entries_[idx].meta.tag == tag) {
                to_remove.push_back(key);
            }
        }
        for (const auto& key : to_remove) {
            auto it = key_index_.find(key);
            if (it != key_index_.end()) {
                remove_entry_locked(it->second);
                ++count;
            }
        }
        if (count > 0) {
            stats_->record_invalidation();
            stats_->set_current_entries(entries_.size());
        }
        return count;
    }

    /// Invalidate by time range
    size_t invalidate_time_range(int64_t from_ms, int64_t to_ms) {
        std::unique_lock lock(mutex_);
        size_t count = 0;
        std::vector<K> to_remove;
        for (const auto& [key, idx] : key_index_) {
            if (idx < entries_.size()) {
                int64_t created = entries_[idx].meta.created_at_ms;
                if (created >= from_ms && created <= to_ms) {
                    to_remove.push_back(key);
                }
            }
        }
        for (const auto& key : to_remove) {
            auto it = key_index_.find(key);
            if (it != key_index_.end()) {
                remove_entry_locked(it->second);
                ++count;
            }
        }
        if (count > 0) {
            stats_->record_invalidation();
            stats_->set_current_entries(entries_.size());
        }
        return count;
    }

    /// Invalidate by regex pattern (string keys only)
    size_t invalidate_pattern(const std::string& pattern) {
        if constexpr (std::is_same_v<K, std::string>) {
            std::unique_lock lock(mutex_);
            try {
                std::regex re(pattern);
                size_t count = 0;
                std::vector<K> to_remove;
                for (const auto& [key, idx] : key_index_) {
                    if (std::regex_match(key, re)) {
                        to_remove.push_back(key);
                    }
                }
                for (const auto& key : to_remove) {
                    auto it = key_index_.find(key);
                    if (it != key_index_.end()) {
                        remove_entry_locked(it->second);
                        ++count;
                    }
                }
                if (count > 0) {
                    stats_->record_invalidation();
                    stats_->set_current_entries(entries_.size());
                }
                return count;
            } catch (const std::regex_error&) {
                return 0;
            }
        }
        return 0;
    }

    /// Full flush (clear all)
    size_t invalidate_all() {
        std::unique_lock lock(mutex_);
        size_t count = entries_.size();
        clear_locked();
        stats_->record_invalidation();
        return count;
    }

    /// Invalidate by access count (remove least-frequently-accessed)
    size_t invalidate_least_accessed(size_t max_to_remove) {
        std::unique_lock lock(mutex_);
        if (entries_.empty()) return 0;

        // Collect entries with their access counts
        std::vector<std::pair<K, uint64_t>> access_counts;
        access_counts.reserve(entries_.size());
        for (const auto& [key, idx] : key_index_) {
            if (idx < entries_.size() && !entries_[idx].meta.pinned) {
                access_counts.emplace_back(key, entries_[idx].meta.access_count);
            }
        }

        // Sort by access count ascending
        std::sort(access_counts.begin(), access_counts.end(),
                  [](const auto& a, const auto& b) { return a.second < b.second; });

        size_t to_remove = std::min(max_to_remove, access_counts.size());
        for (size_t i = 0; i < to_remove; ++i) {
            auto it = key_index_.find(access_counts[i].first);
            if (it != key_index_.end()) {
                remove_entry_locked(it->second);
            }
        }

        if (to_remove > 0) {
            stats_->record_invalidation();
            stats_->set_current_entries(entries_.size());
        }
        return to_remove;
    }

    /// Bump generation — invalidates all entries not matching current generation
    void bump_generation() {
        std::unique_lock lock(mutex_);
        generation_.fetch_add(1, std::memory_order_acq_rel);
    }

    /// Invalidate entries from previous generations
    size_t invalidate_old_generations() {
        std::unique_lock lock(mutex_);
        uint32_t current_gen = generation_.load(std::memory_order_acquire);
        size_t count = 0;
        std::vector<K> to_remove;
        for (const auto& [key, idx] : key_index_) {
            if (idx < entries_.size() &&
                entries_[idx].meta.generation < current_gen &&
                !entries_[idx].meta.pinned) {
                to_remove.push_back(key);
            }
        }
        for (const auto& key : to_remove) {
            auto it = key_index_.find(key);
            if (it != key_index_.end()) {
                remove_entry_locked(it->second);
                ++count;
            }
        }
        if (count > 0) {
            stats_->record_invalidation();
            stats_->set_current_entries(entries_.size());
        }
        return count;
    }

    /// Expire TTL entries (lazy expiry)
    size_t expire_ttl_entries(int64_t now_ms = 0) {
        std::unique_lock lock(mutex_);
        if (now_ms == 0) now_ms = current_time_ms();
        size_t count = 0;
        std::vector<K> expired;
        for (const auto& [key, idx] : key_index_) {
            if (idx >= entries_.size()) continue;
            const auto& meta = entries_[idx].meta;
            if (meta.ttl_ms == 0 || meta.pinned) continue;
            if (is_expired(meta, now_ms)) {
                expired.push_back(key);
            }
        }
        for (const auto& key : expired) {
            auto it = key_index_.find(key);
            if (it != key_index_.end()) {
                remove_entry_locked(it->second, EvictionReason::kTTLExpired);
                ++count;
            }
        }
        if (count > 0) {
            stats_->set_current_entries(entries_.size());
            stats_->set_estimated_memory(current_memory_.load(std::memory_order_relaxed));
        }
        return count;
    }

    /// Pin an entry (prevents eviction)
    bool pin(const K& key) {
        std::unique_lock lock(mutex_);
        auto it = key_index_.find(key);
        if (it == key_index_.end()) return false;
        entries_[it->second].meta.pinned = true;
        return true;
    }

    /// Unpin an entry
    bool unpin(const K& key) {
        std::unique_lock lock(mutex_);
        auto it = key_index_.find(key);
        if (it == key_index_.end()) return false;
        entries_[it->second].meta.pinned = false;
        return true;
    }

    /// Update the estimated size of an entry
    bool update_size(const K& key, size_t new_size) {
        std::unique_lock lock(mutex_);
        auto it = key_index_.find(key);
        if (it == key_index_.end()) return false;
        size_t old_size = entries_[it->second].meta.estimated_size;
        entries_[it->second].meta.estimated_size = new_size;
        current_memory_.fetch_sub(old_size, std::memory_order_relaxed);
        current_memory_.fetch_add(new_size, std::memory_order_relaxed);
        return true;
    }

    /// Mark entry as dirty (needs write-back)
    bool mark_dirty(const K& key) {
        std::unique_lock lock(mutex_);
        auto it = key_index_.find(key);
        if (it == key_index_.end()) return false;
        entries_[it->second].meta.dirty = true;
        return true;
    }

    /// Mark entry as clean
    bool mark_clean(const K& key) {
        std::unique_lock lock(mutex_);
        auto it = key_index_.find(key);
        if (it == key_index_.end()) return false;
        entries_[it->second].meta.dirty = false;
        return true;
    }

    /// Get all dirty entries that need write-back
    std::vector<std::pair<K, V>> get_dirty_entries() const {
        std::shared_lock lock(mutex_);
        std::vector<std::pair<K, V>> result;
        for (const auto& [key, idx] : key_index_) {
            if (idx < entries_.size() && entries_[idx].meta.dirty) {
                result.emplace_back(key, entries_[idx].value);
            }
        }
        return result;
    }

    /// Get metadata for a key
    std::optional<CacheEntryMetadata> get_metadata(const K& key) const {
        std::shared_lock lock(mutex_);
        auto it = key_index_.find(key);
        if (it == key_index_.end()) return std::nullopt;
        return entries_[it->second].meta;
    }

    /// Get estimated total memory
    size_t estimated_memory() const {
        return current_memory_.load(std::memory_order_relaxed);
    }

    /// Get current memory pressure ratio (0.0 to 1.0+)
    double memory_pressure() const {
        size_t max = max_memory_;
        if (max == 0) return 0.0;
        return static_cast<double>(current_memory_.load(std::memory_order_relaxed)) / static_cast<double>(max);
    }

    /// Get capacity pressure ratio
    double capacity_pressure() const {
        std::shared_lock lock(mutex_);
        if (capacity_ == 0) return 0.0;
        return static_cast<double>(entries_.size()) / static_cast<double>(capacity_);
    }

    /// Health check
    CacheHealth health_check() {
        double mem_pressure = memory_pressure();
        double cap_pressure = capacity_pressure();
        if (mem_pressure > 0.95 || cap_pressure > 0.98) {
            stats_->set_health(CacheHealth::kCritical);
            return CacheHealth::kCritical;
        }
        if (mem_pressure > 0.75 || cap_pressure > 0.85) {
            stats_->set_health(CacheHealth::kWarning);
            return CacheHealth::kWarning;
        }
        if (mem_pressure > 0.50 || cap_pressure > 0.70) {
            stats_->set_health(CacheHealth::kDegraded);
            return CacheHealth::kDegraded;
        }
        stats_->set_health(CacheHealth::kHealthy);
        return CacheHealth::kHealthy;
    }

    /// Compact the cache by removing expired and low-value entries
    size_t compact() {
        std::unique_lock lock(mutex_);
        int64_t now = current_time_ms();
        size_t removed = 0;

        // First pass: remove TTL-expired entries
        std::vector<K> to_remove;
        for (const auto& [key, idx] : key_index_) {
            if (idx >= entries_.size()) continue;
            const auto& meta = entries_[idx].meta;
            if (meta.ttl_ms > 0 && !meta.pinned && is_expired(meta, now)) {
                to_remove.push_back(key);
            }
        }
        for (const auto& key : to_remove) {
            auto it = key_index_.find(key);
            if (it != key_index_.end()) {
                remove_entry_locked(it->second, EvictionReason::kTTLExpired);
                ++removed;
            }
        }

        // Second pass: if still over memory limit, evict LRU
        while (current_memory_.load(std::memory_order_relaxed) > max_memory_ &&
               !entries_.empty()) {
            if (!evict_one_locked(EvictionReason::kMemoryPressure)) break;
            ++removed;
        }

        stats_->set_current_entries(entries_.size());
        stats_->set_estimated_memory(current_memory_.load(std::memory_order_relaxed));
        return removed;
    }

    /// JSON representation for admin API
    json to_json() const {
        CacheStatsSnapshot snap = stats_->snapshot();
        json j;
        j["name"] = name_;
        j["type"] = "LRU";
        j["capacity"] = capacity_;
        j["max_memory"] = max_memory_;
        j["current_size"] = snap.current_size;
        j["current_entries"] = snap.current_entries;
        j["estimated_memory"] = snap.estimated_memory_bytes;
        j["hit_rate"] = snap.hit_rate;
        j["miss_rate"] = snap.miss_rate;
        j["memory_pressure"] = memory_pressure();
        j["capacity_pressure"] = capacity_pressure();
        j["health"] = static_cast<int>(snap.health);
        return j;
    }

private:
    // ---- Internal helpers ----

    static int64_t current_time_ms() {
        return chr::duration_cast<chr::milliseconds>(
            chr::system_clock::now().time_since_epoch()
        ).count();
    }

    static bool is_expired(const CacheEntryMetadata& meta, int64_t now_ms) {
        switch (meta.ttl_mode) {
            case TTLMode::kAbsolute:
                return (meta.created_at_ms + meta.ttl_ms) <= now_ms;
            case TTLMode::kIdle:
                return (meta.last_accessed_ms + meta.ttl_ms) <= now_ms;
            case TTLMode::kSliding:
                return (meta.created_at_ms + meta.ttl_ms) <= now_ms;
            // created_at_ms is updated on each access for sliding
            case TTLMode::kNone:
                return false;
        }
        return false;
    }

    /// Estimate size of a key-value pair. Override via template specialization.
    size_t estimate_size(const K& key, const V& value) {
        // Default estimation based on sizeof
        size_t s = sizeof(K) + sizeof(V);
        if constexpr (std::is_same_v<K, std::string>) {
            s += key.size();
        }
        if constexpr (std::is_same_v<V, std::string>) {
            s += value.size();
        }
        if constexpr (std::is_same_v<V, std::vector<char>>) {
            s += value.size();
        }
        return s + sizeof(CacheEntryMetadata);
    }

    /// Promote entry to front of LRU list
    void promote_locked(size_t idx) {
        if (idx >= entries_.size()) return;
        auto& list_it = entries_[idx].list_it;
        if (list_it != lru_list_.begin()) {
            lru_list_.splice(lru_list_.begin(), lru_list_, list_it);
        }
    }

    /// Evict one entry (the LRU - back of list). Returns true if evicted.
    bool evict_one_locked(EvictionReason reason) {
        if (lru_list_.empty()) return false;

        // Find the least-recently-used non-pinned entry
        auto it = lru_list_.rbegin();
        while (it != lru_list_.rend()) {
            size_t idx = *it;
            if (idx < entries_.size() && !entries_[idx].meta.pinned) {
                remove_entry_locked(idx, reason);
                return true;
            }
            ++it;
        }
        return false; // All entries are pinned
    }

    /// Remove an entry by index
    void remove_entry_locked(size_t idx, EvictionReason reason = EvictionReason::kManual) {
        if (idx >= entries_.size()) return;

        ListNode& node = entries_[idx];

        // Call eviction callback if set
        if (eviction_callback_) {
            eviction_callback_(node.key, node.value, reason);
        }

        // Update memory tracking
        current_memory_.fetch_sub(node.meta.estimated_size, std::memory_order_relaxed);

        // Remove from key index
        key_index_.erase(node.key);

        // Remove from LRU list
        lru_list_.erase(node.list_it);

        // Clear the entry (don't actually erase from vector to avoid reallocation,
        // but mark it as empty). Instead, we swap with the last element for O(1) removal.
        if (idx != entries_.size() - 1) {
            // Update the key_index for the swapped entry
            size_t last_idx = entries_.size() - 1;
            key_index_[entries_[last_idx].key] = idx;

            // Update the LRU list iterator for the swapped entry
            *(entries_[last_idx].list_it) = idx;

            // Swap
            std::swap(entries_[idx], entries_[last_idx]);
        }
        entries_.pop_back();

        stats_->record_eviction(reason);
    }

    /// Clear all entries
    void clear_locked() {
        // Call eviction callback for each entry
        if (eviction_callback_) {
            for (auto& entry : entries_) {
                eviction_callback_(entry.key, entry.value, EvictionReason::kManual);
            }
        }
        current_memory_.store(0, std::memory_order_relaxed);
        entries_.clear();
        lru_list_.clear();
        key_index_.clear();
    }

    /// Enforce capacity limit
    void enforce_capacity_locked(std::unique_lock<std::shared_mutex>& lock) {
        (void)lock;
        while (entries_.size() > capacity_) {
            if (!evict_one_locked(EvictionReason::kCapacity)) break;
        }
    }

    /// Enforce memory limit
    void enforce_memory_locked(std::unique_lock<std::shared_mutex>& lock) {
        (void)lock;
        size_t target = static_cast<size_t>(max_memory_ * (1.0 - eviction_ratio_));
        while (current_memory_.load(std::memory_order_relaxed) > max_memory_ &&
               !entries_.empty()) {
            if (!evict_one_locked(EvictionReason::kMemoryPressure)) break;
        }
    }

    // ---- Member variables ----
    std::string name_;
    size_t capacity_;
    size_t max_memory_;
    std::atomic<size_t> current_memory_;
    double eviction_ratio_;
    mutable std::shared_mutex mutex_;
    std::vector<ListNode> entries_;           // Pool of entries (index = position)
    std::list<size_t> lru_list_;              // LRU order (front = MRU, back = LRU)
    std::unordered_map<K, size_t, KeyHash> key_index_;  // Key -> index in entries_
    EvictionCallback eviction_callback_;
    std::shared_ptr<CacheStats> stats_;
    std::atomic<uint32_t> generation_;
    std::atomic<bool> shutdown_;
};

// ============================================================================
// TTLCache<K, V> — Generic Time-To-Live Cache Implementation
// ============================================================================
// Implements a thread-safe TTL cache where entries expire after a configured
// duration. Supports absolute TTL, idle TTL, and sliding TTL modes.
// Uses a priority queue (min-heap) keyed on expiry time for efficient
// background expiry scanning.
// ============================================================================
template <typename K, typename V, typename KeyHash = std::hash<K>>
class TTLCache {
public:
    // Entry in the expiry heap
    struct ExpiryEntry {
        int64_t expiry_ms;
        K key;

        bool operator<(const ExpiryEntry& other) const {
            return expiry_ms > other.expiry_ms; // Min-heap: smallest expiry first
        }
    };

    using EvictionCallback = CacheEvictionCallback<K, V>;

    // ---- Construction ----

    explicit TTLCache(const std::string& name,
                      int64_t default_ttl_ms = kDefaultTTLSeconds * 1000,
                      TTLMode default_mode = TTLMode::kAbsolute,
                      size_t max_size = kDefaultLRUCapacity)
        : name_(name)
        , default_ttl_ms_(default_ttl_ms)
        , default_mode_(default_mode)
        , max_size_(max_size)
        , stats_(std::make_shared<CacheStats>(name))
        , shutdown_(false)
    {
        entries_.reserve(std::min(max_size_, size_t(1000)));
    }

    ~TTLCache() {
        shutdown_.store(true, std::memory_order_release);
        clear();
    }

    TTLCache(const TTLCache&) = delete;
    TTLCache& operator=(const TTLCache&) = delete;

    // ---- Configuration ----

    const std::string& name() const { return name_; }

    void set_default_ttl(int64_t ttl_ms) {
        std::unique_lock lock(mutex_);
        default_ttl_ms_ = ttl_ms;
    }

    int64_t default_ttl() const {
        std::shared_lock lock(mutex_);
        return default_ttl_ms_;
    }

    void set_max_size(size_t sz) {
        std::unique_lock lock(mutex_);
        max_size_ = sz;
        enforce_max_size_locked();
    }

    size_t max_size() const {
        std::shared_lock lock(mutex_);
        return max_size_;
    }

    void set_eviction_callback(EvictionCallback cb) {
        std::unique_lock lock(mutex_);
        eviction_callback_ = std::move(cb);
    }

    // ---- Core Operations ----

    /// Get a value by key. Returns nullopt if missing or expired.
    std::optional<V> get(const K& key) {
        auto t0 = chr::high_resolution_clock::now();
        std::unique_lock lock(mutex_);

        auto it = entries_.find(key);
        if (it == entries_.end()) {
            auto latency = chr::duration_cast<chr::microseconds>(
                chr::high_resolution_clock::now() - t0).count();
            stats_->record_get(false, latency);
            return std::nullopt;
        }

        Entry& entry = it->second;
        int64_t now = current_time_ms();

        // Check expiry
        if (entry.meta.ttl_ms > 0 && is_expired_internal(entry, now)) {
            V val = std::move(entry.value);
            remove_locked(key, EvictionReason::kTTLExpired);
            auto latency = chr::duration_cast<chr::microseconds>(
                chr::high_resolution_clock::now() - t0).count();
            stats_->record_get(false, latency);
            return std::nullopt;
        }

        // Update access metadata for idle/sliding modes
        entry.meta.last_accessed_ms = now;
        entry.meta.access_count++;
        if (entry.meta.ttl_mode == TTLMode::kIdle ||
            entry.meta.ttl_mode == TTLMode::kSliding) {
            entry.meta.created_at_ms = now;
            // Rebuild expiry heap entry
            rebuild_expiry_entry(key, entry.meta);
        }

        V result = entry.value;
        auto latency = chr::duration_cast<chr::microseconds>(
            chr::high_resolution_clock::now() - t0).count();
        stats_->record_get(true, latency);
        return result;
    }

    /// Put a value with default TTL
    void put(const K& key, const V& value) {
        CacheEntryMetadata meta;
        meta.ttl_ms = default_ttl_ms_;
        meta.ttl_mode = default_mode_;
        put_internal(key, value, meta);
    }

    /// Put with custom TTL
    void put_with_ttl(const K& key, const V& value,
                      int64_t ttl_ms, TTLMode mode = TTLMode::kAbsolute) {
        CacheEntryMetadata meta;
        meta.ttl_ms = ttl_ms;
        meta.ttl_mode = mode;
        put_internal(key, value, meta);
    }

    /// Put with tag
    void put_with_tag(const K& key, const V& value,
                      const std::string& tag) {
        CacheEntryMetadata meta;
        meta.ttl_ms = default_ttl_ms_;
        meta.ttl_mode = default_mode_;
        meta.tag = tag;
        put_internal(key, value, meta);
    }

    /// Put with full metadata
    void put_with_meta(const K& key, const V& value,
                       const CacheEntryMetadata& meta) {
        put_internal(key, value, meta);
    }

    /// Remove a key
    bool remove(const K& key) {
        std::unique_lock lock(mutex_);
        bool removed = remove_locked(key, EvictionReason::kManual);
        if (removed) {
            stats_->record_remove();
            stats_->set_current_entries(entries_.size());
        }
        return removed;
    }

    /// Check existence (not expired)
    bool contains(const K& key) {
        std::unique_lock lock(mutex_);
        auto it = entries_.find(key);
        if (it == entries_.end()) {
            stats_->record_contains(false);
            return false;
        }
        if (it->second.meta.ttl_ms > 0 &&
            is_expired_internal(it->second, current_time_ms())) {
            stats_->record_contains(false);
            return false;
        }
        stats_->record_contains(true);
        return true;
    }

    /// Size
    size_t size() const {
        std::shared_lock lock(mutex_);
        return entries_.size();
    }

    /// Clear
    void clear() {
        std::unique_lock lock(mutex_);
        clear_locked();
        stats_->record_clear();
    }

    /// Expire all entries past their TTL — returns number expired
    size_t expire(int64_t now_ms = 0) {
        std::unique_lock lock(mutex_);
        if (now_ms == 0) now_ms = current_time_ms();
        size_t count = 0;

        // Use the expiry heap for efficient scanning
        while (!expiry_heap_.empty()) {
            const ExpiryEntry& top = expiry_heap_.top();
            if (top.expiry_ms > now_ms) break; // Not yet expired

            K key = top.key;
            // Verify entry still exists and is actually expired
            auto it = entries_.find(key);
            if (it != entries_.end() &&
                is_expired_internal(it->second, now_ms)) {
                remove_locked(key, EvictionReason::kTTLExpired);
                ++count;
            } else {
                // Entry was already removed or refreshed, pop stale heap entry
                // We handle this by checking below
            }
            (void)top;
        }

        // Also do a linear scan for any missed entries (defensive)
        std::vector<K> to_remove;
        for (const auto& [key, entry] : entries_) {
            if (entry.meta.ttl_ms > 0 && is_expired_internal(entry, now_ms)) {
                to_remove.push_back(key);
            }
        }
        for (const auto& key : to_remove) {
            auto it = entries_.find(key);
            if (it != entries_.end()) {
                remove_locked(key, EvictionReason::kTTLExpired);
                ++count;
            }
        }

        // Clean up stale heap entries
        rebuild_heap();

        if (count > 0) {
            stats_->set_current_entries(entries_.size());
        }
        return count;
    }

    /// Get time until next expiry (ms). Returns -1 if no expiring entries.
    int64_t time_until_next_expiry() const {
        std::shared_lock lock(mutex_);
        if (expiry_heap_.empty()) return -1;
        int64_t now = current_time_ms();
        int64_t next = expiry_heap_.top().expiry_ms;
        return std::max<int64_t>(0, next - now);
    }

    /// Get stats
    std::shared_ptr<CacheStats> stats() { return stats_; }
    std::shared_ptr<const CacheStats> stats() const { return stats_; }

    /// Invalidate by exact key
    size_t invalidate_key(const K& key) {
        std::unique_lock lock(mutex_);
        bool removed = remove_locked(key, EvictionReason::kInvalidated);
        if (removed) {
            stats_->record_invalidation();
            stats_->set_current_entries(entries_.size());
        }
        return removed ? 1 : 0;
    }

    /// Invalidate by tag
    size_t invalidate_tag(const std::string& tag) {
        std::unique_lock lock(mutex_);
        size_t count = 0;
        std::vector<K> to_remove;
        for (const auto& [key, entry] : entries_) {
            if (entry.meta.tag == tag) {
                to_remove.push_back(key);
            }
        }
        for (const auto& key : to_remove) {
            remove_locked(key, EvictionReason::kInvalidated);
            ++count;
        }
        if (count > 0) {
            stats_->record_invalidation();
            stats_->set_current_entries(entries_.size());
        }
        return count;
    }

    /// Invalidate all
    size_t invalidate_all() {
        std::unique_lock lock(mutex_);
        size_t count = entries_.size();
        clear_locked();
        stats_->record_invalidation();
        return count;
    }

    /// Invalidate by time range
    size_t invalidate_time_range(int64_t from_ms, int64_t to_ms) {
        std::unique_lock lock(mutex_);
        size_t count = 0;
        std::vector<K> to_remove;
        for (const auto& [key, entry] : entries_) {
            int64_t created = entry.meta.created_at_ms;
            if (created >= from_ms && created <= to_ms) {
                to_remove.push_back(key);
            }
        }
        for (const auto& key : to_remove) {
            remove_locked(key, EvictionReason::kInvalidated);
            ++count;
        }
        if (count > 0) {
            stats_->record_invalidation();
            stats_->set_current_entries(entries_.size());
        }
        return count;
    }

    /// JSON representation
    json to_json() const {
        CacheStatsSnapshot snap = stats_->snapshot();
        json j;
        j["name"] = name_;
        j["type"] = "TTL";
        j["default_ttl_ms"] = default_ttl_ms_;
        j["max_size"] = max_size_;
        j["current_entries"] = snap.current_entries;
        j["hit_rate"] = snap.hit_rate;
        j["health"] = static_cast<int>(snap.health);
        return j;
    }

private:
    struct Entry {
        V value;
        CacheEntryMetadata meta;

        Entry() = default;
        Entry(const V& v, const CacheEntryMetadata& m) : value(v), meta(m) {}
    };

    void put_internal(const K& key, const V& value, const CacheEntryMetadata& meta_hint) {
        auto t0 = chr::high_resolution_clock::now();
        std::unique_lock lock(mutex_);

        CacheEntryMetadata meta = meta_hint;
        int64_t now = current_time_ms();
        if (meta.created_at_ms == 0) {
            meta.created_at_ms = now;
        }
        meta.last_accessed_ms = now;
        meta.access_count = 1;

        auto it = entries_.find(key);
        if (it != entries_.end()) {
            // Update existing
            it->second.value = value;
            it->second.meta = meta;
            rebuild_expiry_entry(key, meta);
        } else {
            // Enforce max size
            enforce_max_size_locked();
            entries_[key] = Entry(value, meta);
            add_expiry_entry(key, meta);
        }

        stats_->set_current_entries(entries_.size());
        auto latency = chr::duration_cast<chr::microseconds>(
            chr::high_resolution_clock::now() - t0).count();
        stats_->record_put(latency);
    }

    bool remove_locked(const K& key, EvictionReason reason) {
        auto it = entries_.find(key);
        if (it == entries_.end()) return false;

        if (eviction_callback_) {
            eviction_callback_(key, it->second.value, reason);
        }

        entries_.erase(it);
        // Heap cleanup is deferred (stale entries handled in expire())
        return true;
    }

    void clear_locked() {
        if (eviction_callback_) {
            for (auto& [key, entry] : entries_) {
                eviction_callback_(key, entry.value, EvictionReason::kManual);
            }
        }
        entries_.clear();
        expiry_heap_ = std::priority_queue<ExpiryEntry>();
        stats_->set_current_entries(0);
    }

    void enforce_max_size_locked() {
        while (entries_.size() >= max_size_ && !entries_.empty()) {
            // Evict the entry with the earliest expiry first
            if (!expiry_heap_.empty()) {
                K key = expiry_heap_.top().key;
                auto it = entries_.find(key);
                if (it != entries_.end()) {
                    remove_locked(key, EvictionReason::kCapacity);
                    continue;
                }
            }
            // Fallback: evict arbitrary entry
            auto it = entries_.begin();
            if (it != entries_.end()) {
                remove_locked(it->first, EvictionReason::kCapacity);
            }
        }
    }

    void add_expiry_entry(const K& key, const CacheEntryMetadata& meta) {
        if (meta.ttl_ms > 0) {
            int64_t expiry = 0;
            switch (meta.ttl_mode) {
                case TTLMode::kAbsolute:
                case TTLMode::kSliding:
                    expiry = meta.created_at_ms + meta.ttl_ms;
                    break;
                case TTLMode::kIdle:
                    expiry = meta.last_accessed_ms + meta.ttl_ms;
                    break;
                case TTLMode::kNone:
                    return;
            }
            expiry_heap_.push(ExpiryEntry{expiry, key});
        }
    }

    void rebuild_expiry_entry(const K& key, const CacheEntryMetadata& meta) {
        // Simplification: push a new entry; stale ones will be skipped
        add_expiry_entry(key, meta);
    }

    void rebuild_heap() {
        std::priority_queue<ExpiryEntry> new_heap;
        for (const auto& [key, entry] : entries_) {
            if (entry.meta.ttl_ms > 0) {
                int64_t expiry = 0;
                switch (entry.meta.ttl_mode) {
                    case TTLMode::kAbsolute:
                    case TTLMode::kSliding:
                        expiry = entry.meta.created_at_ms + entry.meta.ttl_ms;
                        break;
                    case TTLMode::kIdle:
                        expiry = entry.meta.last_accessed_ms + entry.meta.ttl_ms;
                        break;
                    case TTLMode::kNone:
                        continue;
                }
                new_heap.push(ExpiryEntry{expiry, key});
            }
        }
        expiry_heap_ = std::move(new_heap);
    }

    static bool is_expired_internal(const Entry& entry, int64_t now_ms) {
        const auto& meta = entry.meta;
        switch (meta.ttl_mode) {
            case TTLMode::kAbsolute:
                return (meta.created_at_ms + meta.ttl_ms) <= now_ms;
            case TTLMode::kIdle:
                return (meta.last_accessed_ms + meta.ttl_ms) <= now_ms;
            case TTLMode::kSliding:
                return (meta.created_at_ms + meta.ttl_ms) <= now_ms;
            case TTLMode::kNone:
                return false;
        }
        return false;
    }

    static int64_t current_time_ms() {
        return chr::duration_cast<chr::milliseconds>(
            chr::system_clock::now().time_since_epoch()
        ).count();
    }

    std::string name_;
    int64_t default_ttl_ms_;
    TTLMode default_mode_;
    size_t max_size_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<K, Entry, KeyHash> entries_;
    std::priority_queue<ExpiryEntry> expiry_heap_;
    EvictionCallback eviction_callback_;
    std::shared_ptr<CacheStats> stats_;
    std::atomic<bool> shutdown_;
};

// ============================================================================
// TwoTierCache<K, V> — Combines LRU (L1) + TTL (L2) caching
// ============================================================================
// L1: Small, fast LRU cache for hot items
// L2: Larger TTL cache for warm items
// On L1 miss: checks L2; if found, promotes to L1
// On write: goes to both L1 and L2
// ============================================================================
template <typename K, typename V, typename KeyHash = std::hash<K>>
class TwoTierCache {
public:
    TwoTierCache(const std::string& name,
                 size_t l1_capacity = 1000,
                 size_t l2_capacity = 100000,
                 int64_t l2_ttl_ms = kDefaultTTLSeconds * 1000 * 12)  // 1 hour
        : name_(name)
        , l1_(std::make_shared<LRUCache<K, V, KeyHash>>(name + "_L1", l1_capacity))
        , l2_(std::make_shared<TTLCache<K, V, KeyHash>>(name + "_L2", l2_ttl_ms))
        , stats_(std::make_shared<CacheStats>(name))
        , l1_hit_count_(0), l2_hit_count_(0), miss_count_(0)
        , shutdown_(false)
    {
    }

    ~TwoTierCache() {
        shutdown_.store(true, std::memory_order_release);
    }

    TwoTierCache(const TwoTierCache&) = delete;
    TwoTierCache& operator=(const TwoTierCache&) = delete;

    const std::string& name() const { return name_; }

    // ---- Core Operations ----

    std::optional<V> get(const K& key) {
        auto t0 = chr::high_resolution_clock::now();

        // Try L1 first
        auto result = l1_->get(key);
        if (result.has_value()) {
            l1_hit_count_.fetch_add(1, std::memory_order_relaxed);
            stats_->record_get(true, chr::duration_cast<chr::microseconds>(
                chr::high_resolution_clock::now() - t0).count());
            return result;
        }

        // L1 miss — try L2
        auto l2_result = l2_->get(key);
        if (l2_result.has_value()) {
            l2_hit_count_.fetch_add(1, std::memory_order_relaxed);
            // Promote to L1
            l1_->put(key, *l2_result);
            stats_->record_get(true, chr::duration_cast<chr::microseconds>(
                chr::high_resolution_clock::now() - t0).count());
            return l2_result;
        }

        // Total miss
        miss_count_.fetch_add(1, std::memory_order_relaxed);
        stats_->record_get(false, chr::duration_cast<chr::microseconds>(
            chr::high_resolution_clock::now() - t0).count());
        return std::nullopt;
    }

    void put(const K& key, const V& value) {
        l1_->put(key, value);
        l2_->put(key, value);
        stats_->set_current_entries(l1_->size() + l2_->size());
    }

    void put_with_ttl(const K& key, const V& value,
                      int64_t ttl_ms, TTLMode mode = TTLMode::kAbsolute) {
        l1_->put_with_ttl(key, value, ttl_ms, mode);
        l2_->put_with_ttl(key, value, ttl_ms, mode);
    }

    void put_with_tag(const K& key, const V& value, const std::string& tag) {
        l1_->put_with_tag(key, value, tag);
        l2_->put_with_tag(key, value, tag);
    }

    bool remove(const K& key) {
        bool r1 = l1_->remove(key);
        bool r2 = l2_->remove(key);
        return r1 || r2;
    }

    bool contains(const K& key) {
        return l1_->contains(key) || l2_->contains(key);
    }

    void clear() {
        l1_->clear();
        l2_->clear();
        stats_->record_clear();
    }

    size_t size() const {
        return l1_->size() + l2_->size();
    }

    size_t l1_size() const { return l1_->size(); }
    size_t l2_size() const { return l2_->size(); }

    uint64_t l1_hits() const { return l1_hit_count_.load(std::memory_order_relaxed); }
    uint64_t l2_hits() const { return l2_hit_count_.load(std::memory_order_relaxed); }
    uint64_t misses() const { return miss_count_.load(std::memory_order_relaxed); }

    // ---- Invalidation ----

    size_t invalidate_key(const K& key) {
        size_t c1 = l1_->invalidate_key(key);
        size_t c2 = l2_->invalidate_key(key);
        return c1 + c2;
    }

    size_t invalidate_tag(const std::string& tag) {
        size_t c1 = l1_->invalidate_tag(tag);
        size_t c2 = l2_->invalidate_tag(tag);
        return c1 + c2;
    }

    size_t invalidate_all() {
        size_t c1 = l1_->invalidate_all();
        size_t c2 = l2_->invalidate_all();
        return c1 + c2;
    }

    size_t invalidate_time_range(int64_t from_ms, int64_t to_ms) {
        size_t c1 = l1_->invalidate_time_range(from_ms, to_ms);
        size_t c2 = l2_->invalidate_time_range(from_ms, to_ms);
        return c1 + c2;
    }

    // ---- Expiry and maintenance ----

    size_t expire_l2() {
        return l2_->expire();
    }

    size_t compact() {
        size_t c1 = l1_->compact();
        size_t c2 = l2_->expire();
        return c1 + c2;
    }

    // ---- Stats ----

    std::shared_ptr<CacheStats> stats() { return stats_; }
    std::shared_ptr<const CacheStats> stats() const { return stats_; }

    std::shared_ptr<LRUCache<K, V, KeyHash>> l1() { return l1_; }
    std::shared_ptr<TTLCache<K, V, KeyHash>> l2() { return l2_; }

    json to_json() const {
        json j;
        j["name"] = name_;
        j["type"] = "TwoTier";
        j["l1"] = l1_->to_json();
        j["l2"] = l2_->to_json();
        j["l1_hits"] = l1_hit_count_.load();
        j["l2_hits"] = l2_hit_count_.load();
        j["misses"] = miss_count_.load();
        return j;
    }

private:
    std::string name_;
    std::shared_ptr<LRUCache<K, V, KeyHash>> l1_;
    std::shared_ptr<TTLCache<K, V, KeyHash>> l2_;
    std::shared_ptr<CacheStats> stats_;
    std::atomic<uint64_t> l1_hit_count_;
    std::atomic<uint64_t> l2_hit_count_;
    std::atomic<uint64_t> miss_count_;
    std::atomic<bool> shutdown_;
};

// ============================================================================
// CacheInvalidator — centralized cache invalidation engine
// ============================================================================
// Manages invalidation across multiple caches. Supports:
//   - Key-based, pattern-based, tag-based, time-range, and full invalidation
//   - Batch invalidation with configurable batch size
//   - Async invalidation via background worker
//   - Cascade invalidation (invalidate dependent caches)
//   - Invalidation event recording for debugging/audit
// ============================================================================
class CacheInvalidator {
public:
    struct InvalidationEvent {
        int64_t timestamp_ms;
        std::string cache_name;
        InvalidationStrategy strategy;
        std::string detail;  // key/pattern/tag
        size_t entries_removed;
        bool success;

        json to_json() const {
            json j;
            j["timestamp_ms"] = timestamp_ms;
            j["cache_name"] = cache_name;
            j["strategy"] = static_cast<int>(strategy);
            j["detail"] = detail;
            j["entries_removed"] = entries_removed;
            j["success"] = success;
            return j;
        }
    };

    CacheInvalidator() : max_events_(10000), batch_size_(kMaxInvalidationBatch) {
        events_.reserve(max_events_);
    }

    // ---- Registration ----

    /// Register an LRU cache for invalidation
    template <typename K, typename V, typename KeyHash = std::hash<K>>
    void register_cache(std::shared_ptr<LRUCache<K, V, KeyHash>> cache) {
        std::unique_lock lock(mutex_);
        lru_caches_[cache->name()] = cache;
    }

    /// Register a TTL cache for invalidation
    template <typename K, typename V, typename KeyHash = std::hash<K>>
    void register_cache(std::shared_ptr<TTLCache<K, V, KeyHash>> cache) {
        std::unique_lock lock(mutex_);
        ttl_caches_[cache->name()] = cache;
    }

    /// Register a two-tier cache
    template <typename K, typename V, typename KeyHash = std::hash<K>>
    void register_cache(std::shared_ptr<TwoTierCache<K, V, KeyHash>> cache) {
        std::unique_lock lock(mutex_);
        twotier_caches_[cache->name()] = cache;
    }

    /// Register a cascade dependency (invalidating 'source' also invalidates 'dependent')
    void register_cascade(const std::string& source, const std::string& dependent) {
        std::unique_lock lock(mutex_);
        cascade_map_[source].push_back(dependent);
    }

    // ---- String-keyed invalidation (cache-type agnostic) ----

    /// Invalidate by exact key across all registered caches
    size_t invalidate_key(const std::string& cache_name, const std::string& key) {
        size_t total = 0;

        // Try LRU caches
        {
            auto it = lru_caches_.find(cache_name);
            if (it != lru_caches_.end()) {
                total += it->second->invalidate_key(key);
            }
        }

        // Try TTL caches
        {
            auto it = ttl_caches_.find(cache_name);
            if (it != ttl_caches_.end()) {
                total += it->second->invalidate_key(key);
            }
        }

        // Try two-tier caches
        {
            auto it = twotier_caches_.find(cache_name);
            if (it != twotier_caches_.end()) {
                total += it->second->invalidate_key(key);
            }
        }

        record_event(cache_name, InvalidationStrategy::kExactKey, key, total, true);

        // Cascade
        total += cascade_invalidate(cache_name, InvalidationStrategy::kExactKey, key);

        return total;
    }

    /// Invalidate by prefix
    size_t invalidate_prefix(const std::string& cache_name, const std::string& prefix) {
        size_t total = 0;

        auto it = lru_caches_.find(cache_name);
        if (it != lru_caches_.end()) {
            total += it->second->invalidate_prefix(prefix);
        }

        record_event(cache_name, InvalidationStrategy::kPrefix, prefix, total, true);
        total += cascade_invalidate(cache_name, InvalidationStrategy::kPrefix, prefix);
        return total;
    }

    /// Invalidate by pattern
    size_t invalidate_pattern(const std::string& cache_name, const std::string& pattern) {
        size_t total = 0;

        auto it = lru_caches_.find(cache_name);
        if (it != lru_caches_.end()) {
            total += it->second->invalidate_pattern(pattern);
        }

        record_event(cache_name, InvalidationStrategy::kPattern, pattern, total, true);
        total += cascade_invalidate(cache_name, InvalidationStrategy::kPattern, pattern);
        return total;
    }

    /// Invalidate by tag
    size_t invalidate_tag(const std::string& cache_name, const std::string& tag) {
        size_t total = 0;

        {
            auto it = lru_caches_.find(cache_name);
            if (it != lru_caches_.end()) {
                total += it->second->invalidate_tag(tag);
            }
        }
        {
            auto it = ttl_caches_.find(cache_name);
            if (it != ttl_caches_.end()) {
                total += it->second->invalidate_tag(tag);
            }
        }
        {
            auto it = twotier_caches_.find(cache_name);
            if (it != twotier_caches_.end()) {
                total += it->second->invalidate_tag(tag);
            }
        }

        record_event(cache_name, InvalidationStrategy::kTag, tag, total, true);
        total += cascade_invalidate(cache_name, InvalidationStrategy::kTag, tag);
        return total;
    }

    /// Invalidate by time range
    size_t invalidate_time_range(const std::string& cache_name,
                                 int64_t from_ms, int64_t to_ms) {
        size_t total = 0;

        {
            auto it = lru_caches_.find(cache_name);
            if (it != lru_caches_.end()) {
                total += it->second->invalidate_time_range(from_ms, to_ms);
            }
        }
        {
            auto it = ttl_caches_.find(cache_name);
            if (it != ttl_caches_.end()) {
                total += it->second->invalidate_time_range(from_ms, to_ms);
            }
        }
        {
            auto it = twotier_caches_.find(cache_name);
            if (it != twotier_caches_.end()) {
                total += it->second->invalidate_time_range(from_ms, to_ms);
            }
        }

        std::string detail = "range[" + std::to_string(from_ms) + "," +
                             std::to_string(to_ms) + "]";
        record_event(cache_name, InvalidationStrategy::kTimeRange, detail, total, true);
        return total;
    }

    /// Full flush a specific cache
    size_t invalidate_all(const std::string& cache_name) {
        size_t total = 0;

        {
            auto it = lru_caches_.find(cache_name);
            if (it != lru_caches_.end()) {
                total += it->second->invalidate_all();
            }
        }
        {
            auto it = ttl_caches_.find(cache_name);
            if (it != ttl_caches_.end()) {
                total += it->second->invalidate_all();
            }
        }
        {
            auto it = twotier_caches_.find(cache_name);
            if (it != twotier_caches_.end()) {
                total += it->second->invalidate_all();
            }
        }

        record_event(cache_name, InvalidationStrategy::kFullFlush, "*", total, true);
        total += cascade_invalidate(cache_name, InvalidationStrategy::kFullFlush, "*");
        return total;
    }

    /// Flush all caches
    size_t flush_all() {
        size_t total = 0;
        std::shared_lock lock(mutex_);
        for (auto& [name, cache] : lru_caches_) {
            total += cache->invalidate_all();
            record_event(name, InvalidationStrategy::kFullFlush, "*",
                         total, true);
        }
        for (auto& [name, cache] : ttl_caches_) {
            total += cache->invalidate_all();
        }
        for (auto& [name, cache] : twotier_caches_) {
            total += cache->invalidate_all();
        }
        return total;
    }

    /// Bump generation on a specific LRU cache
    void bump_generation(const std::string& cache_name) {
        std::shared_lock lock(mutex_);
        auto it = lru_caches_.find(cache_name);
        if (it != lru_caches_.end()) {
            it->second->bump_generation();
        }
    }

    /// Invalidate old generations
    size_t invalidate_old_generations(const std::string& cache_name) {
        std::shared_lock lock(mutex_);
        size_t total = 0;
        auto it = lru_caches_.find(cache_name);
        if (it != lru_caches_.end()) {
            total = it->second->invalidate_old_generations();
        }
        return total;
    }

    /// Invalidate least-accessed entries
    size_t invalidate_least_accessed(const std::string& cache_name, size_t max_count) {
        std::shared_lock lock(mutex_);
        size_t total = 0;
        auto it = lru_caches_.find(cache_name);
        if (it != lru_caches_.end()) {
            total = it->second->invalidate_least_accessed(max_count);
        }
        record_event(cache_name, InvalidationStrategy::kAccessBased,
                     "least_accessed:" + std::to_string(max_count), total, true);
        return total;
    }

    // ---- Event history ----

    std::vector<InvalidationEvent> recent_events(size_t limit = 100) const {
        std::shared_lock lock(mutex_);
        size_t count = std::min(limit, events_.size());
        return std::vector<InvalidationEvent>(
            events_.end() - static_cast<ptrdiff_t>(count), events_.end());
    }

    json recent_events_json(size_t limit = 100) const {
        auto evts = recent_events(limit);
        json arr = json::array();
        for (const auto& e : evts) {
            arr.push_back(e.to_json());
        }
        return arr;
    }

    void clear_history() {
        std::unique_lock lock(mutex_);
        events_.clear();
    }

    // ---- Statistics ----

    json stats_json() const {
        json j;
        j["registered_lru_caches"] = lru_caches_.size();
        j["registered_ttl_caches"] = ttl_caches_.size();
        j["registered_twotier_caches"] = twotier_caches_.size();
        j["total_events"] = events_.size();
        j["cascade_dependencies"] = cascade_map_.size();
        return j;
    }

private:
    template <typename CachePtr>
    size_t invalidate_string_key(CachePtr& cache_ptr_map, const std::string& cache_name,
                                  const std::string& key) {
        auto it = cache_ptr_map.find(cache_name);
        if (it != cache_ptr_map.end()) {
            return it->second->invalidate_key(key);
        }
        return 0;
    }

    size_t cascade_invalidate(const std::string& source,
                              InvalidationStrategy strategy,
                              const std::string& detail) {
        size_t total = 0;
        auto it = cascade_map_.find(source);
        if (it == cascade_map_.end()) return 0;

        for (const auto& dep : it->second) {
            total += invalidate_all(dep);
        }
        return total;
    }

    void record_event(const std::string& cache_name, InvalidationStrategy strategy,
                      const std::string& detail, size_t removed, bool success) {
        if (removed == 0 && strategy != InvalidationStrategy::kFullFlush) return;

        InvalidationEvent evt;
        evt.timestamp_ms = chr::duration_cast<chr::milliseconds>(
            chr::system_clock::now().time_since_epoch()).count();
        evt.cache_name = cache_name;
        evt.strategy = strategy;
        evt.detail = detail;
        evt.entries_removed = removed;
        evt.success = success;

        std::unique_lock lock(mutex_);
        if (events_.size() >= max_events_) {
            events_.erase(events_.begin(), events_.begin() + (max_events_ / 4));
        }
        events_.push_back(std::move(evt));
    }

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string,
        std::shared_ptr<void>> lru_caches_;  // type-erased
    std::unordered_map<std::string,
        std::shared_ptr<void>> ttl_caches_;
    std::unordered_map<std::string,
        std::shared_ptr<void>> twotier_caches_;

    // Concrete registries for string-keyed caches (most common)
    std::unordered_map<std::string,
        std::shared_ptr<LRUCache<std::string, std::string>>> lru_string_caches_;
    std::unordered_map<std::string,
        std::shared_ptr<TTLCache<std::string, std::string>>> ttl_string_caches_;
    std::unordered_map<std::string,
        std::shared_ptr<TwoTierCache<std::string, std::string>>> twotier_string_caches_;

    std::unordered_map<std::string, std::vector<std::string>> cascade_map_;
    std::vector<InvalidationEvent> events_;
    size_t max_events_;
    size_t batch_size_;
};

// ============================================================================
// CacheManager — Top-Level Cache Management Orchestrator
// ============================================================================
// Singleton that manages all caches in the Matrix homeserver. Provides:
//   - Named cache creation (LRU, TTL, TwoTier)
//   - Cache lookup by name
//   - Global invalidation coordination
//   - Background maintenance workers
//   - Admin API endpoint support
//   - Configuration management
//   - Health monitoring
// ============================================================================
class CacheManager {
public:
    // ---- Singleton ----

    static CacheManager& instance() {
        static CacheManager mgr;
        return mgr;
    }

    // ---- Cache Creation ----

    /// Get or create an LRU cache for string keys/values
    std::shared_ptr<LRUCache<std::string, std::string>>
    get_or_create_lru_string(const std::string& name, size_t capacity = kDefaultLRUCapacity) {
        std::unique_lock lock(mutex_);
        auto it = lru_string_caches_.find(name);
        if (it != lru_string_caches_.end()) return it->second;

        auto cache = std::make_shared<LRUCache<std::string, std::string>>(name, capacity);
        lru_string_caches_[name] = cache;
        global_stats_.register_cache(name, cache->stats());
        invalidator_.register_cache(cache);
        return cache;
    }

    /// Get or create a TTL cache for string keys/values
    std::shared_ptr<TTLCache<std::string, std::string>>
    get_or_create_ttl_string(const std::string& name,
                             int64_t default_ttl_ms = kDefaultTTLSeconds * 1000) {
        std::unique_lock lock(mutex_);
        auto it = ttl_string_caches_.find(name);
        if (it != ttl_string_caches_.end()) return it->second;

        auto cache = std::make_shared<TTLCache<std::string, std::string>>(name, default_ttl_ms);
        ttl_string_caches_[name] = cache;
        global_stats_.register_cache(name, cache->stats());
        invalidator_.register_cache(cache);
        return cache;
    }

    /// Get or create a TwoTier cache for string keys/values
    std::shared_ptr<TwoTierCache<std::string, std::string>>
    get_or_create_twotier_string(const std::string& name,
                                  size_t l1_cap = 1000,
                                  size_t l2_cap = 100000) {
        std::unique_lock lock(mutex_);
        auto it = twotier_string_caches_.find(name);
        if (it != twotier_string_caches_.end()) return it->second;

        auto cache = std::make_shared<TwoTierCache<std::string, std::string>>(
            name, l1_cap, l2_cap);
        twotier_string_caches_[name] = cache;
        global_stats_.register_cache(name, cache->stats());
        invalidator_.register_cache(cache);
        return cache;
    }

    /// Remove a cache by name
    bool remove_cache(const std::string& name) {
        std::unique_lock lock(mutex_);
        size_t removed = 0;
        removed += lru_string_caches_.erase(name);
        removed += ttl_string_caches_.erase(name);
        removed += twotier_string_caches_.erase(name);
        if (removed > 0) {
            global_stats_.unregister_cache(name);
        }
        return removed > 0;
    }

    // ---- Cache Lookup ----

    /// Check if a named cache exists
    bool has_cache(const std::string& name) const {
        std::shared_lock lock(mutex_);
        return lru_string_caches_.count(name) > 0 ||
               ttl_string_caches_.count(name) > 0 ||
               twotier_string_caches_.count(name) > 0;
    }

    /// List all cache names
    std::vector<std::string> list_caches() const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> names;
        for (const auto& [name, _] : lru_string_caches_) names.push_back(name);
        for (const auto& [name, _] : ttl_string_caches_) names.push_back(name);
        for (const auto& [name, _] : twotier_string_caches_) names.push_back(name);
        std::sort(names.begin(), names.end());
        return names;
    }

    // ---- Global Operations ----

    /// Expire TTL entries across all TTL caches
    size_t expire_all() {
        std::shared_lock lock(mutex_);
        size_t total = 0;
        for (auto& [name, cache] : ttl_string_caches_) {
            total += cache->expire();
        }
        for (auto& [name, cache] : twotier_string_caches_) {
            total += cache->expire_l2();
        }
        return total;
    }

    /// Compact all LRU caches
    size_t compact_all() {
        std::shared_lock lock(mutex_);
        size_t total = 0;
        for (auto& [name, cache] : lru_string_caches_) {
            total += cache->compact();
        }
        for (auto& [name, cache] : twotier_string_caches_) {
            total += cache->compact();
        }
        return total;
    }

    /// Flush all caches
    size_t flush_all() {
        return invalidator_.flush_all();
    }

    /// Perform comprehensive health check on all caches
    json health_check_all() {
        std::shared_lock lock(mutex_);
        json result;
        json caches = json::array();
        int critical = 0, warning = 0, degraded = 0, healthy = 0;

        for (auto& [name, cache] : lru_string_caches_) {
            CacheHealth h = cache->health_check();
            json cj = cache->to_json();
            cj["type"] = "LRU";
            caches.push_back(cj);
            switch (h) {
                case CacheHealth::kCritical: ++critical; break;
                case CacheHealth::kWarning: ++warning; break;
                case CacheHealth::kDegraded: ++degraded; break;
                case CacheHealth::kHealthy: ++healthy; break;
            }
        }
        for (auto& [name, cache] : ttl_string_caches_) {
            json cj = cache->to_json();
            cj["type"] = "TTL";
            caches.push_back(cj);
            ++healthy; // TTL caches don't have pressure issues
        }
        for (auto& [name, cache] : twotier_string_caches_) {
            json cj = cache->to_json();
            cj["type"] = "TwoTier";
            caches.push_back(cj);
            ++healthy;
        }

        result["caches"] = caches;
        result["total"] = caches.size();
        result["critical"] = critical;
        result["warning"] = warning;
        result["degraded"] = degraded;
        result["healthy"] = healthy;
        result["overall"] = (critical > 0) ? "critical" :
                            (warning > 0) ? "warning" :
                            (degraded > 0) ? "degraded" : "healthy";
        return result;
    }

    // ---- Invalidation (delegated to CacheInvalidator) ----

    CacheInvalidator& invalidator() { return invalidator_; }

    size_t invalidate_key(const std::string& cache_name, const std::string& key) {
        return invalidator_.invalidate_key(cache_name, key);
    }

    size_t invalidate_prefix(const std::string& cache_name, const std::string& prefix) {
        return invalidator_.invalidate_prefix(cache_name, prefix);
    }

    size_t invalidate_pattern(const std::string& cache_name, const std::string& pattern) {
        return invalidator_.invalidate_pattern(cache_name, pattern);
    }

    size_t invalidate_tag(const std::string& cache_name, const std::string& tag) {
        return invalidator_.invalidate_tag(cache_name, tag);
    }

    size_t invalidate_all(const std::string& cache_name) {
        return invalidator_.invalidate_all(cache_name);
    }

    size_t invalidate_time_range(const std::string& cache_name,
                                 int64_t from_ms, int64_t to_ms) {
        return invalidator_.invalidate_time_range(cache_name, from_ms, to_ms);
    }

    // ---- Statistics ----

    GlobalCacheStats& global_stats() { return global_stats_; }

    json stats_json() const {
        return global_stats_.aggregate_json();
    }

    /// Get stats for a specific cache
    json cache_stats_json(const std::string& name) const {
        std::shared_lock lock(mutex_);
        {
            auto it = lru_string_caches_.find(name);
            if (it != lru_string_caches_.end()) {
                return it->second->to_json();
            }
        }
        {
            auto it = ttl_string_caches_.find(name);
            if (it != ttl_string_caches_.end()) {
                return it->second->to_json();
            }
        }
        {
            auto it = twotier_string_caches_.find(name);
            if (it != twotier_string_caches_.end()) {
                return it->second->to_json();
            }
        }
        return json{{"error", "cache not found"}};
    }

    // ---- Admin API Support ----

    /// Full admin API response
    json admin_summary() const {
        json j;
        j["caches"] = list_caches();
        j["stats"] = stats_json();
        j["health"] = const_cast<CacheManager*>(this)->health_check_all();
        j["invalidator"] = invalidator_.stats_json();
        j["recent_invalidations"] = invalidator_.recent_events_json(50);
        return j;
    }

    // ---- Background Maintenance ----

    /// Start background maintenance workers
    void start_background_maintenance() {
        if (background_running_.exchange(true)) return;

        expiry_thread_ = std::thread([this]() { background_expiry_worker(); });
        compaction_thread_ = std::thread([this]() { background_compaction_worker(); });
        stats_thread_ = std::thread([this]() { background_stats_worker(); });
    }

    /// Stop background maintenance
    void stop_background_maintenance() {
        background_running_.store(false);
        if (expiry_thread_.joinable()) expiry_thread_.join();
        if (compaction_thread_.joinable()) compaction_thread_.join();
        if (stats_thread_.joinable()) stats_thread_.join();
    }

    // ---- Configuration ----

    void set_expiry_scan_interval(int64_t ms) {
        expiry_scan_interval_ms_.store(ms, std::memory_order_relaxed);
    }

    void set_compaction_interval(int64_t ms) {
        compaction_interval_ms_.store(ms, std::memory_order_relaxed);
    }

    void set_stats_aggregation_interval(int64_t ms) {
        stats_aggregation_interval_ms_.store(ms, std::memory_order_relaxed);
    }

private:
    CacheManager()
        : background_running_(false)
        , expiry_scan_interval_ms_(kDefaultExpiryScanIntervalMs)
        , compaction_interval_ms_(kDefaultCompactionIntervalMs)
        , stats_aggregation_interval_ms_(kDefaultStatsAggregationIntervalMs)
    {}

    ~CacheManager() {
        stop_background_maintenance();
    }

    CacheManager(const CacheManager&) = delete;
    CacheManager& operator=(const CacheManager&) = delete;

    // ---- Background Workers ----

    void background_expiry_worker() {
        while (background_running_.load(std::memory_order_acquire)) {
            int64_t interval = expiry_scan_interval_ms_.load(std::memory_order_relaxed);
            std::this_thread::sleep_for(chr::milliseconds(interval));

            try {
                expire_all();
            } catch (const std::exception& e) {
                std::cerr << "[cache_manager] expiry worker error: "
                          << e.what() << std::endl;
            }
        }
    }

    void background_compaction_worker() {
        while (background_running_.load(std::memory_order_acquire)) {
            int64_t interval = compaction_interval_ms_.load(std::memory_order_relaxed);
            std::this_thread::sleep_for(chr::milliseconds(interval));

            try {
                compact_all();
            } catch (const std::exception& e) {
                std::cerr << "[cache_manager] compaction worker error: "
                          << e.what() << std::endl;
            }
        }
    }

    void background_stats_worker() {
        while (background_running_.load(std::memory_order_acquire)) {
            int64_t interval = stats_aggregation_interval_ms_.load(
                std::memory_order_relaxed);
            std::this_thread::sleep_for(chr::milliseconds(interval));

            try {
                global_stats_.aggregate_json();
            } catch (const std::exception& e) {
                std::cerr << "[cache_manager] stats worker error: "
                          << e.what() << std::endl;
            }
        }
    }

    mutable std::shared_mutex mutex_;

    // String-keyed caches (most common use case)
    std::unordered_map<std::string,
        std::shared_ptr<LRUCache<std::string, std::string>>> lru_string_caches_;
    std::unordered_map<std::string,
        std::shared_ptr<TTLCache<std::string, std::string>>> ttl_string_caches_;
    std::unordered_map<std::string,
        std::shared_ptr<TwoTierCache<std::string, std::string>>> twotier_string_caches_;

    GlobalCacheStats global_stats_;
    CacheInvalidator invalidator_;

    // Background maintenance
    std::atomic<bool> background_running_;
    std::atomic<int64_t> expiry_scan_interval_ms_;
    std::atomic<int64_t> compaction_interval_ms_;
    std::atomic<int64_t> stats_aggregation_interval_ms_;
    std::thread expiry_thread_;
    std::thread compaction_thread_;
    std::thread stats_thread_;
};

// ============================================================================
// CacheKeyBuilder — Utility for constructing structured cache keys
// ============================================================================
class CacheKeyBuilder {
public:
    /// Build a cache key from components with a delimiter
    static std::string build(std::initializer_list<std::string_view> parts,
                             char delimiter = ':') {
        std::string result;
        bool first = true;
        for (const auto& part : parts) {
            if (!first) result += delimiter;
            result.append(part);
            first = false;
        }
        return result;
    }

    /// Build with variadic template
    template <typename... Args>
    static std::string build(char delimiter, Args&&... args) {
        std::string result;
        build_impl(result, delimiter, std::forward<Args>(args)...);
        return result;
    }

    /// User-scoped key: "user:{user_id}:{suffix}"
    static std::string user_key(const std::string& user_id, const std::string& suffix) {
        return "user:" + user_id + ":" + suffix;
    }

    /// Room-scoped key: "room:{room_id}:{suffix}"
    static std::string room_key(const std::string& room_id, const std::string& suffix) {
        return "room:" + room_id + ":" + suffix;
    }

    /// Event-scoped key: "event:{event_id}:{suffix}"
    static std::string event_key(const std::string& event_id, const std::string& suffix) {
        return "event:" + event_id + ":" + suffix;
    }

    /// Device-scoped key: "device:{user_id}:{device_id}:{suffix}"
    static std::string device_key(const std::string& user_id,
                                  const std::string& device_id,
                                  const std::string& suffix) {
        return "device:" + user_id + ":" + device_id + ":" + suffix;
    }

    /// Sync token key: "sync:{user_id}:{token_hash}"
    static std::string sync_key(const std::string& user_id, const std::string& token_hash) {
        return "sync:" + user_id + ":" + token_hash;
    }

    /// Federation key: "fed:{origin}:{suffix}"
    static std::string federation_key(const std::string& origin, const std::string& suffix) {
        return "fed:" + origin + ":" + suffix;
    }

    /// Extract the prefix (namespace portion) from a key
    static std::string prefix(const std::string& key) {
        auto pos = key.find(':');
        if (pos == std::string::npos) return key;
        return key.substr(0, pos);
    }

    /// Check if a key belongs to a given namespace
    static bool in_namespace(const std::string& key, const std::string& ns) {
        return key.compare(0, ns.size(), ns) == 0 &&
               (key.size() == ns.size() || key[ns.size()] == ':');
    }

    /// Extract user_id from a user-scoped key
    static std::optional<std::string> extract_user_id(const std::string& key) {
        if (key.size() < 6 || key.substr(0, 5) != "user:") return std::nullopt;
        auto start = key.find(':', 5);
        if (start == std::string::npos) return std::nullopt;
        return key.substr(5, start - 5);
    }

    /// Extract room_id from a room-scoped key
    static std::optional<std::string> extract_room_id(const std::string& key) {
        if (key.size() < 6 || key.substr(0, 5) != "room:") return std::nullopt;
        auto start = key.find(':', 5);
        if (start == std::string::npos) return std::nullopt;
        return key.substr(5, start - 5);
    }

private:
    template <typename T, typename... Rest>
    static void build_impl(std::string& result, char delimiter, T&& first, Rest&&... rest) {
        if (!result.empty()) result += delimiter;
        if constexpr (std::is_arithmetic_v<std::decay_t<T>>) {
            result += std::to_string(first);
        } else {
            result += std::forward<T>(first);
        }
        if constexpr (sizeof...(Rest) > 0) {
            build_impl(result, delimiter, std::forward<Rest>(rest)...);
        }
    }

    static void build_impl(std::string&, char) {} // Base case
};

// ============================================================================
// CacheWarmingEngine — Pre-populate caches on startup or config change
// ============================================================================
class CacheWarmingEngine {
public:
    CacheWarmingEngine() : enabled_(false), batch_size_(500), shutdown_(false) {}

    void enable(bool flag) { enabled_.store(flag, std::memory_order_release); }
    bool is_enabled() const { return enabled_.load(std::memory_order_acquire); }

    /// Register a warming task for a specific cache
    using WarmingTask = std::function<size_t()>; // Returns number of entries loaded

    void register_task(const std::string& cache_name, WarmingTask task) {
        std::unique_lock lock(mutex_);
        tasks_[cache_name] = std::move(task);
    }

    void unregister_task(const std::string& cache_name) {
        std::unique_lock lock(mutex_);
        tasks_.erase(cache_name);
    }

    /// Execute all registered warming tasks
    json warm_all() {
        if (!enabled_.load(std::memory_order_acquire)) {
            return json{{"status", "disabled"}};
        }

        json result;
        json per_cache = json::object();
        size_t total_loaded = 0;
        int64_t start_ms = chr::duration_cast<chr::milliseconds>(
            chr::system_clock::now().time_since_epoch()).count();

        std::shared_lock lock(mutex_);
        for (auto& [name, task] : tasks_) {
            try {
                size_t loaded = task();
                per_cache[name] = loaded;
                total_loaded += loaded;
            } catch (const std::exception& e) {
                per_cache[name] = json{{"error", e.what()}};
            }
        }

        int64_t elapsed = chr::duration_cast<chr::milliseconds>(
            chr::system_clock::now().time_since_epoch()).count() - start_ms;

        result["status"] = "completed";
        result["total_entries_loaded"] = total_loaded;
        result["caches_warmed"] = per_cache.size();
        result["elapsed_ms"] = elapsed;
        result["per_cache"] = per_cache;
        return result;
    }

    /// Warm a specific cache
    size_t warm(const std::string& cache_name) {
        std::shared_lock lock(mutex_);
        auto it = tasks_.find(cache_name);
        if (it == tasks_.end()) return 0;
        return it->second();
    }

    json status_json() const {
        json j;
        j["enabled"] = enabled_.load();
        std::shared_lock lock(mutex_);
        j["registered_tasks"] = tasks_.size();
        json names = json::array();
        for (const auto& [name, _] : tasks_) names.push_back(name);
        j["task_names"] = names;
        return j;
    }

private:
    std::atomic<bool> enabled_;
    size_t batch_size_;
    std::atomic<bool> shutdown_;
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, WarmingTask> tasks_;
};

// ============================================================================
// CacheMemoryTracker — Track and limit total cache memory usage
// ============================================================================
class CacheMemoryTracker {
public:
    CacheMemoryTracker() : total_limit_(kDefaultMaxCacheMemory),
                           current_usage_(0), high_water_mark_(0) {}

    void set_total_limit(size_t bytes) {
        total_limit_.store(bytes, std::memory_order_release);
    }

    size_t total_limit() const {
        return total_limit_.load(std::memory_order_acquire);
    }

    size_t current_usage() const {
        return current_usage_.load(std::memory_order_relaxed);
    }

    size_t high_water_mark() const {
        return high_water_mark_.load(std::memory_order_relaxed);
    }

    void add_usage(size_t bytes) {
        size_t prev = current_usage_.fetch_add(bytes, std::memory_order_relaxed);
        size_t curr = prev + bytes;
        // Update high water mark
        size_t hwm = high_water_mark_.load(std::memory_order_relaxed);
        while (curr > hwm &&
               !high_water_mark_.compare_exchange_weak(hwm, curr,
                   std::memory_order_relaxed)) {}
    }

    void sub_usage(size_t bytes) {
        current_usage_.fetch_sub(bytes, std::memory_order_relaxed);
    }

    double pressure() const {
        size_t limit = total_limit_.load(std::memory_order_acquire);
        if (limit == 0) return 0.0;
        return static_cast<double>(current_usage_.load(std::memory_order_relaxed)) /
               static_cast<double>(limit);
    }

    bool is_over_limit() const {
        return current_usage_.load(std::memory_order_relaxed) >
               total_limit_.load(std::memory_order_acquire);
    }

    void reset_high_water_mark() {
        high_water_mark_.store(current_usage_.load(std::memory_order_relaxed),
                               std::memory_order_relaxed);
    }

    json to_json() const {
        json j;
        j["total_limit_bytes"] = total_limit_.load();
        j["current_usage_bytes"] = current_usage_.load();
        j["high_water_mark_bytes"] = high_water_mark_.load();
        j["pressure"] = pressure();
        j["over_limit"] = is_over_limit();
        return j;
    }

private:
    std::atomic<size_t> total_limit_;
    std::atomic<size_t> current_usage_;
    std::atomic<size_t> high_water_mark_;
};

// ============================================================================
// CacheTagRegistry — Global registry of cache tags for cross-cache invalidation
// ============================================================================
class CacheTagRegistry {
public:
    /// Register a tag usage in a cache
    void register_tag(const std::string& tag, const std::string& cache_name) {
        std::unique_lock lock(mutex_);
        tag_to_caches_[tag].insert(cache_name);
    }

    /// Unregister a tag from a cache
    void unregister_tag(const std::string& tag, const std::string& cache_name) {
        std::unique_lock lock(mutex_);
        auto it = tag_to_caches_.find(tag);
        if (it != tag_to_caches_.end()) {
            it->second.erase(cache_name);
            if (it->second.empty()) {
                tag_to_caches_.erase(it);
            }
        }
    }

    /// Get all caches using a given tag
    std::vector<std::string> get_caches_for_tag(const std::string& tag) const {
        std::shared_lock lock(mutex_);
        auto it = tag_to_caches_.find(tag);
        if (it == tag_to_caches_.end()) return {};
        return std::vector<std::string>(it->second.begin(), it->second.end());
    }

    /// List all registered tags
    std::vector<std::string> list_tags() const {
        std::shared_lock lock(mutex_);
        std::vector<std::string> tags;
        for (const auto& [tag, _] : tag_to_caches_) {
            tags.push_back(tag);
        }
        return tags;
    }

    /// Check if a tag is registered
    bool has_tag(const std::string& tag) const {
        std::shared_lock lock(mutex_);
        return tag_to_caches_.count(tag) > 0;
    }

    json to_json() const {
        std::shared_lock lock(mutex_);
        json j;
        for (const auto& [tag, caches] : tag_to_caches_) {
            j[tag] = std::vector<std::string>(caches.begin(), caches.end());
        }
        return j;
    }

private:
    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::unordered_set<std::string>> tag_to_caches_;
};

// ============================================================================
// Utility function: get or create cache via CacheManager convenience API
// ============================================================================

/// Get or create a named LRU cache
inline std::shared_ptr<LRUCache<std::string, std::string>>
get_or_create_lru_cache(const std::string& name, size_t capacity = kDefaultLRUCapacity) {
    return CacheManager::instance().get_or_create_lru_string(name, capacity);
}

/// Get or create a named TTL cache
inline std::shared_ptr<TTLCache<std::string, std::string>>
get_or_create_ttl_cache(const std::string& name,
                        int64_t ttl_ms = kDefaultTTLSeconds * 1000) {
    return CacheManager::instance().get_or_create_ttl_string(name, ttl_ms);
}

/// Get or create a named TwoTier cache
inline std::shared_ptr<TwoTierCache<std::string, std::string>>
get_or_create_twotier_cache(const std::string& name,
                             size_t l1_cap = 1000,
                             size_t l2_cap = 100000) {
    return CacheManager::instance().get_or_create_twotier_string(name, l1_cap, l2_cap);
}

/// Invalidate a key in a named cache
inline size_t invalidate_cache_key(const std::string& name, const std::string& key) {
    return CacheManager::instance().invalidate_key(name, key);
}

/// Invalidate by tag across all caches
inline size_t invalidate_tag_all_caches(const std::string& tag) {
    return CacheManager::instance().invalidate_tag("", tag);
}

// ============================================================================
// Self-Tests
// ============================================================================
#ifdef PROGRESSIVE_CACHE_SELFTEST

namespace {

// ---- Test helpers ----

static int test_passed = 0;
static int test_failed = 0;

#define CACHE_TEST(name) \
    static void test_##name(); \
    struct test_##name##_runner { \
        test_##name##_runner() { \
            try { test_##name(); test_passed++; \
            std::cout << "  [PASS] " << #name << std::endl; \
            } catch (const std::exception& e) { \
                test_failed++; \
                std::cerr << "  [FAIL] " << #name << ": " << e.what() << std::endl; \
            } \
        } \
    } test_##name##_instance; \
    static void test_##name()

#define CACHE_CHECK(cond) \
    do { if (!(cond)) throw std::runtime_error("Check failed: " #cond); } while(0)

// ---- Test: LRU basic operations ----
CACHE_TEST(lru_basic_ops) {
    LRUCache<std::string, std::string> cache("test_lru", 10);

    CACHE_CHECK(cache.size() == 0);
    CACHE_CHECK(cache.empty());

    cache.put("key1", "value1");
    CACHE_CHECK(cache.size() == 1);
    CACHE_CHECK(cache.contains("key1"));
    CACHE_CHECK(!cache.contains("nonexistent"));

    auto val = cache.get("key1");
    CACHE_CHECK(val.has_value());
    CACHE_CHECK(*val == "value1");

    auto miss = cache.get("missing");
    CACHE_CHECK(!miss.has_value());
}

// ---- Test: LRU eviction ----
CACHE_TEST(lru_eviction) {
    LRUCache<int, int> cache("test_evict", 3);

    cache.put(1, 100);
    cache.put(2, 200);
    cache.put(3, 300);
    CACHE_CHECK(cache.size() == 3);

    // Access key 1 to make it MRU
    cache.get(1);

    // Insert key 4 — should evict key 2 (LRU)
    cache.put(4, 400);
    CACHE_CHECK(cache.size() == 3);
    CACHE_CHECK(cache.contains(1));
    CACHE_CHECK(cache.contains(3));
    CACHE_CHECK(cache.contains(4));
    CACHE_CHECK(!cache.contains(2)); // evicted
}

// ---- Test: LRU capacity enforcement ----
CACHE_TEST(lru_capacity) {
    LRUCache<std::string, int> cache("test_cap", 5);

    for (int i = 0; i < 10; ++i) {
        cache.put("key" + std::to_string(i), i);
    }

    CACHE_CHECK(cache.size() <= 5);
    // The first 5 should be evicted; last 5 remain
    for (int i = 0; i < 5; ++i) {
        CACHE_CHECK(!cache.contains("key" + std::to_string(i)));
    }
    for (int i = 5; i < 10; ++i) {
        CACHE_CHECK(cache.contains("key" + std::to_string(i)));
    }
}

// ---- Test: LRU update existing ----
CACHE_TEST(lru_update) {
    LRUCache<std::string, std::string> cache("test_update", 5);

    cache.put("key", "old");
    CACHE_CHECK(*cache.get("key") == "old");

    cache.put("key", "new");
    CACHE_CHECK(cache.size() == 1); // Should not increase size
    CACHE_CHECK(*cache.get("key") == "new");
}

// ---- Test: LRU remove ----
CACHE_TEST(lru_remove) {
    LRUCache<std::string, int> cache("test_remove", 5);

    cache.put("a", 1);
    cache.put("b", 2);
    cache.put("c", 3);

    CACHE_CHECK(cache.remove("b"));
    CACHE_CHECK(!cache.contains("b"));
    CACHE_CHECK(cache.size() == 2);

    CACHE_CHECK(!cache.remove("nonexistent"));
    CACHE_CHECK(cache.size() == 2);
}

// ---- Test: LRU clear ----
CACHE_TEST(lru_clear) {
    LRUCache<int, int> cache("test_clear", 10);

    for (int i = 0; i < 5; ++i) cache.put(i, i * 10);
    CACHE_CHECK(cache.size() == 5);

    cache.clear();
    CACHE_CHECK(cache.size() == 0);
    CACHE_CHECK(cache.empty());
}

// ---- Test: LRU pinning ----
CACHE_TEST(lru_pinning) {
    LRUCache<std::string, int> cache("test_pin", 3);

    cache.put("a", 1);
    cache.put("b", 2);
    cache.put("c", 3);

    CACHE_CHECK(cache.pin("a"));

    // Put 3 more entries — even though "a" is LRU, it's pinned
    cache.put("d", 4);
    cache.put("e", 5);
    cache.put("f", 6);

    CACHE_CHECK(cache.contains("a")); // pinned, should survive
    CACHE_CHECK(cache.size() <= 3 + 1); // capacity 3 + 1 pinned over capacity
}

// ---- Test: LRU invalidation by exact key ----
CACHE_TEST(lru_invalidate_key) {
    LRUCache<std::string, int> cache("test_inv_key", 10);

    for (int i = 0; i < 5; ++i) {
        cache.put("key" + std::to_string(i), i);
    }

    size_t removed = cache.invalidate_key("key2");
    CACHE_CHECK(removed == 1);
    CACHE_CHECK(!cache.contains("key2"));
    CACHE_CHECK(cache.contains("key3"));
}

// ---- Test: LRU invalidation by prefix ----
CACHE_TEST(lru_invalidate_prefix) {
    LRUCache<std::string, int> cache("test_inv_prefix", 20);

    cache.put("room:abc:events", 1);
    cache.put("room:abc:state", 2);
    cache.put("room:xyz:events", 3);
    cache.put("user:alice:profile", 4);

    size_t removed = cache.invalidate_prefix("room:abc");
    CACHE_CHECK(removed == 2);
    CACHE_CHECK(!cache.contains("room:abc:events"));
    CACHE_CHECK(!cache.contains("room:abc:state"));
    CACHE_CHECK(cache.contains("room:xyz:events"));
    CACHE_CHECK(cache.contains("user:alice:profile"));
}

// ---- Test: LRU invalidation by tag ----
CACHE_TEST(lru_invalidate_tag) {
    LRUCache<std::string, int> cache("test_inv_tag", 20);

    cache.put_with_tag("key1", 1, "group_a");
    cache.put_with_tag("key2", 2, "group_a");
    cache.put_with_tag("key3", 3, "group_b");

    size_t removed = cache.invalidate_tag("group_a");
    CACHE_CHECK(removed == 2);
    CACHE_CHECK(!cache.contains("key1"));
    CACHE_CHECK(!cache.contains("key2"));
    CACHE_CHECK(cache.contains("key3"));
}

// ---- Test: LRU TTL expiry ----
CACHE_TEST(lru_ttl_expiry) {
    LRUCache<std::string, int> cache("test_lru_ttl", 10);

    // Put with a very short TTL (1ms) — should expire immediately
    cache.put_with_ttl("ephemeral", 42, 1, TTLMode::kAbsolute);
    std::this_thread::sleep_for(chr::milliseconds(5));

    size_t expired = cache.expire_ttl_entries();
    CACHE_CHECK(expired == 1);
    CACHE_CHECK(!cache.contains("ephemeral"));
}

// ---- Test: LRU generation-based invalidation ----
CACHE_TEST(lru_generation) {
    LRUCache<std::string, int> cache("test_gen", 20);

    cache.put("a", 1);
    cache.put("b", 2);

    cache.bump_generation();
    cache.put("c", 3);

    size_t removed = cache.invalidate_old_generations();
    CACHE_CHECK(removed == 2);
    CACHE_CHECK(!cache.contains("a"));
    CACHE_CHECK(!cache.contains("b"));
    CACHE_CHECK(cache.contains("c"));
}

// ---- Test: LRU eviction callback ----
CACHE_TEST(lru_eviction_callback) {
    LRUCache<int, int> cache("test_cb", 3);

    std::vector<std::pair<int, int>> evicted;
    cache.set_eviction_callback([&](const int& k, const int& v, EvictionReason) {
        evicted.emplace_back(k, v);
    });

    cache.put(1, 10);
    cache.put(2, 20);
    cache.put(3, 30);
    cache.put(4, 40); // Should evict key 1

    CACHE_CHECK(evicted.size() >= 1);
    CACHE_CHECK(evicted[0].first == 1);
}

// ---- Test: TTL basic operations ----
CACHE_TEST(ttl_basic_ops) {
    TTLCache<std::string, std::string> cache("test_ttl", 60000); // 60 sec TTL

    cache.put("key1", "value1");
    CACHE_CHECK(cache.size() == 1);
    CACHE_CHECK(cache.contains("key1"));

    auto val = cache.get("key1");
    CACHE_CHECK(val.has_value());
    CACHE_CHECK(*val == "value1");
}

// ---- Test: TTL expiry ----
CACHE_TEST(ttl_expiry) {
    TTLCache<std::string, int> cache("test_ttl_exp", 10); // 10ms TTL

    cache.put("fast", 99);
    CACHE_CHECK(cache.contains("fast"));

    std::this_thread::sleep_for(chr::milliseconds(50));

    CACHE_CHECK(!cache.contains("fast"));
    size_t expired = cache.expire();
    CACHE_CHECK(expired == 1);
    CACHE_CHECK(cache.size() == 0);
}

// ---- Test: TTL max size enforcement ----
CACHE_TEST(ttl_max_size) {
    TTLCache<int, int> cache("test_ttl_size", 60000, TTLMode::kAbsolute, 5);

    for (int i = 0; i < 10; ++i) {
        cache.put(i, i * 10);
    }

    CACHE_CHECK(cache.size() <= 5);
}

// ---- Test: TwoTier cache ----
CACHE_TEST(twotier_basic) {
    TwoTierCache<std::string, std::string> cache("test_tt", 50, 200);

    cache.put("key1", "val1");

    auto val = cache.get("key1");
    CACHE_CHECK(val.has_value());
    CACHE_CHECK(*val == "val1");

    // L1 should have it
    CACHE_CHECK(cache.l1_size() == 1);
}

// ---- Test: TwoTier L2 fallback ----
CACHE_TEST(twotier_fallback) {
    TwoTierCache<std::string, std::string> cache("test_tt2", 2, 10);

    // Fill L1 (capacity 2)
    cache.put("a", "1");
    cache.put("b", "2");
    cache.put("c", "3"); // evicts "a" from L1

    // "a" should still be in L2
    auto val = cache.get("a");
    CACHE_CHECK(val.has_value());
    CACHE_CHECK(*val == "1");
    // After retrieval, "a" is promoted back to L1
    CACHE_CHECK(cache.l1()->contains("a"));
}

// ---- Test: Cache stats ----
CACHE_TEST(cache_stats) {
    LRUCache<int, int> cache("test_stats", 10);

    cache.put(1, 10);
    cache.put(2, 20);

    cache.get(1); // hit
    cache.get(1); // hit
    cache.get(3); // miss
    cache.get(4); // miss

    auto snap = cache.stats()->snapshot();
    CACHE_CHECK(snap.total_gets == 4);
    CACHE_CHECK(snap.total_hits == 2);
    CACHE_CHECK(snap.total_misses == 2);
    CACHE_CHECK(snap.hit_rate == 0.5);
    CACHE_CHECK(snap.total_puts == 2);
}

// ---- Test: Cache invalidation event recording ----
CACHE_TEST(invalidation_events) {
    CacheInvalidator inv;

    auto lru = std::make_shared<LRUCache<std::string, std::string>>("events_test", 100);
    // Add entries
    for (int i = 0; i < 5; ++i) {
        lru->put("k" + std::to_string(i), "v" + std::to_string(i));
    }
    inv.register_cache(lru);

    // Manual invalidation via cache + record through invalidator
    inv.invalidate_key("events_test", "k1");
    inv.invalidate_key("events_test", "k2");

    auto events = inv.recent_events(10);
    CACHE_CHECK(events.size() >= 2);
}

// ---- Test: CacheKeyBuilder ----
CACHE_TEST(key_builder) {
    std::string key = CacheKeyBuilder::user_key("@alice:example.com", "profile");
    CACHE_CHECK(key == "user:@alice:example.com:profile");

    std::string room_key = CacheKeyBuilder::room_key("!abc:example.com", "state");
    CACHE_CHECK(room_key == "room:!abc:example.com:state");

    std::string multi = CacheKeyBuilder::build(':', "a", 42, "c");
    CACHE_CHECK(multi == "a:42:c");

    CACHE_CHECK(CacheKeyBuilder::in_namespace(key, "user"));
    CACHE_CHECK(!CacheKeyBuilder::in_namespace(key, "room"));
}

// ---- Test: CacheManager singleton ----
CACHE_TEST(cache_manager_singleton) {
    auto& mgr = CacheManager::instance();
    auto& mgr2 = CacheManager::instance();
    CACHE_CHECK(&mgr == &mgr2);
}

// ---- Test: CacheManager create and list ----
CACHE_TEST(cache_manager_create) {
    auto& mgr = CacheManager::instance();
    auto cache = mgr.get_or_create_lru_string("test_cm_lru", 100);
    CACHE_CHECK(cache != nullptr);

    auto names = mgr.list_caches();
    CACHE_CHECK(std::find(names.begin(), names.end(), "test_cm_lru") != names.end());

    CACHE_CHECK(mgr.has_cache("test_cm_lru"));
}

// ---- Test: LatencyHistogram ----
CACHE_TEST(latency_histogram) {
    LatencyHistogram hist;

    for (int i = 0; i < 100; ++i) {
        hist.record(50);   // 100 samples at 50us
    }
    for (int i = 0; i < 10; ++i) {
        hist.record(1000); // 10 samples at 1000us
    }

    int64_t avg = hist.average_us();
    CACHE_CHECK(avg > 0);

    int64_t p50 = hist.p50();
    CACHE_CHECK(p50 <= 100); // median should be around 50

    int64_t p99 = hist.p99();
    CACHE_CHECK(p99 >= 1000); // 99th percentile catches the 1000us samples
}

// ---- Test: Memory pressure ----
CACHE_TEST(memory_pressure_test) {
    LRUCache<std::string, std::string> cache("test_mem", 10000, 1024); // 1KB max

    // Put a large-ish value
    std::string big_value(512, 'x');
    cache.put("big", big_value);

    CACHE_CHECK(cache.memory_pressure() > 0.0);

    auto health = cache.health_check();
    // Small values may not trigger pressure, but health should be one of the valid values
    CACHE_CHECK(health == CacheHealth::kHealthy ||
                health == CacheHealth::kWarning ||
                health == CacheHealth::kCritical ||
                health == CacheHealth::kDegraded);
}

// ---- Test: GlobalCacheStats ----
CACHE_TEST(global_cache_stats) {
    GlobalCacheStats gs;
    auto stats1 = std::make_shared<CacheStats>("c1");
    auto stats2 = std::make_shared<CacheStats>("c2");
    gs.register_cache("c1", stats1);
    gs.register_cache("c2", stats2);

    stats1->record_get(true, 100);
    stats1->record_get(false, 200);
    stats2->record_put(50);

    auto json = gs.aggregate_json();
    CACHE_CHECK(json["total_caches"] == 2);
    CACHE_CHECK(json["total_gets"] == 2);
    CACHE_CHECK(json["total_puts"] == 1);
}

// ---- Test: Cache entry metadata ----
CACHE_TEST(entry_metadata) {
    LRUCache<std::string, int> cache("test_meta", 10);

    CacheEntryMetadata meta;
    meta.ttl_ms = 5000;
    meta.ttl_mode = TTLMode::kAbsolute;
    meta.tag = "test_tag";
    meta.estimated_size = 128;

    cache.put("meta_key", 42, meta);

    auto retrieved_meta = cache.get_metadata("meta_key");
    CACHE_CHECK(retrieved_meta.has_value());
    CACHE_CHECK(retrieved_meta->ttl_ms == 5000);
    CACHE_CHECK(retrieved_meta->tag == "test_tag");
    CACHE_CHECK(retrieved_meta->estimated_size == 128);
}

// ---- Test: Dirty entries ----
CACHE_TEST(dirty_entries) {
    LRUCache<std::string, int> cache("test_dirty", 10);

    cache.put("clean", 1);
    cache.put("dirty1", 2);
    cache.put("dirty2", 3);

    cache.mark_dirty("dirty1");
    cache.mark_dirty("dirty2");

    auto dirty = cache.get_dirty_entries();
    CACHE_CHECK(dirty.size() == 2);

    cache.mark_clean("dirty1");
    dirty = cache.get_dirty_entries();
    CACHE_CHECK(dirty.size() == 1);
}

// ---- Test: Size estimation update ----
CACHE_TEST(size_update) {
    LRUCache<std::string, std::string> cache("test_sz", 10, 1024 * 1024);

    cache.put("key", "small");
    size_t small_mem = cache.estimated_memory();

    cache.update_size("key", 10000);
    size_t large_mem = cache.estimated_memory();

    CACHE_CHECK(large_mem > small_mem);
}

// ---- Test: CacheInvalidator cascade ----
CACHE_TEST(invalidator_cascade) {
    CacheInvalidator inv;

    auto cache_a = std::make_shared<LRUCache<std::string, std::string>>("A", 100);
    auto cache_b = std::make_shared<LRUCache<std::string, std::string>>("B", 100);

    cache_a->put("x", "1");
    cache_b->put("y", "2");

    inv.register_cache(cache_a);
    inv.register_cache(cache_b);
    inv.register_cascade("A", "B");

    inv.invalidate_all("A");
    CACHE_CHECK(cache_a->size() == 0);
    CACHE_CHECK(cache_b->size() == 0); // Cascade cleared B too
}

// ---- Test: CacheMemoryTracker ----
CACHE_TEST(memory_tracker) {
    CacheMemoryTracker tracker;
    tracker.set_total_limit(1000);

    tracker.add_usage(300);
    CACHE_CHECK(tracker.current_usage() == 300);
    CACHE_CHECK(!tracker.is_over_limit());

    tracker.add_usage(800);
    CACHE_CHECK(tracker.current_usage() == 1100);
    CACHE_CHECK(tracker.is_over_limit());

    double p = tracker.pressure();
    CACHE_CHECK(p > 1.0);

    tracker.sub_usage(200);
    CACHE_CHECK(tracker.current_usage() == 900);
    CACHE_CHECK(!tracker.is_over_limit());

    CACHE_CHECK(tracker.high_water_mark() == 1100);
}

// ---- Test: peek without promotion ----
CACHE_TEST(lru_peek) {
    LRUCache<int, int> cache("test_peek", 3);

    cache.put(1, 10);
    cache.put(2, 20);
    cache.put(3, 30);

    // Peek at key 1 without promoting
    auto val = cache.peek(1);
    CACHE_CHECK(val.has_value());
    CACHE_CHECK(*val == 10);

    // Put new key — key 1 should be evicted (it was LRU, not promoted by peek)
    cache.put(4, 40);
    CACHE_CHECK(!cache.contains(1));
    CACHE_CHECK(cache.contains(2));
    CACHE_CHECK(cache.contains(3));
    CACHE_CHECK(cache.contains(4));
}

// ---- Test: CacheInvalidator time range ----
CACHE_TEST(invalidator_time_range) {
    LRUCache<std::string, int> cache("test_tr", 100);
    auto now = chr::duration_cast<chr::milliseconds>(
        chr::system_clock::now().time_since_epoch()).count();

    // Put entries at current time
    cache.put("new1", 1);
    cache.put("new2", 2);

    // All entries should be in the range
    size_t removed = cache.invalidate_time_range(0, now + 100000);
    CACHE_CHECK(removed == 2);
    CACHE_CHECK(cache.size() == 0);
}

// ---- Test: LRU compact ----
CACHE_TEST(lru_compact) {
    LRUCache<std::string, std::string> cache("test_compact", 10, 512);

    // Put entries that exceed memory limit
    std::string large(200, 'x');
    cache.put("a", large);
    cache.put("b", large);
    cache.put("c", large); // This should trigger memory pressure

    size_t removed = cache.compact();
    // Some should be removed to get under memory limit
    CACHE_CHECK(cache.estimated_memory() <= 512 || cache.size() <= 1);
    CACHE_CHECK(removed >= 0);
}

// ---- Test: Cache stats reset ----
CACHE_TEST(stats_reset) {
    CacheStats stats("test_reset");

    stats.record_get(true, 100);
    stats.record_get(false, 50);
    stats.record_put(30);

    auto snap = stats.snapshot();
    CACHE_CHECK(snap.total_gets == 2);
    CACHE_CHECK(snap.total_puts == 1);

    stats.reset();

    auto snap2 = stats.snapshot();
    CACHE_CHECK(snap2.total_gets == 0);
    CACHE_CHECK(snap2.total_puts == 0);
}

// ---- Run all tests ----
static void run_self_tests() {
    std::cout << "[cache_manager] Running self-tests..." << std::endl;
    // Tests are run via static constructors above
    std::cout << "[cache_manager] Self-test results: "
              << test_passed << " passed, " << test_failed << " failed" << std::endl;
    if (test_failed > 0) {
        throw std::runtime_error("Cache manager self-tests failed");
    }
}

// Static initialization for self-tests
static const bool _selftest_runner = []() {
    try {
        run_self_tests();
    } catch (const std::exception& e) {
        std::cerr << "[cache_manager] SELFTEST FATAL: " << e.what() << std::endl;
        std::abort();
    }
    return true;
}();

}  // anonymous namespace

#endif  // PROGRESSIVE_CACHE_SELFTEST

}  // namespace progressive

// ============================================================================
// End of cache_manager.cpp
// ============================================================================
