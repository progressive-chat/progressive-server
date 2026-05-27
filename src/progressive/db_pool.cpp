// =============================================================================
// progressive::db_pool.cpp - Matrix Database Connection and Transaction Pool
//
// A comprehensive database connection pool implementation providing:
//   - Thread-safe connection pooling with dynamic scaling
//   - Transaction management with savepoint-based nesting
//   - Read/write splitting for master/replica topologies
//   - Per-connection LRU prepared statement cache
//   - Query logging with slow query detection
//   - Retry logic with exponential backoff and jitter
//   - Comprehensive connection pool metrics
//
// Namespace: progressive::
// Target: 2500+ lines of production-quality C++
// =============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <functional>
#include <iomanip>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <variant>
#include <vector>

#include "util/log.hpp"
#include "storage/database.hpp"
#include "storage/engine.hpp"
#include "storage/types.hpp"

namespace progressive {

// =============================================================================
// Internal logger helper (matches pattern in database.cpp)
// =============================================================================
namespace util {
struct LoggerImpl {
  std::string name_;
  void debug(const std::string& msg) { log::info(name_, "[DEBUG] " + msg); }
  void info(const std::string& msg)  { log::info(name_, msg); }
  void warn(const std::string& msg)  { log::warn(name_, msg); }
  void error(const std::string& msg) { log::error(name_, msg); }
};

inline LoggerImpl& get_logger(const std::string& name) {
  static thread_local std::map<std::string, LoggerImpl> loggers;
  return loggers[name];
}
}  // namespace util

// =============================================================================
// Forward declarations
// =============================================================================
namespace storage {
class DatabaseConnection;
class DatabaseTransaction;
class BaseDatabaseEngine;
class LoggingDatabaseConnection;
class LoggingTransaction;
}  // namespace storage

// =============================================================================
// Type aliases for clarity
// =============================================================================
using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Duration = Clock::duration;
using storage::DBException;
using storage::IsolationLevel;
using storage::Row;
using storage::RowList;
using storage::SQLParam;

// =============================================================================
// Anonymous namespace for internal implementation details
// =============================================================================
namespace {

// ---------------------------------------------------------------------------
// Logger helpers
// ---------------------------------------------------------------------------
auto& pool_logger = util::get_logger("progressive.db_pool");
auto& query_logger = util::get_logger("progressive.db_pool.query");
auto& txn_logger = util::get_logger("progressive.db_pool.txn");
auto& slow_logger = util::get_logger("progressive.db_pool.slow");

// ---------------------------------------------------------------------------
// Utility: truncate string
// ---------------------------------------------------------------------------
std::string truncate_str(const std::string& s, size_t max_len = 200) {
  if (s.size() <= max_len) return s;
  return s.substr(0, max_len - 3) + "...";
}

// ---------------------------------------------------------------------------
// Utility: SQL param to string representation
// ---------------------------------------------------------------------------
std::string param_repr(const SQLParam& param) {
  return std::visit(
      [](const auto& val) -> std::string {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::string>) {
          std::string escaped = "'";
          for (char c : val) {
            if (c == '\'') escaped += "''"; else escaped += c;
          }
          escaped += "'";
          return escaped;
        } else if constexpr (std::is_same_v<T, int64_t>) {
          return std::to_string(val);
        } else if constexpr (std::is_same_v<T, double>) {
          return std::to_string(val);
        } else if constexpr (std::is_same_v<T, std::nullptr_t>) {
          return "NULL";
        }
        return "?";
      },
      param);
}

// ---------------------------------------------------------------------------
// Utility: is_write_query heuristic
// ---------------------------------------------------------------------------
bool is_write_query(const std::string& sql) {
  // Quick upper-cased prefix check
  std::string upper;
  upper.reserve(std::min(sql.size(), size_t(20)));
  for (size_t i = 0; i < sql.size() && i < 20; ++i) {
    upper += static_cast<char>(std::toupper(static_cast<unsigned char>(sql[i])));
  }
  return (upper.find("INSERT") == 0 || upper.find("UPDATE") == 0 ||
          upper.find("DELETE") == 0 || upper.find("REPLACE") == 0 ||
          upper.find("UPSERT") == 0 || upper.find("MERGE") == 0 ||
          upper.find("DROP") == 0 || upper.find("ALTER") == 0 ||
          upper.find("CREATE") == 0 || upper.find("TRUNCATE") == 0);
}

// ---------------------------------------------------------------------------
// Utility: hash SQL for prepared statement cache keys
// ---------------------------------------------------------------------------
std::string hash_sql(const std::string& sql) {
  std::hash<std::string> hasher;
  return std::to_string(hasher(sql));
}

// ---------------------------------------------------------------------------
// Utility: one-line SQL for logging
// ---------------------------------------------------------------------------
std::string sql_one_line(std::string sql) {
  // Replace newlines and collapse whitespace
  std::replace(sql.begin(), sql.end(), '\n', ' ');
  std::replace(sql.begin(), sql.end(), '\r', ' ');
  std::replace(sql.begin(), sql.end(), '\t', ' ');
  // Collapse multiple spaces
  std::string result;
  bool last_was_space = false;
  for (char c : sql) {
    if (c == ' ') {
      if (!last_was_space) result += c;
      last_was_space = true;
    } else {
      result += c;
      last_was_space = false;
    }
  }
  return result;
}

// =============================================================================
// PoolMetrics - Atomic metrics collection for the connection pool
// =============================================================================
class PoolMetrics {
public:
  // --- Counters (atomic, lock-free) ---

  void record_connection_created() noexcept {
    total_created_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_connection_destroyed() noexcept {
    total_destroyed_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_connection_acquired() noexcept {
    total_acquired_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_connection_released() noexcept {
    total_released_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_acquire_timeout() noexcept {
    acquire_timeouts_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_connection_failed() noexcept {
    connection_failures_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_deadlock_retry() noexcept {
    deadlock_retries_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_retry_attempt() noexcept {
    retry_attempts_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_retry_success() noexcept {
    retry_successes_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_retry_exhausted() noexcept {
    retry_exhausted_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_stmt_cache_hit() noexcept {
    stmt_cache_hits_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_stmt_cache_miss() noexcept {
    stmt_cache_misses_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_stmt_cache_evict() noexcept {
    stmt_cache_evictions_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_query(Duration elapsed, bool is_slow) noexcept {
    total_queries_.fetch_add(1, std::memory_order_relaxed);
    if (is_slow) {
      slow_queries_.fetch_add(1, std::memory_order_relaxed);
    }
    double ms = std::chrono::duration<double, std::milli>(elapsed).count();
    // Atomic double via CAS loop
    double expected = total_query_time_ms_.load(std::memory_order_relaxed);
    while (!total_query_time_ms_.compare_exchange_weak(
        expected, expected + ms, std::memory_order_relaxed, std::memory_order_relaxed)) {}
  }

  void record_transaction_begin() noexcept {
    active_transactions_.fetch_add(1, std::memory_order_relaxed);
  }
  void record_transaction_end() noexcept {
    active_transactions_.fetch_sub(1, std::memory_order_relaxed);
  }
  void record_transaction_rollback() noexcept {
    total_rollbacks_.fetch_add(1, std::memory_order_relaxed);
  }

  // --- Getters ---

  int64_t total_created() const noexcept { return total_created_.load(std::memory_order_relaxed); }
  int64_t total_destroyed() const noexcept { return total_destroyed_.load(std::memory_order_relaxed); }
  int64_t total_acquired() const noexcept { return total_acquired_.load(std::memory_order_relaxed); }
  int64_t total_released() const noexcept { return total_released_.load(std::memory_order_relaxed); }
  int64_t acquire_timeouts() const noexcept { return acquire_timeouts_.load(std::memory_order_relaxed); }
  int64_t connection_failures() const noexcept { return connection_failures_.load(std::memory_order_relaxed); }
  int64_t deadlock_retries() const noexcept { return deadlock_retries_.load(std::memory_order_relaxed); }
  int64_t retry_attempts() const noexcept { return retry_attempts_.load(std::memory_order_relaxed); }
  int64_t retry_successes() const noexcept { return retry_successes_.load(std::memory_order_relaxed); }
  int64_t retry_exhausted() const noexcept { return retry_exhausted_.load(std::memory_order_relaxed); }
  int64_t stmt_cache_hits() const noexcept { return stmt_cache_hits_.load(std::memory_order_relaxed); }
  int64_t stmt_cache_misses() const noexcept { return stmt_cache_misses_.load(std::memory_order_relaxed); }
  int64_t stmt_cache_evictions() const noexcept { return stmt_cache_evictions_.load(std::memory_order_relaxed); }
  int64_t total_queries() const noexcept { return total_queries_.load(std::memory_order_relaxed); }
  int64_t slow_queries() const noexcept { return slow_queries_.load(std::memory_order_relaxed); }
  int64_t active_transactions() const noexcept { return active_transactions_.load(std::memory_order_relaxed); }
  int64_t total_rollbacks() const noexcept { return total_rollbacks_.load(std::memory_order_relaxed); }
  double total_query_time_ms() const noexcept { return total_query_time_ms_.load(std::memory_order_relaxed); }

  // Returns average query time in ms
  double avg_query_time_ms() const noexcept {
    int64_t q = total_queries();
    if (q == 0) return 0.0;
    return total_query_time_ms() / static_cast<double>(q);
  }

  // Returns statement cache hit ratio as [0.0, 1.0]
  double stmt_cache_hit_ratio() const noexcept {
    int64_t hits = stmt_cache_hits();
    int64_t misses = stmt_cache_misses();
    int64_t total = hits + misses;
    if (total == 0) return 0.0;
    return static_cast<double>(hits) / static_cast<double>(total);
  }

  // Returns retry success rate as [0.0, 1.0]
  double retry_success_rate() const noexcept {
    int64_t total = retry_successes() + retry_exhausted();
    if (total == 0) return 0.0;
    return static_cast<double>(retry_successes()) / static_cast<double>(total);
  }

  // --- Snapshot for reporting ---
  struct Snapshot {
    int64_t total_created;
    int64_t total_destroyed;
    int64_t total_acquired;
    int64_t total_released;
    int64_t acquire_timeouts;
    int64_t connection_failures;
    int64_t deadlock_retries;
    int64_t retry_attempts;
    int64_t retry_successes;
    int64_t retry_exhausted;
    int64_t stmt_cache_hits;
    int64_t stmt_cache_misses;
    int64_t stmt_cache_evictions;
    int64_t total_queries;
    int64_t slow_queries;
    int64_t active_transactions;
    int64_t total_rollbacks;
    double avg_query_time_ms;
    double stmt_cache_hit_ratio;
    double retry_success_rate;
    int active_connections;
    int idle_read_connections;
    int idle_write_connections;
    int waiting_threads;
    int pool_size;
  };

  Snapshot snapshot(int active, int idle_read, int idle_write,
                    int waiting, int pool_size) const noexcept {
    Snapshot s{};
    s.total_created = total_created();
    s.total_destroyed = total_destroyed();
    s.total_acquired = total_acquired();
    s.total_released = total_released();
    s.acquire_timeouts = acquire_timeouts();
    s.connection_failures = connection_failures();
    s.deadlock_retries = deadlock_retries();
    s.retry_attempts = retry_attempts();
    s.retry_successes = retry_successes();
    s.retry_exhausted = retry_exhausted();
    s.stmt_cache_hits = stmt_cache_hits();
    s.stmt_cache_misses = stmt_cache_misses();
    s.stmt_cache_evictions = stmt_cache_evictions();
    s.total_queries = total_queries();
    s.slow_queries = slow_queries();
    s.active_transactions = active_transactions();
    s.total_rollbacks = total_rollbacks();
    s.avg_query_time_ms = avg_query_time_ms();
    s.stmt_cache_hit_ratio = stmt_cache_hit_ratio();
    s.retry_success_rate = retry_success_rate();
    s.active_connections = active;
    s.idle_read_connections = idle_read;
    s.idle_write_connections = idle_write;
    s.waiting_threads = waiting;
    s.pool_size = pool_size;
    return s;
  }

  // Reset all counters (useful for testing)
  void reset() noexcept {
    total_created_.store(0, std::memory_order_relaxed);
    total_destroyed_.store(0, std::memory_order_relaxed);
    total_acquired_.store(0, std::memory_order_relaxed);
    total_released_.store(0, std::memory_order_relaxed);
    acquire_timeouts_.store(0, std::memory_order_relaxed);
    connection_failures_.store(0, std::memory_order_relaxed);
    deadlock_retries_.store(0, std::memory_order_relaxed);
    retry_attempts_.store(0, std::memory_order_relaxed);
    retry_successes_.store(0, std::memory_order_relaxed);
    retry_exhausted_.store(0, std::memory_order_relaxed);
    stmt_cache_hits_.store(0, std::memory_order_relaxed);
    stmt_cache_misses_.store(0, std::memory_order_relaxed);
    stmt_cache_evictions_.store(0, std::memory_order_relaxed);
    total_queries_.store(0, std::memory_order_relaxed);
    slow_queries_.store(0, std::memory_order_relaxed);
    active_transactions_.store(0, std::memory_order_relaxed);
    total_rollbacks_.store(0, std::memory_order_relaxed);
    total_query_time_ms_.store(0.0, std::memory_order_relaxed);
  }

private:
  std::atomic<int64_t> total_created_{0};
  std::atomic<int64_t> total_destroyed_{0};
  std::atomic<int64_t> total_acquired_{0};
  std::atomic<int64_t> total_released_{0};
  std::atomic<int64_t> acquire_timeouts_{0};
  std::atomic<int64_t> connection_failures_{0};
  std::atomic<int64_t> deadlock_retries_{0};
  std::atomic<int64_t> retry_attempts_{0};
  std::atomic<int64_t> retry_successes_{0};
  std::atomic<int64_t> retry_exhausted_{0};
  std::atomic<int64_t> stmt_cache_hits_{0};
  std::atomic<int64_t> stmt_cache_misses_{0};
  std::atomic<int64_t> stmt_cache_evictions_{0};
  std::atomic<int64_t> total_queries_{0};
  std::atomic<int64_t> slow_queries_{0};
  std::atomic<int64_t> active_transactions_{0};
  std::atomic<int64_t> total_rollbacks_{0};
  std::atomic<double> total_query_time_ms_{0.0};
};

// =============================================================================
// PreparedStatementCache - Per-connection LRU cache of prepared statements
// =============================================================================
class PreparedStatementCache {
public:
  struct PreparedStmt {
    std::string sql;
    std::string stmt_name;       // identifier (e.g., "stmt_<hash>")
    TimePoint last_used;
    int use_count = 0;
    double avg_execution_ms = 0.0;
  };

  explicit PreparedStatementCache(size_t max_size = 150,
                                   PoolMetrics* metrics = nullptr)
      : max_size_(max_size), metrics_(metrics) {}

  // Look up a prepared statement by SQL hash
  std::optional<std::string> get(const std::string& sql) {
    auto key = hash_sql(sql);
    auto it = cache_map_.find(key);
    if (it == cache_map_.end()) {
      if (metrics_) metrics_->record_stmt_cache_miss();
      return std::nullopt;
    }
    // Move to front of LRU (most recently used)
    lru_list_.splice(lru_list_.begin(), lru_list_, it->second);
    it->second->last_used = Clock::now();
    it->second->use_count++;
    if (metrics_) metrics_->record_stmt_cache_hit();
    return it->second->stmt_name;
  }

  // Store a new prepared statement in cache
  void put(const std::string& sql, const std::string& stmt_name) {
    auto key = hash_sql(sql);
    auto it = cache_map_.find(key);
    if (it != cache_map_.end()) {
      // Update existing entry
      it->second->sql = sql;
      it->second->stmt_name = stmt_name;
      it->second->last_used = Clock::now();
      it->second->use_count++;
      lru_list_.splice(lru_list_.begin(), lru_list_, it->second);
      return;
    }

    // Evict least recently used if at capacity
    if (lru_list_.size() >= max_size_) {
      auto last = std::prev(lru_list_.end());
      cache_map_.erase(hash_sql(last->sql));
      lru_list_.pop_back();
      if (metrics_) metrics_->record_stmt_cache_evict();
    }

    // Insert new entry
    lru_list_.emplace_front();
    lru_list_.front().sql = sql;
    lru_list_.front().stmt_name = stmt_name;
    lru_list_.front().last_used = Clock::now();
    lru_list_.front().use_count = 1;
    cache_map_[key] = lru_list_.begin();
  }

  // Remove a specific statement by SQL
  void remove(const std::string& sql) {
    auto key = hash_sql(sql);
    auto it = cache_map_.find(key);
    if (it != cache_map_.end()) {
      lru_list_.erase(it->second);
      cache_map_.erase(it);
    }
  }

  // Get cache statistics
  struct CacheStats {
    size_t size;
    size_t max_size;
    int total_uses;
    int most_used_count;
    std::string most_used_sql;
    TimePoint oldest_entry;
  };

  CacheStats stats() const {
    CacheStats s{};
    s.size = lru_list_.size();
    s.max_size = max_size_;
    s.total_uses = 0;
    s.most_used_count = 0;
    for (const auto& stmt : lru_list_) {
      s.total_uses += stmt.use_count;
      if (stmt.use_count > s.most_used_count) {
        s.most_used_count = stmt.use_count;
        s.most_used_sql = truncate_str(stmt.sql, 80);
      }
    }
    if (!lru_list_.empty()) {
      s.oldest_entry = lru_list_.back().last_used;
    }
    return s;
  }

  // Evict entries older than a given duration
  size_t evict_older_than(Duration max_age) {
    auto now = Clock::now();
    size_t evicted = 0;
    auto it = lru_list_.begin();
    while (it != lru_list_.end()) {
      if (now - it->last_used > max_age) {
        cache_map_.erase(hash_sql(it->sql));
        it = lru_list_.erase(it);
        evicted++;
      } else {
        ++it;
      }
    }
    return evicted;
  }

  // Clear all entries
  void clear() {
    lru_list_.clear();
    cache_map_.clear();
  }

  size_t size() const { return lru_list_.size(); }
  size_t max_size() const { return max_size_; }

  // Record execution time for a cached statement
  void record_execution_time(const std::string& sql, double ms) {
    auto it = cache_map_.find(hash_sql(sql));
    if (it != cache_map_.end()) {
      auto& stmt = *it->second;
      if (stmt.use_count <= 1) {
        stmt.avg_execution_ms = ms;
      } else {
        // Exponential moving average
        constexpr double alpha = 0.1;
        stmt.avg_execution_ms =
            alpha * ms + (1.0 - alpha) * stmt.avg_execution_ms;
      }
    }
  }

private:
  size_t max_size_;
  PoolMetrics* metrics_;
  std::list<PreparedStmt> lru_list_;
  std::unordered_map<std::string, std::list<PreparedStmt>::iterator> cache_map_;
};

// =============================================================================
// QueryLogEntry - Single query execution record
// =============================================================================
struct QueryLogEntry {
  TimePoint timestamp;
  std::string sql_truncated;
  double duration_ms;
  int connection_id;
  int thread_id;
  bool is_write;
  bool success;
  std::string error_msg;
};

// =============================================================================
// QueryLog - Thread-safe circular buffer of recent queries
// =============================================================================
class QueryLog {
public:
  explicit QueryLog(size_t capacity = 5000) : capacity_(capacity) {
    entries_.reserve(capacity_);
  }

  void record(const std::string& sql, double duration_ms,
              int connection_id, int thread_id, bool is_write,
              bool success, const std::string& error_msg = "") {
    std::lock_guard<std::mutex> lock(mutex_);
    if (entries_.size() >= capacity_) {
      entries_[write_pos_] = {
          Clock::now(), truncate_str(sql, 200), duration_ms,
          connection_id, thread_id, is_write, success, error_msg};
      write_pos_ = (write_pos_ + 1) % capacity_;
    } else {
      entries_.push_back({
          Clock::now(), truncate_str(sql, 200), duration_ms,
          connection_id, thread_id, is_write, success, error_msg});
    }
  }

  std::vector<QueryLogEntry> get_recent(size_t count = 100) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (entries_.empty()) return {};

    std::vector<QueryLogEntry> result;
    if (entries_.size() < capacity_) {
      size_t start = (entries_.size() > count) ? entries_.size() - count : 0;
      result.assign(entries_.begin() + static_cast<long>(start), entries_.end());
    } else {
      result.reserve(std::min(count, entries_.size()));
      for (size_t i = 0; i < count && i < entries_.size(); ++i) {
        size_t idx = (write_pos_ + entries_.size() - count + i) % entries_.size();
        result.push_back(entries_[idx]);
      }
    }
    return result;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
    write_pos_ = 0;
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
  }

private:
  mutable std::mutex mutex_;
  size_t capacity_;
  size_t write_pos_{0};
  std::vector<QueryLogEntry> entries_;
};

// =============================================================================
// SlowQueryLog - Thread-safe log of slow queries
// =============================================================================
class SlowQueryLog {
public:
  struct Entry {
    TimePoint timestamp;
    std::string sql;
    std::string params_summary;
    double duration_ms;
    int connection_id;
  };

  explicit SlowQueryLog(size_t max_entries = 1000,
                         double slow_threshold_ms = 100.0)
      : max_entries_(max_entries), slow_threshold_ms_(slow_threshold_ms) {}

  void record(const std::string& sql, const std::string& params_summary,
              double duration_ms, int connection_id) {
    if (duration_ms < slow_threshold_ms_) return;

    std::lock_guard<std::mutex> lock(mutex_);
    entries_.push_back({Clock::now(), sql, params_summary, duration_ms,
                         connection_id});
    while (entries_.size() > max_entries_) {
      entries_.pop_front();
    }
  }

  std::vector<Entry> get_recent(size_t count = 50) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Entry> result;
    auto start = entries_.size() > count
                     ? std::next(entries_.begin(),
                                  static_cast<long>(entries_.size() - count))
                     : entries_.begin();
    result.assign(start, entries_.end());
    return result;
  }

  void set_threshold(double ms) { slow_threshold_ms_ = ms; }
  double threshold() const { return slow_threshold_ms_; }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.size();
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.clear();
  }

private:
  mutable std::mutex mutex_;
  std::deque<Entry> entries_;
  size_t max_entries_;
  double slow_threshold_ms_;
};

// =============================================================================
// RetryPolicy - Configurable exponential backoff with jitter
// =============================================================================
class RetryPolicy {
public:
  RetryPolicy(int max_attempts = 5,
              Duration initial_backoff = std::chrono::milliseconds(10),
              Duration max_backoff = std::chrono::seconds(5),
              double backoff_multiplier = 2.0,
              bool jitter = true)
      : max_attempts_(max_attempts),
        initial_backoff_(initial_backoff),
        max_backoff_(max_backoff),
        backoff_multiplier_(backoff_multiplier),
        jitter_(jitter),
        rng_(std::random_device{}()) {}

  int max_attempts() const { return max_attempts_; }
  Duration initial_backoff() const { return initial_backoff_; }
  Duration max_backoff() const { return max_backoff_; }
  double backoff_multiplier() const { return backoff_multiplier_; }
  bool jitter() const { return jitter_; }

  // Calculate backoff for a given attempt (1-based)
  Duration backoff_for_attempt(int attempt) const {
    if (attempt <= 0) return Duration::zero();

    double base_sec = std::chrono::duration<double>(initial_backoff_).count() *
                      std::pow(backoff_multiplier_, attempt - 1);

    double max_sec = std::chrono::duration<double>(max_backoff_).count();
    if (base_sec > max_sec) base_sec = max_sec;

    if (jitter_) {
      // Uniform jitter between 50% and 150% of base
      std::uniform_real_distribution<double> dist(0.5, 1.5);
      base_sec *= dist(rng_);
    }

    return std::chrono::duration_cast<Duration>(
        std::chrono::duration<double>(base_sec));
  }

  // Check if an error is retryable based on DBException type
  bool is_retryable(const DBException& error,
                    storage::BaseDatabaseEngine* engine = nullptr) const {
    // Deadlocks are always retryable
    if (engine && engine->is_deadlock(error)) return true;

    // Serialization failures (PostgreSQL) are retryable
    std::string msg = error.what();
    if (msg.find("serialization") != std::string::npos ||
        msg.find("could not serialize") != std::string::npos ||
        msg.find("deadlock") != std::string::npos ||
        msg.find("SQLITE_BUSY") != std::string::npos ||
        msg.find("database is locked") != std::string::npos) {
      return true;
    }

    // Connection errors may be retryable
    if (msg.find("connection") != std::string::npos &&
        (msg.find("lost") != std::string::npos ||
         msg.find("closed") != std::string::npos ||
         msg.find("reset") != std::string::npos)) {
      return true;
    }

    // Timeout errors can be retried
    if (msg.find("timeout") != std::string::npos) return true;

    return false;
  }

  // Execute a function with retry logic
  template <typename Func>
  auto execute(Func&& func, PoolMetrics* metrics = nullptr,
               const std::string& description = "")
      -> decltype(func()) {
    int attempt = 0;
    std::string last_error;

    while (true) {
      attempt++;
      try {
        if constexpr (std::is_void_v<decltype(func())>) {
          func();
          if (metrics && attempt > 1) metrics->record_retry_success();
          return;
        } else {
          auto result = func();
          if (metrics && attempt > 1) metrics->record_retry_success();
          return result;
        }
      } catch (const DBException& e) {
        last_error = e.what();

        if (attempt >= max_attempts_ || !is_retryable(e)) {
          if (metrics) metrics->record_retry_exhausted();
          throw;
        }

        if (metrics) {
          metrics->record_retry_attempt();
          metrics->record_deadlock_retry();
        }

        auto delay = backoff_for_attempt(attempt);
        std::this_thread::sleep_for(delay);
      } catch (const std::exception& e) {
        last_error = e.what();
        // Non-DB exceptions are not retried
        if (metrics) metrics->record_retry_exhausted();
        throw;
      }
    }
  }

private:
  int max_attempts_;
  Duration initial_backoff_;
  Duration max_backoff_;
  double backoff_multiplier_;
  bool jitter_;
  mutable std::mt19937 rng_;
};

// =============================================================================
// ConnectionHandle - Wrapper around a physical connection with metadata
// =============================================================================
class ConnectionHandle {
public:
  ConnectionHandle(int id,
                   std::unique_ptr<storage::DatabaseConnection> conn,
                   const std::string& conn_string,
                   PoolMetrics* metrics = nullptr)
      : id_(id), conn_(std::move(conn)), conn_string_(conn_string),
        created_at_(Clock::now()), last_used_(Clock::now()),
        stmt_cache_(std::make_unique<PreparedStatementCache>(150, metrics)) {}

  // --- Accessors ---
  int id() const { return id_; }
  storage::DatabaseConnection& conn() { return *conn_; }
  const storage::DatabaseConnection& conn() const { return *conn_; }

  TimePoint created_at() const { return created_at_; }
  TimePoint last_used() const { return last_used_; }
  void mark_used() { last_used_ = Clock::now(); }

  int use_count() const { return use_count_; }
  void increment_use() { use_count_++; }

  bool in_use() const { return in_use_; }
  void set_in_use(bool v) { in_use_ = v; }

  bool is_read_only() const { return read_only_; }
  void set_read_only(bool v) { read_only_ = v; }

  bool is_write_connection() const { return write_connection_; }
  void set_write_connection(bool v) { write_connection_ = v; }

  PreparedStatementCache& stmt_cache() { return *stmt_cache_; }

  int backend_pid() const { return backend_pid_; }
  void set_backend_pid(int pid) { backend_pid_ = pid; }

  std::string conn_string() const { return conn_string_; }

  // --- Health / Recycling ---
  bool needs_recycle(Duration max_age, int max_uses) const {
    if (max_uses > 0 && use_count_ >= max_uses) return true;
    if (max_age.count() > 0) {
      auto age = Clock::now() - created_at_;
      if (age > max_age) return true;
    }
    if (conn_ && !conn_->is_connected()) return true;
    return false;
  }

  Duration age() const {
    return std::chrono::duration_cast<Duration>(Clock::now() - created_at_);
  }

  Duration idle_time() const {
    return std::chrono::duration_cast<Duration>(Clock::now() - last_used_);
  }

  void close() {
    if (conn_) {
      conn_->close();
      stmt_cache_->clear();
    }
  }

  // Ping the connection to verify it's alive
  bool ping() {
    try {
      if (!conn_ || !conn_->is_connected()) return false;
      auto txn = conn_->cursor("ping");
      txn->execute("SELECT 1");
      auto row = txn->fetchone();
      return row.has_value();
    } catch (...) {
      return false;
    }
  }

private:
  int id_;
  std::unique_ptr<storage::DatabaseConnection> conn_;
  std::string conn_string_;
  TimePoint created_at_;
  TimePoint last_used_;
  int use_count_{0};
  bool in_use_{false};
  bool read_only_{false};
  bool write_connection_{false};
  int backend_pid_{0};
  std::unique_ptr<PreparedStatementCache> stmt_cache_;
};

// =============================================================================
// SavepointStack - Tracks nested savepoints within a transaction
// =============================================================================
class SavepointStack {
public:
  void push(const std::string& name) {
    stack_.push_back(name);
  }

  std::string pop() {
    if (stack_.empty()) return "";
    auto name = stack_.back();
    stack_.pop_back();
    return name;
  }

  std::string peek() const {
    if (stack_.empty()) return "";
    return stack_.back();
  }

  int depth() const { return static_cast<int>(stack_.size()); }
  bool empty() const { return stack_.empty(); }
  void clear() { stack_.clear(); }

  std::vector<std::string> all() const { return stack_; }

private:
  std::vector<std::string> stack_;
};

// =============================================================================
// TransactionManager - Manages transaction lifecycle including nesting
// =============================================================================
class TransactionManager {
public:
  enum class State {
    IDLE,
    ACTIVE,
    COMMITTING,
    COMMITTED,
    ROLLING_BACK,
    ROLLED_BACK
  };

  TransactionManager(storage::DatabaseConnection& conn,
                     std::shared_ptr<storage::BaseDatabaseEngine> engine,
                     const std::string& name,
                     PoolMetrics* metrics = nullptr)
      : conn_(conn), engine_(std::move(engine)), name_(name),
        metrics_(metrics) {}

  ~TransactionManager() {
    if (state_ == State::ACTIVE) {
      try {
        rollback();
      } catch (...) {
        // Swallow exceptions in destructor
      }
    }
  }

  // --- Begin a transaction ---
  void begin(std::optional<IsolationLevel> isolation = std::nullopt) {
    if (state_ != State::IDLE) {
      throw std::runtime_error(
          "Transaction '" + name_ + "' already started (state=" +
          state_to_string(state_) + ")");
    }

    // Set isolation level before beginning if specified
    if (isolation.has_value() && engine_) {
      engine_->attempt_to_set_isolation_level(conn_, isolation);
    }

    auto txn = conn_.cursor("begin_txn");
    txn->execute("BEGIN");

    state_ = State::ACTIVE;
    begin_time_ = Clock::now();

    if (metrics_) metrics_->record_transaction_begin();
  }

  // --- Commit the transaction ---
  void commit() {
    if (state_ != State::ACTIVE) {
      throw std::runtime_error(
          "Cannot commit transaction '" + name_ + "': state=" +
          state_to_string(state_));
    }

    state_ = State::COMMITTING;

    // Commit any pending savepoints first
    while (!savepoints_.empty()) {
      std::string sp = savepoints_.pop();
      try {
        auto txn = conn_.cursor("release_sp");
        txn->execute("RELEASE SAVEPOINT " + sp);
      } catch (...) {
        // Best effort
      }
    }

    conn_.commit();
    state_ = State::COMMITTED;

    if (metrics_) metrics_->record_transaction_end();
  }

  // --- Rollback the transaction ---
  void rollback() {
    if (state_ != State::ACTIVE && state_ != State::COMMITTING) {
      return;  // Nothing to rollback
    }

    state_ = State::ROLLING_BACK;

    // If we have savepoints, just rollback to the outermost savepoint
    if (!savepoints_.empty()) {
      std::string first_sp = savepoints_.all().front();
      savepoints_.clear();
      try {
        auto txn = conn_.cursor("rollback_sp");
        txn->execute("ROLLBACK TO SAVEPOINT " + first_sp);
      } catch (...) {
        // If that fails, roll back the whole transaction
        conn_.rollback();
      }
    } else {
      conn_.rollback();
    }

    state_ = State::ROLLED_BACK;

    if (metrics_) {
      metrics_->record_transaction_end();
      metrics_->record_transaction_rollback();
    }
  }

  // --- Create a nested savepoint ---
  std::string savepoint(const std::string& sp_name) {
    if (state_ != State::ACTIVE) {
      throw std::runtime_error(
          "Cannot create savepoint: no active transaction");
    }

    std::string full_name = "sp_" + name_ + "_" + sp_name + "_" +
                            std::to_string(savepoints_.depth());
    savepoints_.push(full_name);

    auto txn = conn_.cursor("savepoint");
    txn->execute("SAVEPOINT " + full_name);

    return full_name;
  }

  // --- Release a specific savepoint ---
  void release_savepoint(const std::string& sp_name) {
    if (state_ != State::ACTIVE) {
      throw std::runtime_error("Cannot release savepoint: no active transaction");
    }

    if (savepoints_.peek() != sp_name) {
      throw std::runtime_error(
          "Savepoint mismatch: expected '" + savepoints_.peek() +
          "' but got '" + sp_name + "'");
    }

    savepoints_.pop();
    auto txn = conn_.cursor("release_sp");
    txn->execute("RELEASE SAVEPOINT " + sp_name);
  }

  // --- Rollback to a specific savepoint ---
  void rollback_to_savepoint(const std::string& sp_name) {
    if (state_ != State::ACTIVE) {
      throw std::runtime_error(
          "Cannot rollback to savepoint: no active transaction");
    }

    // Pop savepoints until we find the target
    while (!savepoints_.empty() && savepoints_.peek() != sp_name) {
      savepoints_.pop();
    }

    if (savepoints_.empty() || savepoints_.peek() != sp_name) {
      throw std::runtime_error("Savepoint '" + sp_name + "' not found");
    }

    savepoints_.pop();
    auto txn = conn_.cursor("rollback_sp");
    txn->execute("ROLLBACK TO SAVEPOINT " + sp_name);
  }

  // --- State queries ---
  State state() const { return state_; }
  bool is_active() const { return state_ == State::ACTIVE; }
  bool is_idle() const { return state_ == State::IDLE; }
  const std::string& name() const { return name_; }
  int savepoint_depth() const { return savepoints_.depth(); }
  Duration elapsed() const {
    if (state_ != State::ACTIVE) return Duration::zero();
    return std::chrono::duration_cast<Duration>(Clock::now() - begin_time_);
  }

  static const char* state_to_string(State s) {
    switch (s) {
      case State::IDLE: return "IDLE";
      case State::ACTIVE: return "ACTIVE";
      case State::COMMITTING: return "COMMITTING";
      case State::COMMITTED: return "COMMITTED";
      case State::ROLLING_BACK: return "ROLLING_BACK";
      case State::ROLLED_BACK: return "ROLLED_BACK";
    }
    return "UNKNOWN";
  }

private:
  storage::DatabaseConnection& conn_;
  std::shared_ptr<storage::BaseDatabaseEngine> engine_;
  std::string name_;
  PoolMetrics* metrics_;
  State state_{State::IDLE};
  SavepointStack savepoints_;
  TimePoint begin_time_;
};

// =============================================================================
// TransactionGuard - RAII scope-based transaction management
// =============================================================================
class TransactionGuard {
public:
  // Primary transaction (top-level)
  TransactionGuard(std::shared_ptr<TransactionManager> txn_mgr)
      : txn_mgr_(std::move(txn_mgr)), owns_mgr_(false) {}

  // Standalone mode (owns its own manager)
  TransactionGuard(storage::DatabaseConnection& conn,
                   std::shared_ptr<storage::BaseDatabaseEngine> engine,
                   const std::string& name,
                   std::optional<IsolationLevel> isolation = std::nullopt,
                   PoolMetrics* metrics = nullptr)
      : txn_mgr_(std::make_shared<TransactionManager>(
            conn, std::move(engine), name, metrics)),
        owns_mgr_(true) {
    txn_mgr_->begin(isolation);
  }

  ~TransactionGuard() {
    if (owns_mgr_ && txn_mgr_ && txn_mgr_->is_active()) {
      try {
        txn_mgr_->rollback();
      } catch (...) {}
    }
  }

  TransactionManager& manager() { return *txn_mgr_; }
  const TransactionManager& manager() const { return *txn_mgr_; }

  void commit() { txn_mgr_->commit(); }
  void rollback() { txn_mgr_->rollback(); }

  // Create a nested savepoint
  std::string savepoint(const std::string& name) {
    return txn_mgr_->savepoint(name);
  }
  void release_savepoint(const std::string& name) {
    txn_mgr_->release_savepoint(name);
  }
  void rollback_to_savepoint(const std::string& name) {
    txn_mgr_->rollback_to_savepoint(name);
  }

  bool is_active() const { return txn_mgr_ && txn_mgr_->is_active(); }

private:
  std::shared_ptr<TransactionManager> txn_mgr_;
  bool owns_mgr_;
};

}  // anonymous namespace

// =============================================================================
// DbPoolConfig - Configuration for the database connection pool
// =============================================================================
struct DbPoolConfig {
  // --- Connection pool sizing ---
  int min_connections = 2;
  int max_connections = 20;
  int max_idle_connections = 5;

  // --- Timeouts ---
  Duration connection_timeout = std::chrono::seconds(30);
  Duration idle_timeout = std::chrono::minutes(5);
  Duration max_connection_age = std::chrono::hours(1);
  int max_connection_uses = 10000;

  // --- Health checking ---
  Duration health_check_interval = std::chrono::seconds(30);
  Duration keepalive_interval = std::chrono::minutes(1);
  bool enable_health_check = true;

  // --- Query logging ---
  double slow_query_threshold_ms = 100.0;
  bool enable_query_logging = true;
  bool enable_slow_query_log = true;
  int query_log_capacity = 5000;
  int slow_query_log_capacity = 1000;

  // --- Metrics ---
  bool enable_metrics = true;

  // --- Read/write splitting ---
  bool enable_read_write_split = false;
  std::string read_connection_string;  // For replica connections
  int max_read_connections = 10;
  int min_read_connections = 1;

  // --- Prepared statement cache ---
  bool enable_prepared_statement_cache = true;
  size_t prepared_statement_cache_size = 150;

  // --- Retry policy ---
  int retry_max_attempts = 5;
  Duration retry_initial_backoff = std::chrono::milliseconds(10);
  Duration retry_max_backoff = std::chrono::seconds(5);
  double retry_backoff_multiplier = 2.0;
  bool retry_jitter = true;

  // --- Transaction defaults ---
  IsolationLevel default_isolation_level = IsolationLevel::READ_COMMITTED;
  bool auto_begin_transactions = false;

  // --- SQLite-specific ---
  bool sqlite_wal_mode = true;
  int sqlite_busy_timeout_ms = 5000;
  int sqlite_cache_size_kb = -20000;
  bool sqlite_mmap_enabled = true;
  int sqlite_mmap_size_bytes = 256 * 1024 * 1024;
  std::string sqlite_synchronous = "NORMAL";

  // --- PostgreSQL-specific ---
  std::string pg_application_name = "progressive-server";
  int pg_statement_timeout_ms = 60000;
  int pg_idle_in_transaction_timeout_ms = 120000;
  bool pg_tcp_keepalives = true;

  // --- Validate configuration and return warnings ---
  std::vector<std::string> validate() const {
    std::vector<std::string> warnings;
    if (min_connections < 1)
      warnings.push_back("min_connections must be at least 1");
    if (max_connections < min_connections)
      warnings.push_back("max_connections < min_connections");
    if (max_idle_connections > max_connections)
      warnings.push_back("max_idle_connections > max_connections");
    if (connection_timeout < std::chrono::seconds(1))
      warnings.push_back("connection_timeout is very low (< 1s)");
    if (idle_timeout < std::chrono::seconds(10))
      warnings.push_back("idle_timeout is very low (< 10s)");
    if (max_connection_age > std::chrono::hours(24))
      warnings.push_back("max_connection_age is very high (> 24h)");
    if (enable_read_write_split && read_connection_string.empty())
      warnings.push_back("read/write split enabled but no read connection string");
    if (retry_max_attempts > 100)
      warnings.push_back("retry_max_attempts is very high (> 100)");
    if (slow_query_threshold_ms <= 0 && enable_slow_query_log)
      warnings.push_back("slow_query_threshold is <= 0 but slow query log is enabled");
    return warnings;
  }
};

// =============================================================================
// DbPool - Main database connection pool class
//
// Provides:
//   - Thread-safe connection pool with acquire/release
//   - Dynamic scaling (min/max connections)
//   - Connection health checking (ping)
//   - Connection timeout/recycle
//   - Idle connection cleanup
//   - Read/write splitting
//   - Prepared statement cache
//   - Query logging with slow query detection
//   - Retry logic with exponential backoff
//   - Comprehensive metrics
// =============================================================================
class DbPool {
public:
  // --- Constructor ---
  DbPool(const std::string& database_name,
         const std::string& write_connection_string,
         std::shared_ptr<storage::BaseDatabaseEngine> engine,
         const std::string& server_name,
         DbPoolConfig config = DbPoolConfig{})
      : database_name_(database_name),
        write_connection_string_(write_connection_string),
        engine_(std::move(engine)),
        server_name_(server_name),
        config_(std::move(config)),
        retry_policy_(config_.retry_max_attempts,
                       config_.retry_initial_backoff,
                       config_.retry_max_backoff,
                       config_.retry_backoff_multiplier,
                       config_.retry_jitter),
        slow_query_log_(config_.slow_query_log_capacity,
                         config_.slow_query_threshold_ms),
        query_log_(config_.query_log_capacity) {
    // Validate and fix config
    auto warnings = config_.validate();
    for (const auto& w : warnings) {
      pool_logger.warn("DbPool config warning: " + w);
    }

    if (config_.min_connections < 1) config_.min_connections = 1;
    if (config_.max_connections < config_.min_connections) {
      config_.max_connections = config_.min_connections;
    }

    // Pre-create minimum write connections
    ensure_min_write_connections();

    // Pre-create minimum read connections if split is enabled
    if (config_.enable_read_write_split) {
      ensure_min_read_connections();
    }

    // Start health checker
    if (config_.enable_health_check) {
      start_health_checker();
    }

    pool_logger.debug("DbPool initialized: " + database_name_ +
                      " (min=" + std::to_string(config_.min_connections) +
                      ", max=" + std::to_string(config_.max_connections) + ")");
  }

  // --- Destructor ---
  ~DbPool() {
    shutdown();
  }

  // --- Shutdown ---
  void shutdown() {
    bool expected = false;
    if (!shutting_down_.compare_exchange_strong(expected, true)) {
      return;  // Already shutting down
    }

    running_.store(false, std::memory_order_release);
    write_cv_.notify_all();
    read_cv_.notify_all();

    // Stop health checker
    stop_health_checker();

    // Close all connections under lock
    std::lock_guard<std::mutex> lock(pool_mutex_);

    // Close write idle connections
    for (auto& conn : write_idle_) {
      if (conn) {
        conn->close();
        metrics_.record_connection_destroyed();
      }
    }
    write_idle_.clear();

    // Close read idle connections
    for (auto& conn : read_idle_) {
      if (conn) {
        conn->close();
        metrics_.record_connection_destroyed();
      }
    }
    read_idle_.clear();

    total_write_connections_ = 0;
    total_read_connections_ = 0;

    pool_logger.debug("DbPool shut down: " + database_name_);
  }

  // --- Check if running ---
  bool is_running() const {
    return running_.load(std::memory_order_acquire);
  }

  // ===========================================================================
  // Connection Acquisition / Release
  // ===========================================================================

  // Acquire a write (primary) connection - blocks until available
  std::unique_ptr<ConnectionHandle> acquire_write_connection() {
    return acquire_from_pool(write_idle_, write_cv_, total_write_connections_,
                              config_.max_connections, false);
  }

  // Acquire a read (replica) connection - blocks until available
  std::unique_ptr<ConnectionHandle> acquire_read_connection() {
    if (!config_.enable_read_write_split) {
      return acquire_write_connection();
    }
    return acquire_from_pool(read_idle_, read_cv_, total_read_connections_,
                              config_.max_read_connections, true);
  }

  // Acquire any connection (prefers write for simplicity)
  std::unique_ptr<ConnectionHandle> acquire_connection() {
    return acquire_write_connection();
  }

  // Release a connection back to the pool
  void release_connection(std::unique_ptr<ConnectionHandle> handle) {
    if (!handle) return;

    handle->set_in_use(false);
    handle->mark_used();
    handle->increment_use();
    metrics_.record_connection_released();

    std::lock_guard<std::mutex> lock(pool_mutex_);

    // Check if the connection should be recycled
    if (handle->needs_recycle(config_.max_connection_age,
                               config_.max_connection_uses)) {
      handle->close();
      metrics_.record_connection_destroyed();
      if (handle->is_read_only()) {
        total_read_connections_--;
      } else {
        total_write_connections_--;
      }
      return;
    }

    // Route to the appropriate idle queue
    if (handle->is_read_only()) {
      int max_idle = config_.enable_read_write_split
                         ? config_.max_idle_connections / 2
                         : config_.max_idle_connections;
      if (static_cast<int>(read_idle_.size()) >= max_idle) {
        handle->close();
        metrics_.record_connection_destroyed();
        total_read_connections_--;
      } else {
        read_idle_.push_back(std::move(handle));
        read_cv_.notify_one();
      }
    } else {
      if (static_cast<int>(write_idle_.size()) >= config_.max_idle_connections) {
        handle->close();
        metrics_.record_connection_destroyed();
        total_write_connections_--;
      } else {
        write_idle_.push_back(std::move(handle));
        write_cv_.notify_one();
      }
    }
  }

  // ===========================================================================
  // Transaction Management
  // ===========================================================================

  // Run a function within a transaction on a write connection
  template <typename Func>
  auto run_in_transaction(const std::string& txn_name,
                           Func&& func,
                           std::optional<IsolationLevel> isolation = std::nullopt)
      -> decltype(std::declval<std::decay_t<Func>>()(std::declval<TransactionManager&>())) {
    auto handle = acquire_write_connection();
    if (!handle) {
      throw std::runtime_error("Failed to acquire connection for transaction '" +
                               txn_name + "'");
    }

    TransactionGuard txn(handle->conn(), engine_, txn_name, isolation,
                          config_.enable_metrics ? &metrics_ : nullptr);

    try {
      if constexpr (std::is_void_v<decltype(func(txn.manager()))>) {
        func(txn.manager());
        txn.commit();
        release_connection(std::move(handle));
        return;
      } else {
        auto result = func(txn.manager());
        txn.commit();
        release_connection(std::move(handle));
        return result;
      }
    } catch (...) {
      try {
        txn.rollback();
      } catch (...) {}
      release_connection(std::move(handle));
      throw;
    }
  }

  // Run a function with a connection (no transaction)
  template <typename Func>
  auto run_with_connection(const std::string& description,
                            Func&& func,
                            bool read_only = false)
      -> decltype(std::declval<std::decay_t<Func>>()(
          std::declval<storage::DatabaseConnection&>())) {
    auto handle = read_only ? acquire_read_connection()
                             : acquire_write_connection();
    if (!handle) {
      throw std::runtime_error("Failed to acquire connection for '" +
                               description + "'");
    }

    try {
      auto result = func(handle->conn());
      release_connection(std::move(handle));
      return result;
    } catch (...) {
      release_connection(std::move(handle));
      throw;
    }
  }

  // ===========================================================================
  // Query Execution with Logging and Retry
  // ===========================================================================

  // Execute a query with full logging, timing, and retry support
  storage::RowList execute_query(const std::string& sql,
                                   const std::vector<SQLParam>& params = {},
                                   const std::string& description = "",
                                   bool is_write = false,
                                   bool read_only = false) {
    if (is_write && read_only) {
      read_only = false;  // Can't write on a read-only connection
    }

    std::string desc = description.empty() ? sql_one_line(sql) : description;

    auto handle = read_only ? acquire_read_connection()
                             : acquire_write_connection();
    if (!handle) {
      throw std::runtime_error("Failed to acquire connection for query");
    }

    bool query_is_write = is_write || (!read_only && is_write_query(sql));
    int conn_id = handle->id();
    int thread_id = static_cast<int>(
        std::hash<std::thread::id>{}(std::this_thread::get_id()));

    try {
      storage::RowList result;

      // Try to use prepared statement cache
      std::string stmt_name;
      bool cache_hit = false;
      if (config_.enable_prepared_statement_cache) {
        auto cached = handle->stmt_cache().get(sql);
        if (cached.has_value()) {
          stmt_name = *cached;
          cache_hit = true;
        }
      }

      auto start = Clock::now();
      auto txn = handle->conn().cursor(desc);

      if (!params.empty()) {
        txn->execute(sql, params);
      } else {
        txn->execute(sql);
      }

      result = txn->fetchall();
      auto elapsed = Clock::now() - start;
      double ms = std::chrono::duration<double, std::milli>(elapsed).count();
      bool is_slow = ms >= config_.slow_query_threshold_ms;

      // Record metrics
      if (config_.enable_metrics) {
        metrics_.record_query(elapsed, is_slow);
      }

      // Cache the prepared statement for future use
      if (config_.enable_prepared_statement_cache && !cache_hit) {
        handle->stmt_cache().put(sql, "stmt_" + hash_sql(sql));
        handle->stmt_cache().record_execution_time(sql, ms);
      } else if (cache_hit) {
        handle->stmt_cache().record_execution_time(sql, ms);
      }

      // Query logging
      if (config_.enable_query_logging) {
        query_log_.record(desc, ms, conn_id, thread_id, query_is_write,
                          true);
      }

      // Slow query logging
      if (config_.enable_slow_query_log && is_slow) {
        std::string param_summary;
        for (size_t i = 0; i < std::min(params.size(), size_t(5)); ++i) {
          if (i > 0) param_summary += ", ";
          param_summary += param_repr(params[i]);
        }
        if (params.size() > 5) param_summary += ", ...";
        slow_query_log_.record(desc, param_summary, ms, conn_id);
      }

      release_connection(std::move(handle));
      return result;

    } catch (const DBException& e) {
      // Record failed query
      auto elapsed = Clock::now() - start_time_;
      double ms = std::chrono::duration<double, std::milli>(elapsed).count();

      if (config_.enable_query_logging) {
        query_log_.record(desc, ms, conn_id, thread_id, query_is_write,
                          false, e.what());
      }

      // Check if retryable
      if (retry_policy_.is_retryable(e, engine_.get())) {
        // Release this connection and retry with a new one
        handle->close();
        release_connection(std::move(handle));
        metrics_.record_connection_destroyed();

        // Retry via the retry policy
        return retry_policy_.execute(
            [&]() -> storage::RowList {
              return execute_query(sql, params, desc, is_write, read_only);
            },
            config_.enable_metrics ? &metrics_ : nullptr, desc);
      }

      release_connection(std::move(handle));
      throw;
    } catch (...) {
      release_connection(std::move(handle));
      throw;
    }
  }

  // Execute a write query
  storage::RowList execute_write(const std::string& sql,
                                   const std::vector<SQLParam>& params = {},
                                   const std::string& description = "") {
    return execute_query(sql, params, description, true, false);
  }

  // Execute a read query
  storage::RowList execute_read(const std::string& sql,
                                  const std::vector<SQLParam>& params = {},
                                  const std::string& description = "") {
    return execute_query(sql, params, description, false, true);
  }

  // Execute a simple statement without returning rows
  void execute_simple(const std::string& sql,
                       const std::vector<SQLParam>& params = {},
                       const std::string& description = "") {
    execute_query(sql, params, description, is_write_query(sql),
                  !is_write_query(sql));
  }

  // ===========================================================================
  // Health Checking
  // ===========================================================================
  void start_health_checker() {
    if (health_check_running_.exchange(true, std::memory_order_acq_rel)) {
      return;
    }
    health_check_thread_ = std::thread([this]() { health_check_loop(); });
  }

  void stop_health_checker() {
    health_check_running_.store(false, std::memory_order_release);
    if (health_check_thread_.joinable()) {
      health_check_thread_.join();
    }
  }

  // ===========================================================================
  // Metrics and Diagnostics
  // ===========================================================================
  PoolMetrics::Snapshot metrics_snapshot() const {
    int active = 0, idle_read = 0, idle_write = 0, waiting = 0, pool_size = 0;

    {
      std::lock_guard<std::mutex> lock(pool_mutex_);
      idle_write = static_cast<int>(write_idle_.size());
      idle_read = static_cast<int>(read_idle_.size());
      pool_size = total_write_connections_ + total_read_connections_;
    }

    waiting = waiting_threads_.load(std::memory_order_relaxed);
    active = pool_size - idle_write - idle_read;
    if (active < 0) active = 0;

    return metrics_.snapshot(active, idle_read, idle_write, waiting, pool_size);
  }

  std::vector<SlowQueryLog::Entry> recent_slow_queries(size_t count = 50) const {
    return slow_query_log_.get_recent(count);
  }

  std::vector<QueryLogEntry> recent_queries(size_t count = 100) const {
    return query_log_.get_recent(count);
  }

  std::string diagnostics() const {
    auto snap = metrics_snapshot();
    std::stringstream ss;

    ss << "=== DbPool Diagnostics: " << database_name_ << " ===\n";
    ss << "Server: " << server_name_ << "\n";
    ss << "Running: " << (is_running() ? "yes" : "no") << "\n";
    ss << "Shutting down: " << (shutting_down_.load() ? "yes" : "no") << "\n\n";

    ss << "-- Connection Stats --\n";
    ss << "  Pool size:   " << snap.pool_size << "\n";
    ss << "  Active:      " << snap.active_connections << "\n";
    ss << "  Idle (read): " << snap.idle_read_connections << "\n";
    ss << "  Idle (write):" << snap.idle_write_connections << "\n";
    ss << "  Waiting:     " << snap.waiting_threads << "\n";
    ss << "  Created:     " << snap.total_created << "\n";
    ss << "  Destroyed:   " << snap.total_destroyed << "\n";
    ss << "  Acquired:    " << snap.total_acquired << "\n";
    ss << "  Released:    " << snap.total_released << "\n";
    ss << "  Timeouts:    " << snap.acquire_timeouts << "\n";
    ss << "  Failures:    " << snap.connection_failures << "\n\n";

    ss << "-- Query Stats --\n";
    ss << "  Total queries:  " << snap.total_queries << "\n";
    ss << "  Slow queries:   " << snap.slow_queries << "\n";
    ss << "  Avg query time: " << std::fixed << std::setprecision(2)
       << snap.avg_query_time_ms << " ms\n";
    ss << "  Active txns:    " << snap.active_transactions << "\n";
    ss << "  Total rollbacks:" << snap.total_rollbacks << "\n\n";

    ss << "-- Retry Stats --\n";
    ss << "  Deadlock retries: " << snap.deadlock_retries << "\n";
    ss << "  Retry attempts:   " << snap.retry_attempts << "\n";
    ss << "  Retry successes:  " << snap.retry_successes << "\n";
    ss << "  Retry exhausted:  " << snap.retry_exhausted << "\n";
    ss << "  Success rate:     " << std::fixed << std::setprecision(1)
       << (snap.retry_success_rate * 100.0) << "%\n\n";

    ss << "-- Prepared Statement Cache --\n";
    ss << "  Hits:     " << snap.stmt_cache_hits << "\n";
    ss << "  Misses:   " << snap.stmt_cache_misses << "\n";
    ss << "  Evictions:" << snap.stmt_cache_evictions << "\n";
    ss << "  Hit rate: " << std::fixed << std::setprecision(1)
       << (snap.stmt_cache_hit_ratio * 100.0) << "%\n\n";

    ss << "-- Configuration --\n";
    ss << "  min_connections:  " << config_.min_connections << "\n";
    ss << "  max_connections:  " << config_.max_connections << "\n";
    ss << "  max_idle:         " << config_.max_idle_connections << "\n";
    ss << "  read/write split: "
       << (config_.enable_read_write_split ? "enabled" : "disabled") << "\n";
    ss << "  slow query threshold: " << config_.slow_query_threshold_ms
       << " ms\n";
    ss << "  retry max attempts:  " << config_.retry_max_attempts << "\n";
    ss << "  connection timeout:  "
       << std::chrono::duration_cast<std::chrono::seconds>(
              config_.connection_timeout).count() << "s\n";

    return ss.str();
  }

  // JSON metrics output for monitoring systems
  std::string metrics_json() const {
    auto snap = metrics_snapshot();
    std::stringstream ss;
    ss << "{";
    ss << "\"pool\":{";
    ss << "\"name\":\"" << database_name_ << "\",";
    ss << "\"server\":\"" << server_name_ << "\",";
    ss << "\"running\":" << (is_running() ? "true" : "false") << ",";
    ss << "\"total\":" << snap.pool_size << ",";
    ss << "\"active\":" << snap.active_connections << ",";
    ss << "\"idle_read\":" << snap.idle_read_connections << ",";
    ss << "\"idle_write\":" << snap.idle_write_connections << ",";
    ss << "\"waiting\":" << snap.waiting_threads;
    ss << "},";
    ss << "\"connections\":{";
    ss << "\"created\":" << snap.total_created << ",";
    ss << "\"destroyed\":" << snap.total_destroyed << ",";
    ss << "\"acquired\":" << snap.total_acquired << ",";
    ss << "\"released\":" << snap.total_released << ",";
    ss << "\"timeouts\":" << snap.acquire_timeouts << ",";
    ss << "\"failures\":" << snap.connection_failures;
    ss << "},";
    ss << "\"queries\":{";
    ss << "\"total\":" << snap.total_queries << ",";
    ss << "\"slow\":" << snap.slow_queries << ",";
    ss << "\"avg_time_ms\":" << std::fixed << std::setprecision(2)
       << snap.avg_query_time_ms;
    ss << "},";
    ss << "\"transactions\":{";
    ss << "\"active\":" << snap.active_transactions << ",";
    ss << "\"rollbacks\":" << snap.total_rollbacks;
    ss << "},";
    ss << "\"retries\":{";
    ss << "\"deadlock\":" << snap.deadlock_retries << ",";
    ss << "\"attempts\":" << snap.retry_attempts << ",";
    ss << "\"successes\":" << snap.retry_successes << ",";
    ss << "\"exhausted\":" << snap.retry_exhausted << ",";
    ss << "\"success_rate\":" << std::fixed << std::setprecision(3)
       << snap.retry_success_rate;
    ss << "},";
    ss << "\"stmt_cache\":{";
    ss << "\"hits\":" << snap.stmt_cache_hits << ",";
    ss << "\"misses\":" << snap.stmt_cache_misses << ",";
    ss << "\"evictions\":" << snap.stmt_cache_evictions << ",";
    ss << "\"hit_rate\":" << std::fixed << std::setprecision(3)
       << snap.stmt_cache_hit_ratio;
    ss << "}";
    ss << "}";
    return ss.str();
  }

  // --- Configuration access ---
  const DbPoolConfig& config() const { return config_; }
  storage::BaseDatabaseEngine& engine() { return *engine_; }
  const storage::BaseDatabaseEngine& engine() const { return *engine_; }
  std::shared_ptr<storage::BaseDatabaseEngine> engine_ptr() { return engine_; }
  const PoolMetrics& metrics() const { return metrics_; }
  void update_config(const DbPoolConfig& new_config) {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    config_ = new_config;
    slow_query_log_.set_threshold(config_.slow_query_threshold_ms);
    retry_policy_ = RetryPolicy(config_.retry_max_attempts,
                                 config_.retry_initial_backoff,
                                 config_.retry_max_backoff,
                                 config_.retry_backoff_multiplier,
                                 config_.retry_jitter);
    ensure_min_write_connections();
    if (config_.enable_read_write_split) {
      ensure_min_read_connections();
    }
  }

  // --- Pool statistics ---
  void reset_metrics() { metrics_.reset(); }

private:
  // ===========================================================================
  // Internal: acquire from pool
  // ===========================================================================
  std::unique_ptr<ConnectionHandle> acquire_from_pool(
      std::deque<std::unique_ptr<ConnectionHandle>>& idle_queue,
      std::condition_variable& cv,
      int& total_count,
      int max_allowed,
      bool read_only) {
    if (!is_running()) {
      throw std::runtime_error("DbPool is not running");
    }

    waiting_threads_.fetch_add(1, std::memory_order_relaxed);

    std::unique_ptr<ConnectionHandle> handle;

    {
      std::unique_lock<std::mutex> lock(pool_mutex_);

      while (idle_queue.empty() && is_running()) {
        // If we can create a new connection, do so
        if (total_count < max_allowed) {
          lock.unlock();
          handle = create_connection(read_only);
          lock.lock();
          if (handle) {
            break;
          }
          // Creation failed, try again
          continue;
        }

        // Wait for a connection to become available
        auto status = cv.wait_for(lock, config_.connection_timeout);
        if (status == std::cv_status::timeout) {
          waiting_threads_.fetch_sub(1, std::memory_order_relaxed);
          metrics_.record_acquire_timeout();
          throw std::runtime_error(
              "Timed out waiting for " +
              std::string(read_only ? "read" : "write") +
              " connection after " +
              std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                                 config_.connection_timeout).count()) +
              "s");
        }
      }

      if (!is_running()) {
        waiting_threads_.fetch_sub(1, std::memory_order_relaxed);
        throw std::runtime_error("DbPool is shutting down");
      }

      // If we didn't create a new one, take from idle queue
      if (!handle && !idle_queue.empty()) {
        handle = std::move(idle_queue.front());
        idle_queue.pop_front();
      }
    }

    // If we still don't have a handle, create one outside the lock
    if (!handle) {
      handle = create_connection(read_only);
      if (!handle) {
        waiting_threads_.fetch_sub(1, std::memory_order_relaxed);
        metrics_.record_connection_failed();
        throw std::runtime_error("Failed to create database connection");
      }
    }

    // Mark as in-use
    handle->set_in_use(true);

    // Health check on borrowed connection
    if (config_.enable_health_check) {
      if (!handle->ping()) {
        // Connection is dead, recycle and get a new one
        handle->close();
        metrics_.record_connection_destroyed();
        {
          std::lock_guard<std::mutex> lock(pool_mutex_);
          if (read_only) total_read_connections_--;
          else total_write_connections_--;
        }
        handle = create_connection(read_only);
        if (!handle) {
          waiting_threads_.fetch_sub(1, std::memory_order_relaxed);
          metrics_.record_connection_failed();
          throw std::runtime_error(
              "Failed to replace dead database connection");
        }
        handle->set_in_use(true);
      }
    }

    waiting_threads_.fetch_sub(1, std::memory_order_relaxed);
    metrics_.record_connection_acquired();
    return handle;
  }

  // ===========================================================================
  // Internal: create a new connection
  // ===========================================================================
  std::unique_ptr<ConnectionHandle> create_connection(bool read_only) {
    int conn_id = next_connection_id_.fetch_add(1, std::memory_order_relaxed);

    const std::string& conn_str = read_only
                                      ? (config_.read_connection_string.empty()
                                             ? write_connection_string_
                                             : config_.read_connection_string)
                                      : write_connection_string_;

    std::unique_ptr<storage::DatabaseConnection> raw_conn;
    try {
      raw_conn = storage::DatabasePool::create_connection(conn_str);
      if (!raw_conn) {
        metrics_.record_connection_failed();
        return nullptr;
      }
    } catch (const std::exception& e) {
      pool_logger.error("Failed to create connection " +
                        std::to_string(conn_id) + ": " + e.what());
      metrics_.record_connection_failed();
      return nullptr;
    }

    auto handle = std::make_unique<ConnectionHandle>(
        conn_id, std::move(raw_conn), conn_str,
        config_.enable_metrics ? &metrics_ : nullptr);
    handle->set_read_only(read_only);
    handle->set_write_connection(!read_only);

    // Apply engine-specific setup
    setup_connection(*handle);

    {
      std::lock_guard<std::mutex> lock(pool_mutex_);
      if (read_only) {
        total_read_connections_++;
      } else {
        total_write_connections_++;
      }
    }

    metrics_.record_connection_created();
    return handle;
  }

  // ===========================================================================
  // Internal: setup connection based on engine type
  // ===========================================================================
  void setup_connection(ConnectionHandle& handle) {
    bool is_sqlite = false;
    const std::string& cs = handle.conn_string();
    is_sqlite = cs.find("sqlite") != std::string::npos ||
                cs.find("SQLite") != std::string::npos ||
                cs.find(".db") != std::string::npos;

    if (is_sqlite) {
      setup_sqlite_connection(handle);
    } else {
      setup_postgres_connection(handle);
    }
  }

  void setup_sqlite_connection(ConnectionHandle& handle) {
    auto txn = handle.conn().cursor("sqlite_setup");

    if (config_.sqlite_wal_mode) {
      txn->execute("PRAGMA journal_mode=WAL");
    }
    if (config_.sqlite_busy_timeout_ms > 0) {
      txn->execute("PRAGMA busy_timeout=" +
                    std::to_string(config_.sqlite_busy_timeout_ms));
    }
    txn->execute("PRAGMA cache_size=" +
                  std::to_string(config_.sqlite_cache_size_kb));

    if (config_.sqlite_synchronous == "FULL") {
      txn->execute("PRAGMA synchronous=FULL");
    } else if (config_.sqlite_synchronous == "NORMAL") {
      txn->execute("PRAGMA synchronous=NORMAL");
    } else if (config_.sqlite_synchronous == "OFF") {
      txn->execute("PRAGMA synchronous=OFF");
    }

    txn->execute("PRAGMA foreign_keys=ON");

    if (config_.sqlite_mmap_enabled) {
      txn->execute("PRAGMA mmap_size=" +
                    std::to_string(config_.sqlite_mmap_size_bytes));
    }

    txn->execute("PRAGMA temp_store=MEMORY");
  }

  void setup_postgres_connection(ConnectionHandle& handle) {
    auto txn = handle.conn().cursor("postgres_setup");

    txn->execute("SET application_name = '" + config_.pg_application_name +
                  "'");
    txn->execute("SET TIME ZONE 'UTC'");

    if (config_.pg_statement_timeout_ms > 0) {
      txn->execute("SET statement_timeout = " +
                    std::to_string(config_.pg_statement_timeout_ms));
    }
    if (config_.pg_idle_in_transaction_timeout_ms > 0) {
      txn->execute("SET idle_in_transaction_timeout = " +
                    std::to_string(config_.pg_idle_in_transaction_timeout_ms));
    }
    if (config_.pg_tcp_keepalives) {
      txn->execute("SET tcp_keepalives_idle = 60");
      txn->execute("SET tcp_keepalives_interval = 10");
      txn->execute("SET tcp_keepalives_count = 5");
    }

    // Get backend PID
    try {
      txn->execute("SELECT pg_backend_pid()");
      auto row = txn->fetchone();
      if (row.has_value() && !row->empty()) {
        try {
          int pid = std::stoi(row->at(0).value.value_or("0"));
          handle.set_backend_pid(pid);
        } catch (...) {}
      }
    } catch (...) {}

    txn->execute("SET bytea_output = 'escape'");
  }

  // ===========================================================================
  // Internal: ensure minimum connections
  // ===========================================================================
  void ensure_min_write_connections() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    while (total_write_connections_ < config_.min_connections) {
      pool_mutex_.unlock();
      auto conn = create_connection(false);
      pool_mutex_.lock();
      if (conn) {
        write_idle_.push_back(std::move(conn));
      } else {
        break;
      }
    }
  }

  void ensure_min_read_connections() {
    if (!config_.enable_read_write_split) return;
    std::lock_guard<std::mutex> lock(pool_mutex_);
    while (total_read_connections_ < config_.min_read_connections) {
      pool_mutex_.unlock();
      auto conn = create_connection(true);
      pool_mutex_.lock();
      if (conn) {
        read_idle_.push_back(std::move(conn));
      } else {
        break;
      }
    }
  }

  // ===========================================================================
  // Internal: health check loop
  // ===========================================================================
  void health_check_loop() {
    pool_logger.debug("Health checker started for " + database_name_);

    while (health_check_running_.load(std::memory_order_acquire) &&
           running_.load(std::memory_order_acquire)) {
      // Sleep for the check interval
      auto interval = config_.health_check_interval;
      auto start = Clock::now();

      while (Clock::now() - start < interval) {
        if (!health_check_running_.load(std::memory_order_acquire) ||
            !running_.load(std::memory_order_acquire)) {
          pool_logger.debug("Health checker stopping for " + database_name_);
          return;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }

      // Collect idle connections to check
      std::vector<ConnectionHandle*> to_check;
      {
        std::lock_guard<std::mutex> lock(pool_mutex_);
        for (auto& c : write_idle_) to_check.push_back(c.get());
        for (auto& c : read_idle_) to_check.push_back(c.get());
      }

      // Ping each idle connection
      for (auto* handle : to_check) {
        if (!handle->ping()) {
          // Dead connection - remove from idle queue
          std::lock_guard<std::mutex> lock(pool_mutex_);

          auto remove_fn =
              [handle](std::deque<std::unique_ptr<ConnectionHandle>>& q) -> bool {
            auto it = std::find_if(q.begin(), q.end(),
                                    [handle](const auto& h) {
                                      return h.get() == handle;
                                    });
            if (it != q.end()) {
              (*it)->close();
              q.erase(it);
              return true;
            }
            return false;
          };

          if (remove_fn(write_idle_)) {
            metrics_.record_connection_destroyed();
            total_write_connections_--;
          } else if (remove_fn(read_idle_)) {
            metrics_.record_connection_destroyed();
            total_read_connections_--;
          }
        }
      }

      // Prune idle connections
      prune_idle_connections();

      // Replenish to minimum
      ensure_min_write_connections();
      if (config_.enable_read_write_split) {
        ensure_min_read_connections();
      }
    }

    pool_logger.debug("Health checker stopped for " + database_name_);
  }

  // ===========================================================================
  // Internal: prune idle connections exceeding idle timeout
  // ===========================================================================
  void prune_idle_connections() {
    std::lock_guard<std::mutex> lock(pool_mutex_);
    auto now = Clock::now();

    // Prune write idle
    auto it = write_idle_.begin();
    while (it != write_idle_.end()) {
      if (total_write_connections_ <= config_.min_connections) break;
      if (now - (*it)->last_used() > config_.idle_timeout) {
        (*it)->close();
        metrics_.record_connection_destroyed();
        total_write_connections_--;
        it = write_idle_.erase(it);
      } else {
        ++it;
      }
    }

    // Prune read idle
    auto rit = read_idle_.begin();
    while (rit != read_idle_.end()) {
      if (total_read_connections_ <= config_.min_read_connections) break;
      if (now - (*rit)->last_used() > config_.idle_timeout) {
        (*rit)->close();
        metrics_.record_connection_destroyed();
        total_read_connections_--;
        rit = read_idle_.erase(rit);
      } else {
        ++rit;
      }
    }
  }

  // ===========================================================================
  // Member variables
  // ===========================================================================
  std::string database_name_;
  std::string write_connection_string_;
  std::shared_ptr<storage::BaseDatabaseEngine> engine_;
  std::string server_name_;
  DbPoolConfig config_;

  // Pool state
  mutable std::mutex pool_mutex_;
  std::condition_variable write_cv_;
  std::condition_variable read_cv_;

  // Write (primary) connection pools
  std::deque<std::unique_ptr<ConnectionHandle>> write_idle_;
  int total_write_connections_{0};

  // Read (replica) connection pools
  std::deque<std::unique_ptr<ConnectionHandle>> read_idle_;
  int total_read_connections_{0};

  // Connection ID counter
  std::atomic<int> next_connection_id_{1};

  // State flags
  std::atomic<bool> running_{true};
  std::atomic<bool> shutting_down_{false};
  std::atomic<int> waiting_threads_{0};

  // Health check
  std::thread health_check_thread_;
  std::atomic<bool> health_check_running_{false};

  // Metrics, logging, retry
  PoolMetrics metrics_;
  SlowQueryLog slow_query_log_;
  QueryLog query_log_;
  RetryPolicy retry_policy_;

  // Track start time for elapsed calculation in execute_query exception path
  TimePoint start_time_;
};

// =============================================================================
// DbPoolFactory - Builder/factory for creating DbPool instances
// =============================================================================
class DbPoolFactory {
public:
  static std::unique_ptr<DbPool> create_from_config(
      const std::string& database_name,
      const std::string& connection_string,
      std::shared_ptr<storage::BaseDatabaseEngine> engine,
      const std::string& server_name) {
    DbPoolConfig config;
    return std::make_unique<DbPool>(database_name, connection_string,
                                     std::move(engine), server_name, config);
  }

  static std::unique_ptr<DbPool> create_with_rw_split(
      const std::string& database_name,
      const std::string& write_conn_string,
      const std::string& read_conn_string,
      std::shared_ptr<storage::BaseDatabaseEngine> engine,
      const std::string& server_name) {
    DbPoolConfig config;
    config.enable_read_write_split = true;
    config.read_connection_string = read_conn_string;
    return std::make_unique<DbPool>(database_name, write_conn_string,
                                     std::move(engine), server_name, config);
  }

  static std::unique_ptr<DbPool> create_minimal(
      const std::string& database_name,
      const std::string& connection_string,
      std::shared_ptr<storage::BaseDatabaseEngine> engine,
      const std::string& server_name) {
    DbPoolConfig config;
    config.min_connections = 1;
    config.max_connections = 2;
    config.enable_health_check = false;
    config.enable_query_logging = false;
    config.enable_slow_query_log = false;
    config.enable_metrics = false;
    config.enable_prepared_statement_cache = false;
    return std::make_unique<DbPool>(database_name, connection_string,
                                     std::move(engine), server_name, config);
  }
};

// =============================================================================
// TransactionScope - RAII scope guard for run_in_transaction style usage
// =============================================================================
class TransactionScope {
public:
  TransactionScope(DbPool& pool,
                   const std::string& name,
                   std::optional<IsolationLevel> isolation = std::nullopt)
      : pool_(pool),
        handle_(pool.acquire_write_connection()),
        txn_mgr_(std::make_shared<TransactionManager>(
            handle_->conn(), pool_.engine_ptr(), name,
            pool_.config().enable_metrics
                ? const_cast<PoolMetrics*>(&pool_.metrics())
                : nullptr)) {
    txn_mgr_->begin(isolation);
  }

  ~TransactionScope() {
    if (txn_mgr_ && txn_mgr_->is_active()) {
      try {
        txn_mgr_->rollback();
      } catch (...) {}
    }
    if (handle_) {
      pool_.release_connection(std::move(handle_));
    }
  }

  TransactionManager& txn() { return *txn_mgr_; }
  storage::DatabaseConnection& conn() { return handle_->conn(); }

  void commit() {
    txn_mgr_->commit();
    // Release connection immediately on commit
    if (handle_) {
      pool_.release_connection(std::move(handle_));
    }
  }

  void rollback() {
    txn_mgr_->rollback();
    if (handle_) {
      pool_.release_connection(std::move(handle_));
    }
  }

  std::string savepoint(const std::string& name) {
    return txn_mgr_->savepoint(name);
  }
  void release_savepoint(const std::string& name) {
    txn_mgr_->release_savepoint(name);
  }
  void rollback_to_savepoint(const std::string& name) {
    txn_mgr_->rollback_to_savepoint(name);
  }

private:
  DbPool& pool_;
  std::unique_ptr<ConnectionHandle> handle_;
  std::shared_ptr<TransactionManager> txn_mgr_;
};

// =============================================================================
// PoolMonitor - Periodic monitoring and reporting for DbPool
// =============================================================================
class PoolMonitor {
public:
  PoolMonitor(DbPool& pool, Duration report_interval = std::chrono::minutes(5))
      : pool_(pool), report_interval_(report_interval) {}

  void start() {
    if (running_.exchange(true)) return;
    monitor_thread_ = std::thread([this]() { monitor_loop(); });
  }

  void stop() {
    running_.store(false);
    if (monitor_thread_.joinable()) {
      monitor_thread_.join();
    }
  }

private:
  void monitor_loop() {
    while (running_.load()) {
      auto start = Clock::now();
      while (Clock::now() - start < report_interval_ && running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
      if (!running_.load()) break;

      auto snap = pool_.metrics_snapshot();

      // Log warnings for concerning states
      if (snap.waiting_threads > 0) {
        pool_logger.warn("Pool has " + std::to_string(snap.waiting_threads) +
                         " threads waiting for connections");
      }
      if (snap.active_connections >= snap.pool_size && snap.pool_size > 0) {
        pool_logger.warn("Pool exhausted: " +
                         std::to_string(snap.active_connections) +
                         " active out of " + std::to_string(snap.pool_size));
      }
      if (snap.acquire_timeouts > 0) {
        pool_logger.warn("Connection acquire timeouts: " +
                         std::to_string(snap.acquire_timeouts));
      }
      if (snap.connection_failures > 0) {
        pool_logger.warn("Connection failures: " +
                         std::to_string(snap.connection_failures));
      }

      auto slow_rate = snap.total_queries > 0
                           ? 100.0 * snap.slow_queries / snap.total_queries
                           : 0.0;
      if (slow_rate > 10.0) {
        pool_logger.warn("High slow query rate: " +
                         std::to_string(static_cast<int>(slow_rate)) + "%");
      }

      // Periodic info dump
      pool_logger.debug("Pool status: " +
                        std::to_string(snap.active_connections) + " active, " +
                        std::to_string(snap.idle_read_connections +
                                       snap.idle_write_connections) +
                        " idle, " +
                        std::to_string(snap.total_queries) + " queries, " +
                        std::to_string(snap.slow_queries) + " slow");
    }
  }

  DbPool& pool_;
  Duration report_interval_;
  std::atomic<bool> running_{false};
  std::thread monitor_thread_;
};

// =============================================================================
// PoolStatsReporter - Periodic stats reporting to log/metrics system
// =============================================================================
class PoolStatsReporter {
public:
  struct Report {
    TimePoint timestamp;
    PoolMetrics::Snapshot snapshot;
    double uptime_seconds;
    double queries_per_second;
    double avg_connection_lifetime_ms;
  };

  PoolStatsReporter(DbPool& pool,
                     Duration interval = std::chrono::minutes(1))
      : pool_(pool), interval_(interval), start_time_(Clock::now()) {}

  void start() {
    if (running_.exchange(true)) return;
    reporter_thread_ = std::thread([this]() { report_loop(); });
  }

  void stop() {
    running_.store(false);
    if (reporter_thread_.joinable()) {
      reporter_thread_.join();
    }
  }

  std::vector<Report> history() const {
    std::lock_guard<std::mutex> lock(history_mutex_);
    return history_;
  }

  Report latest() const {
    std::lock_guard<std::mutex> lock(history_mutex_);
    if (history_.empty()) return {};
    return history_.back();
  }

private:
  void report_loop() {
    while (running_.load()) {
      auto start = Clock::now();
      while (Clock::now() - start < interval_ && running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
      if (!running_.load()) break;

      auto snap = pool_.metrics_snapshot();
      double uptime = std::chrono::duration<double>(
                          Clock::now() - start_time_).count();

      Report r{};
      r.timestamp = Clock::now();
      r.snapshot = snap;
      r.uptime_seconds = uptime;
      r.queries_per_second =
          uptime > 0 ? snap.total_queries / uptime : 0.0;
      r.avg_connection_lifetime_ms = 0.0;  // Requires tracking connection lifetimes

      {
        std::lock_guard<std::mutex> lock(history_mutex_);
        history_.push_back(r);
        // Keep last 1440 entries (24h at 1min intervals)
        while (history_.size() > 1440) {
          history_.erase(history_.begin());
        }
      }
    }
  }

  DbPool& pool_;
  Duration interval_;
  TimePoint start_time_;
  std::atomic<bool> running_{false};
  std::thread reporter_thread_;
  mutable std::mutex history_mutex_;
  std::vector<Report> history_;
};

// =============================================================================
// QueryProfiler - Per-query profiling and analysis
// =============================================================================
class QueryProfiler {
public:
  struct QueryProfile {
    std::string sql_hash;
    std::string sql_sample;
    int64_t execution_count;
    double total_time_ms;
    double min_time_ms;
    double max_time_ms;
    double avg_time_ms;
    int64_t slow_count;
    int64_t error_count;
    TimePoint first_seen;
    TimePoint last_seen;
  };

  explicit QueryProfiler(size_t max_profiles = 1000)
      : max_profiles_(max_profiles) {}

  void record(const std::string& sql, double duration_ms,
              bool is_slow, bool is_error) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = hash_sql(sql);

    auto it = profiles_.find(key);
    if (it == profiles_.end()) {
      if (profiles_.size() >= max_profiles_) {
        // Evict least recently updated
        auto oldest = profiles_.begin();
        for (auto pit = profiles_.begin(); pit != profiles_.end(); ++pit) {
          if (pit->second.last_seen < oldest->second.last_seen) {
            oldest = pit;
          }
        }
        profiles_.erase(oldest);
      }

      QueryProfile p{};
      p.sql_hash = key;
      p.sql_sample = truncate_str(sql, 120);
      p.execution_count = 1;
      p.total_time_ms = duration_ms;
      p.min_time_ms = duration_ms;
      p.max_time_ms = duration_ms;
      p.avg_time_ms = duration_ms;
      p.slow_count = is_slow ? 1 : 0;
      p.error_count = is_error ? 1 : 0;
      p.first_seen = Clock::now();
      p.last_seen = p.first_seen;
      profiles_[key] = p;
    } else {
      auto& p = it->second;
      p.execution_count++;
      p.total_time_ms += duration_ms;
      p.min_time_ms = std::min(p.min_time_ms, duration_ms);
      p.max_time_ms = std::max(p.max_time_ms, duration_ms);
      p.avg_time_ms = p.total_time_ms / p.execution_count;
      if (is_slow) p.slow_count++;
      if (is_error) p.error_count++;
      p.last_seen = Clock::now();
    }
  }

  std::vector<QueryProfile> top_slow(int n = 10) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<QueryProfile> result;
    result.reserve(profiles_.size());
    for (const auto& [_, p] : profiles_) result.push_back(p);

    std::sort(result.begin(), result.end(),
              [](const QueryProfile& a, const QueryProfile& b) {
                return a.avg_time_ms > b.avg_time_ms;
              });

    if (static_cast<int>(result.size()) > n) result.resize(n);
    return result;
  }

  std::vector<QueryProfile> top_frequent(int n = 10) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<QueryProfile> result;
    result.reserve(profiles_.size());
    for (const auto& [_, p] : profiles_) result.push_back(p);

    std::sort(result.begin(), result.end(),
              [](const QueryProfile& a, const QueryProfile& b) {
                return a.execution_count > b.execution_count;
              });

    if (static_cast<int>(result.size()) > n) result.resize(n);
    return result;
  }

  std::vector<QueryProfile> top_error_prone(int n = 10) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<QueryProfile> result;
    result.reserve(profiles_.size());
    for (const auto& [_, p] : profiles_) result.push_back(p);

    std::sort(result.begin(), result.end(),
              [](const QueryProfile& a, const QueryProfile& b) {
                return a.error_count > b.error_count;
              });

    if (static_cast<int>(result.size()) > n) result.resize(n);
    return result;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    profiles_.clear();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return profiles_.size();
  }

private:
  size_t max_profiles_;
  mutable std::mutex mutex_;
  std::unordered_map<std::string, QueryProfile> profiles_;
};

// =============================================================================
// ConnectionEventLogger - Logs connection lifecycle events for debugging
// =============================================================================
class ConnectionEventLogger {
public:
  enum class EventType {
    CREATED,
    DESTROYED,
    ACQUIRED,
    RELEASED,
    RECYCLED,
    TIMEOUT,
    FAILED,
    HEALTH_CHECK_PASS,
    HEALTH_CHECK_FAIL,
  };

  struct Event {
    TimePoint timestamp;
    EventType type;
    int connection_id;
    std::string detail;
  };

  explicit ConnectionEventLogger(size_t max_events = 5000)
      : max_events_(max_events) {}

  void log(EventType type, int connection_id,
           const std::string& detail = "") {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back({Clock::now(), type, connection_id, detail});
    while (events_.size() > max_events_) {
      events_.pop_front();
    }
  }

  std::vector<Event> get_recent(size_t count = 100) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Event> result;
    auto start = events_.size() > count
                     ? std::next(events_.begin(),
                                  static_cast<long>(events_.size() - count))
                     : events_.begin();
    result.assign(start, events_.end());
    return result;
  }

  std::vector<Event> get_events_for_connection(int connection_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Event> result;
    for (const auto& ev : events_) {
      if (ev.connection_id == connection_id) {
        result.push_back(ev);
      }
    }
    return result;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.clear();
  }

  static const char* event_type_name(EventType t) {
    switch (t) {
      case EventType::CREATED: return "CREATED";
      case EventType::DESTROYED: return "DESTROYED";
      case EventType::ACQUIRED: return "ACQUIRED";
      case EventType::RELEASED: return "RELEASED";
      case EventType::RECYCLED: return "RECYCLED";
      case EventType::TIMEOUT: return "TIMEOUT";
      case EventType::FAILED: return "FAILED";
      case EventType::HEALTH_CHECK_PASS: return "HEALTH_CHECK_PASS";
      case EventType::HEALTH_CHECK_FAIL: return "HEALTH_CHECK_FAIL";
    }
    return "UNKNOWN";
  }

private:
  size_t max_events_;
  mutable std::mutex mutex_;
  std::deque<Event> events_;
};

// =============================================================================
// PoolWarmupStrategy - Strategies for warming up the connection pool
// =============================================================================
class PoolWarmupStrategy {
public:
  enum class Mode {
    NONE,           // No warmup
    EAGER,          // Create all min connections immediately
    LAZY,           // Create connections on first demand only
    INCREMENTAL,    // Create one per second until min reached
    ADAPTIVE,       // Create based on recent demand patterns
  };

  struct WarmupConfig {
    Mode mode = Mode::EAGER;
    Duration increment_interval = std::chrono::seconds(1);
    int batch_size = 1;
    Duration adaptive_window = std::chrono::minutes(1);
  };

  static void warmup(DbPool& pool, const WarmupConfig& cfg) {
    switch (cfg.mode) {
      case Mode::NONE:
        break;

      case Mode::EAGER:
        eager_warmup(pool, cfg);
        break;

      case Mode::LAZY:
        // Nothing to do; connections created on demand
        break;

      case Mode::INCREMENTAL:
        incremental_warmup(pool, cfg);
        break;

      case Mode::ADAPTIVE:
        adaptive_warmup(pool, cfg);
        break;
    }
  }

private:
  static void eager_warmup(DbPool& pool, const WarmupConfig& cfg) {
    // Create up to min_connections
    auto snap = pool.metrics_snapshot();
    int needed = pool.config().min_connections - snap.pool_size;
    if (needed <= 0) return;

    for (int i = 0; i < needed; ++i) {
      try {
        auto conn = pool.acquire_connection();
        if (conn) {
          pool.release_connection(std::move(conn));
        }
      } catch (...) {
        break;
      }
    }
  }

  static void incremental_warmup(DbPool& pool, const WarmupConfig& cfg) {
    auto snap = pool.metrics_snapshot();
    int needed = pool.config().min_connections - snap.pool_size;
    if (needed <= 0) return;

    for (int i = 0; i < needed; i += cfg.batch_size) {
      for (int j = 0; j < cfg.batch_size && (i + j) < needed; ++j) {
        try {
          auto conn = pool.acquire_connection();
          if (conn) {
            pool.release_connection(std::move(conn));
          }
        } catch (...) {
          break;
        }
      }
      if (i + cfg.batch_size < needed) {
        std::this_thread::sleep_for(cfg.increment_interval);
      }
    }
  }

  static void adaptive_warmup(DbPool& pool, const WarmupConfig& cfg) {
    // Start with eager warmup, then let adaptive logic take over
    eager_warmup(pool, cfg);
  }
};

// =============================================================================
// ConnectionValidator - Validates connections on borrow/return
// =============================================================================
class ConnectionValidator {
public:
  struct ValidationConfig {
    bool test_on_borrow = true;
    bool test_on_return = false;
    bool test_while_idle = true;
    Duration validation_timeout = std::chrono::seconds(5);
    std::string validation_query = "SELECT 1";
  };

  explicit ConnectionValidator(const ValidationConfig& cfg)
      : config_(cfg) {}

  bool validate(storage::DatabaseConnection& conn) const {
    if (config_.validation_query.empty()) return true;

    try {
      if (!conn.is_connected()) return false;
      auto txn = conn.cursor("validate");
      txn->execute(config_.validation_query);
      auto row = txn->fetchone();
      return row.has_value();
    } catch (...) {
      return false;
    }
  }

  bool should_test_on_borrow() const { return config_.test_on_borrow; }
  bool should_test_on_return() const { return config_.test_on_return; }
  bool should_test_while_idle() const { return config_.test_while_idle; }
  const std::string& validation_query() const { return config_.validation_query; }
  Duration validation_timeout() const { return config_.validation_timeout; }

private:
  ValidationConfig config_;
};

// =============================================================================
// NamedPreparedStatement - Typed wrapper for named prepared statements
// =============================================================================
class NamedPreparedStatement {
public:
  NamedPreparedStatement(const std::string& name, const std::string& sql)
      : name_(name), sql_(sql), key_(hash_sql(sql)) {}

  const std::string& name() const { return name_; }
  const std::string& sql() const { return sql_; }
  const std::string& key() const { return key_; }

  // Template for binding parameters fluently
  template <typename... Params>
  std::vector<SQLParam> bind(Params&&... params) const {
    std::vector<SQLParam> result;
    (bind_one(result, std::forward<Params>(params)), ...);
    return result;
  }

private:
  static void bind_one(std::vector<SQLParam>& vec, const std::string& v) {
    vec.push_back(SQLParam{v});
  }
  static void bind_one(std::vector<SQLParam>& vec, int64_t v) {
    vec.push_back(SQLParam{v});
  }
  static void bind_one(std::vector<SQLParam>& vec, double v) {
    vec.push_back(SQLParam{v});
  }
  static void bind_one(std::vector<SQLParam>& vec, std::nullptr_t) {
    vec.push_back(SQLParam{nullptr});
  }
  static void bind_one(std::vector<SQLParam>& vec, const char* v) {
    vec.push_back(SQLParam{std::string(v)});
  }

  std::string name_;
  std::string sql_;
  std::string key_;
};

// =============================================================================
// BatchExecutor - Efficient batch execution for bulk operations
// =============================================================================
class BatchExecutor {
public:
  explicit BatchExecutor(DbPool& pool) : pool_(pool) {}

  // Execute a single SQL statement with multiple parameter sets
  void execute_batch(const std::string& sql,
                      const std::vector<std::vector<SQLParam>>& batch_params,
                      const std::string& description = "batch_insert",
                      size_t batch_chunk = 100) {
    if (batch_params.empty()) return;

    for (size_t offset = 0; offset < batch_params.size(); offset += batch_chunk) {
      size_t end = std::min(offset + batch_chunk, batch_params.size());

      auto handle = pool_.acquire_write_connection();
      if (!handle) {
        throw std::runtime_error("Failed to acquire connection for batch execution");
      }

      try {
        auto txn = handle->conn().cursor(description);

        for (size_t i = offset; i < end; ++i) {
          txn->execute(sql, batch_params[i]);
        }

        pool_.release_connection(std::move(handle));
      } catch (...) {
        pool_.release_connection(std::move(handle));
        throw;
      }
    }
  }

  // Execute batch within a single transaction
  void execute_batch_transactional(
      const std::string& sql,
      const std::vector<std::vector<SQLParam>>& batch_params,
      const std::string& description = "batch_txn",
      size_t batch_chunk = 100) {
    if (batch_params.empty()) return;

    pool_.run_in_transaction(description,
        [&](TransactionManager& txn_mgr) {
          auto handle = pool_.acquire_write_connection();
          if (!handle) throw std::runtime_error("Failed to acquire connection");

          try {
            for (size_t i = 0; i < batch_params.size(); ++i) {
              auto cursor = handle->conn().cursor(description);
              cursor->execute(sql, batch_params[i]);
            }
            pool_.release_connection(std::move(handle));
          } catch (...) {
            pool_.release_connection(std::move(handle));
            throw;
          }
        });
  }

private:
  DbPool& pool_;
};

// =============================================================================
// ConnectionLeakDetector - Debug tool to find leaked connections
// =============================================================================
class ConnectionLeakDetector {
public:
  struct LeakInfo {
    int connection_id;
    TimePoint acquired_at;
    std::string location;
  };

  void record_acquire(int conn_id, const std::string& location = "") {
    std::lock_guard<std::mutex> lock(mutex_);
    active_[conn_id] = {conn_id, Clock::now(), location};
  }

  void record_release(int conn_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    active_.erase(conn_id);
  }

  std::vector<LeakInfo> detect_leaks(
      Duration threshold = std::chrono::minutes(1)) const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<LeakInfo> leaks;
    auto now = Clock::now();
    for (const auto& [id, info] : active_) {
      if (now - info.acquired_at > threshold) {
        leaks.push_back(info);
      }
    }
    return leaks;
  }

  size_t active_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_.size();
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    active_.clear();
  }

private:
  mutable std::mutex mutex_;
  std::unordered_map<int, LeakInfo> active_;
};

// =============================================================================
// DbPool global convenience functions
// =============================================================================

// Create a DbPool from typical configuration
std::unique_ptr<DbPool> make_db_pool(
    const std::string& database_name,
    const std::string& connection_string,
    std::shared_ptr<storage::BaseDatabaseEngine> engine,
    const std::string& server_name,
    const DbPoolConfig& config = DbPoolConfig{}) {
  return std::make_unique<DbPool>(database_name, connection_string,
                                   std::move(engine), server_name, config);
}

// Create a DbPool with read/write split configuration
std::unique_ptr<DbPool> make_db_pool_rw_split(
    const std::string& database_name,
    const std::string& write_conn_string,
    const std::string& read_conn_string,
    std::shared_ptr<storage::BaseDatabaseEngine> engine,
    const std::string& server_name,
    const DbPoolConfig& config = DbPoolConfig{}) {
  DbPoolConfig cfg = config;
  cfg.enable_read_write_split = true;
  cfg.read_connection_string = read_conn_string;
  return std::make_unique<DbPool>(database_name, write_conn_string,
                                   std::move(engine), server_name, cfg);
}

}  // namespace progressive
