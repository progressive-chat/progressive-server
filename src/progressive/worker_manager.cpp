// ============================================================================
// worker_manager.cpp — Matrix Worker Management System
//
// Implements the complete worker lifecycle management infrastructure:
//   - Worker type definitions: generic, pusher, federation, media,
//     appservice, user_dir, frontend, persister, writer, synchrotron
//   - Worker configuration with per-type defaults, resource limits,
//     scaling policies, and instance-specific overrides
//   - Worker registration and discovery with unique worker IDs,
//     instance naming, capability advertisement, and graceful
//     startup/shutdown sequencing
//   - Heartbeat mechanism with configurable intervals, timeout
//     detection, missed-beat tracking, auto-expiry of dead
//     workers, and leader election support
//   - Replication streams for event data, presence, receipts,
//     typing, to-device messages, device lists, account data,
//     push rules, and custom application streams
//   - Load balancing with multiple strategies (round-robin,
//     least-connections, weighted, consistent-hash, adaptive),
//     work stealing, backpressure signaling, and overload shedding
//   - Worker pool management with dynamic scaling, health-based
//     routing, circuit breakers, and graceful degradation
//   - SQL DDL for worker registry, heartbeat log, replication
//     positions, load metrics, and allocation history tables
//   - Admin API support (worker list, status, kill, restart,
//     drain, scale, metrics queries)
//   - Prometheus metrics export for worker counts, heartbeats,
//     load averages, queue depths, and allocation rates
//   - Integration with health checker for worker-aware health
//     scoring and dependency tracking
//
// Worker Types:
//   1. generic        — general-purpose worker for unclassified tasks
//   2. pusher         — push notification delivery to gateways
//   3. federation     — inbound/outbound server-to-server federation
//   4. media          — media upload/download, thumbnail generation
//   5. appservice     — application service bridge API handling
//   6. user_dir       — user directory search and indexing
//   7. frontend       — HTTP request handling, client-facing API
//   8. persister      — database write batching and commit sequencing
//   9. writer         — streaming event writing and ordering
//   10. synchrotron   — sync request processing and response assembly
//
// Equivalent to:
//   synapse/app/generic_worker.py                       (~200 lines)
//   synapse/app/pusher.py                               (~100 lines)
//   synapse/app/federation_reader.py / sender.py        (~300 lines)
//   synapse/app/media_repository.py                     (~150 lines)
//   synapse/app/appservice.py                           (~200 lines)
//   synapse/app/user_dir.py                             (~100 lines)
//   synapse/app/frontend_proxy.py                       (~250 lines)
//   synapse/app/event_persister.py                      (~150 lines)
//   synapse/app/stream_writer.py                        (~200 lines)
//   synapse/app/synchrotron.py                          (~250 lines)
//   synapse/replication/tcp/client.py                   (~800 lines)
//   synapse/replication/tcp/handler.py                  (~500 lines)
//   synapse/replication/tcp/streams/                    (~1,000 lines)
//   synapse/util/worker.py                              (~300 lines)
//   synapse/metrics/workers.py                          (~200 lines)
//
// Total equivalent: ~4,700 lines of Python
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
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
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
#include "progressive/storage/engine.hpp"
#include "progressive/storage/types.hpp"
#include "progressive/util/cache.hpp"
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
// Forward declarations for storage
// ============================================================================
namespace storage {
class DatabasePool;
class LoggingTransaction;
}  // namespace storage

using storage::DatabasePool;
using storage::LoggingTransaction;
using storage::Row;
using storage::RowList;
using storage::ColumnValue;
using storage::SQLParam;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class WorkerTypeRegistry;
class WorkerConfigEngine;
class WorkerRegistrationService;
class WorkerHeartbeatEngine;
class ReplicationStreamManager;
class LoadBalancer;
class WorkerPoolManager;
class WorkerMetricsCollector;
class WorkerAdminAPI;
class WorkerDiscoveryService;
class CircuitBreaker;
class WorkStealingEngine;
class WorkerDrainManager;
class WorkerOrchestrator;

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// --------------------------------------------------------------------------
// Logging helper (matches project conventions)
// --------------------------------------------------------------------------
struct WorkerLogger {
  std::string name_;
  void debug(const std::string& msg) { std::cerr << "[DEBUG][Worker:" << name_ << "] " << msg << "\n"; }
  void info(const std::string& msg)  { std::cerr << "[INFO][Worker:" << name_ << "] " << msg << "\n"; }
  void warn(const std::string& msg)  { std::cerr << "[WARN][Worker:" << name_ << "] " << msg << "\n"; }
  void error(const std::string& msg) { std::cerr << "[ERROR][Worker:" << name_ << "] " << msg << "\n"; }
};

WorkerLogger& get_worker_logger(const std::string& name) {
  static thread_local std::map<std::string, WorkerLogger> loggers;
  if (loggers.find(name) == loggers.end()) {
    loggers[name].name_ = name;
  }
  return loggers[name];
}

// --------------------------------------------------------------------------
// Worker type enumeration
// --------------------------------------------------------------------------
enum class WorkerType : uint8_t {
  kGeneric      = 0,   // General-purpose worker for unclassified tasks
  kPusher       = 1,   // Push notification delivery to gateways
  kFederation   = 2,   // Federation inbound/outbound S2S communication
  kMedia        = 3,   // Media upload/download and thumbnail generation
  kAppservice   = 4,   // Application service bridge API handling
  kUserDir      = 5,   // User directory search and indexing
  kFrontend     = 6,   // HTTP request handling, client-facing API
  kPersister    = 7,   // Database write batching and commit sequencing
  kWriter       = 8,   // Streaming event writing and ordering
  kSynchrotron  = 9,   // Sync request processing and response assembly
  kCount        = 10
};

constexpr size_t kNumWorkerTypes = static_cast<size_t>(WorkerType::kCount);

constexpr std::array<const char*, kNumWorkerTypes> kWorkerTypeNames = {
  "generic", "pusher", "federation", "media", "appservice",
  "user_dir", "frontend", "persister", "writer", "synchrotron"
};

const char* worker_type_to_string(WorkerType wt) {
  auto idx = static_cast<size_t>(wt);
  return (idx < kNumWorkerTypes) ? kWorkerTypeNames[idx] : "unknown";
}

WorkerType string_to_worker_type(const std::string& s) {
  for (size_t i = 0; i < kNumWorkerTypes; ++i) {
    if (s == kWorkerTypeNames[i]) return static_cast<WorkerType>(i);
  }
  return WorkerType::kGeneric;
}

// Capability bitmask for worker type
constexpr uint64_t kCapNone           = 0ull;
constexpr uint64_t kCapHTTP           = 1ull << 0;
constexpr uint64_t kCapFederation     = 1ull << 1;
constexpr uint64_t kCapDatabaseWrite  = 1ull << 2;
constexpr uint64_t kCapDatabaseRead   = 1ull << 3;
constexpr uint64_t kCapMediaStorage   = 1ull << 4;
constexpr uint64_t kCapPushTransport  = 1ull << 5;
constexpr uint64_t kCapSync           = 1ull << 6;
constexpr uint64_t kCapAppserviceAPI  = 1ull << 7;
constexpr uint64_t kCapUserSearch     = 1ull << 8;
constexpr uint64_t kCapEventPersist   = 1ull << 9;
constexpr uint64_t kCapStreamWrite    = 1ull << 10;
constexpr uint64_t kCapReplication    = 1ull << 11;
constexpr uint64_t kCapBackgroundTask = 1ull << 12;
constexpr uint64_t kCapMetrics        = 1ull << 13;
constexpr uint64_t kCapAdmin          = 1ull << 14;
constexpr uint64_t kCapCache          = 1ull << 15;

uint64_t worker_type_capabilities(WorkerType wt) {
  switch (wt) {
    case WorkerType::kGeneric:     return kCapHTTP | kCapDatabaseRead | kCapBackgroundTask;
    case WorkerType::kPusher:      return kCapPushTransport | kCapDatabaseRead | kCapHTTP;
    case WorkerType::kFederation:  return kCapFederation | kCapHTTP | kCapDatabaseRead | kCapDatabaseWrite;
    case WorkerType::kMedia:       return kCapHTTP | kCapMediaStorage | kCapDatabaseRead | kCapDatabaseWrite;
    case WorkerType::kAppservice:  return kCapAppserviceAPI | kCapHTTP | kCapDatabaseRead | kCapDatabaseWrite;
    case WorkerType::kUserDir:     return kCapUserSearch | kCapDatabaseRead | kCapHTTP;
    case WorkerType::kFrontend:    return kCapHTTP | kCapDatabaseRead | kCapCache | kCapMetrics;
    case WorkerType::kPersister:   return kCapEventPersist | kCapDatabaseWrite | kCapDatabaseRead;
    case WorkerType::kWriter:      return kCapStreamWrite | kCapDatabaseWrite | kCapDatabaseRead | kCapReplication;
    case WorkerType::kSynchrotron: return kCapSync | kCapDatabaseRead | kCapHTTP | kCapCache;
    default:                       return kCapNone;
  }
}

// --------------------------------------------------------------------------
// Worker status enumeration
// --------------------------------------------------------------------------
enum class WorkerStatus : uint8_t {
  kUnknown     = 0,
  kStarting    = 1,
  kRunning     = 2,
  kDraining    = 3,
  kDrained     = 4,
  kStopping    = 5,
  kStopped     = 6,
  kFailed      = 7,
  kOrphaned    = 8,
  kRestarting  = 9,
  kDegraded    = 10,
  kIsolated    = 11
};

const char* worker_status_to_string(WorkerStatus s) {
  switch (s) {
    case WorkerStatus::kUnknown:    return "unknown";
    case WorkerStatus::kStarting:   return "starting";
    case WorkerStatus::kRunning:    return "running";
    case WorkerStatus::kDraining:   return "draining";
    case WorkerStatus::kDrained:    return "drained";
    case WorkerStatus::kStopping:   return "stopping";
    case WorkerStatus::kStopped:    return "stopped";
    case WorkerStatus::kFailed:     return "failed";
    case WorkerStatus::kOrphaned:   return "orphaned";
    case WorkerStatus::kRestarting: return "restarting";
    case WorkerStatus::kDegraded:   return "degraded";
    case WorkerStatus::kIsolated:   return "isolated";
  }
  return "unknown";
}

WorkerStatus string_to_worker_status(const std::string& s) {
  if (s == "starting")   return WorkerStatus::kStarting;
  if (s == "running")    return WorkerStatus::kRunning;
  if (s == "draining")   return WorkerStatus::kDraining;
  if (s == "drained")    return WorkerStatus::kDrained;
  if (s == "stopping")   return WorkerStatus::kStopping;
  if (s == "stopped")    return WorkerStatus::kStopped;
  if (s == "failed")     return WorkerStatus::kFailed;
  if (s == "orphaned")   return WorkerStatus::kOrphaned;
  if (s == "restarting") return WorkerStatus::kRestarting;
  if (s == "degraded")   return WorkerStatus::kDegraded;
  if (s == "isolated")   return WorkerStatus::kIsolated;
  return WorkerStatus::kUnknown;
}

// --------------------------------------------------------------------------
// Load balancing strategy enumeration
// --------------------------------------------------------------------------
enum class LoadBalanceStrategy : uint8_t {
  kRoundRobin        = 0,
  kLeastConnections  = 1,
  kWeighted          = 2,
  kConsistentHash    = 3,
  kAdaptive          = 4,
  kRandom            = 5,
  kFastestResponse   = 6,
  kResourceAware     = 7
};

const char* lb_strategy_to_string(LoadBalanceStrategy s) {
  switch (s) {
    case LoadBalanceStrategy::kRoundRobin:       return "round_robin";
    case LoadBalanceStrategy::kLeastConnections:  return "least_connections";
    case LoadBalanceStrategy::kWeighted:          return "weighted";
    case LoadBalanceStrategy::kConsistentHash:    return "consistent_hash";
    case LoadBalanceStrategy::kAdaptive:          return "adaptive";
    case LoadBalanceStrategy::kRandom:            return "random";
    case LoadBalanceStrategy::kFastestResponse:   return "fastest_response";
    case LoadBalanceStrategy::kResourceAware:     return "resource_aware";
  }
  return "round_robin";
}

LoadBalanceStrategy string_to_lb_strategy(const std::string& s) {
  if (s == "round_robin")        return LoadBalanceStrategy::kRoundRobin;
  if (s == "least_connections")  return LoadBalanceStrategy::kLeastConnections;
  if (s == "weighted")           return LoadBalanceStrategy::kWeighted;
  if (s == "consistent_hash")    return LoadBalanceStrategy::kConsistentHash;
  if (s == "adaptive")           return LoadBalanceStrategy::kAdaptive;
  if (s == "random")             return LoadBalanceStrategy::kRandom;
  if (s == "fastest_response")   return LoadBalanceStrategy::kFastestResponse;
  if (s == "resource_aware")     return LoadBalanceStrategy::kResourceAware;
  return LoadBalanceStrategy::kRoundRobin;
}

// --------------------------------------------------------------------------
// Replication stream type enumeration
// --------------------------------------------------------------------------
enum class ReplicationStreamType : uint8_t {
  kEvents       = 0,
  kPresence     = 1,
  kReceipts     = 2,
  kTyping       = 3,
  kToDevice     = 4,
  kDeviceLists  = 5,
  kAccountData  = 6,
  kPushRules    = 7,
  kBackfill     = 8,
  kCaches       = 9,
  kDeviceMessages = 10,
  kFederationAck  = 11,
  kCurrentState  = 12,
  kCustomStream  = 13,
  kCount         = 14
};

constexpr size_t kNumReplicationStreamTypes = static_cast<size_t>(ReplicationStreamType::kCount);

constexpr std::array<const char*, kNumReplicationStreamTypes> kRepStreamNames = {
  "events", "presence", "receipts", "typing", "to_device",
  "device_lists", "account_data", "push_rules", "backfill",
  "caches", "device_messages", "federation_ack", "current_state", "custom"
};

const char* rep_stream_to_string(ReplicationStreamType rt) {
  auto idx = static_cast<size_t>(rt);
  return (idx < kNumReplicationStreamTypes) ? kRepStreamNames[idx] : "unknown";
}

// --------------------------------------------------------------------------
// Constants
// --------------------------------------------------------------------------
constexpr int64_t kDefaultHeartbeatIntervalMs = 5000;
constexpr int64_t kDefaultHeartbeatTimeoutMs = 30000;
constexpr int64_t kDefaultWorkerDrainTimeoutMs = 60000;
constexpr int64_t kDefaultWorkerStartupTimeoutMs = 120000;
constexpr int64_t kDefaultReplicationPollIntervalMs = 1000;
constexpr int64_t kDefaultReplicationMaxLagMs = 60000;
constexpr size_t kDefaultMaxWorkersPerType = 64;
constexpr size_t kDefaultMinWorkersPerType = 1;
constexpr size_t kMaxWorkerNameLength = 128;
constexpr size_t kMaxInstanceIdLength = 256;
constexpr size_t kMaxWorkerTags = 32;
constexpr int kMaxMissedHeartbeats = 6;
constexpr int kMaxRestartAttempts = 10;
constexpr int64_t kRestartBackoffBaseMs = 1000;
constexpr int64_t kRestartBackoffMaxMs = 300000;
constexpr int64_t kCircuitBreakerOpenTimeoutMs = 30000;
constexpr int kCircuitBreakerFailureThreshold = 5;
constexpr int kCircuitBreakerHalfOpenMaxRequests = 3;
constexpr int64_t kMetricsReportIntervalMs = 15000;
constexpr int64_t kWorkerReaperIntervalMs = 10000;
constexpr int64_t kLoadReportIntervalMs = 5000;
constexpr int64_t kDiscoveryBroadcastIntervalMs = 30000;
constexpr size_t kConsistentHashVirtualNodes = 256;
constexpr size_t kMaxReplicationStreamBatchSize = 500;
constexpr int64_t kMaxReplicationStreamAgeMs = 300000;

// --------------------------------------------------------------------------
// Time utility helpers
// --------------------------------------------------------------------------
int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
    chr::system_clock::now().time_since_epoch()).count();
}

int64_t now_us() {
  return chr::duration_cast<chr::microseconds>(
    chr::system_clock::now().time_since_epoch()).count();
}

std::string iso8601_now() {
  auto now = chr::system_clock::now();
  auto tt = chr::system_clock::to_time_t(now);
  std::ostringstream oss;
  oss << std::put_time(std::gmtime(&tt), "%Y-%m-%dT%H:%M:%SZ");
  return oss.str();
}

// --------------------------------------------------------------------------
// UUID generation for worker IDs (simple v4-like)
// --------------------------------------------------------------------------
std::string generate_worker_uuid() {
  static std::random_device rd;
  static std::mt19937_64 gen(rd());
  static std::uniform_int_distribution<uint64_t> dis;
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (int i = 0; i < 4; ++i) {
    uint64_t part = dis(gen);
    oss << std::setw(16) << part;
    if (i < 3) oss << "-";
  }
  return oss.str();
}

// --------------------------------------------------------------------------
// MurmurHash3-style simple hash for consistent hashing
// --------------------------------------------------------------------------
uint64_t hash_string(const std::string& s) {
  uint64_t h = 14695981039346656037ull;
  for (char c : s) {
    h ^= static_cast<uint64_t>(static_cast<uint8_t>(c));
    h *= 1099511628211ull;
  }
  return h;
}

uint64_t hash_bytes(const void* data, size_t len) {
  const auto* bytes = static_cast<const uint8_t*>(data);
  uint64_t h = 14695981039346656037ull;
  for (size_t i = 0; i < len; ++i) {
    h ^= static_cast<uint64_t>(bytes[i]);
    h *= 1099511628211ull;
  }
  return h;
}

// --------------------------------------------------------------------------
// Exponential backoff calculator
// --------------------------------------------------------------------------
int64_t compute_backoff_ms(int attempt, int64_t base_ms, int64_t max_ms) {
  double factor = std::pow(2.0, static_cast<double>(attempt));
  int64_t with_jitter = static_cast<int64_t>(base_ms * factor);
  // Add 25% jitter
  static std::random_device rd;
  static std::mt19937_64 gen(rd());
  std::uniform_int_distribution<int64_t> jitter(0, with_jitter / 4);
  int64_t result = with_jitter + jitter(gen);
  return std::min(result, max_ms);
}

// --------------------------------------------------------------------------
// Exponential moving average for load tracking
// --------------------------------------------------------------------------
class ExpMovingAverage {
public:
  explicit ExpMovingAverage(double alpha = 0.2) : alpha_(alpha), value_(0.0), initialized_(false) {}

  void add_sample(double sample) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (!initialized_) {
      value_ = sample;
      initialized_ = true;
    } else {
      value_ = alpha_ * sample + (1.0 - alpha_) * value_;
    }
  }

  double value() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return value_;
  }

  void reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    value_ = 0.0;
    initialized_ = false;
  }

private:
  double alpha_;
  double value_;
  bool initialized_;
  mutable std::mutex mtx_;
};

// --------------------------------------------------------------------------
// Ring buffer for sliding window metrics
// --------------------------------------------------------------------------
template<typename T, size_t N>
class SlidingWindow {
public:
  void push(T value) {
    std::lock_guard<std::mutex> lock(mtx_);
    buffer_[pos_] = value;
    pos_ = (pos_ + 1) % N;
    if (count_ < N) count_++;
  }

  T average() const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (count_ == 0) return T{};
    T sum{};
    for (size_t i = 0; i < count_; ++i) {
      sum += buffer_[i];
    }
    return sum / static_cast<T>(count_);
  }

  T max() const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (count_ == 0) return T{};
    T m = buffer_[0];
    for (size_t i = 1; i < count_; ++i) {
      if (buffer_[i] > m) m = buffer_[i];
    }
    return m;
  }

  T min() const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (count_ == 0) return T{};
    T m = buffer_[0];
    for (size_t i = 1; i < count_; ++i) {
      if (buffer_[i] < m) m = buffer_[i];
    }
    return m;
  }

  std::vector<T> values() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return std::vector<T>(buffer_.begin(), buffer_.begin() + count_);
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return count_;
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mtx_);
    buffer_.fill(T{});
    pos_ = 0;
    count_ = 0;
  }

private:
  std::array<T, N> buffer_{};
  size_t pos_ = 0;
  size_t count_ = 0;
  mutable std::mutex mtx_;
};

// --------------------------------------------------------------------------
// SQL DDL for worker management tables
// --------------------------------------------------------------------------
constexpr const char* kWorkerRegistryDDL = R"SQL(
CREATE TABLE IF NOT EXISTS worker_registry (
    worker_id       TEXT PRIMARY KEY,
    worker_type     TEXT NOT NULL,
    worker_name     TEXT NOT NULL,
    instance_id     TEXT NOT NULL,
    hostname        TEXT,
    pid             INTEGER,
    status          TEXT NOT NULL DEFAULT 'starting',
    capabilities    INTEGER NOT NULL DEFAULT 0,
    listen_address  TEXT,
    listen_port     INTEGER,
    tags            TEXT,  -- JSON array
    metadata        TEXT,  -- JSON object
    registered_at   INTEGER NOT NULL,
    last_heartbeat  INTEGER,
    last_status_change INTEGER,
    restart_count   INTEGER NOT NULL DEFAULT 0,
    version         TEXT,
    config_hash     TEXT
);

CREATE INDEX IF NOT EXISTS idx_worker_type ON worker_registry(worker_type);
CREATE INDEX IF NOT EXISTS idx_worker_status ON worker_registry(status);
CREATE INDEX IF NOT EXISTS idx_worker_instance ON worker_registry(instance_id);
CREATE INDEX IF NOT EXISTS idx_worker_heartbeat ON worker_registry(last_heartbeat);
)SQL";

constexpr const char* kHeartbeatLogDDL = R"SQL(
CREATE TABLE IF NOT EXISTS worker_heartbeat_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id       TEXT NOT NULL,
    received_at     INTEGER NOT NULL,
    load_cpu        REAL,
    load_memory_mb  REAL,
    active_connections INTEGER,
    queue_depth     INTEGER,
    error_count     INTEGER,
    request_rate    REAL,
    response_time_p50 REAL,
    response_time_p95 REAL,
    response_time_p99 REAL,
    custom_metrics  TEXT  -- JSON
);

CREATE INDEX IF NOT EXISTS idx_hb_worker_time ON worker_heartbeat_log(worker_id, received_at);
)SQL";

constexpr const char* kReplicationPositionDDL = R"SQL(
CREATE TABLE IF NOT EXISTS replication_positions (
    worker_id       TEXT NOT NULL,
    stream_name     TEXT NOT NULL,
    position        INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    lag_ms          INTEGER,
    PRIMARY KEY (worker_id, stream_name)
);

CREATE INDEX IF NOT EXISTS idx_rep_pos_stream ON replication_positions(stream_name, position);
)SQL";

constexpr const char* kLoadMetricsDDL = R"SQL(
CREATE TABLE IF NOT EXISTS worker_load_metrics (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id       TEXT NOT NULL,
    recorded_at     INTEGER NOT NULL,
    load_score      REAL NOT NULL,
    cpu_percent     REAL,
    memory_percent  REAL,
    connection_count INTEGER,
    request_rate    REAL,
    queue_depth     INTEGER,
    error_rate      REAL,
    backlog_size    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_load_worker_time ON worker_load_metrics(worker_id, recorded_at);
)SQL";

constexpr const char* kAllocationHistoryDDL = R"SQL(
CREATE TABLE IF NOT EXISTS worker_allocation_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    worker_id       TEXT NOT NULL,
    allocated_at    INTEGER NOT NULL,
    released_at     INTEGER,
    task_type       TEXT NOT NULL,
    task_id         TEXT,
    result          TEXT,
    duration_ms     INTEGER,
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_alloc_worker ON worker_allocation_history(worker_id, allocated_at);
)SQL";

// --------------------------------------------------------------------------
// All SQL DDL statements
// --------------------------------------------------------------------------
std::vector<std::string> get_all_ddl() {
  return {
    kWorkerRegistryDDL,
    kHeartbeatLogDDL,
    kReplicationPositionDDL,
    kLoadMetricsDDL,
    kAllocationHistoryDDL
  };
}

}  // namespace

// ============================================================================
// WorkerTypeRegistry — Static worker type metadata and capability registry
// ============================================================================
class WorkerTypeRegistry {
public:
  WorkerTypeRegistry() {
    init_defaults();
  }

  // --------------------------------------------------------------------------
  // Worker type descriptor
  // --------------------------------------------------------------------------
  struct TypeDescriptor {
    WorkerType type;
    std::string name;
    uint64_t capabilities;
    std::string description;
    std::vector<WorkerType> dependencies;
    std::vector<ReplicationStreamType> required_streams;
    std::vector<ReplicationStreamType> produced_streams;
    size_t default_pool_min;
    size_t default_pool_max;
    int64_t default_startup_timeout_ms;
    bool can_be_leader;
    bool requires_database;
    bool is_critical;
  };

  // --------------------------------------------------------------------------
  // Get descriptor for a worker type
  // --------------------------------------------------------------------------
  const TypeDescriptor& descriptor(WorkerType wt) const {
    auto it = descriptors_.find(wt);
    if (it != descriptors_.end()) return it->second;
    return unknown_descriptor_;
  }

  // --------------------------------------------------------------------------
  // Get all registered types
  // --------------------------------------------------------------------------
  const std::map<WorkerType, TypeDescriptor>& all() const {
    return descriptors_;
  }

  // --------------------------------------------------------------------------
  // Get capabilities for a type
  // --------------------------------------------------------------------------
  uint64_t capabilities(WorkerType wt) const {
    return descriptor(wt).capabilities;
  }

  // --------------------------------------------------------------------------
  // Check if a type depends on another
  // --------------------------------------------------------------------------
  bool depends_on(WorkerType wt, WorkerType dep) const {
    const auto& desc = descriptor(wt);
    for (auto d : desc.dependencies) {
      if (d == dep) return true;
    }
    return false;
  }

  // --------------------------------------------------------------------------
  // Get all dependencies recursively
  // --------------------------------------------------------------------------
  std::set<WorkerType> all_dependencies(WorkerType wt) const {
    std::set<WorkerType> result;
    std::set<WorkerType> visited;
    std::function<void(WorkerType)> collect = [&](WorkerType w) {
      if (visited.count(w)) return;
      visited.insert(w);
      const auto& desc = descriptor(w);
      for (auto dep : desc.dependencies) {
        result.insert(dep);
        collect(dep);
      }
    };
    collect(wt);
    return result;
  }

  // --------------------------------------------------------------------------
  // Get startup order (dependencies first)
  // --------------------------------------------------------------------------
  std::vector<WorkerType> startup_order() const {
    std::vector<WorkerType> result;
    std::set<WorkerType> placed;
    // Topological sort by dependencies
    std::function<void(WorkerType)> visit = [&](WorkerType wt) {
      if (placed.count(wt)) return;
      const auto& desc = descriptor(wt);
      for (auto dep : desc.dependencies) {
        visit(dep);
      }
      placed.insert(wt);
      result.push_back(wt);
    };
    for (size_t i = 0; i < kNumWorkerTypes; ++i) {
      visit(static_cast<WorkerType>(i));
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Get shutdown order (reverse of startup)
  // --------------------------------------------------------------------------
  std::vector<WorkerType> shutdown_order() const {
    auto order = startup_order();
    std::reverse(order.begin(), order.end());
    return order;
  }

  // --------------------------------------------------------------------------
  // Critical worker types (server cannot operate without them)
  // --------------------------------------------------------------------------
  std::vector<WorkerType> critical_types() const {
    std::vector<WorkerType> result;
    for (const auto& [wt, desc] : descriptors_) {
      if (desc.is_critical) result.push_back(wt);
    }
    return result;
  }

private:
  // --------------------------------------------------------------------------
  // Initialize default type descriptors
  // --------------------------------------------------------------------------
  void init_defaults() {
    // --- Generic Worker ---
    descriptors_[WorkerType::kGeneric] = {
      WorkerType::kGeneric,
      "generic",
      kCapHTTP | kCapDatabaseRead | kCapBackgroundTask,
      "General-purpose worker for unclassified tasks",
      {},  // No specific dependencies
      {},  // No required streams
      {},  // No produced streams
      1,    // min pool
      16,   // max pool
      60000,  // startup timeout
      false,  // can_be_leader
      true,   // requires_database
      false   // is_critical
    };

    // --- Pusher Worker ---
    descriptors_[WorkerType::kPusher] = {
      WorkerType::kPusher,
      "pusher",
      kCapPushTransport | kCapDatabaseRead | kCapHTTP,
      "Push notification delivery to gateways",
      {WorkerType::kPersister},  // Needs persister for event data
      {ReplicationStreamType::kEvents, ReplicationStreamType::kPushRules},
      {},
      1, 2, 90000, false, true, false
    };

    // --- Federation Worker ---
    descriptors_[WorkerType::kFederation] = {
      WorkerType::kFederation,
      "federation",
      kCapFederation | kCapHTTP | kCapDatabaseRead | kCapDatabaseWrite,
      "Inbound/outbound server-to-server federation",
      {WorkerType::kPersister},
      {ReplicationStreamType::kEvents, ReplicationStreamType::kPresence,
       ReplicationStreamType::kReceipts, ReplicationStreamType::kTyping,
       ReplicationStreamType::kDeviceLists, ReplicationStreamType::kFederationAck},
      {ReplicationStreamType::kBackfill},
      1, 8, 120000, false, true, true  // Critical
    };

    // --- Media Worker ---
    descriptors_[WorkerType::kMedia] = {
      WorkerType::kMedia,
      "media",
      kCapHTTP | kCapMediaStorage | kCapDatabaseRead | kCapDatabaseWrite,
      "Media upload/download and thumbnail generation",
      {},
      {},
      {},
      1, 4, 60000, false, false, false
    };

    // --- Appservice Worker ---
    descriptors_[WorkerType::kAppservice] = {
      WorkerType::kAppservice,
      "appservice",
      kCapAppserviceAPI | kCapHTTP | kCapDatabaseRead | kCapDatabaseWrite,
      "Application service bridge API handling",
      {WorkerType::kPersister},
      {ReplicationStreamType::kEvents, ReplicationStreamType::kToDevice,
       ReplicationStreamType::kDeviceMessages},
      {},
      1, 4, 90000, false, true, false
    };

    // --- User Directory Worker ---
    descriptors_[WorkerType::kUserDir] = {
      WorkerType::kUserDir,
      "user_dir",
      kCapUserSearch | kCapDatabaseRead | kCapHTTP,
      "User directory search and indexing",
      {WorkerType::kPersister},
      {ReplicationStreamType::kEvents, ReplicationStreamType::kCurrentState},
      {},
      1, 2, 60000, false, true, false
    };

    // --- Frontend Worker ---
    descriptors_[WorkerType::kFrontend] = {
      WorkerType::kFrontend,
      "frontend",
      kCapHTTP | kCapDatabaseRead | kCapCache | kCapMetrics | kCapAdmin,
      "HTTP request handling, client-facing API",
      {WorkerType::kSynchrotron},  // Delegates sync to synchrotron
      {},
      {},
      1, 32, 60000, false, true, true  // Critical
    };

    // --- Persister Worker ---
    descriptors_[WorkerType::kPersister] = {
      WorkerType::kPersister,
      "persister",
      kCapEventPersist | kCapDatabaseWrite | kCapDatabaseRead,
      "Database write batching and commit sequencing",
      {},
      {ReplicationStreamType::kEvents},
      {ReplicationStreamType::kEvents},  // Produces events stream for others
      1, 4, 90000, false, true, true  // Critical
    };

    // --- Writer Worker ---
    descriptors_[WorkerType::kWriter] = {
      WorkerType::kWriter,
      "writer",
      kCapStreamWrite | kCapDatabaseWrite | kCapDatabaseRead | kCapReplication,
      "Streaming event writing and ordering",
      {WorkerType::kPersister},
      {},
      {ReplicationStreamType::kEvents, ReplicationStreamType::kPresence,
       ReplicationStreamType::kReceipts, ReplicationStreamType::kTyping,
       ReplicationStreamType::kToDevice, ReplicationStreamType::kDeviceLists,
       ReplicationStreamType::kAccountData, ReplicationStreamType::kPushRules},
      1, 4, 90000, false, true, true  // Critical
    };

    // --- Synchrotron Worker ---
    descriptors_[WorkerType::kSynchrotron] = {
      WorkerType::kSynchrotron,
      "synchrotron",
      kCapSync | kCapDatabaseRead | kCapHTTP | kCapCache,
      "Sync request processing and response assembly",
      {WorkerType::kWriter, WorkerType::kPersister},
      {ReplicationStreamType::kEvents, ReplicationStreamType::kPresence,
       ReplicationStreamType::kReceipts, ReplicationStreamType::kTyping,
       ReplicationStreamType::kToDevice, ReplicationStreamType::kDeviceLists,
       ReplicationStreamType::kAccountData, ReplicationStreamType::kPushRules,
       ReplicationStreamType::kCaches},
      {},
      1, 16, 120000, false, true, true  // Critical
    };
  }

  std::map<WorkerType, TypeDescriptor> descriptors_;
  TypeDescriptor unknown_descriptor_{
    WorkerType::kGeneric, "unknown", kCapNone, "Unknown worker type",
    {}, {}, {}, 0, 0, 0, false, false, false
  };
};

// ============================================================================
// WorkerConfig — Per-instance worker configuration
// ============================================================================
struct WorkerConfig {
  // Identity
  std::string worker_id;           // Unique worker ID (UUID)
  std::string worker_name;         // Human-readable name
  std::string instance_id;         // Instance/cluster identifier
  WorkerType type;                 // Worker type
  std::string hostname;            // Host machine name
  int64_t pid;                     // Process ID

  // Networking
  std::string listen_address;      // Bind address for HTTP/replication
  int listen_port;                 // Port number
  std::string replication_address; // Replication stream endpoint
  int replication_port;            // Replication port

  // Heartbeat configuration
  int64_t heartbeat_interval_ms;   // How often to send heartbeat
  int64_t heartbeat_timeout_ms;    // When a worker is considered dead

  // Startup/shutdown
  int64_t startup_timeout_ms;      // Max time to wait for startup
  int64_t drain_timeout_ms;        // Max time for graceful drain
  int max_restart_attempts;        // Max restart count before giving up
  int64_t restart_backoff_base_ms; // Base delay for backoff

  // Resource limits
  size_t max_connections;          // Max concurrent connections
  size_t max_queue_depth;          // Max request queue depth
  int64_t max_memory_mb;           // Memory limit in MB
  double max_cpu_percent;          // CPU soft limit (0-100)
  size_t max_request_rate;         // Max requests per second

  // Load balancing
  double weight;                   // Relative weight for weighted LB
  LoadBalanceStrategy lb_strategy; // Preferred LB strategy
  std::string consistent_hash_key; // Key for consistent hash ring

  // Tags and metadata
  std::vector<std::string> tags;
  json metadata;

  // Replication
  std::vector<ReplicationStreamType> subscribe_streams;
  std::vector<ReplicationStreamType> publish_streams;
  int64_t replication_poll_interval_ms;
  int64_t max_replication_lag_ms;

  // Circuit breaker
  int circuit_breaker_failures;    // Threshold before opening
  int64_t circuit_breaker_timeout_ms;  // How long to stay open

  // Version
  std::string version;
  std::string config_hash;

  // --------------------------------------------------------------------------
  // Default constructor
  // --------------------------------------------------------------------------
  WorkerConfig()
    : worker_id(generate_worker_uuid())
    , worker_name("worker-" + worker_id.substr(0, 8))
    , instance_id("default")
    , type(WorkerType::kGeneric)
    , hostname("localhost")
    , pid(0)
    , listen_address("0.0.0.0")
    , listen_port(0)
    , replication_address("127.0.0.1")
    , replication_port(0)
    , heartbeat_interval_ms(kDefaultHeartbeatIntervalMs)
    , heartbeat_timeout_ms(kDefaultHeartbeatTimeoutMs)
    , startup_timeout_ms(kDefaultWorkerStartupTimeoutMs)
    , drain_timeout_ms(kDefaultWorkerDrainTimeoutMs)
    , max_restart_attempts(kMaxRestartAttempts)
    , restart_backoff_base_ms(kRestartBackoffBaseMs)
    , max_connections(1000)
    , max_queue_depth(10000)
    , max_memory_mb(2048)
    , max_cpu_percent(80.0)
    , max_request_rate(10000)
    , weight(1.0)
    , lb_strategy(LoadBalanceStrategy::kAdaptive)
    , replication_poll_interval_ms(kDefaultReplicationPollIntervalMs)
    , max_replication_lag_ms(kDefaultReplicationMaxLagMs)
    , circuit_breaker_failures(kCircuitBreakerFailureThreshold)
    , circuit_breaker_timeout_ms(kCircuitBreakerOpenTimeoutMs)
    , version("0.1.0-progressive")
  {}

  // --------------------------------------------------------------------------
  // Type-aware defaults
  // --------------------------------------------------------------------------
  static WorkerConfig for_type(WorkerType wt, const WorkerTypeRegistry& registry) {
    WorkerConfig cfg;
    cfg.type = wt;
    cfg.worker_name = std::string(worker_type_to_string(wt)) + "-" + cfg.worker_id.substr(0, 8);

    const auto& desc = registry.descriptor(wt);

    // Set type-specific defaults
    cfg.startup_timeout_ms = desc.default_startup_timeout_ms;

    // Set subscription streams
    cfg.subscribe_streams = desc.required_streams;
    cfg.publish_streams = desc.produced_streams;

    // Set weights and concurrency based on type
    switch (wt) {
      case WorkerType::kGeneric:
        cfg.weight = 1.0;
        cfg.max_connections = 500;
        break;
      case WorkerType::kPusher:
        cfg.weight = 2.0;
        cfg.max_connections = 200;
        cfg.max_queue_depth = 50000;
        break;
      case WorkerType::kFederation:
        cfg.weight = 4.0;
        cfg.max_connections = 2000;
        cfg.max_queue_depth = 50000;
        break;
      case WorkerType::kMedia:
        cfg.weight = 2.0;
        cfg.max_connections = 500;
        cfg.max_memory_mb = 4096;
        break;
      case WorkerType::kAppservice:
        cfg.weight = 2.0;
        cfg.max_connections = 500;
        break;
      case WorkerType::kUserDir:
        cfg.weight = 1.0;
        cfg.max_connections = 200;
        break;
      case WorkerType::kFrontend:
        cfg.weight = 3.0;
        cfg.max_connections = 10000;
        cfg.max_request_rate = 50000;
        break;
      case WorkerType::kPersister:
        cfg.weight = 5.0;
        cfg.max_connections = 100;
        cfg.max_memory_mb = 4096;
        cfg.heartbeat_interval_ms = 2000;
        break;
      case WorkerType::kWriter:
        cfg.weight = 4.0;
        cfg.max_connections = 200;
        cfg.heartbeat_interval_ms = 2000;
        break;
      case WorkerType::kSynchrotron:
        cfg.weight = 3.0;
        cfg.max_connections = 5000;
        cfg.max_memory_mb = 8192;
        break;
      default:
        break;
    }

    return cfg;
  }

  // --------------------------------------------------------------------------
  // Serialize to JSON
  // --------------------------------------------------------------------------
  json to_json() const {
    json j;
    j["worker_id"] = worker_id;
    j["worker_name"] = worker_name;
    j["instance_id"] = instance_id;
    j["worker_type"] = worker_type_to_string(type);
    j["hostname"] = hostname;
    j["pid"] = pid;
    j["listen_address"] = listen_address;
    j["listen_port"] = listen_port;
    j["replication_address"] = replication_address;
    j["replication_port"] = replication_port;
    j["heartbeat_interval_ms"] = heartbeat_interval_ms;
    j["heartbeat_timeout_ms"] = heartbeat_timeout_ms;
    j["startup_timeout_ms"] = startup_timeout_ms;
    j["drain_timeout_ms"] = drain_timeout_ms;
    j["max_restart_attempts"] = max_restart_attempts;
    j["max_connections"] = max_connections;
    j["max_queue_depth"] = max_queue_depth;
    j["max_memory_mb"] = max_memory_mb;
    j["max_cpu_percent"] = max_cpu_percent;
    j["max_request_rate"] = max_request_rate;
    j["weight"] = weight;
    j["lb_strategy"] = lb_strategy_to_string(lb_strategy);
    j["consistent_hash_key"] = consistent_hash_key;
    j["tags"] = tags;
    j["metadata"] = metadata;
    j["version"] = version;
    j["config_hash"] = config_hash;
    json sub_streams;
    for (auto st : subscribe_streams) {
      sub_streams.push_back(rep_stream_to_string(st));
    }
    j["subscribe_streams"] = sub_streams;
    json pub_streams;
    for (auto st : publish_streams) {
      pub_streams.push_back(rep_stream_to_string(st));
    }
    j["publish_streams"] = pub_streams;
    return j;
  }

  // --------------------------------------------------------------------------
  // Deserialize from JSON
  // --------------------------------------------------------------------------
  static WorkerConfig from_json(const json& j) {
    WorkerConfig cfg;
    if (j.contains("worker_id")) cfg.worker_id = j["worker_id"].get<std::string>();
    if (j.contains("worker_name")) cfg.worker_name = j["worker_name"].get<std::string>();
    if (j.contains("instance_id")) cfg.instance_id = j["instance_id"].get<std::string>();
    if (j.contains("worker_type")) cfg.type = string_to_worker_type(j["worker_type"].get<std::string>());
    if (j.contains("hostname")) cfg.hostname = j["hostname"].get<std::string>();
    if (j.contains("pid")) cfg.pid = j["pid"].get<int64_t>();
    if (j.contains("listen_address")) cfg.listen_address = j["listen_address"].get<std::string>();
    if (j.contains("listen_port")) cfg.listen_port = j["listen_port"].get<int>();
    if (j.contains("replication_address")) cfg.replication_address = j["replication_address"].get<std::string>();
    if (j.contains("replication_port")) cfg.replication_port = j["replication_port"].get<int>();
    if (j.contains("heartbeat_interval_ms")) cfg.heartbeat_interval_ms = j["heartbeat_interval_ms"].get<int64_t>();
    if (j.contains("heartbeat_timeout_ms")) cfg.heartbeat_timeout_ms = j["heartbeat_timeout_ms"].get<int64_t>();
    if (j.contains("startup_timeout_ms")) cfg.startup_timeout_ms = j["startup_timeout_ms"].get<int64_t>();
    if (j.contains("drain_timeout_ms")) cfg.drain_timeout_ms = j["drain_timeout_ms"].get<int64_t>();
    if (j.contains("max_connections")) cfg.max_connections = j["max_connections"].get<size_t>();
    if (j.contains("max_queue_depth")) cfg.max_queue_depth = j["max_queue_depth"].get<size_t>();
    if (j.contains("max_memory_mb")) cfg.max_memory_mb = j["max_memory_mb"].get<int64_t>();
    if (j.contains("max_cpu_percent")) cfg.max_cpu_percent = j["max_cpu_percent"].get<double>();
    if (j.contains("weight")) cfg.weight = j["weight"].get<double>();
    if (j.contains("lb_strategy")) cfg.lb_strategy = string_to_lb_strategy(j["lb_strategy"].get<std::string>());
    if (j.contains("consistent_hash_key")) cfg.consistent_hash_key = j["consistent_hash_key"].get<std::string>();
    if (j.contains("tags")) cfg.tags = j["tags"].get<std::vector<std::string>>();
    if (j.contains("metadata")) cfg.metadata = j["metadata"];
    if (j.contains("version")) cfg.version = j["version"].get<std::string>();
    if (j.contains("config_hash")) cfg.config_hash = j["config_hash"].get<std::string>();
    if (j.contains("subscribe_streams")) {
      for (const auto& s : j["subscribe_streams"]) {
        cfg.subscribe_streams.push_back(
          static_cast<ReplicationStreamType>(
            std::distance(kRepStreamNames.begin(),
              std::find(kRepStreamNames.begin(), kRepStreamNames.end(), s.get<std::string>()))));
      }
    }
    if (j.contains("publish_streams")) {
      for (const auto& s : j["publish_streams"]) {
        cfg.publish_streams.push_back(
          static_cast<ReplicationStreamType>(
            std::distance(kRepStreamNames.begin(),
              std::find(kRepStreamNames.begin(), kRepStreamNames.end(), s.get<std::string>()))));
      }
    }
    return cfg;
  }
};

// ============================================================================
// WorkerInstance — Runtime representation of a single worker
// ============================================================================
class WorkerInstance {
public:
  explicit WorkerInstance(const WorkerConfig& config)
    : config_(config)
    , status_(WorkerStatus::kUnknown)
    , registered_at_ms_(now_ms())
    , last_heartbeat_ms_(0)
    , missed_heartbeats_(0)
    , restart_count_(0)
    , active_connections_(0)
    , queue_depth_(0)
    , error_count_(0)
    , status_change_ms_(registered_at_ms_)
  {}

  // --------------------------------------------------------------------------
  // Identity accessors
  // --------------------------------------------------------------------------
  const std::string& worker_id() const { return config_.worker_id; }
  const std::string& worker_name() const { return config_.worker_name; }
  const std::string& instance_id() const { return config_.instance_id; }
  WorkerType type() const { return config_.type; }
  const WorkerConfig& config() const { return config_; }

  // --------------------------------------------------------------------------
  // Status management
  // --------------------------------------------------------------------------
  WorkerStatus status() const {
    std::shared_lock lock(status_mtx_);
    return status_;
  }

  void set_status(WorkerStatus new_status) {
    std::unique_lock lock(status_mtx_);
    if (status_ != new_status) {
      status_ = new_status;
      status_change_ms_ = now_ms();
    }
  }

  int64_t status_change_ms() const {
    std::shared_lock lock(status_mtx_);
    return status_change_ms_;
  }

  // --------------------------------------------------------------------------
  // Heartbeat management
  // --------------------------------------------------------------------------
  void record_heartbeat() {
    std::unique_lock lock(hb_mtx_);
    last_heartbeat_ms_ = now_ms();
    missed_heartbeats_ = 0;
  }

  int64_t last_heartbeat_ms() const {
    std::shared_lock lock(hb_mtx_);
    return last_heartbeat_ms_;
  }

  int missed_heartbeats() const {
    std::shared_lock lock(hb_mtx_);
    return missed_heartbeats_;
  }

  int increment_missed_heartbeats() {
    std::unique_lock lock(hb_mtx_);
    return ++missed_heartbeats_;
  }

  bool is_heartbeat_expired(int64_t timeout_ms) const {
    std::shared_lock lock(hb_mtx_);
    if (last_heartbeat_ms_ == 0) return false;
    return (now_ms() - last_heartbeat_ms_) > timeout_ms;
  }

  // --------------------------------------------------------------------------
  // Restart tracking
  // --------------------------------------------------------------------------
  int restart_count() const { return restart_count_; }

  int increment_restart() {
    return ++restart_count_;
  }

  void reset_restarts() {
    restart_count_ = 0;
  }

  // --------------------------------------------------------------------------
  // Load metrics
  // --------------------------------------------------------------------------
  void update_load(double cpu, double memory_mb, int conns, int queue, int errors) {
    std::unique_lock lock(load_mtx_);
    load_cpu_.add_sample(cpu);
    load_memory_mb_.add_sample(memory_mb);
    active_connections_ = conns;
    queue_depth_ = queue;
    error_count_ = errors;
    last_load_update_ms_ = now_ms();
  }

  double cpu_avg() const { return load_cpu_.value(); }
  double memory_avg_mb() const { return load_memory_mb_.value(); }
  int active_connections() const {
    std::shared_lock lock(load_mtx_);
    return active_connections_;
  }
  int queue_depth() const {
    std::shared_lock lock(load_mtx_);
    return queue_depth_;
  }
  int error_count() const {
    std::shared_lock lock(load_mtx_);
    return error_count_;
  }

  // --------------------------------------------------------------------------
  // Computed load score (0-100, higher = more loaded)
  // --------------------------------------------------------------------------
  double load_score() const {
    std::shared_lock lock(load_mtx_);
    double cpu_score = load_cpu_.value() / std::max(1.0, config_.max_cpu_percent) * 50.0;
    double mem_score = load_memory_mb_.value() / std::max(1.0, static_cast<double>(config_.max_memory_mb)) * 30.0;
    double conn_score = active_connections_ > 0
      ? static_cast<double>(active_connections_) / std::max(static_cast<size_t>(1), config_.max_connections) * 15.0
      : 0.0;
    double queue_score = queue_depth_ > 0
      ? static_cast<double>(queue_depth_) / std::max(static_cast<size_t>(1), config_.max_queue_depth) * 5.0
      : 0.0;
    return std::min(100.0, cpu_score + mem_score + conn_score + queue_score);
  }

  // --------------------------------------------------------------------------
  // Request rate tracking
  // --------------------------------------------------------------------------
  void record_request(int64_t duration_us, bool success) {
    std::unique_lock lock(req_mtx_);
    total_requests_++;
    if (success) successful_requests_++;
    request_times_us_.push_back(duration_us);
    if (request_times_us_.size() > 1000) {
      request_times_us_.pop_front();  // Keep sliding window
    }
  }

  double request_rate_per_sec() const {
    std::shared_lock lock(req_mtx_);
    if (request_window_start_ms_ == 0) return 0.0;
    int64_t elapsed = now_ms() - request_window_start_ms_;
    if (elapsed == 0) return 0.0;
    return static_cast<double>(request_window_count_) / (elapsed / 1000.0);
  }

  double error_rate() const {
    std::shared_lock lock(req_mtx_);
    if (total_requests_ == 0) return 0.0;
    return static_cast<double>(total_requests_ - successful_requests_)
      / static_cast<double>(total_requests_);
  }

  int64_t p50_response_time_us() const {
    std::shared_lock lock(req_mtx_);
    if (request_times_us_.empty()) return 0;
    std::vector<int64_t> vals(request_times_us_.begin(), request_times_us_.end());
    std::sort(vals.begin(), vals.end());
    return vals.at(vals.size() / 2);
  }

  int64_t p95_response_time_us() const {
    std::shared_lock lock(req_mtx_);
    if (request_times_us_.empty()) return 0;
    std::vector<int64_t> vals(request_times_us_.begin(), request_times_us_.end());
    std::sort(vals.begin(), vals.end());
    return vals.at(static_cast<size_t>(vals.size() * 0.95));
  }

  int64_t p99_response_time_us() const {
    std::shared_lock lock(req_mtx_);
    if (request_times_us_.empty()) return 0;
    std::vector<int64_t> vals(request_times_us_.begin(), request_times_us_.end());
    std::sort(vals.begin(), vals.end());
    return vals.at(static_cast<size_t>(vals.size() * 0.99));
  }

  // --------------------------------------------------------------------------
  // Capability check
  // --------------------------------------------------------------------------
  bool has_capability(uint64_t cap) const {
    return (worker_type_capabilities(config_.type) & cap) != 0;
  }

  // --------------------------------------------------------------------------
  // Lifecycle helpers
  // --------------------------------------------------------------------------
  bool is_active() const {
    auto s = status();
    return s == WorkerStatus::kRunning || s == WorkerStatus::kStarting
        || s == WorkerStatus::kDraining || s == WorkerStatus::kDegraded;
  }

  bool is_healthy() const {
    auto s = status();
    return s == WorkerStatus::kRunning;
  }

  bool can_accept_work() const {
    auto s = status();
    return (s == WorkerStatus::kRunning || s == WorkerStatus::kStarting
            || s == WorkerStatus::kDegraded)
        && !is_overloaded();
  }

  bool is_overloaded() const {
    return load_score() > 90.0 || queue_depth() > static_cast<int>(config_.max_queue_depth * 0.9);
  }

  // --------------------------------------------------------------------------
  // Serialize for API
  // --------------------------------------------------------------------------
  json to_json() const {
    json j;
    j["worker_id"] = config_.worker_id;
    j["worker_name"] = config_.worker_name;
    j["instance_id"] = config_.instance_id;
    j["worker_type"] = worker_type_to_string(config_.type);
    j["status"] = worker_status_to_string(status());
    j["hostname"] = config_.hostname;
    j["pid"] = config_.pid;
    j["registered_at_ms"] = registered_at_ms_;
    j["last_heartbeat_ms"] = last_heartbeat_ms();
    j["missed_heartbeats"] = missed_heartbeats();
    j["restart_count"] = restart_count_;
    j["load_score"] = load_score();
    j["cpu_avg"] = cpu_avg();
    j["memory_avg_mb"] = memory_avg_mb();
    j["active_connections"] = active_connections();
    j["queue_depth"] = queue_depth();
    j["error_count"] = error_count();
    j["request_rate"] = request_rate_per_sec();
    j["error_rate"] = error_rate();
    j["p50_us"] = p50_response_time_us();
    j["p95_us"] = p95_response_time_us();
    j["p99_us"] = p99_response_time_us();
    j["version"] = config_.version;
    j["tags"] = config_.tags;
    return j;
  }

private:
  WorkerConfig config_;
  int64_t registered_at_ms_;

  // Status
  WorkerStatus status_;
  mutable std::shared_mutex status_mtx_;
  int64_t status_change_ms_;

  // Heartbeat
  int64_t last_heartbeat_ms_;
  int missed_heartbeats_;
  mutable std::shared_mutex hb_mtx_;

  // Restarts
  std::atomic<int> restart_count_{0};

  // Load metrics
  ExpMovingAverage load_cpu_{0.3};
  ExpMovingAverage load_memory_mb_{0.3};
  int active_connections_;
  int queue_depth_;
  int error_count_;
  int64_t last_load_update_ms_{0};
  mutable std::shared_mutex load_mtx_;

  // Request tracking
  int64_t total_requests_{0};
  int64_t successful_requests_{0};
  std::deque<int64_t> request_times_us_;
  int64_t request_window_start_ms_{0};
  int64_t request_window_count_{0};
  mutable std::shared_mutex req_mtx_;
};

// ============================================================================
// WorkerHeartbeatEngine — Heartbeat tracking, timeout detection, reaping
// ============================================================================
class WorkerHeartbeatEngine {
public:
  WorkerHeartbeatEngine(std::shared_ptr<WorkerLogger> logger = nullptr)
    : logger_(logger), running_(false) {}

  ~WorkerHeartbeatEngine() { stop(); }

  // --------------------------------------------------------------------------
  // Register a worker for heartbeat tracking
  // --------------------------------------------------------------------------
  void register_worker(std::shared_ptr<WorkerInstance> worker) {
    std::unique_lock lock(mtx_);
    workers_[worker->worker_id()] = worker;
    if (logger_) logger_->info("Registered worker for heartbeat: " + worker->worker_name());
  }

  // --------------------------------------------------------------------------
  // Unregister a worker
  // --------------------------------------------------------------------------
  void unregister_worker(const std::string& worker_id) {
    std::unique_lock lock(mtx_);
    workers_.erase(worker_id);
  }

  // --------------------------------------------------------------------------
  // Receive a heartbeat from a worker
  // --------------------------------------------------------------------------
  bool heartbeat(const std::string& worker_id, const json& metrics = json{}) {
    std::shared_lock lock(mtx_);
    auto it = workers_.find(worker_id);
    if (it == workers_.end()) return false;
    auto& worker = it->second;
    worker->record_heartbeat();

    if (!metrics.is_null()) {
      double cpu = metrics.value("cpu_percent", 0.0);
      double mem = metrics.value("memory_mb", 0.0);
      int conns = metrics.value("active_connections", 0);
      int queue = metrics.value("queue_depth", 0);
      int errors = metrics.value("error_count", 0);
      worker->update_load(cpu, mem, conns, queue, errors);
    }
    return true;
  }

  // --------------------------------------------------------------------------
  // Check all workers for expired heartbeats
  // Returns list of workers that have missed too many heartbeats
  // --------------------------------------------------------------------------
  std::vector<std::shared_ptr<WorkerInstance>> check_timeouts() {
    std::vector<std::shared_ptr<WorkerInstance>> expired;

    std::shared_lock lock(mtx_);
    for (auto& [id, worker] : workers_) {
      if (!worker->is_active()) continue;

      auto timeout = worker->config().heartbeat_timeout_ms;
      if (worker->is_heartbeat_expired(timeout)) {
        int missed = worker->increment_missed_heartbeats();
        int max_missed = worker->config().heartbeat_timeout_ms
          / worker->config().heartbeat_interval_ms;

        if (logger_) {
          logger_->warn("Worker " + worker->worker_name()
            + " missed heartbeat (" + std::to_string(missed) + "/" + std::to_string(max_missed) + ")");
        }

        if (missed >= max_missed || missed >= kMaxMissedHeartbeats) {
          worker->set_status(WorkerStatus::kOrphaned);
          expired.push_back(worker);
        }
      }
    }

    return expired;
  }

  // --------------------------------------------------------------------------
  // Reap orphaned/dead workers
  // --------------------------------------------------------------------------
  std::vector<std::string> reap_dead_workers() {
    std::vector<std::string> reaped;
    std::unique_lock lock(mtx_);
    auto it = workers_.begin();
    while (it != workers_.end()) {
      auto& worker = it->second;
      auto s = worker->status();
      if (s == WorkerStatus::kOrphaned || s == WorkerStatus::kFailed
          || s == WorkerStatus::kStopped) {
        // Keep failed workers for diagnostics for a while
        int64_t age = now_ms() - worker->status_change_ms();
        if (age > 300000 || s != WorkerStatus::kFailed) {  // 5 min for failed, immediate for others
          if (logger_) logger_->info("Reaping dead worker: " + worker->worker_name());
          reaped.push_back(it->first);
          it = workers_.erase(it);
          continue;
        }
      }
      ++it;
    }
    return reaped;
  }

  // --------------------------------------------------------------------------
  // Get all tracked workers
  // --------------------------------------------------------------------------
  std::vector<std::shared_ptr<WorkerInstance>> all_workers() const {
    std::shared_lock lock(mtx_);
    std::vector<std::shared_ptr<WorkerInstance>> result;
    result.reserve(workers_.size());
    for (const auto& [id, w] : workers_) {
      result.push_back(w);
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Get worker by ID
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> get_worker(const std::string& worker_id) const {
    std::shared_lock lock(mtx_);
    auto it = workers_.find(worker_id);
    return (it != workers_.end()) ? it->second : nullptr;
  }

  // --------------------------------------------------------------------------
  // Count workers by type and status
  // --------------------------------------------------------------------------
  size_t worker_count(WorkerType wt, WorkerStatus status = WorkerStatus::kRunning) const {
    std::shared_lock lock(mtx_);
    size_t count = 0;
    for (const auto& [id, w] : workers_) {
      if (w->type() == wt && w->status() == status) {
        count++;
      }
    }
    return count;
  }

  // --------------------------------------------------------------------------
  // Start background heartbeat checker thread
  // --------------------------------------------------------------------------
  void start(int64_t check_interval_ms = 5000) {
    if (running_) return;
    running_ = true;
    checker_thread_ = std::thread([this, check_interval_ms]() {
      while (running_) {
        {
          std::unique_lock lock(mtx_);
          cv_.wait_for(lock, chr::milliseconds(check_interval_ms));
        }
        if (!running_) break;
        auto expired = check_timeouts();
        for (auto& w : expired) {
          if (on_worker_expired_) {
            on_worker_expired_(w);
          }
        }
        reap_dead_workers();
      }
    });
  }

  // --------------------------------------------------------------------------
  // Stop background checker
  // --------------------------------------------------------------------------
  void stop() {
    running_ = false;
    cv_.notify_all();
    if (checker_thread_.joinable()) {
      checker_thread_.join();
    }
  }

  // --------------------------------------------------------------------------
  // Callback when a worker expires
  // --------------------------------------------------------------------------
  void set_on_worker_expired(std::function<void(std::shared_ptr<WorkerInstance>)> callback) {
    on_worker_expired_ = callback;
  }

private:
  std::shared_ptr<WorkerLogger> logger_;
  std::map<std::string, std::shared_ptr<WorkerInstance>> workers_;
  mutable std::shared_mutex mtx_;

  std::thread checker_thread_;
  std::condition_variable cv_;
  std::atomic<bool> running_{false};

  std::function<void(std::shared_ptr<WorkerInstance>)> on_worker_expired_;
};

// ============================================================================
// ReplicationStreamManager — Manages data replication between workers
// ============================================================================
class ReplicationStreamManager {
public:
  struct StreamPosition {
    ReplicationStreamType stream;
    int64_t position;
    int64_t updated_at_ms;
    int64_t lag_ms;
  };

  struct StreamBatch {
    ReplicationStreamType stream;
    int64_t from_position;
    int64_t to_position;
    std::vector<json> rows;
    int64_t batch_size;
    bool limited;
  };

  ReplicationStreamManager(DatabasePool& db,
      std::shared_ptr<WorkerLogger> logger = nullptr)
    : db_(db), logger_(logger) {}

  // --------------------------------------------------------------------------
  // Initialize replication tables
  // --------------------------------------------------------------------------
  void init_tables(LoggingTransaction& txn) {
    for (const auto& ddl : get_all_ddl()) {
      txn.execute(ddl);
    }
    if (logger_) logger_->info("Replication tables initialized");
  }

  // --------------------------------------------------------------------------
  // Update a worker's replication position for a stream
  // --------------------------------------------------------------------------
  void update_position(const std::string& worker_id,
      ReplicationStreamType stream, int64_t position) {
    std::unique_lock lock(mtx_);
    auto key = std::make_pair(worker_id, stream);
    auto& pos = positions_[key];
    pos.stream = stream;
    pos.position = position;
    pos.updated_at_ms = now_ms();

    // Calculate lag: position behind max
    auto stream_max = max_positions_.find(stream);
    if (stream_max != max_positions_.end()) {
      pos.lag_ms = stream_max->second - position;
    }
  }

  // --------------------------------------------------------------------------
  // Get a worker's position for a stream
  // --------------------------------------------------------------------------
  int64_t get_position(const std::string& worker_id, ReplicationStreamType stream) const {
    std::shared_lock lock(mtx_);
    auto it = positions_.find(std::make_pair(worker_id, stream));
    return (it != positions_.end()) ? it->second.position : 0;
  }

  // --------------------------------------------------------------------------
  // Update the max position for a stream (called by writer/persister)
  // --------------------------------------------------------------------------
  void update_max_position(ReplicationStreamType stream, int64_t max_position) {
    std::unique_lock lock(mtx_);
    max_positions_[stream] = max_position;
  }

  // --------------------------------------------------------------------------
  // Get max position for a stream
  // --------------------------------------------------------------------------
  int64_t get_max_position(ReplicationStreamType stream) const {
    std::shared_lock lock(mtx_);
    auto it = max_positions_.find(stream);
    return (it != max_positions_.end()) ? it->second : 0;
  }

  // --------------------------------------------------------------------------
  // Get all stream positions for a worker
  // --------------------------------------------------------------------------
  std::vector<StreamPosition> get_all_positions(const std::string& worker_id) const {
    std::shared_lock lock(mtx_);
    std::vector<StreamPosition> result;
    for (const auto& [key, pos] : positions_) {
      if (key.first == worker_id) {
        result.push_back(pos);
      }
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Get a batch of data for a stream (for a worker to consume)
  // --------------------------------------------------------------------------
  StreamBatch get_batch(const std::string& worker_id,
      ReplicationStreamType stream, int64_t limit = kMaxReplicationStreamBatchSize) {
    StreamBatch batch;
    batch.stream = stream;
    batch.from_position = get_position(worker_id, stream);
    batch.to_position = get_max_position(stream);

    if (batch.from_position >= batch.to_position) {
      batch.batch_size = 0;
      batch.limited = false;
      return batch;
    }

    int64_t to_pos = std::min(batch.from_position + limit, batch.to_position);

    // In a real implementation, this would query the database
    // For now, we simulate with position tracking
    batch.to_position = to_pos;
    batch.batch_size = to_pos - batch.from_position;
    batch.limited = (to_pos < batch.to_position);

    // Update the worker's position
    update_position(worker_id, stream, to_pos);

    return batch;
  }

  // --------------------------------------------------------------------------
  // Check if a worker has caught up on all subscribed streams
  // --------------------------------------------------------------------------
  bool is_caught_up(const std::string& worker_id,
      const std::vector<ReplicationStreamType>& streams) const {
    std::shared_lock lock(mtx_);
    for (auto stream : streams) {
      auto it = positions_.find(std::make_pair(worker_id, stream));
      int64_t pos = (it != positions_.end()) ? it->second.position : 0;
      auto max_it = max_positions_.find(stream);
      int64_t max_pos = (max_it != max_positions_.end()) ? max_it->second : 0;
      if (pos < max_pos) return false;
    }
    return true;
  }

  // --------------------------------------------------------------------------
  // Get lag for a worker across all streams
  // --------------------------------------------------------------------------
  int64_t total_lag(const std::string& worker_id,
      const std::vector<ReplicationStreamType>& streams) const {
    int64_t total = 0;
    std::shared_lock lock(mtx_);
    for (auto stream : streams) {
      auto it = positions_.find(std::make_pair(worker_id, stream));
      int64_t pos = (it != positions_.end()) ? it->second.position : 0;
      auto max_it = max_positions_.find(stream);
      int64_t max_pos = (max_it != max_positions_.end()) ? max_it->second : 0;
      total += (max_pos - pos);
    }
    return total;
  }

  // --------------------------------------------------------------------------
  // Persist all positions to database
  // --------------------------------------------------------------------------
  void persist_positions(LoggingTransaction& txn) {
    std::shared_lock lock(mtx_);
    for (const auto& [key, pos] : positions_) {
      std::string sql =
        "INSERT OR REPLACE INTO replication_positions "
        "(worker_id, stream_name, position, updated_at, lag_ms) "
        "VALUES (?, ?, ?, ?, ?)";
      txn.execute(sql, {
        SQLParam(key.first),
        SQLParam(std::string(rep_stream_to_string(key.second))),
        SQLParam(pos.position),
        SQLParam(pos.updated_at_ms),
        SQLParam(pos.lag_ms)
      });
    }
  }

  // --------------------------------------------------------------------------
  // Load positions from database
  // --------------------------------------------------------------------------
  void load_positions(LoggingTransaction& txn) {
    std::unique_lock lock(mtx_);
    auto rows = txn.select("SELECT worker_id, stream_name, position, updated_at, lag_ms "
                           "FROM replication_positions");
    for (const auto& row : rows) {
      auto worker_id = row.at("worker_id");
      auto stream_name = row.at("stream_name");
      auto it = std::find(kRepStreamNames.begin(), kRepStreamNames.end(), stream_name);
      if (it == kRepStreamNames.end()) continue;
      auto stream = static_cast<ReplicationStreamType>(
        std::distance(kRepStreamNames.begin(), it));

      StreamPosition pos;
      pos.stream = stream;
      pos.position = std::stoll(row.at("position"));
      pos.updated_at_ms = std::stoll(row.at("updated_at"));
      pos.lag_ms = std::stoll(row.at("lag_ms"));

      positions_[std::make_pair(worker_id, stream)] = pos;
    }
  }

  // --------------------------------------------------------------------------
  // Get metrics
  // --------------------------------------------------------------------------
  json get_metrics() const {
    json j;
    j["stream_count"] = kNumReplicationStreamTypes;

    json positions;
    std::shared_lock lock(mtx_);
    for (size_t i = 0; i < kNumReplicationStreamTypes; ++i) {
      auto st = static_cast<ReplicationStreamType>(i);
      auto it = max_positions_.find(st);
      positions[rep_stream_to_string(st)] = (it != max_positions_.end()) ? it->second : 0;
    }
    j["max_positions"] = positions;

    json lags;
    for (const auto& [key, pos] : positions_) {
      if (pos.lag_ms > 0) {
        lags.push_back({
          {"worker_id", key.first},
          {"stream", rep_stream_to_string(key.second)},
          {"lag", pos.lag_ms}
        });
      }
    }
    j["lagged_workers"] = lags;

    return j;
  }

private:
  DatabasePool& db_;
  std::shared_ptr<WorkerLogger> logger_;

  std::map<std::pair<std::string, ReplicationStreamType>, StreamPosition> positions_;
  std::map<ReplicationStreamType, int64_t> max_positions_;
  mutable std::shared_mutex mtx_;
};

// ============================================================================
// CircuitBreaker — Per-worker failure isolation
// ============================================================================
class CircuitBreaker {
public:
  enum State {
    kClosed,
    kOpen,
    kHalfOpen
  };

  CircuitBreaker(const std::string& worker_id,
      int failure_threshold = kCircuitBreakerFailureThreshold,
      int64_t open_timeout_ms = kCircuitBreakerOpenTimeoutMs,
      int half_open_max = kCircuitBreakerHalfOpenMaxRequests)
    : worker_id_(worker_id)
    , failure_threshold_(failure_threshold)
    , open_timeout_ms_(open_timeout_ms)
    , half_open_max_(half_open_max)
    , state_(kClosed)
    , failure_count_(0)
    , success_count_(0)
    , half_open_requests_(0)
    , last_state_change_ms_(now_ms())
    , total_failures_(0)
    , total_successes_(0)
  {}

  // --------------------------------------------------------------------------
  // Record a successful request
  // --------------------------------------------------------------------------
  void record_success() {
    std::unique_lock lock(mtx_);
    total_successes_++;

    switch (state_) {
      case kClosed:
        failure_count_ = 0;  // Reset failure count on success
        break;
      case kHalfOpen:
        success_count_++;
        if (success_count_ >= half_open_max_) {
          // Transition to closed
          state_ = kClosed;
          failure_count_ = 0;
          last_state_change_ms_ = now_ms();
        }
        break;
      case kOpen:
        break;  // Ignore success when open (shouldn't happen)
    }
  }

  // --------------------------------------------------------------------------
  // Record a failed request
  // --------------------------------------------------------------------------
  void record_failure() {
    std::unique_lock lock(mtx_);
    total_failures_++;
    failure_count_++;

    if (state_ == kClosed && failure_count_ >= failure_threshold_) {
      // Trip the circuit
      state_ = kOpen;
      last_state_change_ms_ = now_ms();
    } else if (state_ == kHalfOpen) {
      // Any failure in half-open trips back to open
      state_ = kOpen;
      last_state_change_ms_ = now_ms();
    }
  }

  // --------------------------------------------------------------------------
  // Check if the circuit allows requests
  // --------------------------------------------------------------------------
  bool allow_request() {
    std::unique_lock lock(mtx_);

    switch (state_) {
      case kClosed:
        return true;

      case kOpen: {
        int64_t elapsed = now_ms() - last_state_change_ms_;
        if (elapsed >= open_timeout_ms_) {
          // Transition to half-open
          state_ = kHalfOpen;
          half_open_requests_ = 0;
          success_count_ = 0;
          last_state_change_ms_ = now_ms();
          return true;
        }
        return false;
      }

      case kHalfOpen:
        if (half_open_requests_ < half_open_max_) {
          half_open_requests_++;
          return true;
        }
        return false;
    }

    return false;
  }

  // --------------------------------------------------------------------------
  // Get current state
  // --------------------------------------------------------------------------
  State state() const {
    std::shared_lock lock(mtx_);
    return state_;
  }

  const char* state_str() const {
    switch (state()) {
      case kClosed:   return "closed";
      case kOpen:     return "open";
      case kHalfOpen: return "half_open";
    }
    return "unknown";
  }

  // --------------------------------------------------------------------------
  // Reset the circuit breaker
  // --------------------------------------------------------------------------
  void reset() {
    std::unique_lock lock(mtx_);
    state_ = kClosed;
    failure_count_ = 0;
    success_count_ = 0;
    half_open_requests_ = 0;
    last_state_change_ms_ = now_ms();
  }

  // --------------------------------------------------------------------------
  // Metrics
  // --------------------------------------------------------------------------
  json to_json() const {
    std::shared_lock lock(mtx_);
    json j;
    j["worker_id"] = worker_id_;
    j["state"] = state_str();
    j["failure_count"] = failure_count_;
    j["success_count"] = success_count_;
    j["total_failures"] = total_failures_;
    j["total_successes"] = total_successes_;
    j["failure_threshold"] = failure_threshold_;
    j["last_state_change_ms"] = last_state_change_ms_;
    j["open_timeout_ms"] = open_timeout_ms_;
    return j;
  }

private:
  std::string worker_id_;
  int failure_threshold_;
  int64_t open_timeout_ms_;
  int half_open_max_;

  State state_;
  int failure_count_;
  int success_count_;
  int half_open_requests_;
  int64_t last_state_change_ms_;

  int64_t total_failures_;
  int64_t total_successes_;

  mutable std::shared_mutex mtx_;
};

// ============================================================================
// LoadBalancer — Intelligent load distribution across workers
// ============================================================================
class LoadBalancer {
public:
  LoadBalancer(const WorkerTypeRegistry& registry,
      std::shared_ptr<WorkerLogger> logger = nullptr)
    : registry_(registry), logger_(logger) {}

  // --------------------------------------------------------------------------
  // Select a worker using the configured strategy
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> select_worker(
      const std::vector<std::shared_ptr<WorkerInstance>>& candidates,
      LoadBalanceStrategy strategy = LoadBalanceStrategy::kAdaptive,
      const std::string& affinity_key = "") {
    if (candidates.empty()) return nullptr;

    // Filter: only workers that can accept work
    std::vector<std::shared_ptr<WorkerInstance>> available;
    for (const auto& w : candidates) {
      if (w->can_accept_work()) {
        available.push_back(w);
      }
    }
    if (available.empty()) return nullptr;

    switch (strategy) {
      case LoadBalanceStrategy::kRoundRobin:
        return select_round_robin(available);

      case LoadBalanceStrategy::kLeastConnections:
        return select_least_connections(available);

      case LoadBalanceStrategy::kWeighted:
        return select_weighted(available);

      case LoadBalanceStrategy::kConsistentHash:
        return select_consistent_hash(available, affinity_key);

      case LoadBalanceStrategy::kAdaptive:
        return select_adaptive(available);

      case LoadBalanceStrategy::kRandom:
        return select_random(available);

      case LoadBalanceStrategy::kFastestResponse:
        return select_fastest_response(available);

      case LoadBalanceStrategy::kResourceAware:
        return select_resource_aware(available);
    }

    return available[0];
  }

  // --------------------------------------------------------------------------
  // Select a worker by type
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> select_by_type(
      const std::map<std::string, std::shared_ptr<WorkerInstance>>& workers,
      WorkerType wt, const std::string& affinity_key = "") {
    std::vector<std::shared_ptr<WorkerInstance>> candidates;
    for (const auto& [id, w] : workers) {
      if (w->type() == wt) {
        candidates.push_back(w);
      }
    }
    return select_worker(candidates, LoadBalanceStrategy::kAdaptive, affinity_key);
  }

private:
  // --------------------------------------------------------------------------
  // Round-robin selection
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> select_round_robin(
      const std::vector<std::shared_ptr<WorkerInstance>>& available) {
    std::unique_lock lock(rr_mtx_);
    if (rr_index_ >= available.size()) rr_index_ = 0;
    return available[rr_index_++];
  }

  // --------------------------------------------------------------------------
  // Least connections selection
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> select_least_connections(
      const std::vector<std::shared_ptr<WorkerInstance>>& available) {
    std::shared_ptr<WorkerInstance> best = available[0];
    int min_conns = best->active_connections();

    for (size_t i = 1; i < available.size(); ++i) {
      int conns = available[i]->active_connections();
      if (conns < min_conns) {
        min_conns = conns;
        best = available[i];
      }
    }
    return best;
  }

  // --------------------------------------------------------------------------
  // Weighted selection
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> select_weighted(
      const std::vector<std::shared_ptr<WorkerInstance>>& available) {
    double total_weight = 0.0;
    for (const auto& w : available) {
      total_weight += w->config().weight;
    }

    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_real_distribution<double> dis(0.0, total_weight);

    double r = dis(gen);
    double cumulative = 0.0;
    for (const auto& w : available) {
      cumulative += w->config().weight;
      if (r <= cumulative) return w;
    }
    return available.back();
  }

  // --------------------------------------------------------------------------
  // Consistent hash selection
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> select_consistent_hash(
      const std::vector<std::shared_ptr<WorkerInstance>>& available,
      const std::string& affinity_key) {
    if (affinity_key.empty()) {
      return select_adaptive(available);
    }

    std::unique_lock lock(hash_mtx_);

    // Rebuild ring if workers changed
    rebuild_consistent_hash_ring(available);

    uint64_t key_hash = hash_string(affinity_key);

    // Find first node with hash >= key_hash (wrap around)
    auto it = hash_ring_.lower_bound(key_hash);
    if (it == hash_ring_.end()) {
      it = hash_ring_.begin();
    }

    if (it != hash_ring_.end()) {
      return it->second;
    }
    return available[0];
  }

  void rebuild_consistent_hash_ring(
      const std::vector<std::shared_ptr<WorkerInstance>>& available) {
    // Check if ring needs rebuild
    size_t expected_size = available.size() * kConsistentHashVirtualNodes;
    if (hash_ring_.size() == expected_size) {
      // Quick check: is the ring still valid?
      bool valid = true;
      for (const auto& w : available) {
        if (!hash_ring_valid_ids_.count(w->worker_id())) {
          valid = false;
          break;
        }
      }
      if (valid) return;
    }

    // Rebuild
    hash_ring_.clear();
    hash_ring_valid_ids_.clear();

    for (const auto& w : available) {
      hash_ring_valid_ids_.insert(w->worker_id());
      for (size_t i = 0; i < kConsistentHashVirtualNodes; ++i) {
        std::string vnode_key = w->worker_id() + ":" + std::to_string(i);
        uint64_t hash = hash_string(vnode_key);
        hash_ring_[hash] = w;
      }
    }
  }

  // --------------------------------------------------------------------------
  // Adaptive selection (considers load, error rate, response time)
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> select_adaptive(
      const std::vector<std::shared_ptr<WorkerInstance>>& available) {
    std::shared_ptr<WorkerInstance> best = nullptr;
    double best_score = std::numeric_limits<double>::max();

    for (const auto& w : available) {
      // Composite score: lower is better
      double load = w->load_score();             // 0-100
      double error = w->error_rate() * 100.0;    // 0-100
      double p95_ms = w->p95_response_time_us() / 1000.0;  // ms
      double conn_ratio = w->active_connections() > 0
        ? static_cast<double>(w->active_connections())
          / std::max(static_cast<size_t>(1), w->config().max_connections) * 100.0
        : 0.0;

      double score = load * 0.4 + error * 0.3 + conn_ratio * 0.2
                   + std::min(100.0, p95_ms / 10.0) * 0.1;

      if (score < best_score) {
        best_score = score;
        best = w;
      }
    }
    return best;
  }

  // --------------------------------------------------------------------------
  // Random selection
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> select_random(
      const std::vector<std::shared_ptr<WorkerInstance>>& available) {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<size_t> dis(0, available.size() - 1);
    return available[dis(gen)];
  }

  // --------------------------------------------------------------------------
  // Fastest response selection
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> select_fastest_response(
      const std::vector<std::shared_ptr<WorkerInstance>>& available) {
    std::shared_ptr<WorkerInstance> best = available[0];
    int64_t best_p95 = best->p95_response_time_us();

    for (size_t i = 1; i < available.size(); ++i) {
      int64_t p95 = available[i]->p95_response_time_us();
      if (p95 < best_p95) {
        best_p95 = p95;
        best = available[i];
      }
    }
    return best;
  }

  // --------------------------------------------------------------------------
  // Resource-aware selection
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> select_resource_aware(
      const std::vector<std::shared_ptr<WorkerInstance>>& available) {
    std::shared_ptr<WorkerInstance> best = nullptr;
    double best_available = -1.0;

    for (const auto& w : available) {
      double cpu_avail = 1.0 - (w->cpu_avg() / 100.0);
      double mem_avail = 1.0 - (w->memory_avg_mb()
        / std::max(1.0, static_cast<double>(w->config().max_memory_mb)));
      double conn_avail = 1.0 - (w->active_connections()
        / std::max(1.0, static_cast<double>(w->config().max_connections)));

      double availability = cpu_avail * 0.5 + mem_avail * 0.3 + conn_avail * 0.2;

      if (availability > best_available) {
        best_available = availability;
        best = w;
      }
    }
    return best;
  }

  const WorkerTypeRegistry& registry_;
  std::shared_ptr<WorkerLogger> logger_;

  size_t rr_index_ = 0;
  std::mutex rr_mtx_;

  std::map<uint64_t, std::shared_ptr<WorkerInstance>> hash_ring_;
  std::set<std::string> hash_ring_valid_ids_;
  std::mutex hash_mtx_;
};

// ============================================================================
// WorkStealingEngine — Cross-worker work redistribution
// ============================================================================
class WorkStealingEngine {
public:
  WorkStealingEngine(std::shared_ptr<WorkerLogger> logger = nullptr)
    : logger_(logger), running_(false) {}

  // --------------------------------------------------------------------------
  // Find the most overloaded and most idle workers of a type
  // --------------------------------------------------------------------------
  struct StealCandidate {
    std::shared_ptr<WorkerInstance> victim;
    std::shared_ptr<WorkerInstance> thief;
    int queue_diff;
  };

  std::vector<StealCandidate> find_steal_opportunities(
      const std::vector<std::shared_ptr<WorkerInstance>>& workers) {
    std::vector<StealCandidate> opportunities;

    // Group by type
    std::map<WorkerType, std::vector<std::shared_ptr<WorkerInstance>>> by_type;
    for (const auto& w : workers) {
      if (w->is_healthy()) {
        by_type[w->type()].push_back(w);
      }
    }

    for (auto& [wt, group] : by_type) {
      if (group.size() < 2) continue;

      auto victim = std::max_element(group.begin(), group.end(),
        [](const auto& a, const auto& b) {
          return a->queue_depth() < b->queue_depth();
        });
      auto thief = std::min_element(group.begin(), group.end(),
        [](const auto& a, const auto& b) {
          return a->queue_depth() < b->queue_depth();
        });

      int diff = (*victim)->queue_depth() - (*thief)->queue_depth();
      if (diff > 100) {  // Only steal if significant imbalance
        opportunities.push_back({*victim, *thief, diff});
      }
    }

    return opportunities;
  }

  // --------------------------------------------------------------------------
  // Execute work stealing
  // --------------------------------------------------------------------------
  json execute_steal(const StealCandidate& candidate) {
    // In a real implementation, this would move queued tasks between workers
    int steal_amount = std::min(candidate.queue_diff / 2, 500);
    json result;
    result["victim_id"] = candidate.victim->worker_id();
    result["thief_id"] = candidate.thief->worker_id();
    result["stolen_count"] = steal_amount;
    result["victim_queue_before"] = candidate.victim->queue_depth();
    result["thief_queue_before"] = candidate.thief->queue_depth();

    if (logger_) {
      logger_->info("Work steal: " + std::to_string(steal_amount)
        + " items from " + candidate.victim->worker_name()
        + " to " + candidate.thief->worker_name());
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Start background work stealer
  // --------------------------------------------------------------------------
  void start(std::function<std::vector<std::shared_ptr<WorkerInstance>>()> worker_provider,
      int64_t interval_ms = 10000) {
    if (running_) return;
    running_ = true;
    worker_provider_ = worker_provider;
    stealer_thread_ = std::thread([this, interval_ms]() {
      while (running_) {
        std::this_thread::sleep_for(chr::milliseconds(interval_ms));
        if (!running_) break;
        if (!worker_provider_) continue;
        auto workers = worker_provider_();
        auto opps = find_steal_opportunities(workers);
        for (auto& opp : opps) {
          execute_steal(opp);
        }
      }
    });
  }

  void stop() {
    running_ = false;
    if (stealer_thread_.joinable()) stealer_thread_.join();
  }

private:
  std::shared_ptr<WorkerLogger> logger_;
  std::atomic<bool> running_{false};
  std::thread stealer_thread_;
  std::function<std::vector<std::shared_ptr<WorkerInstance>>()> worker_provider_;
};

// ============================================================================
// WorkerPoolManager — Dynamic worker pool scaling and management
// ============================================================================
class WorkerPoolManager {
public:
  WorkerPoolManager(const WorkerTypeRegistry& registry,
      std::shared_ptr<WorkerHeartbeatEngine> heartbeat,
      std::shared_ptr<WorkerLogger> logger = nullptr)
    : registry_(registry), heartbeat_(heartbeat), logger_(logger) {}

  // --------------------------------------------------------------------------
  // Add a worker to the pool
  // --------------------------------------------------------------------------
  void register_worker(std::shared_ptr<WorkerInstance> worker) {
    std::unique_lock lock(mtx_);
    all_workers_[worker->worker_id()] = worker;
    by_type_[worker->type()].push_back(worker);
    heartbeat_->register_worker(worker);
    if (logger_) {
      logger_->info("Pool registered worker: " + worker->worker_name()
        + " type=" + std::string(worker_type_to_string(worker->type())));
    }
  }

  // --------------------------------------------------------------------------
  // Remove a worker from the pool
  // --------------------------------------------------------------------------
  void unregister_worker(const std::string& worker_id) {
    std::unique_lock lock(mtx_);
    auto it = all_workers_.find(worker_id);
    if (it == all_workers_.end()) return;

    auto& worker = it->second;
    auto type = worker->type();

    // Remove from by_type
    auto& vec = by_type_[type];
    vec.erase(std::remove(vec.begin(), vec.end(), worker), vec.end());

    // Remove from all
    all_workers_.erase(it);
    heartbeat_->unregister_worker(worker_id);

    if (logger_) {
      logger_->info("Pool unregistered worker: " + worker->worker_name());
    }
  }

  // --------------------------------------------------------------------------
  // Get workers by type
  // --------------------------------------------------------------------------
  std::vector<std::shared_ptr<WorkerInstance>> get_by_type(WorkerType wt) const {
    std::shared_lock lock(mtx_);
    auto it = by_type_.find(wt);
    return (it != by_type_.end()) ? it->second : std::vector<std::shared_ptr<WorkerInstance>>{};
  }

  // --------------------------------------------------------------------------
  // Get all workers
  // --------------------------------------------------------------------------
  std::vector<std::shared_ptr<WorkerInstance>> all() const {
    std::shared_lock lock(mtx_);
    std::vector<std::shared_ptr<WorkerInstance>> result;
    result.reserve(all_workers_.size());
    for (const auto& [id, w] : all_workers_) result.push_back(w);
    return result;
  }

  // --------------------------------------------------------------------------
  // Get a specific worker
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> get(const std::string& worker_id) const {
    std::shared_lock lock(mtx_);
    auto it = all_workers_.find(worker_id);
    return (it != all_workers_.end()) ? it->second : nullptr;
  }

  // --------------------------------------------------------------------------
  // Count workers by type
  // --------------------------------------------------------------------------
  size_t count_by_type(WorkerType wt) const {
    std::shared_lock lock(mtx_);
    auto it = by_type_.find(wt);
    return (it != by_type_.end()) ? it->second.size() : 0;
  }

  // --------------------------------------------------------------------------
  // Count active workers by type
  // --------------------------------------------------------------------------
  size_t count_active_by_type(WorkerType wt) const {
    std::shared_lock lock(mtx_);
    auto it = by_type_.find(wt);
    if (it == by_type_.end()) return 0;
    size_t count = 0;
    for (const auto& w : it->second) {
      if (w->is_active()) count++;
    }
    return count;
  }

  // --------------------------------------------------------------------------
  // Get pool metrics
  // --------------------------------------------------------------------------
  json pool_metrics() const {
    json j;
    std::shared_lock lock(mtx_);
    for (const auto& [wt, workers] : by_type_) {
      json type_info;
      type_info["type"] = worker_type_to_string(wt);
      type_info["total"] = workers.size();

      size_t active = 0, running = 0, degraded = 0;
      double avg_load = 0.0;
      int total_connections = 0;
      int total_queue = 0;

      for (const auto& w : workers) {
        if (w->is_active()) active++;
        if (w->status() == WorkerStatus::kRunning) running++;
        if (w->status() == WorkerStatus::kDegraded) degraded++;
        avg_load += w->load_score();
        total_connections += w->active_connections();
        total_queue += w->queue_depth();
      }

      type_info["active"] = active;
      type_info["running"] = running;
      type_info["degraded"] = degraded;
      type_info["avg_load_score"] = workers.empty() ? 0.0 : avg_load / workers.size();
      type_info["total_connections"] = total_connections;
      type_info["total_queue_depth"] = total_queue;

      j[worker_type_to_string(wt)] = type_info;
    }

    j["total_workers"] = all_workers_.size();
    return j;
  }

  // --------------------------------------------------------------------------
  // Get all worker IDs for a type
  // --------------------------------------------------------------------------
  std::vector<std::string> worker_ids_by_type(WorkerType wt) const {
    std::shared_lock lock(mtx_);
    std::vector<std::string> ids;
    auto it = by_type_.find(wt);
    if (it != by_type_.end()) {
      for (const auto& w : it->second) {
        ids.push_back(w->worker_id());
      }
    }
    return ids;
  }

private:
  const WorkerTypeRegistry& registry_;
  std::shared_ptr<WorkerHeartbeatEngine> heartbeat_;
  std::shared_ptr<WorkerLogger> logger_;

  std::map<std::string, std::shared_ptr<WorkerInstance>> all_workers_;
  std::map<WorkerType, std::vector<std::shared_ptr<WorkerInstance>>> by_type_;
  mutable std::shared_mutex mtx_;
};

// ============================================================================
// WorkerRegistrationService — Registration/discovery lifecycle management
// ============================================================================
class WorkerRegistrationService {
public:
  WorkerRegistrationService(DatabasePool& db,
      const WorkerTypeRegistry& registry,
      std::shared_ptr<WorkerPoolManager> pool,
      std::shared_ptr<WorkerHeartbeatEngine> heartbeat,
      std::shared_ptr<WorkerLogger> logger = nullptr)
    : db_(db), registry_(registry), pool_(pool), heartbeat_(heartbeat),
      logger_(logger) {}

  // --------------------------------------------------------------------------
  // Register a new worker
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> register_worker(
      const WorkerConfig& config, LoggingTransaction& txn) {

    // Persist to database
    std::string sql = R"SQL(
      INSERT INTO worker_registry
        (worker_id, worker_type, worker_name, instance_id, hostname, pid,
         status, capabilities, listen_address, listen_port, tags, metadata,
         registered_at, last_heartbeat, last_status_change, restart_count,
         version, config_hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    )SQL";

    json tags_json(config.tags);
    txn.execute(sql, {
      SQLParam(config.worker_id),
      SQLParam(std::string(worker_type_to_string(config.type))),
      SQLParam(config.worker_name),
      SQLParam(config.instance_id),
      SQLParam(config.hostname),
      SQLParam(static_cast<int64_t>(config.pid)),
      SQLParam(std::string("starting")),
      SQLParam(static_cast<int64_t>(worker_type_capabilities(config.type))),
      SQLParam(config.listen_address),
      SQLParam(static_cast<int64_t>(config.listen_port)),
      SQLParam(tags_json.dump()),
      SQLParam(config.metadata.dump()),
      SQLParam(now_ms()),
      SQLParam(now_ms()),
      SQLParam(now_ms()),
      SQLParam(static_cast<int64_t>(0)),
      SQLParam(config.version),
      SQLParam(config.config_hash)
    });

    // Create runtime instance
    auto instance = std::make_shared<WorkerInstance>(config);
    instance->set_status(WorkerStatus::kStarting);

    // Register with pool and heartbeat
    pool_->register_worker(instance);

    if (logger_) {
      logger_->info("Registered worker: " + config.worker_name
        + " (" + config.worker_id + ") type=" + worker_type_to_string(config.type));
    }

    return instance;
  }

  // --------------------------------------------------------------------------
  // Create a worker by type with defaults
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> create_worker(
      WorkerType wt, const std::string& instance_id,
      LoggingTransaction& txn, const json& overrides = json{}) {

    WorkerConfig config = WorkerConfig::for_type(wt, registry_);
    config.instance_id = instance_id;

    // Apply overrides
    if (overrides.contains("worker_name")) config.worker_name = overrides["worker_name"];
    if (overrides.contains("hostname")) config.hostname = overrides["hostname"];
    if (overrides.contains("listen_address")) config.listen_address = overrides["listen_address"];
    if (overrides.contains("listen_port")) config.listen_port = overrides["listen_port"];
    if (overrides.contains("tags")) config.tags = overrides["tags"].get<std::vector<std::string>>();
    if (overrides.contains("metadata")) config.metadata = overrides["metadata"];
    if (overrides.contains("weight")) config.weight = overrides["weight"];
    if (overrides.contains("max_connections")) config.max_connections = overrides["max_connections"];

    return register_worker(config, txn);
  }

  // --------------------------------------------------------------------------
  // Start a worker (mark as running)
  // --------------------------------------------------------------------------
  void start_worker(const std::string& worker_id) {
    auto worker = pool_->get(worker_id);
    if (!worker) {
      if (logger_) logger_->error("Cannot start unknown worker: " + worker_id);
      return;
    }
    worker->set_status(WorkerStatus::kRunning);
    worker->record_heartbeat();

    if (logger_) logger_->info("Worker started: " + worker->worker_name());
  }

  // --------------------------------------------------------------------------
  // Drain a worker (graceful shutdown)
  // --------------------------------------------------------------------------
  json drain_worker(const std::string& worker_id) {
    auto worker = pool_->get(worker_id);
    if (!worker) {
      return json{{"error", "worker not found"}, {"worker_id", worker_id}};
    }

    worker->set_status(WorkerStatus::kDraining);
    if (logger_) logger_->info("Draining worker: " + worker->worker_name());

    json result;
    result["worker_id"] = worker_id;
    result["status"] = "draining";
    result["drain_started_ms"] = now_ms();
    result["drain_timeout_ms"] = worker->config().drain_timeout_ms;
    return result;
  }

  // --------------------------------------------------------------------------
  // Stop a worker immediately
  // --------------------------------------------------------------------------
  void stop_worker(const std::string& worker_id) {
    auto worker = pool_->get(worker_id);
    if (!worker) return;
    worker->set_status(WorkerStatus::kStopping);
    worker->set_status(WorkerStatus::kStopped);
    if (logger_) logger_->info("Worker stopped: " + worker->worker_name());
  }

  // --------------------------------------------------------------------------
  // Restart a worker
  // --------------------------------------------------------------------------
  json restart_worker(const std::string& worker_id) {
    auto worker = pool_->get(worker_id);
    if (!worker) {
      return json{{"error", "worker not found"}, {"worker_id", worker_id}};
    }

    int attempts = worker->restart_count();
    if (attempts >= worker->config().max_restart_attempts) {
      return json{
        {"error", "max restart attempts exceeded"},
        {"worker_id", worker_id},
        {"attempts", attempts}
      };
    }

    worker->set_status(WorkerStatus::kRestarting);
    int next_attempt = worker->increment_restart();
    int64_t backoff = compute_backoff_ms(next_attempt,
      worker->config().restart_backoff_base_ms, kRestartBackoffMaxMs);

    if (logger_) {
      logger_->info("Restarting worker: " + worker->worker_name()
        + " (attempt " + std::to_string(next_attempt)
        + ", backoff " + std::to_string(backoff) + "ms)");
    }

    json result;
    result["worker_id"] = worker_id;
    result["status"] = "restarting";
    result["attempt"] = next_attempt;
    result["backoff_ms"] = backoff;
    return result;
  }

  // --------------------------------------------------------------------------
  // De-register a worker
  // --------------------------------------------------------------------------
  void deregister_worker(const std::string& worker_id, LoggingTransaction& txn) {
    txn.execute("DELETE FROM worker_registry WHERE worker_id = ?",
      {SQLParam(worker_id)});
    txn.execute("DELETE FROM replication_positions WHERE worker_id = ?",
      {SQLParam(worker_id)});
    pool_->unregister_worker(worker_id);
    if (logger_) logger_->info("Deregistered worker: " + worker_id);
  }

  // --------------------------------------------------------------------------
  // Load all workers from database on startup
  // --------------------------------------------------------------------------
  void load_from_database(LoggingTransaction& txn) {
    auto rows = txn.select(
      "SELECT worker_id, worker_type, worker_name, instance_id, hostname, pid, "
      "status, capabilities, listen_address, listen_port, tags, metadata, "
      "registered_at, last_heartbeat, last_status_change, restart_count, "
      "version, config_hash FROM worker_registry");

    for (const auto& row : rows) {
      WorkerConfig config;
      config.worker_id = row.at("worker_id");
      config.worker_name = row.at("worker_name");
      config.instance_id = row.at("instance_id");
      config.type = string_to_worker_type(row.at("worker_type"));
      config.hostname = row.at("hostname");
      config.pid = std::stoll(row.at("pid"));
      config.listen_address = row.at("listen_address");
      config.listen_port = std::stoi(row.at("listen_port"));
      config.version = row.at("version");
      config.config_hash = row.at("config_hash");

      if (!row.at("tags").empty()) {
        config.tags = json::parse(row.at("tags")).get<std::vector<std::string>>();
      }
      if (!row.at("metadata").empty()) {
        config.metadata = json::parse(row.at("metadata"));
      }

      auto instance = std::make_shared<WorkerInstance>(config);
      WorkerStatus status = string_to_worker_status(row.at("status"));

      // On restart, previously running workers are orphaned until re-registered
      if (status == WorkerStatus::kRunning || status == WorkerStatus::kStarting) {
        status = WorkerStatus::kOrphaned;
      }
      instance->set_status(status);

      pool_->register_worker(instance);
    }

    if (logger_) {
      logger_->info("Loaded " + std::to_string(rows.size())
        + " workers from database");
    }
  }

  // --------------------------------------------------------------------------
  // Persist all workers to database
  // --------------------------------------------------------------------------
  void persist_all(LoggingTransaction& txn) {
    auto workers = pool_->all();
    for (const auto& w : workers) {
      txn.execute(
        "UPDATE worker_registry SET status = ?, last_heartbeat = ?, "
        "last_status_change = ?, restart_count = ? WHERE worker_id = ?",
        {
          SQLParam(std::string(worker_status_to_string(w->status()))),
          SQLParam(w->last_heartbeat_ms()),
          SQLParam(w->status_change_ms()),
          SQLParam(static_cast<int64_t>(w->restart_count())),
          SQLParam(w->worker_id())
        });
    }
  }

private:
  DatabasePool& db_;
  const WorkerTypeRegistry& registry_;
  std::shared_ptr<WorkerPoolManager> pool_;
  std::shared_ptr<WorkerHeartbeatEngine> heartbeat_;
  std::shared_ptr<WorkerLogger> logger_;
};

// ============================================================================
// WorkerMetricsCollector — Metrics aggregation and Prometheus export
// ============================================================================
class WorkerMetricsCollector {
public:
  WorkerMetricsCollector(std::shared_ptr<WorkerPoolManager> pool,
      std::shared_ptr<WorkerLogger> logger = nullptr)
    : pool_(pool), logger_(logger), running_(false) {}

  // --------------------------------------------------------------------------
  // Collect current metrics snapshot
  // --------------------------------------------------------------------------
  json collect() const {
    json j;
    auto workers = pool_->all();

    // Aggregate by type
    std::map<WorkerType, json> by_type;
    for (const auto& w : workers) {
      auto wt = w->type();
      if (!by_type.count(wt)) {
        by_type[wt] = json{
          {"type", worker_type_to_string(wt)},
          {"total", 0},
          {"active", 0},
          {"running", 0},
          {"draining", 0},
          {"failed", 0},
          {"orphaned", 0},
          {"stopped", 0},
          {"degraded", 0},
          {"avg_load_score", 0.0},
          {"max_load_score", 0.0},
          {"total_connections", 0},
          {"total_queue_depth", 0},
          {"total_errors", 0},
          {"avg_error_rate", 0.0},
          {"total_requests", 0},
          {"avg_p95_us", 0},
          {"avg_request_rate", 0.0}
        };
      }

      auto& info = by_type[wt];
      info["total"] = info["total"].get<int>() + 1;
      if (w->is_active()) info["active"] = info["active"].get<int>() + 1;

      switch (w->status()) {
        case WorkerStatus::kRunning:   info["running"] = info["running"].get<int>() + 1; break;
        case WorkerStatus::kDraining:  info["draining"] = info["draining"].get<int>() + 1; break;
        case WorkerStatus::kFailed:    info["failed"] = info["failed"].get<int>() + 1; break;
        case WorkerStatus::kOrphaned:  info["orphaned"] = info["orphaned"].get<int>() + 1; break;
        case WorkerStatus::kStopped:   info["stopped"] = info["stopped"].get<int>() + 1; break;
        case WorkerStatus::kDegraded:  info["degraded"] = info["degraded"].get<int>() + 1; break;
        default: break;
      }

      info["avg_load_score"] = info["avg_load_score"].get<double>() + w->load_score();
      info["max_load_score"] = std::max(info["max_load_score"].get<double>(), w->load_score());
      info["total_connections"] = info["total_connections"].get<int>() + w->active_connections();
      info["total_queue_depth"] = info["total_queue_depth"].get<int>() + w->queue_depth();
      info["total_errors"] = info["total_errors"].get<int>() + w->error_count();
      info["avg_error_rate"] = info["avg_error_rate"].get<double>() + w->error_rate();
      info["avg_p95_us"] = info["avg_p95_us"].get<int64_t>() + w->p95_response_time_us();
      info["avg_request_rate"] = info["avg_request_rate"].get<double>() + w->request_rate_per_sec();
    }

    // Average the averaged metrics
    for (auto& [wt, info] : by_type) {
      int total = info["total"].get<int>();
      if (total > 0) {
        info["avg_load_score"] = info["avg_load_score"].get<double>() / total;
        info["avg_error_rate"] = info["avg_error_rate"].get<double>() / total;
        info["avg_p95_us"] = info["avg_p95_us"].get<int64_t>() / total;
        info["avg_request_rate"] = info["avg_request_rate"].get<double>() / total;
      }
    }

    j["by_type"] = by_type;
    j["total_workers"] = workers.size();
    j["collected_at_ms"] = now_ms();

    return j;
  }

  // --------------------------------------------------------------------------
  // Generate Prometheus-format metrics
  // --------------------------------------------------------------------------
  std::string prometheus_metrics() const {
    std::ostringstream out;
    auto metrics = collect();
    int64_t ts = now_ms();

    // Overall worker counts
    out << "# HELP progressive_workers_total Total number of workers\n";
    out << "# TYPE progressive_workers_total gauge\n";
    out << "progressive_workers_total " << metrics["total_workers"].get<int>() << " " << ts << "\n\n";

    // Per-type metrics
    out << "# HELP progressive_workers_by_type Number of workers per type\n";
    out << "# TYPE progressive_workers_by_type gauge\n";
    for (const auto& [wt_str, info] : metrics["by_type"].items()) {
      out << "progressive_workers_by_type{type=\"" << wt_str << "\"} "
          << info["total"].get<int>() << " " << ts << "\n";
    }
    out << "\n";

    out << "# HELP progressive_workers_active Active workers per type\n";
    out << "# TYPE progressive_workers_active gauge\n";
    for (const auto& [wt_str, info] : metrics["by_type"].items()) {
      out << "progressive_workers_active{type=\"" << wt_str << "\"} "
          << info["active"].get<int>() << " " << ts << "\n";
    }
    out << "\n";

    out << "# HELP progressive_workers_failed Failed workers per type\n";
    out << "# TYPE progressive_workers_failed gauge\n";
    for (const auto& [wt_str, info] : metrics["by_type"].items()) {
      out << "progressive_workers_failed{type=\"" << wt_str << "\"} "
          << info["failed"].get<int>() << " " << ts << "\n";
    }
    out << "\n";

    out << "# HELP progressive_workers_orphaned Orphaned workers per type\n";
    out << "# TYPE progressive_workers_orphaned gauge\n";
    for (const auto& [wt_str, info] : metrics["by_type"].items()) {
      out << "progressive_workers_orphaned{type=\"" << wt_str << "\"} "
          << info["orphaned"].get<int>() << " " << ts << "\n";
    }
    out << "\n";

    out << "# HELP progressive_worker_load_score Average load score per type\n";
    out << "# TYPE progressive_worker_load_score gauge\n";
    for (const auto& [wt_str, info] : metrics["by_type"].items()) {
      out << "progressive_worker_load_score{type=\"" << wt_str << "\"} "
          << std::fixed << std::setprecision(2)
          << info["avg_load_score"].get<double>() << " " << ts << "\n";
    }
    out << "\n";

    out << "# HELP progressive_worker_connections Total connections per type\n";
    out << "# TYPE progressive_worker_connections gauge\n";
    for (const auto& [wt_str, info] : metrics["by_type"].items()) {
      out << "progressive_worker_connections{type=\"" << wt_str << "\"} "
          << info["total_connections"].get<int>() << " " << ts << "\n";
    }
    out << "\n";

    out << "# HELP progressive_worker_queue_depth Total queue depth per type\n";
    out << "# TYPE progressive_worker_queue_depth gauge\n";
    for (const auto& [wt_str, info] : metrics["by_type"].items()) {
      out << "progressive_worker_queue_depth{type=\"" << wt_str << "\"} "
          << info["total_queue_depth"].get<int>() << " " << ts << "\n";
    }
    out << "\n";

    out << "# HELP progressive_worker_error_rate Average error rate per type\n";
    out << "# TYPE progressive_worker_error_rate gauge\n";
    for (const auto& [wt_str, info] : metrics["by_type"].items()) {
      out << "progressive_worker_error_rate{type=\"" << wt_str << "\"} "
          << std::fixed << std::setprecision(4)
          << info["avg_error_rate"].get<double>() << " " << ts << "\n";
    }
    out << "\n";

    out << "# HELP progressive_worker_p95_response_us P95 response time per type (microseconds)\n";
    out << "# TYPE progressive_worker_p95_response_us gauge\n";
    for (const auto& [wt_str, info] : metrics["by_type"].items()) {
      out << "progressive_worker_p95_response_us{type=\"" << wt_str << "\"} "
          << info["avg_p95_us"].get<int64_t>() << " " << ts << "\n";
    }
    out << "\n";

    out << "# HELP progressive_worker_request_rate Request rate per type\n";
    out << "# TYPE progressive_worker_request_rate gauge\n";
    for (const auto& [wt_str, info] : metrics["by_type"].items()) {
      out << "progressive_worker_request_rate{type=\"" << wt_str << "\"} "
          << std::fixed << std::setprecision(2)
          << info["avg_request_rate"].get<double>() << " " << ts << "\n";
    }
    out << "\n";

    return out.str();
  }

  // --------------------------------------------------------------------------
  // Start background metrics collection
  // --------------------------------------------------------------------------
  void start(int64_t interval_ms = kMetricsReportIntervalMs) {
    if (running_) return;
    running_ = true;
    metrics_thread_ = std::thread([this, interval_ms]() {
      while (running_) {
        std::this_thread::sleep_for(chr::milliseconds(interval_ms));
        if (!running_) break;
        auto snapshot = collect();
        {
          std::unique_lock lock(cache_mtx_);
          cached_metrics_ = snapshot;
        }
      }
    });
  }

  void stop() {
    running_ = false;
    if (metrics_thread_.joinable()) metrics_thread_.join();
  }

  // --------------------------------------------------------------------------
  // Get cached metrics
  // --------------------------------------------------------------------------
  json get_cached() const {
    std::shared_lock lock(cache_mtx_);
    return cached_metrics_;
  }

private:
  std::shared_ptr<WorkerPoolManager> pool_;
  std::shared_ptr<WorkerLogger> logger_;
  std::atomic<bool> running_{false};
  std::thread metrics_thread_;
  json cached_metrics_;
  mutable std::shared_mutex cache_mtx_;
};

// ============================================================================
// WorkerAdminAPI — Admin endpoints for worker management
// ============================================================================
class WorkerAdminAPI {
public:
  WorkerAdminAPI(std::shared_ptr<WorkerPoolManager> pool,
      std::shared_ptr<WorkerRegistrationService> registration,
      std::shared_ptr<WorkerHeartbeatEngine> heartbeat,
      std::shared_ptr<ReplicationStreamManager> replication,
      std::shared_ptr<WorkerMetricsCollector> metrics,
      std::shared_ptr<LoadBalancer> load_balancer,
      std::shared_ptr<WorkerLogger> logger = nullptr)
    : pool_(pool), registration_(registration), heartbeat_(heartbeat),
      replication_(replication), metrics_(metrics), load_balancer_(load_balancer),
      logger_(logger) {}

  // --------------------------------------------------------------------------
  // GET /_progressive/workers — List all workers
  // --------------------------------------------------------------------------
  json list_workers(const std::string& type_filter = "",
      const std::string& status_filter = "") const {
    json result;
    json workers_json = json::array();

    auto workers = pool_->all();
    for (const auto& w : workers) {
      if (!type_filter.empty()
          && worker_type_to_string(w->type()) != type_filter) continue;
      if (!status_filter.empty()
          && worker_status_to_string(w->status()) != status_filter) continue;
      workers_json.push_back(w->to_json());
    }

    result["workers"] = workers_json;
    result["total"] = workers_json.size();
    result["timestamp_ms"] = now_ms();
    return result;
  }

  // --------------------------------------------------------------------------
  // GET /_progressive/workers/:worker_id — Get worker details
  // --------------------------------------------------------------------------
  json get_worker(const std::string& worker_id) const {
    auto worker = pool_->get(worker_id);
    if (!worker) {
      return json{{"error", "worker not found"}, {"worker_id", worker_id}};
    }
    json j = worker->to_json();
    j["config"] = worker->config().to_json();
    return j;
  }

  // --------------------------------------------------------------------------
  // GET /_progressive/workers/pools — Pool overview
  // --------------------------------------------------------------------------
  json pool_overview() const {
    return pool_->pool_metrics();
  }

  // --------------------------------------------------------------------------
  // GET /_progressive/workers/metrics — Metrics snapshot
  // --------------------------------------------------------------------------
  json metrics_snapshot() const {
    return metrics_->get_cached();
  }

  // --------------------------------------------------------------------------
  // GET /_progressive/workers/replication — Replication status
  // --------------------------------------------------------------------------
  json replication_status() const {
    return replication_->get_metrics();
  }

  // --------------------------------------------------------------------------
  // POST /_progressive/workers/:worker_id/drain — Drain a worker
  // --------------------------------------------------------------------------
  json drain_worker(const std::string& worker_id) {
    return registration_->drain_worker(worker_id);
  }

  // --------------------------------------------------------------------------
  // POST /_progressive/workers/:worker_id/restart — Restart a worker
  // --------------------------------------------------------------------------
  json restart_worker(const std::string& worker_id) {
    return registration_->restart_worker(worker_id);
  }

  // --------------------------------------------------------------------------
  // POST /_progressive/workers/:worker_id/stop — Stop a worker
  // --------------------------------------------------------------------------
  json stop_worker(const std::string& worker_id) {
    auto worker = pool_->get(worker_id);
    if (!worker) {
      return json{{"error", "worker not found"}, {"worker_id", worker_id}};
    }
    registration_->stop_worker(worker_id);
    return json{{"status", "stopped"}, {"worker_id", worker_id}};
  }

  // --------------------------------------------------------------------------
  // POST /_progressive/workers/create — Create a new worker
  // --------------------------------------------------------------------------
  json create_worker(const json& request, LoggingTransaction& txn) {
    WorkerType wt = string_to_worker_type(request.value("worker_type", "generic"));
    std::string instance = request.value("instance_id", "default");
    auto worker = registration_->create_worker(wt, instance, txn, request);
    registration_->start_worker(worker->worker_id());
    return worker->to_json();
  }

  // --------------------------------------------------------------------------
  // POST /_progressive/workers/scale — Scale a worker type pool
  // --------------------------------------------------------------------------
  json scale_pool(const json& request, LoggingTransaction& txn) {
    WorkerType wt = string_to_worker_type(request.value("worker_type", "generic"));
    int target = request.value("target_count", 1);
    std::string instance = request.value("instance_id", "default");

    int current = static_cast<int>(pool_->count_active_by_type(wt));
    json result;
    result["worker_type"] = worker_type_to_string(wt);
    result["previous_count"] = current;
    result["target_count"] = target;

    if (target > current) {
      // Scale up
      int to_create = target - current;
      json created = json::array();
      for (int i = 0; i < to_create; ++i) {
        auto worker = registration_->create_worker(wt, instance, txn);
        registration_->start_worker(worker->worker_id());
        created.push_back(worker->worker_id());
      }
      result["created"] = created;
      result["action"] = "scale_up";
    } else if (target < current) {
      // Scale down - drain workers
      int to_drain = current - target;
      auto workers = pool_->get_by_type(wt);
      json drained = json::array();

      // Drain workers with lowest load first
      std::sort(workers.begin(), workers.end(),
        [](const auto& a, const auto& b) {
          return a->load_score() < b->load_score();
        });

      for (int i = 0; i < to_drain && i < static_cast<int>(workers.size()); ++i) {
        auto r = registration_->drain_worker(workers[i]->worker_id());
        drained.push_back(r);
      }
      result["drained"] = drained;
      result["action"] = "scale_down";
    } else {
      result["action"] = "no_change";
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // GET /_progressive/workers/prometheus — Prometheus metrics
  // --------------------------------------------------------------------------
  std::string prometheus() const {
    return metrics_->prometheus_metrics();
  }

  // --------------------------------------------------------------------------
  // GET /_progressive/workers/health — Worker health overview
  // --------------------------------------------------------------------------
  json health() const {
    json j;
    auto workers = pool_->all();

    bool all_healthy = true;
    json issues = json::array();

    for (const auto& w : workers) {
      if (w->status() == WorkerStatus::kFailed || w->status() == WorkerStatus::kOrphaned) {
        all_healthy = false;
        issues.push_back({
          {"worker_id", w->worker_id()},
          {"worker_name", w->worker_name()},
          {"type", worker_type_to_string(w->type())},
          {"status", worker_status_to_string(w->status())}
        });
      }
    }

    j["healthy"] = all_healthy;
    j["total_workers"] = workers.size();
    j["issues"] = issues;
    j["timestamp_ms"] = now_ms();
    return j;
  }

private:
  std::shared_ptr<WorkerPoolManager> pool_;
  std::shared_ptr<WorkerRegistrationService> registration_;
  std::shared_ptr<WorkerHeartbeatEngine> heartbeat_;
  std::shared_ptr<ReplicationStreamManager> replication_;
  std::shared_ptr<WorkerMetricsCollector> metrics_;
  std::shared_ptr<LoadBalancer> load_balancer_;
  std::shared_ptr<WorkerLogger> logger_;
};

// ============================================================================
// WorkerDrainManager — Graceful worker drain orchestration
// ============================================================================
class WorkerDrainManager {
public:
  WorkerDrainManager(std::shared_ptr<WorkerPoolManager> pool,
      std::shared_ptr<WorkerHeartbeatEngine> heartbeat,
      std::shared_ptr<WorkerLogger> logger = nullptr)
    : pool_(pool), heartbeat_(heartbeat), logger_(logger), running_(false) {}

  // --------------------------------------------------------------------------
  // Monitor draining workers and complete drain when queues are empty
  // --------------------------------------------------------------------------
  void start(int64_t check_interval_ms = 5000) {
    if (running_) return;
    running_ = true;
    drain_thread_ = std::thread([this, check_interval_ms]() {
      while (running_) {
        std::this_thread::sleep_for(chr::milliseconds(check_interval_ms));
        if (!running_) break;
        check_draining_workers();
      }
    });
  }

  void stop() {
    running_ = false;
    if (drain_thread_.joinable()) drain_thread_.join();
  }

  // --------------------------------------------------------------------------
  // Force-drain all workers of a type
  // --------------------------------------------------------------------------
  json force_drain_type(WorkerType wt, int64_t timeout_ms = 30000) {
    auto workers = pool_->get_by_type(wt);
    json result;
    result["type"] = worker_type_to_string(wt);
    json drained = json::array();

    for (auto& w : workers) {
      if (w->status() == WorkerStatus::kRunning) {
        w->set_status(WorkerStatus::kDraining);
        drained.push_back({{"worker_id", w->worker_id()}, {"status", "draining"}});
      }
    }
    result["drained"] = drained;
    return result;
  }

private:
  void check_draining_workers() {
    auto workers = pool_->all();
    for (auto& w : workers) {
      if (w->status() != WorkerStatus::kDraining) continue;

      // Check if queues are drained
      bool queue_empty = w->queue_depth() == 0;
      bool connections_closed = w->active_connections() == 0;
      int64_t drain_duration = now_ms() - w->status_change_ms();

      if (queue_empty && connections_closed) {
        w->set_status(WorkerStatus::kDrained);
        if (logger_) {
          logger_->info("Worker drain complete: " + w->worker_name()
            + " (took " + std::to_string(drain_duration) + "ms)");
        }
      } else if (drain_duration > w->config().drain_timeout_ms) {
        // Force drain timeout
        w->set_status(WorkerStatus::kDrained);
        if (logger_) {
          logger_->warn("Worker drain timed out: " + w->worker_name()
            + " (forced after " + std::to_string(drain_duration) + "ms)");
        }
      }
    }
  }

  std::shared_ptr<WorkerPoolManager> pool_;
  std::shared_ptr<WorkerHeartbeatEngine> heartbeat_;
  std::shared_ptr<WorkerLogger> logger_;
  std::atomic<bool> running_{false};
  std::thread drain_thread_;
};

// ============================================================================
// WorkerDiscoveryService — Peer-to-peer worker discovery
// ============================================================================
class WorkerDiscoveryService {
public:
  WorkerDiscoveryService(std::shared_ptr<WorkerPoolManager> pool,
      std::shared_ptr<WorkerLogger> logger = nullptr)
    : pool_(pool), logger_(logger), running_(false) {}

  // --------------------------------------------------------------------------
  // Broadcast presence
  // --------------------------------------------------------------------------
  void start_broadcast(int64_t interval_ms = kDiscoveryBroadcastIntervalMs) {
    if (running_) return;
    running_ = true;
    broadcast_thread_ = std::thread([this, interval_ms]() {
      while (running_) {
        std::this_thread::sleep_for(chr::milliseconds(interval_ms));
        if (!running_) break;
        broadcast_presence();
      }
    });
  }

  void stop() {
    running_ = false;
    if (broadcast_thread_.joinable()) broadcast_thread_.join();
  }

  // --------------------------------------------------------------------------
  // Discover peers
  // --------------------------------------------------------------------------
  json discover() const {
    auto workers = pool_->all();
    json peers = json::array();
    for (const auto& w : workers) {
      if (w->is_active()) {
        peers.push_back({
          {"worker_id", w->worker_id()},
          {"worker_name", w->worker_name()},
          {"type", worker_type_to_string(w->type())},
          {"address", w->config().listen_address},
          {"port", w->config().listen_port},
          {"replication_port", w->config().replication_port}
        });
      }
    }
    return peers;
  }

  // --------------------------------------------------------------------------
  // Register a listener for worker join/leave events
  // --------------------------------------------------------------------------
  using WorkerEventCallback = std::function<void(const std::string& event,
    std::shared_ptr<WorkerInstance>)>;

  void on_worker_event(WorkerEventCallback callback) {
    event_callbacks_.push_back(callback);
  }

  void notify(const std::string& event, std::shared_ptr<WorkerInstance> worker) {
    for (auto& cb : event_callbacks_) {
      cb(event, worker);
    }
  }

private:
  void broadcast_presence() {
    // In a real implementation, this would broadcast via UDP multicast
    // or publish to a service registry (Consul/etcd)
    if (logger_) {
      auto workers = pool_->all();
      size_t active = 0;
      for (const auto& w : workers) {
        if (w->is_active()) active++;
      }
      logger_->debug("Discovery broadcast: " + std::to_string(active)
        + " active / " + std::to_string(workers.size()) + " total");
    }
  }

  std::shared_ptr<WorkerPoolManager> pool_;
  std::shared_ptr<WorkerLogger> logger_;
  std::atomic<bool> running_{false};
  std::thread broadcast_thread_;
  std::vector<WorkerEventCallback> event_callbacks_;
};

// ============================================================================
// WorkerConfigEngine — Configuration management and validation
// ============================================================================
class WorkerConfigEngine {
public:
  WorkerConfigEngine(const WorkerTypeRegistry& registry,
      std::shared_ptr<WorkerLogger> logger = nullptr)
    : registry_(registry), logger_(logger) {}

  // --------------------------------------------------------------------------
  // Validate a worker configuration
  // --------------------------------------------------------------------------
  json validate(const WorkerConfig& config) const {
    json errors = json::array();
    json warnings = json::array();
    const auto& desc = registry_.descriptor(config.type);

    // Check type validity
    if (desc.name == "unknown") {
      errors.push_back("Unknown worker type: " + std::string(worker_type_to_string(config.type)));
    }

    // Check worker name
    if (config.worker_name.empty()) {
      errors.push_back("Worker name must not be empty");
    }
    if (config.worker_name.length() > kMaxWorkerNameLength) {
      errors.push_back("Worker name too long (max " + std::to_string(kMaxWorkerNameLength) + " chars)");
    }

    // Check instance ID
    if (config.instance_id.empty()) {
      errors.push_back("Instance ID must not be empty");
    }

    // Check heartbeat intervals
    if (config.heartbeat_interval_ms < 1000) {
      warnings.push_back("Heartbeat interval is very short (< 1s)");
    }
    if (config.heartbeat_timeout_ms < config.heartbeat_interval_ms * 2) {
      warnings.push_back("Heartbeat timeout should be at least 2x interval");
    }

    // Check resource limits
    if (config.max_connections == 0) {
      warnings.push_back("max_connections is 0; worker won't accept connections");
    }
    if (config.max_memory_mb < 64) {
      warnings.push_back("Memory limit is very low (< 64 MB)");
    }

    // Check drain timeout
    if (config.drain_timeout_ms < 5000) {
      warnings.push_back("Drain timeout is very short (< 5s); may not drain fully");
    }

    // Check tags
    if (config.tags.size() > kMaxWorkerTags) {
      errors.push_back("Too many tags (max " + std::to_string(kMaxWorkerTags) + ")");
    }

    // Check subscription streams
    for (auto stream : config.subscribe_streams) {
      if (static_cast<size_t>(stream) >= kNumReplicationStreamTypes) {
        errors.push_back("Invalid subscription stream index");
      }
    }

    json result;
    result["valid"] = errors.empty();
    result["errors"] = errors;
    result["warnings"] = warnings;
    return result;
  }

  // --------------------------------------------------------------------------
  // Compute a configuration hash for change detection
  // --------------------------------------------------------------------------
  std::string compute_hash(const WorkerConfig& config) const {
    json j = config.to_json();
    std::string serialized = j.dump();
    uint64_t h = hash_string(serialized);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0') << std::setw(16) << h;
    return oss.str();
  }

  // --------------------------------------------------------------------------
  // Merge two configurations (base + overrides)
  // --------------------------------------------------------------------------
  WorkerConfig merge(const WorkerConfig& base, const json& overrides) const {
    auto j = base.to_json();

    for (auto it = overrides.begin(); it != overrides.end(); ++it) {
      j[it.key()] = it.value();
    }

    return WorkerConfig::from_json(j);
  }

  // --------------------------------------------------------------------------
  // Generate default pool configuration
  // --------------------------------------------------------------------------
  json default_pool_config(WorkerType wt) const {
    const auto& desc = registry_.descriptor(wt);
    json j;
    j["type"] = desc.name;
    j["description"] = desc.description;
    j["min_workers"] = desc.default_pool_min;
    j["max_workers"] = desc.default_pool_max;
    j["is_critical"] = desc.is_critical;
    j["requires_database"] = desc.requires_database;
    j["can_be_leader"] = desc.can_be_leader;

    json streams = json::array();
    for (auto s : desc.required_streams) {
      streams.push_back(rep_stream_to_string(s));
    }
    j["required_streams"] = streams;

    json produced = json::array();
    for (auto s : desc.produced_streams) {
      produced.push_back(rep_stream_to_string(s));
    }
    j["produced_streams"] = produced;

    return j;
  }

private:
  const WorkerTypeRegistry& registry_;
  std::shared_ptr<WorkerLogger> logger_;
};

// ============================================================================
// WorkerOrchestrator — Top-level coordination of all worker subsystems
// ============================================================================
class WorkerOrchestrator {
public:
  WorkerOrchestrator(DatabasePool& db)
    : db_(db)
    , logger_(std::make_shared<WorkerLogger>())
    , registry_(std::make_shared<WorkerTypeRegistry>())
    , heartbeat_(std::make_shared<WorkerHeartbeatEngine>(logger_))
    , replication_(std::make_shared<ReplicationStreamManager>(db, logger_))
    , pool_(std::make_shared<WorkerPoolManager>(*registry_, heartbeat_, logger_))
    , registration_(std::make_shared<WorkerRegistrationService>(
        db, *registry_, pool_, heartbeat_, logger_))
    , load_balancer_(std::make_shared<LoadBalancer>(*registry_, logger_))
    , metrics_(std::make_shared<WorkerMetricsCollector>(pool_, logger_))
    , admin_(std::make_shared<WorkerAdminAPI>(
        pool_, registration_, heartbeat_, replication_, metrics_, load_balancer_, logger_))
    , config_engine_(std::make_shared<WorkerConfigEngine>(*registry_, logger_))
    , drain_mgr_(std::make_shared<WorkerDrainManager>(pool_, heartbeat_, logger_))
    , discovery_(std::make_shared<WorkerDiscoveryService>(pool_, logger_))
    , work_stealer_(std::make_shared<WorkStealingEngine>(logger_))
    , running_(false)
  {
    logger_->name_ = "orchestrator";
  }

  // --------------------------------------------------------------------------
  // Initialize the orchestrator
  // --------------------------------------------------------------------------
  void init() {
    // Initialize database tables
    auto txn = db_.begin_transaction();
    replication_->init_tables(*txn);

    // Load persisted workers
    registration_->load_from_database(*txn);

    // Load replication positions
    replication_->load_positions(*txn);

    txn->commit();

    // Set up heartbeat expiry callback
    heartbeat_->set_on_worker_expired([this](std::shared_ptr<WorkerInstance> w) {
      logger_->warn("Worker expired: " + w->worker_name());
      discovery_->notify("worker_expired", w);
    });

    logger_->info("WorkerOrchestrator initialized");
  }

  // --------------------------------------------------------------------------
  // Start all background services
  // --------------------------------------------------------------------------
  void start() {
    if (running_) return;
    running_ = true;

    heartbeat_->start();
    metrics_->start();
    drain_mgr_->start();
    discovery_->start_broadcast();
    work_stealer_->start([this]() { return pool_->all(); });

    logger_->info("WorkerOrchestrator started");
  }

  // --------------------------------------------------------------------------
  // Stop all background services
  // --------------------------------------------------------------------------
  void stop() {
    if (!running_) return;
    running_ = false;

    work_stealer_->stop();
    discovery_->stop();
    drain_mgr_->stop();
    metrics_->stop();
    heartbeat_->stop();

    logger_->info("WorkerOrchestrator stopped");
  }

  // --------------------------------------------------------------------------
  // Bootstrap: ensure minimum required workers for each critical type
  // --------------------------------------------------------------------------
  json bootstrap_workers() {
    json result;
    auto txn = db_.begin_transaction();
    auto critical = registry_->critical_types();

    for (auto wt : critical) {
      size_t current = pool_->count_by_type(wt);
      const auto& desc = registry_->descriptor(wt);
      size_t min_needed = desc.default_pool_min;

      if (current < min_needed) {
        size_t to_create = min_needed - current;
        json created = json::array();
        for (size_t i = 0; i < to_create; ++i) {
          auto worker = registration_->create_worker(wt, "bootstrap", *txn);
          registration_->start_worker(worker->worker_id());
          created.push_back(worker->worker_id());
        }
        result[worker_type_to_string(wt)] = {
          {"created", created},
          {"total", min_needed}
        };
      } else {
        result[worker_type_to_string(wt)] = {
          {"existing", current},
          {"total", current}
        };
      }
    }

    txn->commit();
    logger_->info("Bootstrap completed");
    return result;
  }

  // --------------------------------------------------------------------------
  // Select a worker for a task
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerInstance> select_worker(
      WorkerType wt, const std::string& affinity_key = "") {
    return load_balancer_->select_by_type(
      pool_->get_by_type_map(), wt, affinity_key);
  }

  // --------------------------------------------------------------------------
  // Accessor methods for all subsystems
  // --------------------------------------------------------------------------
  std::shared_ptr<WorkerTypeRegistry> registry() const { return registry_; }
  std::shared_ptr<WorkerPoolManager> pool() const { return pool_; }
  std::shared_ptr<WorkerRegistrationService> registration() const { return registration_; }
  std::shared_ptr<WorkerHeartbeatEngine> heartbeat() const { return heartbeat_; }
  std::shared_ptr<ReplicationStreamManager> replication() const { return replication_; }
  std::shared_ptr<LoadBalancer> load_balancer() const { return load_balancer_; }
  std::shared_ptr<WorkerMetricsCollector> metrics() const { return metrics_; }
  std::shared_ptr<WorkerAdminAPI> admin() const { return admin_; }
  std::shared_ptr<WorkerConfigEngine> config_engine() const { return config_engine_; }
  std::shared_ptr<WorkerDrainManager> drain_manager() const { return drain_mgr_; }
  std::shared_ptr<WorkerDiscoveryService> discovery() const { return discovery_; }
  std::shared_ptr<WorkStealingEngine> work_stealer() const { return work_stealer_; }

private:
  DatabasePool& db_;
  std::shared_ptr<WorkerLogger> logger_;

  std::shared_ptr<WorkerTypeRegistry> registry_;
  std::shared_ptr<WorkerHeartbeatEngine> heartbeat_;
  std::shared_ptr<ReplicationStreamManager> replication_;
  std::shared_ptr<WorkerPoolManager> pool_;
  std::shared_ptr<WorkerRegistrationService> registration_;
  std::shared_ptr<LoadBalancer> load_balancer_;
  std::shared_ptr<WorkerMetricsCollector> metrics_;
  std::shared_ptr<WorkerAdminAPI> admin_;
  std::shared_ptr<WorkerConfigEngine> config_engine_;
  std::shared_ptr<WorkerDrainManager> drain_mgr_;
  std::shared_ptr<WorkerDiscoveryService> discovery_;
  std::shared_ptr<WorkStealingEngine> work_stealer_;

  std::atomic<bool> running_{false};
};

// ============================================================================
// Global worker orchestrator singleton
// ============================================================================
namespace {
  std::shared_ptr<WorkerOrchestrator> global_orchestrator_;
  std::mutex global_init_mutex_;
}

std::shared_ptr<WorkerOrchestrator> init_worker_orchestrator(DatabasePool& db) {
  std::lock_guard<std::mutex> lock(global_init_mutex_);
  if (!global_orchestrator_) {
    global_orchestrator_ = std::make_shared<WorkerOrchestrator>(db);
    global_orchestrator_->init();
    global_orchestrator_->bootstrap_workers();
    global_orchestrator_->start();
  }
  return global_orchestrator_;
}

std::shared_ptr<WorkerOrchestrator> get_worker_orchestrator() {
  return global_orchestrator_;
}

void shutdown_worker_orchestrator() {
  std::lock_guard<std::mutex> lock(global_init_mutex_);
  if (global_orchestrator_) {
    global_orchestrator_->stop();
    global_orchestrator_.reset();
  }
}

// ============================================================================
// Convenience free functions for external integration
// ============================================================================

json list_workers_json(const std::string& type, const std::string& status) {
  auto orch = get_worker_orchestrator();
  if (!orch) return json{{"error", "orchestrator not initialized"}};
  return orch->admin()->list_workers(type, status);
}

json get_worker_json(const std::string& worker_id) {
  auto orch = get_worker_orchestrator();
  if (!orch) return json{{"error", "orchestrator not initialized"}};
  return orch->admin()->get_worker(worker_id);
}

json worker_pool_overview() {
  auto orch = get_worker_orchestrator();
  if (!orch) return json{{"error", "orchestrator not initialized"}};
  return orch->admin()->pool_overview();
}

std::string worker_prometheus_metrics() {
  auto orch = get_worker_orchestrator();
  if (!orch) return "";
  return orch->admin()->prometheus();
}

json worker_health_check() {
  auto orch = get_worker_orchestrator();
  if (!orch) return json{{"healthy", false}, {"error", "orchestrator not initialized"}};
  return orch->admin()->health();
}

json drain_worker_graceful(const std::string& worker_id) {
  auto orch = get_worker_orchestrator();
  if (!orch) return json{{"error", "orchestrator not initialized"}};
  return orch->admin()->drain_worker(worker_id);
}

bool select_worker_for_type(WorkerType wt, std::shared_ptr<WorkerInstance>& out,
    const std::string& affinity_key = "") {
  auto orch = get_worker_orchestrator();
  if (!orch) return false;
  out = orch->select_worker(wt, affinity_key);
  return out != nullptr;
}

bool record_worker_heartbeat(const std::string& worker_id, const json& metrics) {
  auto orch = get_worker_orchestrator();
  if (!orch) return false;
  return orch->heartbeat()->heartbeat(worker_id, metrics);
}

int64_t get_replication_position(const std::string& worker_id,
    ReplicationStreamType stream) {
  auto orch = get_worker_orchestrator();
  if (!orch) return 0;
  return orch->replication()->get_position(worker_id, stream);
}

void update_replication_position(const std::string& worker_id,
    ReplicationStreamType stream, int64_t position) {
  auto orch = get_worker_orchestrator();
  if (!orch) return;
  orch->replication()->update_position(worker_id, stream, position);
}

json create_worker_simple(const std::string& type_name,
    const std::string& instance_id, const json& overrides) {
  auto orch = get_worker_orchestrator();
  if (!orch) return json{{"error", "orchestrator not initialized"}};
  auto txn = orch->get_database().begin_transaction();
  WorkerType wt = string_to_worker_type(type_name);
  auto worker = orch->registration()->create_worker(wt, instance_id, *txn, overrides);
  orch->registration()->start_worker(worker->worker_id());
  txn->commit();
  return worker->to_json();
}

}  // namespace progressive

// ============================================================================
// End of worker_manager.cpp
// ============================================================================
