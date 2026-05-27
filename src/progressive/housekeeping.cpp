// =============================================================================
// housekeeping.cpp — Matrix Housekeeping: Background Task Scheduler for
//   Cleanup Operations, Periodic Maintenance, and Resource Reclamation
//
// Implements:
//   - Expired Event Purge: Retention-policy-based event cleanup,
//     per-room max_lifetime enforcement, redacted event compaction,
//     orphaned event_relations cleanup, event_json garbage collection
//   - Old Receipt Cleanup: Expired read receipts removal,
//     stale fully-read markers, old linearized receipt compaction,
//     receipt_graph deduplication, notification count recalculation
//   - Stale Presence Cleanup: Inactive user presence pruning,
//     presence_stream garbage collection, presence_list updates for
//     departed users, timeout tracking and auto-offline marking
//   - Expired Token Cleanup: Access token expiration enforcement,
//     refresh token revocation, OIDC session expiry, registration
//     token cleanup, password_reset_token removal, threepid
//     validation session expiry, UI auth session garbage collection
//   - Old Media Cache Cleanup: Remote media cache eviction by
//     last_access_ts, orphaned thumbnail removal, filesystem
//     storage reclamation, media quarantine expiry, size-quota
//     enforcement, per-user media usage aggregation
//   - Stats Aggregation: Daily user stats rollup (DAU/MAU),
//     room statistics recomputation, server-wide metrics snapshot,
//     federation throughput aggregation, event throughput time series
//   - Database Vacuum: Periodic VACUUM for SQLite storage reclamation,
//     ANALYZE for query planner optimization, WAL checkpointing,
//     index rebuild for fragmented B-trees, PRAGMA optimize
//   - Failed Federation Retry: Destination retry scheduling with
//     exponential backoff, transaction retry queue draining,
//     stale destination pruning, federation lag compensation
//   - Device List Update Poke Sending: Batched device list change
//     notification to remote servers, retry on failure, rate
//     limiting per destination, backlog management
//
// Equivalent to:
//   synapse/handlers/housekeeping.py
//   synapse/storage/databases/main/events.py (purge_history)
//   synapse/storage/databases/main/event_push_actions.py (remove_old)
//   synapse/storage/databases/main/presence.py (gc)
//   synapse/storage/databases/main/registration.py (token cleanup)
//   synapse/storage/databases/main/media_repository.py (expire)
//   synapse/handlers/stats.py
//   synapse/storage/databases/main/__init__.py (vacuum)
//   synapse/federation/sender/__init__.py (retry)
//   synapse/handlers/device.py (device_list_update)
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++ with full SQL coverage.
// =============================================================================

#include <algorithm>
#include <array>
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
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/event_federation.hpp"
#include "progressive/storage/databases/main/federation_stores.hpp"
#include "progressive/storage/databases/main/filtering.hpp"
#include "progressive/storage/databases/main/end_to_end_keys.hpp"
#include "progressive/storage/databases/main/push_rule.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/final_stores.hpp"
#include "progressive/storage/databases/main/remaining_stores.hpp"
#include "progressive/storage/databases/main/small_stores.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class EventPurger;
class ReceiptCleaner;
class PresenceCleaner;
class TokenExpiryManager;
class MediaCacheCleaner;
class StatsAggregator;
class DatabaseVacuumEngine;
class FederationRetryManager;
class DeviceListPokeSender;
class HousekeepingScheduler;
class HousekeepingMetrics;
class HousekeepingAdminAPI;

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// --------------------------------------------------------------------------
// Logging helper (matches project conventions)
// --------------------------------------------------------------------------
struct HkLogger {
  std::string name_;
  void debug(const std::string& msg) { std::cerr << "[DEBUG][" << name_ << "] " << msg << "\n"; }
  void info(const std::string& msg)  { std::cerr << "[INFO][" << name_ << "] " << msg << "\n"; }
  void warn(const std::string& msg)  { std::cerr << "[WARN][" << name_ << "] " << msg << "\n"; }
  void error(const std::string& msg) { std::cerr << "[ERROR][" << name_ << "] " << msg << "\n"; }
};

HkLogger& get_hk_logger(const std::string& name) {
  static thread_local std::map<std::string, HkLogger> loggers;
  if (loggers.find(name) == loggers.end()) {
    loggers[name].name_ = name;
  }
  return loggers[name];
}

// --------------------------------------------------------------------------
// Timestamp helpers
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

inline int64_t days_ago_sec(int days) {
  return now_sec() - static_cast<int64_t>(days) * 86400;
}

inline int64_t hours_ago_sec(int hours) {
  return now_sec() - static_cast<int64_t>(hours) * 3600;
}

inline int64_t minutes_ago_ms(int minutes) {
  return now_ms() - static_cast<int64_t>(minutes) * 60000;
}

inline int64_t days_ago_ms(int days) {
  return now_ms() - static_cast<int64_t>(days) * 86400000;
}

inline std::string iso8601_from_ts(int64_t ts_sec) {
  char buf[32];
  auto t = static_cast<std::time_t>(ts_sec);
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

// --------------------------------------------------------------------------
// SQL escape helper
// --------------------------------------------------------------------------
std::string sql_quote(const std::string& s) {
  std::string result;
  result.reserve(s.size() + 4);
  result += '\'';
  for (char c : s) {
    if (c == '\'') result += "''"; else result += c;
  }
  result += '\'';
  return result;
}

// --------------------------------------------------------------------------
// Enum for housekeeping task types
// --------------------------------------------------------------------------
enum class HkTaskType : uint8_t {
  EVENT_PURGE          = 0,
  RECEIPT_CLEANUP      = 1,
  PRESENCE_CLEANUP     = 2,
  TOKEN_EXPIRY         = 3,
  MEDIA_CACHE_CLEANUP  = 4,
  STATS_AGGREGATION    = 5,
  DATABASE_VACUUM      = 6,
  FEDERATION_RETRY     = 7,
  DEVICE_LIST_POKE     = 8,
  ALL_TASKS            = 9
};

const char* hk_task_name(HkTaskType t) {
  switch (t) {
    case HkTaskType::EVENT_PURGE:          return "event_purge";
    case HkTaskType::RECEIPT_CLEANUP:      return "receipt_cleanup";
    case HkTaskType::PRESENCE_CLEANUP:     return "presence_cleanup";
    case HkTaskType::TOKEN_EXPIRY:         return "token_expiry";
    case HkTaskType::MEDIA_CACHE_CLEANUP:  return "media_cache_cleanup";
    case HkTaskType::STATS_AGGREGATION:    return "stats_aggregation";
    case HkTaskType::DATABASE_VACUUM:      return "database_vacuum";
    case HkTaskType::FEDERATION_RETRY:     return "federation_retry";
    case HkTaskType::DEVICE_LIST_POKE:     return "device_list_poke";
    case HkTaskType::ALL_TASKS:            return "all_tasks";
  }
  return "unknown";
}

// --------------------------------------------------------------------------
// Task run mode
// --------------------------------------------------------------------------
enum class RunMode : uint8_t {
  SCHEDULED = 0,  // Running on cron
  MANUAL    = 1,  // Triggered by admin API
  STARTUP   = 2,  // Running at server startup
  SHUTDOWN  = 3   // Running at server shutdown
};

const char* run_mode_name(RunMode m) {
  switch (m) {
    case RunMode::SCHEDULED: return "scheduled";
    case RunMode::MANUAL:    return "manual";
    case RunMode::STARTUP:   return "startup";
    case RunMode::SHUTDOWN:  return "shutdown";
  }
  return "unknown";
}

// --------------------------------------------------------------------------
// Default intervals (milliseconds)
// --------------------------------------------------------------------------
constexpr int64_t kDefaultEventPurgeIntervalMs       = 3'600'000;   // 1 hour
constexpr int64_t kDefaultReceiptCleanupIntervalMs    = 7'200'000;   // 2 hours
constexpr int64_t kDefaultPresenceCleanupIntervalMs   = 1'800'000;   // 30 min
constexpr int64_t kDefaultTokenExpiryIntervalMs       = 900'000;     // 15 min
constexpr int64_t kDefaultMediaCacheCleanupIntervalMs = 10'800'000;  // 3 hours
constexpr int64_t kDefaultStatsAggregationIntervalMs  = 3'600'000;   // 1 hour
constexpr int64_t kDefaultDatabaseVacuumIntervalMs    = 86'400'000;  // 24 hours
constexpr int64_t kDefaultFederationRetryIntervalMs   = 60'000;      // 1 min
constexpr int64_t kDefaultDeviceListPokeIntervalMs    = 30'000;      // 30 sec

// --------------------------------------------------------------------------
// Default retention/cutoff periods
// --------------------------------------------------------------------------
constexpr int64_t kDefaultEventRetentionDays          = 365;   // 1 year default
constexpr int64_t kDefaultReceiptRetentionDays        = 90;    // 90 days
constexpr int64_t kDefaultPresenceMaxInactiveHours     = 24;    // 24 hours
constexpr int64_t kDefaultAccessTokenMaxAgeDays        = 365;   // 1 year
constexpr int64_t kDefaultRefreshTokenMaxAgeDays       = 90;    // 90 days
constexpr int64_t kDefaultRemoteMediaCacheExpiryDays   = 60;    // 60 days
constexpr int64_t kDefaultStatsHistoryDays             = 90;    // 90 days

// --------------------------------------------------------------------------
// Batch sizes for cleanup operations
// --------------------------------------------------------------------------
constexpr int64_t kEventPurgeBatchSize              = 500;
constexpr int64_t kReceiptCleanupBatchSize          = 1000;
constexpr int64_t kPresenceCleanupBatchSize         = 500;
constexpr int64_t kTokenExpiryBatchSize             = 200;
constexpr int64_t kMediaCacheBatchSize              = 100;
constexpr int64_t kFederationRetryBatchSize         = 50;
constexpr int64_t kDeviceListPokeBatchSize          = 100;
constexpr int64_t kStatsRoomBatchSize               = 200;
constexpr int64_t kStatsUserBatchSize               = 500;

// --------------------------------------------------------------------------
// Federation retry backoff configuration
// --------------------------------------------------------------------------
constexpr int64_t kRetryBaseIntervalMs              = 10'000;   // 10 sec base
constexpr int64_t kRetryMaxIntervalMs               = 3'600'000; // 1 hour max
constexpr double  kRetryBackoffMultiplier            = 2.0;
constexpr int     kRetryMaxFailuresBeforePrune        = 100;

// --------------------------------------------------------------------------
// String constants
// --------------------------------------------------------------------------
constexpr const char* kMembershipJoin   = "join";
constexpr const char* kMembershipLeave  = "leave";
constexpr const char* kMembershipBan    = "ban";
constexpr const char* kReceiptTypeRead   = "m.read";
constexpr const char* kReceiptTypeFullyRead = "m.fully_read";

// ============================================================================
// HousekeepingMetrics — Atomic counters for housekeeping operations
// ============================================================================
class HousekeepingMetrics {
public:
  struct TaskStats {
    std::atomic<int64_t> runs_total{0};
    std::atomic<int64_t> runs_success{0};
    std::atomic<int64_t> runs_failed{0};
    std::atomic<int64_t> items_processed{0};
    std::atomic<int64_t> items_deleted{0};
    std::atomic<int64_t> last_run_ms{0};
    std::atomic<int64_t> last_duration_ms{0};
    std::atomic<int64_t> total_duration_ms{0};
    std::atomic<int64_t> errors_total{0};
  };

  TaskStats& for_task(HkTaskType t) {
    return stats_[static_cast<size_t>(t)];
  }

  const TaskStats& for_task(HkTaskType t) const {
    return stats_[static_cast<size_t>(t)];
  }

  void record_run(HkTaskType t, bool success, int64_t items, int64_t deleted, int64_t dur_ms) {
    auto& s = for_task(t);
    s.runs_total.fetch_add(1, std::memory_order_relaxed);
    if (success) s.runs_success.fetch_add(1, std::memory_order_relaxed);
    else s.runs_failed.fetch_add(1, std::memory_order_relaxed);
    s.items_processed.fetch_add(items, std::memory_order_relaxed);
    s.items_deleted.fetch_add(deleted, std::memory_order_relaxed);
    s.last_run_ms.store(now_ms(), std::memory_order_relaxed);
    s.last_duration_ms.store(dur_ms, std::memory_order_relaxed);
    s.total_duration_ms.fetch_add(dur_ms, std::memory_order_relaxed);
  }

  void record_error(HkTaskType t) {
    for_task(t).errors_total.fetch_add(1, std::memory_order_relaxed);
  }

  json to_json() const {
    json j;
    for (int i = 0; i <= static_cast<int>(HkTaskType::DEVICE_LIST_POKE); ++i) {
      auto t = static_cast<HkTaskType>(i);
      auto& s = stats_[i];
      json tj;
      tj["name"] = hk_task_name(t);
      tj["runs_total"] = s.runs_total.load();
      tj["runs_success"] = s.runs_success.load();
      tj["runs_failed"] = s.runs_failed.load();
      tj["items_processed"] = s.items_processed.load();
      tj["items_deleted"] = s.items_deleted.load();
      tj["last_run_ms"] = s.last_run_ms.load();
      tj["last_duration_ms"] = s.last_duration_ms.load();
      tj["total_duration_ms"] = s.total_duration_ms.load();
      tj["errors_total"] = s.errors_total.load();
      j.push_back(tj);
    }
    return j;
  }

private:
  TaskStats stats_[9];
};

// ============================================================================
// RetentionPolicy — Per-room and global retention policy configuration
// ============================================================================
struct RetentionPolicy {
  int64_t max_lifetime_ms = kDefaultEventRetentionDays * 86400 * 1000LL;
  int64_t min_lifetime_ms = 0;
  std::map<std::string, int64_t> room_overrides; // room_id -> max_lifetime_ms
  bool purge_redacted_events_immediately = false;
  bool delete_local_media_on_purge = true;

  int64_t effective_max_lifetime_ms(const std::string& room_id) const {
    auto it = room_overrides.find(room_id);
    if (it != room_overrides.end()) return it->second;
    return max_lifetime_ms;
  }
};

// ============================================================================
// TaskRunContext — Context passed to each housekeeping task execution
// ============================================================================
struct TaskRunContext {
  HkTaskType type;
  RunMode mode;
  int64_t started_at_ms;
  int64_t batch_size;
  int64_t max_runtime_ms;  // 0 = no limit
  bool dry_run;
  json config;
};

// ============================================================================
// TaskRunResult — Result of a housekeeping task execution
// ============================================================================
struct TaskRunResult {
  HkTaskType type;
  bool success;
  int64_t items_processed;
  int64_t items_deleted;
  int64_t duration_ms;
  std::string error_message;
  json details;

  static TaskRunResult ok(HkTaskType t, int64_t processed, int64_t deleted, int64_t dur) {
    TaskRunResult r;
    r.type = t;
    r.success = true;
    r.items_processed = processed;
    r.items_deleted = deleted;
    r.duration_ms = dur;
    return r;
  }

  static TaskRunResult fail(HkTaskType t, const std::string& err, int64_t dur) {
    TaskRunResult r;
    r.type = t;
    r.success = false;
    r.error_message = err;
    r.duration_ms = dur;
    return r;
  }
};

}  // anonymous namespace

// ============================================================================
// 1. EventPurger — Purges expired events from rooms based on retention policy
// ============================================================================
class EventPurger {
public:
  EventPurger(std::shared_ptr<storage::DatabasePool> db,
              std::shared_ptr<RetentionPolicy> policy,
              HousekeepingMetrics& metrics)
    : db_(std::move(db)), policy_(std::move(policy)), metrics_(metrics),
      logger_(get_hk_logger("progressive.housekeeping.event_purger")) {}

  TaskRunResult run(const TaskRunContext& ctx) {
    auto start = now_ms();
    int64_t total_processed = 0;
    int64_t total_deleted = 0;
    json details = json::object();

    try {
      logger_.info("Starting event purge run (mode=" + std::string(run_mode_name(ctx.mode)) + ")");

      // 1a. Purge room events past retention max_lifetime
      auto room_result = purge_expired_room_events(ctx);
      total_processed += room_result["rooms_scanned"].get<int64_t>();
      total_deleted += room_result["events_deleted"].get<int64_t>();
      details["room_events"] = room_result;

      // 1b. Purge redacted events if configured
      if (policy_->purge_redacted_events_immediately) {
        auto redacted_result = purge_redacted_events(ctx);
        total_processed += redacted_result["events_scanned"].get<int64_t>();
        total_deleted += redacted_result["events_deleted"].get<int64_t>();
        details["redacted_events"] = redacted_result;
      }

      // 1c. Purge orphaned event relations
      auto relations_result = purge_orphaned_event_relations(ctx);
      total_processed += relations_result["scanned"].get<int64_t>();
      total_deleted += relations_result["deleted"].get<int64_t>();
      details["orphaned_relations"] = relations_result;

      // 1d. Purge orphaned event_json entries
      auto json_result = purge_orphaned_event_json(ctx);
      total_processed += json_result["scanned"].get<int64_t>();
      total_deleted += json_result["deleted"].get<int64_t>();
      details["orphaned_event_json"] = json_result;

      // 1e. Purge old event_auth entries for purged events
      auto auth_result = purge_orphaned_event_auth(ctx);
      total_processed += auth_result["scanned"].get<int64_t>();
      total_deleted += auth_result["deleted"].get<int64_t>();
      details["orphaned_event_auth"] = auth_result;

      // 1f. Purge old event_edges entries for purged events
      auto edges_result = purge_orphaned_event_edges(ctx);
      total_processed += edges_result["scanned"].get<int64_t>();
      total_deleted += edges_result["deleted"].get<int64_t>();
      details["orphaned_event_edges"] = edges_result;

      // 1g. Purge old state events outside current state
      auto state_result = purge_old_state_events(ctx);
      total_processed += state_result["scanned"].get<int64_t>();
      total_deleted += state_result["deleted"].get<int64_t>();
      details["old_state_events"] = state_result;

      auto dur = now_ms() - start;
      logger_.info("Event purge complete: processed=" + std::to_string(total_processed) +
                   " deleted=" + std::to_string(total_deleted) +
                   " duration_ms=" + std::to_string(dur));

      auto result = TaskRunResult::ok(HkTaskType::EVENT_PURGE,
                                       total_processed, total_deleted, dur);
      result.details = details;
      metrics_.record_run(HkTaskType::EVENT_PURGE, true, total_processed, total_deleted, dur);
      return result;

    } catch (const std::exception& e) {
      auto dur = now_ms() - start;
      logger_.error("Event purge failed: " + std::string(e.what()));
      metrics_.record_error(HkTaskType::EVENT_PURGE);
      auto result = TaskRunResult::fail(HkTaskType::EVENT_PURGE, e.what(), dur);
      result.details = details;
      return result;
    }
  }

private:
  json purge_expired_room_events(const TaskRunContext& ctx) {
    int64_t rooms_scanned = 0, events_deleted = 0;
    int64_t cutoff_ms = now_ms() - policy_->max_lifetime_ms;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kEventPurgeBatchSize;

    db_->runInteraction("hk_purge_events", [&](storage::LoggingTransaction& txn) {
      // Find rooms with events older than the default retention cutoff
      txn.execute(
        R"SQL(
          SELECT DISTINCT e.room_id
          FROM events e
          WHERE e.origin_server_ts < ?
            AND e.origin_server_ts > 0
          ORDER BY e.room_id
        )SQL",
        {cutoff_ms}
      );
      auto rooms = txn.fetchall();

      for (auto& row : rooms) {
        std::string room_id = row[0].value.value_or("");
        if (room_id.empty()) continue;

        int64_t room_cutoff = now_ms() - policy_->effective_max_lifetime_ms(room_id);

        // Find the topological_ordering boundary for this room at the cutoff time
        txn.execute(
          R"SQL(
            SELECT COALESCE(MAX(topological_ordering), 0)
            FROM events
            WHERE room_id = ? AND origin_server_ts < ?
          )SQL",
          {room_id, room_cutoff}
        );
        auto topo_row = txn.fetchone();
        int64_t topo_boundary = topo_row && topo_row->at(0).value
            ? std::stoll(*topo_row->at(0).value) : 0;

        if (topo_boundary <= 0) { rooms_scanned++; continue; }

        // Get the stream_ordering boundary
        txn.execute(
          R"SQL(
            SELECT COALESCE(MAX(stream_ordering), 0)
            FROM events
            WHERE room_id = ? AND origin_server_ts < ?
          )SQL",
          {room_id, room_cutoff}
        );
        auto stream_row = txn.fetchone();
        int64_t stream_boundary = stream_row && stream_row->at(0).value
            ? std::stoll(*stream_row->at(0).value) : 0;

        // Delete events before the boundary, in batches
        int64_t batch_deleted = 0;
        do {
          txn.execute(
            R"SQL(
              DELETE FROM event_json
              WHERE event_id IN (
                SELECT event_id FROM events
                WHERE room_id = ? AND topological_ordering <= ?
                ORDER BY topological_ordering LIMIT ?
              )
            )SQL",
            {room_id, topo_boundary, batch}
          );
          txn.execute(
            R"SQL(
              DELETE FROM events
              WHERE room_id = ? AND topological_ordering <= ?
              ORDER BY topological_ordering LIMIT ?
            )SQL",
            {room_id, topo_boundary, batch}
          );

          batch_deleted = txn.rowcount();
          events_deleted += batch_deleted;
        } while (batch_deleted >= batch);

        // Clean up state_groups for purged events
        txn.execute(
          R"SQL(
            DELETE FROM state_groups_state
            WHERE state_group NOT IN (
              SELECT DISTINCT state_group FROM event_to_state_groups
            )
          )SQL",
          {}
        );

        // Clean up event_to_state_groups for purged events
        txn.execute(
          R"SQL(
            DELETE FROM event_to_state_groups
            WHERE event_id NOT IN (SELECT event_id FROM events)
          )SQL",
          {}
        );

        // Clean up event_forward_extremities for purged events
        txn.execute(
          R"SQL(
            DELETE FROM event_forward_extremities
            WHERE event_id NOT IN (SELECT event_id FROM events)
          )SQL",
          {}
        );

        // Clean up event_backward_extremities for purged events
        txn.execute(
          R"SQL(
            DELETE FROM event_backward_extremities
            WHERE event_id NOT IN (SELECT event_id FROM events)
          )SQL",
          {}
        );

        rooms_scanned++;

        if (ctx.max_runtime_ms > 0 && (now_ms() - ctx.started_at_ms) > ctx.max_runtime_ms) {
          break;
        }
      }
    });

    return json{{"rooms_scanned", rooms_scanned}, {"events_deleted", events_deleted}};
  }

  json purge_redacted_events(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kEventPurgeBatchSize;

    db_->runInteraction("hk_purge_redacted", [&](storage::LoggingTransaction& txn) {
      int64_t batch_deleted = 0;
      do {
        txn.execute(
          R"SQL(
            DELETE FROM event_json
            WHERE event_id IN (
              SELECT e.event_id FROM events e
              INNER JOIN redactions r ON e.event_id = r.redacts
              WHERE r.have_censored = 1
              LIMIT ?
            )
          )SQL",
          {batch}
        );
        batch_deleted = txn.rowcount();

        txn.execute(
          R"SQL(
            DELETE FROM events
            WHERE event_id IN (
              SELECT e.event_id FROM events e
              INNER JOIN redactions r ON e.event_id = r.redacts
              WHERE r.have_censored = 1
              LIMIT ?
            )
          )SQL",
          {batch}
        );
        int64_t db2 = txn.rowcount();
        scanned += batch_deleted;
        deleted += db2;
        if (db2 == 0) batch_deleted = 0;
      } while (batch_deleted >= batch);
    });

    return json{{"events_scanned", scanned}, {"events_deleted", deleted}};
  }

  json purge_orphaned_event_relations(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_purge_orphan_rels", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM event_relations
          WHERE event_id NOT IN (SELECT event_id FROM events)
             OR relates_to_id NOT IN (SELECT event_id FROM events)
        )SQL",
        {}
      );
      auto count_row = txn.fetchone();
      scanned = count_row && count_row->at(0).value
          ? std::stoll(*count_row->at(0).value) : 0;

      txn.execute(
        R"SQL(
          DELETE FROM event_relations
          WHERE event_id NOT IN (SELECT event_id FROM events)
             OR relates_to_id NOT IN (SELECT event_id FROM events)
        )SQL",
        {}
      );
      deleted = txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json purge_orphaned_event_json(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_purge_orphan_json", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM event_json WHERE event_id NOT IN (SELECT event_id FROM events)",
        {}
      );
      auto count_row = txn.fetchone();
      scanned = count_row && count_row->at(0).value
          ? std::stoll(*count_row->at(0).value) : 0;

      txn.execute(
        "DELETE FROM event_json WHERE event_id NOT IN (SELECT event_id FROM events)",
        {}
      );
      deleted = txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json purge_orphaned_event_auth(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_purge_orphan_auth", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM event_auth WHERE event_id NOT IN (SELECT event_id FROM events)",
        {}
      );
      auto count_row = txn.fetchone();
      scanned = count_row && count_row->at(0).value
          ? std::stoll(*count_row->at(0).value) : 0;

      txn.execute(
        "DELETE FROM event_auth WHERE event_id NOT IN (SELECT event_id FROM events)",
        {}
      );
      deleted = txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json purge_orphaned_event_edges(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_purge_orphan_edges", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM event_edges WHERE event_id NOT IN (SELECT event_id FROM events)",
        {}
      );
      auto count_row = txn.fetchone();
      scanned = count_row && count_row->at(0).value
          ? std::stoll(*count_row->at(0).value) : 0;

      txn.execute(
        "DELETE FROM event_edges WHERE event_id NOT IN (SELECT event_id FROM events)",
        {}
      );
      deleted = txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json purge_old_state_events(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_purge_old_state", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM state_events se
          WHERE se.event_id NOT IN (SELECT event_id FROM current_state_events)
            AND se.event_id NOT IN (
              SELECT event_id FROM event_forward_extremities
            )
            AND se.event_id NOT IN (
              SELECT event_id FROM event_backward_extremities
            )
        )SQL",
        {}
      );
      auto count_row = txn.fetchone();
      scanned = count_row && count_row->at(0).value
          ? std::stoll(*count_row->at(0).value) : 0;

      txn.execute(
        R"SQL(
          DELETE FROM state_events
          WHERE event_id NOT IN (SELECT event_id FROM current_state_events)
            AND event_id NOT IN (SELECT event_id FROM event_forward_extremities)
            AND event_id NOT IN (SELECT event_id FROM event_backward_extremities)
        )SQL",
        {}
      );
      deleted = txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  std::shared_ptr<storage::DatabasePool> db_;
  std::shared_ptr<RetentionPolicy> policy_;
  HousekeepingMetrics& metrics_;
  HkLogger& logger_;
};

// ============================================================================
// 2. ReceiptCleaner — Removes old receipts and compacts receipt storage
// ============================================================================
class ReceiptCleaner {
public:
  ReceiptCleaner(std::shared_ptr<storage::DatabasePool> db,
                 HousekeepingMetrics& metrics)
    : db_(std::move(db)), metrics_(metrics),
      logger_(get_hk_logger("progressive.housekeeping.receipt_cleaner")) {}

  TaskRunResult run(const TaskRunContext& ctx) {
    auto start = now_ms();
    int64_t total_processed = 0, total_deleted = 0;

    try {
      logger_.info("Starting receipt cleanup");

      // 2a. Remove old linearized receipts beyond retention period
      auto lin_result = purge_old_linearized_receipts(ctx);
      total_deleted += lin_result["deleted"].get<int64_t>();
      total_processed += lin_result["scanned"].get<int64_t>();

      // 2b. Remove stale m.fully_read markers
      auto fr_result = purge_stale_fully_read(ctx);
      total_deleted += fr_result["deleted"].get<int64_t>();
      total_processed += fr_result["scanned"].get<int64_t>();

      // 2c. Compact receipt_graph — remove old entries
      auto graph_result = compact_receipt_graph(ctx);
      total_deleted += graph_result["deleted"].get<int64_t>();
      total_processed += graph_result["scanned"].get<int64_t>();

      // 2d. Remove receipts for rooms where the user has left
      auto left_result = purge_left_room_receipts(ctx);
      total_deleted += left_result["deleted"].get<int64_t>();
      total_processed += left_result["scanned"].get<int64_t>();

      auto dur = now_ms() - start;
      auto result = TaskRunResult::ok(HkTaskType::RECEIPT_CLEANUP,
                                       total_processed, total_deleted, dur);
      result.details = json{
        {"linearized", lin_result},
        {"fully_read", fr_result},
        {"receipt_graph", graph_result},
        {"left_rooms", left_result}
      };
      metrics_.record_run(HkTaskType::RECEIPT_CLEANUP, true, total_processed, total_deleted, dur);
      return result;

    } catch (const std::exception& e) {
      auto dur = now_ms() - start;
      metrics_.record_error(HkTaskType::RECEIPT_CLEANUP);
      return TaskRunResult::fail(HkTaskType::RECEIPT_CLEANUP, e.what(), dur);
    }
  }

private:
  json purge_old_linearized_receipts(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kReceiptCleanupBatchSize;
    int64_t cutoff_ms = now_ms() - (kDefaultReceiptRetentionDays * 86400 * 1000LL);

    db_->runInteraction("hk_purge_old_receipts", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM receipts_linearized WHERE stream_id IN (SELECT stream_id FROM receipts_linearized ORDER BY stream_id DESC LIMIT -1 OFFSET ?)",
        {}
      );
      // Use simpler approach: count receipts before cutoff
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM receipts_linearized rl
          INNER JOIN events e ON rl.event_id = e.event_id
          WHERE e.origin_server_ts < ?
        )SQL",
        {cutoff_ms}
      );
      auto cnt_row = txn.fetchone();
      scanned = cnt_row && cnt_row->at(0).value
          ? std::stoll(*cnt_row->at(0).value) : 0;

      int64_t batch_deleted = 0;
      do {
        txn.execute(
          R"SQL(
            DELETE FROM receipts_linearized
            WHERE stream_id IN (
              SELECT rl.stream_id FROM receipts_linearized rl
              INNER JOIN events e ON rl.event_id = e.event_id
              WHERE e.origin_server_ts < ?
              LIMIT ?
            )
          )SQL",
          {cutoff_ms, batch}
        );
        batch_deleted = txn.rowcount();
        deleted += batch_deleted;
      } while (batch_deleted >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json purge_stale_fully_read(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;
    int64_t cutoff_ms = now_ms() - (kDefaultReceiptRetentionDays * 86400 * 1000LL);

    db_->runInteraction("hk_purge_fully_read", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM receipts_linearized
          WHERE receipt_type = 'm.fully_read'
        )SQL",
        {}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      if (scanned > 0) {
        txn.execute(
          R"SQL(
            DELETE FROM receipts_linearized
            WHERE receipt_type = 'm.fully_read'
              AND stream_id IN (
                SELECT rl.stream_id FROM receipts_linearized rl
                INNER JOIN events e ON rl.event_id = e.event_id
                WHERE rl.receipt_type = 'm.fully_read'
                  AND e.origin_server_ts < ?
              )
          )SQL",
          {cutoff_ms}
        );
        deleted = txn.rowcount();
      }
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json compact_receipt_graph(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_compact_receipt_graph", [&](storage::LoggingTransaction& txn) {
      // Remove receipt_graph entries where the user has no other receipts
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM receipts_graph rg
          WHERE rg.user_id NOT IN (
            SELECT DISTINCT user_id FROM receipts_linearized
          )
        )SQL",
        {}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      txn.execute(
        R"SQL(
          DELETE FROM receipts_graph
          WHERE user_id NOT IN (
            SELECT DISTINCT user_id FROM receipts_linearized
          )
        )SQL",
        {}
      );
      deleted = txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json purge_left_room_receipts(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_purge_left_receipts", [&](storage::LoggingTransaction& txn) {
      // Find rooms where the receipt user is no longer a member
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM receipts_linearized rl
          WHERE NOT EXISTS (
            SELECT 1 FROM room_memberships rm
            WHERE rm.room_id = rl.room_id
              AND rm.user_id = rl.user_id
              AND rm.membership IN ('join', 'invite')
          )
        )SQL",
        {}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      txn.execute(
        R"SQL(
          DELETE FROM receipts_linearized
          WHERE NOT EXISTS (
            SELECT 1 FROM room_memberships rm
            WHERE rm.room_id = receipts_linearized.room_id
              AND rm.user_id = receipts_linearized.user_id
              AND rm.membership IN ('join', 'invite')
          )
        )SQL",
        {}
      );
      deleted = txn.rowcount();

      txn.execute(
        R"SQL(
          DELETE FROM receipts_graph
          WHERE NOT EXISTS (
            SELECT 1 FROM room_memberships rm
            WHERE rm.room_id = receipts_graph.room_id
              AND rm.user_id = receipts_graph.user_id
              AND rm.membership IN ('join', 'invite')
          )
        )SQL",
        {}
      );
      deleted += txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  std::shared_ptr<storage::DatabasePool> db_;
  HousekeepingMetrics& metrics_;
  HkLogger& logger_;
};

// ============================================================================
// 3. PresenceCleaner — Prunes stale presence entries and marks users offline
// ============================================================================
class PresenceCleaner {
public:
  PresenceCleaner(std::shared_ptr<storage::DatabasePool> db,
                  HousekeepingMetrics& metrics)
    : db_(std::move(db)), metrics_(metrics),
      logger_(get_hk_logger("progressive.housekeeping.presence_cleaner")) {}

  TaskRunResult run(const TaskRunContext& ctx) {
    auto start = now_ms();
    int64_t total_processed = 0, total_deleted = 0;

    try {
      logger_.info("Starting presence cleanup");

      // 3a. Mark stale users as offline
      auto stale_result = mark_stale_users_offline(ctx);
      total_processed += stale_result["processed"].get<int64_t>();
      total_deleted += stale_result["deleted"].get<int64_t>();

      // 3b. Prune old presence_stream entries
      auto stream_result = prune_presence_stream(ctx);
      total_processed += stream_result["scanned"].get<int64_t>();
      total_deleted += stream_result["deleted"].get<int64_t>();

      // 3c. Clean up presence_list for deactivated users
      auto plist_result = clean_presence_list(ctx);
      total_processed += plist_result["scanned"].get<int64_t>();
      total_deleted += plist_result["deleted"].get<int64_t>();

      // 3d. Remove presence state for deleted users
      auto pstate_result = cleanup_presence_state(ctx);
      total_processed += pstate_result["scanned"].get<int64_t>();
      total_deleted += pstate_result["deleted"].get<int64_t>();

      auto dur = now_ms() - start;
      auto result = TaskRunResult::ok(HkTaskType::PRESENCE_CLEANUP,
                                       total_processed, total_deleted, dur);
      result.details = json{
        {"stale_users", stale_result},
        {"presence_stream", stream_result},
        {"presence_list", plist_result},
        {"presence_state", pstate_result}
      };
      metrics_.record_run(HkTaskType::PRESENCE_CLEANUP, true, total_processed, total_deleted, dur);
      return result;

    } catch (const std::exception& e) {
      auto dur = now_ms() - start;
      metrics_.record_error(HkTaskType::PRESENCE_CLEANUP);
      return TaskRunResult::fail(HkTaskType::PRESENCE_CLEANUP, e.what(), dur);
    }
  }

private:
  json mark_stale_users_offline(const TaskRunContext& ctx) {
    int64_t processed = 0, deleted = 0;
    int64_t cutoff_ms = now_ms() - (kDefaultPresenceMaxInactiveHours * 3600 * 1000LL);
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kPresenceCleanupBatchSize;

    db_->runInteraction("hk_mark_stale_offline", [&](storage::LoggingTransaction& txn) {
      // First count stale users
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM presence_stream
          WHERE last_active_ts < ?
            AND state = 'online'
        )SQL",
        {cutoff_ms}
      );
      auto cnt = txn.fetchone();
      processed = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      // Mark them as offline in batches
      int64_t batch_updated = 0;
      do {
        txn.execute(
          R"SQL(
            UPDATE presence_stream
            SET state = 'offline',
                status_msg = '',
                currently_active = 0,
                last_active_ts = last_active_ts
            WHERE stream_id IN (
              SELECT stream_id FROM presence_stream
              WHERE last_active_ts < ? AND state = 'online'
              LIMIT ?
            )
          )SQL",
          {cutoff_ms, batch}
        );
        batch_updated = txn.rowcount();
        deleted += batch_updated;
      } while (batch_updated >= batch);

      // Also update presence_state table
      txn.execute(
        R"SQL(
          UPDATE presence_state
          SET state = 'offline',
              status_msg = '',
              currently_active = 0
          WHERE last_active_ts < ?
            AND state = 'online'
        )SQL",
        {cutoff_ms}
      );
      deleted += txn.rowcount();
    });

    return json{{"processed", processed}, {"deleted", deleted}};
  }

  json prune_presence_stream(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kPresenceCleanupBatchSize;

    db_->runInteraction("hk_prune_presence_stream", [&](storage::LoggingTransaction& txn) {
      // Count entries before pruning
      txn.execute("SELECT COUNT(*) FROM presence_stream", {});
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      // Keep only the latest presence update per user (within retention window)
      int64_t cutoff_ms = now_ms() - (90LL * 86400 * 1000); // 90 day history
      int64_t batch_deleted = 0;
      do {
        txn.execute(
          "DELETE FROM presence_stream WHERE stream_id IN (SELECT stream_id FROM presence_stream WHERE last_active_ts < ? AND state = 'offline' LIMIT ?)",
          {cutoff_ms, batch}
        );
        batch_deleted = txn.rowcount();
        deleted += batch_deleted;
      } while (batch_deleted >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json clean_presence_list(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_clean_presence_list", [&](storage::LoggingTransaction& txn) {
      // Remove presence_list entries for users who don't exist
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM presence_list pl
          WHERE pl.observed_user_id NOT IN (
            SELECT name FROM users
          )
        )SQL",
        {}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      txn.execute(
        R"SQL(
          DELETE FROM presence_list
          WHERE observed_user_id NOT IN (SELECT name FROM users)
        )SQL",
        {}
      );
      deleted = txn.rowcount();

      // Also remove presence where the observer doesn't exist
      txn.execute(
        R"SQL(
          DELETE FROM presence_list
          WHERE user_id NOT IN (SELECT name FROM users)
        )SQL",
        {}
      );
      deleted += txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json cleanup_presence_state(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_clean_presence_state", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM presence_state
          WHERE user_id NOT IN (SELECT name FROM users)
        )SQL",
        {}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      txn.execute(
        "DELETE FROM presence_state WHERE user_id NOT IN (SELECT name FROM users)",
        {}
      );
      deleted = txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  std::shared_ptr<storage::DatabasePool> db_;
  HousekeepingMetrics& metrics_;
  HkLogger& logger_;
};

// ============================================================================
// 4. TokenExpiryManager — Cleans up expired access tokens, refresh tokens,
//    registration tokens, and various session tokens
// ============================================================================
class TokenExpiryManager {
public:
  TokenExpiryManager(std::shared_ptr<storage::DatabasePool> db,
                     HousekeepingMetrics& metrics)
    : db_(std::move(db)), metrics_(metrics),
      logger_(get_hk_logger("progressive.housekeeping.token_expiry")) {}

  TaskRunResult run(const TaskRunContext& ctx) {
    auto start = now_ms();
    int64_t total_processed = 0, total_deleted = 0;

    try {
      logger_.info("Starting token expiry cleanup");

      // 4a. Expire old access tokens
      auto at_result = expire_access_tokens(ctx);
      total_deleted += at_result["deleted"].get<int64_t>();
      total_processed += at_result["scanned"].get<int64_t>();

      // 4b. Expire old refresh tokens
      auto rt_result = expire_refresh_tokens(ctx);
      total_deleted += rt_result["deleted"].get<int64_t>();
      total_processed += rt_result["scanned"].get<int64_t>();

      // 4c. Clean up expired registration tokens
      auto reg_result = cleanup_registration_tokens(ctx);
      total_deleted += reg_result["deleted"].get<int64_t>();
      total_processed += reg_result["scanned"].get<int64_t>();

      // 4d. Clean up expired password reset tokens
      auto pw_result = cleanup_password_reset_tokens(ctx);
      total_deleted += pw_result["deleted"].get<int64_t>();
      total_processed += pw_result["scanned"].get<int64_t>();

      // 4e. Clean up expired threepid validation sessions
      auto tp_result = cleanup_threepid_sessions(ctx);
      total_deleted += tp_result["deleted"].get<int64_t>();
      total_processed += tp_result["scanned"].get<int64_t>();

      // 4f. Clean up expired UI auth sessions
      auto uia_result = cleanup_ui_auth_sessions(ctx);
      total_deleted += uia_result["deleted"].get<int64_t>();
      total_processed += uia_result["scanned"].get<int64_t>();

      // 4g. Clean up expired OIDC sessions
      auto oidc_result = cleanup_oidc_sessions(ctx);
      total_deleted += oidc_result["deleted"].get<int64_t>();
      total_processed += oidc_result["scanned"].get<int64_t>();

      // 4h. Clean up expired login tokens
      auto login_result = cleanup_login_tokens(ctx);
      total_deleted += login_result["deleted"].get<int64_t>();
      total_processed += login_result["scanned"].get<int64_t>();

      auto dur = now_ms() - start;
      auto result = TaskRunResult::ok(HkTaskType::TOKEN_EXPIRY,
                                       total_processed, total_deleted, dur);
      result.details = json{
        {"access_tokens", at_result},
        {"refresh_tokens", rt_result},
        {"registration_tokens", reg_result},
        {"password_reset_tokens", pw_result},
        {"threepid_sessions", tp_result},
        {"ui_auth_sessions", uia_result},
        {"oidc_sessions", oidc_result},
        {"login_tokens", login_result}
      };
      metrics_.record_run(HkTaskType::TOKEN_EXPIRY, true, total_processed, total_deleted, dur);
      return result;

    } catch (const std::exception& e) {
      auto dur = now_ms() - start;
      metrics_.record_error(HkTaskType::TOKEN_EXPIRY);
      return TaskRunResult::fail(HkTaskType::TOKEN_EXPIRY, e.what(), dur);
    }
  }

private:
  json expire_access_tokens(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kTokenExpiryBatchSize;
    int64_t cutoff_ms = now_ms() - (kDefaultAccessTokenMaxAgeDays * 86400 * 1000LL);

    db_->runInteraction("hk_expire_access_tokens", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM access_tokens WHERE valid_until_ms > 0 AND valid_until_ms < ?",
        {now_ms()}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      // Delete tokens with expired valid_until_ms
      txn.execute(
        "DELETE FROM access_tokens WHERE valid_until_ms > 0 AND valid_until_ms < ?",
        {now_ms()}
      );
      deleted += txn.rowcount();

      // Delete tokens that have never been used and are very old
      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM access_tokens WHERE last_validated < ? AND used = 0 LIMIT ?",
          {cutoff_ms, batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json expire_refresh_tokens(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kTokenExpiryBatchSize;
    int64_t cutoff_ms = now_ms() - (kDefaultRefreshTokenMaxAgeDays * 86400 * 1000LL);

    db_->runInteraction("hk_expire_refresh_tokens", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM refresh_tokens WHERE expiry_ts > 0 AND expiry_ts < ?",
        {now_ms()}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      txn.execute(
        "DELETE FROM refresh_tokens WHERE expiry_ts > 0 AND expiry_ts < ?",
        {now_ms()}
      );
      deleted += txn.rowcount();

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM refresh_tokens WHERE created_at < ? AND (expiry_ts = 0 OR expiry_ts < ?) LIMIT ?",
          {cutoff_ms, now_ms(), batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json cleanup_registration_tokens(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kTokenExpiryBatchSize;

    db_->runInteraction("hk_cleanup_reg_tokens", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM registration_tokens WHERE expiry_time > 0 AND expiry_time < ?",
        {now_ms()}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM registration_tokens WHERE (expiry_time > 0 AND expiry_time < ?) OR (uses_allowed > 0 AND pending + completed >= uses_allowed) LIMIT ?",
          {now_ms(), batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json cleanup_password_reset_tokens(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kTokenExpiryBatchSize;

    db_->runInteraction("hk_cleanup_pw_reset", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM password_reset_tokens WHERE expiry_ts < ?",
        {now_ms()}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM password_reset_tokens WHERE expiry_ts < ? LIMIT ?",
          {now_ms(), batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json cleanup_threepid_sessions(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kTokenExpiryBatchSize;

    db_->runInteraction("hk_cleanup_threepid", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM threepid_validation_sessions WHERE validated_at IS NULL AND added_at < ?",
        {hours_ago_sec(24) * 1000}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM threepid_validation_sessions WHERE validated_at IS NULL AND added_at < ? LIMIT ?",
          {hours_ago_sec(24) * 1000, batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);

      // Also clean up expired validated sessions
      txn.execute(
        "DELETE FROM threepid_validation_sessions WHERE validated_at IS NOT NULL AND validated_at < ?",
        {days_ago_ms(30)}
      );
      deleted += txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json cleanup_ui_auth_sessions(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kTokenExpiryBatchSize;

    db_->runInteraction("hk_cleanup_uia", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM ui_auth_sessions WHERE expiry_time > 0 AND expiry_time < ?",
        {now_ms()}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM ui_auth_sessions WHERE expiry_time > 0 AND expiry_time < ? LIMIT ?",
          {now_ms(), batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json cleanup_oidc_sessions(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kTokenExpiryBatchSize;

    db_->runInteraction("hk_cleanup_oidc", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM oidc_sessions WHERE expiry_ts < ?",
        {now_ms()}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM oidc_sessions WHERE expiry_ts < ? LIMIT ?",
          {now_ms(), batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json cleanup_login_tokens(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kTokenExpiryBatchSize;

    db_->runInteraction("hk_cleanup_login_tokens", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM login_tokens WHERE expiry_ts < ?",
        {now_ms()}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM login_tokens WHERE expiry_ts < ? LIMIT ?",
          {now_ms(), batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  std::shared_ptr<storage::DatabasePool> db_;
  HousekeepingMetrics& metrics_;
  HkLogger& logger_;
};

// ============================================================================
// 5. MediaCacheCleaner — Evicts expired remote media and cleans up media
//    storage metadata
// ============================================================================
class MediaCacheCleaner {
public:
  MediaCacheCleaner(std::shared_ptr<storage::DatabasePool> db,
                    HousekeepingMetrics& metrics)
    : db_(std::move(db)), metrics_(metrics),
      logger_(get_hk_logger("progressive.housekeeping.media_cache_cleaner")) {}

  TaskRunResult run(const TaskRunContext& ctx) {
    auto start = now_ms();
    int64_t total_processed = 0, total_deleted = 0;

    try {
      logger_.info("Starting media cache cleanup");

      // 5a. Evict expired remote media cache entries
      auto remote_result = evict_expired_remote_media(ctx);
      total_deleted += remote_result["deleted"].get<int64_t>();
      total_processed += remote_result["scanned"].get<int64_t>();

      // 5b. Remove orphaned remote media thumbnails
      auto thumb_result = remove_orphaned_thumbnails(ctx);
      total_deleted += thumb_result["deleted"].get<int64_t>();
      total_processed += thumb_result["scanned"].get<int64_t>();

      // 5c. Clean up quarantined media past expiry
      auto quarantine_result = cleanup_quarantined_media(ctx);
      total_deleted += quarantine_result["deleted"].get<int64_t>();
      total_processed += quarantine_result["scanned"].get<int64_t>();

      // 5d. Remove media entries for deleted users
      auto orphan_local_result = remove_orphaned_local_media(ctx);
      total_deleted += orphan_local_result["deleted"].get<int64_t>();
      total_processed += orphan_local_result["scanned"].get<int64_t>();

      // 5e. Enforce per-user media size quotas (mark for review)
      auto quota_result = enforce_media_quotas(ctx);
      total_processed += quota_result["users_checked"].get<int64_t>();

      auto dur = now_ms() - start;
      auto result = TaskRunResult::ok(HkTaskType::MEDIA_CACHE_CLEANUP,
                                       total_processed, total_deleted, dur);
      result.details = json{
        {"remote_media", remote_result},
        {"orphaned_thumbnails", thumb_result},
        {"quarantined", quarantine_result},
        {"orphaned_local", orphan_local_result},
        {"quota_enforcement", quota_result}
      };
      metrics_.record_run(HkTaskType::MEDIA_CACHE_CLEANUP, true, total_processed, total_deleted, dur);
      return result;

    } catch (const std::exception& e) {
      auto dur = now_ms() - start;
      metrics_.record_error(HkTaskType::MEDIA_CACHE_CLEANUP);
      return TaskRunResult::fail(HkTaskType::MEDIA_CACHE_CLEANUP, e.what(), dur);
    }
  }

private:
  json evict_expired_remote_media(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kMediaCacheBatchSize;
    int64_t cutoff_ms = now_ms() - (kDefaultRemoteMediaCacheExpiryDays * 86400 * 1000LL);

    db_->runInteraction("hk_evict_remote_media", [&](storage::LoggingTransaction& txn) {
      // Count expired entries
      txn.execute(
        "SELECT COUNT(*) FROM remote_media_cache WHERE last_access_ts < ?",
        {cutoff_ms}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      // Delete thumbnails first
      int64_t batch_d = 0;
      do {
        txn.execute(
          R"SQL(
            DELETE FROM remote_media_cache_thumbnails
            WHERE (media_origin, media_id) IN (
              SELECT media_origin, media_id FROM remote_media_cache
              WHERE last_access_ts < ?
              LIMIT ?
            )
          )SQL",
          {cutoff_ms, batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);

      // Delete main entries
      int64_t batch_e = 0;
      do {
        txn.execute(
          "DELETE FROM remote_media_cache WHERE last_access_ts < ? LIMIT ?",
          {cutoff_ms, batch}
        );
        batch_e = txn.rowcount();
        deleted += batch_e;
      } while (batch_e >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json remove_orphaned_thumbnails(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_remove_orphan_thumbs", [&](storage::LoggingTransaction& txn) {
      // Orphaned remote thumbnails
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM remote_media_cache_thumbnails rmct
          WHERE NOT EXISTS (
            SELECT 1 FROM remote_media_cache rmc
            WHERE rmc.media_origin = rmct.media_origin
              AND rmc.media_id = rmct.media_id
          )
        )SQL",
        {}
      );
      auto cnt = txn.fetchone();
      scanned += cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      txn.execute(
        R"SQL(
          DELETE FROM remote_media_cache_thumbnails
          WHERE NOT EXISTS (
            SELECT 1 FROM remote_media_cache rmc
            WHERE rmc.media_origin = remote_media_cache_thumbnails.media_origin
              AND rmc.media_id = remote_media_cache_thumbnails.media_id
          )
        )SQL",
        {}
      );
      deleted += txn.rowcount();

      // Orphaned local thumbnails
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM local_media_repository_thumbnails lmrt
          WHERE NOT EXISTS (
            SELECT 1 FROM local_media_repository lmr
            WHERE lmr.media_id = lmrt.media_id
          )
        )SQL",
        {}
      );
      cnt = txn.fetchone();
      scanned += cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      txn.execute(
        R"SQL(
          DELETE FROM local_media_repository_thumbnails
          WHERE NOT EXISTS (
            SELECT 1 FROM local_media_repository lmr
            WHERE lmr.media_id = local_media_repository_thumbnails.media_id
          )
        )SQL",
        {}
      );
      deleted += txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json cleanup_quarantined_media(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kMediaCacheBatchSize;
    // Delete quarantined media older than 90 days
    int64_t cutoff_ms = now_ms() - (90LL * 86400 * 1000);

    db_->runInteraction("hk_cleanup_quarantined", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM local_media_repository WHERE quarantined_by IS NOT NULL AND created_ts < ?",
        {cutoff_ms}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM local_media_repository_thumbnails WHERE media_id IN (SELECT media_id FROM local_media_repository WHERE quarantined_by IS NOT NULL AND created_ts < ? LIMIT ?)",
          {cutoff_ms, batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);

      int64_t batch_e = 0;
      do {
        txn.execute(
          "DELETE FROM local_media_repository WHERE quarantined_by IS NOT NULL AND created_ts < ? LIMIT ?",
          {cutoff_ms, batch}
        );
        batch_e = txn.rowcount();
        deleted += batch_e;
      } while (batch_e >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json remove_orphaned_local_media(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kMediaCacheBatchSize;

    db_->runInteraction("hk_remove_orphan_local_media", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM local_media_repository lmr
          WHERE lmr.user_id NOT IN (SELECT name FROM users)
        )SQL",
        {}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM local_media_repository_thumbnails WHERE media_id IN (SELECT media_id FROM local_media_repository WHERE user_id NOT IN (SELECT name FROM users) LIMIT ?)",
          {batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);

      int64_t batch_e = 0;
      do {
        txn.execute(
          "DELETE FROM local_media_repository WHERE user_id NOT IN (SELECT name FROM users) LIMIT ?",
          {batch}
        );
        batch_e = txn.rowcount();
        deleted += batch_e;
      } while (batch_e >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json enforce_media_quotas(const TaskRunContext& /*ctx*/) {
    int64_t users_checked = 0;
    std::vector<json> over_quota;

    db_->runInteraction("hk_enforce_quotas", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        R"SQL(
          SELECT user_id,
                 COUNT(*) as media_count,
                 COALESCE(SUM(media_length), 0) as total_bytes
          FROM local_media_repository
          WHERE user_id IS NOT NULL
          GROUP BY user_id
          ORDER BY total_bytes DESC
        )SQL",
        {}
      );

      int64_t quota_limit = 1024LL * 1024 * 1024; // 1 GB default
      for (auto& row : txn.fetchall()) {
        std::string uid = row[0].value.value_or("");
        int64_t count = row[1].value ? std::stoll(*row[1].value) : 0;
        int64_t total = row[2].value ? std::stoll(*row[2].value) : 0;
        users_checked++;

        if (total > quota_limit) {
          json entry;
          entry["user_id"] = uid;
          entry["media_count"] = count;
          entry["total_bytes"] = total;
          entry["quota_bytes"] = quota_limit;
          entry["over_by_bytes"] = total - quota_limit;
          over_quota.push_back(entry);
        }
      }
    });

    return json{{"users_checked", users_checked}, {"over_quota", over_quota}};
  }

  std::shared_ptr<storage::DatabasePool> db_;
  HousekeepingMetrics& metrics_;
  HkLogger& logger_;
};

// ============================================================================
// 6. StatsAggregator — Aggregates daily user stats, room stats, and server-
//    wide metrics for admin dashboards and monitoring
// ============================================================================
class StatsAggregator {
public:
  StatsAggregator(std::shared_ptr<storage::DatabasePool> db,
                  HousekeepingMetrics& metrics)
    : db_(std::move(db)), metrics_(metrics),
      logger_(get_hk_logger("progressive.housekeeping.stats_aggregator")) {}

  TaskRunResult run(const TaskRunContext& ctx) {
    auto start = now_ms();
    int64_t total_processed = 0, total_deleted = 0;

    try {
      logger_.info("Starting stats aggregation");

      // 6a. Aggregate daily active users (DAU)
      auto dau_result = aggregate_dau(ctx);
      total_processed += dau_result["users_counted"].get<int64_t>();

      // 6b. Aggregate monthly active users (MAU)
      auto mau_result = aggregate_mau(ctx);
      total_processed += mau_result["users_counted"].get<int64_t>();

      // 6c. Aggregate room statistics
      auto room_stats = aggregate_room_stats(ctx);
      total_processed += room_stats["rooms_processed"].get<int64_t>();

      // 6d. Snap server-wide totals
      auto server_stats = snap_server_totals(ctx);
      total_processed += server_stats["tables_checked"].get<int64_t>();

      // 6e. Aggregate event throughput time series
      auto throughput = aggregate_event_throughput(ctx);
      total_processed += throughput["buckets_processed"].get<int64_t>();

      // 6f. Aggregate federation throughput
      auto fed_stats = aggregate_federation_stats(ctx);
      total_processed += fed_stats["destinations_checked"].get<int64_t>();

      // 6g. Prune old stats entries beyond retention
      auto prune_result = prune_old_stats(ctx);
      total_deleted += prune_result["deleted"].get<int64_t>();

      auto dur = now_ms() - start;
      auto result = TaskRunResult::ok(HkTaskType::STATS_AGGREGATION,
                                       total_processed, total_deleted, dur);
      result.details = json{
        {"dau", dau_result},
        {"mau", mau_result},
        {"room_stats", room_stats},
        {"server_totals", server_stats},
        {"event_throughput", throughput},
        {"federation", fed_stats},
        {"pruned", prune_result}
      };
      metrics_.record_run(HkTaskType::STATS_AGGREGATION, true, total_processed, total_deleted, dur);
      return result;

    } catch (const std::exception& e) {
      auto dur = now_ms() - start;
      metrics_.record_error(HkTaskType::STATS_AGGREGATION);
      return TaskRunResult::fail(HkTaskType::STATS_AGGREGATION, e.what(), dur);
    }
  }

private:
  json aggregate_dau(const TaskRunContext& /*ctx*/) {
    int64_t users_counted = 0;
    int64_t today_midnight = midnight_utc_sec();

    db_->runInteraction("hk_aggregate_dau", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        R"SQL(
          INSERT OR REPLACE INTO stats_daily_users (date_sec, user_count, bucket_type)
          SELECT ?, COUNT(DISTINCT e.sender), 'dau'
          FROM events e
          WHERE e.origin_server_ts >= ? AND e.origin_server_ts < ?
        )SQL",
        {today_midnight, today_midnight * 1000LL, (today_midnight + 86400) * 1000LL}
      );

      txn.execute(
        R"SQL(
          SELECT user_count FROM stats_daily_users
          WHERE date_sec = ? AND bucket_type = 'dau'
        )SQL",
        {today_midnight}
      );
      auto row = txn.fetchone();
      users_counted = row && row->at(0).value ? std::stoll(*row->at(0).value) : 0;
    });

    return json{{"users_counted", users_counted}, {"date", iso8601_from_ts(today_midnight)}};
  }

  json aggregate_mau(const TaskRunContext& /*ctx*/) {
    int64_t users_counted = 0;
    int64_t first_of_month = first_of_month_sec();

    db_->runInteraction("hk_aggregate_mau", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        R"SQL(
          INSERT OR REPLACE INTO stats_monthly_users (month_sec, user_count)
          SELECT ?, COUNT(DISTINCT e.sender)
          FROM events e
          WHERE e.origin_server_ts >= ? AND e.origin_server_ts < ?
        )SQL",
        {first_of_month, first_of_month * 1000LL, now_sec() * 1000LL}
      );

      txn.execute(
        "SELECT user_count FROM stats_monthly_users WHERE month_sec = ?",
        {first_of_month}
      );
      auto row = txn.fetchone();
      users_counted = row && row->at(0).value ? std::stoll(*row->at(0).value) : 0;
    });

    return json{{"users_counted", users_counted}, {"month_sec", first_of_month}};
  }

  json aggregate_room_stats(const TaskRunContext& ctx) {
    int64_t rooms_processed = 0;
    int64_t total_events = 0;
    int64_t total_messages = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kStatsRoomBatchSize;

    db_->runInteraction("hk_aggregate_room_stats", [&](storage::LoggingTransaction& txn) {
      txn.execute("SELECT COUNT(*) FROM rooms", {});
      auto cnt = txn.fetchone();
      rooms_processed = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      // Total events count
      txn.execute("SELECT COUNT(*) FROM events", {});
      auto evt = txn.fetchone();
      total_events = evt && evt->at(0).value ? std::stoll(*evt->at(0).value) : 0;

      // Total messages count
      txn.execute(
        "SELECT COUNT(*) FROM events WHERE type = 'm.room.message'",
        {}
      );
      auto msg = txn.fetchone();
      total_messages = msg && msg->at(0).value ? std::stoll(*msg->at(0).value) : 0;

      // Per-room event count aggregation
      txn.execute(
        R"SQL(
          INSERT OR REPLACE INTO stats_room_daily (room_id, date_sec, event_count, message_count, member_count)
          SELECT e.room_id, ?, COUNT(*),
                 SUM(CASE WHEN e.type = 'm.room.message' THEN 1 ELSE 0 END),
                 (SELECT COUNT(*) FROM room_memberships rm
                  WHERE rm.room_id = e.room_id AND rm.membership = 'join')
          FROM events e
          WHERE e.origin_server_ts >= ? AND e.origin_server_ts < ?
          GROUP BY e.room_id
          ORDER BY COUNT(*) DESC
          LIMIT ?
        )SQL",
        {now_sec() - 86400, (now_sec() - 86400) * 1000LL, now_sec() * 1000LL, batch}
      );
    });

    return json{
      {"rooms_processed", rooms_processed},
      {"total_events", total_events},
      {"total_messages", total_messages}
    };
  }

  json snap_server_totals(const TaskRunContext& /*ctx*/) {
    int64_t tables_checked = 0;
    int64_t total_users = 0;
    int64_t total_rooms = 0;
    int64_t total_devices = 0;
    int64_t total_tokens = 0;
    int64_t total_media_local = 0;
    int64_t total_media_remote = 0;

    db_->runInteraction("hk_snap_totals", [&](storage::LoggingTransaction& txn) {
      tables_checked = 7;

      txn.execute("SELECT COUNT(*) FROM users", {});
      auto row = txn.fetchone();
      total_users = row && row->at(0).value ? std::stoll(*row->at(0).value) : 0;

      txn.execute("SELECT COUNT(*) FROM rooms", {});
      row = txn.fetchone();
      total_rooms = row && row->at(0).value ? std::stoll(*row->at(0).value) : 0;

      txn.execute("SELECT COUNT(*) FROM devices", {});
      row = txn.fetchone();
      total_devices = row && row->at(0).value ? std::stoll(*row->at(0).value) : 0;

      txn.execute("SELECT COUNT(*) FROM access_tokens", {});
      row = txn.fetchone();
      total_tokens = row && row->at(0).value ? std::stoll(*row->at(0).value) : 0;

      txn.execute("SELECT COUNT(*), COALESCE(SUM(media_length), 0) FROM local_media_repository", {});
      row = txn.fetchone();
      if (row) {
        if (row->at(0).value) total_media_local = std::stoll(*row->at(0).value);
      }

      txn.execute("SELECT COUNT(*), COALESCE(SUM(media_length), 0) FROM remote_media_cache", {});
      row = txn.fetchone();
      if (row) {
        if (row->at(0).value) total_media_remote = std::stoll(*row->at(0).value);
      }

      int64_t snap_ts = now_sec();
      txn.execute(
        "INSERT INTO stats_server_snapshots (snapshot_ts, total_users, total_rooms, total_devices, total_access_tokens, total_local_media_files, total_remote_media_files) VALUES (?,?,?,?,?,?,?)",
        {snap_ts, total_users, total_rooms, total_devices, total_tokens, total_media_local, total_media_remote}
      );
    });

    return json{
      {"tables_checked", tables_checked},
      {"total_users", total_users},
      {"total_rooms", total_rooms},
      {"total_devices", total_devices},
      {"total_access_tokens", total_tokens},
      {"total_local_media_files", total_media_local},
      {"total_remote_media_files", total_media_remote}
    };
  }

  json aggregate_event_throughput(const TaskRunContext& /*ctx*/) {
    int64_t buckets_processed = 0;
    std::vector<json> throughput_data;

    db_->runInteraction("hk_event_throughput", [&](storage::LoggingTransaction& txn) {
      // Bucket by hour for the last 24 hours
      for (int h = 0; h < 24; ++h) {
        int64_t bucket_start_ms = now_ms() - ((h + 1) * 3600 * 1000LL);
        int64_t bucket_end_ms = bucket_start_ms + 3600 * 1000LL;

        txn.execute(
          R"SQL(
            SELECT COUNT(*),
                   COUNT(DISTINCT sender),
                   COUNT(DISTINCT room_id)
            FROM events
            WHERE origin_server_ts >= ? AND origin_server_ts < ?
          )SQL",
          {bucket_start_ms, bucket_end_ms}
        );
        auto row = txn.fetchone();
        if (row) {
          json bucket;
          bucket["hour_ago"] = h + 1;
          bucket["event_count"] = row->at(0).value ? std::stoll(*row->at(0).value) : 0;
          bucket["unique_senders"] = row->at(1).value ? std::stoll(*row->at(1).value) : 0;
          bucket["unique_rooms"] = row->at(2).value ? std::stoll(*row->at(2).value) : 0;
          throughput_data.push_back(bucket);
          buckets_processed++;
        }
      }
    });

    return json{{"buckets_processed", buckets_processed}, {"data", throughput_data}};
  }

  json aggregate_federation_stats(const TaskRunContext& /*ctx*/) {
    int64_t destinations_checked = 0;
    int64_t total_inbound = 0, total_outbound = 0;

    db_->runInteraction("hk_fed_stats", [&](storage::LoggingTransaction& txn) {
      txn.execute("SELECT COUNT(*) FROM federation_stream_position", {});
      auto row = txn.fetchone();
      destinations_checked = row && row->at(0).value ? std::stoll(*row->at(0).value) : 0;

      // Count recent federation events
      int64_t since = now_ms() - 3600 * 1000LL;
      txn.execute(
        "SELECT COUNT(*) FROM events WHERE sender NOT LIKE '%' || ? AND origin_server_ts >= ?",
        {":localhost", since}
      );
      row = txn.fetchone();
      total_inbound = row && row->at(0).value ? std::stoll(*row->at(0).value) : 0;

      // Outbound federation - destination retry stats
      txn.execute(
        "SELECT COUNT(*) FROM destinations WHERE retry_interval > 0",
        {}
      );
      row = txn.fetchone();
      total_outbound = row && row->at(0).value ? std::stoll(*row->at(0).value) : 0;
    });

    return json{
      {"destinations_checked", destinations_checked},
      {"total_recent_inbound", total_inbound},
      {"total_destinations_with_retry", total_outbound}
    };
  }

  json prune_old_stats(const TaskRunContext& ctx) {
    int64_t deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kStatsUserBatchSize;

    db_->runInteraction("hk_prune_old_stats", [&](storage::LoggingTransaction& txn) {
      int64_t cutoff_sec = now_sec() - (kDefaultStatsHistoryDays * 86400LL);

      txn.execute("DELETE FROM stats_daily_users WHERE date_sec < ?", {cutoff_sec});
      deleted += txn.rowcount();

      txn.execute("DELETE FROM stats_room_daily WHERE date_sec < ?", {cutoff_sec});
      deleted += txn.rowcount();

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM stats_server_snapshots WHERE snapshot_ts < ? LIMIT ?",
          {cutoff_sec, batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);
    });

    return json{{"deleted", deleted}};
  }

  static int64_t midnight_utc_sec() {
    auto now = chr::system_clock::now();
    auto tt = chr::system_clock::to_time_t(now);
    auto* utc = std::gmtime(&tt);
    utc->tm_hour = 0;
    utc->tm_min = 0;
    utc->tm_sec = 0;
    return static_cast<int64_t>(std::mktime(utc));
  }

  static int64_t first_of_month_sec() {
    auto now = chr::system_clock::now();
    auto tt = chr::system_clock::to_time_t(now);
    auto* utc = std::gmtime(&tt);
    utc->tm_mday = 1;
    utc->tm_hour = 0;
    utc->tm_min = 0;
    utc->tm_sec = 0;
    return static_cast<int64_t>(std::mktime(utc));
  }

  std::shared_ptr<storage::DatabasePool> db_;
  HousekeepingMetrics& metrics_;
  HkLogger& logger_;
};

// ============================================================================
// 7. DatabaseVacuumEngine — Runs VACUUM, ANALYZE, WAL checkpoint, and other
//    database maintenance operations
// ============================================================================
class DatabaseVacuumEngine {
public:
  DatabaseVacuumEngine(std::shared_ptr<storage::DatabasePool> db,
                       HousekeepingMetrics& metrics)
    : db_(std::move(db)), metrics_(metrics),
      logger_(get_hk_logger("progressive.housekeeping.database_vacuum")) {}

  TaskRunResult run(const TaskRunContext& ctx) {
    auto start = now_ms();
    int64_t total_processed = 0, total_deleted = 0;

    try {
      logger_.info("Starting database vacuum/maintenance");

      // 7a. Run PRAGMA optimize
      auto pragma_result = run_pragma_optimize(ctx);
      total_processed += pragma_result["operations"].get<int64_t>();

      // 7b. Run ANALYZE for query planner
      auto analyze_result = run_analyze(ctx);
      total_processed += analyze_result["tables_analyzed"].get<int64_t>();

      // 7c. WAL checkpoint
      auto wal_result = run_wal_checkpoint(ctx);
      total_processed += wal_result["pages_moved"].get<int64_t>();

      // 7d. VACUUM (only if file size warrants it)
      auto vacuum_result = run_vacuum(ctx);
      total_processed += vacuum_result["space_freed"].get<int64_t>();

      // 7e. Integrity check
      auto integrity_result = run_integrity_check(ctx);
      total_processed += integrity_result["tables_checked"].get<int64_t>();

      // 7f. Reindex fragmented indexes
      auto reindex_result = run_reindex(ctx);
      total_processed += reindex_result["indexes_rebuilt"].get<int64_t>();

      auto dur = now_ms() - start;
      auto result = TaskRunResult::ok(HkTaskType::DATABASE_VACUUM,
                                       total_processed, total_deleted, dur);
      result.details = json{
        {"pragma_optimize", pragma_result},
        {"analyze", analyze_result},
        {"wal_checkpoint", wal_result},
        {"vacuum", vacuum_result},
        {"integrity", integrity_result},
        {"reindex", reindex_result}
      };
      metrics_.record_run(HkTaskType::DATABASE_VACUUM, true, total_processed, total_deleted, dur);
      return result;

    } catch (const std::exception& e) {
      auto dur = now_ms() - start;
      metrics_.record_error(HkTaskType::DATABASE_VACUUM);
      return TaskRunResult::fail(HkTaskType::DATABASE_VACUUM, e.what(), dur);
    }
  }

private:
  json run_pragma_optimize(const TaskRunContext& /*ctx*/) {
    int64_t operations = 0;

    db_->runInteraction("hk_pragma_optimize", [&](storage::LoggingTransaction& txn) {
      try {
        txn.execute("PRAGMA optimize", {});
        operations++;
      } catch (...) {}

      try {
        txn.execute("PRAGMA analysis_limit=400", {});
        operations++;
      } catch (...) {}

      try {
        txn.execute("PRAGMA cache_size=-20000", {}); // 20MB cache
        operations++;
      } catch (...) {}

      try {
        txn.execute("PRAGMA journal_mode=WAL", {});
        operations++;
      } catch (...) {}

      try {
        txn.execute("PRAGMA synchronous=NORMAL", {});
        operations++;
      } catch (...) {}

      try {
        txn.execute("PRAGMA temp_store=MEMORY", {});
        operations++;
      } catch (...) {}
    });

    return json{{"operations", operations}};
  }

  json run_analyze(const TaskRunContext& /*ctx*/) {
    int64_t tables_analyzed = 0;

    db_->runInteraction("hk_analyze", [&](storage::LoggingTransaction& txn) {
      try {
        txn.execute("ANALYZE", {});
        tables_analyzed++;

        // Get table counts for logging
        txn.execute(
          "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
          {}
        );

        std::vector<std::string> tables;
        for (auto& row : txn.fetchall()) {
          if (row[0].value) tables.push_back(*row[0].value);
        }
        tables_analyzed = static_cast<int64_t>(tables.size());

        // Analyze stats tables
        try { txn.execute("ANALYZE sqlite_stat1", {}); } catch (...) {}
        try { txn.execute("ANALYZE sqlite_stat4", {}); } catch (...) {}
      } catch (...) {
        logger_.warn("ANALYZE failed, may not be supported");
      }
    });

    return json{{"tables_analyzed", tables_analyzed}};
  }

  json run_wal_checkpoint(const TaskRunContext& /*ctx*/) {
    int64_t pages_moved = 0;

    db_->runInteraction("hk_wal_checkpoint", [&](storage::LoggingTransaction& txn) {
      try {
        txn.execute("PRAGMA wal_checkpoint(TRUNCATE)", {});
        auto row = txn.fetchone();
        if (row) {
          // wal_checkpoint returns: busy(0/1), log, checkpointed
          // log = pages in WAL, checkpointed = pages moved to DB
          if (row->size() >= 2 && row->at(2).value) {
            pages_moved = std::stoll(*row->at(2).value);
          }
        }
      } catch (...) {
        logger_.warn("WAL checkpoint failed, may not be in WAL mode");
      }

      try {
        txn.execute("PRAGMA wal_checkpoint(PASSIVE)", {});
      } catch (...) {}
    });

    return json{{"pages_moved", pages_moved}};
  }

  json run_vacuum(const TaskRunContext& /*ctx*/) {
    int64_t space_freed = 0;
    bool vacuum_needed = false;

    db_->runInteraction("hk_get_db_size", [&](storage::LoggingTransaction& txn) {
      try {
        txn.execute(
          "SELECT page_count * page_size as total_size FROM pragma_page_count(), pragma_page_size()",
          {}
        );
        auto row = txn.fetchone();
        if (row && row->at(0).value) {
          int64_t total_size = std::stoll(*row->at(0).value);
          (void)total_size;

          // Count freelist pages
          txn.execute("PRAGMA freelist_count", {});
          auto fr = txn.fetchone();
          int64_t freelist = fr && fr->at(0).value ? std::stoll(*fr->at(0).value) : 0;

          // VACUUM if freelist pages > 10% of total
          int64_t total_pages = 0;
          txn.execute("PRAGMA page_count", {});
          auto pc = txn.fetchone();
          if (pc && pc->at(0).value) {
            total_pages = std::stoll(*pc->at(0).value);
          }

          if (total_pages > 0 && freelist * 10 > total_pages) {
            vacuum_needed = true;
          }
        }
      } catch (...) {
        // Alternate approach
        try {
          txn.execute("PRAGMA freelist_count", {});
          auto fr = txn.fetchone();
          if (fr && fr->at(0).value && std::stoll(*fr->at(0).value) > 1000) {
            vacuum_needed = true;
          }
        } catch (...) {}
      }
    });

    if (vacuum_needed) {
      db_->runInteraction("hk_vacuum", [&](storage::LoggingTransaction& txn) {
        // Get size before
        int64_t size_before = 0;
        try {
          txn.execute(
            "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
            {}
          );
          auto row = txn.fetchone();
          if (row && row->at(0).value) size_before = std::stoll(*row->at(0).value);
          txn.execute("VACUUM", {});

          txn.execute(
            "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
            {}
          );
          row = txn.fetchone();
          if (row && row->at(0).value) {
            int64_t size_after = std::stoll(*row->at(0).value);
            space_freed = std::max(int64_t(0), size_before - size_after);
          }
        } catch (...) {
          logger_.warn("VACUUM operation failed");
        }
      });
    }

    return json{{"space_freed", space_freed}, {"vacuum_performed", vacuum_needed}};
  }

  json run_integrity_check(const TaskRunContext& /*ctx*/) {
    int64_t tables_checked = 0;
    bool all_ok = true;

    db_->runInteraction("hk_integrity", [&](storage::LoggingTransaction& txn) {
      try {
        txn.execute("PRAGMA integrity_check", {});
        auto row = txn.fetchone();
        if (row && row->at(0).value) {
          std::string result = *row->at(0).value;
          if (result == "ok") {
            all_ok = true;
            tables_checked = 1;
          } else {
            all_ok = false;
            logger_.warn("Integrity check failed: " + result);
          }
        }
      } catch (...) {
        all_ok = false;
        logger_.warn("PRAGMA integrity_check not supported");
      }

      // Quick check
      try {
        txn.execute("PRAGMA quick_check", {});
        auto row = txn.fetchone();
        if (row && row->at(0).value && *row->at(0).value == "ok") {
          tables_checked++;
        }
      } catch (...) {}
    });

    return json{{"tables_checked", tables_checked}, {"all_ok", all_ok}};
  }

  json run_reindex(const TaskRunContext& /*ctx*/) {
    int64_t indexes_rebuilt = 0;

    db_->runInteraction("hk_reindex", [&](storage::LoggingTransaction& txn) {
      try {
        // Get list of user indexes (not sqlite_autoindex_* or sqlite_*)
        txn.execute(
          "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name",
          {}
        );

        std::vector<std::string> indexes;
        for (auto& row : txn.fetchall()) {
          if (row[0].value) {
            std::string name = *row[0].value;
            if (name.find("sqlite_autoindex") == std::string::npos) {
              indexes.push_back(name);
            }
          }
        }

        // Reindex each
        for (auto& idx_name : indexes) {
          try {
            txn.execute("REINDEX " + idx_name, {});
            indexes_rebuilt++;
          } catch (...) {
            // Skip indexes that fail
          }

          if (indexes_rebuilt > 50) break; // safety limit
        }
      } catch (...) {
        // Fallback: global reindex
        try {
          txn.execute("REINDEX", {});
          indexes_rebuilt = 1;
        } catch (...) {
          logger_.warn("REINDEX operation failed");
        }
      }
    });

    return json{{"indexes_rebuilt", indexes_rebuilt}};
  }

  std::shared_ptr<storage::DatabasePool> db_;
  HousekeepingMetrics& metrics_;
  HkLogger& logger_;
};

// ============================================================================
// 8. FederationRetryManager — Retries failed federation transactions with
//    exponential backoff, prunes stale destinations
// ============================================================================
class FederationRetryManager {
public:
  FederationRetryManager(std::shared_ptr<storage::DatabasePool> db,
                         HousekeepingMetrics& metrics)
    : db_(std::move(db)), metrics_(metrics),
      logger_(get_hk_logger("progressive.housekeeping.federation_retry")) {}

  TaskRunResult run(const TaskRunContext& ctx) {
    auto start = now_ms();
    int64_t total_processed = 0, total_deleted = 0;

    try {
      logger_.info("Starting federation retry cycle");

      // 8a. Find destinations due for retry
      auto retry_result = retry_due_destinations(ctx);
      total_processed += retry_result["destinations_processed"].get<int64_t>();

      // 8b. Prune destinations that have failed too many times
      auto prune_result = prune_dead_destinations(ctx);
      total_deleted += prune_result["deleted"].get<int64_t>();
      total_processed += prune_result["scanned"].get<int64_t>();

      // 8c. Clean up old federation stream positions
      auto stream_result = cleanup_federation_streams(ctx);
      total_deleted += stream_result["deleted"].get<int64_t>();
      total_processed += stream_result["scanned"].get<int64_t>();

      // 8d. Prune old device inbox messages for remote users
      auto inbox_result = prune_device_inbox(ctx);
      total_deleted += inbox_result["deleted"].get<int64_t>();
      total_processed += inbox_result["scanned"].get<int64_t>();

      auto dur = now_ms() - start;
      auto result = TaskRunResult::ok(HkTaskType::FEDERATION_RETRY,
                                       total_processed, total_deleted, dur);
      result.details = json{
        {"retry", retry_result},
        {"pruned", prune_result},
        {"stream_positions", stream_result},
        {"device_inbox", inbox_result}
      };
      metrics_.record_run(HkTaskType::FEDERATION_RETRY, true, total_processed, total_deleted, dur);
      return result;

    } catch (const std::exception& e) {
      auto dur = now_ms() - start;
      metrics_.record_error(HkTaskType::FEDERATION_RETRY);
      return TaskRunResult::fail(HkTaskType::FEDERATION_RETRY, e.what(), dur);
    }
  }

private:
  json retry_due_destinations(const TaskRunContext& ctx) {
    int64_t destinations_processed = 0;
    int64_t destinations_retried = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kFederationRetryBatchSize;

    db_->runInteraction("hk_retry_destinations", [&](storage::LoggingTransaction& txn) {
      // Find destinations where next_retry <= now
      txn.execute(
        R"SQL(
          SELECT destination, retry_interval, failure_count,
                 last_success, last_failure, next_retry
          FROM destinations
          WHERE next_retry <= ? AND next_retry > 0
          ORDER BY next_retry ASC
          LIMIT ?
        )SQL",
        {now_ms(), batch}
      );

      std::vector<std::tuple<std::string, int64_t, int64_t>> to_retry;
      for (auto& row : txn.fetchall()) {
        std::string dest = row[0].value.value_or("");
        int64_t retry_interval = row[1].value ? std::stoll(*row[1].value) : 0;
        int64_t failure_count = row[2].value ? std::stoll(*row[2].value) : 0;
        destinations_processed++;

        if (!dest.empty()) {
          // Mark for retry: set next_retry to 0 to indicate pending
          // Update retry interval with exponential backoff
          int64_t new_interval = static_cast<int64_t>(
              std::min(static_cast<double>(kRetryMaxIntervalMs),
                       retry_interval * kRetryBackoffMultiplier));
          if (new_interval < kRetryBaseIntervalMs) {
            new_interval = kRetryBaseIntervalMs;
          }

          txn.execute(
            "UPDATE destinations SET retry_interval = ?, next_retry = ? WHERE destination = ?",
            {new_interval, now_ms() + new_interval, dest}
          );
          destinations_retried++;
        }
      }
    });

    return json{
      {"destinations_processed", destinations_processed},
      {"destinations_retried", destinations_retried}
    };
  }

  json prune_dead_destinations(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_prune_destinations", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM destinations WHERE failure_count >= ?",
        {kRetryMaxFailuresBeforePrune}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      // Remove destinations that have failed too many times and haven't
      // succeeded in a long time (30 days)
      int64_t cutoff = now_ms() - (30LL * 86400 * 1000);
      txn.execute(
        R"SQL(
          DELETE FROM destinations
          WHERE failure_count >= ?
            AND (last_success = 0 OR last_success < ?)
        )SQL",
        {kRetryMaxFailuresBeforePrune, cutoff}
      );
      deleted = txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json cleanup_federation_streams(const TaskRunContext& /*ctx*/) {
    int64_t scanned = 0, deleted = 0;

    db_->runInteraction("hk_cleanup_fed_streams", [&](storage::LoggingTransaction& txn) {
      // Remove stream positions for destinations that don't exist
      txn.execute(
        R"SQL(
          SELECT COUNT(*) FROM federation_stream_position fsp
          WHERE NOT EXISTS (
            SELECT 1 FROM destinations d
            WHERE d.destination = fsp.type || '|' || fsp.instance_name
          )
        )SQL",
        {}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      txn.execute(
        R"SQL(
          DELETE FROM federation_stream_position
          WHERE NOT EXISTS (
            SELECT 1 FROM destinations d
            WHERE d.destination = federation_stream_position.type || '|' || federation_stream_position.instance_name
          )
        )SQL",
        {}
      );
      deleted = txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json prune_device_inbox(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kDeviceListPokeBatchSize;
    int64_t cutoff = now_ms() - (90LL * 86400 * 1000);

    db_->runInteraction("hk_prune_device_inbox", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM device_inbox WHERE created_ts < ?",
        {cutoff}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM device_inbox WHERE created_ts < ? LIMIT ?",
          {cutoff, batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  std::shared_ptr<storage::DatabasePool> db_;
  HousekeepingMetrics& metrics_;
  HkLogger& logger_;
};

// ============================================================================
// 9. DeviceListPokeSender — Sends batched device list update notifications
//    to remote servers for users whose devices have changed
// ============================================================================
class DeviceListPokeSender {
public:
  DeviceListPokeSender(std::shared_ptr<storage::DatabasePool> db,
                       HousekeepingMetrics& metrics)
    : db_(std::move(db)), metrics_(metrics),
      logger_(get_hk_logger("progressive.housekeeping.device_list_poke")) {}

  TaskRunResult run(const TaskRunContext& ctx) {
    auto start = now_ms();
    int64_t total_processed = 0, total_deleted = 0;

    try {
      logger_.info("Starting device list poke sender cycle");

      // 9a. Find users whose device lists have changed
      auto changed_result = find_changed_device_lists(ctx);
      total_processed += changed_result["users_found"].get<int64_t>();

      // 9b. Queue pending pokes to remote servers
      auto queue_result = queue_device_list_pokes(ctx);
      total_processed += queue_result["pokes_queued"].get<int64_t>();

      // 9c. Prune old device list stream entries
      auto prune_result = prune_device_list_stream(ctx);
      total_deleted += prune_result["deleted"].get<int64_t>();
      total_processed += prune_result["scanned"].get<int64_t>();

      // 9d. Clean up orphaned device list outbound pokes
      auto outbound_result = cleanup_device_list_outbound_pokes(ctx);
      total_deleted += outbound_result["deleted"].get<int64_t>();
      total_processed += outbound_result["scanned"].get<int64_t>();

      auto dur = now_ms() - start;
      auto result = TaskRunResult::ok(HkTaskType::DEVICE_LIST_POKE,
                                       total_processed, total_deleted, dur);
      result.details = json{
        {"changed_lists", changed_result},
        {"queued_pokes", queue_result},
        {"pruned_stream", prune_result},
        {"outbound_cleanup", outbound_result}
      };
      metrics_.record_run(HkTaskType::DEVICE_LIST_POKE, true, total_processed, total_deleted, dur);
      return result;

    } catch (const std::exception& e) {
      auto dur = now_ms() - start;
      metrics_.record_error(HkTaskType::DEVICE_LIST_POKE);
      return TaskRunResult::fail(HkTaskType::DEVICE_LIST_POKE, e.what(), dur);
    }
  }

private:
  json find_changed_device_lists(const TaskRunContext& ctx) {
    int64_t users_found = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kDeviceListPokeBatchSize;

    db_->runInteraction("hk_find_changed_devices", [&](storage::LoggingTransaction& txn) {
      // Count users with changed device lists (unread by stream ordering)
      txn.execute(
        R"SQL(
          SELECT COUNT(DISTINCT dl.user_id)
          FROM device_lists_stream dl
          WHERE dl.stream_id > (
            SELECT COALESCE(MAX(stream_id), 0) FROM device_lists_stream
          ) - ?
        )SQL",
        {batch}
      );
      auto cnt = txn.fetchone();
      users_found = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      // Get users who haven't had their device lists poked yet
      txn.execute(
        R"SQL(
          SELECT DISTINCT dl.user_id
          FROM device_lists_stream dl
          LEFT JOIN device_lists_outbound_pokes dop
            ON dl.user_id = dop.user_id
          WHERE dop.stream_id IS NULL OR dop.stream_id < dl.stream_id
          ORDER BY dl.stream_id ASC
          LIMIT ?
        )SQL",
        {batch}
      );
    });

    return json{{"users_found", users_found}};
  }

  json queue_device_list_pokes(const TaskRunContext& ctx) {
    int64_t pokes_queued = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kDeviceListPokeBatchSize;
    int64_t current_ts = now_ms();

    db_->runInteraction("hk_queue_pokes", [&](storage::LoggingTransaction& txn) {
      // Get users needing pokes and their remote servers
      txn.execute(
        R"SQL(
          SELECT DISTINCT dl.user_id, dl.stream_id
          FROM device_lists_stream dl
          LEFT JOIN device_lists_outbound_pokes dop
            ON dl.user_id = dop.user_id AND dl.stream_id = dop.stream_id
          WHERE dop.user_id IS NULL
          ORDER BY dl.stream_id ASC
          LIMIT ?
        )SQL",
        {batch}
      );

      std::vector<std::tuple<std::string, int64_t>> pending;
      for (auto& row : txn.fetchall()) {
        std::string uid = row[0].value.value_or("");
        int64_t sid = row[1].value ? std::stoll(*row[1].value) : 0;
        if (!uid.empty() && sid > 0) {
          pending.emplace_back(uid, sid);
        }
      }

      for (auto& [uid, sid] : pending) {
        // Extract server name from user_id
        auto colon_pos = uid.find(':');
        if (colon_pos == std::string::npos) continue;
        std::string server_name = uid.substr(colon_pos + 1);

        // Skip local users
        if (server_name == "localhost" || server_name.find("localhost:") == 0) continue;

        // Insert the outbound poke
        try {
          txn.execute(
            "INSERT INTO device_lists_outbound_pokes (destination, user_id, stream_id, ts) VALUES (?,?,?,?)",
            {server_name, uid, sid, current_ts}
          );
          pokes_queued++;
        } catch (...) {
          // Skip duplicates
        }
      }
    });

    return json{{"pokes_queued", pokes_queued}};
  }

  json prune_device_list_stream(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kDeviceListPokeBatchSize;
    int64_t cutoff = now_ms() - (90LL * 86400 * 1000);

    db_->runInteraction("hk_prune_device_stream", [&](storage::LoggingTransaction& txn) {
      txn.execute("SELECT COUNT(*) FROM device_lists_stream", {});
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      // Keep only the latest entry per user within retention
      txn.execute(
        R"SQL(
          DELETE FROM device_lists_stream
          WHERE stream_id NOT IN (
            SELECT MAX(stream_id) FROM device_lists_stream
            GROUP BY user_id
          )
          AND stream_id IN (
            SELECT stream_id FROM device_lists_stream
            ORDER BY stream_id ASC
            LIMIT ?
          )
        )SQL",
        {batch}
      );
      deleted = txn.rowcount();
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  json cleanup_device_list_outbound_pokes(const TaskRunContext& ctx) {
    int64_t scanned = 0, deleted = 0;
    int64_t batch = ctx.batch_size > 0 ? ctx.batch_size : kDeviceListPokeBatchSize;
    int64_t cutoff = now_ms() - (7LL * 86400 * 1000);

    db_->runInteraction("hk_cleanup_outbound_pokes", [&](storage::LoggingTransaction& txn) {
      txn.execute(
        "SELECT COUNT(*) FROM device_lists_outbound_pokes WHERE ts < ? AND sent = 1",
        {cutoff}
      );
      auto cnt = txn.fetchone();
      scanned = cnt && cnt->at(0).value ? std::stoll(*cnt->at(0).value) : 0;

      int64_t batch_d = 0;
      do {
        txn.execute(
          "DELETE FROM device_lists_outbound_pokes WHERE ts < ? AND sent = 1 LIMIT ?",
          {cutoff, batch}
        );
        batch_d = txn.rowcount();
        deleted += batch_d;
      } while (batch_d >= batch);
    });

    return json{{"scanned", scanned}, {"deleted", deleted}};
  }

  std::shared_ptr<storage::DatabasePool> db_;
  HousekeepingMetrics& metrics_;
  HkLogger& logger_;
};

// ============================================================================
// HousekeepingScheduler — Main orchestrator that schedules and runs all
//   housekeeping tasks on configurable intervals
// ============================================================================
class HousekeepingScheduler {
public:
  HousekeepingScheduler(std::shared_ptr<storage::DatabasePool> db)
    : db_(std::move(db)),
      metrics_(std::make_shared<HousekeepingMetrics>()),
      policy_(std::make_shared<RetentionPolicy>()),
      logger_(get_hk_logger("progressive.housekeeping.scheduler")),
      running_(false),
      shutdown_requested_(false) {

    // Initialize all task engines
    event_purger_    = std::make_unique<EventPurger>(db_, policy_, *metrics_);
    receipt_cleaner_ = std::make_unique<ReceiptCleaner>(db_, *metrics_);
    presence_cleaner_ = std::make_unique<PresenceCleaner>(db_, *metrics_);
    token_expiry_    = std::make_unique<TokenExpiryManager>(db_, *metrics_);
    media_cleaner_   = std::make_unique<MediaCacheCleaner>(db_, *metrics_);
    stats_agg_       = std::make_unique<StatsAggregator>(db_, *metrics_);
    vacuum_engine_   = std::make_unique<DatabaseVacuumEngine>(db_, *metrics_);
    fed_retry_       = std::make_unique<FederationRetryManager>(db_, *metrics_);
    device_poke_     = std::make_unique<DeviceListPokeSender>(db_, *metrics_);

    // Set default intervals
    intervals_[HkTaskType::EVENT_PURGE]         = kDefaultEventPurgeIntervalMs;
    intervals_[HkTaskType::RECEIPT_CLEANUP]     = kDefaultReceiptCleanupIntervalMs;
    intervals_[HkTaskType::PRESENCE_CLEANUP]    = kDefaultPresenceCleanupIntervalMs;
    intervals_[HkTaskType::TOKEN_EXPIRY]        = kDefaultTokenExpiryIntervalMs;
    intervals_[HkTaskType::MEDIA_CACHE_CLEANUP] = kDefaultMediaCacheCleanupIntervalMs;
    intervals_[HkTaskType::STATS_AGGREGATION]   = kDefaultStatsAggregationIntervalMs;
    intervals_[HkTaskType::DATABASE_VACUUM]     = kDefaultDatabaseVacuumIntervalMs;
    intervals_[HkTaskType::FEDERATION_RETRY]    = kDefaultFederationRetryIntervalMs;
    intervals_[HkTaskType::DEVICE_LIST_POKE]    = kDefaultDeviceListPokeIntervalMs;

    logger_.info("HousekeepingScheduler initialized with 9 task engines");
  }

  ~HousekeepingScheduler() {
    shutdown();
  }

  // ------------------------------------------------------------------------
  // Start the background scheduler thread
  // ------------------------------------------------------------------------
  void start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_) return;
    running_ = true;
    shutdown_requested_ = false;
    worker_ = std::thread(&HousekeepingScheduler::scheduler_loop, this);
    logger_.info("HousekeepingScheduler started");
  }

  // ------------------------------------------------------------------------
  // Request shutdown and join worker thread
  // ------------------------------------------------------------------------
  void shutdown() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!running_) return;
      shutdown_requested_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) {
      worker_.join();
    }
    {
      std::lock_guard<std::mutex> lock(mutex_);
      running_ = false;
    }
    logger_.info("HousekeepingScheduler shut down");
  }

  // ------------------------------------------------------------------------
  // Run a specific task immediately (for admin API trigger)
  // ------------------------------------------------------------------------
  TaskRunResult run_task_now(HkTaskType type, RunMode mode = RunMode::MANUAL,
                              const json& config = json::object()) {
    TaskRunContext ctx;
    ctx.type = type;
    ctx.mode = mode;
    ctx.started_at_ms = now_ms();
    ctx.batch_size = 0; // use defaults
    ctx.max_runtime_ms = 600'000; // 10 min max
    ctx.dry_run = false;
    ctx.config = config;

    return execute_task(type, ctx);
  }

  // ------------------------------------------------------------------------
  // Run all tasks (for startup or admin trigger)
  // ------------------------------------------------------------------------
  json run_all_tasks(RunMode mode = RunMode::MANUAL) {
    json results = json::array();
    static const HkTaskType all_types[] = {
      HkTaskType::EVENT_PURGE,
      HkTaskType::RECEIPT_CLEANUP,
      HkTaskType::PRESENCE_CLEANUP,
      HkTaskType::TOKEN_EXPIRY,
      HkTaskType::MEDIA_CACHE_CLEANUP,
      HkTaskType::STATS_AGGREGATION,
      HkTaskType::DATABASE_VACUUM,
      HkTaskType::FEDERATION_RETRY,
      HkTaskType::DEVICE_LIST_POKE
    };

    for (auto type : all_types) {
      auto result = run_task_now(type, mode);
      json r;
      r["task"] = hk_task_name(type);
      r["success"] = result.success;
      r["items_processed"] = result.items_processed;
      r["items_deleted"] = result.items_deleted;
      r["duration_ms"] = result.duration_ms;
      if (!result.success) r["error"] = result.error_message;
      if (!result.details.is_null()) r["details"] = result.details;
      results.push_back(r);

      // Store last run times
      last_run_[type] = now_ms();
    }

    return results;
  }

  // ------------------------------------------------------------------------
  // Get metrics snapshot
  // ------------------------------------------------------------------------
  json get_metrics() const { return metrics_->to_json(); }

  // ------------------------------------------------------------------------
  // Get/set intervals for task scheduling
  // ------------------------------------------------------------------------
  int64_t get_interval(HkTaskType type) const {
    auto it = intervals_.find(type);
    return it != intervals_.end() ? it->second : 0;
  }

  void set_interval(HkTaskType type, int64_t interval_ms) {
    intervals_[type] = interval_ms;
  }

  // ------------------------------------------------------------------------
  // Get retention policy (mutable, so admin API can tweak it)
  // ------------------------------------------------------------------------
  RetentionPolicy& policy() { return *policy_; }
  const RetentionPolicy& policy() const { return *policy_; }

  // ------------------------------------------------------------------------
  // Check if scheduler is running
  // ------------------------------------------------------------------------
  bool is_running() const { return running_; }

  // ------------------------------------------------------------------------
  // Admin API: get current state
  // ------------------------------------------------------------------------
  json get_state() const {
    json j;
    j["running"] = running_;
    j["shutdown_requested"] = shutdown_requested_;
    j["metrics"] = metrics_->to_json();

    json intervals_json;
    for (auto& [type, interval] : intervals_) {
      intervals_json[hk_task_name(type)] = interval;
    }
    j["intervals_ms"] = intervals_json;

    json last_run_json;
    for (auto& [type, ts] : last_run_) {
      last_run_json[hk_task_name(type)] = ts;
    }
    j["last_run_ms"] = last_run_json;

    json next_scheduled_json;
    auto now = now_ms();
    for (auto& [type, ts] : last_run_) {
      auto it = intervals_.find(type);
      if (it != intervals_.end()) {
        int64_t next = ts + it->second;
        next_scheduled_json[hk_task_name(type)] = std::max(int64_t(0), next - now);
      }
    }
    j["next_scheduled_in_ms"] = next_scheduled_json;

    j["retention_policy"] = json{
      {"max_lifetime_ms", policy_->max_lifetime_ms},
      {"min_lifetime_ms", policy_->min_lifetime_ms},
      {"purge_redacted_immediately", policy_->purge_redacted_events_immediately},
      {"delete_local_media_on_purge", policy_->delete_local_media_on_purge}
    };

    return j;
  }

private:
  // ------------------------------------------------------------------------
  // Main scheduler loop
  // ------------------------------------------------------------------------
  void scheduler_loop() {
    logger_.info("Scheduler loop started");

    // Initialize last_run to "now" so we don't immediately run everything
    int64_t init_time = now_ms();
    for (int i = 0; i <= static_cast<int>(HkTaskType::DEVICE_LIST_POKE); ++i) {
      auto type = static_cast<HkTaskType>(i);
      last_run_[type] = init_time;
      // Stagger initial runs
      last_run_[type] -= (intervals_[type] * i) / 9;
    }

    while (true) {
      {
        std::unique_lock<std::mutex> lock(mutex_);
        if (shutdown_requested_) break;

        // Check which tasks are due
        int64_t now = now_ms();
        int64_t min_wait = 60000; // default 60s sleep

        for (int i = 0; i <= static_cast<int>(HkTaskType::DEVICE_LIST_POKE); ++i) {
          auto type = static_cast<HkTaskType>(i);
          int64_t elapsed = now - last_run_[type];
          int64_t interval = intervals_[type];

          if (elapsed >= interval) {
            // Release lock while executing
            lock.unlock();
            execute_scheduled_task(type);
            lock.lock();

            // Update last_run
            last_run_[type] = now_ms();
            now = now_ms(); // recalculate
          }

          int64_t remaining = (last_run_[type] + intervals_[type]) - now;
          if (remaining < min_wait) min_wait = std::max(int64_t(1000), remaining);
        }

        if (min_wait < 1000) min_wait = 1000;

        // Wait for next task or shutdown signal
        cv_.wait_for(lock, chr::milliseconds(min_wait), [this] {
          return shutdown_requested_.load();
        });
      }
    }

    logger_.info("Scheduler loop ended");
  }

  // ------------------------------------------------------------------------
  // Execute a scheduled task
  // ------------------------------------------------------------------------
  void execute_scheduled_task(HkTaskType type) {
    TaskRunContext ctx;
    ctx.type = type;
    ctx.mode = RunMode::SCHEDULED;
    ctx.started_at_ms = now_ms();
    ctx.batch_size = 0;
    ctx.max_runtime_ms = 300'000; // 5 min per task max
    ctx.dry_run = false;

    auto result = execute_task(type, ctx);

    if (result.success) {
      logger_.info("Scheduled task " + std::string(hk_task_name(type)) +
                   " completed: processed=" + std::to_string(result.items_processed) +
                   " deleted=" + std::to_string(result.items_deleted) +
                   " dur=" + std::to_string(result.duration_ms) + "ms");
    } else {
      logger_.error("Scheduled task " + std::string(hk_task_name(type)) +
                    " failed: " + result.error_message);
    }
  }

  // ------------------------------------------------------------------------
  // Execute a specific task by type
  // ------------------------------------------------------------------------
  TaskRunResult execute_task(HkTaskType type, const TaskRunContext& ctx) {
    switch (type) {
      case HkTaskType::EVENT_PURGE:
        return event_purger_->run(ctx);
      case HkTaskType::RECEIPT_CLEANUP:
        return receipt_cleaner_->run(ctx);
      case HkTaskType::PRESENCE_CLEANUP:
        return presence_cleaner_->run(ctx);
      case HkTaskType::TOKEN_EXPIRY:
        return token_expiry_->run(ctx);
      case HkTaskType::MEDIA_CACHE_CLEANUP:
        return media_cleaner_->run(ctx);
      case HkTaskType::STATS_AGGREGATION:
        return stats_agg_->run(ctx);
      case HkTaskType::DATABASE_VACUUM:
        return vacuum_engine_->run(ctx);
      case HkTaskType::FEDERATION_RETRY:
        return fed_retry_->run(ctx);
      case HkTaskType::DEVICE_LIST_POKE:
        return device_poke_->run(ctx);
      default:
        return TaskRunResult::fail(type, "Unknown task type", 0);
    }
  }

  std::shared_ptr<storage::DatabasePool> db_;
  std::shared_ptr<HousekeepingMetrics> metrics_;
  std::shared_ptr<RetentionPolicy> policy_;

  std::unique_ptr<EventPurger> event_purger_;
  std::unique_ptr<ReceiptCleaner> receipt_cleaner_;
  std::unique_ptr<PresenceCleaner> presence_cleaner_;
  std::unique_ptr<TokenExpiryManager> token_expiry_;
  std::unique_ptr<MediaCacheCleaner> media_cleaner_;
  std::unique_ptr<StatsAggregator> stats_agg_;
  std::unique_ptr<DatabaseVacuumEngine> vacuum_engine_;
  std::unique_ptr<FederationRetryManager> fed_retry_;
  std::unique_ptr<DeviceListPokeSender> device_poke_;

  std::map<HkTaskType, int64_t> intervals_;
  std::map<HkTaskType, int64_t> last_run_;

  HkLogger& logger_;
  std::atomic<bool> running_;
  std::atomic<bool> shutdown_requested_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::thread worker_;
};

// ============================================================================
// HousekeepingAdminAPI — REST API endpoints for housekeeping control
// ============================================================================
class HousekeepingAdminAPI {
public:
  HousekeepingAdminAPI(std::shared_ptr<HousekeepingScheduler> scheduler)
    : scheduler_(std::move(scheduler)),
      logger_(get_hk_logger("progressive.housekeeping.admin_api")) {}

  // ------------------------------------------------------------------------
  // GET /_progressive/admin/v1/housekeeping/status
  // ------------------------------------------------------------------------
  json get_status() {
    return scheduler_->get_state();
  }

  // ------------------------------------------------------------------------
  // GET /_progressive/admin/v1/housekeeping/metrics
  // ------------------------------------------------------------------------
  json get_metrics() {
    return scheduler_->get_metrics();
  }

  // ------------------------------------------------------------------------
  // POST /_progressive/admin/v1/housekeeping/run/:task
  //   Body: {"batch_size": 500, "dry_run": false}
  // ------------------------------------------------------------------------
  json run_task(const std::string& task_name, const json& body) {
    HkTaskType type = task_name_to_type(task_name);
    if (type == HkTaskType::ALL_TASKS) {
      return json{{"error", "Unknown task: " + task_name}};
    }

    json config = body.value("config", json::object());
    auto result = scheduler_->run_task_now(type, RunMode::MANUAL, config);

    json r;
    r["task"] = hk_task_name(type);
    r["success"] = result.success;
    r["items_processed"] = result.items_processed;
    r["items_deleted"] = result.items_deleted;
    r["duration_ms"] = result.duration_ms;
    if (!result.success) r["error"] = result.error_message;
    if (!result.details.is_null()) r["details"] = result.details;
    return r;
  }

  // ------------------------------------------------------------------------
  // POST /_progressive/admin/v1/housekeeping/run-all
  // ------------------------------------------------------------------------
  json run_all_tasks() {
    return scheduler_->run_all_tasks(RunMode::MANUAL);
  }

  // ------------------------------------------------------------------------
  // PUT /_progressive/admin/v1/housekeeping/interval/:task
  //   Body: {"interval_ms": 3600000}
  // ------------------------------------------------------------------------
  json set_interval(const std::string& task_name, const json& body) {
    HkTaskType type = task_name_to_type(task_name);
    if (type == HkTaskType::ALL_TASKS) {
      return json{{"error", "Unknown task: " + task_name}};
    }
    if (!body.contains("interval_ms")) {
      return json{{"error", "Missing 'interval_ms' in request body"}};
    }
    int64_t interval = body["interval_ms"];
    if (interval < 1000) {
      return json{{"error", "Interval must be at least 1000ms"}};
    }
    scheduler_->set_interval(type, interval);
    return json{{"task", task_name}, {"interval_ms", interval}, {"status", "updated"}};
  }

  // ------------------------------------------------------------------------
  // PUT /_progressive/admin/v1/housekeeping/retention-policy
  //   Body: {"max_lifetime_ms": ..., "min_lifetime_ms": ...}
  // ------------------------------------------------------------------------
  json update_retention_policy(const json& body) {
    auto& policy = scheduler_->policy();
    if (body.contains("max_lifetime_ms"))
      policy.max_lifetime_ms = body["max_lifetime_ms"];
    if (body.contains("min_lifetime_ms"))
      policy.min_lifetime_ms = body["min_lifetime_ms"];
    if (body.contains("purge_redacted_immediately"))
      policy.purge_redacted_events_immediately = body["purge_redacted_immediately"];
    if (body.contains("delete_local_media_on_purge"))
      policy.delete_local_media_on_purge = body["delete_local_media_on_purge"];
    if (body.contains("room_overrides") && body["room_overrides"].is_object()) {
      for (auto& [room_id, lifetime] : body["room_overrides"].items()) {
        policy.room_overrides[room_id] = lifetime;
      }
    }

    return json{{"status", "updated"}};
  }

  // ------------------------------------------------------------------------
  // POST /_progressive/admin/v1/housekeeping/start
  // ------------------------------------------------------------------------
  json start_scheduler() {
    if (scheduler_->is_running()) {
      return json{{"status", "already_running"}};
    }
    scheduler_->start();
    return json{{"status", "started"}};
  }

  // ------------------------------------------------------------------------
  // POST /_progressive/admin/v1/housekeeping/stop
  // ------------------------------------------------------------------------
  json stop_scheduler() {
    if (!scheduler_->is_running()) {
      return json{{"status", "already_stopped"}};
    }
    scheduler_->shutdown();
    return json{{"status", "stopped"}};
  }

private:
  static HkTaskType task_name_to_type(const std::string& name) {
    if (name == "event_purge")          return HkTaskType::EVENT_PURGE;
    if (name == "receipt_cleanup")      return HkTaskType::RECEIPT_CLEANUP;
    if (name == "presence_cleanup")     return HkTaskType::PRESENCE_CLEANUP;
    if (name == "token_expiry")         return HkTaskType::TOKEN_EXPIRY;
    if (name == "media_cache_cleanup")  return HkTaskType::MEDIA_CACHE_CLEANUP;
    if (name == "stats_aggregation")    return HkTaskType::STATS_AGGREGATION;
    if (name == "database_vacuum")      return HkTaskType::DATABASE_VACUUM;
    if (name == "federation_retry")     return HkTaskType::FEDERATION_RETRY;
    if (name == "device_list_poke")     return HkTaskType::DEVICE_LIST_POKE;
    return HkTaskType::ALL_TASKS;
  }

  std::shared_ptr<HousekeepingScheduler> scheduler_;
  HkLogger& logger_;
};

}  // namespace progressive
