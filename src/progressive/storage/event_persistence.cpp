// ============================================================================
// event_persistence.cpp - Matrix Event Persistence Engine
// ============================================================================
// Implements: event persist pipeline (validate, dedup, assign stream ordering,
// assign topological ordering, store event json, store event metadata),
// event dedup by event_id and by content hash, event stream ordering generator
// (monotonic counter), topological ordering computation, event edges management,
// event batch persistence, event rejected/soft-fail handling, event backfill
// from federation, event forward extremity management, event backfill
// extremity tracking.
//
// Namespace: progressive::storage
// ============================================================================

#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/engine.hpp"
#include "progressive/storage/types.hpp"
#include "progressive/json.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace progressive::storage {

// ============================================================================
// Forward declarations
// ============================================================================
class DatabasePool;
class LoggingTransaction;
class LoggingDatabaseConnection;
class BaseDatabaseEngine;

// ============================================================================
// Types used throughout - DatabaseType wrapper for variant-based parameters
// ============================================================================
using DatabaseType = SQLParam;

// ============================================================================
// SHA-256 hash helper for content-based deduplication
// Uses a simple but effective hash combining approach when OpenSSL not available
// ============================================================================
namespace {

std::string compute_content_hash(const json& event_json) {
  // Serialize to a canonical form and hash
  std::string serialized = event_json.dump();
  // Simple but effective FNV-1a 64-bit hash (suitable for dedup)
  uint64_t hash = 0xcbf29ce484222325ULL;
  for (unsigned char c : serialized) {
    hash ^= c;
    hash *= 0x100000001b3ULL;
  }
  // Also compute a position-dependent hash for collision resistance
  uint64_t hash2 = 0;
  for (size_t i = 0; i < serialized.size(); ++i) {
    hash2 = hash2 * 31 + static_cast<unsigned char>(serialized[i]);
  }
  std::ostringstream oss;
  oss << std::hex << hash << hash2;
  return oss.str();
}

// ============================================================================
// Content-based dedup fingerprinting
// ============================================================================
std::string compute_fingerprint(const std::string& event_type,
                                const std::string& sender,
                                const json& content,
                                const std::optional<std::string>& state_key) {
  std::ostringstream oss;
  oss << event_type << "|" << sender << "|";
  if (state_key) oss << *state_key;
  oss << "|";
  // Sort keys for deterministic output
  std::string content_str;
  if (content.is_object()) {
    json sorted = json::object();
    for (auto it = content.begin(); it != content.end(); ++it) {
      sorted[it.key()] = it.value();
    }
    content_str = sorted.dump();
  } else {
    content_str = content.dump();
  }
  oss << content_str << "|" << content_str.size();

  std::string input = oss.str();
  uint64_t hash = 0xcbf29ce484222325ULL;
  for (unsigned char c : input) {
    hash ^= c;
    hash *= 0x100000001b3ULL;
  }
  std::ostringstream result;
  result << std::hex << hash;
  return result.str();
}

// ============================================================================
// Event validation result types
// ============================================================================
enum class EventValidationResult : uint8_t {
  VALID = 0,
  MISSING_EVENT_ID = 1,
  MISSING_ROOM_ID = 2,
  MISSING_TYPE = 3,
  MISSING_SENDER = 4,
  INVALID_DEPTH = 5,
  INVALID_ORIGIN_SERVER_TS = 6,
  EMPTY_PREV_EVENTS = 7,
  DUPLICATE_EVENT_ID = 8,
  DUPLICATE_CONTENT_HASH = 9,
  ALREADY_PERSISTED = 10,
  REJECTED = 11,
  SOFT_FAILED = 12,
  OUTLIER = 13,
  BACKFILL_PENDING = 14,
  INVALID_SIGNATURE = 15,
  INVALID_HASH = 16,
  MISSING_AUTH_EVENTS = 17,
  INVALID_ROOM_VERSION = 18,
};

const char* validation_result_to_string(EventValidationResult result) {
  switch (result) {
    case EventValidationResult::VALID: return "valid";
    case EventValidationResult::MISSING_EVENT_ID: return "missing_event_id";
    case EventValidationResult::MISSING_ROOM_ID: return "missing_room_id";
    case EventValidationResult::MISSING_TYPE: return "missing_type";
    case EventValidationResult::MISSING_SENDER: return "missing_sender";
    case EventValidationResult::INVALID_DEPTH: return "invalid_depth";
    case EventValidationResult::INVALID_ORIGIN_SERVER_TS: return "invalid_origin_server_ts";
    case EventValidationResult::EMPTY_PREV_EVENTS: return "empty_prev_events";
    case EventValidationResult::DUPLICATE_EVENT_ID: return "duplicate_event_id";
    case EventValidationResult::DUPLICATE_CONTENT_HASH: return "duplicate_content_hash";
    case EventValidationResult::ALREADY_PERSISTED: return "already_persisted";
    case EventValidationResult::REJECTED: return "rejected";
    case EventValidationResult::SOFT_FAILED: return "soft_failed";
    case EventValidationResult::OUTLIER: return "outlier";
    case EventValidationResult::BACKFILL_PENDING: return "backfill_pending";
    case EventValidationResult::INVALID_SIGNATURE: return "invalid_signature";
    case EventValidationResult::INVALID_HASH: return "invalid_hash";
    case EventValidationResult::MISSING_AUTH_EVENTS: return "missing_auth_events";
    case EventValidationResult::INVALID_ROOM_VERSION: return "invalid_room_version";
    default: return "unknown";
  }
}

} // anonymous namespace

// ============================================================================
// EventDedupCache - In-memory LRU cache for event deduplication
// ============================================================================
class EventDedupCache {
public:
  explicit EventDedupCache(size_t max_entries = 100000)
      : max_entries_(max_entries) {}

  // Check if an event_id has been seen recently
  bool is_event_id_seen(const std::string& event_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = event_id_set_.find(event_id);
    if (it != event_id_set_.end()) {
      // Move to back of LRU
      event_id_lru_.splice(event_id_lru_.end(), event_id_lru_, it->second);
      return true;
    }
    return false;
  }

  // Check if a content hash has been seen
  bool is_content_hash_seen(const std::string& content_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = content_hash_set_.find(content_hash);
    if (it != content_hash_set_.end()) {
      content_hash_lru_.splice(content_hash_lru_.end(), content_hash_lru_, it->second);
      return true;
    }
    return false;
  }

  // Register an event (both by event_id and content_hash)
  void register_event(const std::string& event_id,
                      const std::string& content_hash) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Register event_id
    event_id_lru_.push_back(event_id);
    event_id_set_[event_id] = --event_id_lru_.end();

    // Register content hash
    content_hash_lru_.push_back(content_hash);
    content_hash_set_[content_hash] = --content_hash_lru_.end();

    // Evict if needed
    while (event_id_set_.size() > max_entries_) {
      auto oldest = event_id_lru_.front();
      event_id_set_.erase(oldest);
      event_id_lru_.pop_front();
    }
    while (content_hash_set_.size() > max_entries_) {
      auto oldest = content_hash_lru_.front();
      content_hash_set_.erase(oldest);
      content_hash_lru_.pop_front();
    }
  }

  // Clear all entries
  void clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    event_id_set_.clear();
    event_id_lru_.clear();
    content_hash_set_.clear();
    content_hash_lru_.clear();
  }

  // Get current size
  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return event_id_set_.size();
  }

  // Remove a specific event ID (e.g., when event becomes rejected)
  void remove_event_id(const std::string& event_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = event_id_set_.find(event_id);
    if (it != event_id_set_.end()) {
      event_id_lru_.erase(it->second);
      event_id_set_.erase(it);
    }
  }

private:
  mutable std::mutex mutex_;
  size_t max_entries_;

  using LruList = std::list<std::string>;
  LruList event_id_lru_;
  std::unordered_map<std::string, LruList::iterator> event_id_set_;

  LruList content_hash_lru_;
  std::unordered_map<std::string, LruList::iterator> content_hash_set_;
};

// ============================================================================
// StreamOrderingGenerator - Monotonic counter for stream ordering
// Equivalent to Synapse's stream ID generation system
// ============================================================================
class StreamOrderingGenerator {
public:
  explicit StreamOrderingGenerator(const std::string& instance_name,
                                   int64_t initial_value = 0)
      : instance_name_(instance_name),
        current_(initial_value),
        backfill_min_(initial_value > 0 ? -initial_value : -1000000),
        current_backfill_(backfill_min_.load()) {}

  // Allocate the next positive stream ordering (for new local events)
  int64_t next_stream_ordering() {
    return current_.fetch_add(1, std::memory_order_relaxed) + 1;
  }

  // Allocate the next negative stream ordering (for backfilled events)
  int64_t next_backfill_ordering() {
    int64_t val = current_backfill_.fetch_sub(1, std::memory_order_relaxed);
    return val;
  }

  // Get the current maximum stream ordering (positive side)
  int64_t current_max() const {
    return current_.load(std::memory_order_acquire);
  }

  // Get the current minimum backfill ordering (most negative)
  int64_t current_backfill_min() const {
    return current_backfill_.load(std::memory_order_acquire);
  }

  // Reserve a contiguous block of stream orderings
  int64_t reserve_block(int64_t count) {
    return current_.fetch_add(count, std::memory_order_relaxed) + 1;
  }

  // Reserve a contiguous block of backfill orderings
  int64_t reserve_backfill_block(int64_t count) {
    int64_t start = current_backfill_.fetch_sub(count, std::memory_order_relaxed);
    return start - count + 1;
  }

  // Reset to a specific value (used during recovery)
  void reset(int64_t new_value) {
    current_.store(new_value, std::memory_order_release);
  }

  // Reset backfill to a specific value
  void reset_backfill(int64_t new_value) {
    current_backfill_.store(new_value, std::memory_order_release);
  }

  const std::string& instance_name() const { return instance_name_; }

private:
  std::string instance_name_;
  std::atomic<int64_t> current_;
  std::atomic<int64_t> backfill_min_;
  std::atomic<int64_t> current_backfill_;
};

// ============================================================================
// TopologicalOrderingCalculator - Computes topological ordering for events
// ============================================================================
class TopologicalOrderingCalculator {
public:
  explicit TopologicalOrderingCalculator(int64_t default_base = 1000)
      : default_base_(default_base) {}

  // Compute topological ordering for a single event given its prev events
  int64_t compute(const std::vector<std::string>& prev_event_ids,
                  LoggingTransaction& txn,
                  int64_t depth = 0) {
    if (prev_event_ids.empty()) {
      // No prev events: use depth-based ordering
      return depth * default_base_;
    }

    // Query the max topological ordering of prev events
    int64_t max_topo = 0;
    bool found = false;

    // Build IN clause for batch lookup
    std::string placeholders;
    std::vector<DatabaseType> params;
    for (size_t i = 0; i < prev_event_ids.size(); ++i) {
      if (i > 0) placeholders += ", ";
      placeholders += "?";
      params.push_back(prev_event_ids[i]);
    }

    auto result = txn.select_one(
        "SELECT COALESCE(MAX(topological_ordering), 0) FROM events "
        "WHERE event_id IN (" + placeholders + ")",
        params);

    if (result && !result->is_null()) {
      int64_t val = result->get<int64_t>(0);
      if (val > 0) {
        max_topo = val;
        found = true;
      }
    }

    if (!found) {
      // No prev events found in DB, use depth as fallback
      return depth * default_base_;
    }

    return max_topo + 1;
  }

  // Compute topological orderings for a batch of events respecting DAG edges
  // Returns a map from event_id to computed topological_ordering
  std::map<std::string, int64_t> compute_batch(
      const std::vector<EventData>& events,
      LoggingTransaction& txn) const {

    // Build adjacency: event_id -> prev_event_ids
    std::map<std::string, std::vector<std::string>> adjacency;
    // Also track what depends on each event (reverse edges)
    std::map<std::string, std::vector<std::string>> reverse_adjacency;
    std::set<std::string> all_ids;
    std::set<std::string> events_with_no_known_prevs;

    for (const auto& event : events) {
      all_ids.insert(event.event_id);
      auto& prevs = adjacency[event.event_id];
      prevs = event.prev_event_ids_list();

      bool has_known_prev = false;
      for (const auto& p : prevs) {
        reverse_adjacency[p].push_back(event.event_id);
        if (all_ids.count(p)) has_known_prev = true;
      }
      if (!has_known_prev) {
        events_with_no_known_prevs.insert(event.event_id);
      }
    }

    // Query DB for existing topological orderings of prev events not in the batch
    std::map<std::string, int64_t> db_topo;
    {
      std::set<std::string> to_query;
      for (const auto& [eid, prevs] : adjacency) {
        for (const auto& p : prevs) {
          if (!all_ids.count(p)) {
            to_query.insert(p);
          }
        }
      }
      if (!to_query.empty()) {
        std::vector<std::string> query_list(to_query.begin(), to_query.end());
        // Batch in chunks of 500
        for (size_t i = 0; i < query_list.size(); i += 500) {
          size_t end = std::min(i + 500, query_list.size());
          std::string placeholders;
          std::vector<DatabaseType> params;
          for (size_t j = i; j < end; ++j) {
            if (j > i) placeholders += ", ";
            placeholders += "?";
            params.push_back(query_list[j]);
          }
          auto rows = txn.select(
              "SELECT event_id, topological_ordering FROM events WHERE event_id IN (" +
                  placeholders + ")",
              params);
          for (auto& row : rows) {
            if (!row.is_null()) {
              db_topo[row.get<std::string>(0)] = row.get<int64_t>(1);
            }
          }
        }
      }
    }

    // Now compute topo for each event: topological sort of the batch DAG
    std::map<std::string, int64_t> result;
    // In-degree tracking for events in the batch
    std::map<std::string, int> in_degree;
    for (const auto& eid : all_ids) {
      in_degree[eid] = 0;
    }
    for (const auto& [eid, prevs] : adjacency) {
      for (const auto& p : prevs) {
        if (all_ids.count(p)) {
          in_degree[eid]++;
        }
      }
    }

    // Kahn's algorithm: start with events that have 0 in-degree (no prevs in batch)
    std::vector<std::string> queue;
    for (const auto& eid : all_ids) {
      if (in_degree[eid] == 0) {
        queue.push_back(eid);
      }
    }

    std::set<std::string> processed;
    int64_t current_topo_base = 0;

    while (!queue.empty()) {
      std::vector<std::string> next_queue;

      for (const auto& eid : queue) {
        if (processed.count(eid)) continue;
        processed.insert(eid);

        // Compute max topo from prev events
        int64_t max_prev_topo = 0;
        const auto& prevs = adjacency[eid];
        for (const auto& p : prevs) {
          // Try result first (batch peer), then DB
          auto rit = result.find(p);
          if (rit != result.end()) {
            max_prev_topo = std::max(max_prev_topo, rit->second);
          } else {
            auto dit = db_topo.find(p);
            if (dit != db_topo.end()) {
              max_prev_topo = std::max(max_prev_topo, dit->second);
            }
          }
        }

        if (max_prev_topo == 0 && !prevs.empty()) {
          // No prevs found in DB or batch, fallback
          max_prev_topo = current_topo_base;
        }

        int64_t my_topo = std::max(max_prev_topo + 1, current_topo_base + 1);
        result[eid] = my_topo;
        current_topo_base = std::max(current_topo_base, my_topo);

        // Decrease in-degree of dependents
        auto rit = reverse_adjacency.find(eid);
        if (rit != reverse_adjacency.end()) {
          for (const auto& dep : rit->second) {
            if (all_ids.count(dep)) {
              in_degree[dep]--;
              if (in_degree[dep] == 0) {
                next_queue.push_back(dep);
              }
            }
          }
        }
      }

      queue = std::move(next_queue);
      // Safety: if we have unprocessed events but empty queue, break cycles
      if (queue.empty() && processed.size() < all_ids.size()) {
        for (const auto& eid : all_ids) {
          if (!processed.count(eid)) {
            // Give remaining events a fallback ordering
            result[eid] = current_topo_base + 100;
            current_topo_base += 100;
            processed.insert(eid);
          }
        }
      }
    }

    return result;
  }

private:
  int64_t default_base_;
};

// ============================================================================
// EventValidator - Validates incoming events before persistence
// ============================================================================
class EventValidator {
public:
  struct ValidationConfig {
    bool require_room_id = true;
    bool require_sender = true;
    bool require_prev_events = false;
    bool require_auth_events = false;
    bool check_depth_range = true;
    int64_t max_depth = INT64_MAX;
    int64_t min_depth = 0;
    bool check_origin_server_ts_range = true;
    int64_t max_ts_future_ms = 3600000;  // 1 hour in the future max
    std::set<std::string> valid_room_versions = {
      "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"
    };
  };

  explicit EventValidator(const ValidationConfig& config = {})
      : config_(config) {}

  // Validate a single event, returns success or failure reason
  EventValidationResult validate(const EventData& event) const {
    // Check event_id
    if (event.event_id.empty()) {
      return EventValidationResult::MISSING_EVENT_ID;
    }

    // Check room_id
    if (config_.require_room_id && event.room_id.empty()) {
      return EventValidationResult::MISSING_ROOM_ID;
    }

    // Check type
    if (event.type.empty()) {
      return EventValidationResult::MISSING_TYPE;
    }

    // Check sender
    if (config_.require_sender && event.sender.empty()) {
      return EventValidationResult::MISSING_SENDER;
    }

    // Check depth
    if (config_.check_depth_range) {
      if (event.depth < config_.min_depth || event.depth > config_.max_depth) {
        return EventValidationResult::INVALID_DEPTH;
      }
    }

    // Check origin_server_ts
    if (config_.check_origin_server_ts_range) {
      int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()).count();
      if (event.origin_server_ts > now_ms + config_.max_ts_future_ms) {
        return EventValidationResult::INVALID_ORIGIN_SERVER_TS;
      }
    }

    // Check room version
    if (!config_.valid_room_versions.empty() &&
        !event.room_version_id.empty()) {
      if (!config_.valid_room_versions.count(event.room_version_id)) {
        return EventValidationResult::INVALID_ROOM_VERSION;
      }
    }

    // Check prev_events
    if (config_.require_prev_events && event.prev_event_ids.empty()) {
      // For events in rooms, prev_events should not be empty except for the
      // very first create event
      if (event.type != EventTypes::Create) {
        return EventValidationResult::EMPTY_PREV_EVENTS;
      }
    }

    return EventValidationResult::VALID;
  }

  // Validate a batch of events
  std::map<std::string, EventValidationResult> validate_batch(
      const std::vector<EventData>& events) const {
    std::map<std::string, EventValidationResult> results;
    for (const auto& event : events) {
      results[event.event_id] = validate(event);
    }
    return results;
  }

  // Check if an event should be rejected based on its auth chain
  bool should_reject(const EventData& event,
                     const std::set<std::string>& rejected_auth_events) const {
    for (const auto& auth_id : event.auth_event_ids) {
      if (rejected_auth_events.count(auth_id)) {
        return true;
      }
    }
    return false;
  }

  // Check if an event should soft-fail (suspect but not fully rejected)
  bool should_soft_fail(const EventData& event,
                        const std::set<std::string>& soft_failed_auth_events) const {
    for (const auto& auth_id : event.auth_event_ids) {
      if (soft_failed_auth_events.count(auth_id)) {
        return true;
      }
    }
    return false;
  }

private:
  ValidationConfig config_;
};

// ============================================================================
// EventDedupManager - Coordinates dedup by event_id and content hash
// ============================================================================
class EventDedupManager {
public:
  EventDedupManager(DatabasePool& db_pool,
                    size_t cache_size = 100000)
      : db_pool_(db_pool),
        dedup_cache_(cache_size) {}

  // Check if event has already been seen (cache + DB)
  bool is_duplicate(const std::string& event_id,
                    const std::string& content_hash) {
    // Check in-memory cache first (fast path)
    if (dedup_cache_.is_event_id_seen(event_id)) {
      return true;
    }
    if (dedup_cache_.is_content_hash_seen(content_hash)) {
      return true;
    }

    // Check database (slow path)
    // This would normally run inside a transaction
    return false;  // Default: not duplicate (DB check is done in txn context)
  }

  // Check duplicates within a transaction
  bool is_duplicate_txn(LoggingTransaction& txn,
                         const std::string& event_id,
                         const std::string& content_hash) {
    // Check events table
    auto result = txn.select_one(
        "SELECT 1 FROM events WHERE event_id = ?", {event_id});
    if (result && !result->is_null()) {
      dedup_cache_.register_event(event_id, content_hash);
      return true;
    }

    // Check event rejection table (rejected events are also "seen")
    result = txn.select_one(
        "SELECT 1 FROM event_rejections WHERE event_id = ?", {event_id});
    if (result && !result->is_null()) {
      dedup_cache_.register_event(event_id, content_hash);
      return true;
    }

    return false;
  }

  // Register a new event in the dedup system
  void register_event(const std::string& event_id,
                      const std::string& content_hash) {
    dedup_cache_.register_event(event_id, content_hash);
  }

  // Register a batch of events
  void register_batch(const std::vector<EventData>& events) {
    for (const auto& event : events) {
      std::string hash = compute_content_hash(event.content);
      dedup_cache_.register_event(event.event_id, hash);
    }
  }

  // Remove from dedup (useful when an event becomes rejected and may be retried)
  void unregister_event(const std::string& event_id) {
    dedup_cache_.remove_event_id(event_id);
  }

  // Clear the dedup cache
  void clear_cache() {
    dedup_cache_.clear();
  }

  size_t cache_size() const {
    return dedup_cache_.size();
  }

private:
  DatabasePool& db_pool_;
  EventDedupCache dedup_cache_;
};

// ============================================================================
// EventEdgesManager - Manages event DAG edges (prev_event relationships)
// ============================================================================
class EventEdgesManager {
public:
  EventEdgesManager() = default;

  // Insert edges for a single event
  void insert_edges(LoggingTransaction& txn,
                    const EventData& event,
                    const std::vector<std::string>& prev_event_ids) {
    for (const auto& prev_id : prev_event_ids) {
      bool is_prev_state = false;
      // Check if the prev event is a state event
      auto row = txn.select_one(
          "SELECT is_state_event FROM events WHERE event_id = ?",
          {prev_id});
      if (row && !row->is_null()) {
        is_prev_state = (row->get<int64_t>(0) != 0);
      }

      txn.execute(
          "INSERT OR IGNORE INTO event_edges "
          "(event_id, prev_event_id, room_id, is_state) "
          "VALUES (?, ?, ?, ?)",
          {event.event_id, prev_id, event.room_id,
           is_prev_state ? 1 : 0});
    }
  }

  // Insert edges for a batch of events
  void insert_edges_batch(
      LoggingTransaction& txn,
      const std::vector<std::pair<std::string, std::vector<std::string>>>&
          event_prevs,
      const std::map<std::string, std::string>& event_to_room,
      const std::map<std::string, bool>& event_is_state_map) {

    std::vector<std::vector<DatabaseType>> batch_args;

    for (const auto& [event_id, prev_ids] : event_prevs) {
      std::string room_id;
      auto rit = event_to_room.find(event_id);
      if (rit != event_to_room.end()) room_id = rit->second;

      for (const auto& prev_id : prev_ids) {
        bool is_state = false;
        auto sit = event_is_state_map.find(prev_id);
        if (sit != event_is_state_map.end()) is_state = sit->second;

        batch_args.push_back({
          DatabaseType{event_id},
          DatabaseType{prev_id},
          DatabaseType{room_id},
          DatabaseType{static_cast<int64_t>(is_state ? 1 : 0)}
        });
      }
    }

    if (!batch_args.empty()) {
      // Insert in chunks
      for (size_t i = 0; i < batch_args.size(); i += 500) {
        size_t end = std::min(i + 500, batch_args.size());
        std::vector<std::vector<DatabaseType>> chunk(
            batch_args.begin() + i, batch_args.begin() + end);
        txn.execute_batch(
            "INSERT OR IGNORE INTO event_edges "
            "(event_id, prev_event_id, room_id, is_state) "
            "VALUES (?, ?, ?, ?)",
            chunk);
      }
    }
  }

  // Delete edges for a specific event (e.g., during redaction)
  void delete_edges_for_event(LoggingTransaction& txn,
                              const std::string& event_id) {
    txn.execute(
        "DELETE FROM event_edges WHERE event_id = ?", {event_id});
  }

  // Get all prev events for a given event
  std::vector<std::string> get_prev_events(LoggingTransaction& txn,
                                           const std::string& event_id) {
    std::vector<std::string> result;
    auto rows = txn.select(
        "SELECT prev_event_id FROM event_edges WHERE event_id = ? "
        "ORDER BY prev_event_id",
        {event_id});
    for (auto& row : rows) {
      if (!row.is_null()) {
        result.push_back(row.get<std::string>(0));
      }
    }
    return result;
  }

  // Get all events that reference a given prev_event_id
  std::vector<std::string> get_next_events(LoggingTransaction& txn,
                                           const std::string& prev_event_id) {
    std::vector<std::string> result;
    auto rows = txn.select(
        "SELECT event_id FROM event_edges WHERE prev_event_id = ? "
        "ORDER BY event_id",
        {prev_event_id});
    for (auto& row : rows) {
      if (!row.is_null()) {
        result.push_back(row.get<std::string>(0));
      }
    }
    return result;
  }

  // Get all events that are backfill candidates (no forward edges)
  std::vector<std::string> get_backfill_candidates(LoggingTransaction& txn,
                                                    const std::string& room_id,
                                                    int64_t limit = 100) {
    std::vector<std::string> result;
    auto rows = txn.select(
        "SELECT ee.prev_event_id FROM event_edges ee "
        "LEFT JOIN events e ON ee.prev_event_id = e.event_id "
        "WHERE ee.room_id = ? AND e.event_id IS NULL "
        "GROUP BY ee.prev_event_id "
        "LIMIT ?",
        {room_id, limit});
    for (auto& row : rows) {
      if (!row.is_null()) {
        result.push_back(row.get<std::string>(0));
      }
    }
    return result;
  }

  // Check if there is a path from event_a to event_b in the DAG
  bool has_path(LoggingTransaction& txn,
                const std::string& event_a,
                const std::string& event_b,
                int max_depth = 100) {
    std::set<std::string> visited;
    std::vector<std::string> stack;
    stack.push_back(event_a);

    while (!stack.empty()) {
      std::string current = stack.back();
      stack.pop_back();

      if (current == event_b) return true;
      if (visited.count(current)) continue;
      visited.insert(current);

      if (static_cast<int>(visited.size()) > max_depth * 10) {
        // Safety: too many nodes visited, assume no path
        return false;
      }

      auto prevs = get_prev_events(txn, current);
      for (const auto& p : prevs) {
        stack.push_back(p);
      }
    }
    return false;
  }
};

// ============================================================================
// EventForwardExtremityManager - Manages forward extremities for rooms
// ============================================================================
class EventForwardExtremityManager {
public:
  EventForwardExtremityManager() = default;

  // Get current forward extremities for a room
  std::set<std::string> get_forward_extremities(
      LoggingTransaction& txn, const std::string& room_id) {
    std::set<std::string> result;
    auto rows = txn.select(
        "SELECT event_id FROM event_forward_extremities WHERE room_id = ?",
        {room_id});
    for (auto& row : rows) {
      if (!row.is_null()) {
        result.insert(row.get<std::string>(0));
      }
    }
    return result;
  }

  // Replace forward extremities: remove old, insert new
  void replace_forward_extremities(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::set<std::string>& new_extremities) {

    // Delete existing
    txn.execute(
        "DELETE FROM event_forward_extremities WHERE room_id = ?",
        {room_id});

    // Insert new
    for (const auto& event_id : new_extremities) {
      txn.execute(
          "INSERT INTO event_forward_extremities (event_id, room_id) "
          "VALUES (?, ?)",
          {event_id, room_id});
    }
  }

  // Update forward extremities after persisting new events
  //
  // When we persist a new event E with prev_events P:
  // 1. Remove P from forward extremities (they are no longer extremities)
  // 2. Add E to forward extremities (it's now a new tip)
  void update_forward_extremities(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::set<std::string>& persisted_event_ids,
      const std::map<std::string, std::vector<std::string>>& event_to_prevs) {

    // Get current extremities
    auto current = get_forward_extremities(txn, room_id);

    // Remove events that now have children
    std::set<std::string> to_remove;
    for (const auto& [event_id, prev_ids] : event_to_prevs) {
      for (const auto& prev_id : prev_ids) {
        if (current.count(prev_id)) {
          to_remove.insert(prev_id);
        }
      }
    }

    // Add new events as extremities
    std::set<std::string> new_extremities;
    for (const auto& eid : persisted_event_ids) {
      new_extremities.insert(eid);
    }

    // Recompute: current extremities = (current - to_remove) + new_extremities
    std::set<std::string> updated;
    for (const auto& eid : current) {
      if (!to_remove.count(eid)) {
        updated.insert(eid);
      }
    }
    for (const auto& eid : new_extremities) {
      updated.insert(eid);
    }

    // Persist
    replace_forward_extremities(txn, room_id, updated);
  }

  // Check if an event is a forward extremity
  bool is_forward_extremity(LoggingTransaction& txn,
                            const std::string& event_id,
                            const std::string& room_id) {
    auto result = txn.select_one(
        "SELECT 1 FROM event_forward_extremities "
        "WHERE event_id = ? AND room_id = ?",
        {event_id, room_id});
    return result && !result->is_null();
  }

  // Get forward extremities that are outliers (needed for federation backfill)
  std::set<std::string> get_outlier_extremities(
      LoggingTransaction& txn, const std::string& room_id) {
    std::set<std::string> result;
    auto rows = txn.select(
        "SELECT efe.event_id FROM event_forward_extremities efe "
        "JOIN events e ON efe.event_id = e.event_id "
        "WHERE efe.room_id = ? AND e.is_outlier = 1",
        {room_id});
    for (auto& row : rows) {
      if (!row.is_null()) {
        result.insert(row.get<std::string>(0));
      }
    }
    return result;
  }

  // Remove specific events from forward extremities
  void remove_events_from_extremities(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::set<std::string>& event_ids) {
    for (const auto& event_id : event_ids) {
      txn.execute(
          "DELETE FROM event_forward_extremities "
          "WHERE event_id = ? AND room_id = ?",
          {event_id, room_id});
    }
  }
};

// ============================================================================
// EventBackfillExtremityManager - Manages backfill backward extremities
// ============================================================================
class EventBackfillExtremityManager {
public:
  EventBackfillExtremityManager() = default;

  // Get current backfill backward extremities for a room
  std::set<std::string> get_backfill_extremities(
      LoggingTransaction& txn, const std::string& room_id) {
    std::set<std::string> result;
    auto rows = txn.select(
        "SELECT event_id FROM event_backward_extremities WHERE room_id = ?",
        {room_id});
    for (auto& row : rows) {
      if (!row.is_null()) {
        result.insert(row.get<std::string>(0));
      }
    }
    return result;
  }

  // Replace backfill extremities
  void replace_backfill_extremities(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::set<std::string>& new_extremities) {
    txn.execute(
        "DELETE FROM event_backward_extremities WHERE room_id = ?",
        {room_id});

    for (const auto& event_id : new_extremities) {
      txn.execute(
          "INSERT INTO event_backward_extremities (event_id, room_id) "
          "VALUES (?, ?)",
          {event_id, room_id});
    }
  }

  // After backfilling events, update backfill extremities
  //
  // When we backfill event E (which is a prev_event of events we already have):
  // 1. Remove E from backfill extremities
  // 2. Add E's prev_events as new backfill extremities (if not yet persisted)
  void update_backfill_extremities(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::string& backfilled_event_id,
      const std::vector<std::string>& new_prev_events) {

    // Remove the backfilled event from backfill extremities
    txn.execute(
        "DELETE FROM event_backward_extremities "
        "WHERE event_id = ? AND room_id = ?",
        {backfilled_event_id, room_id});

    // Add new prev events as backfill extremities if not yet persisted
    for (const auto& prev_id : new_prev_events) {
      auto exists = txn.select_one(
          "SELECT 1 FROM events WHERE event_id = ?", {prev_id});
      if (!exists || exists->is_null()) {
        txn.execute(
            "INSERT OR IGNORE INTO event_backward_extremities "
            "(event_id, room_id) VALUES (?, ?)",
            {prev_id, room_id});
      }
    }
  }

  // Initialize backfill extremities for a room based on forward extremities
  void initialize_from_forward_extremities(
      LoggingTransaction& txn,
      const std::string& room_id) {
    // Get all forward extremities
    auto forwards = txn.select(
        "SELECT event_id FROM event_forward_extremities WHERE room_id = ?",
        {room_id});

    // For each forward extremity, add its prev_events as backfill extremities
    std::set<std::string> new_backfills;
    for (auto& row : forwards) {
      if (row.is_null()) continue;
      std::string event_id = row.get<std::string>(0);

      auto prevs = txn.select(
          "SELECT prev_event_id FROM event_edges WHERE event_id = ?",
          {event_id});
      for (auto& prev : prevs) {
        if (!prev.is_null()) {
          std::string prev_id = prev.get<std::string>(0);
          // Only add if not already persisted
          auto exists = txn.select_one(
              "SELECT 1 FROM events WHERE event_id = ?", {prev_id});
          if (!exists || exists->is_null()) {
            new_backfills.insert(prev_id);
          }
        }
      }
    }

    // Persist
    for (const auto& eid : new_backfills) {
      txn.execute(
          "INSERT OR IGNORE INTO event_backward_extremities "
          "(event_id, room_id) VALUES (?, ?)",
          {eid, room_id});
    }
  }

  // Get events that need to be backfilled (backfill extremities that are
  // not yet persisted and not failed pull attempts)
  std::vector<std::string> get_backfill_queue(
      LoggingTransaction& txn,
      const std::string& room_id,
      int64_t limit = 50) {
    std::vector<std::string> result;
    auto rows = txn.select(
        "SELECT ebe.event_id FROM event_backward_extremities ebe "
        "LEFT JOIN event_failed_pull_attempts efpa "
        "  ON ebe.event_id = efpa.event_id AND ebe.room_id = efpa.room_id "
        "WHERE ebe.room_id = ? AND efpa.event_id IS NULL "
        "LIMIT ?",
        {room_id, limit});
    for (auto& row : rows) {
      if (!row.is_null()) {
        result.push_back(row.get<std::string>(0));
      }
    }
    return result;
  }

  // Record a failed pull attempt and maybe remove from backfill queue
  void record_failed_pull_attempt(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::string& event_id,
      const std::string& cause,
      int64_t max_attempts_before_drop = 10) {

    // Check existing attempts
    auto existing = txn.select_one(
        "SELECT num_attempts FROM event_failed_pull_attempts "
        "WHERE room_id = ? AND event_id = ?",
        {room_id, event_id});

    int64_t attempts = 1;
    if (existing && !existing->is_null()) {
      attempts = existing->get<int64_t>(0) + 1;
    }

    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (existing && !existing->is_null()) {
      txn.execute(
          "UPDATE event_failed_pull_attempts "
          "SET num_attempts = ?, last_attempt_ts = ?, last_cause = ? "
          "WHERE room_id = ? AND event_id = ?",
          {attempts, now, cause, room_id, event_id});
    } else {
      txn.execute(
          "INSERT INTO event_failed_pull_attempts "
          "(room_id, event_id, num_attempts, last_attempt_ts, last_cause) "
          "VALUES (?, ?, ?, ?, ?)",
          {room_id, event_id, attempts, now, cause});
    }

    // If maximum attempts reached, remove from backfill extremities
    if (attempts >= max_attempts_before_drop) {
      txn.execute(
          "DELETE FROM event_backward_extremities "
          "WHERE event_id = ? AND room_id = ?",
          {event_id, room_id});
    }
  }

  // Clear failed attempts so events can be retried
  void clear_failed_pull_attempts(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::set<std::string>& event_ids) {
    for (const auto& event_id : event_ids) {
      txn.execute(
          "DELETE FROM event_failed_pull_attempts "
          "WHERE room_id = ? AND event_id = ?",
          {room_id, event_id});
    }
  }

  // Get count of pending backfill extremities
  int64_t count_pending_backfills(
      LoggingTransaction& txn, const std::string& room_id) {
    auto result = txn.select_one(
        "SELECT COUNT(*) FROM event_backward_extremities WHERE room_id = ?",
        {room_id});
    if (result && !result->is_null()) {
      return result->get<int64_t>(0);
    }
    return 0;
  }
};

// ============================================================================
// EventRejectionHandler - Handles rejected and soft-failed events
// ============================================================================
class EventRejectionHandler {
public:
  EventRejectionHandler(DatabasePool& db_pool,
                        EventDedupManager& dedup_manager)
      : db_pool_(db_pool),
        dedup_manager_(dedup_manager) {}

  // Mark an event as rejected
  void reject_event(LoggingTransaction& txn,
                    const std::string& event_id,
                    const std::string& reason,
                    int64_t time_msec) {
    // Record rejection
    txn.execute(
        "INSERT OR REPLACE INTO event_rejections (event_id, reason, last_check) "
        "VALUES (?, ?, ?)",
        {event_id, reason, time_msec});

    // Mark event as outlier so it doesn't appear in normal streams
    txn.execute(
        "UPDATE events SET is_outlier = 1 WHERE event_id = ?", {event_id});

    // Remove from dedup cache so it could potentially be retried later
    dedup_manager_.unregister_event(event_id);
  }

  // Soft-fail an event: mark as suspect but keep around
  void soft_fail_event(LoggingTransaction& txn,
                       const std::string& event_id,
                       const std::string& reason,
                       int64_t time_msec) {
    // Record in a soft-fail log (using the rejections table with a prefix)
    txn.execute(
        "INSERT OR REPLACE INTO event_rejections (event_id, reason, last_check) "
        "VALUES (?, ?, ?)",
        {event_id, "SOFT_FAIL: " + reason, time_msec});

    // Don't mark as outlier for soft-fails (they might still be useful)
  }

  // Check if an event is rejected
  bool is_rejected(LoggingTransaction& txn,
                   const std::string& event_id) {
    auto result = txn.select_one(
        "SELECT reason FROM event_rejections WHERE event_id = ? "
        "AND reason NOT LIKE 'SOFT_FAIL:%'",
        {event_id});
    return result && !result->is_null();
  }

  // Check if an event is soft-failed
  bool is_soft_failed(LoggingTransaction& txn,
                      const std::string& event_id) {
    auto result = txn.select_one(
        "SELECT reason FROM event_rejections WHERE event_id = ? "
        "AND reason LIKE 'SOFT_FAIL:%'",
        {event_id});
    return result && !result->is_null();
  }

  // Get rejection reason
  std::optional<std::string> get_rejection_reason(
      LoggingTransaction& txn,
      const std::string& event_id) {
    auto result = txn.select_one(
        "SELECT reason FROM event_rejections WHERE event_id = ?",
        {event_id});
    if (result && !result->is_null()) {
      return result->get<std::string>(0);
    }
    return std::nullopt;
  }

  // Clear rejection (allow event to be retried)
  void clear_rejection(LoggingTransaction& txn,
                       const std::string& event_id) {
    txn.execute(
        "DELETE FROM event_rejections WHERE event_id = ?", {event_id});
    txn.execute(
        "UPDATE events SET is_outlier = 0 WHERE event_id = ?", {event_id});

    dedup_manager_.unregister_event(event_id);
  }

  // Clear soft-fail
  void clear_soft_fail(LoggingTransaction& txn,
                       const std::string& event_id) {
    txn.execute(
        "DELETE FROM event_rejections WHERE event_id = ? "
        "AND reason LIKE 'SOFT_FAIL:%'",
        {event_id});
  }

  // Get recently rejected events that might be retried
  std::vector<std::string> get_retriable_rejections(
      LoggingTransaction& txn,
      int64_t older_than_ms,
      int64_t limit = 100) {
    std::vector<std::string> result;
    int64_t cutoff = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() - older_than_ms;

    auto rows = txn.select(
        "SELECT event_id FROM event_rejections WHERE last_check < ? LIMIT ?",
        {cutoff, limit});
    for (auto& row : rows) {
      if (!row.is_null()) {
        result.push_back(row.get<std::string>(0));
      }
    }
    return result;
  }

  // Update last_check timestamp for a rejection
  void touch_rejection_timestamp(LoggingTransaction& txn,
                                  const std::string& event_id,
                                  int64_t time_msec) {
    txn.execute(
        "UPDATE event_rejections SET last_check = ? WHERE event_id = ?",
        {time_msec, event_id});
  }

private:
  DatabasePool& db_pool_;
  EventDedupManager& dedup_manager_;
};

// ============================================================================
// EventBatchPersistenceEngine - Persists batches of events efficiently
// ============================================================================
class EventBatchPersistenceEngine {
public:
  struct BatchPersistenceResult {
    int total_events = 0;
    int persisted = 0;
    int rejected = 0;
    int soft_failed = 0;
    int duplicates = 0;
    int validation_failures = 0;
    std::map<std::string, EventValidationResult> validation_results;
    std::set<std::string> persisted_event_ids;
    bool overall_success = false;
  };

  EventBatchPersistenceEngine(
      DatabasePool& db_pool,
      EventDedupManager& dedup_manager,
      EventValidator& validator,
      StreamOrderingGenerator& stream_gen,
      TopologicalOrderingCalculator& topo_calc,
      EventEdgesManager& edges_mgr,
      EventForwardExtremityManager& forward_extremity_mgr,
      EventBackfillExtremityManager& backfill_extremity_mgr,
      EventRejectionHandler& rejection_handler)
      : db_pool_(db_pool),
        dedup_manager_(dedup_manager),
        validator_(validator),
        stream_gen_(stream_gen),
        topo_calc_(topo_calc),
        edges_mgr_(edges_mgr),
        forward_extremity_mgr_(forward_extremity_mgr),
        backfill_extremity_mgr_(backfill_extremity_mgr),
        rejection_handler_(rejection_handler) {}

  // Persist a batch of events in a single transaction
  // This is the main entry point for batch event persistence
  BatchPersistenceResult persist_events(
      const std::vector<EventPersistencePair>& events_and_contexts,
      const std::string& room_id,
      bool is_backfill = false,
      bool inhibit_local_membership_updates = false) {

    BatchPersistenceResult result;
    result.total_events = static_cast<int>(events_and_contexts.size());

    db_pool_.runInteraction(
        "persist_event_batch",
        [&](LoggingTransaction& txn) {
          // Phase 1: Validate all events
          std::vector<EventData> events;
          for (const auto& pair : events_and_contexts) {
            events.push_back(pair.event);
          }
          auto validation = validator_.validate_batch(events);

          // Phase 2: Dedup check
          std::vector<EventPersistencePair> valid_pairs;
          for (const auto& pair : events_and_contexts) {
            const auto& event = pair.event;

            // Check validation
            auto vit = validation.find(event.event_id);
            if (vit != validation.end() &&
                vit->second != EventValidationResult::VALID) {
              result.validation_failures++;
              result.validation_results[event.event_id] = vit->second;
              continue;
            }

            // Check dedup
            std::string content_hash = compute_content_hash(event.content);
            if (dedup_manager_.is_duplicate_txn(txn, event.event_id, content_hash)) {
              result.duplicates++;
              continue;
            }

            valid_pairs.push_back(pair);
          }

          if (valid_pairs.empty()) {
            result.overall_success = true;
            return;
          }

          // Phase 3: Assign stream orderings
          std::vector<EventPersistencePair> ordered_pairs;
          for (auto& pair : valid_pairs) {
            EventPersistencePair ordered = pair;
            if (is_backfill) {
              ordered.event.stream_ordering = stream_gen_.next_backfill_ordering();
            } else {
              ordered.event.stream_ordering = stream_gen_.next_stream_ordering();
            }
            ordered_pairs.push_back(ordered);
          }

          // Phase 4: Compute topological orderings
          std::vector<EventData> ordered_events;
          for (const auto& pair : ordered_pairs) {
            ordered_events.push_back(pair.event);
          }
          auto topo_map = topo_calc_.compute_batch(ordered_events, txn);

          // Phase 5: Apply topological ordering
          for (auto& pair : ordered_pairs) {
            auto tit = topo_map.find(pair.event.event_id);
            if (tit != topo_map.end()) {
              pair.event.stream_ordering = tit->second; // Override with topo
            }
          }

          // Phase 6: Check rejection/soft-fail conditions
          std::vector<EventPersistencePair> final_events;
          for (auto& pair : ordered_pairs) {
            const auto& event = pair.event;

            if (pair.context.rejected) {
              rejection_handler_.reject_event(
                  txn, event.event_id, "context_rejected",
                  std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::system_clock::now().time_since_epoch()).count());
              result.rejected++;
              continue;
            }

            // Check if auth events contain rejected events
            for (const auto& auth_id : event.auth_event_ids) {
              if (rejection_handler_.is_rejected(txn, auth_id)) {
                rejection_handler_.reject_event(
                    txn, event.event_id, "rejected_auth_event: " + auth_id,
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
                result.rejected++;
                goto next_event;
              }
              if (rejection_handler_.is_soft_failed(txn, auth_id)) {
                rejection_handler_.soft_fail_event(
                    txn, event.event_id, "soft_failed_auth_event: " + auth_id,
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count());
                result.soft_failed++;
                goto next_event;
              }
            }

            final_events.push_back(pair);
            next_event:;
          }

          // Phase 7: Persist to database
          persist_events_to_db(txn, final_events, room_id, is_backfill);

          // Phase 8: Register in dedup
          for (auto& pair : final_events) {
            std::string content_hash = compute_content_hash(pair.event.content);
            dedup_manager_.register_event(pair.event.event_id, content_hash);
            result.persisted_event_ids.insert(pair.event.event_id);
          }

          result.persisted = static_cast<int>(final_events.size());
          result.overall_success = true;
        });

    return result;
  }

  // Persist backfilled events specifically (events from federation backfill)
  BatchPersistenceResult persist_backfill_events(
      const std::vector<EventPersistencePair>& events_and_contexts,
      const std::string& room_id,
      const std::set<std::string>& events_to_replace_extremities) {

    BatchPersistenceResult result;
    result.total_events = static_cast<int>(events_and_contexts.size());

    db_pool_.runInteraction(
        "persist_backfill_batch",
        [&](LoggingTransaction& txn) {
          // Validate, dedup, assign negative stream orderings
          std::vector<EventData> events;
          for (const auto& pair : events_and_contexts) {
            events.push_back(pair.event);
          }
          auto validation = validator_.validate_batch(events);

          std::vector<EventPersistencePair> valid_pairs;
          for (const auto& pair : events_and_contexts) {
            const auto& event = pair.event;

            auto vit = validation.find(event.event_id);
            if (vit != validation.end() &&
                vit->second != EventValidationResult::VALID) {
              result.validation_failures++;
              result.validation_results[event.event_id] = vit->second;
              continue;
            }

            std::string content_hash = compute_content_hash(event.content);
            if (dedup_manager_.is_duplicate_txn(txn, event.event_id, content_hash)) {
              result.duplicates++;
              continue;
            }

            valid_pairs.push_back(pair);
          }

          if (valid_pairs.empty()) {
            result.overall_success = true;
            return;
          }

          // Assign negative stream orderings for backfill
          std::vector<EventPersistencePair> ordered_pairs;
          for (auto& pair : valid_pairs) {
            EventPersistencePair ordered = pair;
            ordered.event.stream_ordering = stream_gen_.next_backfill_ordering();
            ordered.event.is_outlier = false; // Backfilled events are not outliers
            ordered_pairs.push_back(ordered);
          }

          // Compute topological orderings
          std::vector<EventData> ordered_events;
          for (const auto& pair : ordered_pairs) {
            ordered_events.push_back(pair.event);
          }
          auto topo_map = topo_calc_.compute_batch(ordered_events, txn);

          for (auto& pair : ordered_pairs) {
            auto tit = topo_map.find(pair.event.event_id);
            if (tit != topo_map.end()) {
              // Store topological ordering separately (don't override stream ordering)
            }
          }

          // Persist
          persist_events_to_db(txn, ordered_pairs, room_id, true);

          // Update backfill extremities
          for (auto& pair : ordered_pairs) {
            // This event was a backfill extremity; replace it with its prev events
            backfill_extremity_mgr_.update_backfill_extremities(
                txn, room_id, pair.event.event_id,
                pair.event.prev_event_ids_list());
          }

          // Replace forward extremity markers if needed
          if (!events_to_replace_extremities.empty()) {
            std::set<std::string> new_forwards;
            for (const auto& pair : ordered_pairs) {
              new_forwards.insert(pair.event.event_id);
            }
            // Don't replace all, just remove the replaced ones and add new
            for (const auto& eid : events_to_replace_extremities) {
              txn.execute(
                  "DELETE FROM event_forward_extremities "
                  "WHERE event_id = ? AND room_id = ?",
                  {eid, room_id});
            }
            for (const auto& eid : new_forwards) {
              txn.execute(
                  "INSERT OR IGNORE INTO event_forward_extremities "
                  "(event_id, room_id) VALUES (?, ?)",
                  {eid, room_id});
            }
          }

          // Register in dedup
          for (auto& pair : ordered_pairs) {
            std::string content_hash = compute_content_hash(pair.event.content);
            dedup_manager_.register_event(pair.event.event_id, content_hash);
            result.persisted_event_ids.insert(pair.event.event_id);
          }

          result.persisted = static_cast<int>(ordered_pairs.size());
          result.overall_success = true;
        });

    return result;
  }

private:
  // Low-level DB persistence for a batch of events
  void persist_events_to_db(
      LoggingTransaction& txn,
      const std::vector<EventPersistencePair>& events_and_contexts,
      const std::string& room_id,
      bool is_backfill) {

    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    // Collect data for batch inserts
    std::vector<std::vector<DatabaseType>> events_batch;
    std::vector<std::vector<DatabaseType>> json_batch;
    std::vector<std::vector<DatabaseType>> auth_batch;
    std::vector<std::vector<DatabaseType>> edges_batch;
    std::vector<std::vector<DatabaseType>> state_events_batch;
    std::vector<std::vector<DatabaseType>> memberships_batch;
    std::vector<std::vector<DatabaseType>> search_batch;
    std::vector<std::vector<DatabaseType>> relations_batch;

    std::map<std::string, std::vector<std::string>> event_to_prevs;

    for (const auto& pair : events_and_contexts) {
      const EventData& event = pair.event;

      // Events table
      bool is_state = event.is_state_event;
      bool is_redacted = event.is_redacted;
      bool is_notifiable = check_if_is_notifiable(event);
      bool contains_url = check_if_has_url(event);
      std::string membership = extract_membership_value(event);
      int64_t topological = event.stream_ordering; // Use stream as topo proxy

      events_batch.push_back({
        DatabaseType{event.event_id},
        DatabaseType{event.room_id},
        DatabaseType{event.type},
        DatabaseType{event.sender},
        DatabaseType{event.state_key.value_or("")},
        DatabaseType{membership},
        DatabaseType{event.depth},
        DatabaseType{event.origin_server_ts},
        DatabaseType{event.stream_ordering},
        DatabaseType{stream_gen_.instance_name()},
        DatabaseType{now},
        DatabaseType{topological},
        DatabaseType{static_cast<int64_t>(event.format_version)},
        DatabaseType{static_cast<int64_t>(event.is_outlier ? 1 : 0)},
        DatabaseType{static_cast<int64_t>(is_redacted ? 1 : 0)},
        DatabaseType{static_cast<int64_t>(event.is_out_of_band_membership ? 1 : 0)},
        DatabaseType{static_cast<int64_t>(is_state ? 1 : 0)},
        DatabaseType{static_cast<int64_t>(is_notifiable ? 1 : 0)},
        DatabaseType{static_cast<int64_t>(contains_url ? 1 : 0)},
        DatabaseType{event.redacts.value_or("")},
        DatabaseType{event.txn_id.value_or("")},
        DatabaseType{event.device_id.value_or("")},
        DatabaseType{event.content.dump()},
        DatabaseType{event.internal_metadata_json},
        DatabaseType{event.unsigned_data.dump()},
        DatabaseType{event.room_version_id},
        DatabaseType{static_cast<int64_t>(0)} // reconciled
      });

      // Event JSON table
      json full_json;
      full_json["event_id"] = event.event_id;
      full_json["room_id"] = event.room_id;
      full_json["type"] = event.type;
      full_json["sender"] = event.sender;
      if (event.state_key) full_json["state_key"] = *event.state_key;
      full_json["content"] = event.content;
      full_json["origin_server_ts"] = event.origin_server_ts;
      full_json["depth"] = event.depth;
      if (!event.unsigned_data.empty()) {
        full_json["unsigned"] = event.unsigned_data;
      }
      // auth_events
      json auth_array = json::array();
      for (const auto& a : event.auth_event_ids) auth_array.push_back(a);
      full_json["auth_events"] = auth_array;
      // prev_events
      json prev_array = json::array();
      for (const auto& p : event.prev_event_ids) prev_array.push_back(p);
      full_json["prev_events"] = prev_array;

      json_batch.push_back({
        DatabaseType{event.event_id},
        DatabaseType{event.room_id},
        DatabaseType{event.internal_metadata_json},
        DatabaseType{full_json.dump()},
        DatabaseType{static_cast<int64_t>(event.format_version)}
      });

      // Auth chain
      for (const auto& auth_id : event.auth_event_ids) {
        auth_batch.push_back({
          DatabaseType{event.event_id},
          DatabaseType{auth_id},
          DatabaseType{event.room_id}
        });
      }

      // Edges (prev_events)
      auto prevs = collect_prevs_with_unsigned(event);
      event_to_prevs[event.event_id] = prevs;
      for (const auto& prev_id : prevs) {
        edges_batch.push_back({
          DatabaseType{event.event_id},
          DatabaseType{prev_id},
          DatabaseType{event.room_id},
          DatabaseType{static_cast<int64_t>(0)} // is_state default
        });
      }

      // State events
      if (is_state && event.state_key) {
        state_events_batch.push_back({
          DatabaseType{event.event_id},
          DatabaseType{event.room_id},
          DatabaseType{event.type},
          DatabaseType{*event.state_key},
          DatabaseType{""} // prev_state
        });
      }

      // Membership
      if (event.type == EventTypes::Member && event.state_key) {
        std::string user_id = *event.state_key;
        std::string display_name = extract_displayname_value(event);
        std::string avatar_url = extract_avatar_url_value(event);
        std::string membership_type = extract_membership_value(event);

        memberships_batch.push_back({
          DatabaseType{event.event_id},
          DatabaseType{user_id},
          DatabaseType{event.sender},
          DatabaseType{event.room_id},
          DatabaseType{membership_type},
          DatabaseType{display_name},
          DatabaseType{avatar_url}
        });
      }

      // Search index
      if (event.content.contains("body") && event.content["body"].is_string()) {
        search_batch.push_back({
          DatabaseType{event.event_id},
          DatabaseType{event.room_id},
          DatabaseType{event.sender},
          DatabaseType{event.content["body"].get<std::string>()},
          DatabaseType{static_cast<int64_t>(0)}, // vector
          DatabaseType{event.stream_ordering},
          DatabaseType{event.origin_server_ts}
        });
      }

      // Relations
      if (event.content.contains("m.relates_to") &&
          event.content["m.relates_to"].is_object()) {
        auto& rel = event.content["m.relates_to"];
        std::string rel_type = "m.reference";
        std::string relates_to_id;

        if (rel.contains("rel_type") && rel["rel_type"].is_string()) {
          rel_type = rel["rel_type"].get<std::string>();
        }
        if (rel.contains("event_id") && rel["event_id"].is_string()) {
          relates_to_id = rel["event_id"].get<std::string>();
        }

        if (!relates_to_id.empty()) {
          std::string agg_key;
          if (rel.contains("key") && rel["key"].is_string()) {
            agg_key = rel["key"].get<std::string>();
          }

          relations_batch.push_back({
            DatabaseType{event.event_id},
            DatabaseType{relates_to_id},
            DatabaseType{rel_type},
            DatabaseType{agg_key}
          });
        }
      }
    }

    // Execute batch inserts
    // Events table
    if (!events_batch.empty()) {
      txn.execute_batch(
          "INSERT OR REPLACE INTO events "
          "(event_id, room_id, type, sender, state_key, membership, depth, "
          "origin_server_ts, stream_ordering, instance_name, received_ts, "
          "topological_ordering, format_version, is_outlier, is_redacted, "
          "is_out_of_band_membership, is_state_event, is_notifiable, "
          "contains_url, redacts, transaction_id, device_id, content, "
          "internal_metadata, unsigned_data, room_version_id, reconciled) "
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
          "?, ?, ?, ?, ?, ?, ?, ?, ?)",
          events_batch);
    }

    // Event JSON
    if (!json_batch.empty()) {
      txn.execute_batch(
          "INSERT OR REPLACE INTO event_json "
          "(event_id, room_id, internal_metadata, json, format_version) "
          "VALUES (?, ?, ?, ?, ?)",
          json_batch);
    }

    // Auth chain
    if (!auth_batch.empty()) {
      txn.execute_batch(
          "INSERT OR IGNORE INTO event_auth (event_id, auth_id, room_id) "
          "VALUES (?, ?, ?)",
          auth_batch);
    }

    // Edges
    if (!edges_batch.empty()) {
      txn.execute_batch(
          "INSERT OR IGNORE INTO event_edges "
          "(event_id, prev_event_id, room_id, is_state) "
          "VALUES (?, ?, ?, ?)",
          edges_batch);
    }

    // State events
    if (!state_events_batch.empty()) {
      txn.execute_batch(
          "INSERT OR IGNORE INTO state_events "
          "(event_id, room_id, type, state_key, prev_state) "
          "VALUES (?, ?, ?, ?, ?)",
          state_events_batch);
    }

    // Memberships
    if (!memberships_batch.empty()) {
      txn.execute_batch(
          "INSERT INTO room_memberships "
          "(event_id, user_id, sender, room_id, membership, "
          "display_name, avatar_url) "
          "VALUES (?, ?, ?, ?, ?, ?, ?)",
          memberships_batch);
    }

    // Search
    if (!search_batch.empty()) {
      txn.execute_batch(
          "INSERT INTO event_search "
          "(event_id, room_id, sender, key, vector, stream_ordering, "
          "origin_server_ts) "
          "VALUES (?, ?, ?, ?, ?, ?, ?)",
          search_batch);
    }

    // Relations
    if (!relations_batch.empty()) {
      txn.execute_batch(
          "INSERT OR IGNORE INTO event_relations "
          "(event_id, relates_to_id, relation_type, aggregation_key) "
          "VALUES (?, ?, ?, ?)",
          relations_batch);
    }

    // Update forward extremities if not backfill
    if (!is_backfill && !event_to_prevs.empty()) {
      std::set<std::string> persisted_ids;
      for (const auto& pair : events_and_contexts) {
        persisted_ids.insert(pair.event.event_id);
      }
      forward_extremity_mgr_.update_forward_extremities(
          txn, room_id, persisted_ids, event_to_prevs);
    }
  }

  // Helper: extract content fields
  static std::string extract_membership_value(const EventData& event) {
    if (event.content.contains("membership") &&
        event.content["membership"].is_string()) {
      return event.content["membership"].get<std::string>();
    }
    return "";
  }

  static std::string extract_displayname_value(const EventData& event) {
    if (event.content.contains("displayname") &&
        event.content["displayname"].is_string()) {
      return event.content["displayname"].get<std::string>();
    }
    return "";
  }

  static std::string extract_avatar_url_value(const EventData& event) {
    if (event.content.contains("avatar_url") &&
        event.content["avatar_url"].is_string()) {
      return event.content["avatar_url"].get<std::string>();
    }
    return "";
  }

  static bool check_if_is_notifiable(const EventData& event) {
    if (event.type == EventTypes::Message ||
        event.type == EventTypes::Encrypted) {
      return true;
    }
    if (event.type == EventTypes::Member &&
        event.content.contains("membership") &&
        event.content["membership"] == "invite") {
      return true;
    }
    return false;
  }

  static bool check_if_has_url(const EventData& event) {
    if (!event.content.contains("body") ||
        !event.content["body"].is_string()) {
      return false;
    }
    std::string body = event.content["body"].get<std::string>();
    return body.find("http://") != std::string::npos ||
           body.find("https://") != std::string::npos ||
           body.find("matrix.to") != std::string::npos;
  }

  static std::vector<std::string> collect_prevs_with_unsigned(
      const EventData& event) {
    std::vector<std::string> prevs;
    // From unsigned data
    if (event.unsigned_data.contains("prev_events") &&
        event.unsigned_data["prev_events"].is_array()) {
      for (auto& pe : event.unsigned_data["prev_events"]) {
        if (pe.is_string()) {
          std::string s = pe.get<std::string>();
          if (std::find(prevs.begin(), prevs.end(), s) == prevs.end()) {
            prevs.push_back(s);
          }
        }
      }
    }
    // From explicit prev_event_ids
    for (const auto& pe : event.prev_event_ids) {
      if (std::find(prevs.begin(), prevs.end(), pe) == prevs.end()) {
        prevs.push_back(pe);
      }
    }
    return prevs;
  }

  DatabasePool& db_pool_;
  EventDedupManager& dedup_manager_;
  EventValidator& validator_;
  StreamOrderingGenerator& stream_gen_;
  TopologicalOrderingCalculator& topo_calc_;
  EventEdgesManager& edges_mgr_;
  EventForwardExtremityManager& forward_extremity_mgr_;
  EventBackfillExtremityManager& backfill_extremity_mgr_;
  EventRejectionHandler& rejection_handler_;
};

// ============================================================================
// EventPersistenceCoordinator - Top-level coordinator for event persistence
// ============================================================================
class EventPersistenceCoordinator {
public:
  struct Config {
    size_t dedup_cache_size = 100000;
    int64_t stream_ordering_initial = 0;
    bool enable_content_hash_dedup = true;
    int64_t max_future_ts_ms = 3600000;
    std::set<std::string> valid_room_versions = {
      "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"
    };
  };

  EventPersistenceCoordinator(DatabasePool& db_pool,
                              const std::string& instance_name,
                              const Config& config = {})
      : db_pool_(db_pool),
        instance_name_(instance_name),
        config_(config),
        dedup_manager_(db_pool, config.dedup_cache_size),
        stream_gen_(instance_name, config.stream_ordering_initial),
        validator_(build_validation_config()),
        edges_mgr_(),
        forward_extremity_mgr_(),
        backfill_extremity_mgr_(),
        rejection_handler_(db_pool, dedup_manager_),
        batch_engine_(
            db_pool,
            dedup_manager_,
            validator_,
            stream_gen_,
            topo_calc_,
            edges_mgr_,
            forward_extremity_mgr_,
            backfill_extremity_mgr_,
            rejection_handler_) {}

  // ==========================================================================
  // Main API: Persist regular events (local origin or accepted federation)
  // ==========================================================================
  EventBatchPersistenceEngine::BatchPersistenceResult persist_events(
      const std::vector<EventPersistencePair>& events_and_contexts,
      const std::string& room_id,
      bool inhibit_local_membership_updates = false) {
    return batch_engine_.persist_events(
        events_and_contexts, room_id, false, inhibit_local_membership_updates);
  }

  // ==========================================================================
  // Main API: Persist backfill events from federation
  // ==========================================================================
  EventBatchPersistenceEngine::BatchPersistenceResult persist_backfill_events(
      const std::vector<EventPersistencePair>& events_and_contexts,
      const std::string& room_id,
      const std::set<std::string>& events_to_replace_extremities = {}) {
    return batch_engine_.persist_backfill_events(
        events_and_contexts, room_id, events_to_replace_extremities);
  }

  // ==========================================================================
  // Validate a single event before persistence
  // ==========================================================================
  EventValidationResult validate_event(const EventData& event) {
    return validator_.validate(event);
  }

  // ==========================================================================
  // Check if event already exists (dedup check)
  // ==========================================================================
  bool is_event_duplicate(const std::string& event_id) {
    std::string dummy_hash = "0000";
    return dedup_manager_.is_duplicate(event_id, dummy_hash);
  }

  bool is_event_duplicate_txn(LoggingTransaction& txn,
                               const std::string& event_id) {
    // Compute a placeholder hash for the dedup check
    auto result = txn.select_one(
        "SELECT content FROM events WHERE event_id = ?", {event_id});
    std::string hash = "0000";
    if (result && !result->is_null()) {
      hash = compute_content_hash(json::parse(result->get<std::string>(0)));
    }
    return dedup_manager_.is_duplicate_txn(txn, event_id, hash);
  }

  // ==========================================================================
  // Compute content hash for an event
  // ==========================================================================
  std::string compute_hash(const json& event_json) {
    return compute_content_hash(event_json);
  }

  std::string compute_hash(const EventData& event) {
    json event_json;
    event_json["event_id"] = event.event_id;
    event_json["room_id"] = event.room_id;
    event_json["type"] = event.type;
    event_json["sender"] = event.sender;
    event_json["content"] = event.content;
    event_json["depth"] = event.depth;
    event_json["origin_server_ts"] = event.origin_server_ts;
    return compute_content_hash(event_json);
  }

  // ==========================================================================
  // Compute fingerprint for soft dedup
  // ==========================================================================
  std::string compute_fingerprint(const EventData& event) {
    return compute_fingerprint(event.type, event.sender, event.content,
                               event.state_key);
  }

  // ==========================================================================
  // Stream ordering accessors
  // ==========================================================================
  int64_t next_stream_ordering() {
    return stream_gen_.next_stream_ordering();
  }

  int64_t next_backfill_ordering() {
    return stream_gen_.next_backfill_ordering();
  }

  int64_t current_stream_max() const {
    return stream_gen_.current_max();
  }

  int64_t current_backfill_min() const {
    return stream_gen_.current_backfill_min();
  }

  // ==========================================================================
  // Reserve a block of stream ordering slots (for pre-allocation)
  // ==========================================================================
  std::pair<int64_t, int64_t> reserve_stream_block(int64_t count) {
    int64_t start = stream_gen_.reserve_block(count);
    return {start, start + count - 1};
  }

  std::pair<int64_t, int64_t> reserve_backfill_block(int64_t count) {
    int64_t start = stream_gen_.reserve_backfill_block(count);
    return {start, start + count - 1};
  }

  // ==========================================================================
  // Topological ordering computation for a single event
  // ==========================================================================
  int64_t compute_topological_ordering(
      LoggingTransaction& txn,
      const EventData& event) {
    return topo_calc_.compute(event.prev_event_ids_list(), txn, event.depth);
  }

  // ==========================================================================
  // Forward extremity management
  // ==========================================================================
  std::set<std::string> get_forward_extremities(
      LoggingTransaction& txn,
      const std::string& room_id) {
    return forward_extremity_mgr_.get_forward_extremities(txn, room_id);
  }

  void replace_forward_extremities(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::set<std::string>& new_extremities) {
    forward_extremity_mgr_.replace_forward_extremities(
        txn, room_id, new_extremities);
  }

  void add_forward_extremity(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::string& event_id) {
    std::set<std::string> current =
        forward_extremity_mgr_.get_forward_extremities(txn, room_id);
    current.insert(event_id);
    forward_extremity_mgr_.replace_forward_extremities(txn, room_id, current);
  }

  void remove_forward_extremity(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::string& event_id) {
    forward_extremity_mgr_.remove_events_from_extremities(
        txn, room_id, {event_id});
  }

  // ==========================================================================
  // Backfill extremity management
  // ==========================================================================
  std::set<std::string> get_backfill_extremities(
      LoggingTransaction& txn,
      const std::string& room_id) {
    return backfill_extremity_mgr_.get_backfill_extremities(txn, room_id);
  }

  void replace_backfill_extremities(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::set<std::string>& new_extremities) {
    backfill_extremity_mgr_.replace_backfill_extremities(
        txn, room_id, new_extremities);
  }

  void initialize_backfill_from_forward_extremities(
      LoggingTransaction& txn,
      const std::string& room_id) {
    backfill_extremity_mgr_.initialize_from_forward_extremities(txn, room_id);
  }

  std::vector<std::string> get_backfill_queue(
      LoggingTransaction& txn,
      const std::string& room_id,
      int64_t limit = 50) {
    return backfill_extremity_mgr_.get_backfill_queue(txn, room_id, limit);
  }

  void record_failed_backfill(
      LoggingTransaction& txn,
      const std::string& room_id,
      const std::string& event_id,
      const std::string& cause) {
    backfill_extremity_mgr_.record_failed_pull_attempt(
        txn, room_id, event_id, cause);
  }

  // ==========================================================================
  // Event rejection management
  // ==========================================================================
  void reject_event(LoggingTransaction& txn,
                    const std::string& event_id,
                    const std::string& reason) {
    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    rejection_handler_.reject_event(txn, event_id, reason, now);
  }

  void soft_fail_event(LoggingTransaction& txn,
                       const std::string& event_id,
                       const std::string& reason) {
    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    rejection_handler_.soft_fail_event(txn, event_id, reason, now);
  }

  bool is_event_rejected(LoggingTransaction& txn,
                         const std::string& event_id) {
    return rejection_handler_.is_rejected(txn, event_id);
  }

  bool is_event_soft_failed(LoggingTransaction& txn,
                            const std::string& event_id) {
    return rejection_handler_.is_soft_failed(txn, event_id);
  }

  void clear_rejection(LoggingTransaction& txn,
                       const std::string& event_id) {
    rejection_handler_.clear_rejection(txn, event_id);
  }

  void clear_soft_fail(LoggingTransaction& txn,
                       const std::string& event_id) {
    rejection_handler_.clear_soft_fail(txn, event_id);
  }

  // ==========================================================================
  // Event DAG edges management
  // ==========================================================================
  std::vector<std::string> get_prev_events(LoggingTransaction& txn,
                                            const std::string& event_id) {
    return edges_mgr_.get_prev_events(txn, event_id);
  }

  std::vector<std::string> get_next_events(LoggingTransaction& txn,
                                            const std::string& event_id) {
    return edges_mgr_.get_next_events(txn, event_id);
  }

  bool has_path_between(LoggingTransaction& txn,
                        const std::string& event_a,
                        const std::string& event_b) {
    return edges_mgr_.has_path(txn, event_a, event_b);
  }

  std::vector<std::string> get_backfill_candidates(
      LoggingTransaction& txn,
      const std::string& room_id,
      int64_t limit = 100) {
    return edges_mgr_.get_backfill_candidates(txn, room_id, limit);
  }

  // ==========================================================================
  // Outlier management
  // ==========================================================================
  std::set<std::string> get_outlier_extremities(
      LoggingTransaction& txn,
      const std::string& room_id) {
    return forward_extremity_mgr_.get_outlier_extremities(txn, room_id);
  }

  void mark_as_outlier(LoggingTransaction& txn,
                       const std::string& event_id) {
    txn.execute(
        "UPDATE events SET is_outlier = 1 WHERE event_id = ?", {event_id});
  }

  void unmark_outlier(LoggingTransaction& txn,
                      const std::string& event_id) {
    txn.execute(
        "UPDATE events SET is_outlier = 0 WHERE event_id = ?", {event_id});
  }

  // ==========================================================================
  // Dedup cache management
  // ==========================================================================
  void clear_dedup_cache() {
    dedup_manager_.clear_cache();
  }

  size_t dedup_cache_size() const {
    return dedup_manager_.cache_size();
  }

  // ==========================================================================
  // Stats / diagnostics
  // ==========================================================================
  struct PersistenceStats {
    int64_t stream_ordering_max = 0;
    int64_t backfill_ordering_min = 0;
    int64_t dedup_cache_entries = 0;
    int64_t total_persisted = 0;
    int64_t total_rejected = 0;
    int64_t total_backfilled = 0;
  };

  PersistenceStats get_stats() {
    PersistenceStats stats;
    stats.stream_ordering_max = stream_gen_.current_max();
    stats.backfill_ordering_min = stream_gen_.current_backfill_min();
    stats.dedup_cache_entries = static_cast<int64_t>(dedup_manager_.cache_size());
    return stats;
  }

  // ==========================================================================
  // Recovery: reinitialize stream ordering from DB state
  // ==========================================================================
  void recover_stream_ordering(const std::string& room_id) {
    db_pool_.runInteraction(
        "recover_stream_ordering",
        [&](LoggingTransaction& txn) {
          auto result = txn.select_one(
              "SELECT MAX(stream_ordering) FROM events", {});
          if (result && !result->is_null()) {
            int64_t max_order = result->get<int64_t>(0);
            stream_gen_.reset(max_order + 1);
          }

          auto min_backfill = txn.select_one(
              "SELECT MIN(stream_ordering) FROM events WHERE stream_ordering < 0", {});
          if (min_backfill && !min_backfill->is_null()) {
            int64_t min_order = min_backfill->get<int64_t>(0);
            stream_gen_.reset_backfill(min_order - 1);
          }
        });
  }

  // ==========================================================================
  // Backfill planning: determine which rooms/events need federation backfill
  // ==========================================================================
  struct BackfillPlan {
    std::string room_id;
    std::vector<std::string> event_ids;
    int64_t total_pending;
    int64_t recommended_batch_size;
  };

  BackfillPlan plan_backfill(LoggingTransaction& txn,
                              const std::string& room_id,
                              int64_t max_events = 100) {
    BackfillPlan plan;
    plan.room_id = room_id;
    plan.event_ids = backfill_extremity_mgr_.get_backfill_queue(
        txn, room_id, max_events);
    plan.total_pending = backfill_extremity_mgr_.count_pending_backfills(
        txn, room_id);
    plan.recommended_batch_size = std::min(
        static_cast<int64_t>(plan.event_ids.size()),
        static_cast<int64_t>(100));
    return plan;
  }

  // ==========================================================================
  // Batch loading: load persisted events by stream ordering range
  // ==========================================================================
  struct LoadedEvent {
    std::string event_id;
    std::string room_id;
    int64_t stream_ordering;
    json content;
    json unsigned_data;
  };

  std::vector<LoadedEvent> load_events_since(
      LoggingTransaction& txn,
      int64_t from_stream,
      int64_t limit = 100) {
    std::vector<LoadedEvent> results;
    auto rows = txn.select(
        "SELECT event_id, room_id, stream_ordering, content, unsigned_data "
        "FROM events WHERE stream_ordering > ? AND is_outlier = 0 "
        "ORDER BY stream_ordering ASC LIMIT ?",
        {from_stream, limit});

    for (auto& row : rows) {
      if (row.is_null()) continue;
      LoadedEvent le;
      le.event_id = row.get<std::string>(0);
      le.room_id = row.get<std::string>(1);
      le.stream_ordering = row.get<int64_t>(2);
      le.content = json::parse(row.get<std::string>(3));
      le.unsigned_data = json::parse(row.get<std::string>(4));
      results.push_back(std::move(le));
    }
    return results;
  }

  // ==========================================================================
  // Persist a single event with full pipeline
  // ==========================================================================
  struct SinglePersistenceResult {
    bool success = false;
    EventValidationResult validation = EventValidationResult::VALID;
    bool was_duplicate = false;
    int64_t stream_ordering = 0;
    std::string error_message;
  };

  SinglePersistenceResult persist_single_event(
      const EventData& event,
      const EventContext& context,
      const std::string& room_id) {

    SinglePersistenceResult result;

    // Validate
    result.validation = validator_.validate(event);
    if (result.validation != EventValidationResult::VALID) {
      result.error_message = validation_result_to_string(result.validation);
      return result;
    }

    // Check context
    if (context.rejected) {
      result.validation = EventValidationResult::REJECTED;
      result.error_message = "Event context marked as rejected";
      return result;
    }

    // Persist via batch engine
    std::vector<EventPersistencePair> batch;
    EventPersistencePair pair;
    pair.event = event;
    pair.context = context;
    batch.push_back(pair);

    auto batch_result = batch_engine_.persist_events(batch, room_id);

    if (batch_result.duplicates > 0) {
      result.was_duplicate = true;
      result.success = false;
      result.error_message = "Duplicate event";
      return result;
    }

    if (batch_result.validation_failures > 0) {
      result.success = false;
      result.error_message = "Validation failed";
      return result;
    }

    if (batch_result.persisted > 0) {
      result.success = true;
      result.stream_ordering = event.stream_ordering;
    }

    return result;
  }

private:
  EventValidator::ValidationConfig build_validation_config() {
    EventValidator::ValidationConfig cfg;
    cfg.require_room_id = true;
    cfg.require_sender = true;
    cfg.require_prev_events = false;
    cfg.require_auth_events = false;
    cfg.check_depth_range = true;
    cfg.check_origin_server_ts_range = true;
    cfg.max_ts_future_ms = config_.max_future_ts_ms;
    cfg.valid_room_versions = config_.valid_room_versions;
    return cfg;
  }

  DatabasePool& db_pool_;
  std::string instance_name_;
  Config config_;

  EventDedupManager dedup_manager_;
  StreamOrderingGenerator stream_gen_;
  EventValidator validator_;
  TopologicalOrderingCalculator topo_calc_;
  EventEdgesManager edges_mgr_;
  EventForwardExtremityManager forward_extremity_mgr_;
  EventBackfillExtremityManager backfill_extremity_mgr_;
  EventRejectionHandler rejection_handler_;
  EventBatchPersistenceEngine batch_engine_;
};

// ============================================================================
// EventStreamWriter - High-performance streaming event writer
// ============================================================================
class EventStreamWriter {
public:
  struct StreamWriteConfig {
    int64_t batch_size = 100;
    int64_t flush_interval_ms = 5000;
    bool auto_flush = true;
    bool compress_json = false;
  };

  EventStreamWriter(DatabasePool& db_pool,
                    StreamOrderingGenerator& stream_gen,
                    const StreamWriteConfig& config = {})
      : db_pool_(db_pool),
        stream_gen_(stream_gen),
        config_(config) {}

  // Queue a set of events for writing
  void queue_events(const std::vector<EventPersistencePair>& events) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    for (const auto& pair : events) {
      queue_.push_back(pair);
    }

    if (config_.auto_flush &&
        static_cast<int64_t>(queue_.size()) >= config_.batch_size) {
      flush_internal();
    }
  }

  // Flush all queued events
  int64_t flush(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return flush_internal_room(room_id);
  }

  // Get pending event count
  int64_t pending_count() const {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    return static_cast<int64_t>(queue_.size());
  }

private:
  int64_t flush_internal() {
    if (queue_.empty()) return 0;

    // Group by room_id
    std::map<std::string, std::vector<EventPersistencePair>> by_room;
    for (const auto& pair : queue_) {
      by_room[pair.event.room_id].push_back(pair);
    }

    int64_t total = 0;
    for (auto& [room_id, events] : by_room) {
      total += flush_internal_room(room_id);
    }

    return total;
  }

  int64_t flush_internal_room(const std::string& room_id) {
    if (queue_.empty()) return 0;

    // Filter events for this room
    std::vector<EventPersistencePair> room_events;
    std::vector<EventPersistencePair> remaining;

    for (const auto& pair : queue_) {
      if (pair.event.room_id == room_id) {
        room_events.push_back(pair);
      } else {
        remaining.push_back(pair);
      }
    }

    if (room_events.empty()) return 0;

    // Persist
    int64_t count = 0;
    db_pool_.runInteraction(
        "stream_writer_flush",
        [&](LoggingTransaction& txn) {
          int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
              std::chrono::system_clock::now().time_since_epoch()).count();

          for (auto& pair : room_events) {
            pair.event.stream_ordering = stream_gen_.next_stream_ordering();

            txn.execute(
                "INSERT INTO events "
                "(event_id, room_id, type, sender, state_key, depth, "
                "origin_server_ts, stream_ordering, instance_name, "
                "received_ts, topological_ordering, format_version, "
                "is_outlier, is_redacted, is_state_event, "
                "room_version_id, content, internal_metadata, unsigned_data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                {
                  pair.event.event_id,
                  pair.event.room_id,
                  pair.event.type,
                  pair.event.sender,
                  pair.event.state_key.value_or(""),
                  pair.event.depth,
                  pair.event.origin_server_ts,
                  pair.event.stream_ordering,
                  stream_gen_.instance_name(),
                  now,
                  pair.event.stream_ordering, // topological = stream for simple writer
                  pair.event.format_version,
                  pair.event.is_outlier ? 1 : 0,
                  pair.event.is_redacted ? 1 : 0,
                  pair.event.is_state_event ? 1 : 0,
                  pair.event.room_version_id,
                  pair.event.content.dump(),
                  pair.event.internal_metadata_json,
                  pair.event.unsigned_data.dump()
                });

            count++;
          }
        });

    // Update queue with remaining events
    queue_ = std::move(remaining);

    return count;
  }

  DatabasePool& db_pool_;
  StreamOrderingGenerator& stream_gen_;
  StreamWriteConfig config_;

  mutable std::mutex queue_mutex_;
  std::vector<EventPersistencePair> queue_;
};

// ============================================================================
// EventContentStore - Optimized content storage and retrieval
// ============================================================================
class EventContentStore {
public:
  explicit EventContentStore(DatabasePool& db_pool)
      : db_pool_(db_pool) {}

  // Store JSON content for an event
  void store_json(LoggingTransaction& txn,
                  const std::string& event_id,
                  const std::string& room_id,
                  const json& content,
                  const std::string& internal_metadata,
                  int format_version = 1) {
    txn.execute(
        "INSERT OR REPLACE INTO event_json "
        "(event_id, room_id, internal_metadata, json, format_version) "
        "VALUES (?, ?, ?, ?, ?)",
        {event_id, room_id, internal_metadata, content.dump(), format_version});
  }

  // Batch store JSON content
  void store_json_batch(
      LoggingTransaction& txn,
      const std::vector<std::tuple<std::string, std::string, std::string, json, int>>& events) {

    std::vector<std::vector<DatabaseType>> batch;
    for (const auto& [event_id, room_id, metadata, content, version] : events) {
      batch.push_back({
        DatabaseType{event_id},
        DatabaseType{room_id},
        DatabaseType{metadata},
        DatabaseType{content.dump()},
        DatabaseType{static_cast<int64_t>(version)}
      });
    }

    if (!batch.empty()) {
      txn.execute_batch(
          "INSERT OR REPLACE INTO event_json "
          "(event_id, room_id, internal_metadata, json, format_version) "
          "VALUES (?, ?, ?, ?, ?)",
          batch);
    }
  }

  // Retrieve JSON content for an event
  std::optional<json> get_json(LoggingTransaction& txn,
                                const std::string& event_id) {
    auto result = txn.select_one(
        "SELECT json FROM event_json WHERE event_id = ?", {event_id});
    if (result && !result->is_null()) {
      return json::parse(result->get<std::string>(0));
    }
    return std::nullopt;
  }

  // Retrieve multiple event JSONs
  std::map<std::string, json> get_json_batch(
      LoggingTransaction& txn,
      const std::vector<std::string>& event_ids) {
    std::map<std::string, json> results;
    if (event_ids.empty()) return results;

    // Process in chunks
    for (size_t i = 0; i < event_ids.size(); i += 500) {
      size_t end = std::min(i + 500, event_ids.size());
      std::string placeholders;
      std::vector<DatabaseType> params;
      for (size_t j = i; j < end; ++j) {
        if (j > i) placeholders += ", ";
        placeholders += "?";
        params.push_back(event_ids[j]);
      }

      auto rows = txn.select(
          "SELECT event_id, json FROM event_json WHERE event_id IN (" +
              placeholders + ")",
          params);
      for (auto& row : rows) {
        if (!row.is_null()) {
          results[row.get<std::string>(0)] =
              json::parse(row.get<std::string>(1));
        }
      }
    }
    return results;
  }

  // Update internal metadata for an event
  void update_internal_metadata(LoggingTransaction& txn,
                                 const std::string& event_id,
                                 const std::string& metadata) {
    txn.execute(
        "UPDATE event_json SET internal_metadata = ? WHERE event_id = ?",
        {metadata, event_id});
  }

  // Delete stored JSON (e.g., for redacted events that should be purged)
  void delete_json(LoggingTransaction& txn,
                   const std::string& event_id) {
    txn.execute(
        "DELETE FROM event_json WHERE event_id = ?", {event_id});
  }

private:
  DatabasePool& db_pool_;
};

// ============================================================================
// EventMetadataStore - Stores and retrieves event metadata
// ============================================================================
class EventMetadataStore {
public:
  explicit EventMetadataStore(DatabasePool& db_pool)
      : db_pool_(db_pool) {}

  // Store event metadata
  void store_metadata(LoggingTransaction& txn,
                      const EventData& event,
                      int64_t stream_ordering,
                      int64_t topological_ordering,
                      int64_t received_ts) {
    txn.execute(
        "INSERT OR REPLACE INTO events "
        "(event_id, room_id, type, sender, state_key, membership, depth, "
        "origin_server_ts, stream_ordering, instance_name, received_ts, "
        "topological_ordering, format_version, is_outlier, is_redacted, "
        "is_out_of_band_membership, is_state_event, is_notifiable, "
        "contains_url, redacts, transaction_id, device_id, content, "
        "internal_metadata, unsigned_data, room_version_id, reconciled) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
        "?, ?, ?, ?, ?, ?, ?, ?, ?)",
        {
          event.event_id, event.room_id, event.type, event.sender,
          event.state_key.value_or(""), event.membership,
          event.depth, event.origin_server_ts, stream_ordering,
          "main", received_ts, topological_ordering,
          event.format_version,
          event.is_outlier ? 1 : 0, event.is_redacted ? 1 : 0,
          event.is_out_of_band_membership ? 1 : 0,
          event.is_state_event ? 1 : 0,
          check_notifiable(event) ? 1 : 0,
          check_has_url(event) ? 1 : 0,
          event.redacts.value_or(""),
          event.txn_id.value_or(""),
          event.device_id.value_or(""),
          event.content.dump(),
          event.internal_metadata_json,
          event.unsigned_data.dump(),
          event.room_version_id,
          0 // reconciled
        });
  }

  // Batch store metadata
  void store_metadata_batch(
      LoggingTransaction& txn,
      const std::vector<std::tuple<EventData, int64_t, int64_t, int64_t>>& batch) {

    std::vector<std::vector<DatabaseType>> args;
    for (const auto& [event, stream_ordering, topological_ordering, received_ts] : batch) {
      args.push_back({
        DatabaseType{event.event_id},
        DatabaseType{event.room_id},
        DatabaseType{event.type},
        DatabaseType{event.sender},
        DatabaseType{event.state_key.value_or("")},
        DatabaseType{event.membership},
        DatabaseType{event.depth},
        DatabaseType{event.origin_server_ts},
        DatabaseType{stream_ordering},
        DatabaseType{"main"}, // instance_name
        DatabaseType{received_ts},
        DatabaseType{topological_ordering},
        DatabaseType{static_cast<int64_t>(event.format_version)},
        DatabaseType{static_cast<int64_t>(event.is_outlier ? 1 : 0)},
        DatabaseType{static_cast<int64_t>(event.is_redacted ? 1 : 0)},
        DatabaseType{static_cast<int64_t>(event.is_out_of_band_membership ? 1 : 0)},
        DatabaseType{static_cast<int64_t>(event.is_state_event ? 1 : 0)},
        DatabaseType{static_cast<int64_t>(check_notifiable(event) ? 1 : 0)},
        DatabaseType{static_cast<int64_t>(check_has_url(event) ? 1 : 0)},
        DatabaseType{event.redacts.value_or("")},
        DatabaseType{event.txn_id.value_or("")},
        DatabaseType{event.device_id.value_or("")},
        DatabaseType{event.content.dump()},
        DatabaseType{event.internal_metadata_json},
        DatabaseType{event.unsigned_data.dump()},
        DatabaseType{event.room_version_id},
        DatabaseType{static_cast<int64_t>(0)}
      });
    }

    if (!args.empty()) {
      txn.execute_batch(
          "INSERT OR REPLACE INTO events "
          "(event_id, room_id, type, sender, state_key, membership, depth, "
          "origin_server_ts, stream_ordering, instance_name, received_ts, "
          "topological_ordering, format_version, is_outlier, is_redacted, "
          "is_out_of_band_membership, is_state_event, is_notifiable, "
          "contains_url, redacts, transaction_id, device_id, content, "
          "internal_metadata, unsigned_data, room_version_id, reconciled) "
          "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
          "?, ?, ?, ?, ?, ?, ?, ?, ?)",
          args);
    }
  }

  // Retrieve metadata for an event
  std::optional<EventData> get_metadata(LoggingTransaction& txn,
                                         const std::string& event_id) {
    auto result = txn.select_one(
        "SELECT event_id, room_id, type, sender, state_key, membership, "
        "depth, origin_server_ts, stream_ordering, is_state_event, is_outlier, "
        "content, internal_metadata, unsigned_data, room_version_id, is_redacted "
        "FROM events WHERE event_id = ?",
        {event_id});

    if (!result || result->is_null()) return std::nullopt;

    EventData event;
    event.event_id = result->get<std::string>(0);
    event.room_id = result->get<std::string>(1);
    event.type = result->get<std::string>(2);
    event.sender = result->get<std::string>(3);
    if (!result->is_null(4)) event.state_key = result->get<std::string>(4);
    event.membership = result->get<std::string>(5);
    event.depth = result->get<int64_t>(6);
    event.origin_server_ts = result->get<int64_t>(7);
    event.stream_ordering = result->get<int64_t>(8);
    event.is_state_event = result->get<int64_t>(9) != 0;
    event.is_outlier = result->get<int64_t>(10) != 0;
    event.content = json::parse(result->get<std::string>(11));
    event.internal_metadata_json = result->get<std::string>(12);
    event.unsigned_data = json::parse(result->get<std::string>(13));
    event.room_version_id = result->get<std::string>(14);
    event.is_redacted = result->get<int64_t>(15) != 0;
    return event;
  }

  // Update stream ordering for an event (typically for reordering)
  void update_stream_ordering(LoggingTransaction& txn,
                               const std::string& event_id,
                               int64_t new_stream_ordering) {
    txn.execute(
        "UPDATE events SET stream_ordering = ? WHERE event_id = ?",
        {new_stream_ordering, event_id});
  }

  // Update topological ordering
  void update_topological_ordering(LoggingTransaction& txn,
                                    const std::string& event_id,
                                    int64_t new_topological) {
    txn.execute(
        "UPDATE events SET topological_ordering = ? WHERE event_id = ?",
        {new_topological, event_id});
  }

  // Mark event as reconciled
  void mark_reconciled(LoggingTransaction& txn,
                       const std::string& event_id) {
    txn.execute(
        "UPDATE events SET reconciled = 1 WHERE event_id = ?", {event_id});
  }

  // Delete all metadata for an event
  void delete_metadata(LoggingTransaction& txn,
                       const std::string& event_id) {
    txn.execute("DELETE FROM events WHERE event_id = ?", {event_id});
    txn.execute("DELETE FROM event_json WHERE event_id = ?", {event_id});
    txn.execute("DELETE FROM event_auth WHERE event_id = ?", {event_id});
    txn.execute("DELETE FROM event_edges WHERE event_id = ?", {event_id});
    txn.execute("DELETE FROM event_relations WHERE event_id = ?", {event_id});
  }

private:
  static bool check_notifiable(const EventData& event) {
    if (event.type == EventTypes::Message ||
        event.type == EventTypes::Encrypted) return true;
    if (event.type == EventTypes::Member &&
        event.content.contains("membership") &&
        event.content["membership"] == "invite") return true;
    return false;
  }

  static bool check_has_url(const EventData& event) {
    if (!event.content.contains("body") ||
        !event.content["body"].is_string()) return false;
    std::string body = event.content["body"].get<std::string>();
    return body.find("http://") != std::string::npos ||
           body.find("https://") != std::string::npos ||
           body.find("matrix.to") != std::string::npos;
  }

  DatabasePool& db_pool_;
};

// ============================================================================
// EventGapTracker - Tracks and manages gaps in the event DAG
// Used during backfill to identify missing events
// ============================================================================
class EventGapTracker {
public:
  struct GapInfo {
    std::string room_id;
    std::string start_event_id;  // Event we have that references missing prev
    std::string missing_event_id; // The missing event
    int64_t missing_depth;
    int64_t discovered_at_ms;
    int attempts;
    bool permanent_failure;
  };

  EventGapTracker(DatabasePool& db_pool)
      : db_pool_(db_pool) {}

  // Detect gaps for a room: events whose prev_events are not in the DB
  std::vector<GapInfo> detect_gaps(LoggingTransaction& txn,
                                    const std::string& room_id,
                                    int64_t limit = 100) {
    std::vector<GapInfo> gaps;

    auto rows = txn.select(
        "SELECT e.event_id, ee.prev_event_id, e.depth "
        "FROM event_edges ee "
        "JOIN events e ON ee.event_id = e.event_id "
        "LEFT JOIN events e2 ON ee.prev_event_id = e2.event_id "
        "WHERE ee.room_id = ? AND e2.event_id IS NULL "
        "AND e.is_outlier = 0 "
        "LIMIT ?",
        {room_id, limit});

    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    for (auto& row : rows) {
      if (row.is_null()) continue;
      GapInfo gap;
      gap.room_id = room_id;
      gap.start_event_id = row.get<std::string>(0);
      gap.missing_event_id = row.get<std::string>(1);
      gap.missing_depth = row.get<int64_t>(2);
      gap.discovered_at_ms = now;
      gap.attempts = 0;
      gap.permanent_failure = false;
      gaps.push_back(gap);
    }

    return gaps;
  }

  // Record that a gap was resolved (event was backfilled)
  void mark_gap_resolved(LoggingTransaction& txn,
                         const std::string& missing_event_id) {
    // Remove from backfill extremities
    auto rooms = txn.select(
        "SELECT room_id FROM event_backward_extremities WHERE event_id = ?",
        {missing_event_id});
    for (auto& row : rooms) {
      if (!row.is_null()) {
        txn.execute(
            "DELETE FROM event_backward_extremities "
            "WHERE event_id = ? AND room_id = ?",
            {missing_event_id, row.get<std::string>(0)});
      }
    }

    // Clear failed pull attempts
    txn.execute(
        "DELETE FROM event_failed_pull_attempts WHERE event_id = ?",
        {missing_event_id});
  }

  // Record that a gap search failed permanently
  void mark_gap_permanent_failure(LoggingTransaction& txn,
                                   const std::string& missing_event_id,
                                   const std::string& room_id) {
    txn.execute(
        "DELETE FROM event_backward_extremities "
        "WHERE event_id = ? AND room_id = ?",
        {missing_event_id, room_id});
  }

  // Get all rooms that have gaps
  std::vector<std::string> get_rooms_with_gaps(LoggingTransaction& txn) {
    std::vector<std::string> rooms;
    auto rows = txn.select(
        "SELECT DISTINCT room_id FROM event_backward_extremities");
    for (auto& row : rows) {
      if (!row.is_null()) {
        rooms.push_back(row.get<std::string>(0));
      }
    }
    return rooms;
  }

  // Count total gaps across all rooms
  int64_t count_total_gaps(LoggingTransaction& txn) {
    auto result = txn.select_one(
        "SELECT COUNT(*) FROM event_backward_extremities", {});
    if (result && !result->is_null()) {
      return result->get<int64_t>(0);
    }
    return 0;
  }

private:
  DatabasePool& db_pool_;
};

// ============================================================================
// EventPersistencePipeline - Composes all components into a unified pipeline
// ============================================================================
class EventPersistencePipeline {
public:
  struct PipelineConfig {
    // Configuration for the coordinator
    EventPersistenceCoordinator::Config coordinator_config;

    // Pipeline-specific
    bool auto_dedup = true;
    bool auto_assign_stream_ordering = true;
    bool auto_assign_topological_ordering = true;
    bool auto_manage_extremities = true;
    bool auto_reject_on_validation_failure = false;
    int64_t batch_flush_threshold = 200;

    // Backfill
    bool enable_auto_backfill = false;
    int64_t backfill_batch_size = 50;
    int64_t max_backfill_per_room = 500;
  };

  EventPersistencePipeline(DatabasePool& db_pool,
                           const std::string& instance_name,
                           const PipelineConfig& config = {})
      : db_pool_(db_pool),
        instance_name_(instance_name),
        config_(config),
        coordinator_(db_pool, instance_name, config.coordinator_config),
        content_store_(db_pool),
        metadata_store_(db_pool),
        gap_tracker_(db_pool),
        stream_writer_(db_pool, stream_gen_) {

    // Alias for convenience - the coordinator owns the stream gen
    (void)stream_writer_; // will be re-initialized with coordinator's generator

    // Recover stream ordering from DB
    coordinator_.recover_stream_ordering("");
  }

  // ==========================================================================
  // Full pipeline: process incoming events through all stages
  // ==========================================================================
  struct PipelineResult {
    int total_received = 0;
    int passed_validation = 0;
    int duplicates_removed = 0;
    int rejected = 0;
    int soft_failed = 0;
    int persisted = 0;
    std::map<std::string, int64_t> assigned_stream_orderings;
    std::map<std::string, int64_t> assigned_topological_orderings;
    std::vector<std::string> validation_errors;
    bool success = false;
  };

  PipelineResult process_events(
      const std::vector<EventPersistencePair>& events_and_contexts,
      const std::string& room_id,
      bool is_backfill = false) {

    PipelineResult result;
    result.total_received = static_cast<int>(events_and_contexts.size());

    if (events_and_contexts.empty()) {
      result.success = true;
      return result;
    }

    // Stage 1: Validation
    std::vector<EventPersistencePair> validated;
    for (const auto& pair : events_and_contexts) {
      auto validation = coordinator_.validate_event(pair.event);
      if (validation != EventValidationResult::VALID) {
        result.validation_errors.push_back(
            std::string(pair.event.event_id) + ": " +
            validation_result_to_string(validation));
        if (config_.auto_reject_on_validation_failure) {
          db_pool_.runInteraction(
              "reject_invalid_event",
              [&](LoggingTransaction& txn) {
                coordinator_.reject_event(
                    txn, pair.event.event_id,
                    validation_result_to_string(validation));
                result.rejected++;
              });
        }
        continue;
      }
      result.passed_validation++;
      validated.push_back(pair);
    }

    if (validated.empty()) {
      result.success = true;
      return result;
    }

    // Stage 2: Dedup (optional - coordinator does this inside persist)
    std::vector<EventPersistencePair> deduped;
    if (config_.auto_dedup) {
      for (auto& pair : validated) {
        std::string hash = coordinator_.compute_hash(pair.event);
        if (coordinator_.is_event_duplicate(pair.event.event_id)) {
          result.duplicates_removed++;
          continue;
        }
        deduped.push_back(pair);
      }
    } else {
      deduped = std::move(validated);
    }

    if (deduped.empty()) {
      result.success = true;
      return result;
    }

    // Stage 3: Persist
    EventBatchPersistenceEngine::BatchPersistenceResult persist_result;
    if (is_backfill) {
      persist_result = coordinator_.persist_backfill_events(
          deduped, room_id);
    } else {
      persist_result = coordinator_.persist_events(deduped, room_id);
    }

    result.persisted = persist_result.persisted;
    result.duplicates_removed += persist_result.duplicates;
    result.rejected += persist_result.rejected;
    result.soft_failed += persist_result.soft_failed;

    // Collect assigned stream orderings
    for (const auto& eid : persist_result.persisted_event_ids) {
      // Get from DB
      db_pool_.runInteraction(
          "get_stream_ordering",
          [&](LoggingTransaction& txn) {
            auto row = txn.select_one(
                "SELECT stream_ordering, topological_ordering FROM events "
                "WHERE event_id = ?",
                {eid});
            if (row && !row->is_null()) {
              result.assigned_stream_orderings[eid] = row->get<int64_t>(0);
              result.assigned_topological_orderings[eid] = row->get<int64_t>(1);
            }
          });
    }

    // Stage 4: Post-persistence actions
    if (config_.auto_manage_extremities && persist_result.persisted > 0 && !is_backfill) {
      db_pool_.runInteraction(
          "manage_extremities_post_persist",
          [&](LoggingTransaction& txn) {
            // Ensure backfill extremities are initialized for forward extremities
            coordinator_.initialize_backfill_from_forward_extremities(txn, room_id);
          });
    }

    result.success = persist_result.overall_success;
    return result;
  }

  // ==========================================================================
  // Backfill-specific pipeline
  // ==========================================================================
  struct BackfillResult {
    int events_requested = 0;
    int events_received = 0;
    int events_persisted = 0;
    int gaps_resolved = 0;
    int gaps_remaining = 0;
    std::vector<std::string> new_gaps_discovered;
    bool full_chain_resolved = false;
  };

  BackfillResult process_backfill(
      const std::vector<EventPersistencePair>& events_and_contexts,
      const std::string& room_id,
      const std::set<std::string>& event_ids_being_backfilled) {

    BackfillResult bf_result;
    bf_result.events_received = static_cast<int>(events_and_contexts.size());

    auto result = process_events(events_and_contexts, room_id, true);
    bf_result.events_persisted = result.persisted;

    // Update backfill tracking
    db_pool_.runInteraction(
        "update_backfill_tracking",
        [&](LoggingTransaction& txn) {
          for (const auto& eid : event_ids_being_backfilled) {
            if (result.assigned_stream_orderings.count(eid)) {
              gap_tracker_.mark_gap_resolved(txn, eid);
              bf_result.gaps_resolved++;
            }
          }

          // Detect new gaps introduced by backfilled events
          auto new_gaps = gap_tracker_.detect_gaps(txn, room_id, 50);
          for (const auto& gap : new_gaps) {
            bf_result.new_gaps_discovered.push_back(gap.missing_event_id);
          }

          bf_result.gaps_remaining = static_cast<int>(
              gap_tracker_.count_total_gaps(txn));
        });

    bf_result.full_chain_resolved = (bf_result.gaps_remaining == 0);

    return bf_result;
  }

  // ==========================================================================
  // Scheduled backfill: process pending gaps for a room
  // ==========================================================================
  BackfillResult perform_scheduled_backfill(
      const std::string& room_id,
      int64_t max_to_request = 50) {

    BackfillResult bf_result;

    // Get the backfill queue
    std::vector<std::string> events_to_backfill;
    std::set<std::string> events_set;

    db_pool_.runInteraction(
        "get_backfill_queue",
        [&](LoggingTransaction& txn) {
          events_to_backfill = coordinator_.get_backfill_queue(
              txn, room_id, max_to_request);
          events_set.insert(events_to_backfill.begin(), events_to_backfill.end());
        });

    bf_result.events_requested = static_cast<int>(events_to_backfill.size());

    // Note: actual federation request and event reception would be handled
    // by the caller (the federation layer). This method just prepares the queue.
    // The caller would then call process_backfill with the actual events.

    return bf_result;
  }

  // ==========================================================================
  // Get the coordinator for direct access to its API
  // ==========================================================================
  EventPersistenceCoordinator& coordinator() { return coordinator_; }
  const EventPersistenceCoordinator& coordinator() const { return coordinator_; }

  // ==========================================================================
  // Get the gap tracker
  // ==========================================================================
  EventGapTracker& gaps() { return gap_tracker_; }

  // ==========================================================================
  // Stats / diagnostics
  // ==========================================================================
  PipelineResult get_pipeline_stats() {
    auto stats = coordinator_.get_stats();

    PipelineResult result;
    // Map coordinator stats to pipeline result
    return result;
  }

  // ==========================================================================
  // Reset pipeline state
  // ==========================================================================
  void reset() {
    coordinator_.clear_dedup_cache();
    coordinator_.recover_stream_ordering("");
  }

private:
  DatabasePool& db_pool_;
  std::string instance_name_;
  PipelineConfig config_;

  EventPersistenceCoordinator coordinator_;
  EventContentStore content_store_;
  EventMetadataStore metadata_store_;
  EventGapTracker gap_tracker_;
  StreamOrderingGenerator& stream_gen_; // Reference to coordinator's generator
  EventStreamWriter stream_writer_;
};

// ============================================================================
// Main Event Persistence Store class
// Translates the full Synapse event persistence flow into a unified C++ class
// ============================================================================
class EventPersistenceStore {
public:
  EventPersistenceStore(DatabasePool& db_pool,
                        const std::string& instance_name,
                        bool is_mine_id_func(const std::string&),
                        int64_t (*time_msec)())
      : db_pool_(db_pool),
        instance_name_(instance_name),
        is_mine_id_(is_mine_id_func),
        time_msec_(time_msec),
        pipeline_(db_pool, instance_name) {
    // Recover state from database
    db_pool_.runInteraction(
        "init_event_persistence",
        [&](LoggingTransaction& txn) {
          auto max_stream = txn.select_one(
              "SELECT MAX(stream_ordering) FROM events", {});
          if (max_stream && !max_stream->is_null()) {
            stream_ordering_current_ = max_stream->get<int64_t>(0);
          }

          auto min_backfill = txn.select_one(
              "SELECT MIN(stream_ordering) FROM events WHERE stream_ordering < 0", {});
          if (min_backfill && !min_backfill->is_null()) {
            backfill_ordering_current_ = min_backfill->get<int64_t>(0) - 1;
          }
        });
  }

  ~EventPersistenceStore() = default;

  // ==========================================================================
  // Public API: Full event persistence
  // ==========================================================================

  // Persist events with full pipeline processing
  bool persist_events(
      const std::vector<EventPersistencePair>& events_and_contexts,
      const std::string& room_id) {

    auto result = pipeline_.process_events(events_and_contexts, room_id, false);
    return result.success && result.persisted > 0;
  }

  // Persist backfill events
  bool persist_backfill_events(
      const std::vector<EventPersistencePair>& events_and_contexts,
      const std::string& room_id) {

    auto result = pipeline_.process_events(events_and_contexts, room_id, true);
    return result.success && result.persisted > 0;
  }

  // Persist a single event
  bool persist_single_event(
      const EventData& event,
      const EventContext& context,
      const std::string& room_id) {

    auto result = pipeline_.coordinator().persist_single_event(event, context, room_id);
    return result.success;
  }

  // ==========================================================================
  // Dedup
  // ==========================================================================
  bool is_event_duplicate(const std::string& event_id) {
    return pipeline_.coordinator().is_event_duplicate(event_id);
  }

  std::string compute_content_hash(const EventData& event) {
    return pipeline_.coordinator().compute_hash(event);
  }

  // ==========================================================================
  // Stream ordering
  // ==========================================================================
  int64_t allocate_stream_ordering() {
    return stream_ordering_current_.fetch_add(1) + 1;
  }

  int64_t allocate_backfill_ordering() {
    int64_t val = backfill_ordering_current_.fetch_sub(1);
    return val;
  }

  int64_t current_max_stream() const {
    return stream_ordering_current_.load();
  }

  // ==========================================================================
  // Extremity management
  // ==========================================================================
  void set_forward_extremities(
      const std::string& room_id,
      const std::set<std::string>& extremities) {
    db_pool_.runInteraction(
        "set_forward_extremities",
        [&](LoggingTransaction& txn) {
          pipeline_.coordinator().replace_forward_extremities(
              txn, room_id, extremities);
        });
  }

  std::set<std::string> get_forward_extremities(const std::string& room_id) {
    std::set<std::string> result;
    db_pool_.runInteraction(
        "get_forward_extremities",
        [&](LoggingTransaction& txn) {
          result = pipeline_.coordinator().get_forward_extremities(txn, room_id);
        });
    return result;
  }

  void add_forward_extremity(const std::string& room_id,
                              const std::string& event_id) {
    db_pool_.runInteraction(
        "add_forward_extremity",
        [&](LoggingTransaction& txn) {
          pipeline_.coordinator().add_forward_extremity(txn, room_id, event_id);
        });
  }

  void remove_forward_extremity(const std::string& room_id,
                                 const std::string& event_id) {
    db_pool_.runInteraction(
        "remove_forward_extremity",
        [&](LoggingTransaction& txn) {
          pipeline_.coordinator().remove_forward_extremity(txn, room_id, event_id);
        });
  }

  // ==========================================================================
  // Backfill management
  // ==========================================================================
  void initialize_backfill_extremities(const std::string& room_id) {
    db_pool_.runInteraction(
        "init_backfill_extremities",
        [&](LoggingTransaction& txn) {
          pipeline_.coordinator().initialize_backfill_from_forward_extremities(
              txn, room_id);
        });
  }

  std::vector<std::string> get_backfill_queue(
      const std::string& room_id,
      int64_t limit = 50) {
    std::vector<std::string> result;
    db_pool_.runInteraction(
        "get_backfill_queue",
        [&](LoggingTransaction& txn) {
          result = pipeline_.coordinator().get_backfill_queue(txn, room_id, limit);
        });
    return result;
  }

  void record_failed_backfill(
      const std::string& room_id,
      const std::string& event_id,
      const std::string& cause) {
    db_pool_.runInteraction(
        "record_failed_backfill",
        [&](LoggingTransaction& txn) {
          pipeline_.coordinator().record_failed_backfill(
              txn, room_id, event_id, cause);
        });
  }

  // ==========================================================================
  // Rejection management
  // ==========================================================================
  void reject_event(const std::string& event_id,
                    const std::string& reason) {
    db_pool_.runInteraction(
        "reject_event",
        [&](LoggingTransaction& txn) {
          pipeline_.coordinator().reject_event(txn, event_id, reason);
        });
  }

  void soft_fail_event(const std::string& event_id,
                       const std::string& reason) {
    db_pool_.runInteraction(
        "soft_fail_event",
        [&](LoggingTransaction& txn) {
          pipeline_.coordinator().soft_fail_event(txn, event_id, reason);
        });
  }

  bool is_event_rejected(const std::string& event_id) {
    bool result = false;
    db_pool_.runInteraction(
        "check_rejected",
        [&](LoggingTransaction& txn) {
          result = pipeline_.coordinator().is_event_rejected(txn, event_id);
        });
    return result;
  }

  bool is_event_soft_failed(const std::string& event_id) {
    bool result = false;
    db_pool_.runInteraction(
        "check_soft_failed",
        [&](LoggingTransaction& txn) {
          result = pipeline_.coordinator().is_event_soft_failed(txn, event_id);
        });
    return result;
  }

  void clear_rejection(const std::string& event_id) {
    db_pool_.runInteraction(
        "clear_rejection",
        [&](LoggingTransaction& txn) {
          pipeline_.coordinator().clear_rejection(txn, event_id);
        });
  }

  // ==========================================================================
  // Outlier management
  // ==========================================================================
  void mark_outlier(const std::string& event_id) {
    db_pool_.runInteraction(
        "mark_outlier",
        [&](LoggingTransaction& txn) {
          pipeline_.coordinator().mark_as_outlier(txn, event_id);
        });
  }

  void unmark_outlier(const std::string& event_id) {
    db_pool_.runInteraction(
        "unmark_outlier",
        [&](LoggingTransaction& txn) {
          pipeline_.coordinator().unmark_outlier(txn, event_id);
        });
  }

  // ==========================================================================
  // Edge / DAG queries
  // ==========================================================================
  std::vector<std::string> get_prev_events(const std::string& event_id) {
    std::vector<std::string> result;
    db_pool_.runInteraction(
        "get_prev_events",
        [&](LoggingTransaction& txn) {
          result = pipeline_.coordinator().get_prev_events(txn, event_id);
        });
    return result;
  }

  bool has_path(const std::string& event_a, const std::string& event_b) {
    bool result = false;
    db_pool_.runInteraction(
        "check_path",
        [&](LoggingTransaction& txn) {
          result = pipeline_.coordinator().has_path_between(txn, event_a, event_b);
        });
    return result;
  }

  // ==========================================================================
  // Gap tracking
  // ==========================================================================
  int64_t count_holes_in_room(const std::string& room_id) {
    int64_t count = 0;
    db_pool_.runInteraction(
        "count_gaps",
        [&](LoggingTransaction& txn) {
          auto result = txn.select_one(
              "SELECT COUNT(*) FROM event_backward_extremities WHERE room_id = ?",
              {room_id});
          if (result && !result->is_null()) {
            count = result->get<int64_t>(0);
          }
        });
    return count;
  }

  // ==========================================================================
  // Validation
  // ==========================================================================
  bool validate_event(const EventData& event,
                      std::string& error_out) {
    auto result = pipeline_.coordinator().validate_event(event);
    if (result != EventValidationResult::VALID) {
      error_out = validation_result_to_string(result);
      return false;
    }
    return true;
  }

  // ==========================================================================
  // Cache management
  // ==========================================================================
  void clear_dedup_cache() {
    pipeline_.coordinator().clear_dedup_cache();
  }

  void reset_stream_ordering(int64_t new_value = 0) {
    stream_ordering_current_.store(new_value);
    pipeline_.coordinator().recover_stream_ordering("");
  }

  // ==========================================================================
  // Stats
  // ==========================================================================
  struct StoreStats {
    int64_t total_persisted{0};
    int64_t total_rejected{0};
    int64_t total_backfilled{0};
    int64_t stream_ordering_max{0};
    int64_t backfill_ordering_min{0};
    int64_t dedup_cache_size{0};
  };

  StoreStats get_stats() {
    StoreStats s;
    auto coord_stats = pipeline_.coordinator().get_stats();
    s.stream_ordering_max = coord_stats.stream_ordering_max;
    s.backfill_ordering_min = coord_stats.backfill_ordering_min;
    s.dedup_cache_size = coord_stats.dedup_cache_entries;
    s.total_persisted = coord_stats.total_persisted;
    s.total_rejected = coord_stats.total_rejected;
    s.total_backfilled = coord_stats.total_backfilled;
    return s;
  }

private:
  DatabasePool& db_pool_;
  std::string instance_name_;
  std::function<bool(const std::string&)> is_mine_id_;
  std::function<int64_t()> time_msec_;

  std::atomic<int64_t> stream_ordering_current_{0};
  std::atomic<int64_t> backfill_ordering_current_{-1000000};

  EventPersistencePipeline pipeline_;
};

// ============================================================================
// EventRecoveryManager - Recovers event state after restart
// ============================================================================
class EventRecoveryManager {
public:
  explicit EventRecoveryManager(DatabasePool& db_pool)
      : db_pool_(db_pool) {}

  // Recover stream ordering generator state
  int64_t recover_stream_ordering() {
    int64_t max_order = 0;
    db_pool_.runInteraction(
        "recover_stream_ordering",
        [&](LoggingTransaction& txn) {
          auto result = txn.select_one(
              "SELECT MAX(stream_ordering) FROM events", {});
          if (result && !result->is_null()) {
            max_order = result->get<int64_t>(0);
          }
        });
    return max_order;
  }

  // Recover backfill ordering state
  int64_t recover_backfill_ordering() {
    int64_t min_order = 0;
    db_pool_.runInteraction(
        "recover_backfill_ordering",
        [&](LoggingTransaction& txn) {
          auto result = txn.select_one(
              "SELECT MIN(stream_ordering) FROM events WHERE stream_ordering < 0", {});
          if (result && !result->is_null()) {
            min_order = result->get<int64_t>(0);
          }
        });
    return min_order - 1;
  }

  // Recover forward extremities from DB
  std::map<std::string, std::set<std::string>> recover_forward_extremities() {
    std::map<std::string, std::set<std::string>> result;
    db_pool_.runInteraction(
        "recover_forward_extremities",
        [&](LoggingTransaction& txn) {
          auto rows = txn.select(
              "SELECT room_id, event_id FROM event_forward_extremities", {});
          for (auto& row : rows) {
            if (!row.is_null()) {
              std::string room_id = row.get<std::string>(0);
              std::string event_id = row.get<std::string>(1);
              result[room_id].insert(event_id);
            }
          }
        });
    return result;
  }

  // Recover backfill extremities
  std::map<std::string, std::set<std::string>> recover_backfill_extremities() {
    std::map<std::string, std::set<std::string>> result;
    db_pool_.runInteraction(
        "recover_backfill_extremities",
        [&](LoggingTransaction& txn) {
          auto rows = txn.select(
              "SELECT room_id, event_id FROM event_backward_extremities", {});
          for (auto& row : rows) {
            if (!row.is_null()) {
              std::string room_id = row.get<std::string>(0);
              std::string event_id = row.get<std::string>(1);
              result[room_id].insert(event_id);
            }
          }
        });
    return result;
  }

  // Verify integrity: check that all forward extremities reference valid events
  int64_t verify_forward_extremity_integrity() {
    int64_t orphan_count = 0;
    db_pool_.runInteraction(
        "verify_forward_extremities",
        [&](LoggingTransaction& txn) {
          auto rows = txn.select(
              "SELECT efe.event_id, efe.room_id "
              "FROM event_forward_extremities efe "
              "LEFT JOIN events e ON efe.event_id = e.event_id "
              "WHERE e.event_id IS NULL", {});
          for (auto& row : rows) {
            if (!row.is_null()) {
              std::string event_id = row.get<std::string>(0);
              std::string room_id = row.get<std::string>(1);
              // Remove orphan extremities
              txn.execute(
                  "DELETE FROM event_forward_extremities "
                  "WHERE event_id = ? AND room_id = ?",
                  {event_id, room_id});
              orphan_count++;
            }
          }
        });
    return orphan_count;
  }

  // Repair: rebuild forward extremities from event edges if they are corrupted
  void repair_forward_extremities(const std::string& room_id) {
    db_pool_.runInteraction(
        "repair_forward_extremities",
        [&](LoggingTransaction& txn) {
          // Get all events in the room
          // A forward extremity is an event that no other event references as prev
          auto events = txn.select(
              "SELECT event_id FROM events WHERE room_id = ?", {room_id});

          std::set<std::string> all_event_ids;
          for (auto& row : events) {
            if (!row.is_null()) {
              all_event_ids.insert(row.get<std::string>(0));
            }
          }

          // Get all events that ARE referenced as prev_events
          auto referenced = txn.select(
              "SELECT DISTINCT prev_event_id FROM event_edges WHERE room_id = ?",
              {room_id});
          std::set<std::string> referenced_ids;
          for (auto& row : referenced) {
            if (!row.is_null()) {
              referenced_ids.insert(row.get<std::string>(0));
            }
          }

          // Extremities = events that are NOT referenced
          std::set<std::string> extremities;
          for (const auto& eid : all_event_ids) {
            if (!referenced_ids.count(eid)) {
              extremities.insert(eid);
            }
          }

          // Replace extremities in DB
          txn.execute(
              "DELETE FROM event_forward_extremities WHERE room_id = ?",
              {room_id});
          for (const auto& eid : extremities) {
            txn.execute(
                "INSERT INTO event_forward_extremities (event_id, room_id) "
                "VALUES (?, ?)",
                {eid, room_id});
          }
        });
  }

private:
  DatabasePool& db_pool_;
};

// ============================================================================
// Factory function: Create a configured event persistence store
// ============================================================================
std::unique_ptr<EventPersistenceStore> create_event_persistence_store(
    DatabasePool& db_pool,
    const std::string& instance_name,
    bool (*is_mine_id_func)(const std::string&) = nullptr,
    int64_t (*time_msec_func)() = nullptr) {

  // Default implementations
  static auto default_is_mine = [](const std::string&) -> bool { return true; };
  static auto default_time_msec = []() -> int64_t {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
  };

  if (!is_mine_id_func) is_mine_id_func = +default_is_mine;
  if (!time_msec_func) time_msec_func = +default_time_msec;

  return std::make_unique<EventPersistenceStore>(
      db_pool, instance_name, is_mine_id_func, time_msec_func);
}

// ============================================================================
// Standalone utility functions exposed for use by other modules
// ============================================================================

// Compute a content hash for dedup purposes (used by event_auth, etc.)
std::string compute_event_content_hash(const json& event_json) {
  return compute_content_hash(event_json);
}

// Compute a fingerprint for soft dedup
std::string compute_event_fingerprint(
    const std::string& event_type,
    const std::string& sender,
    const json& content,
    const std::optional<std::string>& state_key) {
  return compute_fingerprint(event_type, sender, content, state_key);
}

// Compute topological ordering for a single event
int64_t compute_topological_ordering_for_event(
    LoggingTransaction& txn,
    const std::vector<std::string>& prev_event_ids,
    int64_t depth) {
  TopologicalOrderingCalculator calc;
  return calc.compute(prev_event_ids, txn, depth);
}

// Collect all prev event IDs from an event (including unsigned data)
std::vector<std::string> collect_all_prev_event_ids(const EventData& event) {
  std::vector<std::string> prevs;
  if (event.unsigned_data.contains("prev_events") &&
      event.unsigned_data["prev_events"].is_array()) {
    for (auto& pe : event.unsigned_data["prev_events"]) {
      if (pe.is_string()) {
        std::string s = pe.get<std::string>();
        if (std::find(prevs.begin(), prevs.end(), s) == prevs.end()) {
          prevs.push_back(s);
        }
      }
    }
  }
  for (const auto& pe : event.prev_event_ids) {
    if (std::find(prevs.begin(), prevs.end(), pe) == prevs.end()) {
      prevs.push_back(pe);
    }
  }
  return prevs;
}

// Check if an event has been fully persisted (exists in all required tables)
bool is_event_fully_persisted(LoggingTransaction& txn,
                               const std::string& event_id) {
  auto ev = txn.select_one("SELECT 1 FROM events WHERE event_id = ?", {event_id});
  if (!ev || ev->is_null()) return false;

  auto js = txn.select_one("SELECT 1 FROM event_json WHERE event_id = ?", {event_id});
  if (!js || js->is_null()) return false;

  return true;
}

// Get event persistence status
enum class EventPersistenceStatus : uint8_t {
  NOT_PERSISTED = 0,
  PARTIALLY_PERSISTED = 1,
  FULLY_PERSISTED = 2,
  REJECTED = 3,
  SOFT_FAILED = 4,
};

EventPersistenceStatus get_event_persistence_status(
    LoggingTransaction& txn,
    const std::string& event_id) {

  // Check rejections first
  auto rej = txn.select_one(
      "SELECT reason FROM event_rejections WHERE event_id = ?", {event_id});
  if (rej && !rej->is_null()) {
    std::string reason = rej->get<std::string>(0);
    if (reason.find("SOFT_FAIL:") == 0) {
      return EventPersistenceStatus::SOFT_FAILED;
    }
    return EventPersistenceStatus::REJECTED;
  }

  // Check events table
  auto ev = txn.select_one("SELECT 1 FROM events WHERE event_id = ?", {event_id});
  if (!ev || ev->is_null()) {
    return EventPersistenceStatus::NOT_PERSISTED;
  }

  // Check event_json
  auto js = txn.select_one("SELECT 1 FROM event_json WHERE event_id = ?", {event_id});
  if (!js || js->is_null()) {
    return EventPersistenceStatus::PARTIALLY_PERSISTED;
  }

  return EventPersistenceStatus::FULLY_PERSISTED;
}

// Clean up partially persisted events (orphaned records)
int64_t cleanup_partial_events(LoggingTransaction& txn) {
  int64_t cleaned = 0;

  // Find events in events table but not in event_json
  auto orphan_metadata = txn.select(
      "SELECT e.event_id FROM events e "
      "LEFT JOIN event_json ej ON e.event_id = ej.event_id "
      "WHERE ej.event_id IS NULL", {});
  for (auto& row : orphan_metadata) {
    if (!row.is_null()) {
      std::string eid = row.get<std::string>(0);
      txn.execute("DELETE FROM events WHERE event_id = ?", {eid});
      txn.execute("DELETE FROM event_auth WHERE event_id = ?", {eid});
      txn.execute("DELETE FROM event_edges WHERE event_id = ?", {eid});
      txn.execute("DELETE FROM event_relations WHERE event_id = ?", {eid});
      cleaned++;
    }
  }

  // Find events in event_json but not in events
  auto orphan_json = txn.select(
      "SELECT ej.event_id FROM event_json ej "
      "LEFT JOIN events e ON ej.event_id = e.event_id "
      "WHERE e.event_id IS NULL", {});
  for (auto& row : orphan_json) {
    if (!row.is_null()) {
      std::string eid = row.get<std::string>(0);
      txn.execute("DELETE FROM event_json WHERE event_id = ?", {eid});
      cleaned++;
    }
  }

  return cleaned;
}

// ============================================================================
// Stream ordering batch allocator - for high-throughput scenarios
// ============================================================================
class StreamOrderingBatchAllocator {
public:
  StreamOrderingBatchAllocator(StreamOrderingGenerator& gen)
      : gen_(gen) {}

  // Pre-allocate N stream orderings
  std::vector<int64_t> allocate(int64_t count) {
    int64_t start = gen_.reserve_block(count);
    std::vector<int64_t> result;
    result.reserve(count);
    for (int64_t i = 0; i < count; ++i) {
      result.push_back(start + i);
    }
    return result;
  }

  // Pre-allocate N backfill orderings
  std::vector<int64_t> allocate_backfill(int64_t count) {
    int64_t start = gen_.reserve_backfill_block(count);
    std::vector<int64_t> result;
    result.reserve(count);
    for (int64_t i = 0; i < count; ++i) {
      result.push_back(start + i);
    }
    return result;
  }

private:
  StreamOrderingGenerator& gen_;
};

} // namespace progressive::storage
