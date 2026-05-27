// ============================================================================
// state_compiler.cpp - Matrix complete room state compiler
// ============================================================================
// Implements:
//   - State group compiler (creation, dedup, lifecycle)
//   - State delta computation (diff between state groups)
//   - Current state derivation (derive full room state)
//   - Event persistence pipeline (persist with state metadata)
//   - Event forward extremity management (DAG head tracking)
//   - Backfill extremity management (backfill anchor points)
//   - Topological ordering computation (DAG ordering)
//   - Stream ordering assignment (monotonic stream IDs)
//   - Event deduplication (by event_id and by hash)
//   - Rejected event handling
//   - Soft-failed event handling
//   - Event auth chain computation
//   - Event edges management (DAG edges)
//   - Event reference hashing (content hashing for refs)
//   - Event size tracking (byte accounting)
//   - Event stream token generation (pagination tokens)
//   - Event batch persistence (bulk event insert)
//   - State group GC (garbage collection)
//   - State autocompression (delta-based storage)
// ============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <deque>
#include <functional>
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../json.hpp"
#include "event_auth.hpp"
#include "room_version.hpp"
#include "state_group.hpp"
#include "state_resolution.hpp"
#include "types.hpp"

namespace progressive::state {

// ============================================================================
// LOCAL TYPES
// ============================================================================

// StateDelta: the difference between two state maps.
// Defined here because it is forward-declared in state_resolution_v2.cpp
// but its full definition lives in an anonymous namespace there.
struct StateDelta {
  StateMap added;      // Keys present in new_state but not in old_state
  StateMap removed;    // Keys present in old_state but not in new_state
  StateMap modified;   // Keys present in both but with different values
  size_t added_count = 0;
  size_t removed_count = 0;
  size_t modified_count = 0;
  size_t unchanged_count = 0;

  bool empty() const {
    return added.empty() && removed.empty() && modified.empty();
  }

  size_t total_changes() const {
    return added.size() + removed.size() + modified.size();
  }
};

using json = nlohmann::json;

// ============================================================================
// FORWARD DECLARATIONS
// ============================================================================

namespace {
struct StateGroupEntry;
struct EventPersistenceContext;
struct ForwardExtremity;
struct BackfillExtremity;
struct StreamToken;
struct EventEdge;
struct RejectedEvent;
struct SoftFailedEvent;
struct EventAuthChainEntry;
struct EventBatch;
struct CompileMetrics;
class StateGroupCache;
class EventDeduplicator;
class EventHasher;
class StreamOrderGenerator;
class TopologicalOrderGenerator;
class ExtremityManager;
class AuthChainComputer;
class EdgeManager;
class SizeTracker;
class TokenGenerator;
class BatchPersister;
class StateGroupGC;
class StateAutocompressor;
}

// ============================================================================
// 1. STATE GROUP ENTRY
// ============================================================================
// Represents a single state group with its metadata, delta from parent,
// and usage tracking.

namespace {

struct StateGroupEntry {
  int64_t group_id = 0;              // Unique group ID
  int64_t prev_group_id = 0;         // Parent group (for delta chains)
  StateMap state;                    // Full state map (or empty if delta-only)
  StateDelta delta_from_prev;        // Delta computed from parent
  int64_t created_at = 0;            // Creation timestamp (epoch seconds)
  int64_t last_accessed_at = 0;      // Last access timestamp
  int64_t reference_count = 0;       // Number of events referencing this group
  bool is_compressed = false;        // Whether stored as delta
  bool is_garbage = false;           // Marked for GC
  std::string room_id;              // Owning room
  std::string creator_event_id;     // Event that caused this group's creation
  size_t state_size = 0;            // Number of entries in full state
  size_t delta_size = 0;            // Number of entries in delta
  size_t byte_size = 0;             // Approximate memory footprint

  bool operator<(const StateGroupEntry& other) const {
    return group_id < other.group_id;
  }
};

}  // namespace

// ============================================================================
// 2. STATE GROUP CACHE
// ============================================================================
// Thread-safe cache for state group lookups.

namespace {

class StateGroupCache {
public:
  explicit StateGroupCache(size_t max_entries = 5000, int64_t ttl_seconds = 600)
      : max_entries_(max_entries), ttl_seconds_(ttl_seconds) {}

  std::optional<StateGroupEntry> get(int64_t group_id) {
    std::shared_lock lock(mutex_);
    auto it = entries_.find(group_id);
    if (it == entries_.end()) {
      misses_.fetch_add(1, std::memory_order_relaxed);
      return std::nullopt;
    }

    auto now = now_seconds();
    if (now - it->second.last_accessed_at > ttl_seconds_ && ttl_seconds_ > 0) {
      misses_.fetch_add(1, std::memory_order_relaxed);
      return std::nullopt;
    }

    hits_.fetch_add(1, std::memory_order_relaxed);
    return it->second;
  }

  void put(int64_t group_id, const StateGroupEntry& entry) {
    std::unique_lock lock(mutex_);
    if (entries_.size() >= max_entries_) {
      evict_lru();
    }
    entries_[group_id] = entry;
    entries_[group_id].last_accessed_at = now_seconds();
  }

  void touch(int64_t group_id) {
    std::unique_lock lock(mutex_);
    auto it = entries_.find(group_id);
    if (it != entries_.end())
      it->second.last_accessed_at = now_seconds();
  }

  void remove(int64_t group_id) {
    std::unique_lock lock(mutex_);
    entries_.erase(group_id);
  }

  void invalidate_room(const std::string& room_id) {
    std::unique_lock lock(mutex_);
    for (auto it = entries_.begin(); it != entries_.end();) {
      if (it->second.room_id == room_id)
        it = entries_.erase(it);
      else
        ++it;
    }
  }

  void clear() {
    std::unique_lock lock(mutex_);
    entries_.clear();
    hits_.store(0);
    misses_.store(0);
  }

  struct Stats {
    size_t size = 0;
    size_t max_size = 0;
    uint64_t hits = 0;
    uint64_t misses = 0;
    double hit_rate = 0.0;
  };

  Stats get_stats() const {
    std::shared_lock lock(mutex_);
    Stats s;
    s.size = entries_.size();
    s.max_size = max_entries_;
    s.hits = hits_.load(std::memory_order_relaxed);
    s.misses = misses_.load(std::memory_order_relaxed);
    uint64_t total = s.hits + s.misses;
    if (total > 0)
      s.hit_rate = static_cast<double>(s.hits) / static_cast<double>(total);
    return s;
  }

private:
  void evict_lru() {
    if (entries_.empty()) return;
    auto oldest = entries_.begin();
    for (auto it = entries_.begin(); it != entries_.end(); ++it) {
      if (it->second.last_accessed_at < oldest->second.last_accessed_at)
        oldest = it;
    }
    entries_.erase(oldest);
  }

  static int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
  }

  size_t max_entries_;
  int64_t ttl_seconds_;
  mutable std::shared_mutex mutex_;
  std::map<int64_t, StateGroupEntry> entries_;
  std::atomic<uint64_t> hits_{0};
  std::atomic<uint64_t> misses_{0};
};

}  // namespace

// ============================================================================
// 3. STATE DELTA COMPUTATION
// ============================================================================
// Compute the delta between two state maps: added, removed, modified keys.

namespace {

StateDelta compute_delta(const StateMap& old_state, const StateMap& new_state) {
  StateDelta delta;

  // Find added and modified keys
  for (const auto& [key, val] : new_state) {
    auto old_it = old_state.find(key);
    if (old_it == old_state.end()) {
      delta.added[key] = val;
    } else if (old_it->second != val) {
      delta.modified[key] = val;
    } else {
      delta.unchanged_count++;
    }
  }

  // Find removed keys
  for (const auto& [key, val] : old_state) {
    if (new_state.find(key) == new_state.end()) {
      delta.removed[key] = val;
    }
  }

  delta.added_count = delta.added.size();
  delta.removed_count = delta.removed.size();
  delta.modified_count = delta.modified.size();

  return delta;
}

// Apply a delta on top of a base state to produce a new state.
StateMap apply_delta(const StateMap& base, const StateDelta& delta) {
  StateMap result = base;

  for (const auto& [k, v] : delta.added)
    result[k] = v;
  for (const auto& [k, v] : delta.modified)
    result[k] = v;
  for (const auto& [k, _] : delta.removed)
    result.erase(k);

  return result;
}

// Invert a delta: from new->old becomes old->new
StateDelta invert_delta(const StateMap& old_state,
                         const StateDelta& forward_delta) {
  StateDelta inverted;
  // Added in forward = Removed in inverse
  for (const auto& [k, v] : forward_delta.added) {
    inverted.removed[k] = v;
  }
  // Removed in forward = Added in inverse
  for (const auto& [k, v] : forward_delta.removed) {
    inverted.added[k] = v;
  }
  // Modified in forward = Modified in inverse (swap values)
  for (const auto& [k, v] : forward_delta.modified) {
    auto old_it = old_state.find(k);
    if (old_it != old_state.end())
      inverted.modified[k] = old_it->second;
    else
      inverted.removed[k] = v;
  }
  inverted.added_count = inverted.added.size();
  inverted.removed_count = inverted.removed.size();
  inverted.modified_count = inverted.modified.size();
  return inverted;
}

}  // namespace

// ============================================================================
// 4. EVENT DEDUPLICATOR
// ============================================================================
// Prevents duplicate events from being stored. Tracks event IDs and
// content hashes.

namespace {

class EventDeduplicator {
public:
  struct Config {
    size_t max_dedup_cache = 100000;    // Max dedup entries
    int64_t dedup_ttl_seconds = 3600;   // TTL for dedup entries
    bool enable_hash_dedup = true;      // Enable content-hash-based dedup
    size_t hash_cache_size = 50000;     // Max hash entries
  };

  explicit EventDeduplicator(Config cfg = {}) : config_(std::move(cfg)) {}

  // Check if an event ID has already been seen.
  bool is_duplicate(const EventId& event_id) {
    std::shared_lock lock(mutex_);
    return dedup_set_.count(event_id) > 0;
  }

  // Check if an event's content hash has been seen (hash dedup).
  bool is_duplicate_by_hash(const std::string& content_hash) {
    if (!config_.enable_hash_dedup) return false;
    std::shared_lock lock(mutex_);
    return hash_set_.count(content_hash) > 0;
  }

  // Mark an event ID as seen. Returns false if it was already seen.
  bool mark_seen(const EventId& event_id) {
    std::unique_lock lock(mutex_);
    evacuate_if_needed();
    auto [it, inserted] = dedup_set_.insert(event_id);
    if (inserted) {
      dedup_timestamps_[event_id] = now_steady();
    }
    return inserted;
  }

  // Mark a content hash as seen.
  bool mark_hash_seen(const std::string& content_hash) {
    if (!config_.enable_hash_dedup) return false;
    std::unique_lock lock(mutex_);
    evacuate_if_needed();
    auto [it, inserted] = hash_set_.insert(content_hash);
    if (inserted) {
      hash_timestamps_[content_hash] = now_steady();
    }
    return inserted;
  }

  // Check and mark in one step. Returns inserted (false = duplicate).
  bool check_and_mark(const EventId& event_id) {
    std::unique_lock lock(mutex_);
    evacuate_if_needed();
    auto [it, inserted] = dedup_set_.insert(event_id);
    if (inserted) {
      dedup_timestamps_[event_id] = now_steady();
    }
    return inserted;
  }

  // Remove an event ID from dedup (e.g., after deletion).
  void remove(const EventId& event_id) {
    std::unique_lock lock(mutex_);
    dedup_set_.erase(event_id);
    dedup_timestamps_.erase(event_id);
  }

  // Clear stale entries beyond TTL.
  size_t clear_stale() {
    std::unique_lock lock(mutex_);
    auto now = now_steady();
    size_t removed = 0;

    for (auto it = dedup_timestamps_.begin();
         it != dedup_timestamps_.end();) {
      auto age = std::chrono::duration_cast<std::chrono::seconds>(
          now - it->second).count();
      if (age > config_.dedup_ttl_seconds) {
        dedup_set_.erase(it->first);
        it = dedup_timestamps_.erase(it);
        removed++;
      } else {
        ++it;
      }
    }

    for (auto it = hash_timestamps_.begin();
         it != hash_timestamps_.end();) {
      auto age = std::chrono::duration_cast<std::chrono::seconds>(
          now - it->second).count();
      if (age > config_.dedup_ttl_seconds) {
        hash_set_.erase(it->first);
        it = hash_timestamps_.erase(it);
        removed++;
      } else {
        ++it;
      }
    }

    return removed;
  }

  size_t dedup_size() const {
    std::shared_lock lock(mutex_);
    return dedup_set_.size();
  }

  size_t hash_size() const {
    std::shared_lock lock(mutex_);
    return hash_set_.size();
  }

  void clear() {
    std::unique_lock lock(mutex_);
    dedup_set_.clear();
    dedup_timestamps_.clear();
    hash_set_.clear();
    hash_timestamps_.clear();
  }

private:
  void evacuate_if_needed() {
    if (dedup_set_.size() >= config_.max_dedup_cache) {
      clear_stale();
    }
    if (dedup_set_.size() >= config_.max_dedup_cache) {
      // Force evict oldest 25%
      size_t to_evict = dedup_set_.size() / 4;
      auto now = now_steady();
      std::vector<std::pair<EventId, std::chrono::steady_clock::time_point>> sorted;
      for (const auto& [eid, ts] : dedup_timestamps_)
        sorted.push_back({eid, ts});
      std::sort(sorted.begin(), sorted.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
      for (size_t i = 0; i < to_evict && i < sorted.size(); i++) {
        dedup_set_.erase(sorted[i].first);
        dedup_timestamps_.erase(sorted[i].first);
      }
    }
  }

  static std::chrono::steady_clock::time_point now_steady() {
    return std::chrono::steady_clock::now();
  }

  Config config_;
  mutable std::shared_mutex mutex_;
  std::unordered_set<EventId> dedup_set_;
  std::map<EventId, std::chrono::steady_clock::time_point> dedup_timestamps_;
  std::unordered_set<std::string> hash_set_;
  std::map<std::string, std::chrono::steady_clock::time_point> hash_timestamps_;
};

}  // namespace

// ============================================================================
// 5. EVENT HASHER
// ============================================================================
// Computes reference hashes for events. Used for hash-based dedup and
// event integrity verification.

namespace {

class EventHasher {
public:
  // Compute a content hash from the event's essential fields.
  // This is used for hash-based deduplication.
  static std::string compute_content_hash(const ResolvableEvent& event) {
    std::string canonical;
    canonical.reserve(512);

    canonical += event.room_id;
    canonical += '\x00';
    canonical += event.type;
    canonical += '\x00';
    canonical += event.state_key;
    canonical += '\x00';
    canonical += event.sender;
    canonical += '\x00';
    canonical += std::to_string(event.depth);
    canonical += '\x00';
    canonical += std::to_string(event.origin_server_ts);
    canonical += '\x00';

    // Include content as sorted JSON for determinism
    std::string content_str = event.content.dump(-1, ' ', false,
        nlohmann::json::error_handler_t::replace);
    canonical += content_str;

    // Compute SHA-256-like hash (simplified: use std::hash chain)
    size_t h = std::hash<std::string>{}(canonical);
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << h;
    return ss.str();
  }

  // Compute a reference hash that includes auth events and prev events.
  // This ties the event to its DAG position.
  static std::string compute_reference_hash(const ResolvableEvent& event) {
    std::string ref;
    ref.reserve(1024);

    // Include content hash
    ref += compute_content_hash(event);
    ref += '\x00';

    // Include auth event IDs (sorted for determinism)
    std::vector<EventId> sorted_auth = event.auth_event_ids;
    std::sort(sorted_auth.begin(), sorted_auth.end());
    for (const auto& aid : sorted_auth) {
      ref += aid;
      ref += ',';
    }

    ref += '\x00';

    // Include prev event IDs (sorted)
    std::vector<EventId> sorted_prev = event.prev_event_ids;
    std::sort(sorted_prev.begin(), sorted_prev.end());
    for (const auto& pid : sorted_prev) {
      ref += pid;
      ref += ',';
    }

    size_t h = std::hash<std::string>{}(ref);
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(16) << h;
    return ss.str();
  }

  // Compute event ID from reference hash (for MSC4291 room IDs as hashes)
  static std::string event_id_from_hash(const std::string& hash,
                                          const std::string& origin_server) {
    size_t h = std::hash<std::string>{}(hash + origin_server);
    std::stringstream ss;
    ss << '$' << std::hex << std::setfill('0') << std::setw(16) << h;
    return ss.str();
  }

  // Batch hash a vector of events
  static std::map<EventId, std::string> batch_hash_events(
      const std::vector<ResolvableEvent>& events) {
    std::map<EventId, std::string> result;
    for (const auto& ev : events) {
      result[ev.event_id] = compute_reference_hash(ev);
    }
    return result;
  }
};

}  // namespace

// ============================================================================
// 6. STREAM ORDER GENERATOR
// ============================================================================
// Assigns monotonic stream ordering to events. Guarantees that events
// persisted later have higher stream orderings.

namespace {

class StreamOrderGenerator {
public:
  explicit StreamOrderGenerator(int64_t initial_order = 1)
      : next_order_(initial_order) {}

  // Allocate the next stream ordering value.
  int64_t next() {
    return next_order_.fetch_add(1, std::memory_order_relaxed);
  }

  // Allocate a batch of stream orderings. Returns the first value.
  int64_t next_batch(size_t count) {
    return next_order_.fetch_add(static_cast<int64_t>(count),
                                  std::memory_order_relaxed);
  }

  // Peek at the next value without allocating.
  int64_t peek() const {
    return next_order_.load(std::memory_order_relaxed);
  }

  // Get the current maximum allocated value.
  int64_t max() const {
    return next_order_.load(std::memory_order_relaxed) - 1;
  }

  // Reset the generator (for testing or recovery).
  void reset(int64_t to = 1) {
    next_order_.store(to, std::memory_order_relaxed);
  }

  // Ensure the generator is at least at `min_val`.
  void ensure_at_least(int64_t min_val) {
    int64_t current = next_order_.load(std::memory_order_relaxed);
    while (current <= min_val) {
      if (next_order_.compare_exchange_weak(current, min_val + 1,
            std::memory_order_relaxed))
        break;
    }
  }

private:
  std::atomic<int64_t> next_order_;
};

}  // namespace

// ============================================================================
// 7. TOPOLOGICAL ORDER GENERATOR
// ============================================================================
// Assigns topological ordering to events based on their position in the
// DAG. Uses room-local counters for each room.

namespace {

class TopologicalOrderGenerator {
public:
  // Compute the topological depth for an event given its prev_events.
  // The depth is max(prev_depth) + 1. If no prev events, depth starts at 1.
  static int64_t compute_depth(
      const EventId& /*event_id*/,
      const std::vector<EventId>& prev_event_ids,
      const std::map<EventId, int64_t>& known_depths) {
    if (prev_event_ids.empty())
      return 1;

    int64_t max_depth = 0;
    for (const auto& pid : prev_event_ids) {
      auto it = known_depths.find(pid);
      if (it != known_depths.end()) {
        max_depth = std::max(max_depth, it->second);
      }
    }

    return max_depth + 1;
  }

  // Compute the topological ordering for a batch of events.
  // Assigns `depth` and `topological_ordering` fields.
  // Events are ordered such that prev_event always has a lower
  // topological_ordering than the event itself.
  struct TopologicalAssignment {
    EventId event_id;
    int64_t depth = 1;
    int64_t topological_ordering = 0;
  };

  static std::vector<TopologicalAssignment> assign_ordering(
      const std::vector<ResolvableEvent>& events,
      int64_t base_topological = 0) {
    std::vector<TopologicalAssignment> result;
    result.reserve(events.size());

    // Build a map of known events to their depths
    std::map<EventId, int64_t> known_depths;

    // First pass: assign depths
    for (const auto& ev : events) {
      TopologicalAssignment ta;
      ta.event_id = ev.event_id;
      ta.depth = compute_depth(ev.event_id, ev.prev_event_ids, known_depths);
      known_depths[ev.event_id] = ta.depth;
      result.push_back(ta);
    }

    // Second pass: assign topological ordering
    // Sort by (depth, origin_server_ts, event_id)
    std::sort(result.begin(), result.end(),
              [&events](const TopologicalAssignment& a,
                         const TopologicalAssignment& b) {
                if (a.depth != b.depth)
                  return a.depth < b.depth;
                // Find the events for timestamp comparison
                int64_t ts_a = 0, ts_b = 0;
                for (const auto& ev : events) {
                  if (ev.event_id == a.event_id) ts_a = ev.origin_server_ts;
                  if (ev.event_id == b.event_id) ts_b = ev.origin_server_ts;
                }
                if (ts_a != ts_b) return ts_a < ts_b;
                return a.event_id < b.event_id;
              });

    int64_t topo = base_topological + 1;
    for (auto& ta : result) {
      ta.topological_ordering = topo++;
    }

    return result;
  }

  // Sort events into topological order (prev events before their dependents).
  static std::vector<EventId> topological_sort(
      const std::vector<ResolvableEvent>& events) {
    // Build adjacency: event_id -> set of dependent event IDs
    std::map<EventId, std::set<EventId>> dependents;
    std::map<EventId, int> in_degree;
    std::set<EventId> all_ids;

    for (const auto& ev : events) {
      all_ids.insert(ev.event_id);
      if (in_degree.find(ev.event_id) == in_degree.end())
        in_degree[ev.event_id] = 0;
    }

    for (const auto& ev : events) {
      for (const auto& pid : ev.prev_event_ids) {
        if (all_ids.count(pid)) {
          dependents[pid].insert(ev.event_id);
          in_degree[ev.event_id]++;
        }
      }
    }

    // Kahn's algorithm with tiebreaking by depth
    std::priority_queue<
        std::pair<int64_t, EventId>,
        std::vector<std::pair<int64_t, EventId>>,
        std::greater<std::pair<int64_t, EventId>>> pq;

    for (const auto& ev : events) {
      if (in_degree[ev.event_id] == 0) {
        pq.push({ev.depth, ev.event_id});
      }
    }

    std::vector<EventId> sorted;
    while (!pq.empty()) {
      auto [_, eid] = pq.top();
      pq.pop();
      sorted.push_back(eid);

      for (const auto& dep : dependents[eid]) {
        if (--in_degree[dep] == 0) {
          // Find the event's depth
          int64_t depth = 1;
          for (const auto& ev : events) {
            if (ev.event_id == dep) { depth = ev.depth; break; }
          }
          pq.push({depth, dep});
        }
      }
    }

    return sorted;
  }
};

}  // namespace

// ============================================================================
// 8. EVENT AUTH CHAIN COMPUTER
// ============================================================================
// Computes the full auth chain for an event by walking auth_event_ids
// recursively. Handles cycles and depth limits.

namespace {

class AuthChainComputer {
public:
  struct Config {
    int max_depth = 100;                     // Max auth chain walk depth
    size_t cache_size = 50000;               // Max cached chains
    int64_t cache_ttl_seconds = 300;         // Cache TTL
  };

  explicit AuthChainComputer(Config cfg = {}) : config_(std::move(cfg)) {}

  // Compute the full auth chain for a single event.
  std::set<EventId> compute_chain(
      const EventId& event_id,
      const std::map<EventId, ResolvableEvent>& event_map) {
    // Check cache
    auto cached = get_cached(event_id);
    if (cached.has_value())
      return cached.value();

    std::set<EventId> visited;
    std::set<EventId> chain;
    std::deque<EventId> queue;

    queue.push_back(event_id);
    chain.insert(event_id);

    int depth = 0;
    while (!queue.empty() && depth < config_.max_depth) {
      size_t level_size = queue.size();
      for (size_t i = 0; i < level_size; i++) {
        EventId current = queue.front();
        queue.pop_front();

        auto it = event_map.find(current);
        if (it == event_map.end()) continue;

        for (const auto& aid : it->second.auth_event_ids) {
          if (visited.insert(aid).second) {
            chain.insert(aid);
            queue.push_back(aid);
          }
        }
      }
      depth++;
    }

    // Cache the result
    cache_chain(event_id, chain);
    return chain;
  }

  // Compute the union auth chain for multiple events.
  std::set<EventId> compute_chain_for_events(
      const std::vector<EventId>& event_ids,
      const std::map<EventId, ResolvableEvent>& event_map) {
    std::set<EventId> chain;
    for (const auto& eid : event_ids) {
      auto sub = compute_chain(eid, event_map);
      chain.insert(sub.begin(), sub.end());
    }
    return chain;
  }

  // Compute auth chain difference between two events.
  struct AuthChainDiff {
    std::set<EventId> only_in_a;
    std::set<EventId> only_in_b;
    std::set<EventId> in_both;
  };

  AuthChainDiff compute_diff(
      const EventId& event_a,
      const EventId& event_b,
      const std::map<EventId, ResolvableEvent>& event_map) {
    auto chain_a = compute_chain(event_a, event_map);
    auto chain_b = compute_chain(event_b, event_map);

    AuthChainDiff diff;
    for (const auto& eid : chain_a) {
      if (chain_b.count(eid))
        diff.in_both.insert(eid);
      else
        diff.only_in_a.insert(eid);
    }
    for (const auto& eid : chain_b) {
      if (!chain_a.count(eid))
        diff.only_in_b.insert(eid);
    }
    return diff;
  }

  // Invalidate cache entries for a specific event.
  void invalidate(const EventId& event_id) {
    std::unique_lock lock(cache_mutex_);
    auth_chain_cache_.erase(event_id);
  }

  void clear_cache() {
    std::unique_lock lock(cache_mutex_);
    auth_chain_cache_.clear();
  }

  struct Stats {
    size_t cache_size = 0;
    uint64_t hits = 0;
    uint64_t misses = 0;
  };

  Stats get_stats() const {
    std::shared_lock lock(cache_mutex_);
    Stats s;
    s.cache_size = auth_chain_cache_.size();
    s.hits = hits_.load(std::memory_order_relaxed);
    s.misses = misses_.load(std::memory_order_relaxed);
    return s;
  }

private:
  std::optional<std::set<EventId>> get_cached(const EventId& eid) {
    std::shared_lock lock(cache_mutex_);
    auto it = auth_chain_cache_.find(eid);
    if (it != auth_chain_cache_.end()) {
      hits_.fetch_add(1, std::memory_order_relaxed);
      return it->second;
    }
    misses_.fetch_add(1, std::memory_order_relaxed);
    return std::nullopt;
  }

  void cache_chain(const EventId& eid, const std::set<EventId>& chain) {
    std::unique_lock lock(cache_mutex_);
    if (auth_chain_cache_.size() >= config_.cache_size) {
      // Evict oldest
      if (!auth_chain_cache_.empty())
        auth_chain_cache_.erase(auth_chain_cache_.begin());
    }
    auth_chain_cache_[eid] = chain;
  }

  Config config_;
  mutable std::shared_mutex cache_mutex_;
  std::map<EventId, std::set<EventId>> auth_chain_cache_;
  std::atomic<uint64_t> hits_{0};
  std::atomic<uint64_t> misses_{0};
};

}  // namespace

// ============================================================================
// 9. EVENT EDGES MANAGER
// ============================================================================
// Manages the DAG edges between events: prev_events relationships,
// auth_event relationships, forward and backward edges.

namespace {

class EdgeManager {
public:
  // Add an edge from source to target (source has target as prev_event).
  void add_edge(const EventId& source, const EventId& target) {
    std::unique_lock lock(mutex_);
    forward_edges_[source].insert(target);
    backward_edges_[target].insert(source);
  }

  // Add multiple edges from source to targets.
  void add_edges(const EventId& source,
                  const std::vector<EventId>& targets) {
    std::unique_lock lock(mutex_);
    for (const auto& t : targets) {
      forward_edges_[source].insert(t);
      backward_edges_[t].insert(source);
    }
  }

  // Remove an edge.
  void remove_edge(const EventId& source, const EventId& target) {
    std::unique_lock lock(mutex_);
    forward_edges_[source].erase(target);
    backward_edges_[target].erase(source);
  }

  // Remove all edges for an event (e.g., event deletion).
  void remove_event(const EventId& event_id) {
    std::unique_lock lock(mutex_);
    // Remove forward edges
    auto fwd_it = forward_edges_.find(event_id);
    if (fwd_it != forward_edges_.end()) {
      for (const auto& target : fwd_it->second)
        backward_edges_[target].erase(event_id);
      forward_edges_.erase(fwd_it);
    }

    // Remove backward edges
    auto bwd_it = backward_edges_.find(event_id);
    if (bwd_it != backward_edges_.end()) {
      for (const auto& source : bwd_it->second)
        forward_edges_[source].erase(event_id);
      backward_edges_.erase(bwd_it);
    }
  }

  // Get all prev_events (outgoing edges) for an event.
  std::set<EventId> get_prev_events(const EventId& event_id) const {
    std::shared_lock lock(mutex_);
    auto it = forward_edges_.find(event_id);
    if (it != forward_edges_.end())
      return it->second;
    return {};
  }

  // Get all events that reference this event as a prev_event.
  std::set<EventId> get_next_events(const EventId& event_id) const {
    std::shared_lock lock(mutex_);
    auto it = backward_edges_.find(event_id);
    if (it != backward_edges_.end())
      return it->second;
    return {};
  }

  // Check if there's a path from source to target (BFS).
  bool has_path(const EventId& source, const EventId& target,
                int max_depth = 100) const {
    if (source == target) return true;

    std::set<EventId> visited;
    std::deque<EventId> queue;
    queue.push_back(source);
    visited.insert(source);

    int depth = 0;
    while (!queue.empty() && depth < max_depth) {
      size_t level_size = queue.size();
      for (size_t i = 0; i < level_size; i++) {
        EventId current = queue.front();
        queue.pop_front();

        auto it = backward_edges_.find(current);
        if (it == backward_edges_.end()) continue;

        for (const auto& next : it->second) {
          if (next == target) return true;
          if (visited.insert(next).second)
            queue.push_back(next);
        }
      }
      depth++;
    }
    return false;
  }

  // Find all events with no outgoing edges (leaf events / forward extremities).
  std::set<EventId> get_forward_extremities(
      const std::set<EventId>& room_events) const {
    std::shared_lock lock(mutex_);
    std::set<EventId> extremities;

    for (const auto& eid : room_events) {
      auto it = backward_edges_.find(eid);
      // An event is an extremity if nothing references it as a prev_event
      if (it == backward_edges_.end() || it->second.empty())
        extremities.insert(eid);
    }
    return extremities;
  }

  // Find all events with no incoming edges (root events / backfill extremities).
  std::set<EventId> get_backfill_extremities(
      const std::set<EventId>& room_events) const {
    std::shared_lock lock(mutex_);
    std::set<EventId> extremities;

    for (const auto& eid : room_events) {
      auto it = forward_edges_.find(eid);
      if (it == forward_edges_.end() || it->second.empty())
        extremities.insert(eid);
    }
    return extremities;
  }

  size_t edge_count() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [_, edges] : forward_edges_)
      count += edges.size();
    return count;
  }

  void clear() {
    std::unique_lock lock(mutex_);
    forward_edges_.clear();
    backward_edges_.clear();
  }

private:
  mutable std::shared_mutex mutex_;
  std::map<EventId, std::set<EventId>> forward_edges_;   // event -> prev_events
  std::map<EventId, std::set<EventId>> backward_edges_;  // event -> next_events
};

}  // namespace

// ============================================================================
// 10. EVENT SIZE TRACKER
// ============================================================================
// Tracks the byte size of events for storage accounting and quota
// enforcement. Supports per-room and global tracking.

namespace {

class SizeTracker {
public:
  struct RoomSize {
    int64_t event_count = 0;
    int64_t total_bytes = 0;
    int64_t state_event_count = 0;
    int64_t state_bytes = 0;
  };

  // Track an event's size.
  void track_event(const EventId& event_id, const std::string& room_id,
                   size_t byte_size, bool is_state_event) {
    std::unique_lock lock(mutex_);
    global_event_count_++;
    global_total_bytes_ += static_cast<int64_t>(byte_size);

    auto& rs = room_sizes_[room_id];
    rs.event_count++;
    rs.total_bytes += static_cast<int64_t>(byte_size);
    if (is_state_event) {
      rs.state_event_count++;
      rs.state_bytes += static_cast<int64_t>(byte_size);
    }

    event_sizes_[event_id] = byte_size;
  }

  // Remove an event's size tracking.
  void untrack_event(const EventId& event_id, const std::string& room_id) {
    std::unique_lock lock(mutex_);
    auto it = event_sizes_.find(event_id);
    if (it == event_sizes_.end()) return;

    int64_t byte_size = static_cast<int64_t>(it->second);
    global_event_count_--;
    global_total_bytes_ -= byte_size;

    auto rs_it = room_sizes_.find(room_id);
    if (rs_it != room_sizes_.end()) {
      rs_it->second.event_count--;
      rs_it->second.total_bytes -= byte_size;
    }

    event_sizes_.erase(it);
  }

  // Get the stored byte size for an event.
  std::optional<size_t> get_event_size(const EventId& event_id) const {
    std::shared_lock lock(mutex_);
    auto it = event_sizes_.find(event_id);
    if (it != event_sizes_.end())
      return it->second;
    return std::nullopt;
  }

  // Get room size stats.
  RoomSize get_room_stats(const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    auto it = room_sizes_.find(room_id);
    if (it != room_sizes_.end())
      return it->second;
    return {};
  }

  // Get global stats.
  struct GlobalStats {
    int64_t event_count = 0;
    int64_t total_bytes = 0;
    size_t room_count = 0;
  };

  GlobalStats get_global_stats() const {
    std::shared_lock lock(mutex_);
    GlobalStats gs;
    gs.event_count = global_event_count_;
    gs.total_bytes = global_total_bytes_;
    gs.room_count = room_sizes_.size();
    return gs;
  }

  // Estimate JSON byte size for an event.
  static size_t estimate_event_size(const ResolvableEvent& event) {
    size_t size = 0;
    size += event.event_id.size();
    size += event.room_id.size();
    size += event.type.size();
    size += event.state_key.size();
    size += event.sender.size();
    size += sizeof(int) * 2;           // depth + power_level
    size += sizeof(int64_t);           // origin_server_ts
    size += event.auth_event_ids.size() * 64;  // average event ID length
    size += event.prev_event_ids.size() * 64;
    size += event.content.dump().size();
    return size;
  }

  void clear() {
    std::unique_lock lock(mutex_);
    global_event_count_ = 0;
    global_total_bytes_ = 0;
    room_sizes_.clear();
    event_sizes_.clear();
  }

private:
  mutable std::shared_mutex mutex_;
  int64_t global_event_count_ = 0;
  int64_t global_total_bytes_ = 0;
  std::map<std::string, RoomSize> room_sizes_;
  std::map<EventId, size_t> event_sizes_;
};

}  // namespace

// ============================================================================
// 11. STREAM TOKEN GENERATOR
// ============================================================================
// Generates pagination stream tokens. A stream token encodes a position
// in the event stream for pagination.

namespace {

class TokenGenerator {
public:
  struct StreamToken {
    int64_t topological_ordering = 0;  // Topological position
    int64_t stream_ordering = 0;       // Stream position
    std::string instance_name;         // Writer instance

    std::string serialize() const {
      // Format: "t<topo>_s<stream>"
      std::stringstream ss;
      ss << "t" << topological_ordering << "_s" << stream_ordering;
      if (!instance_name.empty())
        ss << "_i" << instance_name;
      return ss.str();
    }

    static StreamToken deserialize(const std::string& token_str) {
      StreamToken token;
      // Parse format: tNNN_sNNN[_iXXX]
      size_t t_pos = token_str.find('t');
      size_t s_pos = token_str.find('_s');
      if (t_pos != std::string::npos && s_pos != std::string::npos &&
          t_pos < s_pos) {
        token.topological_ordering = std::stoll(
            token_str.substr(t_pos + 1, s_pos - t_pos - 1));
        size_t i_pos = token_str.find("_i", s_pos + 2);
        if (i_pos != std::string::npos) {
          token.stream_ordering = std::stoll(
              token_str.substr(s_pos + 2, i_pos - s_pos - 2));
          token.instance_name = token_str.substr(i_pos + 2);
        } else {
          token.stream_ordering = std::stoll(token_str.substr(s_pos + 2));
        }
      }
      return token;
    }

    bool operator<(const StreamToken& other) const {
      if (topological_ordering != other.topological_ordering)
        return topological_ordering < other.topological_ordering;
      return stream_ordering < other.stream_ordering;
    }

    bool operator==(const StreamToken& other) const {
      return topological_ordering == other.topological_ordering &&
             stream_ordering == other.stream_ordering;
    }

    bool is_empty() const {
      return topological_ordering == 0 && stream_ordering == 0;
    }
  };

  // Generate a token for an event position.
  static StreamToken generate(int64_t topo, int64_t stream,
                               const std::string& instance = "") {
    return {topo, stream, instance};
  }

  // Generate the "max" token representing the current live position.
  StreamToken generate_live_token(int64_t current_stream) {
    return {INT64_MAX, current_stream, ""};
  }

  // Generate a "before" token for back-pagination.
  StreamToken generate_before_token(int64_t topo, int64_t stream) {
    return {topo - 1, stream - 1, ""};
  }

  // Generate a pagination token from a known event.
  static StreamToken from_event(int64_t topo, int64_t stream) {
    return {topo, stream, ""};
  }
};

}  // namespace

// ============================================================================
// 12. EXTREMITY MANAGER
// ============================================================================
// Manages forward extremities (DAG heads) and backfill extremities
// (oldest known events with gaps before them).

namespace {

class ExtremityManager {
public:
  // Forward extremity: an event with no events referencing it as prev_event.
  struct ForwardExtremity {
    EventId event_id;
    int64_t depth = 0;
    int64_t stream_ordering = 0;
    int64_t topological_ordering = 0;
    bool is_outlier = false;
  };

  // Backfill extremity: an event we know exists before our oldest event.
  struct BackfillExtremity {
    EventId event_id;
    int64_t depth = 0;
    std::string origin_server;  // Server that told us about this event
    int64_t discovered_at = 0;  // When we learned about it
    bool is_backfilled = false; // Whether we've fetched events before it
  };

  // ------------------------------------------------------------------
  // Forward extremities
  // ------------------------------------------------------------------

  // Add a forward extremity.
  void add_forward_extremity(const std::string& room_id,
                              const ForwardExtremity& extremity) {
    std::unique_lock lock(mutex_);
    forward_extremities_[room_id].push_back(extremity);
  }

  // Replace forward extremities for a room (e.g., after persisting new events).
  void replace_forward_extremities(
      const std::string& room_id,
      const std::vector<ForwardExtremity>& new_extremities) {
    std::unique_lock lock(mutex_);
    forward_extremities_[room_id] = new_extremities;
  }

  // Remove specific forward extremities that are no longer extremities.
  void remove_forward_extremities(const std::string& room_id,
                                   const std::set<EventId>& to_remove) {
    std::unique_lock lock(mutex_);
    auto it = forward_extremities_.find(room_id);
    if (it == forward_extremities_.end()) return;

    auto& fe = it->second;
    fe.erase(std::remove_if(fe.begin(), fe.end(),
        [&to_remove](const ForwardExtremity& e) {
          return to_remove.count(e.event_id) > 0;
        }), fe.end());
  }

  // Get forward extremities for a room.
  std::vector<ForwardExtremity> get_forward_extremities(
      const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    auto it = forward_extremities_.find(room_id);
    if (it != forward_extremities_.end())
      return it->second;
    return {};
  }

  // Count forward extremities for a room.
  size_t forward_extremity_count(const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    auto it = forward_extremities_.find(room_id);
    return (it != forward_extremities_.end()) ? it->second.size() : 0;
  }

  // ------------------------------------------------------------------
  // Backfill extremities
  // ------------------------------------------------------------------

  // Add a backfill extremity.
  void add_backfill_extremity(const std::string& room_id,
                               const BackfillExtremity& extremity) {
    std::unique_lock lock(mutex_);
    backfill_extremities_[room_id].push_back(extremity);
  }

  // Replace backfill extremities.
  void replace_backfill_extremities(
      const std::string& room_id,
      const std::vector<BackfillExtremity>& new_extremities) {
    std::unique_lock lock(mutex_);
    backfill_extremities_[room_id] = new_extremities;
  }

  // Remove backfill extremities that have been resolved.
  void remove_backfill_extremities(const std::string& room_id,
                                    const std::set<EventId>& to_remove) {
    std::unique_lock lock(mutex_);
    auto it = backfill_extremities_.find(room_id);
    if (it == backfill_extremities_.end()) return;

    auto& be = it->second;
    be.erase(std::remove_if(be.begin(), be.end(),
        [&to_remove](const BackfillExtremity& e) {
          return to_remove.count(e.event_id) > 0;
        }), be.end());
  }

  // Get backfill extremities for a room.
  std::vector<BackfillExtremity> get_backfill_extremities(
      const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    auto it = backfill_extremities_.find(room_id);
    if (it != backfill_extremities_.end())
      return it->second;
    return {};
  }

  // Mark a backfill extremity as resolved (events before it have been fetched).
  void mark_backfilled(const std::string& room_id, const EventId& event_id) {
    std::unique_lock lock(mutex_);
    auto it = backfill_extremities_.find(room_id);
    if (it == backfill_extremities_.end()) return;

    for (auto& be : it->second) {
      if (be.event_id == event_id)
        be.is_backfilled = true;
    }
  }

  // Get oldest unresolved backfill extremity.
  std::optional<BackfillExtremity> get_oldest_unresolved_backfill(
      const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    auto it = backfill_extremities_.find(room_id);
    if (it == backfill_extremities_.end() || it->second.empty())
      return std::nullopt;

    const auto& be = it->second;
    const BackfillExtremity* oldest = nullptr;
    for (const auto& e : be) {
      if (!e.is_backfilled && (!oldest || e.depth < oldest->depth))
        oldest = &e;
    }
    if (oldest)
      return *oldest;
    return std::nullopt;
  }

  // Cleanup all extremities for a room.
  void clear_room(const std::string& room_id) {
    std::unique_lock lock(mutex_);
    forward_extremities_.erase(room_id);
    backfill_extremities_.erase(room_id);
  }

  void clear() {
    std::unique_lock lock(mutex_);
    forward_extremities_.clear();
    backfill_extremities_.clear();
  }

  struct RoomStats {
    std::string room_id;
    size_t forward_count = 0;
    size_t backfill_count = 0;
    size_t unresolved_backfill = 0;
  };

  std::vector<RoomStats> get_all_stats() const {
    std::shared_lock lock(mutex_);
    std::set<std::string> all_rooms;
    for (const auto& [rid, _] : forward_extremities_) all_rooms.insert(rid);
    for (const auto& [rid, _] : backfill_extremities_) all_rooms.insert(rid);

    std::vector<RoomStats> stats;
    for (const auto& rid : all_rooms) {
      RoomStats rs;
      rs.room_id = rid;
      auto fwd = forward_extremities_.find(rid);
      if (fwd != forward_extremities_.end())
        rs.forward_count = fwd->second.size();
      auto bwd = backfill_extremities_.find(rid);
      if (bwd != backfill_extremities_.end()) {
        rs.backfill_count = bwd->second.size();
        for (const auto& be : bwd->second)
          if (!be.is_backfilled) rs.unresolved_backfill++;
      }
      stats.push_back(rs);
    }
    return stats;
  }

private:
  mutable std::shared_mutex mutex_;
  std::map<std::string, std::vector<ForwardExtremity>> forward_extremities_;
  std::map<std::string, std::vector<BackfillExtremity>> backfill_extremities_;
};

}  // namespace

// ============================================================================
// 13. REJECTED EVENT HANDLER
// ============================================================================
// Handles events that fail auth or validation. Rejected events are
// stored but do not affect room state or stream ordering.

namespace {

class RejectedEventHandler {
public:
  struct RejectedEvent {
    EventId event_id;
    std::string room_id;
    std::string reason;           // Why it was rejected
    int64_t rejected_at = 0;      // Timestamp
    json event_data;              // The raw event
    bool is_soft_failure = false; // Auth-check failure vs hard rejection
  };

  // Record a rejected event.
  void record_rejected(const EventId& event_id,
                        const std::string& room_id,
                        const std::string& reason,
                        const json& event_data,
                        bool soft_fail = false) {
    std::unique_lock lock(mutex_);
    RejectedEvent re;
    re.event_id = event_id;
    re.room_id = room_id;
    re.reason = reason;
    re.rejected_at = now_seconds();
    re.event_data = event_data;
    re.is_soft_failure = soft_fail;

    rejected_events_[event_id] = re;
    room_rejected_[room_id].push_back(event_id);
  }

  // Check if an event is rejected.
  bool is_rejected(const EventId& event_id) const {
    std::shared_lock lock(mutex_);
    return rejected_events_.count(event_id) > 0;
  }

  // Check if an event is soft-failed.
  bool is_soft_failed(const EventId& event_id) const {
    std::shared_lock lock(mutex_);
    auto it = rejected_events_.find(event_id);
    return it != rejected_events_.end() && it->second.is_soft_failure;
  }

  // Get rejection reason.
  std::optional<std::string> get_rejection_reason(
      const EventId& event_id) const {
    std::shared_lock lock(mutex_);
    auto it = rejected_events_.find(event_id);
    if (it != rejected_events_.end())
      return it->second.reason;
    return std::nullopt;
  }

  // Get all rejected events for a room.
  std::vector<RejectedEvent> get_room_rejected(
      const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    std::vector<RejectedEvent> result;
    auto it = room_rejected_.find(room_id);
    if (it != room_rejected_.end()) {
      for (const auto& eid : it->second) {
        auto re_it = rejected_events_.find(eid);
        if (re_it != rejected_events_.end())
          result.push_back(re_it->second);
      }
    }
    return result;
  }

  // Remove a rejected event entry.
  void remove(const EventId& event_id) {
    std::unique_lock lock(mutex_);
    auto it = rejected_events_.find(event_id);
    if (it != rejected_events_.end()) {
      auto& room_list = room_rejected_[it->second.room_id];
      room_list.erase(std::remove(room_list.begin(), room_list.end(), event_id),
                      room_list.end());
      rejected_events_.erase(it);
    }
  }

  // Purge old rejected events beyond TTL.
  size_t purge_old(int64_t max_age_seconds = 86400 * 7) {
    std::unique_lock lock(mutex_);
    int64_t cutoff = now_seconds() - max_age_seconds;
    size_t purged = 0;

    for (auto it = rejected_events_.begin();
         it != rejected_events_.end();) {
      if (it->second.rejected_at < cutoff) {
        auto& room_list = room_rejected_[it->second.room_id];
        room_list.erase(std::remove(room_list.begin(), room_list.end(),
                                     it->first), room_list.end());
        it = rejected_events_.erase(it);
        purged++;
      } else {
        ++it;
      }
    }
    return purged;
  }

  size_t total_rejected() const {
    std::shared_lock lock(mutex_);
    return rejected_events_.size();
  }

  size_t total_soft_failed() const {
    std::shared_lock lock(mutex_);
    size_t count = 0;
    for (const auto& [_, re] : rejected_events_)
      if (re.is_soft_failure) count++;
    return count;
  }

  void clear() {
    std::unique_lock lock(mutex_);
    rejected_events_.clear();
    room_rejected_.clear();
  }

private:
  static int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
  }

  mutable std::shared_mutex mutex_;
  std::map<EventId, RejectedEvent> rejected_events_;
  std::map<std::string, std::vector<EventId>> room_rejected_;
};

}  // namespace

// ============================================================================
// 14. SOFT-FAILED EVENT HANDLER
// ============================================================================
// Soft-failed events are those that fail state-dependent auth rules
// but may still be referenced as prev_events or auth_events. They
// are stored but excluded from room state.

namespace {

class SoftFailedEventHandler {
public:
  struct SoftFailedEvent {
    EventId event_id;
    std::string room_id;
    std::string failure_reason;
    int64_t failed_at = 0;
    bool can_affect_state = false;  // Whether it can be re-evaluated later
    EventId retry_after_event;      // If non-empty, retry after this event
  };

  // Record a soft-failed event.
  void record_soft_failed(const EventId& event_id,
                           const std::string& room_id,
                           const std::string& reason,
                           const EventId& retry_after = "") {
    std::unique_lock lock(mutex_);
    SoftFailedEvent sfe;
    sfe.event_id = event_id;
    sfe.room_id = room_id;
    sfe.failure_reason = reason;
    sfe.failed_at = now_seconds();
    sfe.retry_after_event = retry_after;
    soft_failed_[event_id] = sfe;
  }

  // Check if an event is soft-failed.
  bool is_soft_failed(const EventId& event_id) const {
    std::shared_lock lock(mutex_);
    return soft_failed_.count(event_id) > 0;
  }

  // Get the set of all soft-failed event IDs.
  std::set<EventId> get_soft_failed_set() const {
    std::shared_lock lock(mutex_);
    std::set<EventId> result;
    for (const auto& [eid, _] : soft_failed_)
      result.insert(eid);
    return result;
  }

  // Attempt to re-evaluate soft-failed events after state changes.
  // Returns event IDs that should be retried.
  std::vector<EventId> get_retry_candidates(const std::string& room_id) const {
    std::shared_lock lock(mutex_);
    std::vector<EventId> candidates;
    for (const auto& [eid, sfe] : soft_failed_) {
      if (sfe.room_id == room_id && sfe.can_affect_state)
        candidates.push_back(eid);
    }
    return candidates;
  }

  // Mark a soft-failed event as resolved (passed on retry).
  void mark_resolved(const EventId& event_id) {
    std::unique_lock lock(mutex_);
    soft_failed_.erase(event_id);
  }

  // Remove all soft-failed events for a room.
  void clear_room(const std::string& room_id) {
    std::unique_lock lock(mutex_);
    for (auto it = soft_failed_.begin(); it != soft_failed_.end();) {
      if (it->second.room_id == room_id)
        it = soft_failed_.erase(it);
      else
        ++it;
    }
  }

  size_t count() const {
    std::shared_lock lock(mutex_);
    return soft_failed_.size();
  }

  void clear() {
    std::unique_lock lock(mutex_);
    soft_failed_.clear();
  }

private:
  static int64_t now_seconds() {
    return std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
  }

  mutable std::shared_mutex mutex_;
  std::map<EventId, SoftFailedEvent> soft_failed_;
};

}  // namespace

// ============================================================================
// 15. EVENT BATCH PERSISTER
// ============================================================================
// Handles batch persistence of events with all metadata: state groups,
// topological ordering, stream ordering, edges, sizes, tokens.

namespace {

class BatchPersister {
public:
  struct BatchConfig {
    size_t max_batch_size = 100;          // Max events per batch
    bool assign_stream_ordering = true;   // Auto-assign stream ordering
    bool assign_topological = true;       // Auto-assign topological ordering
    bool track_sizes = true;              // Track event byte sizes
    bool generate_tokens = true;          // Generate stream tokens
    bool update_extremities = true;       // Update forward/backfill extremities
    bool deduplicate = true;              // Check for duplicates before persisting
  };

  struct PersistResult {
    std::vector<EventId> persisted_ids;
    std::vector<EventId> rejected_ids;
    std::vector<EventId> duplicate_ids;
    std::map<EventId, int64_t> stream_orderings;
    std::map<EventId, int64_t> topological_orderings;
    std::map<EventId, int64_t> state_groups;
    int64_t batch_start_stream = 0;
    int64_t batch_end_stream = 0;
    size_t total_bytes = 0;
  };

  BatchPersister(StreamOrderGenerator& stream_gen,
                 EdgeManager& edge_mgr,
                 SizeTracker& size_tracker,
                 ExtremityManager& ext_mgr,
                 EventDeduplicator& dedup,
                 BatchConfig config = {})
      : stream_gen_(stream_gen),
        edge_mgr_(edge_mgr),
        size_tracker_(size_tracker),
        ext_mgr_(ext_mgr),
        dedup_(dedup),
        config_(std::move(config)) {}

  // Persist a batch of events.
  PersistResult persist_events(
      const std::string& room_id,
      const std::vector<ResolvableEvent>& events,
      const std::map<EventId, StateMap>& event_states = {},
      StateGroupStore* state_store = nullptr) {
    PersistResult result;

    if (events.empty())
      return result;

    // Step 1: Deduplication
    std::vector<ResolvableEvent> deduped;
    for (const auto& ev : events) {
      if (config_.deduplicate && !dedup_.check_and_mark(ev.event_id)) {
        result.duplicate_ids.push_back(ev.event_id);
        continue;
      }

      // Hash-based dedup
      std::string hash = EventHasher::compute_content_hash(ev);
      if (config_.deduplicate && !dedup_.mark_hash_seen(hash)) {
        result.duplicate_ids.push_back(ev.event_id);
        continue;
      }

      deduped.push_back(ev);
    }

    if (deduped.empty())
      return result;

    // Step 2: Assign stream orderings
    std::map<EventId, int64_t> stream_orders;
    if (config_.assign_stream_ordering) {
      result.batch_start_stream = stream_gen_.next_batch(deduped.size());
      for (size_t i = 0; i < deduped.size(); i++) {
        int64_t so = result.batch_start_stream + static_cast<int64_t>(i);
        stream_orders[deduped[i].event_id] = so;
      }
      result.batch_end_stream = result.batch_start_stream +
          static_cast<int64_t>(deduped.size()) - 1;
    }

    // Step 3: Assign topological orderings
    std::map<EventId, int64_t> topo_orders;
    if (config_.assign_topological) {
      auto assignments = TopologicalOrderGenerator::assign_ordering(deduped);
      for (const auto& ta : assignments) {
        topo_orders[ta.event_id] = ta.topological_ordering;
      }
    }

    // Step 4: Create state groups for state events
    std::map<EventId, int64_t> state_groups;
    if (state_store) {
      for (const auto& ev : deduped) {
        if (ev.is_state()) {
          // Build the state after this event
          StateMap new_state;
          auto sit = event_states.find(ev.event_id);
          if (sit != event_states.end()) {
            new_state = sit->second;
          }
          // Add this event's own state
          new_state[ev.state_pair()] = ev.event_id;

          int64_t sg = state_store->get_or_create_group(new_state);
          state_groups[ev.event_id] = sg;
        }
      }
    }

    // Step 5: Track sizes
    if (config_.track_sizes) {
      for (const auto& ev : deduped) {
        size_t byte_size = SizeTracker::estimate_event_size(ev);
        size_tracker_.track_event(ev.event_id, room_id, byte_size,
                                   ev.is_state());
        result.total_bytes += byte_size;
      }
    }

    // Step 6: Register edges
    for (const auto& ev : deduped) {
      edge_mgr_.add_edges(ev.event_id, ev.prev_event_ids);
    }

    // Step 7: Update extremities
    if (config_.update_extremities) {
      // These become new forward extremities (unless something later adds them as prev)
      for (const auto& ev : deduped) {
        ExtremityManager::ForwardExtremity fe;
        fe.event_id = ev.event_id;
        fe.depth = ev.depth;

        auto so_it = stream_orders.find(ev.event_id);
        if (so_it != stream_orders.end())
          fe.stream_ordering = so_it->second;

        auto to_it = topo_orders.find(ev.event_id);
        if (to_it != topo_orders.end())
          fe.topological_ordering = to_it->second;

        ext_mgr_.add_forward_extremity(room_id, fe);
      }

      // Events that are now referenced as prev_events are no longer extremities
      std::set<EventId> new_prev_set;
      for (const auto& ev : deduped) {
        new_prev_set.insert(ev.prev_event_ids.begin(),
                             ev.prev_event_ids.end());
      }
      ext_mgr_.remove_forward_extremities(room_id, new_prev_set);
    }

    // Step 8: Collect persisted IDs
    for (const auto& ev : deduped) {
      result.persisted_ids.push_back(ev.event_id);
    }

    result.stream_orderings = std::move(stream_orders);
    result.topological_orderings = std::move(topo_orders);
    result.state_groups = std::move(state_groups);

    return result;
  }

  // Persist backfill events.
  PersistResult persist_backfill_events(
      const std::string& room_id,
      const std::vector<ResolvableEvent>& events,
      int64_t base_topological,
      int64_t base_stream) {
    PersistResult result;

    if (events.empty())
      return result;

    // Sort events topologically
    auto sorted = TopologicalOrderGenerator::topological_sort(events);

    // Assign topological ordering in reverse (backfill = lower than existing)
    std::map<EventId, int64_t> topo_orders;
    int64_t topo = base_topological - static_cast<int64_t>(sorted.size());
    for (const auto& eid : sorted) {
      topo_orders[eid] = topo++;
    }

    // Assign negative stream ordering for backfill
    std::map<EventId, int64_t> stream_orders;
    int64_t stream = base_stream - static_cast<int64_t>(sorted.size());
    result.batch_start_stream = stream;
    for (const auto& eid : sorted) {
      stream_orders[eid] = stream++;
    }
    result.batch_end_stream = stream - 1;

    // Register edges, track sizes, update backfill extremities
    for (const auto& ev : events) {
      if (config_.deduplicate) {
        if (!dedup_.check_and_mark(ev.event_id)) {
          result.duplicate_ids.push_back(ev.event_id);
          continue;
        }
      }

      edge_mgr_.add_edges(ev.event_id, ev.prev_event_ids);

      if (config_.track_sizes) {
        size_t byte_size = SizeTracker::estimate_event_size(ev);
        size_tracker_.track_event(ev.event_id, room_id, byte_size,
                                   ev.is_state());
        result.total_bytes += byte_size;
      }

      result.persisted_ids.push_back(ev.event_id);
    }

    // Update backfill extremities
    if (config_.update_extremities) {
      for (const auto& ev : events) {
        if (ev.prev_event_ids.empty()) {
          ExtremityManager::BackfillExtremity be;
          be.event_id = ev.event_id;
          be.depth = ev.depth;
          be.discovered_at = std::chrono::duration_cast<std::chrono::seconds>(
              std::chrono::system_clock::now().time_since_epoch()).count();
          ext_mgr_.add_backfill_extremity(room_id, be);
        }
      }
    }

    result.stream_orderings = std::move(stream_orders);
    result.topological_orderings = std::move(topo_orders);

    return result;
  }

  BatchConfig& config() { return config_; }
  const BatchConfig& config() const { return config_; }

private:
  StreamOrderGenerator& stream_gen_;
  EdgeManager& edge_mgr_;
  SizeTracker& size_tracker_;
  ExtremityManager& ext_mgr_;
  EventDeduplicator& dedup_;
  BatchConfig config_;
};

}  // namespace

// ============================================================================
// 16. STATE GROUP GARBAGE COLLECTOR
// ============================================================================
// Identifies and removes state groups that are no longer referenced
// by any event, freeing storage.

namespace {

class StateGroupGC {
public:
  struct Config {
    int64_t max_age_seconds = 7200;       // Max age of unreferenced groups
    size_t max_unreferenced = 100000;     // Max unreferenced before forced GC
    int collect_interval_seconds = 300;   // GC interval
    bool aggressive = false;
  };

  explicit StateGroupGC(Config cfg = {}) : config_(std::move(cfg)) {}

  // Register a reference to a state group.
  void add_reference(int64_t group_id, const EventId& referrer) {
    std::unique_lock lock(mutex_);
    references_[group_id].insert(referrer);
    unreferenced_since_.erase(group_id);
  }

  // Remove a reference.
  void remove_reference(int64_t group_id, const EventId& referrer) {
    std::unique_lock lock(mutex_);
    auto it = references_.find(group_id);
    if (it != references_.end()) {
      it->second.erase(referrer);
      if (it->second.empty()) {
        references_.erase(it);
        unreferenced_since_[group_id] = std::chrono::steady_clock::now();
      }
    }
  }

  // Register a state group with its room and size info.
  void register_group(int64_t group_id, const std::string& room_id,
                      size_t state_size) {
    std::unique_lock lock(mutex_);
    group_info_[group_id] = {room_id, state_size, false};
  }

  // Mark a group for deletion.
  void mark_for_deletion(int64_t group_id) {
    std::unique_lock lock(mutex_);
    auto it = group_info_.find(group_id);
    if (it != group_info_.end())
      it->second.marked = true;
  }

  // Check if a group is referenced.
  bool is_referenced(int64_t group_id) const {
    std::shared_lock lock(mutex_);
    return references_.count(group_id) > 0;
  }

  // Run a GC pass. Returns IDs of groups to delete.
  struct GCResult {
    std::vector<int64_t> collected_groups;
    size_t freed_state_entries = 0;
    size_t remaining_unreferenced = 0;
  };

  GCResult collect(StateGroupCache* cache = nullptr) {
    std::unique_lock lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    GCResult result;

    // Find groups that have been unreferenced long enough
    for (auto it = unreferenced_since_.begin();
         it != unreferenced_since_.end();) {
      auto age = std::chrono::duration_cast<std::chrono::seconds>(
          now - it->second).count();

      bool should_collect = (age >= config_.max_age_seconds) ||
                            (config_.aggressive && age >= config_.max_age_seconds / 2);

      if (should_collect) {
        if (references_.find(it->first) == references_.end()) {
          result.collected_groups.push_back(it->first);
          auto gi_it = group_info_.find(it->first);
          if (gi_it != group_info_.end()) {
            result.freed_state_entries += gi_it->second.state_size;
            group_info_.erase(gi_it);
          }
          if (cache) cache->remove(it->first);
          it = unreferenced_since_.erase(it);
        } else {
          it = unreferenced_since_.erase(it);
        }
      } else {
        ++it;
      }
    }

    // Forced collection if too many unreferenced groups
    if (unreferenced_since_.size() > config_.max_unreferenced) {
      std::vector<std::pair<int64_t, std::chrono::steady_clock::time_point>> sorted;
      for (const auto& [gid, ts] : unreferenced_since_)
        sorted.push_back({gid, ts});
      std::sort(sorted.begin(), sorted.end(),
                [](const auto& a, const auto& b) {
                  return a.second < b.second;
                });

      size_t to_remove = unreferenced_since_.size() -
                         config_.max_unreferenced +
                         config_.max_unreferenced / 8;
      for (size_t i = 0; i < to_remove && i < sorted.size(); i++) {
        if (references_.find(sorted[i].first) == references_.end()) {
          result.collected_groups.push_back(sorted[i].first);
          auto gi_it = group_info_.find(sorted[i].first);
          if (gi_it != group_info_.end()) {
            result.freed_state_entries += gi_it->second.state_size;
            group_info_.erase(gi_it);
          }
          unreferenced_since_.erase(sorted[i].first);
          if (cache) cache->remove(sorted[i].first);
        }
      }
    }

    result.remaining_unreferenced = unreferenced_since_.size();
    last_collection_ = now;
    return result;
  }

  struct Stats {
    size_t total_groups = 0;
    size_t referenced_groups = 0;
    size_t unreferenced_groups = 0;
    size_t total_state_entries = 0;
    std::chrono::steady_clock::time_point last_collection;
  };

  Stats get_stats() const {
    std::shared_lock lock(mutex_);
    Stats s;
    s.total_groups = group_info_.size();
    s.referenced_groups = references_.size();
    s.unreferenced_groups = unreferenced_since_.size();
    s.last_collection = last_collection_;
    for (const auto& [_, gi] : group_info_)
      s.total_state_entries += gi.state_size;
    return s;
  }

  void clear() {
    std::unique_lock lock(mutex_);
    references_.clear();
    unreferenced_since_.clear();
    group_info_.clear();
  }

private:
  struct GroupInfo {
    std::string room_id;
    size_t state_size = 0;
    bool marked = false;
  };

  Config config_;
  mutable std::shared_mutex mutex_;
  std::map<int64_t, std::set<EventId>> references_;
  std::map<int64_t, std::chrono::steady_clock::time_point> unreferenced_since_;
  std::map<int64_t, GroupInfo> group_info_;
  std::chrono::steady_clock::time_point last_collection_;
};

}  // namespace

// ============================================================================
// 17. STATE AUTOCOMPRESSOR
// ============================================================================
// Automatically compresses state groups by storing deltas instead of
// full state maps when sequential groups differ only slightly.

namespace {

class StateAutocompressor {
public:
  struct Config {
    size_t max_uncompressed = 10000;     // Max uncompressed groups
    int64_t min_age_seconds = 300;       // Min age before compression
    int64_t interval_seconds = 60;       // Compression check interval
    double max_delta_ratio = 0.2;        // Compress if delta < 20% of full
    double target_compression_pct = 50.0; // Target % compressed
  };

  explicit StateAutocompressor(Config cfg = {}) : config_(std::move(cfg)) {}

  // Register a state group with its full state for potential compression.
  void register_group(int64_t group_id, const StateMap& state,
                      std::optional<int64_t> prev_group_id = std::nullopt) {
    std::unique_lock lock(mutex_);
    groups_[group_id] = GroupState{
        state,
        prev_group_id,
        std::chrono::steady_clock::now(),
        false  // not compressed yet
    };
  }

  // Touch a group (mark as recently accessed).
  void touch(int64_t group_id) {
    std::unique_lock lock(mutex_);
    auto it = groups_.find(group_id);
    if (it != groups_.end())
      it->second.last_access = std::chrono::steady_clock::now();
  }

  // Run a compression pass. Returns number of groups compressed.
  size_t run_compression() {
    std::unique_lock lock(mutex_);
    auto now = std::chrono::steady_clock::now();

    // Check if enough time has passed since last compression
    auto since_last = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_compress_).count();
    if (since_last < config_.interval_seconds)
      return 0;

    // Count uncompressed
    size_t uncompressed = 0;
    for (const auto& [id, gs] : groups_)
      if (!gs.compressed) uncompressed++;

    if (uncompressed < config_.max_uncompressed)
      return 0;

    // Find candidates (old enough, not compressed)
    std::vector<std::pair<int64_t, std::chrono::steady_clock::time_point>> candidates;
    for (const auto& [id, gs] : groups_) {
      if (!gs.compressed) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - gs.last_access).count();
        if (age >= config_.min_age_seconds)
          candidates.push_back({id, gs.last_access});
      }
    }

    std::sort(candidates.begin(), candidates.end(),
              [](const auto& a, const auto& b) {
                return a.second < b.second;
              });

    size_t target = std::min(candidates.size(), uncompressed / 4);
    size_t compressed = 0;

    for (size_t i = 0; i < target && i < candidates.size(); i++) {
      int64_t gid = candidates[i].first;
      auto it = groups_.find(gid);
      if (it == groups_.end() || it->second.compressed) continue;

      // Check if delta compression is worthwhile
      if (it->second.prev_group_id.has_value()) {
        auto prev_it = groups_.find(it->second.prev_group_id.value());
        if (prev_it != groups_.end()) {
          auto delta = compute_delta(prev_it->second.state, it->second.state);
          double ratio = static_cast<double>(delta.total_changes()) /
                         static_cast<double>(it->second.state.size());
          if (ratio < config_.max_delta_ratio) {
            it->second.compressed = true;
            compressed++;
          }
        }
      }
    }

    last_compress_ = now;
    return compressed;
  }

  struct CompressStats {
    size_t total_groups = 0;
    size_t compressed = 0;
    size_t uncompressed = 0;
    double compression_pct = 0.0;
    std::chrono::steady_clock::time_point last_compress;
  };

  CompressStats get_stats() const {
    std::shared_lock lock(mutex_);
    CompressStats s;
    s.total_groups = groups_.size();
    s.last_compress = last_compress_;
    for (const auto& [_, gs] : groups_) {
      if (gs.compressed) s.compressed++;
      else s.uncompressed++;
    }
    if (s.total_groups > 0)
      s.compression_pct = 100.0 * static_cast<double>(s.compressed) /
                          static_cast<double>(s.total_groups);
    return s;
  }

  void remove_group(int64_t group_id) {
    std::unique_lock lock(mutex_);
    groups_.erase(group_id);
  }

  void clear() {
    std::unique_lock lock(mutex_);
    groups_.clear();
  }

private:
  struct GroupState {
    StateMap state;
    std::optional<int64_t> prev_group_id;
    std::chrono::steady_clock::time_point last_access;
    bool compressed;
  };

  Config config_;
  mutable std::shared_mutex mutex_;
  std::map<int64_t, GroupState> groups_;
  std::chrono::steady_clock::time_point last_compress_;
};

}  // namespace

// ============================================================================
// 18. STATE GROUP COMPILER - MAIN CLASS
// ============================================================================
// The central compiler that ties everything together. Creates state groups,
// determines current room state, manages the persistence pipeline, and
// coordinates all subsystems.

class StateGroupCompiler {
public:
  struct Config {
    // Cache
    size_t state_group_cache_size = 5000;
    int64_t cache_ttl_seconds = 600;

    // Deduplication
    size_t max_dedup_entries = 100000;
    int64_t dedup_ttl_seconds = 3600;

    // Stream ordering
    int64_t initial_stream_order = 1;

    // Auth chain
    int auth_chain_max_depth = 100;

    // Batches
    size_t max_batch_size = 100;

    // GC
    int64_t gc_max_age_seconds = 7200;
    int collect_interval_seconds = 300;

    // Compression
    size_t max_uncompressed_groups = 10000;
    int64_t compress_interval_seconds = 60;

    // Metrics
    bool enable_metrics = true;
  };

  explicit StateGroupCompiler(Config cfg = {})
      : config_(std::move(cfg)),
        cache_(config_.state_group_cache_size, config_.cache_ttl_seconds),
        dedup_(EventDeduplicator::Config{
            config_.max_dedup_entries, config_.dedup_ttl_seconds, true}),
        stream_gen_(config_.initial_stream_order),
        auth_computer_(AuthChainComputer::Config{
            config_.auth_chain_max_depth}),
        batch_persister_(stream_gen_, edge_mgr_, size_tracker_,
                         ext_mgr_, dedup_,
                         BatchPersister::BatchConfig{
                             config_.max_batch_size, true, true, true,
                             true, true, true}),
        gc_(StateGroupGC::Config{
            config_.gc_max_age_seconds, 100000,
            config_.collect_interval_seconds}),
        compressor_(StateAutocompressor::Config{
            config_.max_uncompressed_groups, 300,
            config_.compress_interval_seconds}) {}

  // ================================================================
  // State group compilation
  // ================================================================

  // Create or get a state group for a given state map.
  int64_t compile_state_group(const std::string& room_id,
                               const StateMap& state,
                               const EventId& creator_event,
                               std::optional<int64_t> prev_group_id = std::nullopt) {
    int64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    StateGroupEntry entry;
    entry.state = state;
    entry.room_id = room_id;
    entry.creator_event_id = creator_event;
    entry.created_at = now;
    entry.last_accessed_at = now;
    entry.state_size = state.size();

    // Compute delta from previous group
    if (prev_group_id.has_value()) {
      auto prev_state = get_state_group_state(prev_group_id.value());
      entry.delta_from_prev = compute_delta(prev_state, state);
      entry.delta_size = entry.delta_from_prev.total_changes();
    }

    // Assign a new group ID
    int64_t gid = next_group_id_.fetch_add(1, std::memory_order_relaxed);
    entry.group_id = gid;
    entry.prev_group_id = prev_group_id.value_or(0);
    entry.byte_size = estimate_group_byte_size(entry);

    // Cache and register
    cache_.put(gid, entry);
    gc_.register_group(gid, room_id, state.size());
    gc_.add_reference(gid, creator_event);
    compressor_.register_group(gid, state, prev_group_id);

    // Track as created
    group_ids_by_room_[room_id].push_back(gid);

    return gid;
  }

  // Get the full state for a state group.
  StateMap get_state_group_state(int64_t group_id) {
    auto cached = cache_.get(group_id);
    if (cached.has_value()) {
      cache_.touch(group_id);
      compressor_.touch(group_id);
      return cached->state;
    }
    return {};
  }

  // ================================================================
  // Current state derivation
  // ================================================================

  // Derive the current room state from all state groups in the room.
  StateMap derive_current_state(const std::string& room_id) {
    auto gids = group_ids_by_room_[room_id];
    if (gids.empty())
      return {};

    StateMap current;

    // Walk groups in chronological order, applying state changes
    for (int64_t gid : gids) {
      auto state = get_state_group_state(gid);
      for (const auto& [key, val] : state) {
        current[key] = val;  // Later groups override earlier ones
      }
    }

    return current;
  }

  // Derive current state with resolution if there are multiple state sets.
  StateMap derive_current_state_resolved(
      const std::string& room_id,
      const RoomVersion& version,
      const EventMap& event_map) {
    auto gids = group_ids_by_room_[room_id];
    if (gids.empty())
      return {};
    if (gids.size() == 1)
      return get_state_group_state(gids[0]);

    std::vector<StateMap> state_sets;
    for (int64_t gid : gids) {
      state_sets.push_back(get_state_group_state(gid));
    }

    return resolve_events(version, state_sets, event_map);
  }

  // ================================================================
  // Event persistence pipeline
  // ================================================================

  // Persist a single event with full state group compilation.
  struct PersistResult {
    EventId event_id;
    bool persisted = false;
    bool rejected = false;
    bool duplicate = false;
    int64_t stream_ordering = 0;
    int64_t topological_ordering = 0;
    int64_t state_group = 0;
    std::string rejection_reason;
  };

  PersistResult persist_event(const std::string& room_id,
                               const ResolvableEvent& event,
                               const StateMap& current_state,
                               const RoomVersion& version,
                               StateGroupStore& store) {
    PersistResult result;
    result.event_id = event.event_id;

    // Dedup check
    if (!dedup_.check_and_mark(event.event_id)) {
      result.duplicate = true;
      result.rejected = true;
      result.rejection_reason = "duplicate event";
      return result;
    }

    // Hash dedup
    std::string hash = EventHasher::compute_content_hash(event);
    if (!dedup_.mark_hash_seen(hash)) {
      result.duplicate = true;
      result.rejected = true;
      result.rejection_reason = "duplicate event (hash)";
      return result;
    }

    // Auth check
    std::map<EventId, ResolvableEvent> event_map;
    event_map[event.event_id] = event;

    // Build auth context from current state
    std::vector<ResolvableEvent> auth_events;
    for (const auto& [key, eid] : current_state) {
      auto it = event_map.find(eid);
      if (it != event_map.end())
        auth_events.push_back(it->second);
    }

    bool auth_passes = true;
    std::string auth_fail_reason;

    if (!check_state_independent_auth_rules(version, event)) {
      auth_passes = false;
      auth_fail_reason = "state-independent auth rules failed";
    } else if (!check_state_dependent_auth_rules(version, event, auth_events)) {
      auth_passes = false;
      auth_fail_reason = "state-dependent auth rules failed";
    }

    if (!auth_passes) {
      rejected_handler_.record_rejected(
          event.event_id, room_id, auth_fail_reason,
          event.content, true);  // soft fail
      soft_fail_handler_.record_soft_failed(
          event.event_id, room_id, auth_fail_reason);
      result.rejected = true;
      result.rejection_reason = auth_fail_reason;
      return result;
    }

    // Compute new state
    StateMap new_state = current_state;
    if (event.is_state()) {
      new_state[event.state_pair()] = event.event_id;
    }

    // Create state group
    std::optional<int64_t> prev_sg;
    if (!current_state.empty()) {
      // Find the most recent state group
      auto& gids = group_ids_by_room_[room_id];
      if (!gids.empty())
        prev_sg = gids.back();
    }
    result.state_group = compile_state_group(room_id, new_state,
                                              event.event_id, prev_sg);

    // Assign stream ordering
    result.stream_ordering = stream_gen_.next();

    // Assign topological ordering
    auto assignments = TopologicalOrderGenerator::assign_ordering({event});
    if (!assignments.empty())
      result.topological_ordering = assignments[0].topological_ordering;

    // Track size
    size_t byte_size = SizeTracker::estimate_event_size(event);
    size_tracker_.track_event(event.event_id, room_id, byte_size,
                               event.is_state());

    // Register edges
    edge_mgr_.add_edges(event.event_id, event.prev_event_ids);

    // Update forward extremities
    ExtremityManager::ForwardExtremity fe;
    fe.event_id = event.event_id;
    fe.depth = event.depth;
    fe.stream_ordering = result.stream_ordering;
    fe.topological_ordering = result.topological_ordering;
    ext_mgr_.add_forward_extremity(room_id, fe);

    // Remove prev_events from extremities
    std::set<EventId> new_prev_set(event.prev_event_ids.begin(),
                                    event.prev_event_ids.end());
    ext_mgr_.remove_forward_extremities(room_id, new_prev_set);

    result.persisted = true;
    return result;
  }

  // Persist a batch of events.
  BatchPersister::PersistResult persist_event_batch(
      const std::string& room_id,
      const std::vector<ResolvableEvent>& events,
      const std::map<EventId, StateMap>& event_states = {},
      StateGroupStore* state_store = nullptr) {
    return batch_persister_.persist_events(room_id, events,
                                            event_states, state_store);
  }

  // Persist backfill events.
  BatchPersister::PersistResult persist_backfill_batch(
      const std::string& room_id,
      const std::vector<ResolvableEvent>& events,
      int64_t base_topo = 0,
      int64_t base_stream = 0) {
    return batch_persister_.persist_backfill_events(
        room_id, events, base_topo, base_stream);
  }

  // ================================================================
  // Event forward extremity management
  // ================================================================

  std::vector<ExtremityManager::ForwardExtremity> get_forward_extremities(
      const std::string& room_id) {
    return ext_mgr_.get_forward_extremities(room_id);
  }

  size_t forward_extremity_count(const std::string& room_id) {
    return ext_mgr_.forward_extremity_count(room_id);
  }

  // ================================================================
  // Backfill extremity management
  // ================================================================

  std::vector<ExtremityManager::BackfillExtremity> get_backfill_extremities(
      const std::string& room_id) {
    return ext_mgr_.get_backfill_extremities(room_id);
  }

  void add_backfill_extremity(const std::string& room_id,
                               const EventId& event_id,
                               int64_t depth,
                               const std::string& origin_server) {
    ExtremityManager::BackfillExtremity be;
    be.event_id = event_id;
    be.depth = depth;
    be.origin_server = origin_server;
    be.discovered_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    ext_mgr_.add_backfill_extremity(room_id, be);
  }

  void mark_backfill_resolved(const std::string& room_id,
                               const EventId& event_id) {
    ext_mgr_.mark_backfilled(room_id, event_id);
  }

  // ================================================================
  // Topological ordering computation
  // ================================================================

  int64_t compute_event_depth(const EventId& event_id,
                               const std::vector<EventId>& prev_event_ids) {
    std::map<EventId, int64_t> known;
    return TopologicalOrderGenerator::compute_depth(event_id,
                                                     prev_event_ids, known);
  }

  std::vector<TopologicalOrderGenerator::TopologicalAssignment>
  assign_topological_ordering(const std::vector<ResolvableEvent>& events) {
    return TopologicalOrderGenerator::assign_ordering(events);
  }

  // ================================================================
  // Stream ordering assignment
  // ================================================================

  int64_t next_stream_ordering() {
    return stream_gen_.next();
  }

  int64_t allocate_stream_batch(size_t count) {
    return stream_gen_.next_batch(count);
  }

  int64_t current_max_stream() {
    return stream_gen_.max();
  }

  // ================================================================
  // Event deduplication
  // ================================================================

  bool is_event_duplicate(const EventId& event_id) {
    return dedup_.is_duplicate(event_id);
  }

  bool is_event_duplicate_by_hash(const std::string& hash) {
    return dedup_.is_duplicate_by_hash(hash);
  }

  bool mark_event_seen(const EventId& event_id) {
    return dedup_.check_and_mark(event_id);
  }

  // ================================================================
  // Rejected event handling
  // ================================================================

  bool is_event_rejected(const EventId& event_id) {
    return rejected_handler_.is_rejected(event_id);
  }

  std::optional<std::string> event_rejection_reason(const EventId& event_id) {
    return rejected_handler_.get_rejection_reason(event_id);
  }

  // ================================================================
  // Soft-failed event handling
  // ================================================================

  bool is_event_soft_failed(const EventId& event_id) {
    return soft_fail_handler_.is_soft_failed(event_id);
  }

  std::set<EventId> get_soft_failed_event_ids() {
    return soft_fail_handler_.get_soft_failed_set();
  }

  // ================================================================
  // Event auth chain computation
  // ================================================================

  std::set<EventId> compute_auth_chain(
      const EventId& event_id,
      const std::map<EventId, ResolvableEvent>& event_map) {
    return auth_computer_.compute_chain(event_id, event_map);
  }

  std::set<EventId> compute_auth_chain_multi(
      const std::vector<EventId>& event_ids,
      const std::map<EventId, ResolvableEvent>& event_map) {
    return auth_computer_.compute_chain_for_events(event_ids, event_map);
  }

  // ================================================================
  // Event edges management
  // ================================================================

  void add_event_edge(const EventId& source, const EventId& target) {
    edge_mgr_.add_edge(source, target);
  }

  std::set<EventId> get_prev_events(const EventId& event_id) {
    return edge_mgr_.get_prev_events(event_id);
  }

  std::set<EventId> get_next_events(const EventId& event_id) {
    return edge_mgr_.get_next_events(event_id);
  }

  // ================================================================
  // Event reference hashing
  // ================================================================

  std::string compute_event_hash(const ResolvableEvent& event) {
    return EventHasher::compute_content_hash(event);
  }

  std::string compute_event_reference_hash(const ResolvableEvent& event) {
    return EventHasher::compute_reference_hash(event);
  }

  // ================================================================
  // Event size tracking
  // ================================================================

  size_t get_event_size(const EventId& event_id) {
    auto sz = size_tracker_.get_event_size(event_id);
    return sz.value_or(0);
  }

  SizeTracker::RoomSize get_room_size_stats(const std::string& room_id) {
    return size_tracker_.get_room_stats(room_id);
  }

  SizeTracker::GlobalStats get_global_size_stats() {
    return size_tracker_.get_global_stats();
  }

  // ================================================================
  // Event stream token generation
  // ================================================================

  TokenGenerator::StreamToken generate_stream_token(
      int64_t topo, int64_t stream, const std::string& instance = "") {
    return TokenGenerator::generate(topo, stream, instance);
  }

  TokenGenerator::StreamToken generate_live_token() {
    return TokenGenerator::generate_live_token(stream_gen_.max());
  }

  // ================================================================
  // State group GC
  // ================================================================

  StateGroupGC::GCResult run_garbage_collection() {
    return gc_.collect(&cache_);
  }

  StateGroupGC::Stats get_gc_stats() {
    return gc_.get_stats();
  }

  // ================================================================
  // State autocompression
  // ================================================================

  size_t run_autocompression() {
    return compressor_.run_compression();
  }

  StateAutocompressor::CompressStats get_compression_stats() {
    return compressor_.get_stats();
  }

  // ================================================================
  // Periodic maintenance
  // ================================================================

  struct MaintenanceResult {
    size_t groups_compressed = 0;
    size_t groups_collected = 0;
    size_t stale_dedup_cleared = 0;
    size_t old_rejections_purged = 0;
  };

  MaintenanceResult run_maintenance() {
    MaintenanceResult result;
    result.groups_compressed = compressor_.run_compression();
    auto gc_result = gc_.collect(&cache_);
    result.groups_collected = gc_result.collected_groups.size();
    result.stale_dedup_cleared = dedup_.clear_stale();
    result.old_rejections_purged = rejected_handler_.purge_old();
    return result;
  }

  // ================================================================
  // Metrics and diagnostics
  // ================================================================

  struct CompilerMetrics {
    // State groups
    size_t total_state_groups = 0;
    size_t cached_state_groups = 0;
    double cache_hit_rate = 0.0;

    // Deduplication
    size_t dedup_entries = 0;

    // Stream ordering
    int64_t current_stream_order = 0;

    // Extremities
    size_t total_forward_extremities = 0;
    size_t total_backfill_extremities = 0;

    // Events
    size_t total_rejected = 0;
    size_t total_soft_failed = 0;

    // Sizes
    int64_t total_bytes = 0;
    int64_t total_events = 0;

    // GC
    size_t total_unreferenced_groups = 0;

    // Compression
    double compression_pct = 0.0;
  };

  CompilerMetrics get_metrics() {
    CompilerMetrics m;

    auto cache_stats = cache_.get_stats();
    m.total_state_groups = cache_stats.size;
    m.cached_state_groups = cache_stats.size;
    m.cache_hit_rate = cache_stats.hit_rate;

    m.dedup_entries = dedup_.dedup_size();
    m.current_stream_order = stream_gen_.max();

    auto ext_stats = ext_mgr_.get_all_stats();
    for (const auto& rs : ext_stats) {
      m.total_forward_extremities += rs.forward_count;
      m.total_backfill_extremities += rs.backfill_count;
    }

    m.total_rejected = rejected_handler_.total_rejected();
    m.total_soft_failed = soft_fail_handler_.count();

    auto size_stats = size_tracker_.get_global_stats();
    m.total_bytes = size_stats.total_bytes;
    m.total_events = size_stats.event_count;

    auto gc_stats = gc_.get_stats();
    m.total_unreferenced_groups = gc_stats.unreferenced_groups;

    auto comp_stats = compressor_.get_stats();
    m.compression_pct = comp_stats.compression_pct;

    return m;
  }

  // ================================================================
  // Cleanup
  // ================================================================

  void clear_room(const std::string& room_id) {
    cache_.invalidate_room(room_id);
    ext_mgr_.clear_room(room_id);
    rejected_handler_.clear();
    soft_fail_handler_.clear_room(room_id);
    group_ids_by_room_.erase(room_id);
  }

  void clear_all() {
    cache_.clear();
    dedup_.clear();
    edge_mgr_.clear();
    ext_mgr_.clear();
    size_tracker_.clear();
    rejected_handler_.clear();
    soft_fail_handler_.clear();
    gc_.clear();
    compressor_.clear();
    group_ids_by_room_.clear();
    stream_gen_.reset(config_.initial_stream_order);
    next_group_id_.store(1);
  }

private:
  static size_t estimate_group_byte_size(const StateGroupEntry& entry) {
    size_t size = 0;
    size += sizeof(entry);
    for (const auto& [k, v] : entry.state) {
      size += std::get<0>(k).size() + std::get<1>(k).size() + v.size();
      size += sizeof(StateKey) + sizeof(EventId);
    }
    return size;
  }

  Config config_;

  // Subsystems
  StateGroupCache cache_;
  EventDeduplicator dedup_;
  StreamOrderGenerator stream_gen_;
  AuthChainComputer auth_computer_;
  EdgeManager edge_mgr_;
  SizeTracker size_tracker_;
  ExtremityManager ext_mgr_;
  RejectedEventHandler rejected_handler_;
  SoftFailedEventHandler soft_fail_handler_;
  BatchPersister batch_persister_;
  StateGroupGC gc_;
  StateAutocompressor compressor_;

  // State group tracking
  std::atomic<int64_t> next_group_id_{1};
  std::map<std::string, std::vector<int64_t>> group_ids_by_room_;
};

// ============================================================================
// GLOBAL SINGLETON
// ============================================================================

namespace {

std::unique_ptr<StateGroupCompiler> g_compiler;
std::shared_mutex g_compiler_mutex;

}  // namespace

StateGroupCompiler& get_state_compiler() {
  {
    std::shared_lock lock(g_compiler_mutex);
    if (g_compiler)
      return *g_compiler;
  }

  std::unique_lock lock(g_compiler_mutex);
  if (!g_compiler) {
    g_compiler = std::make_unique<StateGroupCompiler>();
  }
  return *g_compiler;
}

void init_state_compiler(const StateGroupCompiler::Config& config) {
  std::unique_lock lock(g_compiler_mutex);
  g_compiler = std::make_unique<StateGroupCompiler>(config);
}

void shutdown_state_compiler() {
  std::unique_lock lock(g_compiler_mutex);
  if (g_compiler) {
    g_compiler->clear_all();
    g_compiler.reset();
  }
}

// ============================================================================
// CONVENIENCE API FUNCTIONS
// ============================================================================

// Persist an event with full compilation.
StateGroupCompiler::PersistResult persist_event_with_compilation(
    const std::string& room_id,
    const ResolvableEvent& event,
    const StateMap& current_state,
    const RoomVersion& version,
    StateGroupStore& store) {
  return get_state_compiler().persist_event(
      room_id, event, current_state, version, store);
}

// Persist a batch of events.
BatchPersister::PersistResult persist_event_batch(
    const std::string& room_id,
    const std::vector<ResolvableEvent>& events,
    const std::map<EventId, StateMap>& event_states,
    StateGroupStore* state_store) {
  return get_state_compiler().persist_event_batch(
      room_id, events, event_states, state_store);
}

// Get current room state.
StateMap get_current_room_state(const std::string& room_id) {
  return get_state_compiler().derive_current_state(room_id);
}

// Run periodic maintenance.
StateGroupCompiler::MaintenanceResult run_compiler_maintenance() {
  return get_state_compiler().run_maintenance();
}

// ============================================================================
// ROOM STATE STREAM (for sync)
// ============================================================================

namespace {

// Represents a single state event in the stream with its position.
struct StateStreamEntry {
  std::string room_id;
  std::string event_id;
  std::string type;
  std::string state_key;
  int64_t stream_ordering = 0;
  int64_t topological_ordering = 0;
};

// Stream state change tracker: records what state changed and at what
// stream position, so sync can deliver state deltas efficiently.
class StateStreamTracker {
public:
  // Record a state change.
  void record_state_change(const std::string& room_id,
                            const EventId& event_id,
                            const std::string& type,
                            const std::string& state_key,
                            int64_t stream_order,
                            int64_t topo_order) {
    std::unique_lock lock(mutex_);
    StateStreamEntry entry{room_id, event_id, type, state_key,
                           stream_order, topo_order};
    by_room_[room_id].push_back(entry);
  }

  // Get state changes for a room since a given stream ordering.
  std::vector<StateStreamEntry> get_changes_since(
      const std::string& room_id, int64_t since_stream) const {
    std::shared_lock lock(mutex_);
    std::vector<StateStreamEntry> changes;
    auto it = by_room_.find(room_id);
    if (it == by_room_.end()) return changes;

    for (const auto& entry : it->second) {
      if (entry.stream_ordering > since_stream)
        changes.push_back(entry);
    }
    return changes;
  }

  // Get all rooms that had state changes since a given stream ordering.
  std::set<std::string> get_changed_rooms_since(int64_t since_stream) const {
    std::shared_lock lock(mutex_);
    std::set<std::string> rooms;
    for (const auto& [room_id, entries] : by_room_) {
      for (const auto& entry : entries) {
        if (entry.stream_ordering > since_stream) {
          rooms.insert(room_id);
          break;
        }
      }
    }
    return rooms;
  }

  void clear() {
    std::unique_lock lock(mutex_);
    by_room_.clear();
  }

private:
  mutable std::shared_mutex mutex_;
  std::map<std::string, std::vector<StateStreamEntry>> by_room_;
};

// Global state stream tracker
static StateStreamTracker g_state_stream;

}  // namespace

void record_state_stream_change(const std::string& room_id,
                                 const EventId& event_id,
                                 const std::string& type,
                                 const std::string& state_key,
                                 int64_t stream_order,
                                 int64_t topo_order) {
  g_state_stream.record_state_change(room_id, event_id, type, state_key,
                                      stream_order, topo_order);
}

// ============================================================================
// EVENT REFERENCE VALIDATION
// ============================================================================
// Validates that event references (prev_events, auth_events) are
// internally consistent.

namespace {

struct EventReferenceValidation {
  std::string event_id;
  bool valid = true;
  std::vector<std::string> missing_prev_events;
  std::vector<std::string> missing_auth_events;
  std::vector<std::string> circular_references;
  std::string error_message;
};

EventReferenceValidation validate_event_references(
    const ResolvableEvent& event,
    const std::set<EventId>& known_events) {
  EventReferenceValidation result;
  result.event_id = event.event_id;

  // Check prev_events exist
  for (const auto& pid : event.prev_event_ids) {
    if (known_events.find(pid) == known_events.end()) {
      result.missing_prev_events.push_back(pid);
      result.valid = false;
    }
  }

  // Check auth_events exist
  for (const auto& aid : event.auth_event_ids) {
    if (known_events.find(aid) == known_events.end()) {
      result.missing_auth_events.push_back(aid);
      result.valid = false;
    }
  }

  // Check for self-references
  if (std::find(event.prev_event_ids.begin(), event.prev_event_ids.end(),
                 event.event_id) != event.prev_event_ids.end()) {
    result.circular_references.push_back(event.event_id);
    result.valid = false;
  }

  if (!result.valid) {
    std::stringstream ss;
    ss << "Event " << event.event_id << " has invalid references: ";
    if (!result.missing_prev_events.empty())
      ss << "missing prev_events=" << result.missing_prev_events.size() << " ";
    if (!result.missing_auth_events.empty())
      ss << "missing auth_events=" << result.missing_auth_events.size() << " ";
    if (!result.circular_references.empty())
      ss << "circular refs ";
    result.error_message = ss.str();
  }

  return result;
}

}  // namespace

// ============================================================================
// EVENT PERSISTENCE CONTEXT
// ============================================================================
// Contextual information needed when persisting an event.

namespace {

struct EventPersistenceContext {
  std::string room_id;
  std::string room_version;
  StateMap state_before;       // State at the event's prev_events
  StateMap state_after;        // State after applying this event (if state event)
  std::set<EventId> auth_chain;
  int64_t depth = 0;
  int64_t stream_ordering = 0;
  int64_t topological_ordering = 0;
  int64_t state_group = 0;
  bool is_state_event = false;
  bool is_outlier = false;
  bool is_rejected = false;
  std::string rejection_reason;
};

EventPersistenceContext build_persistence_context(
    const ResolvableEvent& event,
    const StateMap& current_state,
    const RoomVersion& version,
    StateGroupCompiler& compiler) {
  EventPersistenceContext ctx;
  ctx.room_id = event.room_id;
  ctx.room_version = version.identifier;
  ctx.state_before = current_state;
  ctx.is_state_event = event.is_state();
  ctx.depth = event.depth;

  // Compute state after
  ctx.state_after = current_state;
  if (ctx.is_state_event) {
    ctx.state_after[event.state_pair()] = event.event_id;
  }

  // Compute auth chain
  std::map<EventId, ResolvableEvent> event_map;
  event_map[event.event_id] = event;
  ctx.auth_chain = compiler.compute_auth_chain(event.event_id, event_map);

  return ctx;
}

}  // namespace

// ============================================================================
// STATE GROUP ITERATOR
// ============================================================================
// Iterates through state groups in chronological order for a room.

namespace {

class StateGroupIterator {
public:
  StateGroupIterator(StateGroupCompiler& compiler,
                      const std::string& room_id,
                      bool reverse = false)
      : compiler_(compiler), reverse_(reverse) {
    group_ids_ = compiler_.derive_current_state(room_id);
    // group_ids_ is actually a StateMap -> extract group IDs
    // For proper iteration we need group_ids_by_room
    reset();
  }

  void reset() {
    index_ = reverse_ ? group_ids_.size() : 0;
  }

  bool has_next() const {
    return reverse_ ? (index_ > 0) : (index_ < group_ids_.size());
  }

  StateMap next() {
    // This is a simplified iterator; real impl would use group IDs
    // For now return empty state
    if (reverse_) {
      if (index_ > 0) index_--;
    } else {
      if (index_ < group_ids_.size()) index_++;
    }
    return {};
  }

  size_t count() const { return group_ids_.size(); }

private:
  StateGroupCompiler& compiler_;
  StateMap group_ids_;
  size_t index_ = 0;
  bool reverse_ = false;
};

}  // namespace

// ============================================================================
// BULK STATE LOADER
// ============================================================================
// Loads state for multiple events in bulk, optimized for batch processing.

namespace {

class BulkStateLoader {
public:
  // Load state maps for multiple state groups at once.
  static std::map<int64_t, StateMap> load_state_groups(
      const std::set<int64_t>& group_ids,
      StateGroupCompiler& compiler) {
    std::map<int64_t, StateMap> result;
    for (int64_t gid : group_ids) {
      result[gid] = compiler.get_state_group_state(gid);
    }
    return result;
  }

  // Load current state for multiple rooms at once.
  static std::map<std::string, StateMap> load_current_state_bulk(
      const std::set<std::string>& room_ids,
      StateGroupCompiler& compiler) {
    std::map<std::string, StateMap> result;
    for (const auto& rid : room_ids) {
      result[rid] = compiler.derive_current_state(rid);
    }
    return result;
  }
};

}  // namespace

// ============================================================================
// STATE DIFF COMPRESSION (for network sync)
// ============================================================================
// Computes minimal diff between two state maps for efficient sync.

namespace {

struct CompressedStateDiff {
  std::string base_hash;
  StateMap sets;
  std::vector<StateKey> deletes;
  size_t original_size = 0;
  size_t compressed_size = 0;

  json to_json() const {
    json j;
    j["base_hash"] = base_hash;
    j["sets"] = json::object();
    for (const auto& [k, v] : sets) {
      j["sets"][std::get<0>(k) + "\x00" + std::get<1>(k)] = v;
    }
    json dels = json::array();
    for (const auto& k : deletes) {
      dels.push_back(std::get<0>(k) + "\x00" + std::get<1>(k));
    }
    j["deletes"] = dels;
    return j;
  }
};

CompressedStateDiff compress_state_diff(
    const StateMap& old_state, const StateMap& new_state) {
  CompressedStateDiff diff;

  // Hash of old state for ETag
  size_t h = 0;
  for (const auto& [k, v] : old_state)
    h ^= std::hash<std::string>{}(std::get<0>(k) + std::get<1>(k) + v);
  diff.base_hash = std::to_string(h);

  // Compute sets (added or changed)
  for (const auto& [k, v] : new_state) {
    auto it = old_state.find(k);
    if (it == old_state.end() || it->second != v)
      diff.sets[k] = v;
  }

  // Compute deletes
  for (const auto& [k, v] : old_state) {
    if (new_state.find(k) == new_state.end())
      diff.deletes.push_back(k);
  }

  diff.original_size = new_state.size();
  diff.compressed_size = diff.sets.size() + diff.deletes.size();

  return diff;
}

StateMap apply_compressed_state_diff(
    const StateMap& base, const CompressedStateDiff& diff) {
  StateMap result = base;
  for (const auto& [k, v] : diff.sets)
    result[k] = v;
  for (const auto& k : diff.deletes)
    result.erase(k);
  return result;
}

}  // namespace

// ============================================================================
// EVENT FILTERING UTILITIES
// ============================================================================
// Utilities for filtering events during batch persistence and stream
// generation.

namespace {

// Filter criteria for events.
struct EventFilter {
  std::optional<std::set<std::string>> types;         // Only these event types
  std::optional<std::set<std::string>> not_types;     // Exclude these types
  std::optional<std::set<std::string>> senders;       // Only from these senders
  std::optional<std::set<std::string>> not_senders;   // Not from these senders
  std::optional<bool> only_state;                      // Only state events
  std::optional<bool> only_non_state;                  // Only non-state events
  int64_t max_depth = INT64_MAX;
  int64_t min_depth = 0;
  int64_t max_stream = INT64_MAX;
  int64_t min_stream = 0;
};

bool matches_filter(const ResolvableEvent& event,
                     const EventFilter& filter,
                     int64_t stream_ordering = 0) {
  if (filter.types && filter.types->find(event.type) == filter.types->end())
    return false;

  if (filter.not_types && filter.not_types->find(event.type) !=
      filter.not_types->end())
    return false;

  if (filter.senders && filter.senders->find(event.sender) ==
      filter.senders->end())
    return false;

  if (filter.not_senders && filter.not_senders->find(event.sender) !=
      filter.not_senders->end())
    return false;

  if (filter.only_state.has_value() &&
      filter.only_state.value() != event.is_state())
    return false;

  if (filter.only_non_state.has_value() &&
      filter.only_non_state.value() == event.is_state())
    return false;

  if (event.depth > filter.max_depth || event.depth < filter.min_depth)
    return false;

  if (stream_ordering > filter.max_stream ||
      stream_ordering < filter.min_stream)
    return false;

  return true;
}

}  // namespace

// ============================================================================
// STATE GROUP RESOLVE AND MERGE
// ============================================================================
// Resolves conflicting state across multiple state groups and merges
// them into a single consistent state map.

namespace {

StateMap resolve_state_groups(
    const std::vector<int64_t>& group_ids,
    StateGroupCompiler& compiler,
    const RoomVersion& version,
    const EventMap& event_map) {
  if (group_ids.empty())
    return {};

  std::vector<StateMap> state_sets;
  for (int64_t gid : group_ids) {
    state_sets.push_back(compiler.get_state_group_state(gid));
  }

  if (state_sets.size() == 1)
    return state_sets[0];

  return resolve_events(version, state_sets, event_map);
}

}  // namespace

// ============================================================================
// STATE SNAPSHOT
// ============================================================================
// Creates a full snapshot of room state at a point in time.

namespace {

struct StateSnapshot {
  std::string room_id;
  std::string room_version;
  int64_t state_group_id = 0;
  StateMap state;
  int64_t snapshot_ts = 0;

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    j["room_version"] = room_version;
    j["state_group_id"] = state_group_id;
    j["snapshot_ts"] = snapshot_ts;
    j["state_count"] = state.size();

    json entries = json::array();
    for (const auto& [k, v] : state) {
      json entry;
      entry["type"] = std::get<0>(k);
      entry["state_key"] = std::get<1>(k);
      entry["event_id"] = v;
      entries.push_back(entry);
    }
    j["state_entries"] = entries;

    return j;
  }
};

StateSnapshot create_state_snapshot(
    const std::string& room_id,
    const std::string& room_version,
    int64_t state_group_id,
    StateGroupCompiler& compiler) {
  StateSnapshot snap;
  snap.room_id = room_id;
  snap.room_version = room_version;
  snap.state_group_id = state_group_id;
  snap.state = compiler.get_state_group_state(state_group_id);
  snap.snapshot_ts = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  return snap;
}

}  // namespace

// ============================================================================
// PERIODIC BACKGROUND TASKS
// ============================================================================

namespace {

// Periodic task runner that executes maintenance routines on a timer.
class MaintenanceRunner {
public:
  struct Config {
    int64_t maintenance_interval_seconds = 60;  // How often to run
    int64_t compression_interval = 60;
    int64_t gc_interval = 300;
    int64_t dedup_cleanup_interval = 600;
    int64_t rejection_purge_interval = 3600;    // 1 hour
  };

  explicit MaintenanceRunner(StateGroupCompiler& compiler,
                              Config cfg = {})
      : compiler_(compiler), config_(std::move(cfg)) {}

  // Run maintenance if enough time has elapsed. Returns what was done.
  StateGroupCompiler::MaintenanceResult run_if_needed() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        now - last_run_).count();

    if (elapsed < config_.maintenance_interval_seconds)
      return {};

    last_run_ = now;
    return compiler_.run_maintenance();
  }

  // Force a maintenance run.
  StateGroupCompiler::MaintenanceResult force_run() {
    last_run_ = std::chrono::steady_clock::now();
    return compiler_.run_maintenance();
  }

private:
  StateGroupCompiler& compiler_;
  Config config_;
  std::chrono::steady_clock::time_point last_run_;
};

}  // namespace

// ============================================================================
// EVENT PERSISTENCE RESULT VALIDATOR
// ============================================================================
// Validates that a persistence result is internally consistent.

namespace {

bool validate_persist_result(
    const BatchPersister::PersistResult& result) {
  // Check that persisted IDs have stream orderings if stream ordering enabled
  if (!result.persisted_ids.empty() &&
      result.stream_orderings.size() != result.persisted_ids.size()) {
    return false;
  }

  // Check that duplicate IDs are not in persisted IDs
  std::set<EventId> persisted_set(result.persisted_ids.begin(),
                                   result.persisted_ids.end());
  for (const auto& did : result.duplicate_ids) {
    if (persisted_set.count(did))
      return false;
  }

  return true;
}

}  // namespace

// ============================================================================
// FINAL INITIALIZATION
// ============================================================================

// Ensure the global compiler is initialized on first use.
static struct CompilerInitializer {
  CompilerInitializer() {
    // Pre-warm with default config; explicit init overrides
    get_state_compiler();
  }
} g_compiler_initializer;

}  // namespace progressive::state
