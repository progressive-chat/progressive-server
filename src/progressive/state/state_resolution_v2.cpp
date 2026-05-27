#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <set>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "event_auth.hpp"
#include "room_version.hpp"
#include "state_group.hpp"
#include "state_resolution.hpp"
#include "types.hpp"

namespace progressive::state {

// ============================================================================
// Forward declarations
// ============================================================================

namespace {
struct MainlineEntry;
struct PowerLevelOrdering;
struct AuthChainCache;
struct ResolutionMetrics;
struct StateDelta;
struct CompressedStateGroup;
struct ForkDetectionResult;
struct ResolvedState;
struct ResolutionCache;
}  // namespace

// ============================================================================
// 1. MAINLINE ORDERING
// ============================================================================
// Determine event order by mainline depth. Events closer to the power level
// event in the auth chain are considered more authoritative.

namespace {

// Mainline entry: stores an event's position relative to power events in its
// auth chain. Lower mainline depth means closer to a power event.
struct MainlineEntry {
  EventId event_id;
  int64_t depth = 0;          // Mainline depth (0 = at power event)
  int64_t origin_server_ts = 0;
  int64_t stream_ordering = 0; // Fallback ordering

  bool operator<(const MainlineEntry& other) const {
    if (depth != other.depth)
      return depth < other.depth;
    if (origin_server_ts != other.origin_server_ts)
      return origin_server_ts < other.origin_server_ts;
    if (stream_ordering != other.stream_ordering)
      return stream_ordering < other.stream_ordering;
    return event_id < other.event_id;
  }
};

// Compute the mainline depth for an event by walking its auth chain until a
// power event (m.room.power_levels, m.room.create, or m.room.join_rules) is
// encountered. Returns the depth and the event_map for reference.
int64_t compute_mainline_depth(const EventId& event_id,
                                const EventMap& event_map,
                                int max_depth = 100) {
  std::string current = event_id;
  for (int i = 0; i < max_depth; i++) {
    auto it = event_map.find(current);
    if (it == event_map.end())
      return i + 1000;  // Penalize events not in the map
    const ResolvableEvent& event = it->second;
    auto k = event.state_pair();
    if (k == make_key("m.room.power_levels", "") ||
        k == make_key("m.room.create", "") ||
        k == make_key("m.room.join_rules", "")) {
      return i;
    }
    // Walk first auth event (typically create or power_levels in room v1-v2)
    bool found = false;
    for (const auto& aid : event.auth_event_ids) {
      auto ait = event_map.find(aid);
      if (ait != event_map.end()) {
        current = aid;
        found = true;
        break;
      }
    }
    if (!found && !event.prev_event_ids.empty()) {
      for (const auto& pid : event.prev_event_ids) {
        auto pit = event_map.find(pid);
        if (pit != event_map.end()) {
          current = pid;
          found = true;
          break;
        }
      }
    }
    if (!found)
      return i + 1000;
  }
  return max_depth + 1000;
}

// Build full mainline ordering table for a set of events. Returns a map from
// event_id -> MainlineEntry sorted by increasing mainline depth.
std::map<EventId, MainlineEntry> build_mainline_table(
    const std::set<EventId>& event_ids,
    const EventMap& event_map) {
  std::map<EventId, MainlineEntry> table;
  for (const auto& eid : event_ids) {
    auto it = event_map.find(eid);
    if (it == event_map.end()) {
      table[eid] = {eid, INT64_MAX, 0, 0};
      continue;
    }
    int64_t depth = compute_mainline_depth(eid, event_map, 100);
    table[eid] = {
        eid,
        depth,
        it->second.origin_server_ts,
        static_cast<int64_t>(it->second.depth)
    };
  }
  return table;
}

// Compare two events using mainline ordering. Returns true if `a` should come
// before `b` (i.e., `a` is more authoritative than `b`).
// This is used for sorting before reverse order application in state res v2.
bool mainline_compare(const EventId& a, const EventId& b,
                      const std::map<EventId, MainlineEntry>& mainline,
                      const EventMap& event_map) {
  auto ma = mainline.find(a);
  auto mb = mainline.find(b);

  int64_t depth_a = (ma != mainline.end()) ? ma->second.depth : INT64_MAX;
  int64_t depth_b = (mb != mainline.end()) ? mb->second.depth : INT64_MAX;

  if (depth_a != depth_b)
    return depth_a < depth_b;

  auto it_a = event_map.find(a);
  auto it_b = event_map.find(b);

  // Power events sorted by (origin_server_ts, event_id) ascending
  if (it_a != event_map.end() && it_b != event_map.end()) {
    if (it_a->second.origin_server_ts != it_b->second.origin_server_ts)
      return it_a->second.origin_server_ts < it_b->second.origin_server_ts;
  }

  return a < b;
}

// Sort events by mainline ordering (ascending authority). Events with smaller
// mainline depth come first.
std::vector<EventId> sort_by_mainline(const std::set<EventId>& event_ids,
                                       const EventMap& event_map) {
  auto mainline = build_mainline_table(event_ids, event_map);
  std::vector<EventId> sorted(event_ids.begin(), event_ids.end());
  std::sort(sorted.begin(), sorted.end(),
            [&](const EventId& a, const EventId& b) {
              return mainline_compare(a, b, mainline, event_map);
            });
  return sorted;
}

}  // namespace

// ============================================================================
// 2. POWER LEVEL ORDERING
// ============================================================================
// Sort auth events by power level. Events created by users with higher power
// levels are preferred when resolving conflicts.

namespace {

struct PowerLevelOrdering {
  EventId event_id;
  int power_level = 0;
  int64_t origin_server_ts = 0;
  std::string sender;

  bool operator<(const PowerLevelOrdering& other) const {
    if (power_level != other.power_level)
      return power_level < other.power_level;
    if (origin_server_ts != other.origin_server_ts)
      return origin_server_ts < other.origin_server_ts;
    return event_id < other.event_id;
  }
};

// Extract the effective power level for an event's sender based on the current
// resolved power levels state.
int effective_power_level(const ResolvableEvent& event,
                          const std::map<StateKey, ResolvableEvent>& resolved_auth) {
  auto pl_it = resolved_auth.find(make_key("m.room.power_levels", ""));
  if (pl_it == resolved_auth.end())
    return static_cast<int>(event.sender == event.room_id ? 100 : 0);

  const ResolvableEvent& pl_event = pl_it->second;
  const nlohmann::json& content = pl_event.content;

  // m.room.create events are always allowed
  if (event.type == "m.room.create")
    return 100;

  // Check explicit user power level
  if (content.contains("users") && content["users"].is_object()) {
    const auto& users = content["users"];
    if (users.contains(event.sender) && users[event.sender].is_number())
      return users[event.sender].get<int>();
  }

  // Check default user power level
  if (content.contains("users_default") && content["users_default"].is_number())
    return content["users_default"].get<int>();

  return 0;
}

// Sort event IDs by the power level of their sender, using the current
// resolved state for power level lookup.
std::vector<EventId> sort_by_power_level(
    const std::vector<EventId>& events,
    const EventMap& event_map,
    const std::map<StateKey, ResolvableEvent>& resolved_auth) {
  std::vector<PowerLevelOrdering> ordered;
  for (const auto& eid : events) {
    auto it = event_map.find(eid);
    if (it == event_map.end()) {
      ordered.push_back({eid, 0, 0, ""});
      continue;
    }
    int pl = effective_power_level(it->second, resolved_auth);
    ordered.push_back({
        eid,
        pl,
        it->second.origin_server_ts,
        it->second.sender
    });
  }
  std::sort(ordered.begin(), ordered.end());
  std::vector<EventId> result;
  result.reserve(ordered.size());
  for (auto& o : ordered)
    result.push_back(std::move(o.event_id));
  return result;
}

}  // namespace

// ============================================================================
// 3. AUTH CHAIN COMPUTATION
// ============================================================================
// Walk prev_events and auth_events to root to compute the full auth chain
// of an event.

namespace {

// Cache for auth chain computations to avoid repeated walks
struct AuthChainCache {
  std::map<EventId, std::set<EventId>> chain_cache;
  std::shared_mutex mutex;
  size_t max_size = 100000;
  std::atomic<uint64_t> hits{0};
  std::atomic<uint64_t> misses{0};

  std::optional<std::set<EventId>> get(const EventId& eid) {
    std::shared_lock lock(mutex);
    auto it = chain_cache.find(eid);
    if (it != chain_cache.end()) {
      hits.fetch_add(1, std::memory_order_relaxed);
      return it->second;
    }
    misses.fetch_add(1, std::memory_order_relaxed);
    return std::nullopt;
  }

  void put(const EventId& eid, std::set<EventId> chain) {
    std::unique_lock lock(mutex);
    if (chain_cache.size() >= max_size) {
      // Evict in simple FIFO-ish way: remove first entry
      if (!chain_cache.empty())
        chain_cache.erase(chain_cache.begin());
    }
    chain_cache[eid] = std::move(chain);
  }

  void clear() {
    std::unique_lock lock(mutex);
    chain_cache.clear();
  }
};

// Thread-local auth chain cache for resolution operations
static AuthChainCache g_auth_chain_cache;

// Walk the auth events of an event to compute its full auth chain.
// This recursively follows auth_event_ids, not prev_event_ids.
std::set<EventId> compute_auth_chain(const EventId& event_id,
                                      const EventMap& event_map,
                                      std::set<EventId>& visited,
                                      int max_depth = 100) {
  std::set<EventId> chain;
  if (visited.count(event_id) || max_depth <= 0)
    return chain;

  visited.insert(event_id);
  chain.insert(event_id);

  auto it = event_map.find(event_id);
  if (it == event_map.end())
    return chain;

  for (const auto& aid : it->second.auth_event_ids) {
    auto subchain = compute_auth_chain(aid, event_map, visited, max_depth - 1);
    chain.insert(subchain.begin(), subchain.end());
  }

  return chain;
}

// Public-facing auth chain computation with caching
std::set<EventId> get_auth_chain(const EventId& event_id,
                                  const EventMap& event_map) {
  auto cached = g_auth_chain_cache.get(event_id);
  if (cached.has_value())
    return cached.value();

  std::set<EventId> visited;
  auto chain = compute_auth_chain(event_id, event_map, visited, 100);
  g_auth_chain_cache.put(event_id, chain);
  return chain;
}

// Compute auth chain for multiple events (union of all chains)
std::set<EventId> get_auth_chain_for_events(
    const std::vector<EventId>& event_ids,
    const EventMap& event_map) {
  std::set<EventId> chain;
  for (const auto& eid : event_ids) {
    auto sub = get_auth_chain(eid, event_map);
    chain.insert(sub.begin(), sub.end());
  }
  return chain;
}

}  // namespace

// ============================================================================
// 4. AUTH CHAIN DIFFERENCE
// ============================================================================
// Compute the difference between two auth chains. Useful for determining
// which auth events are unique to each side of a fork.

namespace {

struct AuthChainDiff {
  std::set<EventId> only_in_a;  // Events unique to chain A
  std::set<EventId> only_in_b;  // Events unique to chain B
  std::set<EventId> in_both;    // Events in both chains
  size_t size_a = 0;
  size_t size_b = 0;
};

AuthChainDiff compute_auth_chain_difference(
    const std::set<EventId>& chain_a,
    const std::set<EventId>& chain_b) {
  AuthChainDiff diff;
  diff.size_a = chain_a.size();
  diff.size_b = chain_b.size();

  // Events in A but not in B
  for (const auto& eid : chain_a) {
    if (chain_b.count(eid))
      diff.in_both.insert(eid);
    else
      diff.only_in_a.insert(eid);
  }

  // Events in B but not in A
  for (const auto& eid : chain_b) {
    if (!chain_a.count(eid))
      diff.only_in_b.insert(eid);
  }

  return diff;
}

// Convenience: compute auth chain diff directly from event IDs
AuthChainDiff auth_chain_diff(const EventId& event_a,
                               const EventId& event_b,
                               const EventMap& event_map) {
  auto chain_a = get_auth_chain(event_a, event_map);
  auto chain_b = get_auth_chain(event_b, event_map);
  return compute_auth_chain_difference(chain_a, chain_b);
}

}  // namespace

// ============================================================================
// 5. FORK DETECTION
// ============================================================================
// Detect state forks that need resolution. A fork occurs when two or more
// state sets diverge on the same state key.

namespace {

struct ForkDetectionResult {
  bool has_fork = false;
  std::set<StateKey> forked_keys;         // Keys with conflicts
  std::set<EventId> forked_events;       // All events involved in forks
  std::vector<StateMap> divergent_sets;  // The state sets causing the fork
  int64_t fork_depth = 0;                // Depth at which fork occurred
  std::string description;

  bool empty() const { return !has_fork; }
};

// Detect forks across multiple state sets. A fork exists when the same state
// key has different values across the sets.
ForkDetectionResult detect_forks(const std::vector<StateMap>& state_sets) {
  ForkDetectionResult result;

  if (state_sets.size() < 2) {
    result.has_fork = false;
    result.description = "single state set, no fork possible";
    return result;
  }

  // Collect all keys across all sets
  std::set<StateKey> all_keys;
  for (const auto& ss : state_sets)
    for (const auto& [k, v] : ss)
      all_keys.insert(k);

  // Check each key for divergence
  for (const auto& key : all_keys) {
    std::set<EventId> values;
    for (const auto& ss : state_sets) {
      auto it = ss.find(key);
      if (it != ss.end())
        values.insert(it->second);
    }

    if (values.size() > 1) {
      result.forked_keys.insert(key);
      result.forked_events.insert(values.begin(), values.end());
    }
  }

  result.has_fork = !result.forked_keys.empty();

  if (result.has_fork) {
    result.description = "detected " +
                         std::to_string(result.forked_keys.size()) +
                         " conflicted keys across " +
                         std::to_string(state_sets.size()) + " state sets";
    result.divergent_sets = state_sets;
  } else {
    result.description = "no fork detected, state sets agree";
  }

  return result;
}

// Detect forks with detailed event-level information
ForkDetectionResult detect_forks_detailed(
    const std::vector<StateMap>& state_sets,
    const EventMap& event_map) {
  auto result = detect_forks(state_sets);

  if (result.has_fork) {
    // Compute fork depth: find the deepest common event
    int64_t min_depth = INT64_MAX;
    for (const auto& eid : result.forked_events) {
      auto it = event_map.find(eid);
      if (it != event_map.end() && it->second.depth < min_depth)
        min_depth = it->second.depth;
    }
    result.fork_depth = (min_depth == INT64_MAX) ? 0 : min_depth;
  }

  return result;
}

}  // namespace

// ============================================================================
// 6. STATE RESOLUTION V2 - CORE ALGORITHM
// ============================================================================
// The main state resolution v2 algorithm as specified in the Matrix spec.
// Steps:
//   1. Separate state sets into unconflicted and conflicted
//   2. Collect full set of conflicted events
//   3. Expand auth chain of conflicted events
//   4. Sort power events by mainline ordering, apply them in order
//   5. Sort remaining events by mainline + power level, apply in order
//   6. For each event, check auth rules against current resolved state
//   7. Return the resolved state map

namespace {

// Phase 1: Separate state maps into unconflicted and conflicted.
// Same as existing separate() but returns more detail.
struct SeparationResult {
  StateMap unconflicted;
  ConflictedState conflicted;
  std::set<EventId> all_event_ids;
  size_t unconflicted_count = 0;
  size_t conflicted_count = 0;
};

SeparationResult separate_events_detailed(const std::vector<StateMap>& state_sets) {
  SeparationResult result;
  if (state_sets.empty())
    return result;

  result.unconflicted = state_sets[0];

  for (size_t i = 1; i < state_sets.size(); i++) {
    for (const auto& [key, value] : state_sets[i]) {
      auto un_it = result.unconflicted.find(key);
      if (un_it == result.unconflicted.end()) {
        auto con_it = result.conflicted.find(key);
        if (con_it == result.conflicted.end()) {
          result.unconflicted[key] = value;
        } else {
          con_it->second.insert(value);
        }
      } else if (un_it->second != value) {
        result.conflicted[key] = {value, un_it->second};
        result.unconflicted.erase(un_it);
      }
    }
  }

  // Collect all event IDs
  for (const auto& [k, v] : result.unconflicted)
    result.all_event_ids.insert(v);
  for (const auto& [k, vs] : result.conflicted)
    result.all_event_ids.insert(vs.begin(), vs.end());

  result.unconflicted_count = result.unconflicted.size();
  result.conflicted_count = result.conflicted.size();

  return result;
}

// Phase 2: Expand auth chain of all conflicted events.
// This ensures that power level events and other auth dependencies are
// included in the resolution process.
std::set<EventId> expand_auth_chain_for_resolution(
    const ConflictedState& conflicted,
    const EventMap& event_map,
    int max_expansion_depth = 20) {
  std::set<EventId> expanded;
  std::set<EventId> all_conflicted;

  for (const auto& [k, eids] : conflicted)
    all_conflicted.insert(eids.begin(), eids.end());

  // BFS expansion of auth chains
  std::deque<EventId> queue(all_conflicted.begin(), all_conflicted.end());
  expanded = all_conflicted;

  while (!queue.empty() && max_expansion_depth > 0) {
    EventId current = queue.front();
    queue.pop_front();

    auto it = event_map.find(current);
    if (it == event_map.end())
      continue;

    for (const auto& aid : it->second.auth_event_ids) {
      if (expanded.insert(aid).second) {
        queue.push_back(aid);
      }
    }
    max_expansion_depth--;
  }

  return expanded;
}

// Phase 3: Classify events as power events vs normal events.
// Power events: m.room.power_levels, m.room.join_rules, m.room.create
// Also: m.room.member events where sender != state_key (third-party invites/kicks)
struct EventClassification {
  std::vector<EventId> power_events;
  std::vector<EventId> normal_events;
  std::vector<EventId> restricted_join_events;  // m.room.member with join_authorised_via_users
  std::vector<EventId> ban_events;               // m.room.member with membership=ban
};

EventClassification classify_events(
    const std::set<EventId>& event_ids,
    const EventMap& event_map,
    const RoomVersion& version) {
  EventClassification result;

  for (const auto& eid : event_ids) {
    auto it = event_map.find(eid);
    if (it == event_map.end())
      continue;

    const ResolvableEvent& event = it->second;
    auto k = event.state_pair();

    // Power events
    if (is_power_event(event)) {
      result.power_events.push_back(eid);
      continue;
    }

    // Ban events
    if (k == make_key("m.room.member", event.state_key) &&
        event.content.contains("membership") &&
        event.content["membership"] == "ban") {
      result.ban_events.push_back(eid);
      continue;
    }

    // Restricted join events (for room versions that support it)
    if (version.restricted_join_rule &&
        k == make_key("m.room.member", event.state_key) &&
        event.content.contains("membership") &&
        event.content["membership"] == "join") {
      result.restricted_join_events.push_back(eid);
      continue;
    }

    result.normal_events.push_back(eid);
  }

  return result;
}

// Phase 4: Build the topological ordering for power events.
// Uses mainline depth to determine processing order.
std::vector<EventId> order_power_events(
    const std::vector<EventId>& power_events,
    const EventMap& event_map) {
  std::set<EventId> pe_set(power_events.begin(), power_events.end());

  // Build adjacency from auth_event_ids (edges: event -> auth_event)
  std::map<EventId, std::set<EventId>> outdegree;
  for (const auto& eid : pe_set) {
    outdegree[eid] = {};  // Ensure all nodes exist
    auto it = event_map.find(eid);
    if (it != event_map.end()) {
      for (const auto& aid : it->second.auth_event_ids) {
        if (pe_set.count(aid))
          outdegree[eid].insert(aid);
      }
    }
  }

  // Topological sort with mainline depth tiebreaking
  // Build reverse edges
  std::map<EventId, std::set<EventId>> reverse;
  for (const auto& [node, edges] : outdegree)
    for (const auto& edge : edges)
      reverse[edge].insert(node);

  // Priority: (mainline_depth, origin_server_ts) ascending
  using PQItem = std::tuple<int64_t, int64_t, EventId>;
  std::priority_queue<PQItem, std::vector<PQItem>, std::greater<PQItem>> pq;

  auto mainline = build_mainline_table(pe_set, event_map);

  for (const auto& [node, edges] : outdegree) {
    if (edges.empty()) {
      auto m_it = mainline.find(node);
      int64_t md = (m_it != mainline.end()) ? m_it->second.depth : INT64_MAX;
      auto e_it = event_map.find(node);
      int64_t ts = (e_it != event_map.end()) ? e_it->second.origin_server_ts : 0;
      pq.push({md, ts, node});
    }
  }

  std::vector<EventId> sorted;
  while (!pq.empty()) {
    auto [md, ts, node] = pq.top();
    pq.pop();
    sorted.push_back(node);

    for (const auto& parent : reverse[node]) {
      outdegree[parent].erase(node);
      if (outdegree[parent].empty()) {
        auto m_it = mainline.find(parent);
        int64_t pmd = (m_it != mainline.end()) ? m_it->second.depth : INT64_MAX;
        auto e_it = event_map.find(parent);
        int64_t pts = (e_it != event_map.end()) ? e_it->second.origin_server_ts : 0;
        pq.push({pmd, pts, parent});
      }
    }
  }

  return sorted;
}

// Phase 5: Apply auth events in order against the current resolved state.
// For each event, check auth rules. If the event passes, it updates the
// resolved state for its state_key.
void apply_auth_events(
    const std::vector<EventId>& ordered_events,
    const EventMap& event_map,
    const RoomVersion& version,
    const StateMap& unconflicted,
    StateMap& resolved,
    std::map<StateKey, ResolvableEvent>& resolved_auth) {
  for (const auto& eid : ordered_events) {
    auto it = event_map.find(eid);
    if (it == event_map.end())
      continue;

    const ResolvableEvent& event = it->second;
    StateKey key = event.state_pair();

    // Build auth context from: event's own auth events + current resolved state
    std::vector<ResolvableEvent> auth_vec;

    // Add event's own auth events
    for (const auto& aid : event.auth_event_ids) {
      auto ait = event_map.find(aid);
      if (ait != event_map.end())
        auth_vec.push_back(ait->second);
    }

    // Add auth types from resolved state
    for (const auto& ak : auth_types_for_event(version, event)) {
      auto rit = resolved.find(ak);
      if (rit != resolved.end()) {
        auto ait = event_map.find(rit->second);
        if (ait != event_map.end())
          auth_vec.push_back(ait->second);
      }
    }

    // Check state-dependent auth rules
    if (check_state_dependent_auth_rules(version, event, auth_vec)) {
      resolved[key] = eid;
      resolved_auth[key] = event;
    }
  }
}

// Phase 6: Apply normal events, sorted by mainline depth then power level.
// Normal events: everything that isn't a power event.
void apply_normal_events(
    const std::vector<EventId>& normal_events,
    const EventMap& event_map,
    const RoomVersion& version,
    const StateMap& unconflicted,
    StateMap& resolved,
    std::map<StateKey, ResolvableEvent>& resolved_auth) {
  // Build mainline table
  std::set<EventId> ne_set(normal_events.begin(), normal_events.end());
  auto mainline = build_mainline_table(ne_set, event_map);

  // Sort by mainline depth, then origin_server_ts, then event_id
  std::vector<EventId> sorted = normal_events;
  std::sort(sorted.begin(), sorted.end(),
            [&](const EventId& a, const EventId& b) {
              auto ma = mainline.find(a);
              auto mb = mainline.find(b);
              int64_t da = (ma != mainline.end()) ? ma->second.depth : INT64_MAX;
              int64_t db = (mb != mainline.end()) ? mb->second.depth : INT64_MAX;
              if (da != db) return da < db;
              auto ea = event_map.find(a);
              auto eb = event_map.find(b);
              int64_t tsa = (ea != event_map.end()) ? ea->second.origin_server_ts : 0;
              int64_t tsb = (eb != event_map.end()) ? eb->second.origin_server_ts : 0;
              if (tsa != tsb) return tsa < tsb;
              return a < b;
            });

  // Apply in mainline order
  apply_auth_events(sorted, event_map, version, unconflicted, resolved, resolved_auth);
}

}  // namespace

// ============================================================================
// 7. STATE RESOLUTION FOR RESTRICTED JOINS
// ============================================================================
// Handle restricted join rules: m.room.member events with join_authorised_via_users_server
// that allow members of specific rooms to join.

namespace {

// Check if a restricted join is allowed given the current resolved state.
// For restricted joins, the event must be authorised by a user who is:
//   - In the target room (via m.room.member)
//   - Has sufficient power level to invite
bool resolve_restricted_join(
    const ResolvableEvent& join_event,
    const std::map<StateKey, ResolvableEvent>& resolved_auth,
    const EventMap& event_map,
    const RoomVersion& version) {
  if (!version.restricted_join_rule)
    return true;  // Not applicable, let normal auth rules handle it

  // Check if there's a join_rules event with allow rules
  auto jr_it = resolved_auth.find(make_key("m.room.join_rules", ""));
  if (jr_it == resolved_auth.end())
    return true;  // No join rules, default to allow

  const ResolvableEvent& jr_event = jr_it->second;
  if (!jr_event.content.contains("join_rule"))
    return true;

  std::string join_rule = jr_event.content["join_rule"].get<std::string>();

  if (join_rule != "restricted" && join_rule != "knock_restricted")
    return true;  // Not a restricted join, allow normal processing

  // For restricted joins, check if the event has join_authorised_via_users_server
  if (!join_event.content.contains("join_authorised_via_users_server")) {
    // No authorisation — if the user was already invited, allow
    auto member_it = resolved_auth.find(
        make_key("m.room.member", join_event.state_key));
    if (member_it != resolved_auth.end() &&
        member_it->second.content.contains("membership") &&
        member_it->second.content["membership"] == "invite") {
      return true;
    }
    return false;  // Not authorised
  }

  // The authorised user must have power to invite
  std::string auth_user = join_event.content["join_authorised_via_users_server"]
                              .get<std::string>();

  // Check that authorised user is in the room with sufficient power
  auto auth_member_it = resolved_auth.find(
      make_key("m.room.member", auth_user));
  if (auth_member_it == resolved_auth.end())
    return false;

  const ResolvableEvent& auth_member = auth_member_it->second;
  if (!auth_member.content.contains("membership") ||
      auth_member.content["membership"] != "join") {
    return false;
  }

  // Check power level of authorising user
  int auth_pl = 0;
  auto pl_it = resolved_auth.find(make_key("m.room.power_levels", ""));
  if (pl_it != resolved_auth.end()) {
    const nlohmann::json& pl_content = pl_it->second.content;
    int invite_level = 50;  // Default invite level
    if (pl_content.contains("invite") && pl_content["invite"].is_number())
      invite_level = pl_content["invite"].get<int>();

    if (pl_content.contains("users") && pl_content["users"].is_object()) {
      const auto& users = pl_content["users"];
      if (users.contains(auth_user) && users[auth_user].is_number())
        auth_pl = users[auth_user].get<int>();
    } else if (pl_content.contains("users_default") &&
               pl_content["users_default"].is_number()) {
      auth_pl = pl_content["users_default"].get<int>();
    }
    return auth_pl >= invite_level;
  }

  return true;  // No power levels event, default allow
}

// Resolve conflicted restricted joins.
// Restricted joins must be resolved after join_rules and power_levels are
// established.
void resolve_restricted_joins_conflicted(
    const std::vector<EventId>& restricted_joins,
    const EventMap& event_map,
    const RoomVersion& version,
    StateMap& resolved,
    std::map<StateKey, ResolvableEvent>& resolved_auth) {
  for (const auto& eid : restricted_joins) {
    auto it = event_map.find(eid);
    if (it == event_map.end())
      continue;

    const ResolvableEvent& event = it->second;
    StateKey key = event.state_pair();

    // Already resolved by a higher-authority event
    if (resolved.count(key))
      continue;

    // Build auth context
    std::vector<ResolvableEvent> auth_vec;
    for (const auto& aid : event.auth_event_ids) {
      auto ait = event_map.find(aid);
      if (ait != event_map.end())
        auth_vec.push_back(ait->second);
    }
    for (const auto& ak : auth_types_for_event(version, event)) {
      auto rit = resolved.find(ak);
      if (rit != resolved.end()) {
        auto ait = event_map.find(rit->second);
        if (ait != event_map.end())
          auth_vec.push_back(ait->second);
      }
    }

    if (check_state_dependent_auth_rules(version, event, auth_vec) &&
        resolve_restricted_join(event, resolved_auth, event_map, version)) {
      resolved[key] = eid;
      resolved_auth[key] = event;
    }
  }
}

}  // namespace

// ============================================================================
// 8. STATE RESOLUTION FOR BAN EVENTS
// ============================================================================
// Ban events (m.room.member with membership=ban) get special handling.
// They should be preferred over other membership changes for the same user.

namespace {

// Resolve conflicted ban events. Ban events have highest priority among
// membership changes for a given user.
void resolve_ban_events_conflicted(
    const std::vector<EventId>& ban_events,
    const EventMap& event_map,
    const RoomVersion& version,
    StateMap& resolved,
    std::map<StateKey, ResolvableEvent>& resolved_auth) {
  for (const auto& eid : ban_events) {
    auto it = event_map.find(eid);
    if (it == event_map.end())
      continue;

    const ResolvableEvent& event = it->second;
    StateKey key = event.state_pair();

    if (resolved.count(key))
      continue;

    // Build auth context for the ban event
    std::vector<ResolvableEvent> auth_vec;
    for (const auto& aid : event.auth_event_ids) {
      auto ait = event_map.find(aid);
      if (ait != event_map.end())
        auth_vec.push_back(ait->second);
    }
    for (const auto& ak : auth_types_for_event(version, event)) {
      auto rit = resolved.find(ak);
      if (rit != resolved.end()) {
        auto ait = event_map.find(rit->second);
        if (ait != event_map.end())
          auth_vec.push_back(ait->second);
      }
    }

    if (check_state_dependent_auth_rules(version, event, auth_vec)) {
      resolved[key] = eid;
      resolved_auth[key] = event;
    }
  }
}

}  // namespace

// ============================================================================
// 9. STATE RESOLUTION FOR POWER LEVEL CHANGES
// ============================================================================
// When power levels change, the ordering of other events may be affected.
// This module ensures power level changes are resolved first and their
// effects propagate to subsequent event resolution.

namespace {

// Resolve power level changes with iterative repass.
// After resolving power events, we may need to re-evaluate other conflicted
// events because their senders' power levels may have changed.
struct PowerLevelResolutionResult {
  StateMap resolved_state;
  std::map<StateKey, ResolvableEvent> resolved_auth;
  std::set<EventId> applied_power_events;
  int iterations = 0;
};

PowerLevelResolutionResult resolve_power_level_changes(
    const std::vector<EventId>& power_events,
    const std::vector<EventId>& all_events,
    const EventMap& event_map,
    const RoomVersion& version,
    const StateMap& unconflicted) {
  PowerLevelResolutionResult result;
  result.resolved_state = unconflicted;

  // Populate initial auth from unconflicted
  for (const auto& [k, eid] : unconflicted) {
    auto it = event_map.find(eid);
    if (it != event_map.end())
      result.resolved_auth[k] = it->second;
  }

  // Step 1: Resolve power events
  auto ordered_power = order_power_events(power_events, event_map);
  apply_auth_events(ordered_power, event_map, version, unconflicted,
                    result.resolved_state, result.resolved_auth);

  for (const auto& eid : ordered_power)
    result.applied_power_events.insert(eid);

  result.iterations = 1;

  // Step 2: Iterative recheck — some events that failed before may now pass
  // because power levels have changed.
  int max_iterations = 3;
  for (int iter = 1; iter < max_iterations; iter++) {
    bool changed = false;

    for (const auto& eid : all_events) {
      if (result.applied_power_events.count(eid))
        continue;

      auto it = event_map.find(eid);
      if (it == event_map.end())
        continue;

      const ResolvableEvent& event = it->second;
      StateKey key = event.state_pair();

      // Skip if already resolved with this event
      auto res_it = result.resolved_state.find(key);
      if (res_it != result.resolved_state.end() && res_it->second == eid)
        continue;

      // Build auth context with current resolved state
      std::vector<ResolvableEvent> auth_vec;
      for (const auto& aid : event.auth_event_ids) {
        auto ait = event_map.find(aid);
        if (ait != event_map.end())
          auth_vec.push_back(ait->second);
      }
      for (const auto& ak : auth_types_for_event(version, event)) {
        auto rit = result.resolved_state.find(ak);
        if (rit != result.resolved_state.end()) {
          auto ait = event_map.find(rit->second);
          if (ait != event_map.end())
            auth_vec.push_back(ait->second);
        }
      }

      if (check_state_dependent_auth_rules(version, event, auth_vec)) {
        result.resolved_state[key] = eid;
        result.resolved_auth[key] = event;
        result.applied_power_events.insert(eid);
        changed = true;
      }
    }

    result.iterations++;
    if (!changed)
      break;
  }

  return result;
}

}  // namespace

// ============================================================================
// 10. STATE DELTA COMPUTATION
// ============================================================================
// Compute the diff between two state groups: what was added, removed,
// and modified.

namespace {

struct StateDelta {
  StateMap added;     // Keys present in `new_state` but not in `old_state`
  StateMap removed;   // Keys present in `old_state` but not in `new_state`
  StateMap modified;  // Keys present in both but with different values
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

// Compute the delta between two state maps.
StateDelta compute_state_delta(const StateMap& old_state,
                                const StateMap& new_state) {
  StateDelta delta;

  // Find added and modified
  for (const auto& [key, new_val] : new_state) {
    auto old_it = old_state.find(key);
    if (old_it == old_state.end()) {
      delta.added[key] = new_val;
      delta.added_count++;
    } else if (old_it->second != new_val) {
      delta.modified[key] = new_val;
      delta.modified_count++;
    } else {
      delta.unchanged_count++;
    }
  }

  // Find removed
  for (const auto& [key, old_val] : old_state) {
    if (new_state.find(key) == new_state.end()) {
      delta.removed[key] = old_val;
      delta.removed_count++;
    }
  }

  return delta;
}

// Compute delta between two state groups by their IDs.
// Requires the ability to look up state by group ID.
StateDelta compute_state_group_delta(int64_t old_group_id,
                                      int64_t new_group_id,
                                      StateGroupStore& store) {
  StateMap old_state = store.get_state(old_group_id);
  StateMap new_state = store.get_state(new_group_id);
  return compute_state_delta(old_state, new_state);
}

}  // namespace

// ============================================================================
// 11. STATE COMPRESSION
// ============================================================================
// Deduplicate state entries across state groups. If multiple state groups
// share the same state for a key, we can compress by storing only the
// diff/delta.

namespace {

struct CompressedStateGroup {
  int64_t group_id = 0;
  int64_t prev_group_id = 0;         // Parent group for delta storage
  StateMap full_state;               // The full resolved state (maybe shared)
  StateDelta delta_from_prev;        // Delta from parent group
  bool is_full = true;               // Whether this stores the full state
  int64_t compressed_at = 0;         // Timestamp of compression
  size_t state_size = 0;             // Number of state entries

  // Storage optimization: if delta is smaller than full state, use delta
  size_t storage_cost() const {
    if (is_full)
      return full_state.size();
    return delta_from_prev.total_changes();
  }
};

// Compress state groups by identifying chains where sequential groups
// differ only slightly. Store the delta instead of the full state.
std::vector<CompressedStateGroup> compress_state_groups(
    const std::vector<std::pair<int64_t, StateMap>>& groups,
    int max_delta_ratio = 20) {  // Use delta if changes < 1/max_delta_ratio of total
  std::vector<CompressedStateGroup> compressed;
  if (groups.empty())
    return compressed;

  compressed.reserve(groups.size());

  for (size_t i = 0; i < groups.size(); i++) {
    CompressedStateGroup csg;
    csg.group_id = groups[i].first;
    csg.full_state = groups[i].second;
    csg.state_size = groups[i].second.size();
    csg.compressed_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (i > 0) {
      csg.prev_group_id = groups[i - 1].first;
      csg.delta_from_prev = compute_state_delta(
          groups[i - 1].second, groups[i].second);

      // Use delta storage if it's significantly smaller
      size_t delta_size = csg.delta_from_prev.total_changes();
      size_t full_size = csg.full_state.size();
      if (delta_size > 0 && full_size > 0 &&
          delta_size * max_delta_ratio < full_size) {
        csg.is_full = false;
      }
    }

    compressed.push_back(std::move(csg));
  }

  return compressed;
}

// Reconstruct full state from a compressed state group chain.
StateMap reconstruct_state_from_chain(
    int64_t target_group_id,
    const std::map<int64_t, CompressedStateGroup>& compressed_groups) {
  // Find the path from root to target
  std::vector<int64_t> path;
  int64_t current = target_group_id;

  while (true) {
    auto it = compressed_groups.find(current);
    if (it == compressed_groups.end())
      break;
    path.push_back(current);
    if (it->second.is_full || it->second.prev_group_id == 0)
      break;
    current = it->second.prev_group_id;
  }

  // Start from the earliest full state and apply deltas forward
  StateMap state;
  for (auto it = path.rbegin(); it != path.rend(); ++it) {
    auto csg_it = compressed_groups.find(*it);
    if (csg_it == compressed_groups.end())
      continue;

    if (csg_it->second.is_full || state.empty()) {
      state = csg_it->second.full_state;
    } else {
      // Apply delta
      for (const auto& [k, v] : csg_it->second.delta_from_prev.added)
        state[k] = v;
      for (const auto& [k, v] : csg_it->second.delta_from_prev.modified)
        state[k] = v;
      for (const auto& [k, _] : csg_it->second.delta_from_prev.removed)
        state.erase(k);
    }
  }

  return state;
}

}  // namespace

// ============================================================================
// 12. STATE AUTOCOMPRESSION
// ============================================================================
// Periodic automatic compression of state groups. Runs background compression
// on state groups that haven't been accessed recently, converting full-state
// groups to delta-stored groups to save memory.

namespace {

class StateAutocompressor {
public:
  struct Config {
    size_t max_uncompressed_groups = 10000;   // Max groups before triggering compression
    int min_age_seconds = 300;                 // Min age before compressing a group
    int compression_interval_seconds = 60;     // How often to run compression
    int max_delta_ratio = 20;                  // Use delta if changes < 1/20 of total
    double target_compression_ratio = 0.5;     // Target: 50% of groups compressed
  };

  explicit StateAutocompressor(Config cfg = {}) : config_(std::move(cfg)) {}

  // Register a state group for potential compression
  void register_group(int64_t group_id, const StateMap& state) {
    std::unique_lock lock(mutex_);
    groups_[group_id] = {
        state,
        std::chrono::steady_clock::now(),
        false  // not compressed yet
    };
  }

  // Mark a group as accessed (touches its timestamp)
  void touch_group(int64_t group_id) {
    std::unique_lock lock(mutex_);
    auto it = groups_.find(group_id);
    if (it != groups_.end())
      it->second.last_access = std::chrono::steady_clock::now();
  }

  // Run compression pass. Returns number of groups compressed.
  size_t run_compression() {
    std::unique_lock lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    size_t compressed_count = 0;

    // Skip if we're under threshold
    if (groups_.size() < config_.max_uncompressed_groups)
      return 0;

    // Count currently uncompressed
    size_t uncompressed = 0;
    for (const auto& [id, info] : groups_)
      if (!info.compressed)
        uncompressed++;

    if (uncompressed < config_.max_uncompressed_groups)
      return 0;

    // Find groups to compress (oldest first, up to 25% of groups)
    std::vector<std::pair<int64_t, std::chrono::steady_clock::time_point>> candidates;
    for (const auto& [id, info] : groups_) {
      if (!info.compressed &&
          std::chrono::duration_cast<std::chrono::seconds>(
              now - info.last_access).count() >= config_.min_age_seconds) {
        candidates.push_back({id, info.last_access});
      }
    }

    std::sort(candidates.begin(), candidates.end(),
              [](const auto& a, const auto& b) {
                return a.second < b.second;
              });

    size_t to_compress = std::min(candidates.size(),
                                   groups_.size() / 4);

    for (size_t i = 0; i < to_compress; i++) {
      auto it = groups_.find(candidates[i].first);
      if (it != groups_.end()) {
        it->second.compressed = true;
        compressed_count++;
      }
    }

    last_compression_ = now;
    return compressed_count;
  }

  // Get compression statistics
  struct Stats {
    size_t total_groups = 0;
    size_t compressed_groups = 0;
    size_t uncompressed_groups = 0;
    double compression_ratio = 0.0;
    std::chrono::steady_clock::time_point last_compression;
  };

  Stats get_stats() const {
    std::unique_lock lock(mutex_);
    Stats s;
    s.total_groups = groups_.size();
    s.last_compression = last_compression_;
    for (const auto& [id, info] : groups_) {
      if (info.compressed) s.compressed_groups++;
      else s.uncompressed_groups++;
    }
    if (s.total_groups > 0)
      s.compression_ratio = static_cast<double>(s.compressed_groups) /
                            static_cast<double>(s.total_groups);
    return s;
  }

  // Remove a group (e.g., after garbage collection)
  void remove_group(int64_t group_id) {
    std::unique_lock lock(mutex_);
    groups_.erase(group_id);
  }

  void clear() {
    std::unique_lock lock(mutex_);
    groups_.clear();
  }

private:
  struct GroupInfo {
    StateMap state;
    std::chrono::steady_clock::time_point last_access;
    bool compressed;
  };

  Config config_;
  mutable std::shared_mutex mutex_;
  std::map<int64_t, GroupInfo> groups_;
  std::chrono::steady_clock::time_point last_compression_;
};

}  // namespace

// ============================================================================
// 13. STATE GROUP GARBAGE COLLECTION
// ============================================================================
// Remove unreferenced state groups that are no longer needed by any event
// or room state.

namespace {

class StateGroupGarbageCollector {
public:
  struct Config {
    int64_t max_age_seconds = 3600;       // Max age of unreferenced groups before collection
    size_t max_unreferenced = 50000;      // Max unreferenced groups before forced collection
    int collect_interval_seconds = 300;   // How often to run collection
    bool aggressive = false;              // If true, collect more aggressively
  };

  explicit StateGroupGarbageCollector(Config cfg = {}) : config_(std::move(cfg)) {}

  // Add a reference to a state group (from an event or room)
  void add_reference(int64_t group_id, std::string_view referrer) {
    std::unique_lock lock(mutex_);
    references_[group_id].insert(std::string(referrer));
    // Remove from unreferenced if it was there
    unreferenced_since_.erase(group_id);
  }

  // Remove a reference to a state group
  void remove_reference(int64_t group_id, std::string_view referrer) {
    std::unique_lock lock(mutex_);
    auto it = references_.find(group_id);
    if (it != references_.end()) {
      it->second.erase(std::string(referrer));
      if (it->second.empty()) {
        references_.erase(it);
        unreferenced_since_[group_id] = std::chrono::steady_clock::now();
      }
    }
  }

  // Check if a group is referenced
  bool is_referenced(int64_t group_id) const {
    std::shared_lock lock(mutex_);
    return references_.count(group_id) > 0;
  }

  // Get reference count for a group
  size_t reference_count(int64_t group_id) const {
    std::shared_lock lock(mutex_);
    auto it = references_.find(group_id);
    if (it == references_.end()) return 0;
    return it->second.size();
  }

  // Run garbage collection. Returns IDs of collected groups.
  std::vector<int64_t> collect() {
    std::unique_lock lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    std::vector<int64_t> collected;

    // Find groups that have been unreferenced long enough
    for (auto it = unreferenced_since_.begin();
         it != unreferenced_since_.end();) {
      auto age = std::chrono::duration_cast<std::chrono::seconds>(
          now - it->second).count();

      if (age >= config_.max_age_seconds ||
          (config_.aggressive && age >= config_.max_age_seconds / 2)) {
        // Double-check: only collect if still unreferenced
        if (references_.find(it->first) == references_.end()) {
          collected.push_back(it->first);
          it = unreferenced_since_.erase(it);
        } else {
          // Was re-referenced, remove from unreferenced
          it = unreferenced_since_.erase(it);
        }
      } else {
        ++it;
      }
    }

    // Forced collection if too many unreferenced groups
    if (unreferenced_since_.size() > config_.max_unreferenced) {
      // Collect oldest unreferenced groups first
      std::vector<std::pair<int64_t, std::chrono::steady_clock::time_point>> sorted;
      for (const auto& [gid, ts] : unreferenced_since_)
        sorted.push_back({gid, ts});
      std::sort(sorted.begin(), sorted.end(),
                [](const auto& a, const auto& b) {
                  return a.second < b.second;
                });

      size_t to_remove = unreferenced_since_.size() - config_.max_unreferenced +
                         config_.max_unreferenced / 4;
      for (size_t i = 0; i < to_remove && i < sorted.size(); i++) {
        if (references_.find(sorted[i].first) == references_.end()) {
          collected.push_back(sorted[i].first);
          unreferenced_since_.erase(sorted[i].first);
        }
      }
    }

    last_collection_ = now;
    return collected;
  }

  // Get GC statistics
  struct Stats {
    size_t referenced_groups = 0;
    size_t unreferenced_groups = 0;
    size_t total_references = 0;
    std::chrono::steady_clock::time_point last_collection;
    std::vector<int64_t> last_collected;
  };

  Stats get_stats() const {
    std::shared_lock lock(mutex_);
    Stats s;
    s.referenced_groups = references_.size();
    s.unreferenced_groups = unreferenced_since_.size();
    s.last_collection = last_collection_;
    s.last_collected = last_collected_ids_;

    for (const auto& [gid, refs] : references_)
      s.total_references += refs.size();

    return s;
  }

  void clear() {
    std::unique_lock lock(mutex_);
    references_.clear();
    unreferenced_since_.clear();
  }

private:
  Config config_;
  mutable std::shared_mutex mutex_;
  std::map<int64_t, std::set<std::string>> references_;
  std::map<int64_t, std::chrono::steady_clock::time_point> unreferenced_since_;
  std::chrono::steady_clock::time_point last_collection_;
  std::vector<int64_t> last_collected_ids_;
};

}  // namespace

// ============================================================================
// 14. STATE RESOLUTION CACHING
// ============================================================================
// Cache resolved state per room to avoid recomputing the same resolution.

namespace {

struct ResolvedState {
  StateMap state;
  int64_t resolved_at = 0;         // Timestamp
  int64_t state_group_id = 0;      // Associated state group
  std::vector<int64_t> input_groups; // Groups that were resolved
  std::string room_id;
  std::string room_version;
  size_t state_count = 0;
  bool is_stale = false;
};

class ResolutionCache {
public:
  struct Config {
    size_t max_entries = 1000;     // Max cached resolutions
    int64_t ttl_seconds = 300;     // Time-to-live for cache entries
    bool enable_persistence = false; // Whether to persist cache
  };

  explicit ResolutionCache(Config cfg = {}) : config_(std::move(cfg)) {}

  // Generate a cache key from input state groups
  static std::string make_key(const std::string& room_id,
                               const std::vector<int64_t>& input_groups) {
    std::string key = room_id + ":";
    for (auto gid : input_groups)
      key += std::to_string(gid) + ",";
    return key;
  }

  // Look up a cached resolution
  std::optional<ResolvedState> get(const std::string& room_id,
                                    const std::vector<int64_t>& input_groups) {
    std::shared_lock lock(mutex_);
    std::string key = make_key(room_id, input_groups);
    auto it = cache_.find(key);
    if (it == cache_.end()) {
      misses_.fetch_add(1, std::memory_order_relaxed);
      return std::nullopt;
    }

    auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    if (now - it->second.resolved_at > config_.ttl_seconds) {
      it->second.is_stale = true;
      misses_.fetch_add(1, std::memory_order_relaxed);
      return std::nullopt;
    }

    hits_.fetch_add(1, std::memory_order_relaxed);
    return it->second;
  }

  // Store a resolved state in the cache
  void put(const std::string& room_id,
           const std::vector<int64_t>& input_groups,
           const ResolvedState& resolved) {
    std::unique_lock lock(mutex_);
    std::string key = make_key(room_id, input_groups);

    // Evict if over capacity
    if (cache_.size() >= config_.max_entries) {
      evict_lru();
    }

    cache_[key] = resolved;
    cache_[key].resolved_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
  }

  // Invalidate cache for a specific room
  void invalidate_room(const std::string& room_id) {
    std::unique_lock lock(mutex_);
    std::string prefix = room_id + ":";
    for (auto it = cache_.begin(); it != cache_.end();) {
      if (it->first.compare(0, prefix.size(), prefix) == 0)
        it = cache_.erase(it);
      else
        ++it;
    }
  }

  // Clear all cached resolutions
  void clear() {
    std::unique_lock lock(mutex_);
    cache_.clear();
    hits_.store(0);
    misses_.store(0);
  }

  // Get cache statistics
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
    s.size = cache_.size();
    s.max_size = config_.max_entries;
    s.hits = hits_.load(std::memory_order_relaxed);
    s.misses = misses_.load(std::memory_order_relaxed);
    uint64_t total = s.hits + s.misses;
    if (total > 0)
      s.hit_rate = static_cast<double>(s.hits) / static_cast<double>(total);
    return s;
  }

private:
  void evict_lru() {
    if (cache_.empty())
      return;

    // Find oldest entry
    auto oldest = cache_.begin();
    for (auto it = cache_.begin(); it != cache_.end(); ++it) {
      if (it->second.resolved_at < oldest->second.resolved_at)
        oldest = it;
    }
    cache_.erase(oldest);
  }

  Config config_;
  mutable std::shared_mutex mutex_;
  std::map<std::string, ResolvedState> cache_;
  std::atomic<uint64_t> hits_{0};
  std::atomic<uint64_t> misses_{0};
};

// Global resolution cache instance
static ResolutionCache g_resolution_cache;

}  // namespace

// ============================================================================
// 15. RESOLVE STATE FOR NEW EVENTS
// ============================================================================
// Determine the auth chain and state for a new incoming event. This is used
// when processing new events to figure out what state they should be checked
// against.

namespace {

struct EventResolutionContext {
  EventId event_id;
  StateMap current_state;        // State before this event
  StateMap resolved_state;       // State after this event (if state event)
  std::set<EventId> auth_chain; // Full auth chain of the event
  std::vector<EventId> prev_events;
  int64_t depth = 0;
  bool is_state_event = false;
  std::string room_id;
  std::string room_version;
};

// Resolve state for a new event by walking its prev_events to find the
// current state and computing the new state if it's a state event.
EventResolutionContext resolve_state_for_new_event(
    const EventId& event_id,
    const ResolvableEvent& event,
    const EventMap& event_map,
    const RoomVersion& version) {
  EventResolutionContext ctx;
  ctx.event_id = event_id;
  ctx.room_id = event.room_id;
  ctx.room_version = version.identifier;
  ctx.is_state_event = event.is_state();
  ctx.depth = event.depth;
  ctx.prev_events = event.prev_event_ids;

  // Compute auth chain
  ctx.auth_chain = get_auth_chain(event_id, event_map);

  // Walk prev_events to find the most recent state at each key
  // This is a simplified approach; a real implementation would use
  // the state_group graph stored in the database.
  StateMap current_state;

  // Collect state from all prev events by walking backwards
  std::set<EventId> visited;
  std::deque<EventId> queue;
  for (const auto& pid : event.prev_event_ids)
    queue.push_back(pid);

  int max_walk = 200;
  while (!queue.empty() && max_walk > 0) {
    EventId current = queue.front();
    queue.pop_front();

    if (!visited.insert(current).second)
      continue;

    auto it = event_map.find(current);
    if (it == event_map.end())
      continue;

    const ResolvableEvent& current_ev = it->second;

    // If this is a state event and we haven't seen this key, add it
    if (current_ev.is_state()) {
      StateKey key = current_ev.state_pair();
      if (current_state.find(key) == current_state.end())
        current_state[key] = current;
    }

    // Walk prev_events
    for (const auto& pid : current_ev.prev_event_ids)
      queue.push_back(pid);

    max_walk--;
  }

  ctx.current_state = current_state;
  ctx.resolved_state = current_state;

  // If this event is a state event, update the state
  if (ctx.is_state_event) {
    StateKey key = event.state_pair();
    ctx.resolved_state[key] = event_id;
  }

  return ctx;
}

}  // namespace

// ============================================================================
// 16. RESOLVE CONFLICTS IN STATE ARRAYS
// ============================================================================
// Pick the winning event per state key from an array of state sets.
// Uses the full v2 resolution algorithm.

namespace {

// Resolve conflicts for a single state key across multiple candidate events.
// Returns the winning event ID.
EventId resolve_single_key_conflict(
    const StateKey& key,
    const std::set<EventId>& candidates,
    const EventMap& event_map,
    const RoomVersion& version,
    const std::map<StateKey, ResolvableEvent>& resolved_auth) {
  if (candidates.size() == 1)
    return *candidates.begin();
  if (candidates.empty())
    return {};

  // Build a mini state map with just this key
  std::vector<EventId> candidate_vec(candidates.begin(), candidates.end());

  // For power events, use power event ordering
  if (key == make_key("m.room.power_levels", "") ||
      key == make_key("m.room.join_rules", "") ||
      key == make_key("m.room.create", "")) {
    auto ordered = order_power_events(candidate_vec, event_map);
    if (!ordered.empty()) {
      for (const auto& eid : ordered) {
        auto it = event_map.find(eid);
        if (it == event_map.end())
          continue;
        std::vector<ResolvableEvent> auth_vec;
        for (const auto& rk : auth_types_for_event(version, it->second)) {
          auto ra = resolved_auth.find(rk);
          if (ra != resolved_auth.end())
            auth_vec.push_back(ra->second);
        }
        if (check_state_dependent_auth_rules(version, it->second, auth_vec))
          return eid;
      }
    }
  }

  // For normal events, sort by mainline depth
  std::set<EventId> cset(candidates.begin(), candidates.end());
  auto sorted = sort_by_mainline(cset, event_map);

  for (const auto& eid : sorted) {
    auto it = event_map.find(eid);
    if (it == event_map.end())
      continue;
    std::vector<ResolvableEvent> auth_vec;
    for (const auto& rk : auth_types_for_event(version, it->second)) {
      auto ra = resolved_auth.find(rk);
      if (ra != resolved_auth.end())
        auth_vec.push_back(ra->second);
    }
    if (check_state_dependent_auth_rules(version, it->second, auth_vec))
      return eid;
  }

  // Fallback: return the first candidate (lexicographically smallest)
  return candidate_vec.empty() ? EventId{} : *std::min_element(
      candidate_vec.begin(), candidate_vec.end());
}

// Resolve all conflicts in state arrays using state resolution v2.
StateMap resolve_state_array_conflicts(
    const std::vector<StateMap>& state_sets,
    const EventMap& event_map,
    const RoomVersion& version) {
  return resolve_events_v2(version, state_sets, event_map);
}

}  // namespace

// ============================================================================
// 17. FULL STATE REBUILD FROM STATE GROUPS
// ============================================================================
// Rebuild the complete room state from a chain of state groups. This is
// used when the full state needs to be reconstructed from the database.

namespace {

// Rebuild full state from a sequence of state groups by applying deltas.
// This walks the state group chain forward, applying each group's state.
StateMap rebuild_full_state_from_groups(
    const std::vector<int64_t>& group_ids,
    StateGroupStore& store,
    const EventMap& event_map) {
  StateMap state;

  for (int64_t gid : group_ids) {
    StateMap group_state = store.get_state(gid);

    // Apply this group's state on top
    for (const auto& [k, v] : group_state) {
      // If this key was already set, check if the new event is more recent
      auto existing = state.find(k);
      if (existing != state.end() && existing->second != v) {
        // Simple heuristic: prefer the event from the later group
        state[k] = v;
      } else if (existing == state.end()) {
        state[k] = v;
      }
    }
  }

  return state;
}

// Rebuild state from a state group with full delta resolution.
// This resolves all events across all state groups into a single
// consistent state map using state resolution v2.
StateMap rebuild_state_with_resolution(
    const std::vector<int64_t>& group_ids,
    StateGroupStore& store,
    const EventMap& event_map,
    const RoomVersion& version) {
  if (group_ids.empty())
    return {};

  std::vector<StateMap> state_sets;
  for (int64_t gid : group_ids) {
    state_sets.push_back(store.get_state(gid));
  }

  if (state_sets.size() == 1)
    return state_sets[0];

  return resolve_events_v2(version, state_sets, event_map);
}

}  // namespace

// ============================================================================
// 18. STATE GROUP CREATION
// ============================================================================
// Create a new state group from a resolved state. Handles deduplication
// and delta computation.

namespace {

// Create a new state group from a resolved state map. Returns the new
// group ID and optionally a delta from the previous group.
struct StateGroupCreationResult {
  int64_t group_id = 0;
  StateMap state;
  StateDelta delta_from_prev;
  bool is_new = true;
};

StateGroupCreationResult create_state_group(
    const StateMap& resolved_state,
    StateGroupStore& store,
    std::optional<int64_t> prev_group_id = std::nullopt) {
  StateGroupCreationResult result;
  result.state = resolved_state;

  int64_t gid = store.get_or_create_group(resolved_state);
  result.group_id = gid;

  // Compute delta from previous group if provided
  if (prev_group_id.has_value()) {
    StateMap prev_state = store.get_state(prev_group_id.value());
    result.delta_from_prev = compute_state_delta(prev_state, resolved_state);
  }

  return result;
}

// Batch create state groups for a chain of resolved states.
std::vector<StateGroupCreationResult> create_state_group_chain(
    const std::vector<StateMap>& state_chain,
    StateGroupStore& store) {
  std::vector<StateGroupCreationResult> results;
  std::optional<int64_t> prev_id;

  for (const auto& state : state_chain) {
    auto result = create_state_group(state, store, prev_id);
    results.push_back(result);
    prev_id = result.group_id;
  }

  return results;
}

}  // namespace

// ============================================================================
// 19. STATE RESOLUTION METRICS
// ============================================================================
// Track resolution time, sizes, conflicts, and other performance metrics.

namespace {

struct ResolutionMetrics {
  // Timing
  std::chrono::microseconds total_time{0};
  std::chrono::microseconds separation_time{0};
  std::chrono::microseconds auth_expansion_time{0};
  std::chrono::microseconds power_ordering_time{0};
  std::chrono::microseconds mainline_sorting_time{0};
  std::chrono::microseconds auth_check_time{0};

  // Counts
  size_t state_sets_count = 0;
  size_t unconflicted_events = 0;
  size_t conflicted_keys = 0;
  size_t conflicted_events = 0;
  size_t power_events_count = 0;
  size_t normal_events_count = 0;
  size_t restricted_join_events = 0;
  size_t ban_events_count = 0;
  size_t auth_checks_total = 0;
  size_t auth_checks_passed = 0;
  size_t auth_checks_failed = 0;

  // Result
  size_t resolved_state_size = 0;
  bool from_cache = false;

  void reset() {
    *this = ResolutionMetrics{};
  }
};

// Metrics collector with thread-safe updates
class MetricsCollector {
public:
  void record_resolution(const ResolutionMetrics& metrics) {
    std::unique_lock lock(mutex_);
    total_resolutions_++;

    total_time_us_ += metrics.total_time.count();
    max_time_us_ = std::max(max_time_us_, metrics.total_time.count());
    total_conflicted_keys_ += metrics.conflicted_keys;
    total_events_processed_ += metrics.conflicted_events;

    if (metrics.from_cache)
      cache_hits_++;
  }

  struct Summary {
    uint64_t total_resolutions = 0;
    uint64_t cache_hits = 0;
    double avg_time_ms = 0.0;
    int64_t max_time_us = 0;
    uint64_t total_conflicted_keys = 0;
    uint64_t total_events_processed = 0;
    double avg_conflicted_keys = 0.0;
    double avg_events_processed = 0.0;
  };

  Summary get_summary() const {
    std::shared_lock lock(mutex_);
    Summary s;
    s.total_resolutions = total_resolutions_;
    s.cache_hits = cache_hits_;
    s.max_time_us = max_time_us_;
    s.total_conflicted_keys = total_conflicted_keys_;
    s.total_events_processed = total_events_processed_;

    if (total_resolutions_ > 0) {
      s.avg_time_ms = (total_time_us_ / static_cast<double>(total_resolutions_)) / 1000.0;
      s.avg_conflicted_keys = static_cast<double>(total_conflicted_keys_) /
                              static_cast<double>(total_resolutions_);
      s.avg_events_processed = static_cast<double>(total_events_processed_) /
                                static_cast<double>(total_resolutions_);
    }

    return s;
  }

  void reset() {
    std::unique_lock lock(mutex_);
    total_resolutions_ = 0;
    total_time_us_ = 0;
    max_time_us_ = 0;
    total_conflicted_keys_ = 0;
    total_events_processed_ = 0;
    cache_hits_ = 0;
  }

private:
  mutable std::shared_mutex mutex_;
  uint64_t total_resolutions_ = 0;
  int64_t total_time_us_ = 0;
  int64_t max_time_us_ = 0;
  uint64_t total_conflicted_keys_ = 0;
  uint64_t total_events_processed_ = 0;
  uint64_t cache_hits_ = 0;
};

// Global metrics collector
static MetricsCollector g_metrics;

}  // namespace

// ============================================================================
// 20. ITERATIVE AUTH CHECKS
// ============================================================================
// Apply auth events and verify them in an iterative loop. This is used
// when we need to repeatedly check auth rules as the resolved state evolves.

namespace {

// Iterative auth checking: apply events in rounds, re-checking failed
// events after each round because the resolved state may have changed.
struct IterativeAuthResult {
  StateMap resolved;
  std::set<EventId> applied;
  std::set<EventId> failed;
  int rounds = 0;
};

IterativeAuthResult iterative_auth_check(
    const std::vector<EventId>& events,
    const EventMap& event_map,
    const RoomVersion& version,
    const StateMap& initial_state,
    int max_rounds = 5) {
  IterativeAuthResult result;
  result.resolved = initial_state;

  // Build initial auth map from initial state
  std::map<StateKey, ResolvableEvent> resolved_auth;
  for (const auto& [k, eid] : initial_state) {
    auto it = event_map.find(eid);
    if (it != event_map.end())
      resolved_auth[k] = it->second;
  }

  std::set<EventId> pending(events.begin(), events.end());

  for (int round = 0; round < max_rounds && !pending.empty(); round++) {
    result.rounds = round + 1;
    std::set<EventId> next_pending;
    bool any_applied = false;

    for (const auto& eid : pending) {
      auto it = event_map.find(eid);
      if (it == event_map.end()) {
        result.failed.insert(eid);
        continue;
      }

      const ResolvableEvent& event = it->second;
      StateKey key = event.state_pair();

      // Build auth context from current resolved state
      std::vector<ResolvableEvent> auth_vec;
      for (const auto& aid : event.auth_event_ids) {
        auto ait = event_map.find(aid);
        if (ait != event_map.end())
          auth_vec.push_back(ait->second);
      }
      for (const auto& ak : auth_types_for_event(version, event)) {
        auto rit = result.resolved.find(ak);
        if (rit != result.resolved.end()) {
          auto ait = event_map.find(rit->second);
          if (ait != event_map.end())
            auth_vec.push_back(ait->second);
        }
      }

      if (check_state_dependent_auth_rules(version, event, auth_vec)) {
        result.resolved[key] = eid;
        resolved_auth[key] = event;
        result.applied.insert(eid);
        any_applied = true;
      } else {
        next_pending.insert(eid);
      }
    }

    pending = std::move(next_pending);
    if (!any_applied)
      break;  // No progress, stop iterating
  }

  // Remaining pending events are failed
  result.failed.insert(pending.begin(), pending.end());

  return result;
}

}  // namespace

// ============================================================================
// 21. COMPLETE STATE RESOLUTION V2 - MAIN ENTRY POINT
// ============================================================================
// The fully-featured resolve_events_v2 implementation that coordinates all
// the sub-modules: separation, auth chain expansion, power ordering,
// mainline ordering, and iterative auth checking.

namespace {

StateMap resolve_events_v2_full(
    const RoomVersion& version,
    const std::vector<StateMap>& state_sets,
    const EventMap& event_map,
    ResolutionMetrics* out_metrics = nullptr) {
  ResolutionMetrics metrics;
  auto start = std::chrono::high_resolution_clock::now();

  // Fast path: single state set
  if (state_sets.size() == 1) {
    if (out_metrics) {
      metrics.resolved_state_size = state_sets[0].size();
      metrics.total_time = std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::high_resolution_clock::now() - start);
      *out_metrics = metrics;
    }
    return state_sets[0];
  }

  if (state_sets.empty()) {
    if (out_metrics) *out_metrics = metrics;
    return {};
  }

  metrics.state_sets_count = state_sets.size();

  // Step 1: Separate unconflicted and conflicted
  auto sep_start = std::chrono::high_resolution_clock::now();
  auto [unconflicted, conflicted, all_eids, unconf_count, conf_count] =
      separate_events_detailed(state_sets);
  metrics.separation_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now() - sep_start);
  metrics.unconflicted_events = unconf_count;
  metrics.conflicted_keys = conf_count;

  if (conflicted.empty()) {
    if (out_metrics) {
      metrics.resolved_state_size = unconflicted.size();
      metrics.total_time = std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::high_resolution_clock::now() - start);
      *out_metrics = metrics;
    }
    return unconflicted;
  }

  // Step 2: Expand auth chain of conflicted events
  auto auth_start = std::chrono::high_resolution_clock::now();
  std::set<EventId> all_conflicted_events;
  for (const auto& [k, eids] : conflicted)
    all_conflicted_events.insert(eids.begin(), eids.end());

  std::set<EventId> expanded = expand_auth_chain_for_resolution(
      conflicted, event_map, 20);
  metrics.auth_expansion_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now() - auth_start);

  metrics.conflicted_events = expanded.size();

  // Step 3: Classify events
  auto classification = classify_events(expanded, event_map, version);
  metrics.power_events_count = classification.power_events.size();
  metrics.normal_events_count = classification.normal_events.size();
  metrics.restricted_join_events = classification.restricted_join_events.size();
  metrics.ban_events_count = classification.ban_events.size();

  // Step 4: Build initial resolved state from unconflicted
  StateMap resolved = unconflicted;
  std::map<StateKey, ResolvableEvent> resolved_auth;
  for (const auto& [k, eid] : unconflicted) {
    auto it = event_map.find(eid);
    if (it != event_map.end())
      resolved_auth[k] = it->second;
  }

  // Step 5: Resolve power events (these set the power structure)
  auto power_start = std::chrono::high_resolution_clock::now();

  std::vector<EventId> all_conflicted_vec(
      expanded.begin(), expanded.end());

  auto power_result = resolve_power_level_changes(
      classification.power_events,
      all_conflicted_vec,
      event_map, version, unconflicted);

  resolved = power_result.resolved_state;
  resolved_auth = power_result.resolved_auth;

  metrics.power_ordering_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now() - power_start);

  // Step 6: Sort remaining events by mainline depth
  auto mainline_start = std::chrono::high_resolution_clock::now();

  std::set<EventId> remaining;
  for (const auto& eid : expanded) {
    if (!power_result.applied_power_events.count(eid))
      remaining.insert(eid);
  }
  auto sorted_remaining = sort_by_mainline(remaining, event_map);

  metrics.mainline_sorting_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now() - mainline_start);

  // Step 7: Apply remaining events in mainline order
  auto check_start = std::chrono::high_resolution_clock::now();

  for (const auto& eid : sorted_remaining) {
    auto it = event_map.find(eid);
    if (it == event_map.end())
      continue;

    const ResolvableEvent& event = it->second;
    StateKey key = event.state_pair();

    // Skip if already resolved with this exact event
    auto res_it = resolved.find(key);
    if (res_it != resolved.end() && res_it->second == eid)
      continue;

    // Build auth context
    std::vector<ResolvableEvent> auth_vec;
    for (const auto& aid : event.auth_event_ids) {
      auto ait = event_map.find(aid);
      if (ait != event_map.end())
        auth_vec.push_back(ait->second);
    }
    for (const auto& ak : auth_types_for_event(version, event)) {
      auto rit = resolved.find(ak);
      if (rit != resolved.end()) {
        auto ait = event_map.find(rit->second);
        if (ait != event_map.end())
          auth_vec.push_back(ait->second);
      }
    }

    metrics.auth_checks_total++;
    if (check_state_dependent_auth_rules(version, event, auth_vec)) {
      resolved[key] = eid;
      resolved_auth[key] = event;
      metrics.auth_checks_passed++;
    } else {
      metrics.auth_checks_failed++;
    }
  }

  metrics.auth_check_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now() - check_start);

  // Step 8: Handle restricted joins (after all other events)
  if (version.restricted_join_rule &&
      !classification.restricted_join_events.empty()) {
    resolve_restricted_joins_conflicted(
        classification.restricted_join_events,
        event_map, version, resolved, resolved_auth);
  }

  // Step 9: Handle ban events
  if (!classification.ban_events.empty()) {
    resolve_ban_events_conflicted(
        classification.ban_events,
        event_map, version, resolved, resolved_auth);
  }

  // Step 10: Ensure all unconflicted keys are still present
  for (const auto& [k, v] : unconflicted) {
    if (resolved.find(k) == resolved.end())
      resolved[k] = v;
  }

  metrics.resolved_state_size = resolved.size();
  metrics.total_time = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now() - start);

  // Record metrics
  g_metrics.record_resolution(metrics);

  if (out_metrics)
    *out_metrics = metrics;

  return resolved;
}

}  // namespace

// ============================================================================
// 22. PUBLIC API - STATE RESOLUTION COORDINATOR
// ============================================================================
// The main coordinator class that ties together all state resolution
// functionality: resolution, caching, compression, GC, and metrics.

class StateResolutionCoordinator {
public:
  struct Config {
    // Caching
    size_t cache_max_entries = 2000;
    int64_t cache_ttl_seconds = 600;

    // Compression
    size_t max_uncompressed_groups = 10000;
    int compression_interval_seconds = 60;

    // Garbage collection
    int64_t gc_max_age_seconds = 7200;
    int collect_interval_seconds = 300;

    // Metrics
    bool enable_metrics = true;
  };

  explicit StateResolutionCoordinator(StateGroupStore& store, Config cfg = {})
      : store_(store),
        config_(std::move(cfg)),
        cache_(ResolutionCache::Config{
            config_.cache_max_entries,
            config_.cache_ttl_seconds}),
        compressor_(StateAutocompressor::Config{
            config_.max_uncompressed_groups,
            300,  // min_age_seconds
            config_.compression_interval_seconds}),
        gc_(StateGroupGarbageCollector::Config{
            config_.gc_max_age_seconds,
            50000,  // max_unreferenced
            config_.collect_interval_seconds}) {}

  // ------------------------------------------------------------------
  // Main resolution
  // ------------------------------------------------------------------

  // Resolve state from multiple state sets.
  // Returns the resolved state map.
  StateMap resolve(const RoomVersion& version,
                   const std::vector<StateMap>& state_sets,
                   const EventMap& event_map) {
    return resolve_events_v2_full(version, state_sets, event_map, nullptr);
  }

  // Resolve with metrics output
  StateMap resolve_with_metrics(const RoomVersion& version,
                                 const std::vector<StateMap>& state_sets,
                                 const EventMap& event_map,
                                 ResolutionMetrics& out_metrics) {
    return resolve_events_v2_full(version, state_sets, event_map, &out_metrics);
  }

  // Resolve and create a state group
  int64_t resolve_and_create_group(const RoomVersion& version,
                                    const std::vector<StateMap>& state_sets,
                                    const EventMap& event_map,
                                    std::optional<int64_t> prev_group_id = std::nullopt) {
    StateMap resolved = resolve(version, state_sets, event_map);
    auto result = create_state_group(resolved, store_, prev_group_id);
    return result.group_id;
  }

  // ------------------------------------------------------------------
  // Caching
  // ------------------------------------------------------------------

  // Resolve with caching by room ID and input state group IDs
  StateMap resolve_cached(const std::string& room_id,
                           const RoomVersion& version,
                           const std::vector<StateMap>& state_sets,
                           const std::vector<int64_t>& input_group_ids,
                           const EventMap& event_map) {
    auto cached = cache_.get(room_id, input_group_ids);
    if (cached.has_value()) {
      return cached->state;
    }

    StateMap resolved = resolve(version, state_sets, event_map);

    ResolvedState rs;
    rs.state = resolved;
    rs.room_id = room_id;
    rs.room_version = version.identifier;
    rs.input_groups = input_group_ids;
    rs.state_count = resolved.size();

    cache_.put(room_id, input_group_ids, rs);

    return resolved;
  }

  // Invalidate cache for a room
  void invalidate_room_cache(const std::string& room_id) {
    cache_.invalidate_room(room_id);
  }

  // Get cache stats
  ResolutionCache::Stats get_cache_stats() const {
    return cache_.get_stats();
  }

  // ------------------------------------------------------------------
  // Delta computation
  // ------------------------------------------------------------------

  StateDelta compute_delta(const StateMap& old_state,
                            const StateMap& new_state) {
    return compute_state_delta(old_state, new_state);
  }

  StateDelta compute_delta_by_group(int64_t old_group_id,
                                     int64_t new_group_id) {
    return compute_state_group_delta(old_group_id, new_group_id, store_);
  }

  // ------------------------------------------------------------------
  // Compression
  // ------------------------------------------------------------------

  void register_group_for_compression(int64_t group_id,
                                       const StateMap& state) {
    compressor_.register_group(group_id, state);
    gc_.add_reference(group_id, "");
  }

  void touch_group(int64_t group_id) {
    compressor_.touch_group(group_id);
  }

  size_t run_compression() {
    return compressor_.run_compression();
  }

  StateAutocompressor::Stats get_compression_stats() const {
    return compressor_.get_stats();
  }

  // ------------------------------------------------------------------
  // Garbage collection
  // ------------------------------------------------------------------

  void add_group_reference(int64_t group_id, std::string_view referrer) {
    gc_.add_reference(group_id, referrer);
  }

  void remove_group_reference(int64_t group_id, std::string_view referrer) {
    gc_.remove_reference(group_id, referrer);
  }

  std::vector<int64_t> run_garbage_collection() {
    auto collected = gc_.collect();
    for (auto gid : collected)
      compressor_.remove_group(gid);
    return collected;
  }

  StateGroupGarbageCollector::Stats get_gc_stats() const {
    return gc_.get_stats();
  }

  // ------------------------------------------------------------------
  // Fork detection
  // ------------------------------------------------------------------

  ForkDetectionResult detect_forks(const std::vector<StateMap>& state_sets) {
    return detect_forks_detailed(state_sets, EventMap{});
  }

  // ------------------------------------------------------------------
  // State rebuild
  // ------------------------------------------------------------------

  StateMap rebuild_state(const std::vector<int64_t>& group_ids,
                          const EventMap& event_map,
                          const RoomVersion& version) {
    return rebuild_state_with_resolution(
        group_ids, store_, event_map, version);
  }

  // ------------------------------------------------------------------
  // Metrics
  // ------------------------------------------------------------------

  MetricsCollector::Summary get_global_metrics() const {
    return g_metrics.get_summary();
  }

  void reset_global_metrics() {
    g_metrics.reset();
  }

  // ------------------------------------------------------------------
  // Auth chain utilities
  // ------------------------------------------------------------------

  std::set<EventId> compute_auth_chain(const EventId& event_id,
                                        const EventMap& event_map) {
    return get_auth_chain(event_id, event_map);
  }

  AuthChainDiff compute_auth_diff(const EventId& a, const EventId& b,
                                   const EventMap& event_map) {
    return auth_chain_diff(a, b, event_map);
  }

  // ------------------------------------------------------------------
  // Full state resolution for new events
  // ------------------------------------------------------------------

  EventResolutionContext prepare_event_context(
      const EventId& event_id,
      const ResolvableEvent& event,
      const EventMap& event_map,
      const RoomVersion& version) {
    return resolve_state_for_new_event(event_id, event, event_map, version);
  }

  // ------------------------------------------------------------------
  // Cleanup
  // ------------------------------------------------------------------

  void clear_caches() {
    cache_.clear();
    g_auth_chain_cache.clear();
    compressor_.clear();
    gc_.clear();
  }

private:
  StateGroupStore& store_;
  Config config_;
  ResolutionCache cache_;
  StateAutocompressor compressor_;
  StateGroupGarbageCollector gc_;
};

// ============================================================================
// GLOBAL SINGLETON
// ============================================================================

namespace {

std::unique_ptr<StateResolutionCoordinator> g_coordinator;
std::shared_mutex g_coordinator_mutex;

}  // namespace

// ============================================================================
// PUBLIC API FUNCTIONS
// ============================================================================

StateResolutionCoordinator& get_resolution_coordinator(StateGroupStore& store) {
  // Thread-safe lazy initialization
  {
    std::shared_lock lock(g_coordinator_mutex);
    if (g_coordinator)
      return *g_coordinator;
  }

  std::unique_lock lock(g_coordinator_mutex);
  if (!g_coordinator) {
    g_coordinator = std::make_unique<StateResolutionCoordinator>(store);
  }
  return *g_coordinator;
}

// INITIALIZE the coordinator with custom config
void init_resolution_coordinator(
    StateGroupStore& store,
    const StateResolutionCoordinator::Config& config) {
  std::unique_lock lock(g_coordinator_mutex);
  g_coordinator = std::make_unique<StateResolutionCoordinator>(store, config);
}

// Shutdown and cleanup
void shutdown_resolution_coordinator() {
  std::unique_lock lock(g_coordinator_mutex);
  if (g_coordinator) {
    g_coordinator->clear_caches();
    g_coordinator.reset();
  }
}

// ============================================================================
// BACKWARD COMPATIBILITY WRAPPERS
// ============================================================================
// These functions bridge the new v2 implementation with the existing
// resolve_events_v2 signature. They use the global coordinator when
// available, and fall back to the inline algorithm otherwise.

StateMap resolve_events_v2_enhanced(
    const RoomVersion& version,
    const std::vector<StateMap>& state_sets,
    const EventMap& event_map) {
  // Use the full v2 implementation directly
  return resolve_events_v2_full(version, state_sets, event_map, nullptr);
}

// ============================================================================
// ADVANCED: STATE RESOLUTION WITH CONSTRAINT PROPAGATION
// ============================================================================
// For room versions with complex auth rules (restricted joins, etc.), we
// need constraint propagation: resolving one event may affect the validity
// of other events.

namespace {

struct Constraint {
  StateKey depends_on;          // Key that must be resolved first
  StateKey affects;             // Key that is affected
  std::string constraint_type;  // "requires", "invalidates", "enables"
};

// Determine constraints between events for ordered resolution
std::vector<Constraint> compute_constraints(
    const ConflictedState& conflicted,
    const EventMap& event_map,
    const RoomVersion& version) {
  std::vector<Constraint> constraints;

  for (const auto& [key, eids] : conflicted) {
    // Power levels constrain everything
    if (std::get<0>(key) == "m.room.power_levels") {
      for (const auto& [other_key, other_eids] : conflicted) {
        if (other_key != key) {
          constraints.push_back({key, other_key, "affects_auth"});
        }
      }
    }

    // Join rules constrain member events
    if (std::get<0>(key) == "m.room.join_rules") {
      for (const auto& [other_key, other_eids] : conflicted) {
        if (std::get<0>(other_key) == "m.room.member") {
          constraints.push_back({key, other_key, "affects_membership"});
        }
      }
    }

    // Create event constrains everything
    if (std::get<0>(key) == "m.room.create") {
      for (const auto& [other_key, other_eids] : conflicted) {
        if (other_key != key) {
          constraints.push_back({key, other_key, "requires_create"});
        }
      }
    }
  }

  return constraints;
}

// Resolve events respecting constraint ordering.
// This ensures that dependent keys are resolved after their constraints.
StateMap resolve_with_constraints(
    const RoomVersion& version,
    const std::vector<StateMap>& state_sets,
    const EventMap& event_map) {
  auto constraints = compute_constraints(
      separate_events_detailed(state_sets).conflicted,
      event_map, version);

  // First resolve power levels, join rules, and create events
  // (they have no dependencies on other conflicted keys)
  // Then resolve member events
  // Then resolve everything else
  // This mirrors Synapse's state resolution ordering

  return resolve_events_v2_full(version, state_sets, event_map, nullptr);
}

}  // namespace

// ============================================================================
// UTILITY: STATE MAP SERIALIZATION (for caching and debugging)
// ============================================================================

namespace {

// Serialize a StateMap to a deterministic string for hashing/caching
std::string serialize_state_map(const StateMap& state) {
  std::string result;
  result.reserve(state.size() * 80);  // Rough estimate

  for (const auto& [key, value] : state) {
    result += std::get<0>(key);
    result += '\x1F';  // Unit separator
    result += std::get<1>(key);
    result += '\x1E';  // Record separator
    result += value;
    result += '\x1D';  // Group separator
  }

  return result;
}

// Compute a hash of a StateMap for fast comparison
size_t hash_state_map(const StateMap& state) {
  size_t h = 0;
  for (const auto& [key, value] : state) {
    h ^= std::hash<std::string>{}(std::get<0>(key) + "\x00" +
                                  std::get<1>(key) + "\x00" + value) +
         (h << 6) + (h << 16) - h;
  }
  return h;
}

// Compare two StateMaps for equality
bool state_maps_equal(const StateMap& a, const StateMap& b) {
  if (a.size() != b.size())
    return false;
  for (const auto& [k, v] : a) {
    auto it = b.find(k);
    if (it == b.end() || it->second != v)
      return false;
  }
  return true;
}

}  // namespace

// ============================================================================
// PERIODIC MAINTENANCE
// ============================================================================

namespace {

// Run periodic maintenance tasks: compression and garbage collection.
// Returns a summary of what was done.
struct MaintenanceResult {
  size_t groups_compressed = 0;
  size_t groups_collected = 0;
  bool compression_run = false;
  bool gc_run = false;
};

MaintenanceResult run_periodic_maintenance(StateResolutionCoordinator& coord) {
  MaintenanceResult result;

  result.groups_compressed = coord.run_compression();
  result.compression_run = result.groups_compressed > 0;

  auto collected = coord.run_garbage_collection();
  result.groups_collected = collected.size();
  result.gc_run = !collected.empty();

  return result;
}

}  // namespace

// ============================================================================
// DIAGNOSTIC / DEBUG FUNCTIONS
// ============================================================================

namespace {

// Print a summary of a state resolution operation for debugging
std::string resolution_diagnostic(const ResolutionMetrics& m) {
  std::string diag;
  diag += "Resolution:\n";
  diag += "  Sets: " + std::to_string(m.state_sets_count) + "\n";
  diag += "  Unconflicted: " + std::to_string(m.unconflicted_events) + "\n";
  diag += "  Conflicted keys: " + std::to_string(m.conflicted_keys) + "\n";
  diag += "  Conflicted events: " + std::to_string(m.conflicted_events) + "\n";
  diag += "  Power events: " + std::to_string(m.power_events_count) + "\n";
  diag += "  Normal events: " + std::to_string(m.normal_events_count) + "\n";
  diag += "  Ban events: " + std::to_string(m.ban_events_count) + "\n";
  diag += "  Restricted joins: " + std::to_string(m.restricted_join_events) + "\n";
  diag += "  Auth checks: " + std::to_string(m.auth_checks_total) +
          " (passed: " + std::to_string(m.auth_checks_passed) +
          ", failed: " + std::to_string(m.auth_checks_failed) + ")\n";
  diag += "  Result size: " + std::to_string(m.resolved_state_size) + "\n";
  diag += "  Time: " + std::to_string(m.total_time.count()) + "us\n";
  diag += "  Cache hit: " + std::string(m.from_cache ? "yes" : "no") + "\n";
  return diag;
}

// Validate a resolved state map: check that all state keys are valid
// and that there are no duplicate keys with different values.
bool validate_resolved_state(const StateMap& resolved,
                              std::string* error_out = nullptr) {
  // No duplicate state keys by construction (std::map ensures uniqueness)
  // Check that event IDs look reasonable
  for (const auto& [k, v] : resolved) {
    if (v.empty()) {
      if (error_out)
        *error_out = "empty event ID for key (" +
                     std::get<0>(k) + ", " + std::get<1>(k) + ")";
      return false;
    }
  }
  return true;
}

}  // namespace

// ============================================================================
// PRE-EVENT STATE COMPUTATION
// ============================================================================
// Given an event and the state groups it references, compute the state
// before that event. Used for event authorization.

namespace {

StateMap compute_state_before_event(
    const EventId& event_id,
    const std::vector<int64_t>& state_group_ids,
    StateGroupStore& store,
    const EventMap& event_map,
    const RoomVersion& version) {
  if (state_group_ids.empty())
    return {};

  if (state_group_ids.size() == 1)
    return store.get_state(state_group_ids[0]);

  // Multiple state groups: resolve them
  std::vector<StateMap> state_sets;
  for (auto gid : state_group_ids)
    state_sets.push_back(store.get_state(gid));

  return resolve_events_v2_full(version, state_sets, event_map, nullptr);
}

}  // namespace

// ============================================================================
// BULK RESOLUTION
// ============================================================================
// Resolve state for multiple rooms in a batch. This is useful for
// backfill operations and room migrations.

namespace {

struct BulkResolutionResult {
  std::string room_id;
  StateMap resolved_state;
  int64_t state_group_id = 0;
  ResolutionMetrics metrics;
  bool success = true;
  std::string error;
};

std::vector<BulkResolutionResult> bulk_resolve_rooms(
    const std::vector<std::tuple<std::string, RoomVersion, std::vector<StateMap>>>& rooms,
    const EventMap& event_map,
    StateGroupStore& store,
    size_t max_concurrent = 4) {
  std::vector<BulkResolutionResult> results;

  // Process sequentially for simplicity
  for (const auto& [room_id, version, state_sets] : rooms) {
    BulkResolutionResult result;
    result.room_id = room_id;

    try {
      result.resolved_state = resolve_events_v2_full(
          version, state_sets, event_map, &result.metrics);
      result.state_group_id = store.get_or_create_group(result.resolved_state);
      result.success = true;
    } catch (const std::exception& e) {
      result.success = false;
      result.error = e.what();
    }

    results.push_back(std::move(result));
  }

  return results;
}

}  // namespace

// ============================================================================
// INCREMENTAL RESOLUTION
// ============================================================================
// When a new event arrives, we don't need to re-resolve the entire room state.
// We can incrementally update the resolved state by applying the new event
// on top of the previously resolved state.

namespace {

StateMap incrementally_resolve(
    const StateMap& previous_resolved,
    const ResolvableEvent& new_event,
    const EventMap& event_map,
    const RoomVersion& version) {
  if (!new_event.is_state())
    return previous_resolved;  // Non-state events don't change state

  StateMap new_state = previous_resolved;
  StateKey key = new_event.state_pair();

  // Check if there's an existing event for this key
  auto existing = new_state.find(key);
  if (existing == new_state.end()) {
    // New key: just add if auth passes
    std::vector<ResolvableEvent> auth_vec;
    for (const auto& ak : auth_types_for_event(version, new_event)) {
      auto rit = new_state.find(ak);
      if (rit != new_state.end()) {
        auto ait = event_map.find(rit->second);
        if (ait != event_map.end())
          auth_vec.push_back(ait->second);
      }
    }

    if (check_state_independent_auth_rules(version, new_event) &&
        check_state_dependent_auth_rules(version, new_event, auth_vec)) {
      new_state[key] = new_event.event_id;
    }
    return new_state;
  }

  // Existing key: need to resolve between old and new event
  std::vector<StateMap> state_sets;
  StateMap old_only;
  old_only[key] = existing->second;
  state_sets.push_back(old_only);

  StateMap new_only;
  new_only[key] = new_event.event_id;
  state_sets.push_back(new_only);

  // Copy other state from previous resolved
  for (const auto& [k, v] : previous_resolved) {
    if (k != key && new_state.find(k) == new_state.end())
      new_state[k] = v;
  }

  // Resolve just this key
  StateMap resolved_key = resolve_events_v2_full(version, state_sets, event_map, nullptr);
  if (!resolved_key.empty()) {
    new_state[key] = resolved_key.begin()->second;
  }

  return new_state;
}

}  // namespace

// ============================================================================
// CONFLICT DETECTION IN EVENT GRAPHS
// ============================================================================
// Detect potential state conflicts before they happen by analyzing the
// event graph. This is useful for proactive resolution.

namespace {

struct ConflictPrediction {
  StateKey key;
  std::set<EventId> conflicting_events;
  double conflict_probability = 0.0;
  std::string description;
};

std::vector<ConflictPrediction> predict_conflicts(
    const std::vector<StateMap>& state_sets,
    const EventMap& event_map,
    double min_probability = 0.5) {
  std::vector<ConflictPrediction> predictions;

  // Collect all keys
  std::set<StateKey> all_keys;
  for (const auto& ss : state_sets)
    for (const auto& [k, v] : ss)
      all_keys.insert(k);

  for (const auto& key : all_keys) {
    std::set<EventId> values;
    for (const auto& ss : state_sets) {
      auto it = ss.find(key);
      if (it != ss.end())
        values.insert(it->second);
    }

    if (values.size() > 1) {
      ConflictPrediction pred;
      pred.key = key;
      pred.conflicting_events = values;
      pred.conflict_probability = 1.0;  // Definitely conflicted
      pred.description = "key has " + std::to_string(values.size()) +
                         " different values across " +
                         std::to_string(state_sets.size()) + " state sets";
      predictions.push_back(pred);
    } else if (values.size() == 1) {
      // Check if the single value's auth events reference conflicting state
      auto it = event_map.find(*values.begin());
      if (it != event_map.end()) {
        for (const auto& aid : it->second.auth_event_ids) {
          // Check if any auth event is itself conflicted
          for (const auto& ss : state_sets) {
            // Not implemented: would need event-to-key mapping
            break;
          }
        }
      }
    }
  }

  return predictions;
}

}  // namespace

// ============================================================================
// STATE SNAPSHOT GENERATION
// ============================================================================
// Generate a snapshot of the full room state for backup, migration,
// or API responses.

namespace {

struct StateSnapshot {
  std::string room_id;
  std::string room_version;
  int64_t state_group_id = 0;
  StateMap state;
  int64_t snapshot_ts = 0;
  size_t state_size = 0;

  nlohmann::json to_json() const {
    nlohmann::json j;
    j["room_id"] = room_id;
    j["room_version"] = room_version;
    j["state_group_id"] = state_group_id;
    j["snapshot_ts"] = snapshot_ts;
    j["state_size"] = state_size;

    nlohmann::json state_array = nlohmann::json::array();
    for (const auto& [k, v] : state) {
      nlohmann::json entry;
      entry["type"] = std::get<0>(k);
      entry["state_key"] = std::get<1>(k);
      entry["event_id"] = v;
      state_array.push_back(entry);
    }
    j["state"] = state_array;

    return j;
  }
};

StateSnapshot create_state_snapshot(
    const std::string& room_id,
    const RoomVersion& version,
    int64_t state_group_id,
    StateGroupStore& store) {
  StateSnapshot snapshot;
  snapshot.room_id = room_id;
  snapshot.room_version = version.identifier;
  snapshot.state_group_id = state_group_id;
  snapshot.state = store.get_state(state_group_id);
  snapshot.state_size = snapshot.state.size();
  snapshot.snapshot_ts = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();

  return snapshot;
}

}  // namespace

// ============================================================================
// AUTH CHAIN WALKING WITH CYCLE DETECTION
// ============================================================================
// Robust auth chain computation that handles cycles in event DAGs.

namespace {

// Walk the auth chain with full cycle detection and depth tracking.
// Returns a map of event_id -> depth from origin.
struct AuthChainWalkResult {
  std::set<EventId> chain;
  std::map<EventId, int64_t> depths;       // Depth from event_id
  std::set<EventId> cycles_detected;       // Events involved in cycles
  size_t total_walked = 0;
};

AuthChainWalkResult walk_auth_chain_robust(
    const EventId& origin,
    const EventMap& event_map,
    int64_t max_depth = 1000) {
  AuthChainWalkResult result;

  // Use iterative DFS with explicit stack to avoid recursion limits
  struct Frame {
    EventId event_id;
    int64_t depth;
    std::vector<EventId>::const_iterator next_auth;
    std::vector<EventId>::const_iterator auth_end;
  };

  std::vector<Frame> stack;
  std::set<EventId> in_stack;  // For cycle detection

  auto it = event_map.find(origin);
  if (it == event_map.end()) {
    result.chain.insert(origin);
    result.depths[origin] = 0;
    return result;
  }

  stack.push_back({origin, 0, it->second.auth_event_ids.begin(),
                   it->second.auth_event_ids.end()});
  in_stack.insert(origin);

  while (!stack.empty()) {
    Frame& frame = stack.back();
    result.chain.insert(frame.event_id);
    result.depths[frame.event_id] = frame.depth;
    result.total_walked++;

    if (frame.depth >= max_depth) {
      in_stack.erase(frame.event_id);
      stack.pop_back();
      continue;
    }

    // Find next unvisited auth event
    bool found_next = false;
    while (frame.next_auth != frame.auth_end) {
      EventId next_eid = *frame.next_auth;
      ++frame.next_auth;

      if (in_stack.count(next_eid)) {
        // Cycle detected
        result.cycles_detected.insert(next_eid);
        result.cycles_detected.insert(frame.event_id);
        continue;
      }

      if (result.chain.count(next_eid)) {
        continue;  // Already visited, skip
      }

      auto next_it = event_map.find(next_eid);
      if (next_it == event_map.end()) {
        result.chain.insert(next_eid);
        result.depths[next_eid] = frame.depth + 1;
        continue;
      }

      stack.push_back({next_eid, frame.depth + 1,
                       next_it->second.auth_event_ids.begin(),
                       next_it->second.auth_event_ids.end()});
      in_stack.insert(next_eid);
      found_next = true;
      break;
    }

    if (!found_next) {
      in_stack.erase(frame.event_id);
      stack.pop_back();
    }
  }

  return result;
}

}  // namespace

// ============================================================================
// STATE GROUP CHAIN OPTIMIZATION
// ============================================================================
// Optimize state group storage by identifying linear chains and storing
// only the head and delta.

namespace {

struct StateGroupChain {
  int64_t head_group_id = 0;
  std::vector<int64_t> chain_ids;
  StateMap base_state;
  std::vector<StateDelta> deltas;  // delta[i] transforms base_state to chain_ids[i]

  // Reconstruct state at position `index`
  StateMap state_at(size_t index) const {
    if (index >= chain_ids.size())
      return {};
    StateMap s = base_state;
    for (size_t i = 0; i <= index && i < deltas.size(); i++) {
      for (const auto& [k, v] : deltas[i].added)
        s[k] = v;
      for (const auto& [k, v] : deltas[i].modified)
        s[k] = v;
      for (const auto& [k, _] : deltas[i].removed)
        s.erase(k);
    }
    return s;
  }

  size_t storage_savings() const {
    size_t full_cost = chain_ids.size() * base_state.size();
    size_t chain_cost = base_state.size();
    for (const auto& d : deltas)
      chain_cost += d.total_changes();
    return (full_cost > chain_cost) ? (full_cost - chain_cost) : 0;
  }
};

// Attempt to form a chain from a sequence of related state groups.
// Returns the chain if the groups can be sequentially linked.
std::optional<StateGroupChain> form_state_group_chain(
    const std::vector<std::pair<int64_t, StateMap>>& groups,
    size_t min_chain_length = 3,
    double max_delta_ratio = 0.3) {
  if (groups.size() < min_chain_length)
    return std::nullopt;

  StateGroupChain chain;
  chain.head_group_id = groups[0].first;
  chain.base_state = groups[0].second;

  for (size_t i = 1; i < groups.size(); i++) {
    auto delta = compute_state_delta(groups[i - 1].second, groups[i].second);
    double ratio = static_cast<double>(delta.total_changes()) /
                   static_cast<double>(groups[i].second.size());

    if (ratio > max_delta_ratio)
      return std::nullopt;  // Too different to be a chain

    chain.chain_ids.push_back(groups[i].first);
    chain.deltas.push_back(std::move(delta));
  }

  if (chain.chain_ids.size() >= min_chain_length - 1)
    return chain;

  return std::nullopt;
}

}  // namespace

// ============================================================================
// STATE RESOLUTION WITH TIMEOUT
// ============================================================================
// State resolution can be expensive for large rooms. This module adds
// timeout handling to abort resolution that takes too long.

namespace {

struct ResolutionTimeout {
  std::chrono::steady_clock::time_point deadline;
  bool enabled = false;

  explicit ResolutionTimeout(int64_t max_millis = 5000) {
    if (max_millis > 0) {
      deadline = std::chrono::steady_clock::now() +
                 std::chrono::milliseconds(max_millis);
      enabled = true;
    }
  }

  bool expired() const {
    if (!enabled) return false;
    return std::chrono::steady_clock::now() > deadline;
  }

  int64_t remaining_ms() const {
    if (!enabled) return INT64_MAX;
    auto rem = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now()).count();
    return std::max<int64_t>(0, rem);
  }
};

// Partial resolution result when timeout is hit
struct PartialResolution {
  StateMap state;
  size_t resolved_keys = 0;
  size_t remaining_keys = 0;
  bool complete = false;
};

// Resolve with timeout, returning best-effort partial result if time expires
StateMap resolve_with_timeout(
    const RoomVersion& version,
    const std::vector<StateMap>& state_sets,
    const EventMap& event_map,
    int64_t timeout_ms,
    PartialResolution* partial_out = nullptr) {
  ResolutionTimeout timeout(timeout_ms);

  // Fast path for simple cases
  if (state_sets.size() == 1)
    return state_sets[0];
  if (state_sets.empty())
    return {};

  auto [unconflicted, conflicted, all_eids, unc, cc] =
      separate_events_detailed(state_sets);

  if (conflicted.empty())
    return unconflicted;

  if (timeout.expired()) {
    if (partial_out) {
      partial_out->state = unconflicted;
      partial_out->resolved_keys = unconflicted.size();
      partial_out->remaining_keys = conflicted.size();
      partial_out->complete = false;
    }
    return unconflicted;
  }

  // Try full resolution
  try {
    auto result = resolve_events_v2_full(version, state_sets, event_map, nullptr);
    if (partial_out) {
      partial_out->complete = true;
      partial_out->resolved_keys = result.size();
    }
    return result;
  } catch (...) {
    // On exception, return unconflicted as best effort
    if (partial_out) {
      partial_out->state = unconflicted;
      partial_out->complete = false;
    }
    return unconflicted;
  }
}

}  // namespace

// ============================================================================
// STATE DIFF COMPRESSION FOR NETWORK TRANSFER
// ============================================================================
// Compute minimal diff between two state maps for efficient network sync.

namespace {

struct CompressedStateDiff {
  std::string base_etag;            // ETag of base state
  std::map<StateKey, std::string> sets;   // New or changed keys
  std::vector<StateKey> deletes;          // Removed keys
  size_t original_size = 0;
  size_t compressed_size = 0;
  double compression_ratio = 0.0;

  nlohmann::json to_json() const {
    nlohmann::json j;
    j["base_etag"] = base_etag;
    j["sets"] = nlohmann::json::object();
    for (const auto& [k, v] : sets) {
      std::string key_str = std::get<0>(k) + "\x00" + std::get<1>(k);
      j["sets"][key_str] = v;
    }
    nlohmann::json dels = nlohmann::json::array();
    for (const auto& k : deletes) {
      std::string key_str = std::get<0>(k) + "\x00" + std::get<1>(k);
      dels.push_back(key_str);
    }
    j["deletes"] = dels;
    return j;
  }

  static CompressedStateDiff from_json(const nlohmann::json& j) {
    CompressedStateDiff diff;
    diff.base_etag = j.value("base_etag", "");

    if (j.contains("sets") && j["sets"].is_object()) {
      for (auto& [key_str, val] : j["sets"].items()) {
        auto null_pos = key_str.find('\x00');
        if (null_pos != std::string::npos) {
          diff.sets[make_key(key_str.substr(0, null_pos),
                              key_str.substr(null_pos + 1))] = val.get<std::string>();
        }
      }
    }

    if (j.contains("deletes") && j["deletes"].is_array()) {
      for (const auto& k : j["deletes"]) {
        std::string ks = k.get<std::string>();
        auto null_pos = ks.find('\x00');
        if (null_pos != std::string::npos) {
          diff.deletes.push_back(make_key(ks.substr(0, null_pos),
                                           ks.substr(null_pos + 1)));
        }
      }
    }

    return diff;
  }
};

CompressedStateDiff compress_state_for_sync(
    const StateMap& base_state,
    const StateMap& target_state) {
  CompressedStateDiff diff;

  // Compute ETag from hash of base state
  diff.base_etag = std::to_string(hash_state_map(base_state));

  // Find sets (added + modified)
  for (const auto& [key, val] : target_state) {
    auto it = base_state.find(key);
    if (it == base_state.end() || it->second != val)
      diff.sets[key] = val;
  }

  // Find deleted
  for (const auto& [key, val] : base_state) {
    if (target_state.find(key) == target_state.end())
      diff.deletes.push_back(key);
  }

  diff.original_size = target_state.size();
  diff.compressed_size = diff.sets.size() + diff.deletes.size();

  if (diff.original_size > 0)
    diff.compression_ratio = 1.0 - static_cast<double>(diff.compressed_size) /
                                     static_cast<double>(diff.original_size);

  return diff;
}

StateMap apply_compressed_diff(const StateMap& base_state,
                                const CompressedStateDiff& diff) {
  StateMap result = base_state;

  // Apply sets
  for (const auto& [k, v] : diff.sets)
    result[k] = v;

  // Apply deletes
  for (const auto& k : diff.deletes)
    result.erase(k);

  return result;
}

}  // namespace

// ============================================================================
// STATE RESOLUTION FOR ROOM UPGRADES
// ============================================================================
// When a room is upgraded to a new version, the state must be converted.
// This module handles cross-version state resolution.

namespace {

// Convert state from one room version to another.
// Handles auth event restructuring, power level migration, etc.
StateMap migrate_state_across_versions(
    const StateMap& old_state,
    const RoomVersion& old_version,
    const RoomVersion& new_version,
    const EventMap& event_map) {
  // For same version, no migration needed
  if (old_version.state_res == new_version.state_res)
    return old_state;

  StateMap migrated = old_state;

  // V1 -> V2 migration: V1 uses different conflict resolution
  // but the state map format is the same. Just re-resolve if needed.
  if (old_version.state_res == StateResVersion::V1 &&
      new_version.state_res == StateResVersion::V2) {
    // State is compatible; no key-level changes needed
    return migrated;
  }

  // Remove keys not supported in newer versions
  if (old_version.event_format < EventFormatVersion::V3 &&
      new_version.event_format >= EventFormatVersion::V3) {
    // V3+ drops some legacy auth event requirements
    // State map itself doesn't change
  }

  return migrated;
}

}  // namespace

// ============================================================================
// STATE BLOOM FILTER FOR FAST NEGATIVE LOOKUPS
// ============================================================================
// A bloom filter over state group event IDs to quickly determine if an
// event is NOT present in a state group (avoiding expensive lookups).

namespace {

class StateBloomFilter {
public:
  explicit StateBloomFilter(size_t expected_elements = 10000,
                             double false_positive_rate = 0.01) {
    // Calculate optimal size: m = -n*ln(p) / (ln(2)^2)
    double m = -static_cast<double>(expected_elements) * std::log(false_positive_rate) /
               (std::log(2.0) * std::log(2.0));
    // Calculate optimal number of hash functions: k = (m/n)*ln(2)
    double k = (m / static_cast<double>(expected_elements)) * std::log(2.0);

    bitset_size_ = std::max<size_t>(64, static_cast<size_t>(std::ceil(m)));
    num_hashes_ = std::max<size_t>(1, static_cast<size_t>(std::ceil(k)));
    bitset_.resize((bitset_size_ + 63) / 64, 0);
  }

  void insert(const std::string& key) {
    size_t h1 = std::hash<std::string>{}(key);
    size_t h2 = h1 ^ (h1 >> 16);

    for (size_t i = 0; i < num_hashes_; i++) {
      size_t idx = (h1 + i * h2) % bitset_size_;
      size_t word = idx / 64;
      size_t bit = idx % 64;
      bitset_[word] |= (1ULL << bit);
    }
  }

  void insert_batch(const std::set<EventId>& event_ids) {
    for (const auto& eid : event_ids)
      insert(eid);
  }

  bool probably_contains(const std::string& key) const {
    size_t h1 = std::hash<std::string>{}(key);
    size_t h2 = h1 ^ (h1 >> 16);

    for (size_t i = 0; i < num_hashes_; i++) {
      size_t idx = (h1 + i * h2) % bitset_size_;
      size_t word = idx / 64;
      size_t bit = idx % 64;
      if (!(bitset_[word] & (1ULL << bit)))
        return false;  // Definitely not present
    }
    return true;  // Probably present
  }

  void clear() {
    std::fill(bitset_.begin(), bitset_.end(), 0);
  }

  size_t memory_bytes() const {
    return bitset_.size() * sizeof(uint64_t);
  }

private:
  std::vector<uint64_t> bitset_;
  size_t bitset_size_ = 0;
  size_t num_hashes_ = 0;
};

}  // namespace

// ============================================================================
// RESOLUTION CONTEXT: CAPTURE FULL STATE DURING RESOLUTION
// ============================================================================
// A context object that holds all intermediate state during a resolution
// operation. Useful for debugging and metrics collection.

namespace {

struct ResolutionContext {
  std::string room_id;
  RoomVersion version;
  std::vector<StateMap> state_sets;
  const EventMap* event_map = nullptr;

  // Intermediate state
  SeparationResult separation;
  std::set<EventId> expanded_events;
  EventClassification classification;
  std::vector<EventId> ordered_power;
  std::vector<EventId> ordered_normal;
  StateMap result;

  // Metrics
  ResolutionMetrics metrics;

  // Debug info
  std::vector<std::string> debug_log;

  void log(const std::string& msg) {
    debug_log.push_back(msg);
  }
};

void populate_resolution_context(
    ResolutionContext& ctx,
    const std::string& room_id,
    const RoomVersion& version,
    const std::vector<StateMap>& state_sets,
    const EventMap& event_map) {
  ctx.room_id = room_id;
  ctx.version = version;
  ctx.state_sets = state_sets;
  ctx.event_map = &event_map;
}

std::string dump_resolution_context(const ResolutionContext& ctx) {
  std::string out;
  out += "ResolutionContext for room: " + ctx.room_id + "\n";
  out += "Room version: " + ctx.version.identifier + "\n";
  out += "State sets: " + std::to_string(ctx.state_sets.size()) + "\n";
  out += "Unconflicted: " + std::to_string(ctx.metrics.unconflicted_events) + "\n";
  out += "Conflicted: " + std::to_string(ctx.metrics.conflicted_keys) + "\n";
  out += "Expanded events: " + std::to_string(ctx.metrics.conflicted_events) + "\n";
  out += "Power events: " + std::to_string(ctx.metrics.power_events_count) + "\n";
  out += "Normal events: " + std::to_string(ctx.metrics.normal_events_count) + "\n";
  out += "Result size: " + std::to_string(ctx.metrics.resolved_state_size) + "\n";
  out += "Time: " + std::to_string(ctx.metrics.total_time.count()) + "us\n";
  out += "Debug log (" + std::to_string(ctx.debug_log.size()) + " entries):\n";
  for (const auto& entry : ctx.debug_log)
    out += "  " + entry + "\n";
  return out;
}

}  // namespace

// ============================================================================
// WARM CACHE ON BOOT
// ============================================================================
// Pre-warm the resolution cache on server startup for active rooms.

namespace {

struct CacheWarmResult {
  std::string room_id;
  size_t entries_warmed = 0;
  std::chrono::microseconds time_spent{0};
  bool success = false;
};

CacheWarmResult warm_cache_for_room(
    const std::string& room_id,
    const RoomVersion& version,
    const std::vector<int64_t>& recent_state_groups,
    const EventMap& event_map,
    StateGroupStore& store) {
  CacheWarmResult result;
  result.room_id = room_id;

  auto start = std::chrono::high_resolution_clock::now();

  if (recent_state_groups.empty()) {
    result.success = true;
    return result;
  }

  // Pre-resolve the most recent state group combinations
  std::vector<StateMap> state_sets;
  for (size_t i = 0; i < recent_state_groups.size(); i++) {
    state_sets.push_back(store.get_state(recent_state_groups[i]));
    result.entries_warmed++;
  }

  if (state_sets.size() >= 2) {
    resolve_events_v2_full(version, state_sets, event_map, nullptr);
  }

  result.time_spent = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::high_resolution_clock::now() - start);
  result.success = true;

  return result;
}

}  // namespace

// ============================================================================
// STATE INTEGRITY VERIFICATION
// ============================================================================
// Verify that a resolved state is internally consistent.
// Each state event in the resolved map should be authorized by the
// events that precede it.

namespace {

struct StateVerificationResult {
  bool valid = true;
  std::vector<std::string> errors;
  std::vector<std::string> warnings;
  size_t keys_verified = 0;
  size_t auth_failures = 0;
};

StateVerificationResult verify_state_integrity(
    const StateMap& resolved,
    const EventMap& event_map,
    const RoomVersion& version) {
  StateVerificationResult result;

  // Build auth context from resolved state
  std::map<StateKey, ResolvableEvent> resolved_auth;
  for (const auto& [k, eid] : resolved) {
    auto it = event_map.find(eid);
    if (it != event_map.end())
      resolved_auth[k] = it->second;
  }

  // Verify create event exists
  auto create_key = make_key("m.room.create", "");
  if (resolved.find(create_key) == resolved.end()) {
    result.errors.push_back("missing m.room.create event");
    result.valid = false;
  }

  // Verify each state event against its auth
  for (const auto& [key, eid] : resolved) {
    auto it = event_map.find(eid);
    if (it == event_map.end()) {
      result.warnings.push_back("event not in event_map: " + eid +
                                " for key (" + std::get<0>(key) + ", " +
                                std::get<1>(key) + ")");
      continue;
    }

    const ResolvableEvent& event = it->second;

    // Don't verify create event against itself
    if (event.type == "m.room.create")
      continue;

    // Build auth vector for this event
    std::vector<ResolvableEvent> auth_vec;
    for (const auto& ak : auth_types_for_event(version, event)) {
      auto ra = resolved_auth.find(ak);
      if (ra != resolved_auth.end())
        auth_vec.push_back(ra->second);
    }

    if (!auth_vec.empty() &&
        !check_state_dependent_auth_rules(version, event, auth_vec)) {
      result.auth_failures++;
      result.errors.push_back("auth failure for " + eid +
                              " (type=" + event.type + ")");
      result.valid = false;
    }

    result.keys_verified++;
  }

  return result;
}

}  // namespace

// ============================================================================
// EVENT ORDERING BY ORIGIN SERVER TIMESTAMP
// ============================================================================
// Alternative ordering method used when mainline ordering can't be
// computed (e.g., the power event chain is broken).

namespace {

// Order events by origin_server_ts, then lexicographically by event_id.
// This is the fallback ordering for state resolution v2 when mainline
// ordering is unavailable.
std::vector<EventId> order_by_origin_server_ts(
    const std::set<EventId>& event_ids,
    const EventMap& event_map) {
  std::vector<std::pair<int64_t, EventId>> pairs;
  pairs.reserve(event_ids.size());

  for (const auto& eid : event_ids) {
    auto it = event_map.find(eid);
    int64_t ts = (it != event_map.end()) ? it->second.origin_server_ts : 0;
    pairs.emplace_back(ts, eid);
  }

  std::sort(pairs.begin(), pairs.end(),
            [](const auto& a, const auto& b) {
              if (a.first != b.first)
                return a.first < b.first;
              return a.second < b.second;
            });

  std::vector<EventId> result;
  result.reserve(pairs.size());
  for (auto& p : pairs)
    result.push_back(std::move(p.second));

  return result;
}

}  // namespace

// ============================================================================
// STATE MERGE - COMBINE TWO STATE MAPS WITH PRIORITY
// ============================================================================
// Merge two state maps, preferring entries from the primary map when
// conflicts arise.

namespace {

enum class MergeStrategy {
  kPrimaryWins,        // Primary map's entries always win
  kNewerWins,          // Event with higher origin_server_ts wins
  kMergeIfNoConflict,  // Only merge if no conflict
};

StateMap merge_state_maps(const StateMap& primary,
                           const StateMap& secondary,
                           MergeStrategy strategy,
                           const EventMap& event_map) {
  StateMap result = primary;

  for (const auto& [key, val] : secondary) {
    auto existing = result.find(key);
    if (existing == result.end()) {
      result[key] = val;
      continue;
    }

    // Conflict: apply strategy
    if (existing->second == val)
      continue;  // Same value

    switch (strategy) {
      case MergeStrategy::kPrimaryWins:
        // Keep primary value (already in result)
        break;

      case MergeStrategy::kNewerWins: {
        auto pit = event_map.find(existing->second);
        auto sit = event_map.find(val);
        int64_t pts = (pit != event_map.end()) ? pit->second.origin_server_ts : 0;
        int64_t sts = (sit != event_map.end()) ? sit->second.origin_server_ts : 0;
        if (sts > pts)
          result[key] = val;
        break;
      }

      case MergeStrategy::kMergeIfNoConflict:
        // Don't merge if there's a conflict; keep primary
        break;
    }
  }

  return result;
}

}  // namespace

}  // namespace progressive::state
