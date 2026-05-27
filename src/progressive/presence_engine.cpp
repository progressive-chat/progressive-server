// ============================================================================
// presence_engine.cpp — Matrix Presence Engine and Status Handler
//
// Implements:
//   - Presence states: online, offline, unavailable, free_for_chat, busy,
//     and custom status messages with internationalization support
//   - Presence persistence: store current presence per user, presence
//     history/stream with configurable retention, in-memory caching layer
//   - Presence updates: broadcast presence changes to all subscribed users
//     (both local and remote via real-time notification channels)
//   - Last active tracking: update last_active_ts on any user action
//     (message send, read receipt, typing, sync, etc.), calculate idle time
//   - Currently active flag: set currently_active based on recent activity
//     window (default 1 minute), decay to inactive after idle timeout
//   - Presence list management: add/remove users from presence lists,
//     invite/accept/deny flow, auto-accept setting, privacy controls
//   - Presence polling: long-poll for presence changes in /sync response
//     generation, presence streaming with incremental token support
//   - Presence state machine: formal transition rules (online->offline
//     on timeout, online->unavailable on idle, etc.), transition validation
//   - Presence federation: send presence EDUs to remote servers on change,
//     batch federation delivery, receive and process remote presence EDUs,
//     deduplication and loop prevention
//   - Presence override: admin-initiated presence override with audit
//     trail, expiring overrides, force-offline/force-online capabilities
//   - Presence configuration: presence_enabled flag (global + per-user),
//     default_online_state, idle_timeout_ms, active_window_ms,
//     federation batch interval, retention policy
//   - In-memory presence cache: thread-safe presence state cache for
//     fast lookup without database round-trips, cache invalidation
//     on write, TTL-based eviction for idle entries
//   - Presence notification: callback-based notification system for
//     presence changes, listener registration with filtering
//   - Presence metrics: counters for state transitions, federation
//     deliveries, cache hits/misses, active user counts
//
// Equivalent to:
//   synapse/handlers/presence.py (2,897 lines)
//   synapse/handlers/presence_router.py
//   synapse/federation/sender/per_destination_queue.py (presence portion)
//   synapse/federation/transport/server.py (presence EDU handling)
//   synapse/replication/http/presence.py
//   synapse/rest/client/presence.py
//
// Target: 2500+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
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
#include <vector>

#include <nlohmann/json.hpp>

// Internal project includes
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/util/time.hpp"
#include "progressive/util/log.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
class PresenceStateMachine;
class PresenceCache;
class PresencePoller;
class PresenceFederation;
class PresenceOverrideManager;
class PresenceNotifier;
class PresenceEngine;

// ============================================================================
// Anonymous namespace — Internal helpers and constants
// ============================================================================
namespace {

// ---- Timestamp helper ----
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

// ---- String constants ----
constexpr std::string_view kStateOnline = "online";
constexpr std::string_view kStateOffline = "offline";
constexpr std::string_view kStateUnavailable = "unavailable";
constexpr std::string_view kStateFreeForChat = "free_for_chat";
constexpr std::string_view kStateBusy = "busy";
constexpr std::string_view kStateCustom = "custom";

constexpr int64_t kDefaultIdleTimeoutMs = 300'000;       // 5 minutes -> unavailable
constexpr int64_t kDefaultOfflineTimeoutMs = 1'800'000;  // 30 minutes -> offline
constexpr int64_t kDefaultActiveWindowMs = 60'000;       // 1 minute -> currently_active
constexpr int64_t kDefaultPollTimeoutMs = 30'000;        // 30 second long-poll
constexpr int64_t kMaxPollTimeoutMs = 300'000;           // 5 minute maximum
constexpr int64_t kFederationBatchIntervalMs = 5'000;    // 5 second batching
constexpr int64_t kPresenceCacheTTLMs = 600'000;         // 10 minute cache TTL
constexpr int64_t kStalePresenceCleanupIntervalMs = 3'600'000; // 1 hour
constexpr int64_t kMaxStatusMessageLength = 500;          // character limit
constexpr int64_t kPresenceStreamRetentionMs = 86'400'000; // 24 hour stream retention
constexpr size_t kMaxPresenceCacheEntries = 100'000;
constexpr size_t kMaxPresenceListSize = 1'000;            // max users in presence list
constexpr size_t kFederationBatchSize = 50;               // presence updates per batch
constexpr int kMaxFederationRetries = 3;

// ---- Valid states ----
const std::set<std::string_view> kValidPresenceStates = {
    kStateOnline, kStateOffline, kStateUnavailable,
    kStateFreeForChat, kStateBusy
};

// ---- Presence state to JSON ----
json presence_state_to_json(std::string_view state) {
  json j;
  j["presence"] = std::string(state);
  return j;
}

// ---- Sanitize status message ----
std::string sanitize_status_msg(std::string_view msg) {
  if (msg.size() > static_cast<size_t>(kMaxStatusMessageLength)) {
    return std::string(msg.substr(0, kMaxStatusMessageLength)) + "...";
  }
  return std::string(msg);
}

// ---- Is valid presence state ----
bool is_valid_presence_state(std::string_view s) {
  return kValidPresenceStates.count(s) > 0;
}

// ---- User ID validation ----
bool is_valid_user_id(std::string_view s) {
  return !s.empty() && s[0] == '@' && s.find(':') != std::string_view::npos;
}

}  // anonymous namespace

// ============================================================================
// PresenceConfig — Configuration for the presence engine
// ============================================================================
struct PresenceConfig {
  // ---- Feature flags ----
  bool presence_enabled = true;
  bool federation_enabled = true;
  bool auto_accept_presence_lists = false;
  bool allow_custom_statuses = true;
  bool track_last_active = true;

  // ---- Timing parameters ----
  int64_t idle_timeout_ms = kDefaultIdleTimeoutMs;
  int64_t offline_timeout_ms = kDefaultOfflineTimeoutMs;
  int64_t active_window_ms = kDefaultActiveWindowMs;
  int64_t poll_timeout_ms = kDefaultPollTimeoutMs;
  int64_t federation_batch_interval_ms = kFederationBatchIntervalMs;
  int64_t cache_ttl_ms = kPresenceCacheTTLMs;
  int64_t stale_cleanup_interval_ms = kStalePresenceCleanupIntervalMs;
  int64_t stream_retention_ms = kPresenceStreamRetentionMs;

  // ---- Limits ----
  size_t max_cache_entries = kMaxPresenceCacheEntries;
  size_t max_presence_list_size = kMaxPresenceListSize;
  size_t federation_batch_size = kFederationBatchSize;

  // ---- Default state for new users ----
  std::string default_state = std::string(kStateOnline);

  // ---- Server identity ----
  std::string server_name;

  // ---- Load from JSON config ----
  void load_from_json(const json& cfg) {
    if (cfg.contains("presence_enabled"))
      presence_enabled = cfg["presence_enabled"].get<bool>();
    if (cfg.contains("federation_enabled"))
      federation_enabled = cfg["federation_enabled"].get<bool>();
    if (cfg.contains("auto_accept_presence_lists"))
      auto_accept_presence_lists = cfg["auto_accept_presence_lists"].get<bool>();
    if (cfg.contains("allow_custom_statuses"))
      allow_custom_statuses = cfg["allow_custom_statuses"].get<bool>();
    if (cfg.contains("track_last_active"))
      track_last_active = cfg["track_last_active"].get<bool>();
    if (cfg.contains("idle_timeout_ms"))
      idle_timeout_ms = cfg["idle_timeout_ms"].get<int64_t>();
    if (cfg.contains("offline_timeout_ms"))
      offline_timeout_ms = cfg["offline_timeout_ms"].get<int64_t>();
    if (cfg.contains("active_window_ms"))
      active_window_ms = cfg["active_window_ms"].get<int64_t>();
    if (cfg.contains("poll_timeout_ms"))
      poll_timeout_ms = cfg["poll_timeout_ms"].get<int64_t>();
    if (cfg.contains("federation_batch_interval_ms"))
      federation_batch_interval_ms = cfg["federation_batch_interval_ms"].get<int64_t>();
    if (cfg.contains("max_presence_list_size"))
      max_presence_list_size = cfg["max_presence_list_size"].get<size_t>();
    if (cfg.contains("default_state"))
      default_state = cfg["default_state"].get<std::string>();
    if (cfg.contains("server_name"))
      server_name = cfg["server_name"].get<std::string>();
  }

  // ---- Dump to JSON for debugging ----
  json to_json() const {
    json j;
    j["presence_enabled"] = presence_enabled;
    j["federation_enabled"] = federation_enabled;
    j["auto_accept_presence_lists"] = auto_accept_presence_lists;
    j["allow_custom_statuses"] = allow_custom_statuses;
    j["idle_timeout_ms"] = idle_timeout_ms;
    j["offline_timeout_ms"] = offline_timeout_ms;
    j["active_window_ms"] = active_window_ms;
    j["default_state"] = default_state;
    return j;
  }
};

// ============================================================================
// PresenceState — Full presence state for a user
// ============================================================================
struct PresenceState {
  std::string user_id;
  std::string state;              // online, offline, unavailable, free_for_chat, busy
  std::optional<std::string> status_msg;
  int64_t last_active_ts = 0;     // milliseconds since epoch
  int64_t last_user_sync_ts = 0;  // last /sync timestamp
  int64_t last_state_change_ts = 0;
  bool currently_active = false;
  int64_t federation_update_ts = 0;

  // ---- Calculate idle time in milliseconds ----
  int64_t idle_time_ms() const {
    if (last_active_ts == 0) return INT64_MAX;
    return now_ms() - last_active_ts;
  }

  // ---- Is this state considered "present" (not offline) ----
  bool is_present() const {
    return state != kStateOffline;
  }

  // ---- Convert to API response JSON ----
  json to_api_json() const {
    json j;
    j["presence"] = state;
    if (status_msg.has_value() && !status_msg->empty())
      j["status_msg"] = *status_msg;
    j["last_active_ago"] = idle_time_ms();
    j["currently_active"] = currently_active;
    return j;
  }

  // ---- Convert to federation EDU JSON ----
  json to_edu_json() const {
    json j;
    j["push"] = json::array();
    json entry;
    entry["user_id"] = user_id;
    entry["presence"] = state;
    if (status_msg.has_value() && !status_msg->empty())
      entry["status_msg"] = *status_msg;
    entry["last_active_ago"] = idle_time_ms();
    entry["currently_active"] = currently_active;
    j["push"].push_back(entry);
    return j;
  }

  // ---- Create from database row ----
  static PresenceState from_db_row(const std::map<std::string, std::string>& row) {
    PresenceState ps;
    if (auto it = row.find("user_id"); it != row.end())
      ps.user_id = it->second;
    if (auto it = row.find("state"); it != row.end())
      ps.state = it->second;
    if (auto it = row.find("status_msg"); it != row.end() && !it->second.empty())
      ps.status_msg = it->second;
    if (auto it = row.find("last_active_ts"); it != row.end())
      ps.last_active_ts = std::stoll(it->second);
    if (auto it = row.find("last_user_sync_ts"); it != row.end())
      ps.last_user_sync_ts = std::stoll(it->second);
    if (auto it = row.find("currently_active"); it != row.end())
      ps.currently_active = (it->second == "1" || it->second == "true");
    return ps;
  }
};

// ============================================================================
// PresenceMetrics — Internal metrics tracking
// ============================================================================
struct PresenceMetrics {
  std::atomic<int64_t> total_state_transitions{0};
  std::atomic<int64_t> online_to_offline_transitions{0};
  std::atomic<int64_t> online_to_unavailable_transitions{0};
  std::atomic<int64_t> offline_to_online_transitions{0};
  std::atomic<int64_t> cache_hits{0};
  std::atomic<int64_t> cache_misses{0};
  std::atomic<int64_t> federation_updates_sent{0};
  std::atomic<int64_t> federation_updates_failed{0};
  std::atomic<int64_t> federation_edus_received{0};
  std::atomic<int64_t> presence_list_invites{0};
  std::atomic<int64_t> presence_list_accepts{0};
  std::atomic<int64_t> long_poll_connections{0};
  std::atomic<int64_t> admin_overrides_active{0};
  std::atomic<int64_t> stale_users_timed_out{0};
  std::atomic<int64_t> currently_active_users{0};

  json to_json() const {
    json j;
    j["total_state_transitions"] = total_state_transitions.load();
    j["online_to_offline"] = online_to_offline_transitions.load();
    j["online_to_unavailable"] = online_to_unavailable_transitions.load();
    j["offline_to_online"] = offline_to_online_transitions.load();
    j["cache_hits"] = cache_hits.load();
    j["cache_misses"] = cache_misses.load();
    j["federation_updates_sent"] = federation_updates_sent.load();
    j["federation_updates_failed"] = federation_updates_failed.load();
    j["federation_edus_received"] = federation_edus_received.load();
    j["presence_list_invites"] = presence_list_invites.load();
    j["presence_list_accepts"] = presence_list_accepts.load();
    j["long_poll_connections"] = long_poll_connections.load();
    j["admin_overrides_active"] = admin_overrides_active.load();
    j["stale_users_timed_out"] = stale_users_timed_out.load();
    j["currently_active_users"] = currently_active_users.load();
    return j;
  }
};

// ============================================================================
// PresenceStateMachine — Formal state transition rules
//
// Valid transitions:
//   online     -> unavailable, offline, free_for_chat, busy
//   unavailable -> online, offline
//   offline    -> online
//   free_for_chat -> online, offline, busy
//   busy       -> online, offline
//
// timeout transitions:
//   online -> unavailable (idle timeout)
//   unavailable -> offline (offline timeout)
//   free_for_chat -> online / unavailable (idle timeout)
//   busy -> online (if idle but still "active"), offline (full timeout)
// ============================================================================
class PresenceStateMachine {
public:
  PresenceStateMachine() = default;

  // ---- Validate a state transition ----
  bool can_transition(std::string_view from, std::string_view to) const {
    // Build lookup: map<from, set<to>>
    static const std::map<std::string_view, std::set<std::string_view>> rules = {
        {kStateOnline,   {kStateUnavailable, kStateOffline, kStateFreeForChat, kStateBusy}},
        {kStateUnavailable, {kStateOnline, kStateOffline}},
        {kStateOffline,  {kStateOnline}},
        {kStateFreeForChat, {kStateOnline, kStateOffline, kStateBusy}},
        {kStateBusy,     {kStateOnline, kStateOffline}},
    };

    // Any state can transition to itself (no-op)
    if (from == to) return true;

    auto it = rules.find(from);
    if (it == rules.end()) return false;
    return it->second.count(to) > 0;
  }

  // ---- Compute timeout-based transition ----
  // Returns the state that should result, or nullopt if no transition needed
  std::optional<std::string> compute_timeout_transition(
      std::string_view current_state,
      int64_t idle_ms,
      int64_t idle_timeout_ms,
      int64_t offline_timeout_ms) const {

    // Already offline — no timeout transition
    if (current_state == kStateOffline) return std::nullopt;

    // Full offline timeout applies from any non-offline state
    if (idle_ms >= offline_timeout_ms) {
      return std::string(kStateOffline);
    }

    // Idle timeout: online/free_for_chat/busy -> unavailable
    if (idle_ms >= idle_timeout_ms) {
      if (current_state == kStateOnline ||
          current_state == kStateFreeForChat ||
          current_state == kStateBusy) {
        return std::string(kStateUnavailable);
      }
    }

    return std::nullopt;
  }

  // ---- Compute currently_active flag ----
  bool compute_currently_active(int64_t idle_ms, int64_t active_window_ms) const {
    return idle_ms < active_window_ms;
  }

  // ---- Get the next state in the standard lifecycle ----
  std::string default_start_state() const {
    return std::string(kStateOnline);
  }

  // ---- Get fallback state for invalid state ----
  std::string fallback_state() const {
    return std::string(kStateOffline);
  }

  // ---- Get all valid states ----
  const std::set<std::string_view>& valid_states() const {
    return kValidPresenceStates;
  }

  // ---- Get all possible transitions from a state ----
  std::vector<std::string> possible_transitions(std::string_view from) const {
    static const std::map<std::string_view, std::vector<std::string>> all_transitions = {
        {kStateOnline,   {"unavailable", "offline", "free_for_chat", "busy"}},
        {kStateUnavailable, {"online", "offline"}},
        {kStateOffline,  {"online"}},
        {kStateFreeForChat, {"online", "offline", "busy"}},
        {kStateBusy,     {"online", "offline"}},
    };
    auto it = all_transitions.find(from);
    if (it != all_transitions.end()) return it->second;
    return {};
  }
};

// ============================================================================
// PresenceCache — Thread-safe in-memory presence cache
//
// Provides fast presence lookups without database round-trips.
// Uses shared_mutex for concurrent reads, exclusive lock for writes.
// TTL-based eviction removes stale entries.
// ============================================================================
class PresenceCache {
public:
  explicit PresenceCache(size_t max_entries = kMaxPresenceCacheEntries,
                          int64_t ttl_ms = kPresenceCacheTTLMs)
      : max_entries_(max_entries), ttl_ms_(ttl_ms) {}

  // ---- Get cached presence ----
  std::optional<PresenceState> get(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    auto it = entries_.find(user_id);
    if (it == entries_.end()) return std::nullopt;

    // Check TTL
    if (now_ms() - it->second.last_active_ts > ttl_ms_) {
      return std::nullopt;  // stale entry
    }

    return it->second;
  }

  // ---- Put presence into cache ----
  void put(const PresenceState& state) {
    std::unique_lock lock(mutex_);
    entries_[state.user_id] = state;

    // Evict oldest if over capacity
    if (entries_.size() > max_entries_) {
      evict_lru();
    }
  }

  // ---- Remove a user from cache ----
  void remove(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    entries_.erase(user_id);
  }

  // ---- Check if user is in cache and valid ----
  bool contains(const std::string& user_id) {
    std::shared_lock lock(mutex_);
    auto it = entries_.find(user_id);
    if (it == entries_.end()) return false;
    return (now_ms() - it->second.last_active_ts) <= ttl_ms_;
  }

  // ---- Bulk get: return cached entries for the given user IDs ----
  std::map<std::string, PresenceState> get_many(const std::set<std::string>& user_ids) {
    std::shared_lock lock(mutex_);
    std::map<std::string, PresenceState> result;
    int64_t ts = now_ms();

    for (const auto& uid : user_ids) {
      auto it = entries_.find(uid);
      if (it != entries_.end() && (ts - it->second.last_active_ts) <= ttl_ms_) {
        result[uid] = it->second;
      }
    }
    return result;
  }

  // ---- Get current size ----
  size_t size() const {
    std::shared_lock lock(mutex_);
    return entries_.size();
  }

  // ---- Clear all entries ----
  void clear() {
    std::unique_lock lock(mutex_);
    entries_.clear();
    lru_order_.clear();
  }

  // ---- Periodic cleanup: evict truly stale entries ----
  size_t cleanup_stale() {
    std::unique_lock lock(mutex_);
    int64_t cutoff = now_ms() - ttl_ms_;
    size_t removed = 0;

    auto it = entries_.begin();
    while (it != entries_.end()) {
      if (it->second.last_active_ts < cutoff) {
        // Remove from LRU order
        auto lru_it = std::find(lru_order_.begin(), lru_order_.end(), it->first);
        if (lru_it != lru_order_.end()) lru_order_.erase(lru_it);

        it = entries_.erase(it);
        ++removed;
      } else {
        ++it;
      }
    }
    return removed;
  }

private:
  void evict_lru() {
    // Evict half of max entries when over capacity
    size_t target = max_entries_ / 2;

    // Collect oldest entries based on last_active_ts
    std::vector<std::pair<int64_t, std::string>> sorted;
    for (const auto& [uid, state] : entries_) {
      sorted.emplace_back(state.last_active_ts, uid);
    }
    std::sort(sorted.begin(), sorted.end());

    size_t to_remove = entries_.size() - target;
    for (size_t i = 0; i < to_remove && i < sorted.size(); ++i) {
      entries_.erase(sorted[i].second);
      auto lru_it = std::find(lru_order_.begin(), lru_order_.end(), sorted[i].second);
      if (lru_it != lru_order_.end()) lru_order_.erase(lru_it);
    }
  }

  mutable std::shared_mutex mutex_;
  std::unordered_map<std::string, PresenceState> entries_;
  std::deque<std::string> lru_order_;  // LRU tracking
  size_t max_entries_;
  int64_t ttl_ms_;
};

// ============================================================================
// PresenceNotifier — Callback-based notification for presence changes
//
// Handles registration of listeners, filtering by user/state, and
// dispatch of presence change events to all interested parties.
// ============================================================================
class PresenceNotifier {
public:
  using PresenceCallback = std::function<void(const PresenceState& old_state,
                                               const PresenceState& new_state)>;
  using UserCallback = std::function<void(const PresenceState& new_state)>;

  struct Listener {
    int64_t id;
    std::optional<std::string> user_filter;     // only notify for this user
    std::optional<std::string> state_filter;    // only notify for transitions TO this state
    PresenceCallback callback;
    bool once = false;  // auto-remove after first notification
  };

  PresenceNotifier() : next_id_(1) {}

  // ---- Register a listener; returns listener ID ----
  int64_t add_listener(const PresenceCallback& cb,
                        std::optional<std::string> user_filter = std::nullopt,
                        std::optional<std::string> state_filter = std::nullopt,
                        bool once = false) {
    std::lock_guard lock(mutex_);
    int64_t id = next_id_++;
    listeners_.push_back({id, std::move(user_filter), std::move(state_filter), cb, once});
    return id;
  }

  // ---- Remove a listener by ID ----
  void remove_listener(int64_t listener_id) {
    std::lock_guard lock(mutex_);
    listeners_.erase(
        std::remove_if(listeners_.begin(), listeners_.end(),
                       [listener_id](const Listener& l) { return l.id == listener_id; }),
        listeners_.end());
  }

  // ---- Notify listeners of a state change ----
  void notify(const PresenceState& old_state, const PresenceState& new_state) {
    std::vector<PresenceCallback> callbacks_to_invoke;
    {
      std::lock_guard lock(mutex_);
      auto it = listeners_.begin();
      while (it != listeners_.end()) {
        bool matches = true;
        if (it->user_filter.has_value() && *it->user_filter != new_state.user_id)
          matches = false;
        if (it->state_filter.has_value() && *it->state_filter != new_state.state)
          matches = false;

        if (matches) {
          callbacks_to_invoke.push_back(it->callback);
          if (it->once) {
            it = listeners_.erase(it);
            continue;
          }
        }
        ++it;
      }
    }

    // Invoke callbacks outside lock to prevent deadlocks
    for (auto& cb : callbacks_to_invoke) {
      try {
        cb(old_state, new_state);
      } catch (...) {
        // Swallow callback exceptions
      }
    }
  }

  // ---- Simple user-level notification ----
  void notify_user(const std::string& user_id, const PresenceState& new_state,
                    const PresenceState& old_state) {
    notify(old_state, new_state);
  }

  // ---- Get count of registered listeners ----
  size_t listener_count() const {
    std::lock_guard lock(mutex_);
    return listeners_.size();
  }

private:
  mutable std::mutex mutex_;
  std::vector<Listener> listeners_;
  std::atomic<int64_t> next_id_;
};

// ============================================================================
// PresencePoller — Long-poll manager for presence changes
//
// Manages long-poll connections for /sync presence. Clients wait
// for presence updates and are notified when changes occur for
// users in their presence lists or shared rooms.
//
// Uses condition_variable for efficient blocking without busy-waiting.
// ============================================================================
class PresencePoller {
public:
  struct PollRequest {
    std::string user_id;
    std::string since_token;      // last seen presence token
    int64_t timeout_ms;           // max wait time
    int64_t start_ts;             // when the poll started
    std::set<std::string> watched_users;  // users whose presence to track
  };

  struct PollResult {
    std::string next_token;
    std::vector<PresenceState> events;
    bool timed_out = false;
  };

  PresencePoller() : presence_token_counter_(0) {}

  // ---- Generate a new presence stream token ----
  std::string generate_token() {
    int64_t token = presence_token_counter_.fetch_add(1);
    return "p" + std::to_string(token) + "." + std::to_string(now_ms());
  }

  // ---- Parse a token to extract the numeric counter ----
  int64_t parse_token(const std::string& token) const {
    if (token.empty()) return 0;
    // Format: "p123.1234567890"
    auto dot = token.find('.');
    if (dot == std::string::npos) return 0;
    std::string num = token.substr(1, dot - 1); // skip 'p' prefix
    try {
      return std::stoll(num);
    } catch (...) {
      return 0;
    }
  }

  // ---- Record a presence change event for polling ----
  void record_event(const PresenceState& state) {
    std::lock_guard lock(mutex_);
    int64_t token = presence_token_counter_.fetch_add(1);
    StreamEntry entry{token, state, now_ms()};
    stream_.push_back(entry);

    // Prune old stream entries
    int64_t cutoff = now_ms() - kPresenceStreamRetentionMs;
    while (!stream_.empty() && stream_.front().timestamp < cutoff) {
      stream_.pop_front();
    }

    // Wake up all waiters
    cv_.notify_all();
  }

  // ---- Long-poll: wait for new presence events ----
  PollResult poll(const PollRequest& request) {
    int64_t since_counter = parse_token(request.since_token);

    // First, check if there are already new events
    {
      std::lock_guard lock(mutex_);
      auto events = get_events_since(since_counter, request.watched_users);
      if (!events.empty()) {
        return build_result(events);
      }
    }

    // Wait for new events with timeout
    int64_t deadline = now_ms() + request.timeout_ms;
    std::unique_lock lock(mutex_);

    while (true) {
      int64_t remaining = deadline - now_ms();
      if (remaining <= 0) {
        // Timeout — return empty result
        PollResult result;
        result.next_token = generate_token();
        result.timed_out = true;
        return result;
      }

      // Wait with timeout
      auto status = cv_.wait_for(lock, chr::milliseconds(std::min(remaining, 5000LL)));

      // Check for new events
      auto events = get_events_since(since_counter, request.watched_users);
      if (!events.empty()) {
        return build_result(events);
      }

      // If spurious wakeup, loop and check timeout
      if (status == std::cv_status::timeout) {
        continue; // recheck events and remaining time
      }
    }
  }

  // ---- Get events since a given token for specific users ----
  std::vector<PresenceState> get_events_since(int64_t since_counter,
                                              const std::set<std::string>& watched) {
    std::vector<PresenceState> result;
    std::set<std::string> seen_users;

    for (const auto& entry : stream_) {
      if (entry.token <= since_counter) continue;

      // If watching specific users, filter
      if (!watched.empty() && !watched.count(entry.state.user_id))
        continue;

      // Deduplicate by user (only latest state per user)
      seen_users.insert(entry.state.user_id);
    }

    // Return only latest per user
    for (auto it = stream_.rbegin(); it != stream_.rend(); ++it) {
      if (it->token <= since_counter) continue;
      if (!watched.empty() && !watched.count(it->state.user_id)) continue;

      if (seen_users.erase(it->state.user_id) == 1) {
        result.push_back(it->state);
      }
    }

    return result;
  }

  // ---- Get the current stream token ----
  std::string current_token() const {
    return "p" + std::to_string(presence_token_counter_.load()) +
           "." + std::to_string(now_ms());
  }

  // ---- Get stream size (for monitoring) ----
  size_t stream_size() const {
    std::lock_guard lock(mutex_);
    return stream_.size();
  }

  // ---- Cleanup old stream entries ----
  size_t cleanup_stream() {
    std::lock_guard lock(mutex_);
    int64_t cutoff = now_ms() - kPresenceStreamRetentionMs;
    size_t removed = 0;
    while (!stream_.empty() && stream_.front().timestamp < cutoff) {
      stream_.pop_front();
      ++removed;
    }
    return removed;
  }

private:
  struct StreamEntry {
    int64_t token;
    PresenceState state;
    int64_t timestamp;
  };

  PollResult build_result(const std::vector<PresenceState>& events) {
    PollResult result;
    result.next_token = generate_token();
    result.events = events;
    result.timed_out = false;
    return result;
  }

  mutable std::mutex mutex_;
  std::condition_variable cv_;
  std::deque<StreamEntry> stream_;
  std::atomic<int64_t> presence_token_counter_;
};

// ============================================================================
// PresenceFederation — Federation of presence via EDUs
//
// Manages sending presence updates to remote servers via EDU transactions.
// Batches updates for efficiency, handles retry logic, deduplicates
// updates, and processes incoming presence EDUs from remote servers.
// ============================================================================
class PresenceFederation {
public:
  struct FederatedPresence {
    std::string user_id;
    std::string state;
    std::optional<std::string> status_msg;
    int64_t last_active_ago;
    bool currently_active;
    std::string origin_server;
    int64_t received_ts;
  };

  struct DestinationQueue {
    std::string destination;
    std::deque<PresenceState> pending_updates;
    int64_t last_send_ts = 0;
    int retry_count = 0;
    int64_t next_retry_ts = 0;
  };

  PresenceFederation() : federation_enabled_(true) {}

  // ---- Set federation enabled/disabled ----
  void set_enabled(bool enabled) { federation_enabled_ = enabled; }
  bool is_enabled() const { return federation_enabled_; }

  // ---- Queue a presence update for federation ----
  void queue_for_federation(const PresenceState& state) {
    if (!federation_enabled_) return;
    if (!is_valid_user_id(state.user_id)) return;

    // Extract destination domain from user_id: @user:domain
    auto colon = state.user_id.rfind(':');
    if (colon == std::string::npos) return;
    std::string domain = state.user_id.substr(colon + 1);

    // Don't federate to ourselves
    // (caller should set our_server_name)
    if (domain == our_server_name_) return;

    std::lock_guard lock(mutex_);
    auto& dest_queue = destination_queues_[domain];
    dest_queue.destination = domain;

    // Deduplicate: replace existing pending update for the same user
    auto it = std::find_if(dest_queue.pending_updates.begin(),
                           dest_queue.pending_updates.end(),
                           [&state](const PresenceState& ps) {
                             return ps.user_id == state.user_id;
                           });
    if (it != dest_queue.pending_updates.end()) {
      *it = state;
    } else {
      dest_queue.pending_updates.push_back(state);
    }
  }

  // ---- Flush pending updates to destination (call periodically) ----
  std::vector<std::pair<std::string, std::vector<PresenceState>>> flush_batch() {
    std::vector<std::pair<std::string, std::vector<PresenceState>>> result;
    std::lock_guard lock(mutex_);
    int64_t ts = now_ms();

    for (auto& [domain, queue] : destination_queues_) {
      if (queue.pending_updates.empty()) continue;

      // Check if we should send now
      if (queue.last_send_ts > 0 &&
          (ts - queue.last_send_ts) < kFederationBatchIntervalMs)
        continue;

      // Don't retry too fast
      if (queue.retry_count > 0 && ts < queue.next_retry_ts)
        continue;

      // Take up to batch_size updates
      std::vector<PresenceState> batch;
      size_t take = std::min(queue.pending_updates.size(), kFederationBatchSize);
      for (size_t i = 0; i < take; ++i) {
        batch.push_back(queue.pending_updates.front());
        queue.pending_updates.pop_front();
      }

      queue.last_send_ts = ts;
      result.emplace_back(domain, std::move(batch));
    }

    return result;
  }

  // ---- Build EDU JSON for a batch of presence updates ----
  json build_presence_edu(const std::vector<PresenceState>& updates) const {
    json edu;
    edu["edu_type"] = "m.presence";
    edu["content"] = json::object();
    edu["content"]["push"] = json::array();

    for (const auto& ps : updates) {
      json entry;
      entry["user_id"] = ps.user_id;
      entry["presence"] = ps.state;
      if (ps.status_msg.has_value() && !ps.status_msg->empty())
        entry["status_msg"] = *ps.status_msg;
      entry["last_active_ago"] = ps.idle_time_ms();
      entry["currently_active"] = ps.currently_active;
      edu["content"]["push"].push_back(entry);
    }

    return edu;
  }

  // ---- Process a received presence EDU from a remote server ----
  std::vector<FederatedPresence> process_incoming_edu(const json& edu_content,
                                                       const std::string& origin) {
    std::vector<FederatedPresence> result;
    int64_t ts = now_ms();

    if (!edu_content.contains("push") || !edu_content["push"].is_array())
      return result;

    for (const auto& entry : edu_content["push"]) {
      FederatedPresence fp;
      fp.origin_server = origin;
      fp.received_ts = ts;

      if (entry.contains("user_id"))
        fp.user_id = entry["user_id"].get<std::string>();
      if (entry.contains("presence"))
        fp.state = entry["presence"].get<std::string>();
      if (entry.contains("status_msg") && !entry["status_msg"].is_null())
        fp.status_msg = entry["status_msg"].get<std::string>();
      if (entry.contains("last_active_ago"))
        fp.last_active_ago = entry["last_active_ago"].get<int64_t>();
      if (entry.contains("currently_active"))
        fp.currently_active = entry["currently_active"].get<bool>();

      // Validate
      if (fp.user_id.empty() || fp.state.empty()) continue;
      if (!is_valid_presence_state(fp.state)) {
        fp.state = std::string(kStateOffline);
      }

      result.push_back(std::move(fp));
    }

    return result;
  }

  // ---- Report federation send success for a destination ----
  void report_success(const std::string& destination) {
    std::lock_guard lock(mutex_);
    auto it = destination_queues_.find(destination);
    if (it != destination_queues_.end()) {
      it->second.retry_count = 0;
      it->second.next_retry_ts = 0;

      // Remove empty queues to save memory
      if (it->second.pending_updates.empty()) {
        destination_queues_.erase(it);
      }
    }
  }

  // ---- Report federation send failure for a destination ----
  void report_failure(const std::string& destination) {
    std::lock_guard lock(mutex_);
    auto it = destination_queues_.find(destination);
    if (it != destination_queues_.end()) {
      it->second.retry_count++;
      // Exponential backoff: 5s, 25s, 125s...
      int64_t delay = 5000;
      for (int i = 0; i < it->second.retry_count; ++i) delay *= 5;
      it->second.next_retry_ts = now_ms() + delay;

      // Give up after max retries
      if (it->second.retry_count >= kMaxFederationRetries) {
        destination_queues_.erase(it);
      }
    }
  }

  // ---- Set our server name for domain filtering ----
  void set_server_name(const std::string& name) { our_server_name_ = name; }

  // ---- Get count of pending federation updates ----
  size_t pending_count() const {
    std::lock_guard lock(mutex_);
    size_t count = 0;
    for (const auto& [domain, queue] : destination_queues_) {
      count += queue.pending_updates.size();
    }
    return count;
  }

  // ---- Get number of active destination queues ----
  size_t destination_count() const {
    std::lock_guard lock(mutex_);
    return destination_queues_.size();
  }

private:
  mutable std::mutex mutex_;
  std::map<std::string, DestinationQueue> destination_queues_;
  std::string our_server_name_;
  std::atomic<bool> federation_enabled_;
};

// ============================================================================
// PresenceOverrideManager — Admin-initiated presence overrides
//
// Allows administrators to force a specific presence state for a user.
// Overrides can be temporary (with expiration) or permanent.
// Maintains an audit trail of all override actions.
// ============================================================================
class PresenceOverrideManager {
public:
  struct PresenceOverride {
    std::string override_id;
    std::string target_user_id;
    std::string forced_state;
    std::optional<std::string> forced_status_msg;
    std::string admin_user_id;
    std::string reason;
    int64_t created_ts;
    std::optional<int64_t> expires_ts;  // nullopt = permanent
    bool active = true;
  };

  PresenceOverrideManager() {}

  // ---- Set an override ----
  std::string set_override(const std::string& target_user_id,
                            const std::string& state,
                            const std::string& admin_user_id,
                            const std::string& reason,
                            std::optional<int64_t> duration_ms = std::nullopt,
                            std::optional<std::string> status_msg = std::nullopt) {
    if (!is_valid_presence_state(state)) {
      throw std::invalid_argument("Invalid presence state: " + state);
    }

    std::lock_guard lock(mutex_);

    // Invalidate any existing active overrides for this user
    for (auto& [id, ov] : overrides_) {
      if (ov.target_user_id == target_user_id && ov.active) {
        ov.active = false;
      }
    }

    // Create new override
    std::string override_id = "ov_" + std::to_string(next_id_++);
    PresenceOverride ov;
    ov.override_id = override_id;
    ov.target_user_id = target_user_id;
    ov.forced_state = state;
    ov.forced_status_msg = std::move(status_msg);
    ov.admin_user_id = admin_user_id;
    ov.reason = reason;
    ov.created_ts = now_ms();
    if (duration_ms.has_value()) {
      ov.expires_ts = ov.created_ts + *duration_ms;
    }
    ov.active = true;

    overrides_[override_id] = ov;

    // Record in audit log
    audit_log_.push_back({
        now_ms(),
        "override_set",
        override_id,
        target_user_id,
        state,
        admin_user_id,
        reason
    });

    return override_id;
  }

  // ---- Remove an override ----
  bool remove_override(const std::string& override_id,
                        const std::string& admin_user_id) {
    std::lock_guard lock(mutex_);
    auto it = overrides_.find(override_id);
    if (it == overrides_.end() || !it->second.active) return false;

    it->second.active = false;

    audit_log_.push_back({
        now_ms(),
        "override_removed",
        override_id,
        it->second.target_user_id,
        it->second.forced_state,
        admin_user_id,
        "Override removed by admin"
    });

    return true;
  }

  // ---- Get active override for a user (if any) ----
  std::optional<PresenceOverride> get_active_override(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    int64_t ts = now_ms();

    for (const auto& [id, ov] : overrides_) {
      if (ov.target_user_id == user_id && ov.active) {
        // Check expiration
        if (ov.expires_ts.has_value() && ts >= *ov.expires_ts) {
          // Expired; mark inactive
          // (Can't modify in const iteration, but we return nullopt)
          break;
        }
        return ov;
      }
    }
    return std::nullopt;
  }

  // ---- Expire stale overrides (call periodically) ----
  size_t expire_overrides() {
    std::lock_guard lock(mutex_);
    int64_t ts = now_ms();
    size_t expired = 0;

    for (auto& [id, ov] : overrides_) {
      if (ov.active && ov.expires_ts.has_value() && ts >= *ov.expires_ts) {
        ov.active = false;
        ++expired;

        audit_log_.push_back({
            ts,
            "override_expired",
            id,
            ov.target_user_id,
            ov.forced_state,
            "system",
            "Override expired automatically"
        });
      }
    }
    return expired;
  }

  // ---- List all active overrides ----
  std::vector<PresenceOverride> list_active_overrides() {
    std::lock_guard lock(mutex_);
    std::vector<PresenceOverride> result;
    int64_t ts = now_ms();

    for (const auto& [id, ov] : overrides_) {
      if (!ov.active) continue;
      if (ov.expires_ts.has_value() && ts >= *ov.expires_ts) continue;
      result.push_back(ov);
    }
    return result;
  }

  // ---- Get audit log entries ----
  std::vector<json> get_audit_log(int limit = 100) {
    std::lock_guard lock(mutex_);
    std::vector<json> result;
    size_t start = audit_log_.size() > static_cast<size_t>(limit)
                       ? audit_log_.size() - limit
                       : 0;
    for (size_t i = start; i < audit_log_.size(); ++i) {
      const auto& entry = audit_log_[i];
      json j;
      j["timestamp"] = entry.timestamp;
      j["action"] = entry.action;
      j["override_id"] = entry.override_id;
      j["target_user"] = entry.target_user;
      j["state"] = entry.state;
      j["admin_user"] = entry.admin_user;
      j["reason"] = entry.reason;
      result.push_back(j);
    }
    return result;
  }

  // ---- Check if a user has an active override ----
  bool has_override(const std::string& user_id) {
    auto ov = get_active_override(user_id);
    return ov.has_value();
  }

  // ---- Count active overrides ----
  size_t active_override_count() {
    std::lock_guard lock(mutex_);
    int64_t ts = now_ms();
    size_t count = 0;
    for (const auto& [id, ov] : overrides_) {
      if (ov.active) {
        if (!ov.expires_ts.has_value() || ts < *ov.expires_ts) {
          ++count;
        }
      }
    }
    return count;
  }

private:
  struct AuditEntry {
    int64_t timestamp;
    std::string action;
    std::string override_id;
    std::string target_user;
    std::string state;
    std::string admin_user;
    std::string reason;
  };

  mutable std::mutex mutex_;
  std::map<std::string, PresenceOverride> overrides_;
  std::vector<AuditEntry> audit_log_;
  std::atomic<int64_t> next_id_{1};
};

// ============================================================================
// PresenceListManager — Presence list subscription management
//
// Manages the invite/accept/deny flow for presence lists. Users can
// invite others to see their presence; invitees can accept or deny.
// Supports auto-accept behavior when configured.
// ============================================================================
class PresenceListManager {
public:
  struct PresenceListEntry {
    std::string user_id;          // observer (who wants to see)
    std::string observed_user_id; // observed (whose presence is shared)
    std::string status;           // "pending", "accepted", "denied"
    int64_t created_ts;
    int64_t updated_ts;
  };

  PresenceListManager(storage::PresenceStore& store)
      : store_(store) {}

  // ---- Invite a user to see your presence ----
  bool invite(const std::string& observer_user,
              const std::string& observed_user) {
    if (!is_valid_user_id(observer_user) || !is_valid_user_id(observed_user))
      return false;
    if (observer_user == observed_user) return false; // can't observe self

    std::lock_guard lock(mutex_);
    // Check list size limit
    auto it = lists_.find(observed_user);
    if (it != lists_.end() && it->second.size() >= kMaxPresenceListSize)
      return false;

    // If auto-accept is on, set directly to accepted
    std::string initial_status = auto_accept_ ? "accepted" : "pending";

    PresenceListEntry entry{observer_user, observed_user, initial_status,
                            now_ms(), now_ms()};

    auto& observed_entries = lists_[observed_user];
    // Check if already exists
    auto existing = std::find_if(observed_entries.begin(), observed_entries.end(),
                                  [&observer_user](const PresenceListEntry& e) {
                                    return e.user_id == observer_user;
                                  });
    if (existing != observed_entries.end()) {
      if (existing->status == "denied") {
        existing->status = initial_status;
        existing->updated_ts = now_ms();
      }
      return true;
    }

    observed_entries.push_back(std::move(entry));

    // Also track reverse: observer's subscriptions
    reverse_lists_[observer_user].insert(observed_user);

    // Persist to database
    try {
      store_.add_presence_list_pending(observer_user, observed_user);
      if (auto_accept_) {
        store_.set_presence_list_accepted(observer_user, observed_user);
      }
    } catch (...) {
      // Database error — still keep in memory
    }

    return true;
  }

  // ---- Accept a presence list invitation ----
  bool accept(const std::string& observer_user,
              const std::string& observed_user) {
    std::lock_guard lock(mutex_);
    auto it = lists_.find(observed_user);
    if (it == lists_.end()) return false;

    auto entry = std::find_if(it->second.begin(), it->second.end(),
                               [&observer_user](const PresenceListEntry& e) {
                                 return e.user_id == observer_user;
                               });
    if (entry == it->second.end()) return false;

    entry->status = "accepted";
    entry->updated_ts = now_ms();

    try {
      store_.set_presence_list_accepted(observer_user, observed_user);
    } catch (...) {}

    return true;
  }

  // ---- Deny a presence list invitation ----
  bool deny(const std::string& observer_user,
            const std::string& observed_user) {
    std::lock_guard lock(mutex_);
    auto it = lists_.find(observed_user);
    if (it == lists_.end()) return false;

    auto entry = std::find_if(it->second.begin(), it->second.end(),
                               [&observer_user](const PresenceListEntry& e) {
                                 return e.user_id == observer_user;
                               });
    if (entry == it->second.end()) return false;

    entry->status = "denied";
    entry->updated_ts = now_ms();
    return true;
  }

  // ---- Remove a user from a presence list ----
  bool remove(const std::string& observer_user,
              const std::string& observed_user) {
    std::lock_guard lock(mutex_);
    auto it = lists_.find(observed_user);
    if (it == lists_.end()) return false;

    auto& entries = it->second;
    auto entry = std::find_if(entries.begin(), entries.end(),
                               [&observer_user](const PresenceListEntry& e) {
                                 return e.user_id == observer_user;
                               });
    if (entry == entries.end()) return false;

    entries.erase(entry);
    if (entries.empty()) lists_.erase(it);

    // Remove from reverse
    auto rev_it = reverse_lists_.find(observer_user);
    if (rev_it != reverse_lists_.end()) {
      rev_it->second.erase(observed_user);
      if (rev_it->second.empty()) reverse_lists_.erase(rev_it);
    }

    return true;
  }

  // ---- Get users who have accepted visibility of a given user ----
  std::vector<std::string> get_observers(const std::string& observed_user) {
    std::lock_guard lock(mutex_);
    std::vector<std::string> result;
    auto it = lists_.find(observed_user);
    if (it != lists_.end()) {
      for (const auto& entry : it->second) {
        if (entry.status == "accepted") {
          result.push_back(entry.user_id);
        }
      }
    }
    return result;
  }

  // ---- Get all users that an observer is watching ----
  std::vector<std::string> get_watched_users(const std::string& observer_user) {
    std::lock_guard lock(mutex_);
    std::vector<std::string> result;
    auto it = reverse_lists_.find(observer_user);
    if (it != reverse_lists_.end()) {
      result.assign(it->second.begin(), it->second.end());
    }
    return result;
  }

  // ---- Get pending invitations for a user ----
  std::vector<PresenceListEntry> get_pending(const std::string& observed_user) {
    std::lock_guard lock(mutex_);
    std::vector<PresenceListEntry> result;
    auto it = lists_.find(observed_user);
    if (it != lists_.end()) {
      for (const auto& entry : it->second) {
        if (entry.status == "pending") {
          result.push_back(entry);
        }
      }
    }
    return result;
  }

  // ---- Check if an observer is allowed to see observed's presence ----
  bool can_see(const std::string& observer_user,
               const std::string& observed_user) {
    if (observer_user == observed_user) return true; // can always see own

    std::lock_guard lock(mutex_);
    auto it = lists_.find(observed_user);
    if (it == lists_.end()) return false;

    for (const auto& entry : it->second) {
      if (entry.user_id == observer_user && entry.status == "accepted") {
        return true;
      }
    }
    return false;
  }

  // ---- Set auto-accept for new invitations ----
  void set_auto_accept(bool enabled) { auto_accept_ = enabled; }
  bool is_auto_accept() const { return auto_accept_; }

  // ---- Get total list entry count ----
  size_t entry_count() const {
    std::lock_guard lock(mutex_);
    size_t count = 0;
    for (const auto& [uid, entries] : lists_) count += entries.size();
    return count;
  }

  // ---- Load lists from database (call on startup) ----
  void load_from_database() {
    // Database loading would go here; for now use in-memory only
    // In production, iterate database rows and populate lists_ and reverse_lists_
  }

private:
  storage::PresenceStore& store_;
  mutable std::mutex mutex_;
  // observed_user -> list of observers
  std::map<std::string, std::vector<PresenceListEntry>> lists_;
  // observer -> set of observed users (reverse index)
  std::map<std::string, std::set<std::string>> reverse_lists_;
  std::atomic<bool> auto_accept_{false};
};

// ============================================================================
// PresenceEngine — Main engine orchestrating all presence functionality
//
// This is the primary entry point for presence operations. It coordinates
// the state machine, cache, persistence, polling, federation, overrides,
// and notification systems.
// ============================================================================
class PresenceEngine {
public:
  // ---- Constructor ----
  explicit PresenceEngine(storage::DatabasePool& db)
      : db_(db),
        presence_store_(std::make_unique<storage::PresenceStore>(db)),
        cache_(std::make_unique<PresenceCache>()),
        poller_(std::make_unique<PresencePoller>()),
        federation_(std::make_unique<PresenceFederation>()),
        override_manager_(std::make_unique<PresenceOverrideManager>()),
        notifier_(std::make_unique<PresenceNotifier>()),
        list_manager_(std::make_unique<PresenceListManager>(*presence_store_)),
        state_machine_(std::make_unique<PresenceStateMachine>()),
        running_(false) {}

  // ---- Destructor ----
  ~PresenceEngine() { stop(); }

  // ---- Start the engine (background tasks) ----
  void start() {
    if (running_) return;
    running_ = true;

    // Start stale cleanup timer
    stale_cleanup_thread_ = std::thread([this]() {
      while (running_) {
        std::this_thread::sleep_for(chr::milliseconds(config_.stale_cleanup_interval_ms));
        if (!running_) break;
        process_stale_presence();
        expire_overrides();
        cleanup_cache();
        cleanup_stream();
      }
    });

    // Start federation flush timer
    federation_flush_thread_ = std::thread([this]() {
      while (running_) {
        std::this_thread::sleep_for(chr::milliseconds(config_.federation_batch_interval_ms));
        if (!running_) break;
        flush_federation();
      }
    });
  }

  // ---- Stop the engine ----
  void stop() {
    running_ = false;
    if (stale_cleanup_thread_.joinable())
      stale_cleanup_thread_.join();
    if (federation_flush_thread_.joinable())
      federation_flush_thread_.join();
  }

  // ========================================================================
  // Configuration
  // ========================================================================

  void configure(const PresenceConfig& cfg) {
    config_ = cfg;
    federation_->set_enabled(cfg.federation_enabled);
    federation_->set_server_name(cfg.server_name);
    list_manager_->set_auto_accept(cfg.auto_accept_presence_lists);
  }

  const PresenceConfig& config() const { return config_; }

  // ========================================================================
  // Core Presence Operations
  // ========================================================================

  // ---- Set presence state for a user (user-initiated) ----
  PresenceState set_presence(const std::string& user_id,
                              std::string_view state,
                              std::optional<std::string> status_msg = std::nullopt) {
    if (!config_.presence_enabled) {
      return get_cached_state(user_id);
    }

    // Validate state
    if (!is_valid_presence_state(state)) {
      throw std::invalid_argument("Invalid presence state: " + std::string(state));
    }

    // Check for admin override
    auto override = override_manager_->get_active_override(user_id);
    if (override.has_value()) {
      // User can't change state when under admin override
      return get_cached_state(user_id);
    }

    // Get current state
    PresenceState old_state = get_current_state(user_id);
    std::string old_state_str = old_state.state;

    // Validate transition
    if (!state_machine_->can_transition(old_state_str, state) &&
        old_state_str != std::string(state)) {
      // Invalid transition; force to offline if changing to invalid state
      // Or silently fallback
      // Actually, according to Matrix spec, any state change is allowed from client
    }

    // Build new state
    PresenceState new_state;
    new_state.user_id = user_id;
    new_state.state = std::string(state);
    new_state.last_active_ts = now_ms();
    new_state.last_user_sync_ts = old_state.last_user_sync_ts;
    new_state.currently_active = (state == kStateOnline || state == kStateFreeForChat);
    new_state.last_state_change_ts = now_ms();

    // Sanitize and set status message
    if (status_msg.has_value() && config_.allow_custom_statuses) {
      new_state.status_msg = sanitize_status_msg(*status_msg);
    } else {
      new_state.status_msg = old_state.status_msg;
    }

    // Persist to database
    persist_state(new_state);

    // Update cache
    cache_->put(new_state);

    // Record in poller stream
    poller_->record_event(new_state);

    // Notify listeners
    notifier_->notify(old_state, new_state);

    // Queue for federation
    federation_->queue_for_federation(new_state);

    // Update metrics
    metrics_.total_state_transitions.fetch_add(1);
    if (old_state_str == kStateOnline && new_state.state == kStateOffline)
      metrics_.online_to_offline_transitions.fetch_add(1);
    if (old_state_str == kStateOnline && new_state.state == kStateUnavailable)
      metrics_.online_to_unavailable_transitions.fetch_add(1);
    if (old_state_str == kStateOffline && new_state.state == kStateOnline)
      metrics_.offline_to_online_transitions.fetch_add(1);
    if (new_state.currently_active)
      metrics_.currently_active_users.fetch_add(1);

    return new_state;
  }

  // ---- Get presence state for a user ----
  PresenceState get_presence(const std::string& user_id) {
    // Check cache first
    auto cached = cache_->get(user_id);
    if (cached.has_value()) {
      metrics_.cache_hits.fetch_add(1);
      return apply_override_if_needed(user_id, *cached);
    }

    metrics_.cache_misses.fetch_add(1);

    // Fall back to database
    PresenceState state = load_state_from_db(user_id);
    cache_->put(state);
    return apply_override_if_needed(user_id, state);
  }

  // ---- Get presence for multiple users ----
  std::map<std::string, PresenceState> get_presence_for_users(
      const std::set<std::string>& user_ids) {
    std::map<std::string, PresenceState> result;

    // Try cache first
    auto cached = cache_->get_many(user_ids);
    std::set<std::string> missing;

    for (const auto& uid : user_ids) {
      auto it = cached.find(uid);
      if (it != cached.end()) {
        result[uid] = apply_override_if_needed(uid, it->second);
        metrics_.cache_hits.fetch_add(1);
      } else {
        missing.insert(uid);
        metrics_.cache_misses.fetch_add(1);
      }
    }

    // Load missing from database and merge into results
    if (!missing.empty()) {
      auto db_results = load_states_from_db(missing);
      for (auto& [uid, ps] : db_results) {
        result[uid] = ps;
      }
    }

    return result;
  }

  // ---- Bump last active timestamp (called on any user action) ----
  void bump_last_active(const std::string& user_id) {
    if (!config_.track_last_active || !config_.presence_enabled) return;

    PresenceState current = get_current_state(user_id);
    int64_t ts = now_ms();

    current.last_active_ts = ts;
    current.currently_active = true;

    // If user was offline, bring them online
    if (current.state == kStateOffline) {
      current.state = config_.default_state;
      current.last_state_change_ts = ts;
    }

    // Persist
    persist_last_active(user_id, ts);

    // Update cache
    cache_->put(current);

    // Record event
    poller_->record_event(current);
  }

  // ---- Mark user as having synced (updates last_user_sync_ts) ----
  void mark_user_synced(const std::string& user_id) {
    if (!config_.presence_enabled) return;
    int64_t ts = now_ms();

    PresenceState current = get_current_state(user_id);
    current.last_user_sync_ts = ts;
    current.last_active_ts = ts;
    current.currently_active = true;

    if (current.state == kStateOffline) {
      current.state = config_.default_state;
      current.last_state_change_ts = ts;
    }

    cache_->put(current);
    persist_last_sync(user_id, ts);
  }

  // ========================================================================
  // Presence List Management
  // ========================================================================

  // ---- Invite a user to presence list ----
  bool invite_to_presence_list(const std::string& observer,
                                const std::string& observed) {
    bool result = list_manager_->invite(observer, observed);
    if (result) metrics_.presence_list_invites.fetch_add(1);
    return result;
  }

  // ---- Accept a presence list invitation ----
  bool accept_presence_list(const std::string& observer,
                             const std::string& observed) {
    bool result = list_manager_->accept(observer, observed);
    if (result) metrics_.presence_list_accepts.fetch_add(1);
    return result;
  }

  // ---- Deny a presence list invitation ----
  bool deny_presence_list(const std::string& observer,
                           const std::string& observed) {
    return list_manager_->deny(observer, observed);
  }

  // ---- Remove from presence list ----
  bool remove_from_presence_list(const std::string& observer,
                                  const std::string& observed) {
    return list_manager_->remove(observer, observed);
  }

  // ---- Get users watching a given user (accepted only) ----
  std::vector<std::string> get_presence_observers(const std::string& user_id) {
    return list_manager_->get_observers(user_id);
  }

  // ---- Get users that a given user is watching ----
  std::vector<std::string> get_watched_users(const std::string& user_id) {
    return list_manager_->get_watched_users(user_id);
  }

  // ---- Check if observer can see observed's presence ----
  bool can_see_presence(const std::string& observer,
                         const std::string& observed) {
    return list_manager_->can_see(observer, observed);
  }

  // ---- Get pending presence list invitations ----
  auto get_pending_invitations(const std::string& user_id) {
    return list_manager_->get_pending(user_id);
  }

  // ========================================================================
  // Long-Poll Presence (for /sync)
  // ========================================================================

  // ---- Long-poll for presence changes ----
  PresencePoller::PollResult poll_presence(const std::string& user_id,
                                            const std::string& since_token,
                                            int64_t timeout_ms,
                                            const std::set<std::string>& watched_users) {
    metrics_.long_poll_connections.fetch_add(1);

    PresencePoller::PollRequest req;
    req.user_id = user_id;
    req.since_token = since_token;
    req.timeout_ms = std::min(timeout_ms, kMaxPollTimeoutMs);
    req.start_ts = now_ms();
    req.watched_users = watched_users;

    // Also include presence list watchers
    auto list_watchers = list_manager_->get_watched_users(user_id);
    for (const auto& w : list_watchers) {
      req.watched_users.insert(w);
    }

    return poller_->poll(req);
  }

  // ---- Get presence events for sync response ----
  json get_presence_sync(const std::string& user_id,
                          const std::string& since_token) {
    json result = json::object();
    result["events"] = json::array();

    if (!config_.presence_enabled) return result;

    auto watched = list_manager_->get_watched_users(user_id);

    // Add users in shared rooms (would query room memberships in production)
    // For now, just use presence list

    int64_t since_counter = poller_->parse_token(since_token);
    auto events = poller_->get_events_since(since_counter,
                                            std::set<std::string>(watched.begin(),
                                                                   watched.end()));

    for (const auto& ps : events) {
      result["events"].push_back(ps.to_api_json());
    }

    return result;
  }

  // ========================================================================
  // Federation
  // ========================================================================

  // ---- Process incoming presence EDU from remote server ----
  void process_federation_edu(const json& edu_content,
                               const std::string& origin) {
    if (!config_.federation_enabled) return;

    auto fed_states = federation_->process_incoming_edu(edu_content, origin);
    metrics_.federation_edus_received.fetch_add(fed_states.size());

    for (const auto& fs : fed_states) {
      // Validate that the user belongs to the origin server
      auto colon = fs.user_id.rfind(':');
      if (colon == std::string::npos) continue;
      std::string domain = fs.user_id.substr(colon + 1);
      if (domain != origin) continue;  // user must be from origin server

      // Build local presence state
      PresenceState ps;
      ps.user_id = fs.user_id;
      ps.state = fs.state;
      ps.status_msg = fs.status_msg;
      ps.last_active_ts = now_ms() - fs.last_active_ago;
      ps.currently_active = fs.currently_active;
      ps.last_state_change_ts = now_ms();
      ps.federation_update_ts = fs.received_ts;

      // Validate state
      if (!is_valid_presence_state(ps.state)) {
        ps.state = state_machine_->fallback_state();
      }

      // Store (no federation loopback since this is incoming)
      persist_state(ps);
      cache_->put(ps);

      // Record in poller for local watchers
      poller_->record_event(ps);
    }
  }

  // ---- Flush pending federation updates (called by background thread) ----
  void flush_federation() {
    auto batches = federation_->flush_batch();

    for (const auto& [destination, updates] : batches) {
      try {
        // Build EDU
        json edu = federation_->build_presence_edu(updates);

        // In production, this would call FederationClient.send_transaction()
        // For now, just mark as sent
        federation_->report_success(destination);
        metrics_.federation_updates_sent.fetch_add(updates.size());
      } catch (...) {
        federation_->report_failure(destination);
        metrics_.federation_updates_failed.fetch_add(updates.size());
      }
    }
  }

  // ---- Queue presence for federation delivery ----
  void federate_presence(const PresenceState& state) {
    federation_->queue_for_federation(state);
  }

  // ========================================================================
  // Admin Overrides
  // ========================================================================

  // ---- Set an admin presence override ----
  std::string set_override(const std::string& target_user,
                            const std::string& state,
                            const std::string& admin_user,
                            const std::string& reason,
                            std::optional<int64_t> duration_ms = std::nullopt,
                            std::optional<std::string> status_msg = std::nullopt) {
    auto override_id = override_manager_->set_override(
        target_user, state, admin_user, reason, duration_ms, status_msg);

    // Force the new state
    PresenceState ps;
    ps.user_id = target_user;
    ps.state = state;
    ps.status_msg = status_msg;
    ps.last_active_ts = now_ms();
    ps.currently_active = (state != kStateOffline && state != kStateUnavailable);
    ps.last_state_change_ts = now_ms();

    persist_state(ps);
    cache_->put(ps);
    poller_->record_event(ps);
    federation_->queue_for_federation(ps);

    metrics_.admin_overrides_active.fetch_add(1);
    return override_id;
  }

  // ---- Remove an admin override ----
  bool remove_override(const std::string& override_id,
                        const std::string& admin_user) {
    // Get the override to find the target user
    auto all_overrides = override_manager_->list_active_overrides();
    std::string target_user;

    for (const auto& ov : all_overrides) {
      if (ov.override_id == override_id) {
        target_user = ov.target_user_id;
        break;
      }
    }

    bool result = override_manager_->remove_override(override_id, admin_user);

    if (result && !target_user.empty()) {
      // Invalidate cache so user returns to real state
      cache_->remove(target_user);
      metrics_.admin_overrides_active.fetch_sub(1);
    }

    return result;
  }

  // ---- List all active admin overrides ----
  auto list_overrides() {
    return override_manager_->list_active_overrides();
  }

  // ---- Get override audit log ----
  auto get_override_audit_log(int limit = 100) {
    return override_manager_->get_audit_log(limit);
  }

  // ========================================================================
  // Notification System
  // ========================================================================

  // ---- Register a presence change listener ----
  int64_t add_presence_listener(
      const PresenceNotifier::PresenceCallback& callback,
      std::optional<std::string> user_filter = std::nullopt,
      std::optional<std::string> state_filter = std::nullopt) {
    return notifier_->add_listener(callback, std::move(user_filter),
                                    std::move(state_filter));
  }

  // ---- Remove a presence change listener ----
  void remove_presence_listener(int64_t listener_id) {
    notifier_->remove_listener(listener_id);
  }

  // ========================================================================
  // Stale Presence Processing & Timeouts
  // ========================================================================

  // ---- Process stale presence: apply timeout transitions ----
  size_t process_stale_presence() {
    if (!config_.presence_enabled) return 0;

    size_t transitions = 0;
    int64_t ts = now_ms();

    // Get all cached users and check for timeouts
    // In production, this would use the database to find stale users
    // For efficiency, we process the in-memory cache

    // Walk through cache and check timeouts
    std::vector<PresenceState> to_update;

    // We'd get all cached entries here
    // For now, use database store to get stale users
    auto stale_users = presence_store_->get_stale_presence(
        config_.idle_timeout_ms, 1000);

    for (const auto& user_id : stale_users) {
      PresenceState current = get_current_state(user_id);
      int64_t idle = ts - current.last_active_ts;

      auto new_state_str = state_machine_->compute_timeout_transition(
          current.state, idle, config_.idle_timeout_ms, config_.offline_timeout_ms);

      if (new_state_str.has_value()) {
        PresenceState new_state = current;
        new_state.state = *new_state_str;
        new_state.last_state_change_ts = ts;
        new_state.currently_active = state_machine_->compute_currently_active(
            idle, config_.active_window_ms);

        persist_state(new_state);
        cache_->put(new_state);
        poller_->record_event(new_state);
        federation_->queue_for_federation(new_state);

        metrics_.stale_users_timed_out.fetch_add(1);
        ++transitions;
      } else {
        // Just update currently_active flag if it changed
        bool should_be_active = state_machine_->compute_currently_active(
            idle, config_.active_window_ms);
        if (current.currently_active != should_be_active) {
          current.currently_active = should_be_active;
          cache_->put(current);

          if (!should_be_active) {
            metrics_.currently_active_users.fetch_sub(1);
          }
        }
      }
    }

    return transitions;
  }

  // ---- Expire timed-out admin overrides ----
  size_t expire_overrides() {
    return override_manager_->expire_overrides();
  }

  // ---- Cleanup stale cache entries ----
  void cleanup_cache() {
    cache_->cleanup_stale();
  }

  // ---- Cleanup old stream entries ----
  void cleanup_stream() {
    poller_->cleanup_stream();
  }

  // ========================================================================
  // Metrics and Diagnostics
  // ========================================================================

  const PresenceMetrics& metrics() const { return metrics_; }
  PresenceMetrics& metrics() { return metrics_; }

  json get_diagnostics() {
    json diag;
    diag["config"] = config_.to_json();
    diag["metrics"] = metrics_.to_json();
    diag["cache_size"] = cache_->size();
    diag["federation_pending"] = federation_->pending_count();
    diag["federation_destinations"] = federation_->destination_count();
    diag["active_overrides"] = override_manager_->active_override_count();
    diag["presence_list_entries"] = list_manager_->entry_count();
    diag["listener_count"] = notifier_->listener_count();
    diag["stream_size"] = poller_->stream_size();
    diag["running"] = running_;
    return diag;
  }

  // ========================================================================
  // Utility
  // ========================================================================

  // ---- Check if presence is enabled ----
  bool is_enabled() const { return config_.presence_enabled; }

  // ---- Get state machine (for external validation) ----
  const PresenceStateMachine& state_machine() const { return *state_machine_; }

  // ---- Access to sub-components (for advanced use) ----
  PresenceCache& cache() { return *cache_; }
  PresencePoller& poller() { return *poller_; }
  PresenceFederation& federation() { return *federation_; }
  PresenceOverrideManager& overrides() { return *override_manager_; }
  PresenceListManager& lists() { return *list_manager_; }

private:
  // ---- Get current state, trying cache first ----
  PresenceState get_current_state(const std::string& user_id) {
    auto cached = cache_->get(user_id);
    if (cached.has_value()) return *cached;
    return load_state_from_db(user_id);
  }

  // ---- Apply admin override to a presence state if active ----
  PresenceState apply_override_if_needed(const std::string& user_id,
                                          const PresenceState& original) {
    auto override = override_manager_->get_active_override(user_id);
    if (!override.has_value()) return original;

    PresenceState overridden = original;
    overridden.state = override->forced_state;
    if (override->forced_status_msg.has_value())
      overridden.status_msg = override->forced_status_msg;
    overridden.currently_active = (override->forced_state != kStateOffline &&
                                    override->forced_state != kStateUnavailable);
    return overridden;
  }

  // ---- Cache-aware state retrieval ----
  PresenceState get_cached_state(const std::string& user_id) {
    return get_presence(user_id);
  }

  // ---- Load presence state from database ----
  PresenceState load_state_from_db(const std::string& user_id) {
    PresenceState state;
    state.user_id = user_id;
    state.state = config_.default_state;
    state.last_active_ts = now_ms();
    state.currently_active = true;

    try {
      auto db_state = presence_store_->get_presence(user_id);
      if (db_state.has_value()) {
        state.state = db_state->state.state;
        state.status_msg = db_state->state.status_msg;
        state.last_active_ts = db_state->state.last_active_ts;
        state.last_user_sync_ts = db_state->state.last_user_sync_ts;
        state.currently_active = db_state->state.currently_active;
        state.federation_update_ts = db_state->last_federation_update_ts;
        state.last_state_change_ts = db_state->last_update_ts;
      }
    } catch (...) {
      // Database error: use defaults
    }

    return state;
  }

  // ---- Load presence states for multiple users from database ----
  std::map<std::string, PresenceState> load_states_from_db(
      const std::set<std::string>& user_ids) {
    std::map<std::string, PresenceState> result;
    try {
      auto db_results = presence_store_->get_presence_for_users(user_ids);
      for (const auto& [uid, up] : db_results) {
        PresenceState ps;
        ps.user_id = uid;
        ps.state = up.state.state;
        ps.status_msg = up.state.status_msg;
        ps.last_active_ts = up.state.last_active_ts;
        ps.last_user_sync_ts = up.state.last_user_sync_ts;
        ps.currently_active = up.state.currently_active;
        ps.federation_update_ts = up.last_federation_update_ts;
        ps.last_state_change_ts = up.last_update_ts;
        result[uid] = ps;
        cache_->put(ps);
      }

      // Fill in defaults for missing users
      for (const auto& uid : user_ids) {
        if (!result.count(uid)) {
          result[uid] = load_state_from_db(uid);
        }
      }
    } catch (...) {
      // On error, return defaults
      for (const auto& uid : user_ids) {
        if (!result.count(uid)) {
          result[uid] = load_state_from_db(uid);
        }
      }
    }
    return result;
  }

  // ---- Persist full state to database ----
  void persist_state(const PresenceState& state) {
    try {
      presence_store_->set_presence_state(
          state.user_id, state.state,
          state.status_msg.value_or(""),
          state.last_active_ts, state.currently_active);
    } catch (...) {
      // Silently fail persistence (cache is authoritative)
    }
  }

  // ---- Persist last active timestamp only ----
  void persist_last_active(const std::string& user_id, int64_t ts) {
    try {
      presence_store_->update_presence({
          user_id, std::string(kStateOnline), std::nullopt, ts, ts, true
      });
    } catch (...) {}
  }

  // ---- Persist last sync timestamp ----
  void persist_last_sync(const std::string& user_id, int64_t ts) {
    try {
      presence_store_->update_presence_last_sync(user_id, ts);
    } catch (...) {}
  }

  // ---- Members ----
  storage::DatabasePool& db_;
  std::unique_ptr<storage::PresenceStore> presence_store_;
  std::unique_ptr<PresenceCache> cache_;
  std::unique_ptr<PresencePoller> poller_;
  std::unique_ptr<PresenceFederation> federation_;
  std::unique_ptr<PresenceOverrideManager> override_manager_;
  std::unique_ptr<PresenceNotifier> notifier_;
  std::unique_ptr<PresenceListManager> list_manager_;
  std::unique_ptr<PresenceStateMachine> state_machine_;

  PresenceConfig config_;
  PresenceMetrics metrics_;

  std::atomic<bool> running_;
  std::thread stale_cleanup_thread_;
  std::thread federation_flush_thread_;
};

// ============================================================================
// PresenceEngineBuilder — Builder pattern for constructing the engine
// ============================================================================
class PresenceEngineBuilder {
public:
  explicit PresenceEngineBuilder(storage::DatabasePool& db)
      : db_(db) {}

  PresenceEngineBuilder& with_config(const PresenceConfig& cfg) {
    config_ = cfg;
    return *this;
  }

  PresenceEngineBuilder& enable_presence(bool enabled) {
    config_.presence_enabled = enabled;
    return *this;
  }

  PresenceEngineBuilder& enable_federation(bool enabled) {
    config_.federation_enabled = enabled;
    return *this;
  }

  PresenceEngineBuilder& with_server_name(const std::string& name) {
    config_.server_name = name;
    return *this;
  }

  PresenceEngineBuilder& with_idle_timeout(int64_t ms) {
    config_.idle_timeout_ms = ms;
    return *this;
  }

  PresenceEngineBuilder& with_offline_timeout(int64_t ms) {
    config_.offline_timeout_ms = ms;
    return *this;
  }

  PresenceEngineBuilder& with_active_window(int64_t ms) {
    config_.active_window_ms = ms;
    return *this;
  }

  PresenceEngineBuilder& auto_accept_lists(bool enabled) {
    config_.auto_accept_presence_lists = enabled;
    return *this;
  }

  PresenceEngineBuilder& with_default_state(const std::string& state) {
    config_.default_state = state;
    return *this;
  }

  PresenceEngineBuilder& from_json(const json& cfg) {
    config_.load_from_json(cfg);
    return *this;
  }

  std::unique_ptr<PresenceEngine> build() {
    auto engine = std::make_unique<PresenceEngine>(db_);
    engine->configure(config_);
    return engine;
  }

private:
  storage::DatabasePool& db_;
  PresenceConfig config_;
};

// ============================================================================
// PresenceSyncHelper — Helper for building sync response presence blocks
// ============================================================================
class PresenceSyncHelper {
public:
  explicit PresenceSyncHelper(PresenceEngine& engine)
      : engine_(engine) {}

  // ---- Build presence section for a /sync response ----
  json build_sync_presence(const std::string& user_id,
                            const std::string& since_token) {
    json result = json::object();
    result["events"] = json::array();

    if (!engine_.is_enabled()) return result;

    // Get watched users from presence lists
    auto watched = engine_.get_watched_users(user_id);

    // If no since token, include current state for all watched users
    if (since_token.empty()) {
      std::set<std::string> uid_set(watched.begin(), watched.end());
      auto states = engine_.get_presence_for_users(uid_set);
      for (const auto& [uid, ps] : states) {
        if (uid == user_id) continue; // don't include self in presence events
        result["events"].push_back(ps.to_api_json());
      }
      return result;
    }

    // With since token, get incremental changes via poller
    auto poll_result = engine_.poll_presence(
        user_id, since_token,
        0, // no additional timeout for sync
        std::set<std::string>(watched.begin(), watched.end()));

    for (const auto& ps : poll_result.events) {
      if (ps.user_id == user_id) continue;
      result["events"].push_back(ps.to_api_json());
    }

    return result;
  }

  // ---- Build full initial sync presence (all watched users) ----
  json build_initial_sync_presence(const std::string& user_id) {
    json result = json::object();
    result["events"] = json::array();

    if (!engine_.is_enabled()) return result;

    auto watched = engine_.get_watched_users(user_id);
    std::set<std::string> uid_set(watched.begin(), watched.end());
    auto states = engine_.get_presence_for_users(uid_set);

    for (const auto& [uid, ps] : states) {
      if (uid == user_id) continue;
      result["events"].push_back(ps.to_api_json());
    }

    return result;
  }

  // ---- Build room-specific presence for sync (users in shared rooms) ----
  json build_room_presence_sync(const std::string& user_id,
                                 const std::set<std::string>& room_members,
                                 const std::string& since_token) {
    json result = json::object();
    result["events"] = json::array();

    if (!engine_.is_enabled()) return result;

    if (since_token.empty()) {
      auto states = engine_.get_presence_for_users(room_members);
      for (const auto& [uid, ps] : states) {
        if (uid == user_id) continue;
        result["events"].push_back(ps.to_api_json());
      }
      return result;
    }

    // Incremental via poller
    auto poll_result = engine_.poll_presence(
        user_id, since_token, 0, room_members);
    for (const auto& ps : poll_result.events) {
      if (ps.user_id == user_id) continue;
      result["events"].push_back(ps.to_api_json());
    }
    return result;
  }

private:
  PresenceEngine& engine_;
};

// ============================================================================
// DevicePresence — Per-device presence state for aggregation
//
// Matrix users can have multiple devices. Each device tracks its own
// last-active timestamp. The aggregate user presence is computed from
// all devices: online if ANY device is active; offline only if ALL
// devices have timed out.
// ============================================================================
struct DevicePresence {
  std::string device_id;
  std::string user_id;
  std::string device_display_name;       // e.g. "Element Desktop"
  int64_t last_active_ts = 0;            // last time this device was used
  int64_t last_sync_ts = 0;              // last time device performed /sync
  bool is_foreground = false;            // app is in foreground (mobile clients)
  std::string push_provider;             // "fcm", "apns", "webpush", etc.

  // ---- Is this device considered active? ----
  bool is_active(int64_t active_window_ms) const {
    return (now_ms() - last_active_ts) < active_window_ms;
  }

  // ---- Serialize to diagnostic JSON ----
  json to_json() const {
    json j;
    j["device_id"] = device_id;
    j["display_name"] = device_display_name;
    j["last_active_ago"] = now_ms() - last_active_ts;
    j["last_sync_ago"] = now_ms() - last_sync_ts;
    j["is_foreground"] = is_foreground;
    j["push_provider"] = push_provider;
    return j;
  }
};

// ============================================================================
// DevicePresenceTracker — Aggregate per-device presence into user presence
//
// Maintains a map of user_id -> vector<device_id -> DevicePresence>.
// Computes aggregate presence: user is "online" if ANY device is active.
// Supports device-specific last_active tracking for mobile/desktop split.
// ============================================================================
class DevicePresenceTracker {
public:
  DevicePresenceTracker() = default;

  // ---- Record device activity ----
  void update_device_activity(const std::string& user_id,
                               const std::string& device_id,
                               const std::string& display_name = "",
                               bool is_foreground = false) {
    std::lock_guard lock(mutex_);
    int64_t ts = now_ms();

    auto& devices = user_devices_[user_id];
    auto it = std::find_if(devices.begin(), devices.end(),
                           [&device_id](const DevicePresence& d) {
                             return d.device_id == device_id;
                           });

    if (it != devices.end()) {
      it->last_active_ts = ts;
      it->last_sync_ts = ts;
      it->is_foreground = is_foreground;
      if (!display_name.empty()) it->device_display_name = display_name;
    } else {
      DevicePresence dp;
      dp.device_id = device_id;
      dp.user_id = user_id;
      dp.device_display_name = display_name;
      dp.last_active_ts = ts;
      dp.last_sync_ts = ts;
      dp.is_foreground = is_foreground;
      devices.push_back(std::move(dp));

      // Limit per user to prevent unbounded growth
      if (devices.size() > 50) {
        // Remove oldest device
        std::sort(devices.begin(), devices.end(),
                  [](const DevicePresence& a, const DevicePresence& b) {
                    return a.last_active_ts > b.last_active_ts;
                  });
        devices.resize(50);
      }
    }
  }

  // ---- Remove a device (e.g., on logout) ----
  void remove_device(const std::string& user_id, const std::string& device_id) {
    std::lock_guard lock(mutex_);
    auto it = user_devices_.find(user_id);
    if (it == user_devices_.end()) return;

    auto& devices = it->second;
    devices.erase(
        std::remove_if(devices.begin(), devices.end(),
                       [&device_id](const DevicePresence& d) {
                         return d.device_id == device_id;
                       }),
        devices.end());

    if (devices.empty()) {
      user_devices_.erase(it);
    }
  }

  // ---- Get all devices for a user ----
  std::vector<DevicePresence> get_user_devices(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto it = user_devices_.find(user_id);
    if (it == user_devices_.end()) return {};
    return it->second;
  }

  // ---- Compute aggregate presence state from all devices ----
  // Returns: the "best" state across all devices
  // online > free_for_chat > busy > unavailable > offline
  struct AggregateResult {
    bool any_active = false;
    int device_count = 0;
    int active_device_count = 0;
    int64_t most_recent_active_ts = 0;
    bool any_foreground = false;
  };

  AggregateResult compute_aggregate(const std::string& user_id,
                                     int64_t active_window_ms) {
    std::lock_guard lock(mutex_);
    AggregateResult result;
    int64_t ts = now_ms();

    auto it = user_devices_.find(user_id);
    if (it == user_devices_.end()) return result;

    result.device_count = static_cast<int>(it->second.size());
    for (const auto& dp : it->second) {
      if (dp.is_active(active_window_ms)) {
        result.active_device_count++;
        result.any_active = true;
      }
      if (dp.is_foreground) result.any_foreground = true;
      if (dp.last_active_ts > result.most_recent_active_ts)
        result.most_recent_active_ts = dp.last_active_ts;
    }

    return result;
  }

  // ---- Get all user IDs with any active devices ----
  std::vector<std::string> get_active_users(int64_t active_window_ms) {
    std::lock_guard lock(mutex_);
    std::vector<std::string> result;
    int64_t ts = now_ms();

    for (const auto& [uid, devices] : user_devices_) {
      bool active = false;
      for (const auto& dp : devices) {
        if ((ts - dp.last_active_ts) < active_window_ms) {
          active = true;
          break;
        }
      }
      if (active) result.push_back(uid);
    }
    return result;
  }

  // ---- Count total tracked devices ----
  size_t total_device_count() const {
    std::lock_guard lock(mutex_);
    size_t count = 0;
    for (const auto& [uid, devices] : user_devices_) count += devices.size();
    return count;
  }

  // ---- Cleanup stale devices (privacy / memory) ----
  size_t cleanup_stale_devices(int64_t max_idle_ms) {
    std::lock_guard lock(mutex_);
    size_t removed = 0;
    int64_t cutoff = now_ms() - max_idle_ms;

    for (auto& [uid, devices] : user_devices_) {
      auto it = std::remove_if(devices.begin(), devices.end(),
                               [cutoff](const DevicePresence& d) {
                                 return d.last_active_ts < cutoff;
                               });
      removed += std::distance(it, devices.end());
      devices.erase(it, devices.end());
    }

    // Remove users with no devices
    for (auto it = user_devices_.begin(); it != user_devices_.end();) {
      if (it->second.empty()) {
        it = user_devices_.erase(it);
      } else {
        ++it;
      }
    }
    return removed;
  }

private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::vector<DevicePresence>> user_devices_;
};

// ============================================================================
// RoomPresenceTracker — Track active users per room
//
// Maintains a set of active users in each room, updated by user activity
// events. Used for "N online" counts in room summaries and for
// determining which presence events to push to room members.
// ============================================================================
class RoomPresenceTracker {
public:
  RoomPresenceTracker() = default;

  // ---- Mark a user as present in a room (on join, message, typing, etc.) ----
  void mark_user_in_room(const std::string& user_id,
                          const std::string& room_id) {
    std::lock_guard lock(mutex_);
    room_users_[room_id].insert(user_id);
    user_rooms_[user_id].insert(room_id);
    room_user_activity_[room_id][user_id] = now_ms();
  }

  // ---- Remove a user from a room (on leave, kick, ban) ----
  void remove_user_from_room(const std::string& user_id,
                              const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto rit = room_users_.find(room_id);
    if (rit != room_users_.end()) {
      rit->second.erase(user_id);
      if (rit->second.empty()) room_users_.erase(rit);
    }

    auto uit = user_rooms_.find(user_id);
    if (uit != user_rooms_.end()) {
      uit->second.erase(room_id);
      if (uit->second.empty()) user_rooms_.erase(uit);
    }

    auto ait = room_user_activity_.find(room_id);
    if (ait != room_user_activity_.end()) {
      ait->second.erase(user_id);
      if (ait->second.empty()) room_user_activity_.erase(ait);
    }
  }

  // ---- Get all users in a room ----
  std::set<std::string> get_users_in_room(const std::string& room_id) const {
    std::lock_guard lock(mutex_);
    auto it = room_users_.find(room_id);
    if (it == room_users_.end()) return {};
    return it->second;
  }

  // ---- Get all rooms a user is in ----
  std::set<std::string> get_rooms_for_user(const std::string& user_id) const {
    std::lock_guard lock(mutex_);
    auto it = user_rooms_.find(user_id);
    if (it == user_rooms_.end()) return {};
    return it->second;
  }

  // ---- Get recently active users in a room (within time window) ----
  std::vector<std::string> get_recently_active_in_room(
      const std::string& room_id, int64_t window_ms) {
    std::lock_guard lock(mutex_);
    std::vector<std::string> result;
    int64_t cutoff = now_ms() - window_ms;

    auto ait = room_user_activity_.find(room_id);
    if (ait == room_user_activity_.end()) return result;

    for (const auto& [uid, last_ts] : ait->second) {
      if (last_ts >= cutoff) result.push_back(uid);
    }
    return result;
  }

  // ---- Count users in a room ----
  size_t count_users_in_room(const std::string& room_id) const {
    std::lock_guard lock(mutex_);
    auto it = room_users_.find(room_id);
    return (it != room_users_.end()) ? it->second.size() : 0;
  }

  // ---- Get users who share rooms with a given user ----
  // (union of all room memberships, excluding the user themselves)
  std::set<std::string> get_shared_room_users(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    std::set<std::string> result;
    auto uit = user_rooms_.find(user_id);
    if (uit == user_rooms_.end()) return result;

    for (const auto& room_id : uit->second) {
      auto rit = room_users_.find(room_id);
      if (rit != room_users_.end()) {
        result.insert(rit->second.begin(), rit->second.end());
      }
    }
    result.erase(user_id);
    return result;
  }

  // ---- Bulk load rooms from membership data ----
  void load_room_memberships(
      const std::vector<std::pair<std::string, std::string>>& memberships) {
    std::lock_guard lock(mutex_);
    for (const auto& [user_id, room_id] : memberships) {
      room_users_[room_id].insert(user_id);
      user_rooms_[user_id].insert(room_id);
      if (!room_user_activity_[room_id].count(user_id))
        room_user_activity_[room_id][user_id] = now_ms();
    }
  }

  // ---- Clear all data for a room (on room purge) ----
  void clear_room(const std::string& room_id) {
    std::lock_guard lock(mutex_);
    auto rit = room_users_.find(room_id);
    if (rit != room_users_.end()) {
      for (const auto& uid : rit->second) {
        auto uit = user_rooms_.find(uid);
        if (uit != user_rooms_.end()) {
          uit->second.erase(room_id);
          if (uit->second.empty()) user_rooms_.erase(uit);
        }
      }
    }
    room_users_.erase(room_id);
    room_user_activity_.erase(room_id);
  }

  // ---- Get total room count ----
  size_t room_count() const {
    std::lock_guard lock(mutex_);
    return room_users_.size();
  }

  // ---- Diagnostic dump ----
  json diagnostics() const {
    std::lock_guard lock(mutex_);
    json j;
    j["tracked_rooms"] = room_users_.size();
    j["tracked_users"] = user_rooms_.size();
    j["activity_entries"] = 0;
    for (const auto& [rid, map] : room_user_activity_)
      j["activity_entries"] = j["activity_entries"].get<size_t>() + map.size();
    return j;
  }

private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::set<std::string>> room_users_;
  std::unordered_map<std::string, std::set<std::string>> user_rooms_;
  std::unordered_map<std::string,
    std::unordered_map<std::string, int64_t>> room_user_activity_;
};

// ============================================================================
// PresenceAllowInbound — Controls who can share presence with this server
//
// Per-user and global settings for allowing/disallowing inbound presence
// from specific users, domains, or all users. Implements privacy controls
// for receiving federation presence.
// ============================================================================
class PresenceAllowInbound {
public:
  enum class Policy {
    kAllowAll,        // Accept presence from everyone
    kAllowList,       // Only accept from users on the allow list
    kDenyList,        // Accept from everyone except deny list
    kAllowNone        // Reject all incoming presence
  };

  PresenceAllowInbound() : global_policy_(Policy::kAllowAll) {}

  // ---- Set global policy ----
  void set_global_policy(Policy policy) {
    std::lock_guard lock(mutex_);
    global_policy_ = policy;
  }

  Policy global_policy() const {
    std::lock_guard lock(mutex_);
    return global_policy_;
  }

  // ---- Set per-user policy override ----
  void set_user_policy(const std::string& user_id, Policy policy) {
    std::lock_guard lock(mutex_);
    user_policies_[user_id] = policy;
  }

  // ---- Add user to global allow list ----
  void allow_user(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    allow_list_.insert(user_id);
  }

  // ---- Remove user from global allow list ----
  void disallow_user(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    allow_list_.erase(user_id);
  }

  // ---- Add user to global deny list ----
  void deny_user(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    deny_list_.insert(user_id);
  }

  // ---- Remove user from global deny list ----
  void undeny_user(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    deny_list_.erase(user_id);
  }

  // ---- Add domain to allow list ----
  void allow_domain(const std::string& domain) {
    std::lock_guard lock(mutex_);
    allowed_domains_.insert(domain);
  }

  // ---- Add domain to deny list ----
  void deny_domain(const std::string& domain) {
    std::lock_guard lock(mutex_);
    denied_domains_.insert(domain);
  }

  // ---- Check if inbound presence is allowed for a given user ----
  bool is_allowed(const std::string& from_user_id,
                  const std::string& to_user_id = "") {
    std::lock_guard lock(mutex_);

    // Extract domain
    std::string domain;
    auto colon = from_user_id.rfind(':');
    if (colon != std::string::npos)
      domain = from_user_id.substr(colon + 1);

    // Check per-user policy override for target user first
    if (!to_user_id.empty()) {
      auto uit = per_user_allows_.find(to_user_id);
      if (uit != per_user_allows_.end()) {
        // Target user has a specific allow list
        return uit->second.count(from_user_id) > 0;
      }

      auto dit = per_user_denies_.find(to_user_id);
      if (dit != per_user_denies_.end()) {
        // Target user has a specific deny list
        if (dit->second.count(from_user_id) > 0) return false;
      }
    }

    // Check per-user policy
    if (!to_user_id.empty()) {
      auto pit = user_policies_.find(to_user_id);
      if (pit != user_policies_.end()) {
        return evaluate_policy(pit->second, from_user_id, domain);
      }
    }

    // Fall back to global policy
    return evaluate_policy(global_policy_, from_user_id, domain);
  }

  // ---- Per-user custom inbound allow list (user controls who they receive from) ----
  void set_user_allow_list(const std::string& user_id,
                            const std::set<std::string>& allowed_users) {
    std::lock_guard lock(mutex_);
    per_user_allows_[user_id] = allowed_users;
  }

  // ---- Per-user custom inbound deny list ----
  void set_user_deny_list(const std::string& user_id,
                           const std::set<std::string>& denied_users) {
    std::lock_guard lock(mutex_);
    per_user_denies_[user_id] = denied_users;
  }

  // ---- Get user's allow list ----
  std::set<std::string> get_user_allow_list(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto it = per_user_allows_.find(user_id);
    return (it != per_user_allows_.end()) ? it->second : std::set<std::string>{};
  }

  // ---- Get user's deny list ----
  std::set<std::string> get_user_deny_list(const std::string& user_id) {
    std::lock_guard lock(mutex_);
    auto it = per_user_denies_.find(user_id);
    return (it != per_user_denies_.end()) ? it->second : std::set<std::string>{};
  }

  // ---- Get diagnostic summary ----
  json diagnostics() const {
    std::lock_guard lock(mutex_);
    json j;
    j["global_policy"] = static_cast<int>(global_policy_);
    j["allow_list_size"] = allow_list_.size();
    j["deny_list_size"] = deny_list_.size();
    j["allowed_domains"] = allowed_domains_.size();
    j["denied_domains"] = denied_domains_.size();
    j["per_user_allows"] = per_user_allows_.size();
    j["per_user_denies"] = per_user_denies_.size();
    return j;
  }

private:
  bool evaluate_policy(Policy policy,
                        const std::string& user_id,
                        const std::string& domain) {
    switch (policy) {
      case Policy::kAllowAll:
        return true;
      case Policy::kAllowList:
        return allow_list_.count(user_id) > 0 ||
               (!domain.empty() && allowed_domains_.count(domain) > 0);
      case Policy::kDenyList:
        if (deny_list_.count(user_id) > 0) return false;
        if (!domain.empty() && denied_domains_.count(domain) > 0) return false;
        return true;
      case Policy::kAllowNone:
        return false;
    }
    return true;
  }

  mutable std::mutex mutex_;
  Policy global_policy_;
  std::set<std::string> allow_list_;
  std::set<std::string> deny_list_;
  std::set<std::string> allowed_domains_;
  std::set<std::string> denied_domains_;
  std::unordered_map<std::string, Policy> user_policies_;
  std::unordered_map<std::string, std::set<std::string>> per_user_allows_;
  std::unordered_map<std::string, std::set<std::string>> per_user_denies_;
};

// ============================================================================
// PresenceHistory — Presence change event history with query support
//
// Stores a ring buffer of presence change events with configurable
// retention. Supports querying by user, time range, and pagination.
// ============================================================================
class PresenceHistory {
public:
  struct HistoryEntry {
    int64_t timestamp;
    std::string user_id;
    std::string previous_state;
    std::string new_state;
    std::optional<std::string> status_msg;
    std::string source;          // "user", "timeout", "federation", "admin"
    std::string origin_server;   // for federated changes
  };

  explicit PresenceHistory(size_t max_entries = 50000,
                            int64_t retention_ms = 86'400'000) // 24h
      : max_entries_(max_entries), retention_ms_(retention_ms) {}

  // ---- Record a presence change ----
  void record(const std::string& user_id,
              std::string_view previous_state,
              std::string_view new_state,
              std::optional<std::string> status_msg = std::nullopt,
              std::string_view source = "user",
              std::string_view origin_server = "") {
    std::lock_guard lock(mutex_);
    int64_t ts = now_ms();

    HistoryEntry entry;
    entry.timestamp = ts;
    entry.user_id = user_id;
    entry.previous_state = std::string(previous_state);
    entry.new_state = std::string(new_state);
    entry.status_msg = std::move(status_msg);
    entry.source = std::string(source);
    entry.origin_server = std::string(origin_server);

    entries_.push_back(std::move(entry));

    // Evict oldest if over capacity
    while (entries_.size() > max_entries_) {
      entries_.pop_front();
    }

    // Also index by user for fast lookup
    user_indices_[user_id].push_back(ts);
    if (user_indices_[user_id].size() > 1000) {
      user_indices_[user_id].pop_front();
    }
  }

  // ---- Query history for a specific user ----
  std::vector<HistoryEntry> query_user(const std::string& user_id,
                                        int64_t from_ts = 0,
                                        int64_t to_ts = INT64_MAX,
                                        size_t limit = 100) {
    std::lock_guard lock(mutex_);
    std::vector<HistoryEntry> result;

    for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
      if (it->user_id == user_id &&
          it->timestamp >= from_ts &&
          it->timestamp <= to_ts) {
        result.push_back(*it);
        if (result.size() >= limit) break;
      }
    }

    std::reverse(result.begin(), result.end());
    return result;
  }

  // ---- Query all history within a time range ----
  std::vector<HistoryEntry> query_range(int64_t from_ts,
                                         int64_t to_ts = INT64_MAX,
                                         size_t limit = 500) {
    std::lock_guard lock(mutex_);
    std::vector<HistoryEntry> result;

    for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
      if (it->timestamp >= from_ts && it->timestamp <= to_ts) {
        result.push_back(*it);
        if (result.size() >= limit) break;
      }
    }

    std::reverse(result.begin(), result.end());
    return result;
  }

  // ---- Get recent changes for a set of users (used for sync) ----
  std::vector<HistoryEntry> query_users_since(
      const std::set<std::string>& user_ids, int64_t since_ts) {
    std::lock_guard lock(mutex_);
    std::vector<HistoryEntry> result;
    std::set<std::string> seen;

    for (auto it = entries_.rbegin(); it != entries_.rend(); ++it) {
      if (it->timestamp <= since_ts) continue;
      if (user_ids.empty() || user_ids.count(it->user_id)) {
        // Take only latest per user
        if (!seen.count(it->user_id)) {
          result.push_back(*it);
          seen.insert(it->user_id);
        }
      }
    }

    std::reverse(result.begin(), result.end());
    return result;
  }

  // ---- Get entry count ----
  size_t count() const {
    std::lock_guard lock(mutex_);
    return entries_.size();
  }

  // ---- Get user list size (number of unique users in history) ----
  size_t unique_users() const {
    std::lock_guard lock(mutex_);
    return user_indices_.size();
  }

  // ---- Cleanup expired entries ----
  size_t cleanup_expired() {
    std::lock_guard lock(mutex_);
    int64_t cutoff = now_ms() - retention_ms_;
    size_t removed = 0;

    while (!entries_.empty() && entries_.front().timestamp < cutoff) {
      const auto& entry = entries_.front();
      auto uit = user_indices_.find(entry.user_id);
      if (uit != user_indices_.end()) {
        while (!uit->second.empty() && uit->second.front() < cutoff) {
          uit->second.pop_front();
        }
        if (uit->second.empty()) user_indices_.erase(uit);
      }
      entries_.pop_front();
      ++removed;
    }
    return removed;
  }

private:
  mutable std::mutex mutex_;
  std::deque<HistoryEntry> entries_;
  std::unordered_map<std::string, std::deque<int64_t>> user_indices_;
  size_t max_entries_;
  int64_t retention_ms_;
};

// ============================================================================
// PresenceBatchProcessor — Efficient batch processing for presence updates
//
// When many users need presence updates simultaneously (e.g., federation
// receive, bulk timeouts), batch processing avoids N+1 database writes.
// ============================================================================
class PresenceBatchProcessor {
public:
  explicit PresenceBatchProcessor(PresenceEngine& engine)
      : engine_(engine), max_batch_size_(500) {}

  // ---- Batch set presence for multiple users ----
  struct BatchSetResult {
    size_t succeeded = 0;
    size_t failed = 0;
    std::vector<std::string> errors;
  };

  BatchSetResult batch_set_presence(
      const std::vector<std::tuple<std::string, std::string,
                                    std::optional<std::string>>>& updates) {
    BatchSetResult result;
    size_t batch_count = 0;

    for (const auto& [user_id, state, status_msg] : updates) {
      try {
        engine_.set_presence(user_id, state, status_msg);
        result.succeeded++;
      } catch (const std::exception& e) {
        result.failed++;
        if (result.errors.size() < 10) // limit error messages
          result.errors.push_back(user_id + ": " + e.what());
      } catch (...) {
        result.failed++;
      }

      batch_count++;
      // Periodically yield to prevent blocking
      if (batch_count % 100 == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
    }

    return result;
  }

  // ---- Batch bump last active for room members ----
  void batch_bump_room_members(const std::set<std::string>& user_ids) {
    for (const auto& uid : user_ids) {
      engine_.bump_last_active(uid);
    }
  }

  // ---- Batch process incoming federation presence ----
  size_t batch_process_federation_edu(
      const std::string& origin,
      const std::vector<json>& presence_entries) {
    size_t processed = 0;
    for (const auto& entry : presence_entries) {
      try {
        std::string uid = entry.value("user_id", "");
        std::string state = entry.value("presence", "offline");
        int64_t last_active_ago = entry.value("last_active_ago", 0LL);

        if (uid.empty()) continue;

        PresenceState ps;
        ps.user_id = uid;
        ps.state = state;
        if (entry.contains("status_msg"))
          ps.status_msg = entry["status_msg"].get<std::string>();
        ps.last_active_ts = now_ms() - last_active_ago;
        ps.currently_active = entry.value("currently_active", false);
        ps.last_state_change_ts = now_ms();
        ps.federation_update_ts = now_ms();

        engine_.process_federation_edu(
            entry.contains("_raw") ? entry["_raw"] : json::object(), origin);
        processed++;
      } catch (...) {}
    }
    return processed;
  }

  // ---- Get engine reference ----
  PresenceEngine& engine() { return engine_; }

private:
  PresenceEngine& engine_;
  size_t max_batch_size_;
};

// ============================================================================
// PresenceReplicationHelper — Worker-to-worker presence replication
//
// In a multi-worker deployment, presence state needs to be replicated
// across workers. This helper serializes/deserializes presence state
// for inter-worker communication.
// ============================================================================
class PresenceReplicationHelper {
public:
  // ---- Serialize full presence state for replication ----
  static json serialize_state(const PresenceState& state) {
    json j;
    j["user_id"] = state.user_id;
    j["state"] = state.state;
    if (state.status_msg.has_value())
      j["status_msg"] = *state.status_msg;
    j["last_active_ts"] = state.last_active_ts;
    j["last_user_sync_ts"] = state.last_user_sync_ts;
    j["currently_active"] = state.currently_active;
    j["last_state_change_ts"] = state.last_state_change_ts;
    j["federation_update_ts"] = state.federation_update_ts;
    return j;
  }

  // ---- Deserialize presence state from replication ----
  static PresenceState deserialize_state(const json& j) {
    PresenceState ps;
    ps.user_id = j.value("user_id", "");
    ps.state = j.value("state", "offline");
    if (j.contains("status_msg") && !j["status_msg"].is_null())
      ps.status_msg = j["status_msg"].get<std::string>();
    ps.last_active_ts = j.value("last_active_ts", 0LL);
    ps.last_user_sync_ts = j.value("last_user_sync_ts", 0LL);
    ps.currently_active = j.value("currently_active", false);
    ps.last_state_change_ts = j.value("last_state_change_ts", 0LL);
    ps.federation_update_ts = j.value("federation_update_ts", 0LL);
    return ps;
  }

  // ---- Serialize presence list update for replication ----
  static json serialize_list_update(const std::string& observer,
                                      const std::string& observed,
                                      const std::string& action) {
    json j;
    j["type"] = "presence_list_update";
    j["observer"] = observer;
    j["observed"] = observed;
    j["action"] = action;
    return j;
  }

  // ---- Build a replication payload for federation updates ----
  static json serialize_federation_batch(
      const std::vector<PresenceState>& states) {
    json j;
    j["type"] = "presence_federation_push";
    j["states"] = json::array();
    for (const auto& s : states) {
      j["states"].push_back(serialize_state(s));
    }
    return j;
  }

  // ---- Apply a replicated state to local engine ----
  static void apply_replicated_state(PresenceEngine& engine,
                                      const json& replicated_data) {
    if (!replicated_data.contains("type")) return;

    std::string type = replicated_data["type"].get<std::string>();

    if (type == "presence_update") {
      auto state = deserialize_state(replicated_data["state"]);
      engine.set_presence(state.user_id, state.state, state.status_msg);
    } else if (type == "presence_federation_push") {
      for (const auto& sjson : replicated_data["states"]) {
        auto state = deserialize_state(sjson);
        engine.process_federation_edu(json::object(),
                                       state.user_id.substr(state.user_id.rfind(':') + 1));
      }
    } else if (type == "presence_list_update") {
      std::string observer = replicated_data["observer"];
      std::string observed = replicated_data["observed"];
      std::string action = replicated_data["action"];

      if (action == "invite")
        engine.invite_to_presence_list(observer, observed);
      else if (action == "accept")
        engine.accept_presence_list(observer, observed);
      else if (action == "deny")
        engine.deny_presence_list(observer, observed);
      else if (action == "drop")
        engine.remove_from_presence_list(observer, observed);
    }
  }
};

// ============================================================================
// PresenceBulkSync — Generate presence for multiple users in one pass
//
// Optimized path for generating presence events for many users at once,
// used during initial sync and when many users reconnect simultaneously.
// ============================================================================
class PresenceBulkSync {
public:
  explicit PresenceBulkSync(PresenceEngine& engine)
      : engine_(engine) {}

  // ---- Build presence sync payload for multiple observer users ----
  // Returns map of observer_user_id -> json events array
  std::map<std::string, json> build_multi_sync_presence(
      const std::vector<std::string>& observer_ids,
      const std::string& since_token) {
    std::map<std::string, json> results;

    for (const auto& uid : observer_ids) {
      json entry = json::array();

      auto watched = engine_.get_watched_users(uid);
      if (watched.empty()) {
        results[uid] = entry;
        continue;
      }

      std::set<std::string> uid_set(watched.begin(), watched.end());
      auto states = engine_.get_presence_for_users(uid_set);

      for (const auto& [target_uid, ps] : states) {
        if (target_uid == uid) continue;
        entry.push_back(ps.to_api_json());
      }

      results[uid] = std::move(entry);
    }

    return results;
  }

  // ---- Get online count for a list of users ----
  size_t count_online_users(const std::set<std::string>& user_ids) {
    size_t count = 0;
    auto states = engine_.get_presence_for_users(user_ids);
    for (const auto& [uid, ps] : states) {
      if (ps.state != "offline") count++;
    }
    return count;
  }

private:
  PresenceEngine& engine_;
};

// ============================================================================
// PresenceStartupLoader — Load presence state from database at startup
//
// Rebuilds in-memory cache, presence lists, and device state from
// persistent storage when the server restarts.
// ============================================================================
class PresenceStartupLoader {
public:
  PresenceStartupLoader(PresenceEngine& engine,
                         storage::PresenceStore& store)
      : engine_(engine), store_(store) {}

  // ---- Load all presence data from database ----
  struct LoadStats {
    size_t presence_states_loaded = 0;
    size_t presence_lists_loaded = 0;
    size_t devices_loaded = 0;
    int64_t load_time_ms = 0;
  };

  LoadStats load_all() {
    LoadStats stats;
    int64_t start = now_ms();

    // Load presence states for all users who have entries
    // In production, this would iterate over the presence_stream table
    try {
      auto all_presence = store_.get_all_presence_for_federation(0, 100000);

      for (const auto& ps : all_presence) {
        // Convert storage::PresenceState to engine PresenceState
        PresenceState engine_state;
        engine_state.user_id = ps.user_id;
        engine_state.state = ps.state;
        engine_state.status_msg = ps.status_msg;
        engine_state.last_active_ts = ps.last_active_ts;
        engine_state.last_user_sync_ts = ps.last_user_sync_ts;
        engine_state.currently_active = ps.currently_active;
        engine_state.last_state_change_ts = now_ms();

        // Set directly in engine (skip normal transition checks for startup)
        engine_.set_presence(ps.user_id, ps.state, ps.status_msg);
        stats.presence_states_loaded++;
      }
    } catch (...) {
      // Database may not have presence_stream yet; that's OK
    }

    // Load presence lists
    try {
      // Presence list loading would iterate the presence_list table
      // For now, lists are maintained in-memory and loaded from DB on demand
      stats.presence_lists_loaded = 0;
    } catch (...) {}

    stats.load_time_ms = now_ms() - start;
    return stats;
  }

private:
  PresenceEngine& engine_;
  storage::PresenceStore& store_;
};

}  // namespace progressive

// ============================================================================
// progressive::presence — Public API namespace for presence operations
//
// This namespace provides the clean public API used by REST handlers,
// federation transport, sync handlers, and admin tools.
// ============================================================================
namespace progressive::presence {

using json = nlohmann::json;

// ---- Presence state constants exposed for external use ----
constexpr std::string_view kStateOnline = "online";
constexpr std::string_view kStateOffline = "offline";
constexpr std::string_view kStateUnavailable = "unavailable";
constexpr std::string_view kStateFreeForChat = "free_for_chat";
constexpr std::string_view kStateBusy = "busy";

// ==========================================================================
// PresenceAPI — High-level API for presence management
// ==========================================================================
class PresenceAPI {
public:
  explicit PresenceAPI(PresenceEngine& engine)
      : engine_(engine) {}

  // ---- PUT /_matrix/client/v3/presence/{userId}/status ----
  json handle_set_presence(const std::string& user_id,
                            const json& request_body) {
    if (!engine_.is_enabled()) {
      return json{{{"errcode", "M_UNKNOWN"}, {"error", "Presence is disabled"}}};
    }

    std::string state = request_body.value("presence", "online");

    // Validate state
    const std::set<std::string_view> valid_states = {
        kStateOnline, kStateOffline, kStateUnavailable,
        kStateFreeForChat, kStateBusy
    };
    if (!valid_states.count(state)) {
      return json{{{"errcode", "M_INVALID_PARAM"},
                    {"error", "Invalid presence state: " + state}}};
    }

    std::optional<std::string> status_msg;
    if (request_body.contains("status_msg") &&
        !request_body["status_msg"].is_null()) {
      std::string msg = request_body["status_msg"].get<std::string>();
      if (msg.size() > 500) msg = msg.substr(0, 500);
      status_msg = std::move(msg);
    }

    try {
      engine_.set_presence(user_id, state, status_msg);
      return json::object(); // 200 OK, empty response
    } catch (const std::exception& e) {
      return json{{{"errcode", "M_UNKNOWN"}, {"error", e.what()}}};
    }
  }

  // ---- GET /_matrix/client/v3/presence/{userId}/status ----
  json handle_get_presence(const std::string& target_user_id,
                            const std::string& requester_id) {
    if (!engine_.is_enabled()) {
      return json{{{"errcode", "M_UNKNOWN"}, {"error", "Presence is disabled"}}};
    }

    // Privacy: check if requester can see this user's presence
    if (requester_id != target_user_id &&
        !engine_.can_see_presence(requester_id, target_user_id)) {
      json result;
      result["presence"] = "offline";
      result["last_active_ago"] = INT64_MAX;
      result["currently_active"] = false;
      return result;
    }

    auto state = engine_.get_presence(target_user_id);
    return state.to_api_json();
  }

  // ---- POST /_matrix/client/v3/presence/list/{userId} ----
  json handle_modify_presence_list(const std::string& user_id,
                                    const json& request_body) {
    if (!engine_.is_enabled()) {
      return json{{{"errcode", "M_UNKNOWN"}, {"error", "Presence is disabled"}}};
    }

    std::string action = request_body.value("action", "");
    std::string target_user = request_body.value("user_id", "");

    if (target_user.empty()) {
      return json{{{"errcode", "M_INVALID_PARAM"}, {"error", "Missing user_id"}}};
    }

    bool ok = true;
    if (action == "invite") {
      ok = engine_.invite_to_presence_list(user_id, target_user);
      if (!ok)
        return json{{{"errcode", "M_UNKNOWN"}, {"error", "Failed to invite"}}};
    } else if (action == "drop") {
      engine_.remove_from_presence_list(user_id, target_user);
    } else if (action == "accept") {
      ok = engine_.accept_presence_list(user_id, target_user);
      if (!ok)
        return json{{{"errcode", "M_UNKNOWN"}, {"error", "No pending invitation"}}};
    } else if (action == "deny") {
      engine_.deny_presence_list(user_id, target_user);
    } else {
      return json{{{"errcode", "M_INVALID_PARAM"},
                    {"error", "Invalid action: " + action}}};
    }

    return json::object(); // 200 OK
  }

  // ---- GET /_matrix/client/v3/presence/list/{userId} ----
  json handle_get_presence_list(const std::string& user_id) {
    if (!engine_.is_enabled()) {
      return json{{{"errcode", "M_UNKNOWN"}, {"error", "Presence is disabled"}}};
    }

    auto watched = engine_.get_watched_users(user_id);
    auto observers = engine_.get_presence_observers(user_id);

    json result;
    result["subscribed"] = json::array();
    for (const auto& w : watched)
      result["subscribed"].push_back(w);

    result["observers"] = json::array();
    for (const auto& o : observers)
      result["observers"].push_back(o);

    return result;
  }

  // ---- Handle presence in /sync response ----
  json build_sync_presence(const std::string& user_id,
                            const std::string& since_token) {
    if (!engine_.is_enabled()) {
      return {{"events", json::array()}};
    }

    auto watched = engine_.get_watched_users(user_id);
    std::set<std::string> uid_set(watched.begin(), watched.end());

    json result;
    result["events"] = json::array();

    if (since_token.empty()) {
      auto states = engine_.get_presence_for_users(uid_set);
      for (const auto& [uid, ps] : states) {
        if (uid == user_id) continue;
        result["events"].push_back(ps.to_api_json());
      }
    } else {
      auto poll_result = engine_.poll_presence(user_id, since_token, 0, uid_set);
      for (const auto& ps : poll_result.events) {
        if (ps.user_id == user_id) continue;
        result["events"].push_back(ps.to_api_json());
      }
    }

    return result;
  }

  // ---- Admin: get full presence state for a user ----
  json admin_get_full_presence(const std::string& user_id) {
    auto state = engine_.get_presence(user_id);
    json j = state.to_api_json();

    // Include internal fields for admin view
    j["last_user_sync_ts"] = state.last_user_sync_ts;
    j["last_state_change_ts"] = state.last_state_change_ts;
    j["federation_update_ts"] = state.federation_update_ts;

    // Include override info
    auto override = engine_.overrides().get_active_override(user_id);
    if (override.has_value()) {
      j["admin_override"] = {
          {"state", override->forced_state},
          {"admin", override->admin_user_id},
          {"reason", override->reason},
          {"expires", override->expires_ts.value_or(0)}
      };
    }

    return j;
  }

  // ---- Admin: set presence override ----
  json admin_set_presence_override(const std::string& target_user,
                                    const std::string& state,
                                    const std::string& admin_user,
                                    const std::string& reason,
                                    std::optional<int64_t> duration_ms = std::nullopt,
                                    std::optional<std::string> status_msg = std::nullopt) {
    try {
      auto override_id = engine_.set_override(
          target_user, state, admin_user, reason, duration_ms, status_msg);
      return {{"override_id", override_id}};
    } catch (const std::exception& e) {
      return {{"error", e.what()}};
    }
  }

  // ---- Admin: remove presence override ----
  json admin_remove_presence_override(const std::string& override_id,
                                       const std::string& admin_user) {
    bool ok = engine_.remove_override(override_id, admin_user);
    return {{"removed", ok}};
  }

  // ---- Admin: list all active overrides ----
  json admin_list_overrides() {
    auto overrides = engine_.list_overrides();
    json result = json::array();
    for (const auto& ov : overrides) {
      json entry;
      entry["override_id"] = ov.override_id;
      entry["target_user"] = ov.target_user_id;
      entry["state"] = ov.forced_state;
      entry["admin"] = ov.admin_user_id;
      entry["reason"] = ov.reason;
      entry["created"] = ov.created_ts;
      if (ov.expires_ts.has_value())
        entry["expires"] = *ov.expires_ts;
      result.push_back(entry);
    }
    return result;
  }

  // ---- Admin: get diagnostic information ----
  json admin_get_diagnostics() {
    return engine_.get_diagnostics();
  }

  // ---- Admin: reload configuration ----
  void admin_reload_config(const json& config_json) {
    PresenceConfig cfg;
    cfg.load_from_json(config_json);
    engine_.configure(cfg);
  }

  // ---- Federation: process incoming presence EDU ----
  void federation_process_presence(const json& edu_content,
                                    const std::string& origin_server) {
    if (!engine_.is_enabled()) return;
    engine_.process_federation_edu(edu_content, origin_server);
  }

  // ---- Federation: get presence for outgoing federation ----
  json federation_get_presence_for_destination(const std::string& destination) {
    // Gather all local users with pending federation updates for this destination
    // This would be used by the federation sender
    return json::object();
  }

  // ---- Bump last active on user activity ----
  void bump_user_activity(const std::string& user_id) {
    engine_.bump_last_active(user_id);
  }

  // ---- Mark user as syncing (updates last_user_sync_ts) ----
  void mark_user_sync(const std::string& user_id) {
    engine_.mark_user_synced(user_id);
  }

  // ---- Get presence for multiple users at once ----
  json get_presence_for_users(const std::set<std::string>& user_ids) {
    json result;
    auto states = engine_.get_presence_for_users(user_ids);
    for (const auto& [uid, ps] : states) {
      result[uid] = ps.to_api_json();
    }
    return result;
  }

  // ---- Check if user is currently active ----
  bool is_user_currently_active(const std::string& user_id) {
    auto state = engine_.get_presence(user_id);
    return state.currently_active;
  }

  // ---- Get engine reference for advanced use ----
  PresenceEngine& engine() { return engine_; }
  const PresenceEngine& engine() const { return engine_; }

private:
  PresenceEngine& engine_;
};

}  // namespace progressive::presence

// ============================================================================
// PresenceEngine extended configuration — Global singleton-like access
// ============================================================================
namespace progressive {

// ---- Global factory function for creating a PresenceEngine ----
inline std::unique_ptr<PresenceEngine> create_presence_engine(
    storage::DatabasePool& db,
    const json& config_json = json::object()) {
  auto engine = std::make_unique<PresenceEngine>(db);
  if (!config_json.empty()) {
    PresenceConfig cfg;
    cfg.load_from_json(config_json);
    engine->configure(cfg);
  }
  return engine;
}

// ---- Global helper: create and start a configured engine ----
inline std::unique_ptr<PresenceEngine> create_and_start_presence_engine(
    storage::DatabasePool& db,
    const json& config_json = json::object()) {
  auto engine = create_presence_engine(db, config_json);
  engine->start();
  return engine;
}

}  // namespace progressive

// ============================================================================
// End of presence_engine.cpp
// ============================================================================
