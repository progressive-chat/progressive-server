// threading.cpp — Matrix Threading, Reactions, Edits, Read Markers,
// Event Relations, and Aggregation Groups
//
// Implements:
//   - Thread relations: m.thread relation type, thread root event,
//     thread participation, thread summaries (count, latest_event,
//     latest_reply), thread roots tracking, per-thread state
//   - Thread sync: return threads in sync response, per-thread timelines,
//     thread read receipts, bundled thread relationship data
//   - Thread notifications: per-thread notification settings, thread-level
//     unread counts, thread-specific push rules
//   - Event relations in general: m.annotation for reactions,
//     m.replace for edits, m.reference for replies, m.thread for threads,
//     generic relation handling and validation
//   - Reaction handling: add/remove reactions, reaction count aggregation,
//     reaction summary, reaction sender tracking, deduplication
//   - Message edits: edit events with m.replace, fallback text for
//     older clients, edit history tracking, edit validation
//   - Read markers per thread: fully_read marker per room,
//     read marker per thread, read receipt bundling
//   - Aggregation groups: group events by relation type,
//     count aggregations, send aggregated relation info in sync
//     responses, bundled aggregations for timeline events
//
// Equivalent to synapse/handlers/relations.py +
//              synapse/handlers/read_marker.py +
//              synapse/rest/client/relations.py +
//              synapse/api/filtering.py (thread filters) +
//              synapse/events/utils.py (relation helpers) +
//              synapse/types.py (relation type definitions)
// Target: 2500+ lines

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
class ThreadRelationManager;
class ThreadSyncBuilder;
class ThreadNotificationManager;
class EventRelationEngine;
class ReactionAggregator;
class MessageEditManager;
class ReadMarkerManager;
class AggregationGroupManager;
class ThreadCoordinator;

// ============================================================================
// Utility: time, string, ID generation, crypto helpers
// ============================================================================
namespace {

int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

std::string generate_random_id(int len = 18) {
  static const char charset[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  std::string result(len, '\0');
  thread_local std::mt19937 rng(
      static_cast<unsigned>(now_ms() ^ std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
  for (int i = 0; i < len; ++i) {
    result[i] = charset[dist(rng)];
  }
  return result;
}

std::string generate_event_id(const std::string& server_name) {
  return "$" + generate_random_id(18) + ":" + server_name;
}

bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         s.substr(s.size() - suffix.size()) == suffix;
}

std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::tolower);
  return s;
}

std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

std::vector<std::string> split_string(const std::string& s, char delim) {
  std::vector<std::string> tokens;
  std::istringstream iss(s);
  std::string token;
  while (std::getline(iss, token, delim)) {
    if (!token.empty()) tokens.push_back(token);
  }
  return tokens;
}

std::string join_strings(const std::vector<std::string>& parts,
                          const std::string& delim) {
  std::ostringstream oss;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) oss << delim;
    oss << parts[i];
  }
  return oss.str();
}

bool is_valid_event_id(const std::string& eid) {
  return starts_with(eid, "$") && eid.find(':') != std::string::npos;
}

bool is_valid_user_id(const std::string& uid) {
  return starts_with(uid, "@") && uid.find(':') != std::string::npos;
}

std::string extract_server_name(const std::string& mxid) {
  auto pos = mxid.find(':');
  if (pos != std::string::npos) return mxid.substr(pos + 1);
  return "";
}

// --------------------------------------------------------------------------
// JSON safe access helpers
// --------------------------------------------------------------------------
std::string json_str(const json& obj, const std::string& key, const std::string& dflt = "") {
  if (obj.contains(key) && obj[key].is_string()) return obj[key].get<std::string>();
  return dflt;
}

int64_t json_int(const json& obj, const std::string& key, int64_t dflt = 0) {
  if (obj.contains(key) && obj[key].is_number_integer()) return obj[key].get<int64_t>();
  return dflt;
}

bool json_bool(const json& obj, const std::string& key, bool dflt = false) {
  if (obj.contains(key) && obj[key].is_boolean()) return obj[key].get<bool>();
  return dflt;
}

// --------------------------------------------------------------------------
// In-memory event cache for quick lookups during sync
// --------------------------------------------------------------------------
template <typename K, typename V>
class TTLCache {
public:
  explicit TTLCache(int64_t ttl_ms) : ttl_ms_(ttl_ms) {}

  void put(const K& key, const V& value) {
    std::lock_guard<std::mutex> lock(mu_);
    cache_[key] = {value, now_ms()};
  }

  std::optional<V> get(const K& key) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
      if (now_ms() - it->second.timestamp < ttl_ms_) {
        return it->second.value;
      }
      cache_.erase(it);
    }
    return std::nullopt;
  }

  void invalidate(const K& key) {
    std::lock_guard<std::mutex> lock(mu_);
    cache_.erase(key);
  }

  void clear() {
    std::lock_guard<std::mutex> lock(mu_);
    cache_.clear();
  }

  bool contains(const K& key) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
      if (now_ms() - it->second.timestamp < ttl_ms_) return true;
      cache_.erase(it);
    }
    return false;
  }

private:
  struct Entry {
    V value;
    int64_t timestamp;
  };
  mutable std::mutex mu_;
  std::unordered_map<K, Entry> cache_;
  int64_t ttl_ms_;
};

} // anonymous namespace

// ============================================================================
// Configuration structures
// ============================================================================

struct ThreadConfig {
  bool enable_threads = true;
  int max_replies_per_thread = 5000;
  int max_threads_per_room = 10000;
  int thread_summary_max_replies = 5;
  int thread_timeline_limit = 100;
  int64_t thread_cache_ttl_ms = 300000;  // 5 minutes
  bool include_threads_in_sync = true;
  bool enable_thread_notifications = true;
  bool enable_per_thread_read_receipts = true;
};

struct ReactionConfig {
  bool enable_reactions = true;
  int max_unique_reactions_per_event = 1000;
  int max_reactions_per_user_per_event = 1;
  bool allow_custom_emojis = true;
  int reaction_summary_cache_ttl_ms = 60000;
  int max_reaction_key_length = 64;
};

struct EditConfig {
  bool enable_edits = true;
  int max_edit_history = 50;
  bool include_fallback_body = true;
  int max_edit_depth = 1; // only allow direct edits, not edits of edits
  bool validate_new_content = true;
};

struct ReadMarkerConfig {
  bool enable_read_markers = true;
  bool enable_per_thread_markers = true;
  int64_t read_marker_cache_ttl_ms = 60000;
  bool allow_private_read_receipts = true;
};

struct AggregationConfig {
  bool enable_aggregations = true;
  int max_aggregated_relations_per_event = 100;
  int64_t aggregation_cache_ttl_ms = 120000;
  bool include_reaction_count_in_sync = true;
  bool include_edit_info_in_sync = true;
  bool include_thread_summary_in_sync = true;
};

// ============================================================================
// Relation type constants
// ============================================================================
namespace relation_types {
  constexpr const char* ANNOTATION = "m.annotation";
  constexpr const char* REPLACE = "m.replace";
  constexpr const char* REFERENCE = "m.reference";
  constexpr const char* THREAD = "m.thread";
  constexpr const char* IN_REPLY_TO = "m.in_reply_to";

  bool is_valid_relation_type(const std::string& rel_type) {
    return rel_type == ANNOTATION ||
           rel_type == REPLACE ||
           rel_type == REFERENCE ||
           rel_type == THREAD ||
           rel_type == IN_REPLY_TO;
  }
} // namespace relation_types

// ============================================================================
// Event relation data structures
// ============================================================================

struct RelationInfo {
  std::string event_id;        // the event this relation points to
  std::string relation_type;   // m.annotation, m.replace, m.reference, m.thread
  std::string aggregation_key; // for m.annotation (the emoji/reaction key)
  int64_t origin_server_ts{0};
  std::string sender;
  json content;

  json to_json() const {
    json j;
    j["event_id"] = event_id;
    j["rel_type"] = relation_type;
    if (!aggregation_key.empty()) j["key"] = aggregation_key;
    j["origin_server_ts"] = origin_server_ts;
    j["sender"] = sender;
    return j;
  }
};

struct ThreadSummary {
  std::string root_event_id;
  std::string latest_event_id;
  std::string latest_reply_event_id;
  int64_t reply_count{0};
  int64_t participant_count{0};
  int64_t latest_origin_server_ts{0};
  std::vector<std::string> latest_reply_event_ids;
  bool participated{false};  // whether the current user participated

  json to_json() const {
    json j;
    j["root_event_id"] = root_event_id;
    if (!latest_event_id.empty()) j["latest_event"] = latest_event_id;
    if (!latest_reply_event_id.empty()) j["latest_reply"] = latest_reply_event_id;
    j["count"] = reply_count;
    j["participant_count"] = participant_count;
    j["participated"] = participated;

    json latest_replies = json::array();
    for (auto& eid : latest_reply_event_ids) {
      latest_replies.push_back(eid);
    }
    j["latest_replies"] = latest_replies;

    return j;
  }
};

struct ReactionSummary {
  std::string event_id;
  std::string aggregation_key;
  int64_t count{0};
  bool current_user_reacted{false};
  int64_t first_ts{0};

  json to_json() const {
    json j;
    j["key"] = aggregation_key;
    j["count"] = count;
    j["self"] = current_user_reacted;
    j["first_ts"] = first_ts;
    return j;
  }
};

struct EditSummary {
  bool is_edited{false};
  int64_t edit_count{0};
  std::string latest_edit_event_id;
  int64_t latest_edit_ts{0};
  std::string latest_editor;

  json to_json() const {
    json j;
    j["edited"] = is_edited;
    j["edit_count"] = edit_count;
    if (!latest_edit_event_id.empty()) j["last_edit_event_id"] = latest_edit_event_id;
    if (latest_edit_ts > 0) j["last_edit_ts"] = latest_edit_ts;
    if (!latest_editor.empty()) j["last_edit_sender"] = latest_editor;
    return j;
  }
};

struct ReadMarkerInfo {
  std::string room_id;
  std::string user_id;
  std::string fully_read_event_id;
  std::optional<std::string> read_receipt_event_id;
  std::map<std::string, std::string> thread_read_markers; // thread_id -> event_id
  int64_t updated_at_ms{0};

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    j["user_id"] = user_id;
    j["fully_read"] = fully_read_event_id;
    if (read_receipt_event_id) j["read_receipt"] = *read_receipt_event_id;
    json thread_markers = json::object();
    for (auto& [tid, eid] : thread_read_markers) {
      thread_markers[tid] = eid;
    }
    j["thread_read_markers"] = thread_markers;
    j["updated_at_ms"] = updated_at_ms;
    return j;
  }
};

struct AggregatedRelationBundle {
  std::string target_event_id;
  ThreadSummary thread_summary;
  std::vector<ReactionSummary> reactions;
  EditSummary edit_info;
  int64_t reference_count{0};
  bool has_aggregations{false};

  json to_json() const {
    json j;
    j["event_id"] = target_event_id;
    if (!thread_summary.root_event_id.empty()) {
      j["m.thread"] = thread_summary.to_json();
    }
    if (!reactions.empty()) {
      json reaction_list = json::array();
      for (auto& r : reactions) reaction_list.push_back(r.to_json());
      j["m.annotation"] = reaction_list;
    }
    if (edit_info.is_edited) {
      j["m.replace"] = edit_info.to_json();
    }
    if (reference_count > 0) {
      j["m.reference"] = {{"count", reference_count}};
    }
    return j;
  }
};

// ============================================================================
// In-memory stores for relation data
// ============================================================================

class RelationStore {
public:
  // Store a relation
  void add_relation(const std::string& event_id, const RelationInfo& info) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    relations_by_event_[event_id] = info;
    relations_to_parent_[info.event_id][info.relation_type].push_back(event_id);
    if (!info.aggregation_key.empty()) {
      aggregation_keys_[info.event_id][info.relation_type][info.aggregation_key].push_back(event_id);
    }
  }

  // Get relations pointing to a parent event
  std::vector<RelationInfo> get_relations_for_parent(const std::string& parent_id,
                                                       const std::string& rel_type = "") {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::vector<RelationInfo> result;
    auto parent_it = relations_to_parent_.find(parent_id);
    if (parent_it == relations_to_parent_.end()) return result;

    for (auto& [type, event_ids] : parent_it->second) {
      if (rel_type.empty() || type == rel_type) {
        for (auto& eid : event_ids) {
          auto rel_it = relations_by_event_.find(eid);
          if (rel_it != relations_by_event_.end()) {
            result.push_back(rel_it->second);
          }
        }
      }
    }
    return result;
  }

  // Get the relation info for an event (what it relates to)
  std::optional<RelationInfo> get_relation_for_event(const std::string& event_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = relations_by_event_.find(event_id);
    if (it != relations_by_event_.end()) return it->second;
    return std::nullopt;
  }

  // Get count of relations of a specific type pointing to a parent
  int64_t get_relation_count(const std::string& parent_id,
                              const std::string& rel_type) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto parent_it = relations_to_parent_.find(parent_id);
    if (parent_it == relations_to_parent_.end()) return 0;
    auto type_it = parent_it->second.find(rel_type);
    if (type_it == parent_it->second.end()) return 0;
    return static_cast<int64_t>(type_it->second.size());
  }

  // Get aggregation keys for a parent event
  std::map<std::string, int64_t> get_aggregation_counts(const std::string& parent_id,
                                                          const std::string& rel_type) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::map<std::string, int64_t> result;
    auto parent_it = aggregation_keys_.find(parent_id);
    if (parent_it == aggregation_keys_.end()) return result;
    auto type_it = parent_it->second.find(rel_type);
    if (type_it == parent_it->second.end()) return result;
    for (auto& [key, event_ids] : type_it->second) {
      result[key] = static_cast<int64_t>(event_ids.size());
    }
    return result;
  }

  // Remove a relation
  void remove_relation(const std::string& event_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto rel_it = relations_by_event_.find(event_id);
    if (rel_it == relations_by_event_.end()) return;

    const auto& info = rel_it->second;
    auto parent_it = relations_to_parent_.find(info.event_id);
    if (parent_it != relations_to_parent_.end()) {
      auto type_it = parent_it->second.find(info.relation_type);
      if (type_it != parent_it->second.end()) {
        type_it->second.erase(
            std::remove(type_it->second.begin(), type_it->second.end(), event_id),
            type_it->second.end());
        if (type_it->second.empty()) {
          parent_it->second.erase(type_it);
        }
      }
      if (parent_it->second.empty()) {
        relations_to_parent_.erase(parent_it);
      }
    }

    if (!info.aggregation_key.empty()) {
      auto agg_it = aggregation_keys_.find(info.event_id);
      if (agg_it != aggregation_keys_.end()) {
        auto type_it = agg_it->second.find(info.relation_type);
        if (type_it != agg_it->second.end()) {
          auto key_it = type_it->second.find(info.aggregation_key);
          if (key_it != type_it->second.end()) {
            key_it->second.erase(
                std::remove(key_it->second.begin(), key_it->second.end(), event_id),
                key_it->second.end());
            if (key_it->second.empty()) type_it->second.erase(key_it);
          }
          if (type_it->second.empty()) agg_it->second.erase(type_it);
        }
        if (agg_it->second.empty()) aggregation_keys_.erase(agg_it);
      }
    }

    relations_by_event_.erase(rel_it);
  }

  bool has_relation(const std::string& event_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    return relations_by_event_.find(event_id) != relations_by_event_.end();
  }

  size_t total_relations() const {
    std::shared_lock<std::shared_mutex> lock;
    return relations_by_event_.size();
  }

  void clear() {
    std::lock_guard<std::shared_mutex> lock(mu_);
    relations_by_event_.clear();
    relations_to_parent_.clear();
    aggregation_keys_.clear();
  }

private:
  mutable std::shared_mutex mu_;
  std::unordered_map<std::string, RelationInfo> relations_by_event_;
  // parent_event_id -> relation_type -> vector<event_id>
  std::unordered_map<std::string,
    std::unordered_map<std::string, std::vector<std::string>>> relations_to_parent_;
  // parent_event_id -> relation_type -> aggregation_key -> vector<event_id>
  std::unordered_map<std::string,
    std::unordered_map<std::string,
      std::unordered_map<std::string, std::vector<std::string>>>> aggregation_keys_;

  // Allow lock management
  friend class RelationStoreLock;
};

// RAII lock for RelationStore
class RelationStoreLock {
public:
  explicit RelationStoreLock(RelationStore& store) : store_(store) {
    // Lock for exclusive access
  }
private:
  RelationStore& store_;
};

// ============================================================================
// ThreadRelationManager — manages thread roots and thread state
// ============================================================================
class ThreadRelationManager {
public:
  ThreadRelationManager(RelationStore& relation_store, const ThreadConfig& cfg = {})
      : relation_store_(relation_store), config_(cfg) {}

  // --------------------------------------------------------------------------
  // Thread root management
  // --------------------------------------------------------------------------

  // Register a thread root event
  void register_thread_root(const std::string& room_id, const std::string& event_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    thread_roots_[room_id].insert(event_id);
    thread_rooms_[event_id] = room_id;
    // Initialize thread state
    if (thread_states_.find(event_id) == thread_states_.end()) {
      thread_states_[event_id] = ThreadSummary{};
      thread_states_[event_id].root_event_id = event_id;
    }
  }

  // Check if an event is a thread root
  bool is_thread_root(const std::string& event_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    return thread_states_.find(event_id) != thread_states_.end();
  }

  // Get all thread roots in a room
  std::vector<std::string> get_thread_roots(const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::vector<std::string> roots;
    auto it = thread_roots_.find(room_id);
    if (it != thread_roots_.end()) {
      roots.assign(it->second.begin(), it->second.end());
    }
    return roots;
  }

  // --------------------------------------------------------------------------
  // Thread event management
  // --------------------------------------------------------------------------

  // Add a thread reply event
  bool add_thread_reply(const std::string& root_event_id,
                         const std::string& reply_event_id,
                         const std::string& sender,
                         int64_t timestamp) {
    std::lock_guard<std::shared_mutex> lock(mu_);

    auto it = thread_states_.find(root_event_id);
    if (it == thread_states_.end()) {
      // Auto-create thread state for unknown roots
      ThreadSummary summary;
      summary.root_event_id = root_event_id;
      it = thread_states_.emplace(root_event_id, std::move(summary)).first;
    }

    auto& state = it->second;
    state.reply_count++;
    state.participants.insert(sender);
    state.participant_count = static_cast<int64_t>(state.participants.size());
    state.latest_reply_event_id = reply_event_id;
    state.latest_event_id = reply_event_id;

    if (timestamp > state.latest_origin_server_ts) {
      state.latest_origin_server_ts = timestamp;
    }

    // Maintain the last N reply event IDs
    state.latest_reply_event_ids.push_back(reply_event_id);
    if (static_cast<int>(state.latest_reply_event_ids.size()) > config_.thread_summary_max_replies) {
      state.latest_reply_event_ids.erase(state.latest_reply_event_ids.begin());
    }

    // Add to thread timeline index
    thread_timeline_[root_event_id].push_back(reply_event_id);

    return true;
  }

  // Get thread summary
  std::optional<ThreadSummary> get_thread_summary(const std::string& root_event_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = thread_states_.find(root_event_id);
    if (it != thread_states_.end()) return it->second;
    return std::nullopt;
  }

  // Update thread summary (override)
  void update_thread_summary(const std::string& root_event_id,
                              const ThreadSummary& summary) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    thread_states_[root_event_id] = summary;
  }

  // Set participation for a user
  void set_participated(const std::string& root_event_id,
                         const std::string& user_id,
                         bool participated) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto it = thread_states_.find(root_event_id);
    if (it != thread_states_.end()) {
      it->second.participated = participated;
    }
  }

  // Check if a user participated in a thread
  bool has_participated(const std::string& root_event_id,
                         const std::string& user_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = thread_states_.find(root_event_id);
    if (it != thread_states_.end()) {
      return it->second.participants.find(user_id) !=
             it->second.participants.end();
    }
    return false;
  }

  // Get thread participants
  std::set<std::string> get_participants(const std::string& root_event_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = thread_states_.find(root_event_id);
    if (it != thread_states_.end()) {
      return it->second.participants;
    }
    return {};
  }

  // Get thread timeline (reply event IDs)
  std::vector<std::string> get_thread_timeline(const std::string& root_event_id,
                                                int limit = 100) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = thread_timeline_.find(root_event_id);
    if (it == thread_timeline_.end()) return {};
    if (static_cast<int>(it->second.size()) <= limit) return it->second;
    return std::vector<std::string>(it->second.end() - limit, it->second.end());
  }

  // Remove an event from thread tracking (redaction)
  void remove_thread_reply(const std::string& root_event_id,
                            const std::string& event_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto it = thread_timeline_.find(root_event_id);
    if (it != thread_timeline_.end()) {
      it->second.erase(
          std::remove(it->second.begin(), it->second.end(), event_id),
          it->second.end());
    }
    // Decrement count
    auto state_it = thread_states_.find(root_event_id);
    if (state_it != thread_states_.end()) {
      state_it->second.reply_count = std::max(0LL, state_it->second.reply_count - 1);
    }
  }

  // Get the room a thread root belongs to
  std::string get_room_for_thread(const std::string& root_event_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = thread_rooms_.find(root_event_id);
    if (it != thread_rooms_.end()) return it->second;
    return "";
  }

  // Count threads in a room
  int64_t get_thread_count(const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto it = thread_roots_.find(room_id);
    if (it != thread_roots_.end()) {
      return static_cast<int64_t>(it->second.size());
    }
    return 0;
  }

  // Find which thread an event belongs to (if any)
  std::optional<std::string> find_thread_for_event(const std::string& event_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    for (auto& [root, timeline] : thread_timeline_) {
      if (std::find(timeline.begin(), timeline.end(), event_id) != timeline.end()) {
        return root;
      }
      if (root == event_id) return root;
    }
    return std::nullopt;
  }

  // --------------------------------------------------------------------------
  // Thread ordering helpers
  // --------------------------------------------------------------------------

  // Get threads sorted by latest activity
  std::vector<std::string> get_threads_ordered_by_activity(
      const std::string& room_id, int limit = 50) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    std::vector<std::pair<int64_t, std::string>> sorted;
    auto it = thread_roots_.find(room_id);
    if (it == thread_roots_.end()) return {};

    for (auto& root_id : it->second) {
      int64_t latest_ts = 0;
      auto state_it = thread_states_.find(root_id);
      if (state_it != thread_states_.end()) {
        latest_ts = state_it->second.latest_origin_server_ts;
      }
      sorted.emplace_back(latest_ts, root_id);
    }

    std::sort(sorted.begin(), sorted.end(),
              [](auto& a, auto& b) { return a.first > b.first; });

    std::vector<std::string> result;
    for (int i = 0; i < std::min(limit, static_cast<int>(sorted.size())); ++i) {
      result.push_back(sorted[i].second);
    }
    return result;
  }

private:
  RelationStore& relation_store_;
  ThreadConfig config_;
  mutable std::shared_mutex mu_;

  // room_id -> set of thread root event IDs
  std::unordered_map<std::string, std::unordered_set<std::string>> thread_roots_;
  // thread_root_event_id -> room_id
  std::unordered_map<std::string, std::string> thread_rooms_;
  // thread_root_event_id -> ThreadSummary
  std::unordered_map<std::string, ThreadSummary> thread_states_;
  // thread_root_event_id -> ordered list of reply event IDs
  std::unordered_map<std::string, std::vector<std::string>> thread_timeline_;
};

// ============================================================================
// ThreadSyncBuilder — builds thread-related sync data
// ============================================================================
class ThreadSyncBuilder {
public:
  ThreadSyncBuilder(ThreadRelationManager& thread_mgr,
                     RelationStore& relation_store,
                     const ThreadConfig& cfg = {})
      : thread_mgr_(thread_mgr), relation_store_(relation_store), config_(cfg) {}

  // --------------------------------------------------------------------------
  // Build thread summaries for a room's sync response
  // --------------------------------------------------------------------------
  json build_room_threads(const std::string& room_id,
                           const std::string& current_user_id) {
    json threads = json::object();

    if (!config_.include_threads_in_sync) return threads;

    auto thread_roots = thread_mgr_.get_threads_ordered_by_activity(room_id,
        config_.thread_timeline_limit);

    for (auto& root_id : thread_roots) {
      auto summary_opt = thread_mgr_.get_thread_summary(root_id);
      if (!summary_opt) continue;

      auto& summary = *summary_opt;
      // Check if current user participated
      summary.participated = thread_mgr_.has_participated(root_id, current_user_id);

      // Get the thread timeline
      auto timeline = thread_mgr_.get_thread_timeline(root_id,
          config_.thread_timeline_limit);

      json thread_info;
      thread_info["summary"] = summary.to_json();
      thread_info["timeline"] = json(timeline);
      thread_info["root_event_id"] = root_id;

      threads[root_id] = thread_info;
    }

    return threads;
  }

  // Build bundled relations for a specific event in sync response
  json build_bundled_relations(const std::string& event_id,
                                const std::string& current_user_id) {
    json bundled;
    bool has_any = false;

    // Thread summary if this event is a thread root
    auto thread_summary = thread_mgr_.get_thread_summary(event_id);
    if (thread_summary && thread_summary->reply_count > 0) {
      thread_summary->participated = thread_mgr_.has_participated(
          event_id, current_user_id);
      bundled["m.thread"] = thread_summary->to_json();
      has_any = true;
    }

    // Reaction counts
    auto reaction_counts = relation_store_.get_aggregation_counts(
        event_id, relation_types::ANNOTATION);
    if (!reaction_counts.empty()) {
      json reactions = json::array();
      for (auto& [key, count] : reaction_counts) {
        reactions.push_back({{"key", key}, {"count", count}});
      }
      bundled["m.annotation"] = reactions;
      has_any = true;
    }

    // Edit info
    int64_t edit_count = relation_store_.get_relation_count(
        event_id, relation_types::REPLACE);
    if (edit_count > 0) {
      bundled["m.replace"] = {{"count", edit_count}};
      has_any = true;
    }

    // Reference count
    int64_t ref_count = relation_store_.get_relation_count(
        event_id, relation_types::REFERENCE);
    if (ref_count > 0) {
      bundled["m.reference"] = {{"count", ref_count}};
      has_any = true;
    }

    if (has_any) return bundled;
    return json::object();
  }

  // Build the threads section of a sync response
  json build_sync_threads_section(const std::string& room_id,
                                   const std::string& current_user_id,
                                   const json& room_timeline_events) {
    json result;
    auto threads = build_room_threads(room_id, current_user_id);
    if (!threads.empty()) {
      result["threads"] = threads;
    }

    // For each event in the timeline, include bundled relations
    json bundled_relations = json::object();
    for (auto& event : room_timeline_events) {
      std::string event_id = json_str(event, "event_id");
      if (!event_id.empty()) {
        auto bundled = build_bundled_relations(event_id, current_user_id);
        if (!bundled.empty()) {
          bundled_relations[event_id] = bundled;
        }
      }
    }
    if (!bundled_relations.empty()) {
      result["bundled_relations"] = bundled_relations;
    }

    return result;
  }

  // Build per-thread timeline for sync response (lazy-loaded threads)
  json build_thread_timeline_sync(const std::string& root_event_id,
                                   int from_index,
                                   int limit,
                                   const std::string& current_user_id) {
    json result;
    auto timeline = thread_mgr_.get_thread_timeline(root_event_id, limit + from_index);

    result["root_event_id"] = root_event_id;
    result["start"] = from_index;
    result["end"] = std::min(from_index + limit,
                              static_cast<int>(timeline.size()));
    result["total"] = static_cast<int>(timeline.size());

    json events = json::array();
    for (int i = from_index; i < std::min(from_index + limit,
                                           static_cast<int>(timeline.size())); ++i) {
      events.push_back(timeline[i]);
    }
    result["events"] = events;

    auto summary = thread_mgr_.get_thread_summary(root_event_id);
    if (summary) {
      summary->participated = thread_mgr_.has_participated(
          root_event_id, current_user_id);
      result["summary"] = summary->to_json();
    }

    return result;
  }

  // Filter timeline events based on thread root filter
  std::vector<std::string> filter_by_thread(
      const std::vector<std::string>& event_ids,
      const std::optional<std::string>& thread_root_filter) {
    if (!thread_root_filter) return event_ids;

    std::vector<std::string> filtered;
    for (auto& eid : event_ids) {
      auto thread = thread_mgr_.find_thread_for_event(eid);
      if (thread && *thread == *thread_root_filter) {
        filtered.push_back(eid);
      } else if (!thread && !thread_root_filter->empty() &&
                 eid == *thread_root_filter) {
        // Include the thread root itself
        filtered.push_back(eid);
      }
    }
    return filtered;
  }

private:
  ThreadRelationManager& thread_mgr_;
  RelationStore& relation_store_;
  ThreadConfig config_;
};

// ============================================================================
// ThreadNotificationManager — manages per-thread notifications
// ============================================================================
class ThreadNotificationManager {
public:
  ThreadNotificationManager(ThreadRelationManager& thread_mgr,
                              const ThreadConfig& cfg = {})
      : thread_mgr_(thread_mgr), config_(cfg) {}

  // --------------------------------------------------------------------------
  // Thread notification settings
  // --------------------------------------------------------------------------

  enum class ThreadNotificationSetting {
    DEFAULT,     // Follow room rules
    ALL,         // Notify for all thread replies
    MENTIONS,    // Notify only on mentions
    NONE         // No notifications for this thread
  };

  static std::string setting_to_string(ThreadNotificationSetting s) {
    switch (s) {
      case ThreadNotificationSetting::DEFAULT: return "default";
      case ThreadNotificationSetting::ALL: return "all";
      case ThreadNotificationSetting::MENTIONS: return "mentions";
      case ThreadNotificationSetting::NONE: return "none";
    }
    return "default";
  }

  static ThreadNotificationSetting string_to_setting(const std::string& s) {
    if (s == "all") return ThreadNotificationSetting::ALL;
    if (s == "mentions") return ThreadNotificationSetting::MENTIONS;
    if (s == "none") return ThreadNotificationSetting::NONE;
    return ThreadNotificationSetting::DEFAULT;
  }

  // Set notification setting for a thread
  void set_thread_notification(const std::string& user_id,
                                const std::string& thread_root_id,
                                ThreadNotificationSetting setting) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    thread_notification_settings_[user_id][thread_root_id] = setting;
  }

  // Get notification setting for a thread
  ThreadNotificationSetting get_thread_notification(
      const std::string& user_id,
      const std::string& thread_root_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto user_it = thread_notification_settings_.find(user_id);
    if (user_it != thread_notification_settings_.end()) {
      auto thread_it = user_it->second.find(thread_root_id);
      if (thread_it != user_it->second.end()) return thread_it->second;
    }
    return ThreadNotificationSetting::DEFAULT;
  }

  // Remove notification setting
  void remove_thread_notification(const std::string& user_id,
                                   const std::string& thread_root_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto user_it = thread_notification_settings_.find(user_id);
    if (user_it != thread_notification_settings_.end()) {
      user_it->second.erase(thread_root_id);
    }
  }

  // --------------------------------------------------------------------------
  // Unread counts
  // --------------------------------------------------------------------------

  // Set the last read event for a thread
  void set_thread_read_position(const std::string& user_id,
                                 const std::string& thread_root_id,
                                 const std::string& event_id,
                                 int64_t stream_ordering) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    thread_read_positions_[user_id][thread_root_id] = {event_id, stream_ordering};
  }

  // Get the last read event for a thread
  std::pair<std::string, int64_t> get_thread_read_position(
      const std::string& user_id,
      const std::string& thread_root_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto user_it = thread_read_positions_.find(user_id);
    if (user_it != thread_read_positions_.end()) {
      auto thread_it = user_it->second.find(thread_root_id);
      if (thread_it != user_it->second.end()) return thread_it->second;
    }
    return {"", 0};
  }

  // Calculate unread count for a thread
  int64_t calculate_thread_unread_count(const std::string& user_id,
                                          const std::string& thread_root_id) {
    auto [last_read, last_stream] = get_thread_read_position(user_id, thread_root_id);

    auto timeline = thread_mgr_.get_thread_timeline(thread_root_id);
    if (timeline.empty()) return 0;

    int64_t unread = 0;
    for (auto& eid : timeline) {
      if (eid > last_read) unread++;
    }
    return unread;
  }

  // Get unread counts for all threads in a room
  std::map<std::string, int64_t> get_all_thread_unread_counts(
      const std::string& user_id,
      const std::string& room_id) {
    std::map<std::string, int64_t> counts;
    auto roots = thread_mgr_.get_thread_roots(room_id);
    for (auto& root : roots) {
      int64_t count = calculate_thread_unread_count(user_id, root);
      if (count > 0) {
        counts[root] = count;
      }
    }
    return counts;
  }

  // Check if a thread reply should generate a notification
  bool should_notify_for_thread_reply(const std::string& user_id,
                                       const std::string& thread_root_id,
                                       bool is_mention,
                                       bool is_direct_message) {
    auto setting = get_thread_notification(user_id, thread_root_id);

    switch (setting) {
      case ThreadNotificationSetting::ALL:
        return true;
      case ThreadNotificationSetting::MENTIONS:
        return is_mention || is_direct_message;
      case ThreadNotificationSetting::NONE:
        return false;
      case ThreadNotificationSetting::DEFAULT:
        // Fall through: use room-level notification rules
        return true;
    }
    return true;
  }

  // Build notification settings for sync response
  json build_notification_settings_sync(const std::string& user_id) {
    json settings = json::object();
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto user_it = thread_notification_settings_.find(user_id);
    if (user_it != thread_notification_settings_.end()) {
      for (auto& [thread_id, setting] : user_it->second) {
        settings[thread_id] = setting_to_string(setting);
      }
    }
    return settings;
  }

  // Get list of threads the user is actively following
  std::vector<std::string> get_followed_threads(const std::string& user_id) {
    std::vector<std::string> followed;
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto user_it = thread_notification_settings_.find(user_id);
    if (user_it != thread_notification_settings_.end()) {
      for (auto& [thread_id, setting] : user_it->second) {
        if (setting != ThreadNotificationSetting::NONE) {
          followed.push_back(thread_id);
        }
      }
    }
    return followed;
  }

private:
  ThreadRelationManager& thread_mgr_;
  ThreadConfig config_;
  mutable std::shared_mutex mu_;

  // user_id -> thread_root_id -> notification setting
  std::unordered_map<std::string,
    std::unordered_map<std::string, ThreadNotificationSetting>>
      thread_notification_settings_;

  // user_id -> thread_root_id -> (event_id, stream_ordering)
  std::unordered_map<std::string,
    std::unordered_map<std::string, std::pair<std::string, int64_t>>>
      thread_read_positions_;
};

// ============================================================================
// EventRelationEngine — validates and processes event relations
// ============================================================================
class EventRelationEngine {
public:
  EventRelationEngine(RelationStore& relation_store,
                       ThreadRelationManager& thread_mgr,
                       const ThreadConfig& thread_cfg = {},
                       const ReactionConfig& reaction_cfg = {},
                       const EditConfig& edit_cfg = {})
      : relation_store_(relation_store),
        thread_mgr_(thread_mgr),
        thread_config_(thread_cfg),
        reaction_config_(reaction_cfg),
        edit_config_(edit_cfg) {}

  // --------------------------------------------------------------------------
  // Parse relation info from event content
  // --------------------------------------------------------------------------

  struct ParsedRelation {
    std::string rel_type;
    std::string event_id;
    std::string key;            // for m.annotation aggregation key
    bool is_falling_back{false}; // for m.replace fallback
    bool valid{false};

    static ParsedRelation invalid() {
      ParsedRelation p;
      p.valid = false;
      return p;
    }
  };

  // Parse m.relates_to from event content
  ParsedRelation parse_relation(const json& content) {
    ParsedRelation rel;
    rel.valid = false;

    if (!content.contains("m.relates_to")) return rel;

    auto& relates_to = content["m.relates_to"];
    if (!relates_to.is_object()) return rel;

    if (!relates_to.contains("event_id") || !relates_to["event_id"].is_string()) {
      return rel;
    }

    rel.event_id = relates_to["event_id"].get<std::string>();
    if (rel.event_id.empty()) return rel;

    // Get the relation type
    if (relates_to.contains("rel_type") && relates_to["rel_type"].is_string()) {
      rel.rel_type = relates_to["rel_type"].get<std::string>();
    }

    // For m.annotation, get the key
    if (rel.rel_type == relation_types::ANNOTATION) {
      if (relates_to.contains("key") && relates_to["key"].is_string()) {
        rel.key = relates_to["key"].get<std::string>();
      } else {
        // Key is required for annotations
        return rel;
      }
    }

    // For m.replace, check for fallback
    if (rel.rel_type == relation_types::REPLACE) {
      if (content.contains("m.new_content")) {
        rel.is_falling_back = false;
      } else {
        rel.is_falling_back = true;
      }
    }

    rel.valid = relation_types::is_valid_relation_type(rel.rel_type);
    return rel;
  }

  // --------------------------------------------------------------------------
  // Validate relations
  // --------------------------------------------------------------------------

  struct ValidationResult {
    bool is_valid{false};
    std::string error;
    std::string errcode;

    static ValidationResult ok() {
      ValidationResult r;
      r.is_valid = true;
      return r;
    }

    static ValidationResult fail(const std::string& errcode,
                                   const std::string& error) {
      ValidationResult r;
      r.is_valid = false;
      r.errcode = errcode;
      r.error = error;
      return r;
    }
  };

  // Validate a relation before processing it
  ValidationResult validate_relation(const ParsedRelation& rel,
                                      const std::string& sender,
                                      const std::string& room_id) {
    if (!rel.valid) {
      return ValidationResult::fail("M_INVALID_PARAM",
                                      "Invalid relation type '" + rel.rel_type + "'");
    }

    // Validate the target event ID format
    if (!is_valid_event_id(rel.event_id)) {
      return ValidationResult::fail("M_INVALID_PARAM",
                                      "Invalid event_id in relation");
    }

    // Thread validation
    if (rel.rel_type == relation_types::THREAD) {
      if (!thread_config_.enable_threads) {
        return ValidationResult::fail("M_FORBIDDEN",
                                        "Threading is not enabled");
      }

      // Check if event is already in a thread
      auto existing_thread = thread_mgr_.find_thread_for_event(rel.event_id);
      // Allow if the event is the thread root itself or not yet in any thread
    }

    // Annotation (reaction) validation
    if (rel.rel_type == relation_types::ANNOTATION) {
      if (!reaction_config_.enable_reactions) {
        return ValidationResult::fail("M_FORBIDDEN",
                                        "Reactions are not enabled");
      }

      // Validate reaction key length
      if (static_cast<int>(rel.key.size()) > reaction_config_.max_reaction_key_length) {
        return ValidationResult::fail("M_INVALID_PARAM",
                                        "Reaction key too long (max " +
                                        std::to_string(reaction_config_.max_reaction_key_length) + ")");
      }

      // Check user hasn't already reacted with same key
      auto existing = get_reactions_for_event(rel.event_id);
      int user_reactions = 0;
      for (auto& reaction : existing) {
        if (reaction.sender == sender && reaction.aggregation_key == rel.key) {
          user_reactions++;
        }
      }
      if (user_reactions >= reaction_config_.max_reactions_per_user_per_event) {
        return ValidationResult::fail("M_LIMIT_EXCEEDED",
                                        "Already reacted with this key");
      }
    }

    // Edit validation
    if (rel.rel_type == relation_types::REPLACE) {
      if (!edit_config_.enable_edits) {
        return ValidationResult::fail("M_FORBIDDEN",
                                        "Edits are not enabled");
      }

      // Must have m.new_content
      auto rel_json = relation_store_.get_relation_for_event(rel.event_id);
      // Check that the sender of the original event matches
      // (only the original sender can edit)
    }

    // Reference validation (replies)
    if (rel.rel_type == relation_types::REFERENCE) {
      // References are always allowed as long as the target exists
    }

    return ValidationResult::ok();
  }

  // --------------------------------------------------------------------------
  // Process a relation event
  // --------------------------------------------------------------------------

  bool process_relation(const std::string& event_id,
                         const std::string& room_id,
                         const std::string& sender,
                         const json& content,
                         int64_t timestamp) {
    auto parsed = parse_relation(content);
    if (!parsed.valid) return false;

    // Validate
    auto validation = validate_relation(parsed, sender, room_id);
    if (!validation.is_valid) return false;

    // Store the relation
    RelationInfo info;
    info.event_id = parsed.event_id;
    info.relation_type = parsed.rel_type;
    info.aggregation_key = parsed.key;
    info.origin_server_ts = timestamp;
    info.sender = sender;
    info.content = content;

    if (parsed.rel_type == relation_types::REPLACE) {
      info.content = content.value("m.new_content", json::object());
    }

    relation_store_.add_relation(event_id, info);

    // Handle thread-specific processing
    if (parsed.rel_type == relation_types::THREAD) {
      // Mark the target as a thread root
      thread_mgr_.register_thread_root(room_id, parsed.event_id);
      // Add the current event as a reply in the thread
      thread_mgr_.add_thread_reply(parsed.event_id, event_id, sender, timestamp);
    }

    return true;
  }

  // --------------------------------------------------------------------------
  // Handle event redaction for relations
  // --------------------------------------------------------------------------

  void handle_redaction(const std::string& redacted_event_id) {
    // Check if this event has any relations to other events
    auto rel = relation_store_.get_relation_for_event(redacted_event_id);
    if (rel) {
      // If it's a thread reply, remove from thread tracking
      if (rel->relation_type == relation_types::THREAD) {
        thread_mgr_.remove_thread_reply(rel->event_id, redacted_event_id);
      }
    }

    // Also check if this event is a relation target
    // Remove all relations pointing to it
    relation_store_.remove_relation(redacted_event_id);
  }

  // --------------------------------------------------------------------------
  // Reaction-specific methods
  // --------------------------------------------------------------------------

  // Get all reactions for an event
  std::vector<RelationInfo> get_reactions_for_event(const std::string& event_id) {
    return relation_store_.get_relations_for_parent(event_id,
        relation_types::ANNOTATION);
  }

  // Get reaction count summary
  std::vector<ReactionSummary> get_reaction_summary(const std::string& event_id,
                                                       const std::string& current_user_id) {
    std::vector<ReactionSummary> summaries;
    auto reactions = get_reactions_for_event(event_id);

    std::map<std::string, ReactionSummary> by_key;

    for (auto& reaction : reactions) {
      auto& summary = by_key[reaction.aggregation_key];
      if (summary.event_id.empty()) {
        summary.event_id = event_id;
        summary.aggregation_key = reaction.aggregation_key;
      }
      summary.count++;
      if (reaction.sender == current_user_id) {
        summary.current_user_reacted = true;
      }
      if (summary.first_ts == 0 || reaction.origin_server_ts < summary.first_ts) {
        summary.first_ts = reaction.origin_server_ts;
      }
    }

    for (auto& [key, summary] : by_key) {
      summaries.push_back(summary);
    }

    // Sort by count descending, then by key ascending
    std::sort(summaries.begin(), summaries.end(),
              [](const ReactionSummary& a, const ReactionSummary& b) {
                if (a.count != b.count) return a.count > b.count;
                return a.aggregation_key < b.aggregation_key;
              });

    return summaries;
  }

  // Add a reaction
  bool add_reaction(const std::string& event_id,
                     const std::string& target_event_id,
                     const std::string& sender,
                     const std::string& reaction_key,
                     int64_t timestamp) {
    if (!reaction_config_.enable_reactions) return false;

    // Check for existing reaction
    auto existing = get_reactions_for_event(target_event_id);
    int count = 0;
    for (auto& r : existing) {
      if (r.sender == sender && r.aggregation_key == reaction_key) count++;
    }
    if (count >= reaction_config_.max_reactions_per_user_per_event) {
      return false; // already reacted
    }

    RelationInfo info;
    info.event_id = target_event_id;
    info.relation_type = relation_types::ANNOTATION;
    info.aggregation_key = reaction_key;
    info.origin_server_ts = timestamp;
    info.sender = sender;

    relation_store_.add_relation(event_id, info);
    return true;
  }

  // Remove a reaction (redaction)
  bool remove_reaction(const std::string& reaction_event_id) {
    auto rel = relation_store_.get_relation_for_event(reaction_event_id);
    if (rel && rel->relation_type == relation_types::ANNOTATION) {
      relation_store_.remove_relation(reaction_event_id);
      return true;
    }
    return false;
  }

  // --------------------------------------------------------------------------
  // Edit-specific methods
  // --------------------------------------------------------------------------

  // Check if an event is an edit (m.replace)
  bool is_edit(const json& content) {
    if (!content.contains("m.relates_to")) return false;
    auto& rel = content["m.relates_to"];
    if (!rel.is_object() || !rel.contains("rel_type")) return false;
    return rel["rel_type"].get<std::string>() == relation_types::REPLACE;
  }

  // Get the edit history for an event
  std::vector<RelationInfo> get_edit_history(const std::string& event_id) {
    auto edits = relation_store_.get_relations_for_parent(event_id,
        relation_types::REPLACE);
    std::sort(edits.begin(), edits.end(),
              [](const RelationInfo& a, const RelationInfo& b) {
                return a.origin_server_ts < b.origin_server_ts;
              });
    return edits;
  }

  // Get the latest edit for an event
  std::optional<RelationInfo> get_latest_edit(const std::string& event_id) {
    auto history = get_edit_history(event_id);
    if (history.empty()) return std::nullopt;
    return history.back();
  }

  // Apply an edit to event content (for display)
  json apply_edit(const json& original_content, const json& edit_content) {
    json result = original_content;

    // Apply m.new_content on top of the original
    if (edit_content.contains("m.new_content")) {
      auto& nc = edit_content["m.new_content"];
      if (nc.is_object()) {
        for (auto& [key, value] : nc.items()) {
          result[key] = value;
        }
      }
    }

    return result;
  }

  // Build edit summary for bundled relations
  EditSummary get_edit_summary(const std::string& event_id) {
    EditSummary summary;
    auto history = get_edit_history(event_id);
    if (!history.empty()) {
      summary.is_edited = true;
      summary.edit_count = static_cast<int64_t>(history.size());
      auto& latest = history.back();
      summary.latest_edit_event_id = latest.event_id;
      summary.latest_edit_ts = latest.origin_server_ts;
      summary.latest_editor = latest.sender;
    }
    return summary;
  }

  // Add an edit event
  bool add_edit(const std::string& edit_event_id,
                 const std::string& original_event_id,
                 const std::string& sender,
                 const json& new_content,
                 int64_t timestamp) {
    if (!edit_config_.enable_edits) return false;

    // Check max edit depth (don't allow edits of edits)
    auto existing = relation_store_.get_relation_for_event(original_event_id);
    if (existing && existing->relation_type == relation_types::REPLACE) {
      return false; // can't edit an edit
    }

    RelationInfo info;
    info.event_id = original_event_id;
    info.relation_type = relation_types::REPLACE;
    info.origin_server_ts = timestamp;
    info.sender = sender;
    info.content = new_content;

    relation_store_.add_relation(edit_event_id, info);

    // Enforce max edit history
    auto history = get_edit_history(original_event_id);
    if (static_cast<int>(history.size()) > edit_config_.max_edit_history) {
      // Remove oldest edits
      auto to_remove = history.front();
      relation_store_.remove_relation(to_remove.event_id);
    }

    return true;
  }

private:
  RelationStore& relation_store_;
  ThreadRelationManager& thread_mgr_;
  ThreadConfig thread_config_;
  ReactionConfig reaction_config_;
  EditConfig edit_config_;
};

// ============================================================================
// ReactionAggregator — specialized reaction counting and aggregation
// ============================================================================
class ReactionAggregator {
public:
  ReactionAggregator(RelationStore& relation_store,
                      EventRelationEngine& relation_engine,
                      const ReactionConfig& cfg = {})
      : relation_store_(relation_store),
        relation_engine_(relation_engine),
        config_(cfg) {}

  // --------------------------------------------------------------------------
  // Reaction aggregation for a single event
  // --------------------------------------------------------------------------

  json aggregate_reactions(const std::string& event_id,
                            const std::string& current_user_id) {
    json result = json::array();
    auto summaries = relation_engine_.get_reaction_summary(event_id,
        current_user_id);

    for (auto& summary : summaries) {
      json reaction;
      reaction["key"] = summary.aggregation_key;
      reaction["count"] = summary.count;
      reaction["first_ts"] = summary.first_ts;
      if (summary.current_user_reacted) {
        reaction["self"] = true;
      }
      result.push_back(reaction);
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Batch aggregation for multiple events
  // --------------------------------------------------------------------------

  json batch_aggregate_reactions(const std::vector<std::string>& event_ids,
                                   const std::string& current_user_id) {
    json result = json::object();
    for (auto& event_id : event_ids) {
      auto reactions = aggregate_reactions(event_id, current_user_id);
      if (!reactions.empty()) {
        result[event_id] = reactions;
      }
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Reaction deduplication
  // --------------------------------------------------------------------------

  bool has_user_reacted(const std::string& event_id,
                         const std::string& user_id,
                         const std::string& key) {
    auto reactions = relation_engine_.get_reactions_for_event(event_id);
    for (auto& reaction : reactions) {
      if (reaction.sender == user_id && reaction.aggregation_key == key) {
        return true;
      }
    }
    return false;
  }

  // Get all unique reaction keys for an event
  std::vector<std::string> get_unique_reaction_keys(const std::string& event_id) {
    std::set<std::string> keys;
    auto reactions = relation_engine_.get_reactions_for_event(event_id);
    for (auto& reaction : reactions) {
      keys.insert(reaction.aggregation_key);
    }
    return std::vector<std::string>(keys.begin(), keys.end());
  }

  // Get total reaction count for an event
  int64_t get_total_reaction_count(const std::string& event_id) {
    return relation_store_.get_relation_count(event_id,
        relation_types::ANNOTATION);
  }

  // Get reactors for a specific reaction key
  std::vector<std::string> get_reactors(const std::string& event_id,
                                          const std::string& key) {
    std::vector<std::string> reactors;
    auto reactions = relation_engine_.get_reactions_for_event(event_id);
    for (auto& reaction : reactions) {
      if (reaction.aggregation_key == key) {
        reactors.push_back(reaction.sender);
      }
    }
    return reactors;
  }

  // Check if reaction limit has been reached
  bool is_reaction_limit_reached(const std::string& event_id) {
    auto keys = get_unique_reaction_keys(event_id);
    return static_cast<int>(keys.size()) >= config_.max_unique_reactions_per_event;
  }

  // Build reaction summary for sync bundled relations
  json build_sync_reaction_summary(const std::string& event_id,
                                     const std::string& current_user_id) {
    json result;
    auto summaries = relation_engine_.get_reaction_summary(event_id,
        current_user_id);

    if (summaries.empty()) return result;

    result["count"] = get_total_reaction_count(event_id);

    json by_key = json::object();
    for (auto& summary : summaries) {
      json key_info;
      key_info["count"] = summary.count;
      if (summary.current_user_reacted) key_info["self"] = true;
      key_info["first_ts"] = summary.first_ts;
      by_key[summary.aggregation_key] = key_info;
    }
    result["by_key"] = by_key;

    return result;
  }

private:
  RelationStore& relation_store_;
  EventRelationEngine& relation_engine_;
  ReactionConfig config_;
};

// ============================================================================
// MessageEditManager — manages message edit lifecycle
// ============================================================================
class MessageEditManager {
public:
  MessageEditManager(RelationStore& relation_store,
                      EventRelationEngine& relation_engine,
                      const EditConfig& cfg = {})
      : relation_store_(relation_store),
        relation_engine_(relation_engine),
        config_(cfg) {}

  // --------------------------------------------------------------------------
  // Edit creation and validation
  // --------------------------------------------------------------------------

  struct EditResult {
    bool success{false};
    std::string error;
    std::string errcode;
    json resolved_content;

    static EditResult ok(const json& resolved) {
      EditResult r;
      r.success = true;
      r.resolved_content = resolved;
      return r;
    }

    static EditResult fail(const std::string& errcode, const std::string& error) {
      EditResult r;
      r.success = false;
      r.errcode = errcode;
      r.error = error;
      return r;
    }
  };

  // Process an edit event
  EditResult process_edit(const std::string& edit_event_id,
                           const std::string& original_event_id,
                           const std::string& sender,
                           const json& original_content,
                           const json& edit_content,
                           int64_t timestamp) {
    // Validate the edit
    if (!config_.enable_edits) {
      return EditResult::fail("M_FORBIDDEN",
                               "Message edits are not enabled");
    }

    // Check that new_content exists
    if (!edit_content.contains("m.new_content") ||
        !edit_content["m.new_content"].is_object()) {
      return EditResult::fail("M_INVALID_PARAM",
                               "Edit must contain m.new_content");
    }

    // Resolve the new content
    json resolved = relation_engine_.apply_edit(original_content, edit_content);

    // Ensure body is present
    if (!resolved.contains("body") || !resolved["body"].is_string()) {
      return EditResult::fail("M_INVALID_PARAM",
                               "Edited content must have a body");
    }

    // Validate new content structure
    if (edit_config_.validate_new_content) {
      // Ensure msgtype preservation
      if (original_content.contains("msgtype")) {
        if (edit_content["m.new_content"].contains("msgtype") &&
            edit_content["m.new_content"]["msgtype"] != original_content["msgtype"]) {
          return EditResult::fail("M_INVALID_PARAM",
                                   "Cannot change message type in edit");
        }
      }
    }

    // Store the edit relation
    bool added = relation_engine_.add_edit(edit_event_id,
        original_event_id, sender, edit_content["m.new_content"], timestamp);

    if (!added) {
      return EditResult::fail("M_UNKNOWN",
                               "Failed to store edit");
    }

    return EditResult::ok(resolved);
  }

  // --------------------------------------------------------------------------
  // Edit history
  // --------------------------------------------------------------------------

  json get_edit_history_json(const std::string& event_id) {
    json history = json::array();
    auto edits = relation_engine_.get_edit_history(event_id);

    for (auto& edit : edits) {
      json entry;
      entry["event_id"] = edit.event_id;  // This is the actual edit relation event
      entry["sender"] = edit.sender;
      entry["origin_server_ts"] = edit.origin_server_ts;
      entry["new_content"] = edit.content;
      history.push_back(entry);
    }

    return history;
  }

  // Get the resolved (edited) content for an event
  json get_resolved_content(const std::string& event_id,
                              const json& original_content) {
    auto latest = relation_engine_.get_latest_edit(event_id);
    if (!latest) return original_content;
    return relation_engine_.apply_edit(original_content, latest->content);
  }

  // Generate fallback text for a replacement event
  std::string generate_fallback_text(const json& original_content,
                                      const json& new_content) {
    if (!config_.include_fallback_body) return "";

    std::string fallback;
    if (original_content.contains("body") && original_content["body"].is_string()) {
      fallback += "> " + original_content["body"].get<std::string>() + "\n";
    }
    if (new_content.contains("body") && new_content["body"].is_string()) {
      fallback += new_content["body"].get<std::string>();
    }
    return fallback;
  }

  // Build m.new_content for an edit event
  static json build_new_content(const std::string& new_body,
                                  const json& original_content) {
    json nc;
    nc["body"] = new_body;

    // Copy over msgtype if present
    if (original_content.contains("msgtype")) {
      nc["msgtype"] = original_content["msgtype"];
    }

    // Handle formatted_body
    if (original_content.contains("formatted_body")) {
      // In a real implementation, you'd parse and re-render
      nc["format"] = json_str(original_content, "format", "");
      nc["formatted_body"] = new_body;
    }

    return nc;
  }

  // Count edits for an event
  int64_t count_edits(const std::string& event_id) {
    return relation_store_.get_relation_count(event_id,
        relation_types::REPLACE);
  }

  // Check if an event has been edited
  bool is_edited(const std::string& event_id) {
    return count_edits(event_id) > 0;
  }

private:
  RelationStore& relation_store_;
  EventRelationEngine& relation_engine_;
  EditConfig config_;
};

// ============================================================================
// ReadMarkerManager — manages read markers per room and per thread
// ============================================================================
class ReadMarkerManager {
public:
  ReadMarkerManager(const ReadMarkerConfig& cfg = {}) : config_(cfg) {}

  // --------------------------------------------------------------------------
  // Fully-read marker (room level)
  // --------------------------------------------------------------------------

  // Set the fully-read marker for a room
  void set_fully_read(const std::string& user_id,
                       const std::string& room_id,
                       const std::string& event_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& info = read_markers_[user_id][room_id];
    info.room_id = room_id;
    info.user_id = user_id;
    info.fully_read_event_id = event_id;
    info.updated_at_ms = now_ms();
  }

  // Get the fully-read marker
  std::optional<ReadMarkerInfo> get_read_marker(const std::string& user_id,
                                                  const std::string& room_id) {
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto user_it = read_markers_.find(user_id);
    if (user_it != read_markers_.end()) {
      auto room_it = user_it->second.find(room_id);
      if (room_it != user_it->second.end()) return room_it->second;
    }
    return std::nullopt;
  }

  // Get the fully-read event ID
  std::string get_fully_read_event_id(const std::string& user_id,
                                       const std::string& room_id) {
    auto marker = get_read_marker(user_id, room_id);
    if (marker) return marker->fully_read_event_id;
    return "";
  }

  // --------------------------------------------------------------------------
  // Read receipt (last read position, room level)
  // --------------------------------------------------------------------------

  // Set read receipt
  void set_read_receipt(const std::string& user_id,
                         const std::string& room_id,
                         const std::string& event_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& info = read_markers_[user_id][room_id];
    info.room_id = room_id;
    info.user_id = user_id;
    info.read_receipt_event_id = event_id;
    info.updated_at_ms = now_ms();
  }

  // Get read receipt
  std::optional<std::string> get_read_receipt(const std::string& user_id,
                                                const std::string& room_id) {
    auto marker = get_read_marker(user_id, room_id);
    if (marker) return marker->read_receipt_event_id;
    return std::nullopt;
  }

  // --------------------------------------------------------------------------
  // Per-thread read markers
  // --------------------------------------------------------------------------

  // Set read marker for a specific thread
  void set_thread_read_marker(const std::string& user_id,
                               const std::string& room_id,
                               const std::string& thread_root_id,
                               const std::string& event_id) {
    if (!config_.enable_per_thread_markers) return;

    std::lock_guard<std::shared_mutex> lock(mu_);
    auto& info = read_markers_[user_id][room_id];
    info.room_id = room_id;
    info.user_id = user_id;
    info.thread_read_markers[thread_root_id] = event_id;
    info.updated_at_ms = now_ms();
  }

  // Get read marker for a specific thread
  std::string get_thread_read_marker(const std::string& user_id,
                                      const std::string& room_id,
                                      const std::string& thread_root_id) {
    auto marker = get_read_marker(user_id, room_id);
    if (!marker) return "";

    auto it = marker->thread_read_markers.find(thread_root_id);
    if (it != marker->thread_read_markers.end()) return it->second;
    return "";
  }

  // Get all thread read markers for a room
  std::map<std::string, std::string> get_all_thread_read_markers(
      const std::string& user_id,
      const std::string& room_id) {
    auto marker = get_read_marker(user_id, room_id);
    if (marker) return marker->thread_read_markers;
    return {};
  }

  // --------------------------------------------------------------------------
  // Count unread messages
  // --------------------------------------------------------------------------

  // Count unread events in a room after a given event ID
  int64_t count_unread_events(const std::string& user_id,
                               const std::string& room_id,
                               const std::vector<std::string>& event_ids,
                               const std::string& highlight_event_id_filter = "") {
    auto marker = get_read_marker(user_id, room_id);
    std::string last_read = marker ? marker->fully_read_event_id : "";

    if (last_read.empty()) return static_cast<int64_t>(event_ids.size());

    int64_t unread = 0;
    bool found = false;
    for (auto it = event_ids.rbegin(); it != event_ids.rend(); ++it) {
      if (*it == last_read) {
        found = true;
        break;
      }
      unread++;
    }
    return unread;
  }

  // Check if there are any unread events
  bool has_unread(const std::string& user_id,
                   const std::string& room_id,
                   const std::vector<std::string>& event_ids) {
    return count_unread_events(user_id, room_id, event_ids) > 0;
  }

  // --------------------------------------------------------------------------
  // Build read markers for sync response
  // --------------------------------------------------------------------------

  json build_sync_read_markers(const std::string& user_id,
                                 const std::string& room_id) {
    json result;
    auto marker = get_read_marker(user_id, room_id);
    if (!marker) return result;

    result["room_id"] = marker->room_id;
    result["m.fully_read"] = marker->fully_read_event_id;

    if (marker->read_receipt_event_id) {
      result["m.read"] = *marker->read_receipt_event_id;
    }

    if (config_.enable_per_thread_markers &&
        !marker->thread_read_markers.empty()) {
      json thread_markers = json::object();
      for (auto& [tid, eid] : marker->thread_read_markers) {
        thread_markers[tid] = eid;
      }
      result["m.thread_read"] = thread_markers;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Bulk operations
  // --------------------------------------------------------------------------

  // Bulk-update read markers for a user across rooms
  void bulk_set_read_markers(const std::string& user_id,
                              const std::vector<ReadMarkerInfo>& markers) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    for (auto& marker : markers) {
      read_markers_[user_id][marker.room_id] = marker;
      read_markers_[user_id][marker.room_id].updated_at_ms = now_ms();
    }
  }

  // Remove all markers for a room
  void clear_room_markers(const std::string& user_id,
                           const std::string& room_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    auto user_it = read_markers_.find(user_id);
    if (user_it != read_markers_.end()) {
      user_it->second.erase(room_id);
    }
  }

  // Remove all markers for a user
  void clear_user_markers(const std::string& user_id) {
    std::lock_guard<std::shared_mutex> lock(mu_);
    read_markers_.erase(user_id);
  }

  // Get all marked room IDs for a user
  std::vector<std::string> get_marked_rooms(const std::string& user_id) {
    std::vector<std::string> rooms;
    std::shared_lock<std::shared_mutex> lock(mu_);
    auto user_it = read_markers_.find(user_id);
    if (user_it != read_markers_.end()) {
      for (auto& [rid, info] : user_it->second) {
        rooms.push_back(rid);
      }
    }
    return rooms;
  }

private:
  ReadMarkerConfig config_;
  mutable std::shared_mutex mu_;

  // user_id -> room_id -> ReadMarkerInfo
  std::unordered_map<std::string,
    std::unordered_map<std::string, ReadMarkerInfo>> read_markers_;
};

// ============================================================================
// AggregationGroupManager — groups event relations for sync responses
// ============================================================================
class AggregationGroupManager {
public:
  AggregationGroupManager(RelationStore& relation_store,
                           ThreadRelationManager& thread_mgr,
                           EventRelationEngine& relation_engine,
                           ReadMarkerManager& read_marker_mgr,
                           const AggregationConfig& cfg = {})
      : relation_store_(relation_store),
        thread_mgr_(thread_mgr),
        relation_engine_(relation_engine),
        read_marker_mgr_(read_marker_mgr),
        config_(cfg) {}

  // --------------------------------------------------------------------------
  // Build aggregation bundle for a single event
  // --------------------------------------------------------------------------

  AggregatedRelationBundle build_aggregation_bundle(
      const std::string& event_id,
      const std::string& current_user_id) {
    AggregatedRelationBundle bundle;
    bundle.target_event_id = event_id;
    bundle.has_aggregations = false;

    // Thread summary
    if (config_.include_thread_summary_in_sync) {
      auto thread_summary = thread_mgr_.get_thread_summary(event_id);
      if (thread_summary && thread_summary->reply_count > 0) {
        thread_summary->participated = thread_mgr_.has_participated(
            event_id, current_user_id);
        bundle.thread_summary = *thread_summary;
        bundle.has_aggregations = true;
      }
    }

    // Reaction summary
    if (config_.include_reaction_count_in_sync) {
      bundle.reactions = relation_engine_.get_reaction_summary(
          event_id, current_user_id);
      if (!bundle.reactions.empty()) {
        bundle.has_aggregations = true;
      }
    }

    // Edit info
    if (config_.include_edit_info_in_sync) {
      bundle.edit_info = relation_engine_.get_edit_summary(event_id);
      if (bundle.edit_info.is_edited) {
        bundle.has_aggregations = true;
      }
    }

    // Reference count
    bundle.reference_count = relation_store_.get_relation_count(
        event_id, relation_types::REFERENCE);
    if (bundle.reference_count > 0) {
      bundle.has_aggregations = true;
    }

    return bundle;
  }

  // --------------------------------------------------------------------------
  // Batch build aggregation bundles
  // --------------------------------------------------------------------------

  std::map<std::string, AggregatedRelationBundle> batch_build_aggregations(
      const std::vector<std::string>& event_ids,
      const std::string& current_user_id) {
    std::map<std::string, AggregatedRelationBundle> results;

    // Limit the number of events to process
    size_t limit = std::min(event_ids.size(),
        static_cast<size_t>(config_.max_aggregated_relations_per_event));

    for (size_t i = 0; i < limit; ++i) {
      auto bundle = build_aggregation_bundle(event_ids[i], current_user_id);
      if (bundle.has_aggregations) {
        results[event_ids[i]] = std::move(bundle);
      }
    }

    return results;
  }

  // --------------------------------------------------------------------------
  // Build aggregated relations section for sync response
  // --------------------------------------------------------------------------

  json build_sync_aggregations(const std::string& room_id,
                                 const std::string& current_user_id,
                                 const std::vector<std::string>& recent_event_ids) {
    json result;

    if (!config_.enable_aggregations) return result;

    // Get thread info for the room
    auto thread_roots = thread_mgr_.get_threads_ordered_by_activity(room_id, 50);
    json threads_section = json::object();
    for (auto& root_id : thread_roots) {
      auto summary = thread_mgr_.get_thread_summary(root_id);
      if (summary && summary->reply_count > 0) {
        summary->participated = thread_mgr_.has_participated(
            root_id, current_user_id);
        threads_section[root_id] = summary->to_json();
      }
    }
    if (!threads_section.empty()) {
      result["threads"] = threads_section;
    }

    // Get aggregations for recent events
    auto bundles = batch_build_aggregations(recent_event_ids, current_user_id);
    json aggregations = json::object();
    for (auto& [event_id, bundle] : bundles) {
      aggregations[event_id] = bundle.to_json();
    }
    if (!aggregations.empty()) {
      result["aggregations"] = aggregations;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Group events by relation type
  // --------------------------------------------------------------------------

  struct RelationGroup {
    std::string parent_event_id;
    std::string relation_type;
    std::vector<std::string> child_event_ids;
    int64_t total_count{0};
  };

  std::vector<RelationGroup> group_events_by_relation(
      const std::string& room_id,
      const std::string& relation_type) {
    std::unordered_map<std::string, RelationGroup> groups;

    auto thread_roots = thread_mgr_.get_thread_roots(room_id);
    for (auto& root : thread_roots) {
      auto relations = relation_store_.get_relations_for_parent(root, relation_type);
      for (auto& rel : relations) {
        auto& group = groups[rel.event_id];
        group.parent_event_id = rel.event_id;
        group.relation_type = relation_type;
        group.child_event_ids.push_back(rel.event_id);
        group.total_count++;
      }
    }

    std::vector<RelationGroup> result;
    for (auto& [id, group] : groups) {
      result.push_back(std::move(group));
    }

    // Sort by total count descending
    std::sort(result.begin(), result.end(),
              [](const RelationGroup& a, const RelationGroup& b) {
                return a.total_count > b.total_count;
              });

    return result;
  }

  // --------------------------------------------------------------------------
  // Compact aggregation counts for sync
  // --------------------------------------------------------------------------

  json build_compact_aggregations(const std::string& room_id) {
    json result = json::object();

    // Get reaction counts for all thread roots
    auto thread_roots = thread_mgr_.get_thread_roots(room_id);
    for (auto& root : thread_roots) {
      auto reaction_counts = relation_store_.get_aggregation_counts(
          root, relation_types::ANNOTATION);
      auto edit_count = relation_store_.get_relation_count(
          root, relation_types::REPLACE);
      auto ref_count = relation_store_.get_relation_count(
          root, relation_types::REFERENCE);

      json counts;
      if (!reaction_counts.empty()) {
        json reactions = json::object();
        for (auto& [key, count] : reaction_counts) {
          reactions[key] = count;
        }
        counts["m.annotation"] = reactions;
      }
      if (edit_count > 0) counts["m.replace"] = edit_count;
      if (ref_count > 0) counts["m.reference"] = ref_count;

      if (!counts.empty()) {
        result[root] = counts;
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Event timeline enrichment
  // --------------------------------------------------------------------------

  // Enrich timeline events with bundled aggregations
  json enrich_timeline(const json& timeline_events,
                        const std::string& current_user_id) {
    json enriched = json::array();

    for (auto& event : timeline_events) {
      json evt = event;
      std::string event_id = json_str(event, "event_id");
      if (!event_id.empty()) {
        auto bundle = build_aggregation_bundle(event_id, current_user_id);
        if (bundle.has_aggregations) {
          evt["unsigned"] = evt.value("unsigned", json::object());
          evt["unsigned"]["m.relations"] = bundle.to_json();
        }
      }
      enriched.push_back(evt);
    }

    return enriched;
  }

  // --------------------------------------------------------------------------
  // Cache management
  // --------------------------------------------------------------------------

  std::optional<json> get_cached_aggregation(const std::string& cache_key) {
    return aggregation_cache_.get(cache_key);
  }

  void cache_aggregation(const std::string& cache_key, const json& data) {
    aggregation_cache_.put(cache_key, data);
  }

  void invalidate_aggregation_cache(const std::string& event_id) {
    aggregation_cache_.invalidate(event_id);
  }

  void clear_aggregation_cache() {
    aggregation_cache_.clear();
  }

private:
  RelationStore& relation_store_;
  ThreadRelationManager& thread_mgr_;
  EventRelationEngine& relation_engine_;
  ReadMarkerManager& read_marker_mgr_;
  AggregationConfig config_;

  TTLCache<std::string, json> aggregation_cache_{
    config_.aggregation_cache_ttl_ms > 0 ?
    config_.aggregation_cache_ttl_ms : 120000};
};

// ============================================================================
// ThreadCoordinator — top-level coordinator for all threading operations
// ============================================================================
class ThreadCoordinator {
public:
  ThreadCoordinator()
      : thread_mgr_(relation_store_),
        sync_builder_(thread_mgr_, relation_store_),
        notification_mgr_(thread_mgr_),
        relation_engine_(relation_store_, thread_mgr_),
        reaction_aggregator_(relation_store_, relation_engine_),
        edit_manager_(relation_store_, relation_engine_),
        read_marker_mgr_(),
        aggregation_mgr_(relation_store_, thread_mgr_, relation_engine_,
                          read_marker_mgr_) {}

  // --------------------------------------------------------------------------
  // Configuration access
  // --------------------------------------------------------------------------

  ThreadConfig& thread_config() { return thread_config_; }
  ReactionConfig& reaction_config() { return reaction_config_; }
  EditConfig& edit_config() { return edit_config_; }
  ReadMarkerConfig& read_marker_config() { return read_marker_config_; }
  AggregationConfig& aggregation_config() { return aggregation_config_; }

  // --------------------------------------------------------------------------
  // Event processing
  // --------------------------------------------------------------------------

  // Process a new event for relations/threading
  bool process_event(const std::string& event_id,
                      const std::string& room_id,
                      const std::string& sender,
                      const json& event_content,
                      int64_t timestamp) {
    // Check for relations
    auto parsed = relation_engine_.parse_relation(event_content);
    if (parsed.valid) {
      return relation_engine_.process_relation(event_id, room_id, sender,
          event_content, timestamp);
    }

    // Check if this is an event type that starts or participates in a thread
    // (m.room.message with no m.relates_to is just a normal message)
    return true;
  }

  // Handle redaction of an event
  void handle_redaction(const std::string& redacted_event_id) {
    relation_engine_.handle_redaction(redacted_event_id);
  }

  // --------------------------------------------------------------------------
  // Sync response building
  // --------------------------------------------------------------------------

  // Build the complete threading section of a sync response
  json build_sync_response(const std::string& room_id,
                            const std::string& current_user_id,
                            const json& room_timeline_events) {
    json result;

    // Threads
    if (thread_config_.include_threads_in_sync) {
      auto threads = sync_builder_.build_room_threads(room_id, current_user_id);
      if (!threads.empty()) {
        result["threads"] = threads;
      }
    }

    // Thread notification settings
    if (thread_config_.enable_thread_notifications) {
      auto settings = notification_mgr_.build_notification_settings_sync(
          current_user_id);
      if (!settings.empty()) {
        result["thread_notification_settings"] = settings;
      }
    }

    // Read markers
    if (read_marker_config_.enable_read_markers) {
      auto markers = read_marker_mgr_.build_sync_read_markers(
          current_user_id, room_id);
      if (!markers.empty()) {
        result["read_markers"] = markers;
      }
    }

    // Aggregations / bundled relations
    if (aggregation_config_.enable_aggregations) {
      // Extract event IDs from timeline
      std::vector<std::string> event_ids;
      for (auto& evt : room_timeline_events) {
        std::string eid = json_str(evt, "event_id");
        if (!eid.empty()) event_ids.push_back(eid);
      }

      auto aggregations = aggregation_mgr_.build_sync_aggregations(
          room_id, current_user_id, event_ids);
      for (auto& [key, val] : aggregations.items()) {
        result[key] = val;
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Thread operations delegation
  // --------------------------------------------------------------------------

  ThreadRelationManager& threads() { return thread_mgr_; }
  ThreadSyncBuilder& sync() { return sync_builder_; }
  ThreadNotificationManager& notifications() { return notification_mgr_; }
  EventRelationEngine& relations() { return relation_engine_; }
  ReactionAggregator& reactions() { return reaction_aggregator_; }
  MessageEditManager& edits() { return edit_manager_; }
  ReadMarkerManager& read_markers() { return read_marker_mgr_; }
  AggregationGroupManager& aggregations() { return aggregation_mgr_; }

  // Convenience method: get thread timeline for a root event
  json get_thread_timeline_json(const std::string& root_event_id,
                                  const std::string& current_user_id,
                                  int from_index = 0,
                                  int limit = 20) {
    return sync_builder_.build_thread_timeline_sync(root_event_id,
        from_index, limit, current_user_id);
  }

  // Convenience: get reactions for an event
  json get_reactions_json(const std::string& event_id,
                           const std::string& current_user_id) {
    return reaction_aggregator_.aggregate_reactions(event_id, current_user_id);
  }

  // Convenience: get edit history for an event
  json get_edit_history_json(const std::string& event_id) {
    return edit_manager_.get_edit_history_json(event_id);
  }

  // Convenience: mark thread as read
  void mark_thread_read(const std::string& user_id,
                         const std::string& room_id,
                         const std::string& thread_root_id,
                         const std::string& event_id) {
    read_marker_mgr_.set_thread_read_marker(user_id, room_id,
        thread_root_id, event_id);
  }

  // Convenience: get thread unread counts
  std::map<std::string, int64_t> get_thread_unread_counts(
      const std::string& user_id,
      const std::string& room_id) {
    return notification_mgr_.get_all_thread_unread_counts(user_id, room_id);
  }

  // Convenience: enrich timeline events with relation data
  json enrich_timeline(const json& timeline_events,
                        const std::string& current_user_id) {
    return aggregation_mgr_.enrich_timeline(timeline_events, current_user_id);
  }

  // --------------------------------------------------------------------------
  // Bulk operations
  // --------------------------------------------------------------------------

  // Rebuild all thread state from a set of events
  void rebuild_threads_from_events(const std::string& room_id,
                                    const std::vector<json>& events) {
    // Clear existing thread data for the room
    auto roots = thread_mgr_.get_thread_roots(room_id);
    for (auto& root : roots) {
      // Individual entries get cleaned up as we rebuild
    }

    for (auto& event : events) {
      std::string event_id = json_str(event, "event_id");
      std::string sender = json_str(event, "sender");
      int64_t ts = json_int(event, "origin_server_ts", now_ms());

      json content = event.value("content", json::object());
      process_event(event_id, room_id, sender, content, ts);
    }
  }

  // Get statistics for the room's threading state
  json get_room_threading_stats(const std::string& room_id) {
    json stats;
    stats["total_threads"] = thread_mgr_.get_thread_count(room_id);
    stats["total_relations"] = relation_store_.total_relations();

    int64_t total_replies = 0;
    int64_t total_reactions = 0;
    int64_t total_edits = 0;

    auto roots = thread_mgr_.get_thread_roots(room_id);
    for (auto& root : roots) {
      auto summary = thread_mgr_.get_thread_summary(root);
      if (summary) {
        total_replies += summary->reply_count;
        total_reactions += relation_store_.get_relation_count(
            root, relation_types::ANNOTATION);
        total_edits += relation_store_.get_relation_count(
            root, relation_types::REPLACE);
      }
    }

    stats["total_replies"] = total_replies;
    stats["total_reactions"] = total_reactions;
    stats["total_edits"] = total_edits;

    return stats;
  }

private:
  // Configs
  ThreadConfig thread_config_;
  ReactionConfig reaction_config_;
  EditConfig edit_config_;
  ReadMarkerConfig read_marker_config_;
  AggregationConfig aggregation_config_;

  // Core relationship store
  RelationStore relation_store_;

  // Managers
  ThreadRelationManager thread_mgr_;
  ThreadSyncBuilder sync_builder_;
  ThreadNotificationManager notification_mgr_;
  EventRelationEngine relation_engine_;
  ReactionAggregator reaction_aggregator_;
  MessageEditManager edit_manager_;
  ReadMarkerManager read_marker_mgr_;
  AggregationGroupManager aggregation_mgr_;
};

// ============================================================================
// Thread API handler - processes client thread-related requests
// ============================================================================
class ThreadAPIHandler {
public:
  ThreadAPIHandler(ThreadCoordinator& coordinator)
      : coordinator_(coordinator) {}

  // --------------------------------------------------------------------------
  // GET /_matrix/client/v1/rooms/{roomId}/threads
  // --------------------------------------------------------------------------
  json handle_get_threads(const std::string& room_id,
                           const std::string& user_id,
                           const json& query_params) {
    auto& thread_mgr = coordinator_.threads();
    auto roots = thread_mgr.get_threads_ordered_by_activity(room_id);

    int limit = json_int(query_params, "limit", 50);
    int from = json_int(query_params, "from", 0);

    json result;
    result["room_id"] = room_id;

    json threads = json::array();
    for (size_t i = from; i < std::min(roots.size(), from + limit); ++i) {
      auto summary = thread_mgr.get_thread_summary(roots[i]);
      if (summary) {
        summary->participated = thread_mgr.has_participated(roots[i], user_id);
        json thread_info;
        thread_info["root_event_id"] = roots[i];
        thread_info["summary"] = summary->to_json();
        threads.push_back(thread_info);
      }
    }

    result["threads"] = threads;
    result["total"] = static_cast<int>(roots.size());
    result["next_batch"] = (from + limit < static_cast<int>(roots.size())) ?
        std::to_string(from + limit) : "";

    return result;
  }

  // --------------------------------------------------------------------------
  // GET /_matrix/client/v1/rooms/{roomId}/threads/{threadRootId}
  // --------------------------------------------------------------------------
  json handle_get_thread_detail(const std::string& room_id,
                                  const std::string& thread_root_id,
                                  const std::string& user_id,
                                  const json& query_params) {
    auto& thread_mgr = coordinator_.threads();

    auto summary = thread_mgr.get_thread_summary(thread_root_id);
    if (!summary) {
      return {{"errcode", "M_NOT_FOUND"}, {"error", "Thread not found"}};
    }

    summary->participated = thread_mgr.has_participated(thread_root_id, user_id);

    int limit = json_int(query_params, "limit", 20);
    int from = json_int(query_params, "from", 0);

    json result;
    result = coordinator_.get_thread_timeline_json(thread_root_id,
        user_id, from, limit);
    result["summary"] = summary->to_json();

    // Include reactions for thread events
    json reactions = json::object();
    auto timeline_events = thread_mgr.get_thread_timeline(thread_root_id, limit);
    for (auto& eid : timeline_events) {
      auto r = coordinator_.get_reactions_json(eid, user_id);
      if (!r.empty()) {
        reactions[eid] = r;
      }
    }
    if (!reactions.empty()) {
      result["reactions"] = reactions;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // GET /_matrix/client/v1/rooms/{roomId}/relations/{eventId}
  // --------------------------------------------------------------------------
  json handle_get_relations(const std::string& room_id,
                              const std::string& event_id,
                              const std::string& user_id,
                              const json& query_params) {
    std::string rel_type = json_str(query_params, "rel_type", "");
    std::string direction = json_str(query_params, "dir", "b");
    int limit = json_int(query_params, "limit", 50);
    std::string from_token = json_str(query_params, "from", "");

    auto& relation_store = coordinator_.relations();

    std::vector<RelationInfo> relations;

    if (!rel_type.empty()) {
      relations = relation_store.get_relations_for_parent(event_id);
      // Filter by type
      relations.erase(
          std::remove_if(relations.begin(), relations.end(),
              [&rel_type](const RelationInfo& r) {
                return r.relation_type != rel_type;
              }),
          relations.end());
    } else {
      relations = relation_store.get_relations_for_parent(event_id);
    }

    // Sort by timestamp
    if (direction == "b" || direction == "f") {
      std::sort(relations.begin(), relations.end(),
                [&direction](const RelationInfo& a, const RelationInfo& b) {
                  if (direction == "b")
                    return a.origin_server_ts > b.origin_server_ts;
                  else
                    return a.origin_server_ts < b.origin_server_ts;
                });
    }

    // Paginate
    json result;
    json chunks = json::array();
    size_t start = 0;
    if (!from_token.empty()) {
      auto it = std::find_if(relations.begin(), relations.end(),
          [&from_token](const RelationInfo& r) {
            return r.event_id == from_token;
          });
      if (it != relations.end()) {
        start = std::distance(relations.begin(), it) + 1;
      }
    }

    for (size_t i = start;
         i < std::min(relations.size(), start + limit); ++i) {
      chunks.push_back(relations[i].to_json());
    }

    result["chunk"] = chunks;
    result["original_event_id"] = event_id;
    if (start + limit < relations.size()) {
      result["next_batch"] = relations[start + limit].event_id;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // GET /_matrix/client/v1/rooms/{roomId}/relations/{eventId}/{relType}/{key}
  // --------------------------------------------------------------------------
  json handle_get_relations_by_key(const std::string& room_id,
                                     const std::string& event_id,
                                     const std::string& rel_type,
                                     const std::string& key,
                                     const std::string& user_id,
                                     const json& query_params) {
    int limit = json_int(query_params, "limit", 50);
    std::string from_token = json_str(query_params, "from", "");

    auto& relation_store = coordinator_.relations();
    auto all = relation_store.get_relations_for_parent(event_id, rel_type);

    // Filter by key
    std::vector<RelationInfo> filtered;
    for (auto& rel : all) {
      if (rel.aggregation_key == key) {
        filtered.push_back(rel);
      }
    }

    // Sort by timestamp descending
    std::sort(filtered.begin(), filtered.end(),
              [](const RelationInfo& a, const RelationInfo& b) {
                return a.origin_server_ts > b.origin_server_ts;
              });

    json result;
    json chunks = json::array();
    size_t start = 0;
    if (!from_token.empty()) {
      auto it = std::find_if(filtered.begin(), filtered.end(),
          [&from_token](const RelationInfo& r) {
            return r.event_id == from_token;
          });
      if (it != filtered.end()) {
        start = std::distance(filtered.begin(), it) + 1;
      }
    }

    for (size_t i = start;
         i < std::min(filtered.size(), start + limit); ++i) {
      json entry;
      entry["event_id"] = filtered[i].event_id;
      entry["sender"] = filtered[i].sender;
      entry["origin_server_ts"] = filtered[i].origin_server_ts;
      entry["key"] = filtered[i].aggregation_key;
      chunks.push_back(entry);
    }

    result["chunk"] = chunks;
    if (start + limit < filtered.size()) {
      result["next_batch"] = filtered[start + limit].event_id;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // PUT /_matrix/client/v3/rooms/{roomId}/read_markers
  // --------------------------------------------------------------------------
  json handle_set_read_markers(const std::string& room_id,
                                 const std::string& user_id,
                                 const json& body) {
    auto& markers = coordinator_.read_markers();

    // m.fully_read
    if (body.contains("m.fully_read") && body["m.fully_read"].is_string()) {
      markers.set_fully_read(user_id, room_id,
          body["m.fully_read"].get<std::string>());
    }

    // m.read
    if (body.contains("m.read") && body["m.read"].is_string()) {
      markers.set_read_receipt(user_id, room_id,
          body["m.read"].get<std::string>());
    }

    // m.read.private
    if (body.contains("m.read.private") && body["m.read.private"].is_string()) {
      markers.set_read_receipt(user_id, room_id,
          body["m.read.private"].get<std::string>());
    }

    // Thread read markers
    if (body.contains("m.thread") && body["m.thread"].is_object()) {
      auto& thread_data = body["m.thread"];
      if (thread_data.contains("event_id") && thread_data["event_id"].is_string() &&
          thread_data.contains("thread_id") && thread_data["thread_id"].is_string()) {
        markers.set_thread_read_marker(user_id, room_id,
            thread_data["thread_id"].get<std::string>(),
            thread_data["event_id"].get<std::string>());
      }
    }

    return json::object(); // 200 OK with empty body
  }

  // --------------------------------------------------------------------------
  // Unread notification counts
  // --------------------------------------------------------------------------

  json handle_get_unread_counts(const std::string& user_id,
                                  const std::string& room_id) {
    auto counts = coordinator_.get_thread_unread_counts(user_id, room_id);
    json result = json::object();
    for (auto& [thread_id, count] : counts) {
      result[thread_id] = count;
    }
    return result;
  }

private:
  ThreadCoordinator& coordinator_;
};

// ============================================================================
// Relation utilities - helper functions for external use
// ============================================================================
namespace relation_utils {

// Extract the relationship type from an event's content
std::string get_relation_type(const json& content) {
  if (!content.contains("m.relates_to")) return "";
  auto& rel = content["m.relates_to"];
  if (!rel.is_object() || !rel.contains("rel_type")) return "";
  return json_str(rel, "rel_type");
}

// Extract the parent event ID from a relation
std::string get_relation_parent_id(const json& content) {
  if (!content.contains("m.relates_to")) return "";
  auto& rel = content["m.relates_to"];
  if (!rel.is_object() || !rel.contains("event_id")) return "";
  return json_str(rel, "event_id");
}

// Check if content contains a relation
bool has_relation(const json& content) {
  return content.contains("m.relates_to") &&
         content["m.relates_to"].is_object();
}

// Check if content is an edit
bool is_edit_content(const json& content) {
  return has_relation(content) &&
         get_relation_type(content) == relation_types::REPLACE;
}

// Check if content is a reaction
bool is_reaction_content(const json& content) {
  return has_relation(content) &&
         get_relation_type(content) == relation_types::ANNOTATION;
}

// Check if content is part of a thread
bool is_thread_content(const json& content) {
  return has_relation(content) &&
         get_relation_type(content) == relation_types::THREAD;
}

// Check if content is a reply (reference)
bool is_reply_content(const json& content) {
  return has_relation(content) &&
         get_relation_type(content) == relation_types::REFERENCE;
}

// Get the aggregation key for an annotation
std::string get_annotation_key(const json& content) {
  if (!is_reaction_content(content)) return "";
  auto& rel = content["m.relates_to"];
  return json_str(rel, "key");
}

// Build m.relates_to JSON
json build_relation(const std::string& rel_type,
                      const std::string& event_id,
                      const std::string& key = "") {
  json rel;
  rel["rel_type"] = rel_type;
  rel["event_id"] = event_id;
  if (!key.empty()) {
    rel["key"] = key;
  }
  json result;
  result["m.relates_to"] = rel;
  return result;
}

// Build thread relation
json build_thread_relation(const std::string& thread_root_id,
                            bool is_falling_back = false) {
  json rel;
  rel["rel_type"] = relation_types::THREAD;
  rel["event_id"] = thread_root_id;

  // Add thread-specific flags
  if (is_falling_back) {
    rel["is_falling_back"] = true;
  }

  // Current thread participation (MSC 3391 style)
  rel["latest_event"] = json::object();

  json result;
  result["m.relates_to"] = rel;
  return result;
}

// Build annotation (reaction) relation
json build_annotation_relation(const std::string& event_id,
                                 const std::string& key) {
  return build_relation(relation_types::ANNOTATION, event_id, key);
}

// Build replace (edit) relation
json build_replace_relation(const std::string& event_id) {
  return build_relation(relation_types::REPLACE, event_id);
}

// Build reference (reply) relation
json build_reference_relation(const std::string& event_id) {
  return build_relation(relation_types::REFERENCE, event_id);
}

// Validate event relation circular reference
bool would_create_cycle(const json& content,
                          const std::string& this_event_id,
                          RelationStore& store) {
  std::string parent_id = get_relation_parent_id(content);
  if (parent_id.empty()) return false;
  if (parent_id == this_event_id) return true;

  // Follow the chain (limited depth)
  int max_depth = 10;
  std::string current = parent_id;
  for (int depth = 0; depth < max_depth; ++depth) {
    auto rel = store.get_relation_for_event(current);
    if (!rel) return false;
    if (rel->event_id == this_event_id) return true;
    current = rel->event_id;
  }
  return false;
}

} // namespace relation_utils

// ============================================================================
// /////////////////////////////////////////////////////////////////////////////
// TESTING SECTION
// /////////////////////////////////////////////////////////////////////////////
// ============================================================================
#ifdef THREADING_TESTING
namespace test {

// --------------------------------------------------------------------------
// Test helpers
// --------------------------------------------------------------------------
namespace {
  bool assert_true(bool condition, const std::string& msg = "") {
    if (!condition) {
      std::cerr << "TEST FAILED: " << msg << std::endl;
    }
    return condition;
  }

  bool assert_equal(const std::string& a, const std::string& b,
                     const std::string& msg = "") {
    if (a != b) {
      std::cerr << "TEST FAILED: " << msg << " expected '" << a
                << "' got '" << b << "'" << std::endl;
      return false;
    }
    return true;
  }

  bool assert_equal_int(int64_t a, int64_t b, const std::string& msg = "") {
    if (a != b) {
      std::cerr << "TEST FAILED: " << msg << " expected " << a
                << " got " << b << std::endl;
      return false;
    }
    return true;
  }
} // anonymous namespace

// --------------------------------------------------------------------------
// Test: relation type constants
// --------------------------------------------------------------------------
bool test_relation_type_constants() {
  using namespace relation_types;

  if (!assert_true(is_valid_relation_type(ANNOTATION), "ANNOTATION valid")) return false;
  if (!assert_true(is_valid_relation_type(REPLACE), "REPLACE valid")) return false;
  if (!assert_true(is_valid_relation_type(REFERENCE), "REFERENCE valid")) return false;
  if (!assert_true(is_valid_relation_type(THREAD), "THREAD valid")) return false;
  if (!assert_true(is_valid_relation_type(IN_REPLY_TO), "IN_REPLY_TO valid")) return false;
  if (!assert_true(!is_valid_relation_type("m.invalid"), "invalid type")) return false;
  if (!assert_true(!is_valid_relation_type(""), "empty type")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: parse relation from content
// --------------------------------------------------------------------------
bool test_parse_relation() {
  RelationStore store;
  ThreadRelationManager thread_mgr(store);
  EventRelationEngine engine(store, thread_mgr);

  // Test annotation (reaction)
  json reaction_content;
  reaction_content["m.relates_to"] = {
    {"rel_type", "m.annotation"},
    {"event_id", "$original:localhost"},
    {"key", "👍"}
  };
  reaction_content["body"] = "👍";

  auto parsed = engine.parse_relation(reaction_content);
  if (!assert_true(parsed.valid, "reaction parsed")) return false;
  if (!assert_equal(parsed.rel_type, "m.annotation", "reaction type")) return false;
  if (!assert_equal(parsed.event_id, "$original:localhost", "reaction target")) return false;
  if (!assert_equal(parsed.key, "👍", "reaction key")) return false;

  // Test replace (edit)
  json edit_content;
  edit_content["m.relates_to"] = {
    {"rel_type", "m.replace"},
    {"event_id", "$original:localhost"}
  };
  edit_content["m.new_content"] = {
    {"body", "edited text"},
    {"msgtype", "m.text"}
  };
  edit_content["body"] = " * edited text";

  parsed = engine.parse_relation(edit_content);
  if (!assert_true(parsed.valid, "edit parsed")) return false;
  if (!assert_equal(parsed.rel_type, "m.replace", "edit type")) return false;

  // Test thread
  json thread_content;
  thread_content["m.relates_to"] = {
    {"rel_type", "m.thread"},
    {"event_id", "$threadroot:localhost"}
  };
  thread_content["body"] = "thread reply";

  parsed = engine.parse_relation(thread_content);
  if (!assert_true(parsed.valid, "thread parsed")) return false;
  if (!assert_equal(parsed.rel_type, "m.thread", "thread type")) return false;

  // Test reference (reply)
  json reply_content;
  reply_content["m.relates_to"] = {
    {"rel_type", "m.reference"},
    {"event_id", "$original:localhost"}
  };
  reply_content["body"] = "a reply";

  parsed = engine.parse_relation(reply_content);
  if (!assert_true(parsed.valid, "reply parsed")) return false;
  if (!assert_equal(parsed.rel_type, "m.reference", "reply type")) return false;

  // Test invalid content
  json invalid_content;
  invalid_content["body"] = "no relation";
  parsed = engine.parse_relation(invalid_content);
  if (!assert_true(!parsed.valid, "invalid content")) return false;

  // Test missing event_id
  json missing_eid;
  missing_eid["m.relates_to"] = {
    {"rel_type", "m.annotation"},
    {"key", "x"}
  };
  parsed = engine.parse_relation(missing_eid);
  if (!assert_true(!parsed.valid, "missing event_id")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: relation store operations
// --------------------------------------------------------------------------
bool test_relation_store() {
  RelationStore store;

  // Add relations
  RelationInfo info1;
  info1.event_id = "$target1:localhost";
  info1.relation_type = "m.annotation";
  info1.aggregation_key = "👍";
  info1.origin_server_ts = 1000;
  info1.sender = "@user:localhost";
  store.add_relation("$reaction1:localhost", info1);

  RelationInfo info2;
  info2.event_id = "$target1:localhost";
  info2.relation_type = "m.annotation";
  info2.aggregation_key = "❤️";
  info2.origin_server_ts = 2000;
  info2.sender = "@user2:localhost";
  store.add_relation("$reaction2:localhost", info2);

  RelationInfo info3;
  info3.event_id = "$target1:localhost";
  info3.relation_type = "m.annotation";
  info3.aggregation_key = "👍";
  info3.origin_server_ts = 3000;
  info3.sender = "@user3:localhost";
  store.add_relation("$reaction3:localhost", info3);

  // Get relations for parent
  auto relations = store.get_relations_for_parent("$target1:localhost",
      "m.annotation");
  if (!assert_equal_int(static_cast<int64_t>(relations.size()), 3,
                         "3 annotations")) return false;

  // Get relation count
  int64_t count = store.get_relation_count("$target1:localhost", "m.annotation");
  if (!assert_equal_int(count, 3, "annotation count")) return false;

  // Check non-existent
  count = store.get_relation_count("$nonexistent:localhost", "m.annotation");
  if (!assert_equal_int(count, 0, "nonexistent count")) return false;

  // Get aggregation counts
  auto agg_counts = store.get_aggregation_counts("$target1:localhost",
      "m.annotation");
  if (!assert_equal_int(static_cast<int64_t>(agg_counts.size()), 2,
                         "2 unique keys")) return false;
  if (!assert_equal_int(agg_counts["👍"], 2, "👍 count = 2")) return false;
  if (!assert_equal_int(agg_counts["❤️"], 1, "❤️ count = 1")) return false;

  // Remove a relation
  store.remove_relation("$reaction1:localhost");
  relations = store.get_relations_for_parent("$target1:localhost", "m.annotation");
  if (!assert_equal_int(static_cast<int64_t>(relations.size()), 2,
                         "2 after removal")) return false;

  agg_counts = store.get_aggregation_counts("$target1:localhost", "m.annotation");
  if (!assert_equal_int(agg_counts["👍"], 1, "👍 count after removal")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: thread relation management
// --------------------------------------------------------------------------
bool test_thread_management() {
  RelationStore store;
  ThreadConfig config;
  ThreadRelationManager thread_mgr(store, config);

  std::string room_id = "!test:localhost";

  // Register thread root
  thread_mgr.register_thread_root(room_id, "$thread1:localhost");
  if (!assert_true(thread_mgr.is_thread_root("$thread1:localhost"), "is thread root")) return false;
  if (!assert_true(!thread_mgr.is_thread_root("$nonexistent:localhost"), "not thread root")) return false;

  // Add thread replies
  thread_mgr.add_thread_reply("$thread1:localhost", "$reply1:localhost",
                               "@alice:localhost", 1000);
  thread_mgr.add_thread_reply("$thread1:localhost", "$reply2:localhost",
                               "@bob:localhost", 2000);
  thread_mgr.add_thread_reply("$thread1:localhost", "$reply3:localhost",
                               "@alice:localhost", 3000);

  // Check thread summary
  auto summary = thread_mgr.get_thread_summary("$thread1:localhost");
  if (!assert_true(summary.has_value(), "summary exists")) return false;
  if (!assert_equal_int(summary->reply_count, 3, "3 replies")) return false;
  if (!assert_equal_int(summary->participant_count, 2, "2 participants")) return false;
  if (!assert_equal(summary->latest_reply_event_id, "$reply3:localhost",
                     "latest reply")) return false;

  // Check thread roots
  auto roots = thread_mgr.get_thread_roots(room_id);
  if (!assert_equal_int(static_cast<int64_t>(roots.size()), 1, "1 thread root")) return false;

  // Check participants
  auto participants = thread_mgr.get_participants("$thread1:localhost");
  if (!assert_equal_int(static_cast<int64_t>(participants.size()), 2, "2 participants")) return false;
  if (!assert_true(thread_mgr.has_participated("$thread1:localhost", "@alice:localhost"),
                   "alice participated")) return false;
  if (!assert_true(thread_mgr.has_participated("$thread1:localhost", "@bob:localhost"),
                   "bob participated")) return false;
  if (!assert_true(!thread_mgr.has_participated("$thread1:localhost", "@charlie:localhost"),
                   "charlie not participated")) return false;

  // Get thread timeline
  auto timeline = thread_mgr.get_thread_timeline("$thread1:localhost");
  if (!assert_equal_int(static_cast<int64_t>(timeline.size()), 3,
                         "3 in timeline")) return false;

  // Remove a reply
  thread_mgr.remove_thread_reply("$thread1:localhost", "$reply1:localhost");
  summary = thread_mgr.get_thread_summary("$thread1:localhost");
  if (!assert_equal_int(summary->reply_count, 2, "2 after removal")) return false;

  // Room for thread
  std::string room = thread_mgr.get_room_for_thread("$thread1:localhost");
  if (!assert_equal(room, room_id, "correct room")) return false;

  // Thread count
  int64_t count = thread_mgr.get_thread_count(room_id);
  if (!assert_equal_int(count, 1, "1 thread in room")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: reaction aggregation
// --------------------------------------------------------------------------
bool test_reaction_aggregation() {
  RelationStore store;
  ThreadRelationManager thread_mgr(store);
  ReactionConfig config;
  EventRelationEngine engine(store, thread_mgr, {}, config);
  ReactionAggregator aggregator(store, engine, config);

  // Add reactions
  engine.add_reaction("$react1:localhost", "$msg1:localhost", "@alice:localhost", "👍", 1000);
  engine.add_reaction("$react2:localhost", "$msg1:localhost", "@bob:localhost", "👍", 2000);
  engine.add_reaction("$react3:localhost", "$msg1:localhost", "@charlie:localhost", "❤️", 3000);
  engine.add_reaction("$react4:localhost", "$msg1:localhost", "@bob:localhost", "❤️", 4000);

  // Get reaction summary
  auto summaries = engine.get_reaction_summary("$msg1:localhost", "@alice:localhost");
  if (!assert_equal_int(static_cast<int64_t>(summaries.size()), 2, "2 unique keys")) return false;

  // Find 👍
  bool found_thumbs = false;
  bool found_heart = false;
  bool alice_reacted_thumbs = false;
  for (auto& s : summaries) {
    if (s.aggregation_key == "👍") {
      found_thumbs = true;
      if (!assert_equal_int(s.count, 2, "👍 count")) return false;
      if (s.current_user_reacted) alice_reacted_thumbs = true;
    }
    if (s.aggregation_key == "❤️") {
      found_heart = true;
      if (!assert_equal_int(s.count, 2, "❤️ count")) return false;
    }
  }
  if (!assert_true(found_thumbs, "found 👍")) return false;
  if (!assert_true(found_heart, "found ❤️")) return false;
  if (!assert_true(alice_reacted_thumbs, "alice reacted 👍")) return false;

  // Check duplicate prevention
  bool dup_ok = engine.add_reaction("$reactDup:localhost", "$msg1:localhost",
      "@alice:localhost", "👍", 5000);
  if (!assert_true(!dup_ok, "duplicate reaction prevented")) return false;

  // Check reaction count
  int64_t total = aggregator.get_total_reaction_count("$msg1:localhost");
  if (!assert_equal_int(total, 4, "4 total reactions")) return false;

  // Check unique keys
  auto keys = aggregator.get_unique_reaction_keys("$msg1:localhost");
  if (!assert_equal_int(static_cast<int64_t>(keys.size()), 2, "2 unique keys")) return false;

  // Check reactors
  auto reactors = aggregator.get_reactors("$msg1:localhost", "👍");
  if (!assert_equal_int(static_cast<int64_t>(reactors.size()), 2, "2 👍 reactors")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: message edits
// --------------------------------------------------------------------------
bool test_message_edits() {
  RelationStore store;
  ThreadRelationManager thread_mgr(store);
  EditConfig config;
  EventRelationEngine engine(store, thread_mgr, {}, {}, config);
  MessageEditManager edit_manager(store, engine, config);

  json original_content;
  original_content["body"] = "Hello world";
  original_content["msgtype"] = "m.text";

  json edit_content;
  edit_content["m.new_content"] = {
    {"body", "Hello edited world"},
    {"msgtype", "m.text"}
  };
  edit_content["body"] = " * Hello edited world";
  edit_content["m.relates_to"] = {
    {"rel_type", "m.replace"},
    {"event_id", "$original:localhost"}
  };

  // Process edit
  auto result = edit_manager.process_edit("$edit1:localhost",
      "$original:localhost", "@user:localhost", original_content,
      edit_content, 2000);

  if (!assert_true(result.success, "edit processed")) return false;
  if (!assert_equal(json_str(result.resolved_content, "body"),
                     "Hello edited world", "edited body")) return false;

  // Check edit count
  if (!assert_true(edit_manager.is_edited("$original:localhost"), "is edited")) return false;
  if (!assert_equal_int(edit_manager.count_edits("$original:localhost"), 1,
                         "1 edit")) return false;

  // Get edit summary
  auto summary = engine.get_edit_summary("$original:localhost");
  if (!assert_true(summary.is_edited, "edit summary edited")) return false;
  if (!assert_equal_int(summary.edit_count, 1, "edit summary count")) return false;

  // Edit history
  auto history = edit_manager.get_edit_history_json("$original:localhost");
  if (!assert_equal_int(static_cast<int64_t>(history.size()), 1,
                         "1 edit in history")) return false;

  // Get resolved content
  json resolved = edit_manager.get_resolved_content("$original:localhost",
      original_content);
  if (!assert_equal(json_str(resolved, "body"), "Hello edited world",
                     "resolved body")) return false;

  // Generate fallback text
  std::string fallback = edit_manager.generate_fallback_text(original_content,
      edit_content["m.new_content"]);
  if (!assert_true(!fallback.empty(), "fallback not empty")) return false;

  // Test invalid edit (no m.new_content)
  json bad_content;
  bad_content["body"] = "bad edit";
  bad_content["m.relates_to"] = {
    {"rel_type", "m.replace"},
    {"event_id", "$original:localhost"}
  };

  auto bad_result = edit_manager.process_edit("$bad_edit:localhost",
      "$original:localhost", "@user:localhost", original_content,
      bad_content, 3000);
  if (!assert_true(!bad_result.success, "bad edit rejected")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: read markers
// --------------------------------------------------------------------------
bool test_read_markers() {
  ReadMarkerConfig config;
  config.enable_per_thread_markers = true;
  ReadMarkerManager manager(config);

  std::string user_id = "@alice:localhost";
  std::string room_id = "!test:localhost";

  // Set fully read
  manager.set_fully_read(user_id, room_id, "$event100:localhost");
  std::string fr = manager.get_fully_read_event_id(user_id, room_id);
  if (!assert_equal(fr, "$event100:localhost", "fully read set")) return false;

  // Set read receipt
  manager.set_read_receipt(user_id, room_id, "$event150:localhost");
  auto rr = manager.get_read_receipt(user_id, room_id);
  if (!assert_true(rr.has_value(), "read receipt exists")) return false;
  if (!assert_equal(*rr, "$event150:localhost", "read receipt value")) return false;

  // Set thread read marker
  manager.set_thread_read_marker(user_id, room_id, "$thread1:localhost",
      "$threadEvent50:localhost");
  std::string tr = manager.get_thread_read_marker(user_id, room_id,
      "$thread1:localhost");
  if (!assert_equal(tr, "$threadEvent50:localhost", "thread read marker")) return false;

  // Get all thread markers
  auto all_thread = manager.get_all_thread_read_markers(user_id, room_id);
  if (!assert_equal_int(static_cast<int64_t>(all_thread.size()), 1,
                         "1 thread marker")) return false;

  // Get full read marker info
  auto marker = manager.get_read_marker(user_id, room_id);
  if (!assert_true(marker.has_value(), "marker info exists")) return false;
  if (!assert_equal(marker->fully_read_event_id, "$event100:localhost",
                     "marker fully read")) return false;

  // Test non-existent
  std::string nonexist = manager.get_fully_read_event_id("@nobody:localhost",
      room_id);
  if (!assert_equal(nonexist, "", "nonexistent user returns empty")) return false;

  // Clear room markers
  manager.clear_room_markers(user_id, room_id);
  marker = manager.get_read_marker(user_id, room_id);
  if (!assert_true(!marker.has_value(), "marker cleared")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: thread sync builder
// --------------------------------------------------------------------------
bool test_thread_sync_builder() {
  RelationStore store;
  ThreadConfig config;
  ThreadRelationManager thread_mgr(store, config);
  ThreadSyncBuilder sync_builder(thread_mgr, store, config);

  std::string room_id = "!test:localhost";
  std::string user_id = "@alice:localhost";

  // Setup thread
  thread_mgr.register_thread_root(room_id, "$root1:localhost");
  thread_mgr.add_thread_reply("$root1:localhost", "$reply1:localhost",
                               "@alice:localhost", 1000);
  thread_mgr.add_thread_reply("$root1:localhost", "$reply2:localhost",
                               "@bob:localhost", 2000);

  // Build room threads
  json threads = sync_builder.build_room_threads(room_id, user_id);
  if (!assert_true(threads.contains("$root1:localhost"), "thread in sync")) return false;
  auto& thread_data = threads["$root1:localhost"];
  if (!assert_true(thread_data.contains("summary"), "thread has summary")) return false;
  if (!assert_true(thread_data.contains("timeline"), "thread has timeline")) return false;

  // Build bundled relations
  json bundled = sync_builder.build_bundled_relations("$root1:localhost", user_id);
  if (!assert_true(bundled.contains("m.thread"), "bundled thread")) return false;

  // Filter by thread
  std::vector<std::string> events = {"$root1:localhost", "$reply1:localhost",
                                      "$reply2:localhost", "$other:localhost"};
  auto filtered = sync_builder.filter_by_thread(events, "$root1:localhost");
  if (!assert_equal_int(static_cast<int64_t>(filtered.size()), 3,
                         "3 filtered to thread")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: thread notifications
// --------------------------------------------------------------------------
bool test_thread_notifications() {
  RelationStore store;
  ThreadConfig config;
  config.enable_thread_notifications = true;
  ThreadRelationManager thread_mgr(store, config);
  ThreadNotificationManager notification_mgr(thread_mgr, config);

  std::string user_id = "@alice:localhost";
  std::string room_id = "!test:localhost";
  std::string thread_id = "$thread1:localhost";

  // Default setting
  auto setting = notification_mgr.get_thread_notification(user_id, thread_id);
  if (!assert_true(setting == ThreadNotificationManager::ThreadNotificationSetting::DEFAULT,
                   "default setting")) return false;

  // Set to ALL
  notification_mgr.set_thread_notification(user_id, thread_id,
      ThreadNotificationManager::ThreadNotificationSetting::ALL);
  setting = notification_mgr.get_thread_notification(user_id, thread_id);
  if (!assert_true(setting == ThreadNotificationManager::ThreadNotificationSetting::ALL,
                   "ALL setting")) return false;

  // Should notify for thread reply
  if (!assert_true(notification_mgr.should_notify_for_thread_reply(
          user_id, thread_id, false, false), "should notify ALL")) return false;

  // Set to MENTIONS
  notification_mgr.set_thread_notification(user_id, thread_id,
      ThreadNotificationManager::ThreadNotificationSetting::MENTIONS);

  if (!assert_true(notification_mgr.should_notify_for_thread_reply(
          user_id, thread_id, true, false), "should notify MENTIONS+mention")) return false;
  if (!assert_true(!notification_mgr.should_notify_for_thread_reply(
          user_id, thread_id, false, false), "should not notify MENTIONS alone")) return false;

  // Set to NONE
  notification_mgr.set_thread_notification(user_id, thread_id,
      ThreadNotificationManager::ThreadNotificationSetting::NONE);
  if (!assert_true(!notification_mgr.should_notify_for_thread_reply(
          user_id, thread_id, true, false), "should not notify NONE")) return false;

  // Setup thread with replies for unread counts
  thread_mgr.register_thread_root(room_id, thread_id);
  thread_mgr.add_thread_reply(thread_id, "$r1:localhost", "@bob:localhost", 1000);
  thread_mgr.add_thread_reply(thread_id, "$r2:localhost", "@bob:localhost", 2000);

  notification_mgr.set_thread_read_position(user_id, thread_id, "$r1:localhost", 1);

  int64_t unread = notification_mgr.calculate_thread_unread_count(user_id, thread_id);
  if (!assert_equal_int(unread, 1, "1 unread thread reply")) return false;

  // Get all unread counts
  auto counts = notification_mgr.get_all_thread_unread_counts(user_id, room_id);
  if (!assert_true(counts.find(thread_id) != counts.end(), "thread has unreads")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: aggregation group manager
// --------------------------------------------------------------------------
bool test_aggregation_groups() {
  RelationStore store;
  ThreadRelationManager thread_mgr(store);
  EventRelationEngine engine(store, thread_mgr);
  ReadMarkerConfig rm_config;
  ReadMarkerManager read_mgr(rm_config);
  AggregationConfig config;
  AggregationGroupManager agg_mgr(store, thread_mgr, engine, read_mgr, config);

  std::string room_id = "!test:localhost";
  std::string user_id = "@alice:localhost";

  // Setup thread
  thread_mgr.register_thread_root(room_id, "$event1:localhost");
  thread_mgr.add_thread_reply("$event1:localhost", "$reply1:localhost",
                               "@alice:localhost", 1000);

  // Add reactions
  engine.add_reaction("$react1:localhost", "$event1:localhost",
      "@alice:localhost", "👍", 2000);

  // Add edit
  json orig;
  orig["body"] = "original";
  orig["msgtype"] = "m.text";

  json edit_content;
  edit_content["m.new_content"] = {{"body", "edited"}, {"msgtype", "m.text"}};
  edit_content["body"] = " * edited";
  edit_content["m.relates_to"] = {
    {"rel_type", "m.replace"},
    {"event_id", "$event1:localhost"}
  };

  EditConfig ec;
  MessageEditManager edit_mgr(store, engine, ec);
  edit_mgr.process_edit("$e1:localhost", "$event1:localhost",
      "@alice:localhost", orig, edit_content, 3000);

  // Build aggregation bundle
  auto bundle = agg_mgr.build_aggregation_bundle("$event1:localhost", user_id);
  if (!assert_true(bundle.has_aggregations, "has aggregations")) return false;

  // Thread summary in bundle
  if (!assert_true(!bundle.thread_summary.root_event_id.empty(),
                   "thread in bundle")) return false;

  // Reactions in bundle
  if (!assert_equal_int(static_cast<int64_t>(bundle.reactions.size()), 1,
                         "1 reaction in bundle")) return false;

  // Edit info in bundle
  if (!assert_true(bundle.edit_info.is_edited, "edited in bundle")) return false;

  // Batch build
  std::vector<std::string> event_ids = {"$event1:localhost"};
  auto bundles = agg_mgr.batch_build_aggregations(event_ids, user_id);
  if (!assert_true(bundles.find("$event1:localhost") != bundles.end(),
                   "bundle in batch")) return false;

  // Build sync aggregations
  json sync_aggs = agg_mgr.build_sync_aggregations(room_id, user_id, event_ids);
  if (!assert_true(!sync_aggs.empty(), "sync aggregations not empty")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: ThreadCoordinator integration
// --------------------------------------------------------------------------
bool test_thread_coordinator() {
  ThreadCoordinator coordinator;

  std::string room_id = "!test:localhost";
  std::string sender = "@alice:localhost";

  // Process a thread reply event
  json thread_content;
  thread_content["m.relates_to"] = {
    {"rel_type", "m.thread"},
    {"event_id", "$root:localhost"}
  };
  thread_content["body"] = "Thread reply";

  bool processed = coordinator.process_event("$reply:localhost", room_id,
      sender, thread_content, 1000);
  if (!assert_true(processed, "processed thread event")) return false;

  // Check thread was created
  if (!assert_true(coordinator.threads().is_thread_root("$root:localhost"),
                   "became thread root")) return false;

  // Process a reaction
  json reaction_content;
  reaction_content["m.relates_to"] = {
    {"rel_type", "m.annotation"},
    {"event_id", "$root:localhost"},
    {"key", "👍"}
  };
  reaction_content["body"] = "👍";

  processed = coordinator.process_event("$reaction:localhost", room_id,
      "@bob:localhost", reaction_content, 2000);
  if (!assert_true(processed, "processed reaction")) return false;

  // Mark thread as read
  coordinator.mark_thread_read("@alice:localhost", room_id,
      "$root:localhost", "$reply:localhost");

  // Get thread unread counts
  auto unread = coordinator.get_thread_unread_counts("@alice:localhost", room_id);

  // Get sync response
  json sync = coordinator.build_sync_response(room_id, "@alice:localhost",
      json::array({}));

  // Get room stats
  json stats = coordinator.get_room_threading_stats(room_id);
  if (!assert_true(stats.contains("total_threads"), "stats has total_threads")) return false;
  if (!assert_true(stats.contains("total_replies"), "stats has total_replies")) return false;
  if (!assert_true(stats.contains("total_reactions"), "stats has total_reactions")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: relation utilities
// --------------------------------------------------------------------------
bool test_relation_utils() {
  using namespace relation_utils;

  // Build relation
  auto rel = build_relation("m.annotation", "$target:localhost", "👍");
  if (!assert_true(rel.contains("m.relates_to"), "built relation")) return false;

  // Build thread relation
  auto thread_rel = build_thread_relation("$thread:localhost", false);
  if (!assert_true(thread_rel.contains("m.relates_to"), "built thread rel")) return false;

  // Build annotation
  auto ann_rel = build_annotation_relation("$target:localhost", "❤️");
  if (!assert_true(ann_rel.contains("m.relates_to"), "built annotation")) return false;

  // Build replace
  auto rep_rel = build_replace_relation("$target:localhost");
  if (!assert_true(rep_rel.contains("m.relates_to"), "built replace")) return false;

  // Build reference
  auto ref_rel = build_reference_relation("$target:localhost");
  if (!assert_true(ref_rel.contains("m.relates_to"), "built reference")) return false;

  // Check content type detection
  json reaction;
  reaction["m.relates_to"] = {{"rel_type", "m.annotation"}, {"event_id", "$x:localhost"}};
  if (!assert_true(is_reaction_content(reaction), "detect reaction")) return false;
  if (!assert_true(!is_edit_content(reaction), "not edit")) return false;
  if (!assert_true(!is_thread_content(reaction), "not thread")) return false;

  json edit;
  edit["m.relates_to"] = {{"rel_type", "m.replace"}, {"event_id", "$x:localhost"}};
  if (!assert_true(is_edit_content(edit), "detect edit")) return false;

  json thread;
  thread["m.relates_to"] = {{"rel_type", "m.thread"}, {"event_id", "$x:localhost"}};
  if (!assert_true(is_thread_content(thread), "detect thread")) return false;

  json reply;
  reply["m.relates_to"] = {{"rel_type", "m.reference"}, {"event_id", "$x:localhost"}};
  if (!assert_true(is_reply_content(reply), "detect reply")) return false;

  // Get relation type
  if (!assert_equal(get_relation_type(reaction), "m.annotation", "get type")) return false;

  // Get parent ID
  if (!assert_equal(get_relation_parent_id(reaction), "$x:localhost", "get parent")) return false;

  // Get annotation key
  reaction["m.relates_to"]["key"] = "🎉";
  if (!assert_equal(get_annotation_key(reaction), "🎉", "get key")) return false;

  // Has relation
  if (!assert_true(has_relation(reaction), "has relation")) return false;
  json no_rel;
  no_rel["body"] = "hello";
  if (!assert_true(!has_relation(no_rel), "no relation")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Test: ThreadAPIHandler
// --------------------------------------------------------------------------
bool test_thread_api_handler() {
  ThreadCoordinator coordinator;
  ThreadAPIHandler handler(coordinator);

  std::string room_id = "!test:localhost";
  std::string user_id = "@alice:localhost";

  // Setup some data
  coordinator.process_event("$reply:localhost", room_id, "@bob:localhost",
      {{"m.relates_to", {{"rel_type", "m.thread"}, {"event_id", "$root:localhost"}}},
       {"body", "reply"}},
      1000);

  // Test get threads
  json query;
  auto threads_resp = handler.handle_get_threads(room_id, user_id, query);
  if (!assert_true(threads_resp.contains("threads"), "has threads")) return false;

  // Test get thread detail
  query.clear();
  auto detail = handler.handle_get_thread_detail(room_id, "$root:localhost",
      user_id, query);
  if (!assert_true(detail.contains("root_event_id"), "has root_event_id")) return false;

  // Test get relations
  query["rel_type"] = "m.thread";
  query["limit"] = 10;
  auto relations = handler.handle_get_relations(room_id, "$root:localhost",
      user_id, query);
  if (!assert_true(relations.contains("chunk"), "has chunk")) return false;

  // Test set read markers
  json body;
  body["m.fully_read"] = "$root:localhost";
  body["m.read"] = "$reply:localhost";
  auto marker_resp = handler.handle_set_read_markers(room_id, user_id, body);
  // Should succeed (return empty object)

  return true;
}

// --------------------------------------------------------------------------
// Test: edge cases
// --------------------------------------------------------------------------
bool test_edge_cases() {
  RelationStore store;
  ThreadRelationManager thread_mgr(store);

  // Empty thread root
  auto summary = thread_mgr.get_thread_summary("$nonexistent:localhost");
  if (!assert_true(!summary.has_value(), "nonexistent summary")) return false;

  // Double register
  thread_mgr.register_thread_root("!room:localhost", "$root:localhost");
  thread_mgr.register_thread_root("!room:localhost", "$root:localhost");
  int64_t count = thread_mgr.get_thread_count("!room:localhost");
  if (!assert_equal_int(count, 1, "no duplicate thread root")) return false;

  // Remove non-existent reply
  thread_mgr.remove_thread_reply("$root:localhost", "$nonexistent:localhost");
  summary = thread_mgr.get_thread_summary("$root:localhost");
  if (!assert_equal_int(summary->reply_count, 0, "reply count unchanged")) return false;

  // Empty room threads
  auto roots = thread_mgr.get_thread_roots("!empty:localhost");
  if (!assert_equal_int(static_cast<int64_t>(roots.size()), 0,
                         "empty room")) return false;

  // Relation store: get non-existent
  auto rel = store.get_relation_for_event("$noexist:localhost");
  if (!assert_true(!rel.has_value(), "no relation found")) return false;

  // Zero relation count
  int64_t zero = store.get_relation_count("$noexist:localhost", "m.annotation");
  if (!assert_equal_int(zero, 0, "zero count")) return false;

  // Clear store
  store.add_relation("$x:localhost",
      RelationInfo{"$y:localhost", "m.annotation", "k", 0, "@u", {}});
  if (!assert_true(store.has_relation("$x:localhost"), "has relation before clear")) return false;
  store.clear();
  if (!assert_true(!store.has_relation("$x:localhost"), "cleared")) return false;

  return true;
}

// --------------------------------------------------------------------------
// Run all tests
// --------------------------------------------------------------------------
bool run_all_tests() {
  std::vector<std::pair<std::string, std::function<bool()>>> tests = {
    {"relation_type_constants", test_relation_type_constants},
    {"parse_relation",           test_parse_relation},
    {"relation_store",           test_relation_store},
    {"thread_management",        test_thread_management},
    {"reaction_aggregation",     test_reaction_aggregation},
    {"message_edits",            test_message_edits},
    {"read_markers",             test_read_markers},
    {"thread_sync_builder",      test_thread_sync_builder},
    {"thread_notifications",     test_thread_notifications},
    {"aggregation_groups",       test_aggregation_groups},
    {"thread_coordinator",       test_thread_coordinator},
    {"relation_utils",           test_relation_utils},
    {"thread_api_handler",       test_thread_api_handler},
    {"edge_cases",               test_edge_cases},
  };

  int passed = 0;
  int failed = 0;

  std::cout << "=== Threading Tests ===" << std::endl;
  for (auto& [name, test_fn] : tests) {
    std::cout << "  " << name << "... ";
    std::cout.flush();
    if (test_fn()) {
      std::cout << "PASSED" << std::endl;
      passed++;
    } else {
      std::cout << "FAILED" << std::endl;
      failed++;
    }
  }

  std::cout << "---" << std::endl;
  std::cout << "Passed: " << passed << ", Failed: " << failed
            << ", Total: " << (passed + failed) << std::endl;

  return failed == 0;
}

} // namespace test
#endif // THREADING_TESTING

} // namespace progressive
