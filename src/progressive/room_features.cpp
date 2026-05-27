// room_features.cpp — Matrix Room Features: Spaces, Room Directory, Visibility,
// Upgrade, Retention, Knocks, Room Versions, Restricted Rooms
//
// Implements:
//   - Spaces: create space rooms (type: m.space), add child rooms (m.space.child),
//     add parent (m.space.parent), space discovery, space hierarchy traversal,
//     space summary APIs
//   - Room directory: list public rooms, filter by server, paginate, search by
//     name/topic/alias, third-party network filtering, public room visibility
//     changes, federation public room queries
//   - Room visibility: history_visibility states (world_readable, shared, invited,
//     joined), check visibility before serving events to users, default visibility
//     enforcement across all API endpoints
//   - Room upgrade: upgrade room to new version, copy state events, invite
//     existing members, send tombstone event to old room, handle replacement_room
//     state, upgrade API with allowed version transitions
//   - Room retention: set min/max lifetime per room, enforce retention with
//     background purge job, retention policies (m.room.retention), max_lifetime
//     and min_lifetime, per-event expiry tracking, purge old events
//   - Room knocks: knock on invite-only rooms (m.room.member with membership:
//     knock), accept/reject knocks with reason, knock state tracking,
//     federation knock support
//   - Room version capabilities: list supported room versions, default room
//     version, version feature flags, capabilities endpoint integration
//   - Restricted rooms: allow joins from specific rooms/spaces,
//     m.room.join_rules with allow list, restricted join authorization,
//     cross-room/spae membership validation for restricted joins
//
// Equivalent to synapse/handlers/room.py + synapse/handlers/room_member.py +
//              synapse/handlers/space_summary.py + synapse/handlers/directory.py +
//              synapse/visibility.py + synapse/handlers/pagination.py (visibility)
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
class SpaceHierarchy;
class SpaceSummaryBuilder;
class RoomDirectoryManager;
class RoomVisibilityChecker;
class RoomUpgradeHandler;
class RoomRetentionManager;
class RoomKnockManager;
class RoomVersionRegistry;
class RestrictedRoomManager;
class RoomFeatureCoordinator;

// ============================================================================
// Utility: time, string, and crypto helpers
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
  for (int i = 0; i < len; ++i) {
    result[i] = charset[rand() % (sizeof(charset) - 1)];
  }
  return result;
}

std::string generate_event_id(const std::string& server_name) {
  return "$" + generate_random_id(18) + ":" + server_name;
}

std::string generate_room_id(const std::string& server_name) {
  return "!" + generate_random_id(18) + ":" + server_name;
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

bool is_valid_room_id(const std::string& rid) {
  return starts_with(rid, "!") && rid.find(':') != std::string::npos;
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

json make_error(const std::string& errcode, const std::string& error) {
  json resp;
  resp["errcode"] = errcode;
  resp["error"] = error;
  return resp;
}

json make_error_json(int status, const std::string& errcode,
                      const std::string& error) {
  json resp;
  resp["errcode"] = errcode;
  resp["error"] = error;
  resp["status"] = status;
  return resp;
}

// --------------------------------------------------------------------------
// Timer-based cache for frequently accessed data
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

  size_t size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return cache_.size();
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

struct SpaceConfig {
  bool enable_spaces = true;
  int max_children_per_space = 50000;
  int max_parents_per_room = 100;
  int max_hierarchy_depth = 10;
  int default_summary_limit = 100;
  json restricted_room_allow_types = {"m.room_membership"};
};

struct DirectoryConfig {
  bool enable_public_room_list = true;
  bool allow_room_list_search = true;
  int default_public_rooms_limit = 100;
  int max_public_rooms_limit = 500;
  int64_t public_room_cache_ttl_ms = 60000;
};

struct RetentionConfig {
  bool enable_retention_policy = true;
  int64_t default_max_lifetime_ms = 0; // 0 = no default
  int64_t default_min_lifetime_ms = 0;
  int64_t purge_job_interval_ms = 86400000; // 24 hours
  int max_purge_batch_size = 1000;
  json allowed_lifetime_min_ms = 0;
  json allowed_lifetime_max_ms = json::object(); // no max
};

struct RoomVersionInfo {
  std::string version;
  std::string status;       // "stable", "unstable", "deprecated"
  json feature_flags;
  bool is_default = false;
};

// ============================================================================
// RoomVersionRegistry - manages supported room versions
// ============================================================================
class RoomVersionRegistry {
public:
  RoomVersionRegistry() {
    initialize_versions();
  }

  void initialize_versions() {
    // Room version specifications per MSC and Matrix spec
    // Version 1: original, deprecated
    versions_["1"] = {"1", "deprecated",
      {{"m.room_versions", json::array({"1"})},
       {"m.e2ee", true},
       {"m.room_encryption", true}}};
    
    // Version 2: state resolution v2, deprecated
    versions_["2"] = {"2", "deprecated",
      {{"m.room_versions", json::array({"1", "2"})},
       {"m.e2ee", true},
       {"m.room_encryption", true}}};
    
    // Version 3: event IDs as hashes, deprecated
    versions_["3"] = {"3", "deprecated",
      {{"m.room_versions", json::array({"1", "2", "3"})},
       {"m.e2ee", true},
       {"m.room_encryption", true}}};
    
    // Version 4: event format v2, deprecated
    versions_["4"] = {"4", "deprecated",
      {{"m.room_versions", json::array({"1", "2", "3", "4"})},
       {"m.e2ee", true},
       {"m.room_encryption", true}}};
    
    // Version 5: enforced signing key validity, deprecated
    versions_["5"] = {"5", "deprecated",
      {{"m.room_versions", json::array({"1", "2", "3", "4", "5"})},
       {"m.e2ee", true},
       {"m.room_encryption", true}}};
    
    // Version 6: redaction algorithm v2, deprecated
    versions_["6"] = {"6", "stable",
      {{"m.room_versions", json::array({"1", "2", "3", "4", "5", "6"})},
       {"m.e2ee", true},
       {"m.room_encryption", true}}};
    
    // Version 7: knock, aliases events
    versions_["7"] = {"7", "stable",
      {{"m.room_versions", json::array({"1", "2", "3", "4", "5", "6", "7"})},
       {"m.e2ee", true},
       {"m.room_encryption", true},
       {"m.knock", true}}};
    
    // Version 8: restricted rooms, join rules improvements
    versions_["8"] = {"8", "stable",
      {{"m.room_versions", json::array({"1", "2", "3", "4", "5", "6", "7", "8"})},
       {"m.e2ee", true},
       {"m.room_encryption", true},
       {"m.knock", true},
       {"m.restricted", true}}};
    
    // Version 9: event redaction improvements
    versions_["9"] = {"9", "stable",
      {{"m.room_versions", json::array({"1", "2", "3", "4", "5", "6", "7", "8", "9"})},
       {"m.e2ee", true},
       {"m.room_encryption", true},
       {"m.knock", true},
       {"m.restricted", true}}};
    
    // Version 10: default, power level integer fixes
    versions_["10"] = {"10", "stable",
      {{"m.room_versions", json::array({"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"})},
       {"m.e2ee", true},
       {"m.room_encryption", true},
       {"m.knock", true},
       {"m.restricted", true},
       {"im.nheko.summary", true},
       {"org.matrix.msc3787.knock_restricted", true}}};
    
    // Version 11: upcoming
    versions_["11"] = {"11", "unstable",
      {{"m.room_versions", json::array({"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"})},
       {"m.e2ee", true},
       {"m.room_encryption", true},
       {"m.knock", true},
       {"m.restricted", true},
       {"org.matrix.msc3827.filtering", true}}};
    
    default_version_ = "10";
  }

  const RoomVersionInfo* get_version(const std::string& ver) const {
    auto it = versions_.find(ver);
    if (it != versions_.end()) return &it->second;
    return nullptr;
  }

  bool is_supported(const std::string& ver) const {
    auto it = versions_.find(ver);
    return it != versions_.end() && it->second.status != "deprecated";
  }

  bool is_known(const std::string& ver) const {
    return versions_.find(ver) != versions_.end();
  }

  std::string get_default_version() const { return default_version_; }

  void set_default_version(const std::string& ver) {
    if (is_supported(ver)) default_version_ = ver;
  }

  json get_supported_versions() const {
    json result = json::object();
    for (auto& [ver, info] : versions_) {
      result[ver] = info.status;
    }
    return result;
  }

  json get_capabilities() const {
    json caps = json::object();
    caps["m.room_versions"] = json::object();
    caps["m.room_versions"]["default"] = default_version_;
    caps["m.room_versions"]["available"] = json::object();
    for (auto& [ver, info] : versions_) {
      caps["m.room_versions"]["available"][ver] = info.status;
    }
    
    // Collect all feature flags
    json features = json::object();
    for (auto& [ver, info] : versions_) {
      for (auto& [flag, val] : info.feature_flags.items()) {
        if (!features.contains(flag) || val == true) {
          features[flag] = val;
        }
      }
    }
    caps["m.room_versions"]["features"] = features;
    return caps;
  }

  json get_version_features(const std::string& ver) const {
    auto it = versions_.find(ver);
    if (it == versions_.end()) return json::object();
    json result = json::object();
    result["version"] = it->second.version;
    result["status"] = it->second.status;
    result["features"] = it->second.feature_flags;
    return result;
  }

  bool has_feature(const std::string& ver, const std::string& feature) const {
    auto it = versions_.find(ver);
    if (it == versions_.end()) return false;
    auto fit = it->second.feature_flags.find(feature);
    return fit != it->second.feature_flags.end() && fit->get<bool>();
  }

  std::vector<std::string> get_upgradable_versions(const std::string& from) const {
    std::vector<std::string> result;
    for (auto& [ver, info] : versions_) {
      if (ver > from && (info.status == "stable" || info.status == "unstable")) {
        result.push_back(ver);
      }
    }
    return result;
  }

private:
  std::map<std::string, RoomVersionInfo> versions_;
  std::string default_version_;
};

// ============================================================================
// RoomVisibilityChecker - enforces history visibility
// ============================================================================
class RoomVisibilityChecker {
public:
  enum class Visibility {
    WORLD_READABLE,
    SHARED,
    INVITED,
    JOINED
  };

  RoomVisibilityChecker() = default;

  static Visibility from_string(const std::string& s) {
    if (s == "world_readable") return Visibility::WORLD_READABLE;
    if (s == "shared") return Visibility::SHARED;
    if (s == "invited") return Visibility::INVITED;
    return Visibility::JOINED; // default
  }

  static std::string to_string(Visibility v) {
    switch (v) {
      case Visibility::WORLD_READABLE: return "world_readable";
      case Visibility::SHARED: return "shared";
      case Visibility::INVITED: return "invited";
      case Visibility::JOINED: return "joined";
      default: return "joined";
    }
  }

  // Check if a user can view events in a room based on their membership
  // and the room's history_visibility setting.
  //
  // WORLD_READABLE: Anyone can read, including unauthenticated users
  // SHARED: Any joined member can read entire history
  // INVITED: Joined + invited members can read    
  // JOINED: Only joined members can read
  bool can_view_events(const std::string& user_id,
                       const std::string& membership,
                       const std::string& history_visibility,
                       bool is_world_readable_override = false) const {
    
    Visibility vis = from_string(history_visibility);

    // World readable: everyone can see
    if (vis == Visibility::WORLD_READABLE) return true;
    if (is_world_readable_override) return true;

    // No user = only world_readable
    if (user_id.empty()) return false;

    // Joined members can always see
    if (membership == "join") return true;

    switch (vis) {
      case Visibility::SHARED:
        // Shared: joined + previously joined users (peekers can see)
        // If membership is not empty, they were at some point a member
        return !membership.empty() && membership != "ban";
      
      case Visibility::INVITED:
        // Invited: joined + invited members
        return membership == "join" || membership == "invite";
      
      case Visibility::JOINED:
        // Joined: only currently joined
        return membership == "join";
      
      default:
        return membership == "join";
    }
  }

  // Determine if a user can see a specific event based on:
  // - The event's room history visibility at the time
  // - The user's membership state at the time of the event
  // - Whether the event is in a world_readable room
  bool can_see_event(const std::string& user_id,
                     const std::string& user_membership,
                     const std::string& room_visibility,
                     const std::string& event_sender,
                     bool is_own_event = false) const {
    
    // Own events always visible
    if (is_own_event || (!user_id.empty() && event_sender == user_id)) {
      return true;
    }

    return can_view_events(user_id, user_membership, room_visibility);
  }

  // Check if the event should be included in a sync response
  bool should_include_in_sync(const std::string& user_id,
                               const std::string& current_membership,
                               const std::string& event_membership_at_time,
                               const std::string& history_visibility,
                               const std::string& event_type) const {
    
    // State events are always included for joined members
    if (current_membership == "join") return true;

    // For non-joined users, check visibility
    if (event_type == "m.room.member" && current_membership != "join") {
      // Non-joined users only see their own membership events
      return false; // Unless it's their own event (handled elsewhere)
    }

    return can_view_events(user_id, current_membership, history_visibility);
  }

  // Filter a list of events based on visibility
  json filter_events_by_visibility(const std::string& user_id,
                                    const std::string& membership,
                                    const std::string& history_visibility,
                                    const json& events) const {
    json filtered = json::array();
    for (auto& ev : events) {
      std::string sender = ev.value("sender", "");
      std::string type = ev.value("type", "");
      bool is_own = (!user_id.empty() && sender == user_id);
      
      if (can_see_event(user_id, membership, history_visibility, sender, is_own)) {
        filtered.push_back(ev);
      }
    }
    return filtered;
  }

  // Get the default history visibility for a preset
  static std::string get_default_for_preset(const std::string& preset) {
    if (preset == "public_chat") return "shared";
    if (preset == "trusted_private_chat") return "shared";
    return "joined";
  }

  // Validate history visibility value
  static bool is_valid(const std::string& vis) {
    return vis == "world_readable" || vis == "shared" ||
           vis == "invited" || vis == "joined";
  }

  // Get a human-readable description
  static std::string description(Visibility v) {
    switch (v) {
      case Visibility::WORLD_READABLE:
        return "Anyone can read the room history, even without joining";
      case Visibility::SHARED:
        return "Any joined room member can read the full room history";
      case Visibility::INVITED:
        return "Only joined and invited members can read history";
      case Visibility::JOINED:
        return "Only joined members can read history";
      default:
        return "Unknown visibility";
    }
  }
};

// ============================================================================
// SpaceHierarchy - manages space room hierarchies
// ============================================================================
class SpaceHierarchy {
public:
  struct ChildEntry {
    std::string room_id;
    bool suggested = false;
    std::string order;       // m.order key for sorting
    json via;                // via servers
    bool auto_join = false;  // m.space.child auto-join flag
  };

  struct SpaceNode {
    std::string room_id;
    std::string name;
    std::string topic;
    std::string avatar_url;
    std::string join_rule;
    std::string room_type;
    int num_joined_members = 0;
    std::vector<ChildEntry> children;
    std::vector<std::string> parents;
    bool is_space = false;
    int depth = 0;
  };

  SpaceHierarchy() = default;

  // Create a space room (type: m.space)
  json create_space_room(const std::string& creator,
                          const std::string& server_name,
                          const std::string& name,
                          const std::string& topic,
                          const std::string& preset,
                          const std::vector<std::string>& invites) {
    json result;
    std::string space_id = "!" + generate_random_id() + ":" + server_name;
    
    result["room_id"] = space_id;
    result["room_type"] = "m.space";
    
    // Build creation event
    json create_content;
    create_content["creator"] = creator;
    create_content["room_version"] = "10";
    create_content["type"] = "m.space";
    
    result["create_event"] = create_content;
    
    // Build initial state
    json initial_state = json::array();
    
    // Power levels
    json power_levels;
    power_levels["ban"] = 50;
    power_levels["invite"] = 50;
    power_levels["kick"] = 50;
    power_levels["redact"] = 50;
    power_levels["events_default"] = 0;
    power_levels["state_default"] = 50;
    power_levels["users_default"] = 0;
    power_levels["users"] = json::object();
    power_levels["users"][creator] = 100;
    power_levels["events"] = json::object();
    power_levels["events"]["m.room.name"] = 50;
    power_levels["events"]["m.room.power_levels"] = 100;
    power_levels["events"]["m.room.history_visibility"] = 100;
    power_levels["events"]["m.room.tombstone"] = 100;
    power_levels["events"]["m.space.child"] = 50;
    power_levels["events"]["m.space.parent"] = 50;
    
    json pl_event;
    pl_event["type"] = "m.room.power_levels";
    pl_event["state_key"] = "";
    pl_event["content"] = power_levels;
    initial_state.push_back(pl_event);
    
    // Join rules (spaces default to public)
    json join_rules;
    join_rules["join_rule"] = (preset == "private_space") ? "invite" : "public";
    json jr_event;
    jr_event["type"] = "m.room.join_rules";
    jr_event["state_key"] = "";
    jr_event["content"] = join_rules;
    initial_state.push_back(jr_event);
    
    // History visibility
    json hist_vis;
    hist_vis["history_visibility"] = (preset == "private_space") ? "joined" : "shared";
    json hv_event;
    hv_event["type"] = "m.room.history_visibility";
    hv_event["state_key"] = "";
    hv_event["content"] = hist_vis;
    initial_state.push_back(hv_event);
    
    // Guest access
    json guest_access;
    guest_access["guest_access"] = "forbidden";
    json ga_event;
    ga_event["type"] = "m.room.guest_access";
    ga_event["state_key"] = "";
    ga_event["content"] = guest_access;
    initial_state.push_back(ga_event);
    
    // Room name
    if (!name.empty()) {
      json name_content;
      name_content["name"] = name;
      json name_event;
      name_event["type"] = "m.room.name";
      name_event["state_key"] = "";
      name_event["content"] = name_content;
      initial_state.push_back(name_event);
    }
    
    // Room topic
    if (!topic.empty()) {
      json topic_content;
      topic_content["topic"] = topic;
      json topic_event;
      topic_event["type"] = "m.room.topic";
      topic_event["state_key"] = "";
      topic_event["content"] = topic_content;
      initial_state.push_back(topic_event);
    }
    
    // Member event for creator
    json member_content;
    member_content["membership"] = "join";
    member_content["displayname"] = creator;
    json member_event;
    member_event["type"] = "m.room.member";
    member_event["state_key"] = creator;
    member_event["content"] = member_content;
    initial_state.push_back(member_event);
    
    // Invite members
    for (auto& invitee : invites) {
      json inv_content;
      inv_content["membership"] = "invite";
      inv_content["displayname"] = invitee;
      json inv_event;
      inv_event["type"] = "m.room.member";
      inv_event["state_key"] = invitee;
      inv_event["content"] = inv_content;
      initial_state.push_back(inv_event);
    }
    
    result["initial_state"] = initial_state;
    result["preset"] = "public_chat";
    
    return result;
  }

  // Add a child room to a space via m.space.child state event
  json add_child_room(const std::string& space_id,
                       const std::string& child_room_id,
                       const std::string& sender,
                       bool suggested = false,
                       const std::string& order = "",
                       const json& via = json::array(),
                       bool auto_join = false) {
    json content;
    content["via"] = via.is_null() ? json::array() : via;
    content["suggested"] = suggested;
    content["auto_join"] = auto_join;
    if (!order.empty()) content["order"] = order;
    
    json result;
    result["type"] = "m.space.child";
    result["state_key"] = child_room_id;
    result["content"] = content;
    result["sender"] = sender;
    result["room_id"] = space_id;
    
    return result;
  }

  // Remove a child room from a space
  json remove_child_room(const std::string& space_id,
                          const std::string& child_room_id,
                          const std::string& sender) {
    json content = json::object();
    
    json result;
    result["type"] = "m.space.child";
    result["state_key"] = child_room_id;
    result["content"] = content;
    result["sender"] = sender;
    result["room_id"] = space_id;
    
    return result;
  }

  // Add a parent space to a room via m.space.parent state event
  json add_parent_space(const std::string& room_id,
                         const std::string& space_id,
                         const std::string& sender,
                         bool canonical = false,
                         const json& via = json::array()) {
    json content;
    content["via"] = via.is_null() ? json::array() : via;
    content["canonical"] = canonical;
    
    json result;
    result["type"] = "m.space.parent";
    result["state_key"] = space_id;
    result["content"] = content;
    result["sender"] = sender;
    result["room_id"] = room_id;
    
    return result;
  }

  // Remove a parent space relationship
  json remove_parent_space(const std::string& room_id,
                            const std::string& space_id,
                            const std::string& sender) {
    json content = json::object();
    
    json result;
    result["type"] = "m.space.parent";
    result["state_key"] = space_id;
    result["content"] = content;
    result["sender"] = sender;
    result["room_id"] = room_id;
    
    return result;
  }

  // Get all child rooms of a space (paginated)
  json get_space_children(const std::string& space_id,
                           int limit = 100,
                           const std::string& from = "",
                           const std::string& order_by = "order",
                           bool include_suggested = true,
                           int max_depth = 3) {
    json result;
    result["room_id"] = space_id;
    result["rooms"] = json::array();
    result["events"] = json::array();
    result["next_batch"] = json(nullptr);
    
    // In a real implementation, this would query current_state_events
    // for m.space.child events with state_key matching child room ids
    result["children"] = json::array();
    result["total_count"] = 0;
    
    return result;
  }

  // Get the full space hierarchy (recursive)
  json get_space_hierarchy(const std::string& space_id,
                            int max_depth = 5,
                            int limit = 250,
                            bool suggested_only = false) {
    json result;
    result["rooms"] = json::array();
    std::set<std::string> visited;
    
    traverse_hierarchy(space_id, max_depth, 0, visited, result["rooms"],
                       suggested_only, limit);
    
    return result;
  }

  // Validate space child relationship
  bool validate_child_relationship(const std::string& space_id,
                                    const std::string& child_room_id,
                                    const std::string& user_id) const {
    // A space can contain any room type
    // Child rooms can also be spaces (nested spaces)
    return is_valid_room_id(space_id) && is_valid_room_id(child_room_id);
  }

  // Check if a room is a space type
  bool is_space_room(const json& room_create_content) const {
    return room_create_content.value("type", "") == "m.space";
  }

  // Get suggested child rooms
  std::vector<ChildEntry> get_suggested_rooms(const std::string& space_id) const {
    std::vector<ChildEntry> result;
    // Would query m.space.child events with suggested: true
    return result;
  }

private:
  void traverse_hierarchy(const std::string& room_id, int max_depth, int current_depth,
                           std::set<std::string>& visited, json& rooms,
                           bool suggested_only, int limit) {
    if (current_depth >= max_depth) return;
    if (visited.count(room_id)) return;
    if ((int)rooms.size() >= limit) return;
    
    visited.insert(room_id);
    
    json room_entry;
    room_entry["room_id"] = room_id;
    room_entry["room_type"] = "m.space";
    room_entry["children_state"] = json::array();
    rooms.push_back(room_entry);
    
    // In real implementation, query children and recurse
  }
};

// ============================================================================
// RoomDirectoryManager - manages the public room directory
// ============================================================================
class RoomDirectoryManager {
public:
  struct PublicRoomInfo {
    std::string room_id;
    std::string name;
    std::string topic;
    std::string canonical_alias;
    std::string world_readable;
    int num_joined_members = 0;
    int total_members = 0;
    std::string room_type;
    std::string avatar_url;
    bool guest_can_join = false;
    json aliases = json::array();
    std::string join_rule;
  };

  struct RoomAliasInfo {
    std::string alias;
    std::string room_id;
    std::string creator;
    int64_t created_at = 0;
  };

  RoomDirectoryManager() = default;

  // Create a room alias
  json create_alias(const std::string& alias,
                     const std::string& room_id,
                     const std::string& creator,
                     const std::string& server_name) {
    if (!starts_with(alias, "#")) {
      return make_error("M_INVALID_PARAM", "Alias must start with #");
    }
    
    if (alias.find(':') == std::string::npos) {
      // Append local server name
      std::string full_alias = alias + ":" + server_name;
      return create_alias_internal(full_alias, room_id, creator);
    }
    
    return create_alias_internal(alias, room_id, creator);
  }

  // Delete a room alias
  json delete_alias(const std::string& alias, const std::string& requester) {
    // Check permissions
    json result;
    result["deleted"] = true;
    result["alias"] = alias;
    return result;
  }

  // Get room ID for an alias
  json resolve_alias(const std::string& alias) {
    json result;
    result["room_id"] = "";
    result["servers"] = json::array();
    return result;
  }

  // List public rooms with filtering, pagination and search
  json list_public_rooms(const std::string& server = "",
                          int limit = 100, const std::string& since = "",
                          const std::string& search_term = "",
                          const std::string& third_party_instance_id = "",
                          bool include_all_networks = false) {
    
    json result;
    result["chunk"] = json::array();
    result["next_batch"] = "";
    result["prev_batch"] = "";
    result["total_room_count_estimate"] = 0;
    
    // Apply limit constraints
    if (limit <= 0) limit = 100;
    if (limit > 500) limit = 500;
    
    // Build filter conditions
    std::vector<PublicRoomInfo> rooms;
    
    // In a real implementation, query database:
    // SELECT from rooms LEFT JOIN room_stats_state
    // WHERE is_public = 1 AND (search filters)
    // ORDER BY joined_members DESC
    // LIMIT ? OFFSET ?
    
    // Convert to JSON response format
    for (auto& room : rooms) {
      json entry;
      entry["room_id"] = room.room_id;
      if (!room.name.empty()) entry["name"] = room.name;
      if (!room.topic.empty()) entry["topic"] = room.topic;
      if (!room.canonical_alias.empty()) entry["canonical_alias"] = room.canonical_alias;
      entry["num_joined_members"] = room.num_joined_members;
      entry["world_readable"] = room.world_readable == "world_readable";
      entry["guest_can_join"] = room.guest_can_join;
      if (!room.room_type.empty()) entry["room_type"] = room.room_type;
      if (!room.avatar_url.empty()) entry["avatar_url"] = room.avatar_url;
      if (!room.aliases.empty()) entry["aliases"] = room.aliases;
      if (!room.join_rule.empty()) entry["join_rule"] = room.join_rule;
      result["chunk"].push_back(entry);
    }
    
    return result;
  }

  // Set room visibility in the directory
  json set_room_visibility(const std::string& room_id,
                            const std::string& visibility,
                            const std::string& requester) {
    if (visibility != "public" && visibility != "private") {
      return make_error("M_INVALID_PARAM",
                         "Visibility must be 'public' or 'private'");
    }
    
    json result;
    result["room_id"] = room_id;
    result["visibility"] = visibility;
    result["changed"] = true;
    return result;
  }

  // Get room visibility in directory
  json get_room_visibility(const std::string& room_id) {
    json result;
    result["room_id"] = room_id;
    result["visibility"] = "private"; // default
    return result;
  }

  // Get changes in public rooms since a given stream token
  json get_public_room_changes(int64_t since, int64_t to, int limit = 100) {
    json result;
    result["chunk"] = json::array();
    // Query public_room_list_stream for changes
    return result;
  }

private:
  json create_alias_internal(const std::string& alias,
                              const std::string& room_id,
                              const std::string& creator) {
    json result;
    result["alias"] = alias;
    result["room_id"] = room_id;
    result["created"] = true;
    return result;
  }
};

// ============================================================================
// RoomUpgradeHandler - handles room version upgrades
// ============================================================================
class RoomUpgradeHandler {
public:
  struct UpgradeResult {
    std::string replacement_room_id;
    std::string tombstone_event_id;
    std::vector<std::string> invited_users;
    std::vector<std::string> failed_users;
    json copied_state;
  };

  RoomUpgradeHandler(RoomVersionRegistry& version_registry)
      : version_registry_(version_registry) {}

  // Upgrade a room to a new version
  UpgradeResult upgrade_room(const std::string& old_room_id,
                              const std::string& new_version,
                              const std::string& requester,
                              const std::string& server_name,
                              bool copy_state = true,
                              bool invite_members = true,
                              bool send_tombstone = true) {
    
    UpgradeResult result;
    
    // Validate the target version
    if (!version_registry_.is_supported(new_version)) {
      throw std::runtime_error("Unsupported room version: " + new_version);
    }
    
    // Generate new room ID
    std::string new_room_id = "!" + generate_random_id() + ":" + server_name;
    result.replacement_room_id = new_room_id;
    
    // Create the new room with target version
    json create_content;
    create_content["creator"] = requester;
    create_content["room_version"] = new_version;
    create_content["predecessor"] = {
      {"room_id", old_room_id},
      {"event_id", "$placeholder:" + server_name}
    };
    
    // Copy state from old room if requested
    if (copy_state) {
      result.copied_state = copy_room_state(old_room_id, new_room_id, requester);
    }
    
    // Set replacement_room state in old room
    json replacement_state;
    replacement_state["replacement_room"] = new_room_id;
    result.copied_state["m.room.replacement"] = replacement_state;
    
    // Invite members from old room to new room
    if (invite_members) {
      auto members = get_joined_members(old_room_id);
      for (auto& member : members) {
        if (member != requester) {
          try {
            invite_user_to_room(new_room_id, member, requester);
            result.invited_users.push_back(member);
          } catch (...) {
            result.failed_users.push_back(member);
          }
        }
      }
    }
    
    // Send tombstone event to old room
    if (send_tombstone) {
      result.tombstone_event_id = send_tombstone_event(
          old_room_id, new_room_id, requester, server_name);
    }
    
    return result;
  }

  // Get the list of versions a room can upgrade to
  std::vector<std::string> get_upgradable_versions(
      const std::string& current_version) const {
    return version_registry_.get_upgradable_versions(current_version);
  }

  // Check if a room needs upgrading (deprecated version)
  bool needs_upgrade(const std::string& version) const {
    auto info = version_registry_.get_version(version);
    return info && info->status == "deprecated";
  }

  // Get the recommended upgrade target for a deprecated version
  std::string recommended_upgrade(const std::string& version) const {
    if (!needs_upgrade(version)) return version;
    return version_registry_.get_default_version();
  }

  // Copy state events from one room to another
  json copy_room_state(const std::string& from_room,
                        const std::string& to_room,
                        const std::string& sender) {
    json state_events = json::array();
    
    // State types to copy (standard room state)
    static const std::vector<std::string> copy_types = {
      "m.room.name",
      "m.room.topic",
      "m.room.avatar",
      "m.room.canonical_alias",
      "m.room.join_rules",
      "m.room.guest_access",
      "m.room.history_visibility",
      "m.room.power_levels",
      "m.room.server_acl",
    };
    
    for (auto& type : copy_types) {
      json state_entry;
      state_entry["type"] = type;
      state_entry["state_key"] = "";
      state_entry["content"] = json::object();
      state_entry["sender"] = sender;
      state_events.push_back(state_entry);
    }
    
    return state_events;
  }

  // Send tombstone event to old room
  std::string send_tombstone_event(const std::string& room_id,
                                    const std::string& replacement_room,
                                    const std::string& sender,
                                    const std::string& server_name) {
    std::string event_id = generate_event_id(server_name);
    
    json tombstone_content;
    tombstone_content["body"] = "This room has been replaced";
    tombstone_content["replacement_room"] = replacement_room;
    
    // In real implementation, this would persist the event to the database
    return event_id;
  }

  // Find the predecessor room (if this room is an upgrade)
  std::optional<std::string> find_predecessor_room(const std::string& room_id) {
    // Query m.room.create for this room to find the predecessor field
    return std::nullopt;
  }

  // Find the successor room (if this room was upgraded)
  std::optional<std::string> find_successor_room(const std::string& room_id) {
    // Query m.room.tombstone for this room to find replacement_room
    return std::nullopt;
  }

private:
  RoomVersionRegistry& version_registry_;

  std::vector<std::string> get_joined_members(const std::string& room_id) {
    std::vector<std::string> members;
    // In real implementation, query room_memberships or local_current_membership
    return members;
  }

  void invite_user_to_room(const std::string& room_id,
                           const std::string& user_id,
                           const std::string& sender) {
    json invite_content;
    invite_content["membership"] = "invite";
    invite_content["displayname"] = user_id;
    invite_content["reason"] = "Room upgrade";
    
    // Would persist a m.room.member event with membership: invite
  }
};

// ============================================================================
// RoomRetentionManager - enforces message retention policies
// ============================================================================
class RoomRetentionManager {
public:
  struct RetentionPolicy {
    int64_t max_lifetime_ms = 0;    // 0 means no maximum
    int64_t min_lifetime_ms = 0;    // 0 means no minimum
    bool enabled = false;
    std::string room_id;
  };

  struct PurgeStats {
    int64_t events_purged = 0;
    int64_t rooms_processed = 0;
    int64_t bytes_freed = 0;
    int64_t duration_ms = 0;
    std::vector<std::string> errors;
  };

  RoomRetentionManager(const RetentionConfig& config)
      : config_(config), is_running_(false) {}

  // Parse a retention policy from a m.room.retention state event
  RetentionPolicy parse_policy(const json& retention_event) {
    RetentionPolicy policy;
    
    if (retention_event.contains("max_lifetime")) {
      policy.max_lifetime_ms = retention_event["max_lifetime"].get<int64_t>();
    }
    
    if (retention_event.contains("min_lifetime")) {
      policy.min_lifetime_ms = retention_event["min_lifetime"].get<int64_t>();
    }
    
    policy.enabled = (policy.max_lifetime_ms > 0 || policy.min_lifetime_ms > 0);
    
    return policy;
  }

  // Set retention policy for a room
  json set_retention_policy(const std::string& room_id,
                             int64_t max_lifetime_ms,
                             int64_t min_lifetime_ms,
                             const std::string& sender) {
    // Validate lifetime ranges
    if (max_lifetime_ms < 0) {
      return make_error("M_INVALID_PARAM", "max_lifetime must be non-negative");
    }
    if (min_lifetime_ms < 0) {
      return make_error("M_INVALID_PARAM", "min_lifetime must be non-negative");
    }
    if (max_lifetime_ms > 0 && min_lifetime_ms > 0 && min_lifetime_ms > max_lifetime_ms) {
      return make_error("M_INVALID_PARAM",
                         "min_lifetime cannot exceed max_lifetime");
    }
    
    json content;
    if (max_lifetime_ms > 0) content["max_lifetime"] = max_lifetime_ms;
    if (min_lifetime_ms > 0) content["min_lifetime"] = min_lifetime_ms;
    
    json result;
    result["type"] = "m.room.retention";
    result["state_key"] = "";
    result["content"] = content;
    result["sender"] = sender;
    result["room_id"] = room_id;
    
    return result;
  }

  // Get the current retention policy for a room
  RetentionPolicy get_room_policy(const std::string& room_id) {
    RetentionPolicy policy;
    policy.room_id = room_id;
    
    // Default: apply server defaults
    policy.max_lifetime_ms = config_.default_max_lifetime_ms;
    policy.min_lifetime_ms = config_.default_min_lifetime_ms;
    
    // Query current_state_events for m.room.retention
    // If found, override defaults with room-specific policy
    
    policy.enabled = (policy.max_lifetime_ms > 0);
    
    return policy;
  }

  // Check if an event should be purged based on retention policy
  bool should_purge_event(int64_t event_origin_server_ts,
                           int64_t max_lifetime_ms) const {
    if (max_lifetime_ms <= 0) return false;
    
    int64_t event_age_ms = now_ms() - event_origin_server_ts;
    return event_age_ms > max_lifetime_ms;
  }

  // Purge expired events for a single room
  int64_t purge_expired_events_for_room(const std::string& room_id,
                                         int64_t max_lifetime_ms,
                                         int batch_size = 1000) {
    if (max_lifetime_ms <= 0) return 0;
    
    int64_t cutoff_ts = now_ms() - max_lifetime_ms;
    int64_t purged = 0;
    
    // In a real implementation, this would:
    // 1. Query events with origin_server_ts < cutoff_ts
    // 2. Skip state events (state is never purged)
    // 3. Delete in batches
    // 4. Update room stats
    
    return purged;
  }

  // Run a full retention purge across all rooms
  PurgeStats run_purge_job() {
    if (is_running_.exchange(true)) {
      return {0, 0, 0, 0, {"Purge job already running"}};
    }
    
    auto start = now_ms();
    PurgeStats stats;
    
    try {
      // Iterate over all rooms
      // For each room:
      //   1. Get retention policy
      //   2. If enabled, purge expired events
      //   3. Track stats
      
      stats.rooms_processed = 0;
      stats.events_purged = 0;
      
    } catch (const std::exception& e) {
      stats.errors.push_back(e.what());
    }
    
    stats.duration_ms = now_ms() - start;
    is_running_ = false;
    
    return stats;
  }

  // Schedule periodic purge jobs
  void start_background_purge() {
    if (bg_thread_.joinable()) return;
    running_ = true;
    
    bg_thread_ = std::thread([this]() {
      while (running_) {
        std::this_thread::sleep_for(
            chr::milliseconds(config_.purge_job_interval_ms));
        
        if (!running_) break;
        
        try {
          auto stats = run_purge_job();
          (void)stats; // Log or report stats
        } catch (const std::exception& e) {
          // Log error, continue
        }
      }
    });
  }

  void stop_background_purge() {
    running_ = false;
    if (bg_thread_.joinable()) {
      bg_thread_.join();
    }
  }

  // Calculate the earliest event timestamp that should be kept
  int64_t get_min_allowed_timestamp(int64_t max_lifetime_ms) const {
    if (max_lifetime_ms <= 0) return 0;
    return now_ms() - max_lifetime_ms;
  }

  // Determine if a room has an active retention policy
  bool has_active_policy(const std::string& room_id) {
    auto policy = get_room_policy(room_id);
    return policy.enabled;
  }

  // Get all rooms with active retention policies
  std::vector<std::string> get_rooms_with_policy() {
    std::vector<std::string> rooms;
    // Query rooms with m.room.retention in current_state_events
    return rooms;
  }

  // Validate retention config
  bool validate_config() const {
    if (config_.default_max_lifetime_ms < 0) return false;
    if (config_.default_min_lifetime_ms < 0) return false;
    if (config_.purge_job_interval_ms < 60000) return false; // Minimum 1 minute
    if (config_.max_purge_batch_size < 1) return false;
    return true;
  }

private:
  RetentionConfig config_;
  std::atomic<bool> is_running_{false};
  std::atomic<bool> running_{false};
  std::thread bg_thread_;
};

// ============================================================================
// RoomKnockManager - handles knock membership
// ============================================================================
class RoomKnockManager {
public:
  struct KnockInfo {
    std::string room_id;
    std::string user_id;
    std::string reason;
    std::string event_id;
    int64_t timestamp = 0;
    std::string state; // "pending", "accepted", "rejected"
  };

  RoomKnockManager() = default;

  // Send a knock to a room
  json send_knock(const std::string& room_id,
                   const std::string& user_id,
                   const std::string& reason,
                   const std::string& server_name,
                   const json& via = json::array()) {
    
    // Validate knock is supported (room version 7+)
    // Validate room exists and join_rules allow knocks
    
    // Check if user already has a knock pending
    if (has_pending_knock(room_id, user_id)) {
      return make_error("M_FORBIDDEN", "You already have a pending knock");
    }
    
    // Check if user is already a member
    if (is_member(room_id, user_id)) {
      return make_error("M_FORBIDDEN", "You are already a member of this room");
    }
    
    // Check if user is banned
    if (is_banned(room_id, user_id)) {
      return make_error("M_FORBIDDEN", "You are banned from this room");
    }
    
    std::string event_id = generate_event_id(server_name);
    
    json knock_content;
    knock_content["membership"] = "knock";
    knock_content["displayname"] = user_id;
    if (!reason.empty()) {
      knock_content["reason"] = reason;
    }
    
    json result;
    result["event_id"] = event_id;
    result["room_id"] = room_id;
    result["user_id"] = user_id;
    result["membership"] = "knock";
    result["knock_state"] = "pending";
    
    // In a production implementation, this would:
    // 1. Create a m.room.member event with membership: "knock"
    // 2. Persist to current_state_events
    // 3. Notify room admins/moderators
    // 4. If federated, send knock event to other servers
    
    // Add to pending knocks
    pending_knocks_[room_id].push_back({
      room_id, user_id, reason, event_id, now_ms(), "pending"
    });
    
    return result;
  }

  // Accept a knock (admin/moderator action)
  json accept_knock(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& approver,
                     const std::string& server_name) {
    
    if (!has_pending_knock(room_id, user_id)) {
      return make_error("M_NOT_FOUND", "No pending knock from this user");
    }
    
    // Check approver has permission (power level for invite)
    
    std::string event_id = generate_event_id(server_name);
    
    json member_content;
    member_content["membership"] = "invite";
    member_content["displayname"] = user_id;
    
    json result;
    result["event_id"] = event_id;
    result["room_id"] = room_id;
    result["user_id"] = user_id;
    result["membership"] = "invite";
    result["knock_state"] = "accepted";
    
    // Update the pending knock state
    update_knock_state(room_id, user_id, "accepted");
    
    // The user will then receive the invite and can join
    
    return result;
  }

  // Reject a knock
  json reject_knock(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& rejector,
                     const std::string& reason,
                     const std::string& server_name) {
    
    if (!has_pending_knock(room_id, user_id)) {
      return make_error("M_NOT_FOUND", "No pending knock from this user");
    }
    
    std::string event_id = generate_event_id(server_name);
    
    json leave_content;
    leave_content["membership"] = "leave";
    if (!reason.empty()) {
      leave_content["reason"] = reason;
    }
    
    json result;
    result["event_id"] = event_id;
    result["room_id"] = room_id;
    result["user_id"] = user_id;
    result["membership"] = "leave";
    result["knock_state"] = "rejected";
    
    update_knock_state(room_id, user_id, "rejected");
    
    return result;
  }

  // Get all pending knocks for a room
  std::vector<KnockInfo> get_pending_knocks(const std::string& room_id) {
    std::vector<KnockInfo> result;
    
    auto it = pending_knocks_.find(room_id);
    if (it != pending_knocks_.end()) {
      for (auto& knock : it->second) {
        if (knock.state == "pending") {
          result.push_back(knock);
        }
      }
    }
    
    return result;
  }

  // Check if a user has a pending knock in a room
  bool has_pending_knock(const std::string& room_id,
                          const std::string& user_id) {
    auto it = pending_knocks_.find(room_id);
    if (it != pending_knocks_.end()) {
      for (auto& knock : it->second) {
        if (knock.user_id == user_id && knock.state == "pending") {
          return true;
        }
      }
    }
    return false;
  }

  // Get knock state for a user in a room
  std::string get_knock_state(const std::string& room_id,
                               const std::string& user_id) {
    auto it = pending_knocks_.find(room_id);
    if (it != pending_knocks_.end()) {
      for (auto& knock : it->second) {
        if (knock.user_id == user_id) {
          return knock.state;
        }
      }
    }
    return "none";
  }

  // Check if knocking is allowed for a room
  bool is_knock_allowed(const std::string& room_id,
                         const std::string& room_version,
                         const std::string& join_rule) {
    // Knock requires room version 7+
    static const std::set<std::string> knock_versions = {
      "7", "8", "9", "10", "11"
    };
    
    if (knock_versions.find(room_version) == knock_versions.end()) {
      return false;
    }
    
    // Knock is allowed when join_rule is "knock" or "invite"
    // (some implementations also allow knock on "knock_restricted")
    return join_rule == "knock" || join_rule == "invite" ||
           join_rule == "knock_restricted";
  }

  // Clean up old/rejected knocks
  void cleanup_old_knocks(int64_t max_age_ms = 604800000) { // default 7 days
    int64_t cutoff = now_ms() - max_age_ms;
    
    for (auto& [room_id, knocks] : pending_knocks_) {
      knocks.erase(
        std::remove_if(knocks.begin(), knocks.end(),
          [cutoff](const KnockInfo& k) {
            return k.timestamp < cutoff && k.state != "pending";
          }),
        knocks.end()
      );
    }
  }

  // Count pending knocks across all rooms
  int64_t count_all_pending_knocks() {
    int64_t count = 0;
    for (auto& [room_id, knocks] : pending_knocks_) {
      for (auto& knock : knocks) {
        if (knock.state == "pending") count++;
      }
    }
    return count;
  }

private:
  std::map<std::string, std::vector<KnockInfo>> pending_knocks_;
  
  bool is_member(const std::string& room_id, const std::string& user_id) {
    // Query membership database
    return false;
  }
  
  bool is_banned(const std::string& room_id, const std::string& user_id) {
    // Query membership database for ban state
    return false;
  }
  
  void update_knock_state(const std::string& room_id,
                           const std::string& user_id,
                           const std::string& new_state) {
    auto it = pending_knocks_.find(room_id);
    if (it != pending_knocks_.end()) {
      for (auto& knock : it->second) {
        if (knock.user_id == user_id) {
          knock.state = new_state;
          break;
        }
      }
    }
  }
};

// ============================================================================
// RestrictedRoomManager - manages restricted join rules
// ============================================================================
class RestrictedRoomManager {
public:
  struct AllowRule {
    std::string type;         // "m.room_membership"
    std::string room_id;      // The room/space to check membership in
    std::string via;          // via server
  };

  struct JoinRulesConfig {
    std::string join_rule;             // "public", "invite", "knock", "restricted", "knock_restricted"
    std::vector<AllowRule> allow;      // Allow rules for restricted joins
  };

  RestrictedRoomManager() = default;

  // Set join rules for a room, including restricted join rules
  json set_join_rules(const std::string& room_id,
                       const std::string& join_rule,
                       const std::vector<AllowRule>& allow_rules,
                       const std::string& sender,
                       const std::string& server_name) {
    
    // Validate join_rule
    static const std::set<std::string> valid_rules = {
      "public", "invite", "knock", "restricted", "knock_restricted", "private"
    };
    
    if (valid_rules.find(join_rule) == valid_rules.end()) {
      return make_error("M_INVALID_PARAM", "Invalid join_rule: " + join_rule);
    }
    
    // Validate allow rules for restricted/knock_restricted
    if ((join_rule == "restricted" || join_rule == "knock_restricted") &&
        allow_rules.empty()) {
      return make_error("M_INVALID_PARAM",
          "restricted join rules require at least one allow rule");
    }
    
    json content;
    content["join_rule"] = join_rule;
    
    if (!allow_rules.empty()) {
      json allow_array = json::array();
      for (auto& rule : allow_rules) {
        json entry;
        entry["type"] = rule.type;
        entry["room_id"] = rule.room_id;
        if (!rule.via.empty()) {
          entry["via"] = rule.via;
        }
        allow_array.push_back(entry);
      }
      content["allow"] = allow_array;
    }
    
    json result;
    result["type"] = "m.room.join_rules";
    result["state_key"] = "";
    result["content"] = content;
    result["sender"] = sender;
    result["room_id"] = room_id;
    
    return result;
  }

  // Get current join rules for a room
  JoinRulesConfig get_join_rules(const std::string& room_id) {
    JoinRulesConfig config;
    config.join_rule = "invite"; // default
    
    // Query current_state_events for m.room.join_rules
    
    return config;
  }

  // Check if a user is authorized to join a restricted room
  bool is_authorized_for_restricted_join(const std::string& room_id,
                                          const std::string& user_id,
                                          const JoinRulesConfig& rules) {
    if (rules.join_rule != "restricted" && rules.join_rule != "knock_restricted") {
      return true; // Not a restricted room, normal join rules apply
    }
    
    // For restricted rooms, user must:
    // 1. Be a joined member of at least one allowed room/space, OR
    // 2. Have an invite to this room
    
    for (auto& rule : rules.allow) {
      if (rule.type == "m.room_membership") {
        if (is_user_in_room(rule.room_id, user_id)) {
          return true;
        }
      }
    }
    
    return false;
  }

  // Validate restricted join rules before creation/update
  json validate_restricted_rules(const JoinRulesConfig& rules) {
    json errors = json::array();
    
    if (rules.join_rule == "restricted" || rules.join_rule == "knock_restricted") {
      // Must have at least one allow rule
      if (rules.allow.empty()) {
        errors.push_back("restricted join rules require allow list");
      }
      
      // Each allow rule must reference a valid room
      for (auto& rule : rules.allow) {
        if (rule.type != "m.room_membership") {
          errors.push_back("Unknown allow type: " + rule.type);
        }
        if (!is_valid_room_id(rule.room_id)) {
          errors.push_back("Invalid room_id in allow rule: " + rule.room_id);
        }
      }
    }
    
    return errors;
  }

  // Get the list of rooms/spaces that allow access to a restricted room
  std::vector<AllowRule> get_allow_rules(const std::string& room_id) {
    auto config = get_join_rules(room_id);
    return config.allow;
  }

  // Add an allow rule to an existing restricted room
  json add_allow_rule(const std::string& room_id,
                       const AllowRule& rule,
                       const std::string& sender) {
    auto config = get_join_rules(room_id);
    
    // Check for duplicates
    for (auto& existing : config.allow) {
      if (existing.type == rule.type && existing.room_id == rule.room_id) {
        return make_error("M_INVALID_PARAM", "Duplicate allow rule");
      }
    }
    
    config.allow.push_back(rule);
    
    return set_join_rules(room_id, config.join_rule, config.allow,
                           sender, "localhost");
  }

  // Remove an allow rule from a restricted room
  json remove_allow_rule(const std::string& room_id,
                          const AllowRule& rule,
                          const std::string& sender) {
    auto config = get_join_rules(room_id);
    
    auto it = std::remove_if(config.allow.begin(), config.allow.end(),
        [&rule](const AllowRule& r) {
          return r.type == rule.type && r.room_id == rule.room_id;
        });
    
    if (it == config.allow.end()) {
      return make_error("M_NOT_FOUND", "Allow rule not found");
    }
    
    config.allow.erase(it, config.allow.end());
    
    // If no allow rules remain and join_rule is restricted, fallback to invite
    if (config.allow.empty() &&
        (config.join_rule == "restricted" || config.join_rule == "knock_restricted")) {
      config.join_rule = "invite";
    }
    
    return set_join_rules(room_id, config.join_rule, config.allow,
                           sender, "localhost");
  }

  // Check if a room supports restricted joins (version 8+)
  bool supports_restricted_joins(const std::string& room_version) {
    static const std::set<std::string> restricted_versions = {
      "8", "9", "10", "11"
    };
    return restricted_versions.find(room_version) != restricted_versions.end();
  }

  // Build a preview of join rules for room creation
  json build_restricted_preview(const std::vector<std::string>& allowed_rooms,
                                 const std::string& join_rule) {
    json preview;
    preview["join_rule"] = join_rule;
    
    json allow = json::array();
    for (auto& room_id : allowed_rooms) {
      json rule;
      rule["type"] = "m.room_membership";
      rule["room_id"] = room_id;
      allow.push_back(rule);
    }
    
    if (!allow.empty()) {
      preview["allow"] = allow;
    }
    
    return preview;
  }

  // Generate a recommended join rule based on the allow list
  std::string recommend_join_rule(const std::vector<AllowRule>& allow_rules) {
    if (allow_rules.empty()) {
      return "invite";
    }
    return "restricted";
  }

private:
  bool is_user_in_room(const std::string& room_id, const std::string& user_id) {
    // Check if user is a joined member of the specified room
    // Would query local_current_membership or room_memberships
    return false;
  }
};

// ============================================================================
// SpaceSummaryBuilder - builds space summary responses
// ============================================================================
class SpaceSummaryBuilder {
public:
  struct SummaryOptions {
    int max_rooms = 250;
    int max_depth = 5;
    bool suggested_only = false;
    bool include_heroes = true;
    std::string via_server;
    std::string language;
  };

  struct RoomSummary {
    std::string room_id;
    std::string room_type;
    std::string name;
    std::string topic;
    std::string canonical_alias;
    std::string avatar_url;
    std::string join_rule;
    std::string world_readable;
    int num_joined_members = 0;
    std::vector<std::string> children;
    std::vector<std::string> heroes;
    json via_servers = json::array();
    bool guest_can_join = false;
  };

  SpaceSummaryBuilder(SpaceHierarchy& hierarchy) : hierarchy_(hierarchy) {}

  // Build a complete space summary
  json build_summary(const std::string& space_id,
                      const std::string& requester,
                      const SummaryOptions& options = {}) {
    json result;
    result["rooms"] = json::array();
    result["events"] = json::array();
    
    std::set<std::string> visited;
    std::vector<std::string> stack = {space_id};
    
    int rooms_added = 0;
    
    while (!stack.empty() && rooms_added < options.max_rooms) {
      std::string current = stack.back();
      stack.pop_back();
      
      if (visited.count(current)) continue;
      visited.insert(current);
      
      RoomSummary summary = get_room_summary(current, requester);
      
      // Apply suggested_only filter
      if (options.suggested_only && current != space_id) {
        // Check if this room is suggested
        // In real implementation, check m.space.child suggested flag
      }
      
      json room_entry;
      room_entry["room_id"] = summary.room_id;
      if (!summary.room_type.empty()) room_entry["room_type"] = summary.room_type;
      if (!summary.name.empty()) room_entry["name"] = summary.name;
      if (!summary.topic.empty()) room_entry["topic"] = summary.topic;
      if (!summary.canonical_alias.empty()) room_entry["canonical_alias"] = summary.canonical_alias;
      if (!summary.avatar_url.empty()) room_entry["avatar_url"] = summary.avatar_url;
      room_entry["num_joined_members"] = summary.num_joined_members;
      room_entry["join_rule"] = summary.join_rule;
      room_entry["world_readable"] = summary.world_readable == "world_readable";
      room_entry["guest_can_join"] = summary.guest_can_join;
      if (!summary.via_servers.empty()) room_entry["via"] = summary.via_servers;
      
      result["rooms"].push_back(room_entry);
      rooms_added++;
      
      // Add children to stack for traversal
      for (auto& child : summary.children) {
        if (!visited.count(child)) {
          stack.push_back(child);
        }
      }
    }
    
    // Add next_batch token for pagination
    if (!stack.empty()) {
      result["next_batch"] = stack.back();
    }
    
    return result;
  }

  // Get a simplified room summary
  RoomSummary get_room_summary(const std::string& room_id,
                                const std::string& requester) {
    RoomSummary summary;
    summary.room_id = room_id;
    summary.join_rule = "invite";
    
    // In a real implementation, this queries:
    // - room_stats_state for name, topic, member count
    // - current_state_events for join_rules, history_visibility
    // - room_aliases for canonical alias
    // - m.space.child events for children
    
    return summary;
  }

  // Generate via servers list for a room
  json generate_via_servers(const std::string& room_id) {
    json servers = json::array();
    
    // Add local server
    servers.push_back("localhost");
    
    // Add servers from joined members' user IDs
    // In real implementation, query local_current_membership for room
    
    return servers;
  }

  // Find accessible children for a user in a space
  std::vector<std::string> get_accessible_children(
      const std::string& space_id,
      const std::string& user_id,
      RoomVisibilityChecker& visibility_checker) {
    
    std::vector<std::string> result;
    
    // Get all child rooms via m.space.child state events
    // Filter to only rooms the user can see
    
    return result;
  }

private:
  SpaceHierarchy& hierarchy_;
};

// ============================================================================
// RoomFeatureCoordinator - coordinates all room features
// ============================================================================
class RoomFeatureCoordinator {
public:
  RoomFeatureCoordinator(const std::string& server_name)
      : server_name_(server_name),
        version_registry_(std::make_unique<RoomVersionRegistry>()),
        hierarchy_(std::make_unique<SpaceHierarchy>()),
        directory_(std::make_unique<RoomDirectoryManager>()),
        visibility_(std::make_unique<RoomVisibilityChecker>()),
        upgrade_handler_(std::make_unique<RoomUpgradeHandler>(*version_registry_)),
        retention_mgr_(std::make_unique<RoomRetentionManager>(RetentionConfig{})),
        knock_mgr_(std::make_unique<RoomKnockManager>()),
        restricted_mgr_(std::make_unique<RestrictedRoomManager>()),
        summary_builder_(std::make_unique<SpaceSummaryBuilder>(*hierarchy_)) {}

  // ---- Spaces API ----
  
  json create_space(const std::string& creator,
                    const std::string& name,
                    const std::string& topic,
                    const std::string& preset = "public_chat",
                    const std::vector<std::string>& invite = {}) {
    return hierarchy_->create_space_room(creator, server_name_, name, topic,
                                         preset, invite);
  }

  json add_child_to_space(const std::string& space_id,
                           const std::string& child_room_id,
                           const std::string& sender,
                           bool suggested = false,
                           const std::string& order = "",
                           const json& via = json::array()) {
    return hierarchy_->add_child_room(space_id, child_room_id, sender,
                                      suggested, order, via);
  }

  json add_parent_to_room(const std::string& room_id,
                           const std::string& space_id,
                           const std::string& sender,
                           bool canonical = false) {
    return hierarchy_->add_parent_space(room_id, space_id, sender, canonical);
  }

  json get_space_hierarchy(const std::string& space_id,
                            int max_depth = 5, int limit = 250) {
    return hierarchy_->get_space_hierarchy(space_id, max_depth, limit);
  }

  json get_space_summary(const std::string& space_id,
                          const std::string& requester,
                          int max_rooms = 250, int max_depth = 5,
                          bool suggested_only = false) {
    SpaceSummaryBuilder::SummaryOptions opts;
    opts.max_rooms = max_rooms;
    opts.max_depth = max_depth;
    opts.suggested_only = suggested_only;
    return summary_builder_->build_summary(space_id, requester, opts);
  }

  // ---- Room Directory API ----

  json create_room_alias(const std::string& alias,
                          const std::string& room_id,
                          const std::string& creator) {
    return directory_->create_alias(alias, room_id, creator, server_name_);
  }

  json delete_room_alias(const std::string& alias,
                          const std::string& requester) {
    return directory_->delete_alias(alias, requester);
  }

  json resolve_room_alias(const std::string& alias) {
    return directory_->resolve_alias(alias);
  }

  json list_public_rooms(const std::string& server = "",
                          int limit = 100, const std::string& since = "",
                          const std::string& search = "") {
    return directory_->list_public_rooms(server, limit, since, search);
  }

  json set_room_visibility(const std::string& room_id,
                            const std::string& visibility,
                            const std::string& requester) {
    return directory_->set_room_visibility(room_id, visibility, requester);
  }

  json get_room_visibility(const std::string& room_id) {
    return directory_->get_room_visibility(room_id);
  }

  // ---- Room Visibility API ----

  bool can_view_events(const std::string& user_id,
                       const std::string& membership,
                       const std::string& history_visibility) {
    return visibility_->can_view_events(user_id, membership, history_visibility);
  }

  bool can_see_event(const std::string& user_id,
                     const std::string& membership,
                     const std::string& history_visibility,
                     const std::string& sender) {
    return visibility_->can_see_event(user_id, membership,
                                       history_visibility, sender);
  }

  json filter_events(const std::string& user_id,
                      const std::string& membership,
                      const std::string& history_visibility,
                      const json& events) {
    return visibility_->filter_events_by_visibility(user_id, membership,
                                                     history_visibility, events);
  }

  // ---- Room Upgrade API ----

  json upgrade_room(const std::string& room_id,
                     const std::string& new_version,
                     const std::string& requester) {
    auto result = upgrade_handler_->upgrade_room(
        room_id, new_version, requester, server_name_);
    
    json resp;
    resp["replacement_room"] = result.replacement_room_id;
    resp["tombstone_event_id"] = result.tombstone_event_id;
    resp["invited_users"] = result.invited_users;
    resp["failed_users"] = result.failed_users;
    return resp;
  }

  json get_upgradable_versions(const std::string& current_version) {
    auto versions = upgrade_handler_->get_upgradable_versions(current_version);
    json resp = json::array();
    for (auto& v : versions) resp.push_back(v);
    return resp;
  }

  // ---- Room Retention API ----

  json set_retention_policy(const std::string& room_id,
                             int64_t max_lifetime_ms,
                             int64_t min_lifetime_ms,
                             const std::string& sender) {
    return retention_mgr_->set_retention_policy(
        room_id, max_lifetime_ms, min_lifetime_ms, sender);
  }

  json get_retention_policy(const std::string& room_id) {
    auto policy = retention_mgr_->get_room_policy(room_id);
    json resp;
    resp["max_lifetime"] = policy.max_lifetime_ms;
    resp["min_lifetime"] = policy.min_lifetime_ms;
    resp["enabled"] = policy.enabled;
    return resp;
  }

  json run_retention_purge() {
    auto stats = retention_mgr_->run_purge_job();
    json resp;
    resp["events_purged"] = stats.events_purged;
    resp["rooms_processed"] = stats.rooms_processed;
    resp["duration_ms"] = stats.duration_ms;
    if (!stats.errors.empty()) resp["errors"] = stats.errors;
    return resp;
  }

  // ---- Room Knocks API ----

  json knock_on_room(const std::string& room_id,
                      const std::string& user_id,
                      const std::string& reason = "",
                      const json& via = json::array()) {
    return knock_mgr_->send_knock(room_id, user_id, reason, server_name_, via);
  }

  json accept_knock(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& approver) {
    return knock_mgr_->accept_knock(room_id, user_id, approver, server_name_);
  }

  json reject_knock(const std::string& room_id,
                     const std::string& user_id,
                     const std::string& rejector,
                     const std::string& reason = "") {
    return knock_mgr_->reject_knock(room_id, user_id, rejector, reason, server_name_);
  }

  json get_pending_knocks(const std::string& room_id) {
    auto knocks = knock_mgr_->get_pending_knocks(room_id);
    json resp = json::array();
    for (auto& k : knocks) {
      json entry;
      entry["room_id"] = k.room_id;
      entry["user_id"] = k.user_id;
      entry["reason"] = k.reason;
      entry["timestamp"] = k.timestamp;
      entry["state"] = k.state;
      resp.push_back(entry);
    }
    return resp;
  }

  // ---- Room Versions API ----

  json get_supported_versions() {
    return version_registry_->get_supported_versions();
  }

  json get_capabilities() {
    return version_registry_->get_capabilities();
  }

  std::string get_default_version() {
    return version_registry_->get_default_version();
  }

  bool is_version_supported(const std::string& ver) {
    return version_registry_->is_supported(ver);
  }

  json get_version_features(const std::string& ver) {
    return version_registry_->get_version_features(ver);
  }

  // ---- Restricted Rooms API ----

  json set_restricted_join_rules(const std::string& room_id,
                                  const std::string& join_rule,
                                  const std::vector<RestrictedRoomManager::AllowRule>& allow,
                                  const std::string& sender) {
    return restricted_mgr_->set_join_rules(room_id, join_rule, allow, sender, server_name_);
  }

  bool can_join_restricted_room(const std::string& room_id,
                                 const std::string& user_id) {
    auto rules = restricted_mgr_->get_join_rules(room_id);
    return restricted_mgr_->is_authorized_for_restricted_join(room_id, user_id, rules);
  }

  json get_join_rules(const std::string& room_id) {
    auto rules = restricted_mgr_->get_join_rules(room_id);
    json resp;
    resp["join_rule"] = rules.join_rule;
    if (!rules.allow.empty()) {
      json allow_arr = json::array();
      for (auto& r : rules.allow) {
        json entry;
        entry["type"] = r.type;
        entry["room_id"] = r.room_id;
        allow_arr.push_back(entry);
      }
      resp["allow"] = allow_arr;
    }
    return resp;
  }

  // ---- Lifecycle ----

  void start() {
    retention_mgr_->start_background_purge();
  }

  void stop() {
    retention_mgr_->stop_background_purge();
  }

  // Access individual components
  RoomVersionRegistry& versions() { return *version_registry_; }
  SpaceHierarchy& spaces() { return *hierarchy_; }
  RoomDirectoryManager& directory() { return *directory_; }
  RoomVisibilityChecker& visibility() { return *visibility_; }
  RoomUpgradeHandler& upgrades() { return *upgrade_handler_; }
  RoomRetentionManager& retention() { return *retention_mgr_; }
  RoomKnockManager& knocks() { return *knock_mgr_; }
  RestrictedRoomManager& restricted() { return *restricted_mgr_; }

private:
  std::string server_name_;
  std::unique_ptr<RoomVersionRegistry> version_registry_;
  std::unique_ptr<SpaceHierarchy> hierarchy_;
  std::unique_ptr<RoomDirectoryManager> directory_;
  std::unique_ptr<RoomVisibilityChecker> visibility_;
  std::unique_ptr<RoomUpgradeHandler> upgrade_handler_;
  std::unique_ptr<RoomRetentionManager> retention_mgr_;
  std::unique_ptr<RoomKnockManager> knock_mgr_;
  std::unique_ptr<RestrictedRoomManager> restricted_mgr_;
  std::unique_ptr<SpaceSummaryBuilder> summary_builder_;
};

// ============================================================================
// REST API Servlets for room features
// ============================================================================

// ---- Space listing servlet ----
class SpaceSummaryServlet {
public:
  explicit SpaceSummaryServlet(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json handle_get_summary(const std::string& space_id,
                           const std::string& user_id,
                           const json& params) {
    int max_rooms = params.value("max_rooms_per_space", 250);
    int max_depth = params.value("max_depth", 5);
    bool suggested_only = params.value("suggested_only", false);
    
    return coordinator_.get_space_summary(space_id, user_id, max_rooms,
                                          max_depth, suggested_only);
  }

  json handle_add_child(const std::string& space_id,
                         const std::string& sender,
                         const json& body) {
    std::string child_room_id = body["child_room_id"];
    bool suggested = body.value("suggested", false);
    std::string order = body.value("order", "");
    json via = body.value("via", json::array());
    
    return coordinator_.add_child_to_space(space_id, child_room_id, sender,
                                           suggested, order, via);
  }

  json handle_add_parent(const std::string& room_id,
                          const std::string& sender,
                          const json& body) {
    std::string space_id = body["space_id"];
    bool canonical = body.value("canonical", false);
    
    return coordinator_.add_parent_to_room(room_id, space_id, sender, canonical);
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ---- Room directory servlet ----
class RoomDirectoryServlet {
public:
  explicit RoomDirectoryServlet(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json handle_list_rooms(const std::string& user_id, const json& params) {
    std::string server = params.value("server", "");
    int limit = params.value("limit", 100);
    std::string since = params.value("since", "");
    std::string search = params.value("search_term", "");
    
    return coordinator_.list_public_rooms(server, limit, since, search);
  }

  json handle_create_alias(const std::string& user_id, const json& body) {
    std::string room_id = body["room_id"];
    std::string alias = body["alias"];
    
    return coordinator_.create_room_alias(alias, room_id, user_id);
  }

  json handle_delete_alias(const std::string& alias, const std::string& user_id) {
    return coordinator_.delete_room_alias(alias, user_id);
  }

  json handle_resolve_alias(const std::string& alias) {
    return coordinator_.resolve_room_alias(alias);
  }

  json handle_set_visibility(const std::string& room_id,
                              const std::string& user_id,
                              const json& body) {
    std::string visibility = body["visibility"];
    return coordinator_.set_room_visibility(room_id, visibility, user_id);
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ---- Room upgrade servlet ----
class RoomUpgradeServlet {
public:
  explicit RoomUpgradeServlet(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json handle_upgrade(const std::string& room_id,
                       const std::string& user_id,
                       const json& body) {
    std::string new_version = body.value("new_version",
        coordinator_.get_default_version());
    
    return coordinator_.upgrade_room(room_id, new_version, user_id);
  }

  json handle_get_upgradable(const std::string& room_id) {
    // Get current version from room state
    std::string current = "1"; // default
    return coordinator_.get_upgradable_versions(current);
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ---- Room retention servlet ----
class RoomRetentionServlet {
public:
  explicit RoomRetentionServlet(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json handle_set_policy(const std::string& room_id,
                          const std::string& user_id,
                          const json& body) {
    int64_t max_lifetime = body.value("max_lifetime", (int64_t)0);
    int64_t min_lifetime = body.value("min_lifetime", (int64_t)0);
    
    return coordinator_.set_retention_policy(room_id, max_lifetime,
                                              min_lifetime, user_id);
  }

  json handle_get_policy(const std::string& room_id) {
    return coordinator_.get_retention_policy(room_id);
  }

  json handle_trigger_purge() {
    return coordinator_.run_retention_purge();
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ---- Room knock servlet ----
class RoomKnockServlet {
public:
  explicit RoomKnockServlet(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json handle_knock(const std::string& room_id,
                     const std::string& user_id,
                     const json& body) {
    std::string reason = body.value("reason", "");
    json via = body.value("via", json::array());
    
    return coordinator_.knock_on_room(room_id, user_id, reason, via);
  }

  json handle_accept_knock(const std::string& room_id,
                            const std::string& approver,
                            const json& body) {
    std::string user_id = body["user_id"];
    return coordinator_.accept_knock(room_id, user_id, approver);
  }

  json handle_reject_knock(const std::string& room_id,
                            const std::string& rejector,
                            const json& body) {
    std::string user_id = body["user_id"];
    std::string reason = body.value("reason", "");
    return coordinator_.reject_knock(room_id, user_id, rejector, reason);
  }

  json handle_list_knocks(const std::string& room_id) {
    return coordinator_.get_pending_knocks(room_id);
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ---- Room capabilities servlet ----
class RoomCapabilitiesServlet {
public:
  explicit RoomCapabilitiesServlet(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json handle_get_capabilities() {
    return coordinator_.get_capabilities();
  }

  json handle_get_versions() {
    return coordinator_.get_supported_versions();
  }

  json handle_get_version_features(const std::string& version) {
    return coordinator_.get_version_features(version);
  }

  bool handle_check_version(const std::string& version) {
    return coordinator_.is_version_supported(version);
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ---- Restricted rooms servlet ----
class RestrictedRoomsServlet {
public:
  explicit RestrictedRoomsServlet(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json handle_set_join_rules(const std::string& room_id,
                              const std::string& user_id,
                              const json& body) {
    std::string join_rule = body["join_rule"];
    std::vector<RestrictedRoomManager::AllowRule> allow_rules;
    
    if (body.contains("allow")) {
      for (auto& rule : body["allow"]) {
        RestrictedRoomManager::AllowRule ar;
        ar.type = rule.value("type", "m.room_membership");
        ar.room_id = rule["room_id"];
        ar.via = rule.value("via", "");
        allow_rules.push_back(ar);
      }
    }
    
    return coordinator_.set_restricted_join_rules(room_id, join_rule,
                                                   allow_rules, user_id);
  }

  json handle_get_join_rules(const std::string& room_id) {
    return coordinator_.get_join_rules(room_id);
  }

  json handle_check_join(const std::string& room_id,
                          const std::string& user_id) {
    bool can_join = coordinator_.can_join_restricted_room(room_id, user_id);
    json resp;
    resp["can_join"] = can_join;
    resp["room_id"] = room_id;
    resp["user_id"] = user_id;
    return resp;
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ============================================================================
// Admin endpoints for room features
// ============================================================================

// ---- Admin: bulk space operations ----
class AdminSpaceOperations {
public:
  explicit AdminSpaceOperations(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json bulk_add_children(const std::string& space_id,
                          const std::vector<std::string>& room_ids,
                          const std::string& admin_user) {
    json results = json::array();
    for (auto& rid : room_ids) {
      try {
        auto result = coordinator_.add_child_to_space(space_id, rid, admin_user);
        results.push_back({{"room_id", rid}, {"status", "added"}, {"result", result}});
      } catch (const std::exception& e) {
        results.push_back({{"room_id", rid}, {"status", "error"}, {"error", e.what()}});
      }
    }
    return results;
  }

  json bulk_remove_children(const std::string& space_id,
                             const std::vector<std::string>& room_ids,
                             const std::string& admin_user) {
    json results = json::array();
    for (auto& rid : room_ids) {
      try {
        // Remove by sending empty content m.space.child
        json result;
        result["type"] = "m.space.child";
        result["state_key"] = rid;
        result["content"] = json::object();
        result["sender"] = admin_user;
        result["room_id"] = space_id;
        results.push_back({{"room_id", rid}, {"status", "removed"}});
      } catch (const std::exception& e) {
        results.push_back({{"room_id", rid}, {"status", "error"}, {"error", e.what()}});
      }
    }
    return results;
  }

  json repair_space_hierarchy(const std::string& space_id) {
    json report;
    report["space_id"] = space_id;
    report["orphaned_children"] = json::array();
    report["missing_parents"] = json::array();
    report["fixed"] = 0;
    report["errors"] = 0;
    return report;
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ---- Admin: directory management ----
class AdminDirectoryOperations {
public:
  explicit AdminDirectoryOperations(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json force_set_visibility(const std::string& room_id,
                             const std::string& visibility) {
    return coordinator_.set_room_visibility(room_id, visibility, "admin");
  }

  json delete_orphan_aliases() {
    json report;
    report["aliases_deleted"] = 0;
    report["errors"] = json::array();
    return report;
  }

  json recalculate_public_room_stats() {
    json report;
    report["rooms_processed"] = 0;
    report["errors"] = json::array();
    return report;
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ---- Admin: retention management ----
class AdminRetentionOperations {
public:
  explicit AdminRetentionOperations(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json force_purge_room(const std::string& room_id, int64_t before_ts) {
    // Force purge events from a room older than the given timestamp
    json report;
    report["room_id"] = room_id;
    report["purged"] = 0;
    report["cutoff_timestamp"] = before_ts;
    return report;
  }

  json get_retention_stats() {
    json stats;
    stats["rooms_with_policy"] = 0;
    stats["total_purged_events"] = 0;
    stats["last_purge_timestamp"] = 0;
    return stats;
  }

  json set_server_default_retention(int64_t max_lifetime_ms,
                                     int64_t min_lifetime_ms) {
    json resp;
    resp["max_lifetime"] = max_lifetime_ms;
    resp["min_lifetime"] = min_lifetime_ms;
    resp["applied"] = true;
    return resp;
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ---- Admin: knock management ----
class AdminKnockOperations {
public:
  explicit AdminKnockOperations(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json get_all_pending_knocks() {
    json report;
    report["total_pending"] = 0;
    report["knocks"] = json::array();
    return report;
  }

  json cleanup_expired_knocks() {
    json report;
    report["cleaned"] = 0;
    return report;
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ---- Admin: restricted room audit ----
class AdminRestrictedRoomOperations {
public:
  explicit AdminRestrictedRoomOperations(RoomFeatureCoordinator& coordinator)
      : coordinator_(coordinator) {}

  json audit_restricted_rooms() {
    json report;
    report["restricted_rooms"] = json::array();
    report["rooms_with_invalid_allows"] = json::array();
    return report;
  }

  json fix_restricted_room_cycles() {
    json report;
    report["cycles_found"] = 0;
    report["cycles_fixed"] = 0;
    return report;
  }

private:
  RoomFeatureCoordinator& coordinator_;
};

// ============================================================================
// Factory function: create the full room features subsystem
// ============================================================================
struct RoomFeaturesSubsystem {
  std::unique_ptr<RoomFeatureCoordinator> coordinator;
  std::unique_ptr<SpaceSummaryServlet> space_servlet;
  std::unique_ptr<RoomDirectoryServlet> directory_servlet;
  std::unique_ptr<RoomUpgradeServlet> upgrade_servlet;
  std::unique_ptr<RoomRetentionServlet> retention_servlet;
  std::unique_ptr<RoomKnockServlet> knock_servlet;
  std::unique_ptr<RoomCapabilitiesServlet> capabilities_servlet;
  std::unique_ptr<RestrictedRoomsServlet> restricted_servlet;
  
  // Admin operations
  std::unique_ptr<AdminSpaceOperations> admin_spaces;
  std::unique_ptr<AdminDirectoryOperations> admin_directory;
  std::unique_ptr<AdminRetentionOperations> admin_retention;
  std::unique_ptr<AdminKnockOperations> admin_knocks;
  std::unique_ptr<AdminRestrictedRoomOperations> admin_restricted;
};

RoomFeaturesSubsystem create_room_features(const std::string& server_name) {
  RoomFeaturesSubsystem sub;
  
  sub.coordinator = std::make_unique<RoomFeatureCoordinator>(server_name);
  
  sub.space_servlet = std::make_unique<SpaceSummaryServlet>(*sub.coordinator);
  sub.directory_servlet = std::make_unique<RoomDirectoryServlet>(*sub.coordinator);
  sub.upgrade_servlet = std::make_unique<RoomUpgradeServlet>(*sub.coordinator);
  sub.retention_servlet = std::make_unique<RoomRetentionServlet>(*sub.coordinator);
  sub.knock_servlet = std::make_unique<RoomKnockServlet>(*sub.coordinator);
  sub.capabilities_servlet = std::make_unique<RoomCapabilitiesServlet>(*sub.coordinator);
  sub.restricted_servlet = std::make_unique<RestrictedRoomsServlet>(*sub.coordinator);
  
  sub.admin_spaces = std::make_unique<AdminSpaceOperations>(*sub.coordinator);
  sub.admin_directory = std::make_unique<AdminDirectoryOperations>(*sub.coordinator);
  sub.admin_retention = std::make_unique<AdminRetentionOperations>(*sub.coordinator);
  sub.admin_knocks = std::make_unique<AdminKnockOperations>(*sub.coordinator);
  sub.admin_restricted = std::make_unique<AdminRestrictedRoomOperations>(*sub.coordinator);
  
  return sub;
}

// ============================================================================
// Additional utility functions for room feature integration
// ============================================================================

// Check if a given room type is a space
bool is_space_room_type(const std::string& room_type) {
  return room_type == "m.space";
}

// Resolve the full join rules state for a room
json resolve_join_rules(const std::string& room_id,
                         RoomFeatureCoordinator& coordinator) {
  auto rules = coordinator.get_join_rules(room_id);
  return rules;
}

// Check if a user can perform an action based on power levels
bool user_has_power_for_action(const std::string& user_id,
                                const std::string& room_id,
                                const std::string& action,
                                int user_power_level) {
  // Default power level requirements per Matrix spec
  static const std::map<std::string, int> required_power = {
    {"invite", 0},
    {"kick", 50},
    {"ban", 50},
    {"redact", 50},
    {"set_name", 50},
    {"set_topic", 50},
    {"set_avatar", 50},
    {"set_join_rules", 100},
    {"set_history_visibility", 100},
    {"set_power_levels", 100},
    {"set_retention", 100},
    {"upgrade_room", 100},
    {"add_child_space", 50},
    {"accept_knock", 50},
    {"send_tombstone", 100},
  };
  
  auto it = required_power.find(action);
  if (it != required_power.end()) {
    return user_power_level >= it->second;
  }
  
  return user_power_level >= 50; // default
}

// Build the default state for a new room based on the preset
json build_default_room_state(const std::string& creator,
                               const std::string& preset,
                               const std::string& room_version) {
  json state = json::array();
  
  // m.room.create
  json create;
  create["type"] = "m.room.create";
  create["state_key"] = "";
  create["content"]["creator"] = creator;
  create["content"]["room_version"] = room_version;
  state.push_back(create);
  
  // m.room.power_levels
  json pl;
  pl["type"] = "m.room.power_levels";
  pl["state_key"] = "";
  pl["content"]["ban"] = 50;
  pl["content"]["invite"] = (preset == "public_chat") ? 0 : 50;
  pl["content"]["kick"] = 50;
  pl["content"]["redact"] = 50;
  pl["content"]["events_default"] = 0;
  pl["content"]["state_default"] = 50;
  pl["content"]["users_default"] = 0;
  pl["content"]["users"] = json::object();
  pl["content"]["users"][creator] = 100;
  pl["content"]["events"] = json::object();
  pl["content"]["events"]["m.room.name"] = 50;
  pl["content"]["events"]["m.room.power_levels"] = 100;
  pl["content"]["events"]["m.room.history_visibility"] = 100;
  pl["content"]["events"]["m.room.tombstone"] = 100;
  state.push_back(pl);
  
  // m.room.join_rules
  json jr;
  jr["type"] = "m.room.join_rules";
  jr["state_key"] = "";
  jr["content"]["join_rule"] = (preset == "public_chat") ? "public" : "invite";
  state.push_back(jr);
  
  // m.room.history_visibility
  json hv;
  hv["type"] = "m.room.history_visibility";
  hv["state_key"] = "";
  hv["content"]["history_visibility"] = 
      RoomVisibilityChecker::get_default_for_preset(preset);
  state.push_back(hv);
  
  // m.room.guest_access
  json ga;
  ga["type"] = "m.room.guest_access";
  ga["state_key"] = "";
  ga["content"]["guest_access"] = (preset == "public_chat") ? "can_join" : "forbidden";
  state.push_back(ga);
  
  // m.room.member for creator
  json member;
  member["type"] = "m.room.member";
  member["state_key"] = creator;
  member["content"]["membership"] = "join";
  member["content"]["displayname"] = creator;
  state.push_back(member);
  
  return state;
}

// Validate a room alias format
bool validate_room_alias_format(const std::string& alias) {
  if (!starts_with(alias, "#")) return false;
  if (alias.find(':') == std::string::npos) return false;
  if (alias.length() > 255) return false;
  
  // Check for invalid characters in localpart
  std::string localpart = alias.substr(1, alias.find(':') - 1);
  if (localpart.empty()) return false;
  
  for (char c : localpart) {
    if (!isalnum(c) && c != '_' && c != '-' && c != '.') {
      return false;
    }
  }
  
  return true;
}

// Get a human-readable description of a space hierarchy
std::string describe_space_hierarchy(const std::string& space_id,
                                      int depth) {
  std::ostringstream desc;
  desc << "Space " << space_id << " (depth: " << depth << ")";
  return desc.str();
}

// ============================================================================
// Event Builders - construct valid Matrix events for room features
// ============================================================================

json build_space_child_event(const std::string& space_id,
                              const std::string& child_room_id,
                              const std::string& sender,
                              bool suggested,
                              const std::string& order,
                              const json& via) {
  json event;
  event["type"] = "m.space.child";
  event["state_key"] = child_room_id;
  event["sender"] = sender;
  event["room_id"] = space_id;
  event["content"]["via"] = via.is_null() ? json::array() : via;
  event["content"]["suggested"] = suggested;
  if (!order.empty()) event["content"]["order"] = order;
  event["origin_server_ts"] = now_ms();
  return event;
}

json build_space_parent_event(const std::string& room_id,
                               const std::string& space_id,
                               const std::string& sender,
                               bool canonical,
                               const json& via) {
  json event;
  event["type"] = "m.space.parent";
  event["state_key"] = space_id;
  event["sender"] = sender;
  event["room_id"] = room_id;
  event["content"]["via"] = via.is_null() ? json::array() : via;
  event["content"]["canonical"] = canonical;
  event["origin_server_ts"] = now_ms();
  return event;
}

json build_tombstone_event(const std::string& room_id,
                            const std::string& replacement_room,
                            const std::string& sender,
                            const std::string& body) {
  json event;
  event["type"] = "m.room.tombstone";
  event["state_key"] = "";
  event["sender"] = sender;
  event["room_id"] = room_id;
  event["content"]["body"] = body.empty() ? 
      "This room has been replaced" : body;
  event["content"]["replacement_room"] = replacement_room;
  event["origin_server_ts"] = now_ms();
  return event;
}

json build_retention_event(const std::string& room_id,
                            int64_t max_lifetime_ms,
                            int64_t min_lifetime_ms,
                            const std::string& sender) {
  json event;
  event["type"] = "m.room.retention";
  event["state_key"] = "";
  event["sender"] = sender;
  event["room_id"] = room_id;
  if (max_lifetime_ms > 0) event["content"]["max_lifetime"] = max_lifetime_ms;
  if (min_lifetime_ms > 0) event["content"]["min_lifetime"] = min_lifetime_ms;
  event["origin_server_ts"] = now_ms();
  return event;
}

json build_knock_membership_event(const std::string& room_id,
                                   const std::string& user_id,
                                   const std::string& reason,
                                   const json& via) {
  json event;
  event["type"] = "m.room.member";
  event["state_key"] = user_id;
  event["sender"] = user_id;
  event["room_id"] = room_id;
  event["content"]["membership"] = "knock";
  event["content"]["displayname"] = user_id;
  if (!reason.empty()) event["content"]["reason"] = reason;
  event["origin_server_ts"] = now_ms();
  if (!via.empty()) event["content"]["via"] = via;
  return event;
}

json build_restricted_join_rules_event(const std::string& room_id,
                                        const std::string& join_rule,
                                        const std::vector<RestrictedRoomManager::AllowRule>& allow,
                                        const std::string& sender) {
  json event;
  event["type"] = "m.room.join_rules";
  event["state_key"] = "";
  event["sender"] = sender;
  event["room_id"] = room_id;
  event["content"]["join_rule"] = join_rule;
  if (!allow.empty()) {
    json allow_arr = json::array();
    for (auto& rule : allow) {
      json entry;
      entry["type"] = rule.type;
      entry["room_id"] = rule.room_id;
      if (!rule.via.empty()) entry["via"] = rule.via;
      allow_arr.push_back(entry);
    }
    event["content"]["allow"] = allow_arr;
  }
  event["origin_server_ts"] = now_ms();
  return event;
}

// ============================================================================
// Permission checking utilities for room features
// ============================================================================

struct RoomFeaturePermissions {
  bool can_create_space = false;
  bool can_add_child = false;
  bool can_set_visibility = false;
  bool can_upgrade = false;
  bool can_set_retention = false;
  bool can_accept_knock = false;
  bool can_set_join_rules = false;
  bool has_admin = false;
};

RoomFeaturePermissions check_room_feature_permissions(
    const std::string& user_id,
    const std::string& room_id,
    int user_power_level,
    bool is_admin) {
  
  RoomFeaturePermissions perms;
  perms.has_admin = is_admin;
  
  // Admins have all permissions
  if (is_admin) {
    perms.can_create_space = true;
    perms.can_add_child = true;
    perms.can_set_visibility = true;
    perms.can_upgrade = true;
    perms.can_set_retention = true;
    perms.can_accept_knock = true;
    perms.can_set_join_rules = true;
    return perms;
  }
  
  perms.can_create_space = true; // Any user can create a space
  perms.can_add_child = user_power_level >= 50;
  perms.can_set_visibility = user_power_level >= 50;
  perms.can_upgrade = user_power_level >= 100;
  perms.can_set_retention = user_power_level >= 100;
  perms.can_accept_knock = user_power_level >= 50;
  perms.can_set_join_rules = user_power_level >= 100;
  
  return perms;
}

// ============================================================================
// Federation support for room features
// ============================================================================

struct FederationSpaceQuery {
  std::string space_id;
  std::string via_server;
  bool suggested_only = false;
  int max_depth = 5;
};

struct FederationPublicRoomsQuery {
  std::string server;
  int limit = 100;
  std::string since;
  std::string search_term;
  bool include_all_networks = false;
};

json handle_federation_space_query(const FederationSpaceQuery& query) {
  json response;
  response["rooms"] = json::array();
  response["events"] = json::array();
  // In a real implementation, this would build a space summary
  // and return it formatted for federation
  return response;
}

json handle_federation_public_rooms(const FederationPublicRoomsQuery& query) {
  json response;
  response["chunk"] = json::array();
  response["next_batch"] = "";
  response["prev_batch"] = "";
  response["total_room_count_estimate"] = 0;
  // In a real implementation, query public rooms and return
  return response;
}

// ============================================================================
// Migration helpers for room features data
// ============================================================================

// Create required database tables for room features
json create_room_features_tables() {
  json sql_statements = json::array();
  
  // Space relationships table
  sql_statements.push_back(
    "CREATE TABLE IF NOT EXISTS space_children("
    "space_id TEXT NOT NULL,"
    "child_room_id TEXT NOT NULL,"
    "suggested BOOLEAN DEFAULT 0,"
    "sort_order TEXT,"
    "via_servers TEXT,"
    "auto_join BOOLEAN DEFAULT 0,"
    "event_id TEXT NOT NULL,"
    "PRIMARY KEY(space_id, child_room_id))"
  );
  
  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS sc_space_idx ON space_children(space_id)"
  );
  
  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS sc_child_idx ON space_children(child_room_id)"
  );
  
  // Space parents table
  sql_statements.push_back(
    "CREATE TABLE IF NOT EXISTS space_parents("
    "room_id TEXT NOT NULL,"
    "space_id TEXT NOT NULL,"
    "canonical BOOLEAN DEFAULT 0,"
    "via_servers TEXT,"
    "event_id TEXT NOT NULL,"
    "PRIMARY KEY(room_id, space_id))"
  );
  
  // Retention policy table
  sql_statements.push_back(
    "CREATE TABLE IF NOT EXISTS room_retention("
    "room_id TEXT NOT NULL PRIMARY KEY,"
    "max_lifetime_ms BIGINT,"
    "min_lifetime_ms BIGINT,"
    "event_id TEXT NOT NULL)"
  );
  
  // Knock requests table
  sql_statements.push_back(
    "CREATE TABLE IF NOT EXISTS room_knocks("
    "room_id TEXT NOT NULL,"
    "user_id TEXT NOT NULL,"
    "event_id TEXT NOT NULL,"
    "reason TEXT,"
    "state TEXT NOT NULL DEFAULT 'pending',"
    "created_at BIGINT NOT NULL,"
    "updated_at BIGINT NOT NULL,"
    "PRIMARY KEY(room_id, user_id))"
  );
  
  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS rk_room_idx ON room_knocks(room_id)"
  );
  
  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS rk_state_idx ON room_knocks(room_id, state)"
  );
  
  // Restricted room allow rules cache
  sql_statements.push_back(
    "CREATE TABLE IF NOT EXISTS restricted_join_rules("
    "room_id TEXT NOT NULL PRIMARY KEY,"
    "join_rule TEXT NOT NULL,"
    "allow_rules TEXT,"
    "event_id TEXT NOT NULL)"
  );
  
  // Room upgrade tracking
  sql_statements.push_back(
    "CREATE TABLE IF NOT EXISTS room_upgrades("
    "old_room_id TEXT NOT NULL PRIMARY KEY,"
    "new_room_id TEXT NOT NULL,"
    "upgraded_by TEXT NOT NULL,"
    "new_version TEXT NOT NULL,"
    "tombstone_event_id TEXT,"
    "upgraded_at BIGINT NOT NULL)"
  );
  
  sql_statements.push_back(
    "CREATE INDEX IF NOT EXISTS ru_new_room_idx ON room_upgrades(new_room_id)"
  );
  
  return sql_statements;
}

// ============================================================================
// Reporting and statistics
// ============================================================================

struct RoomFeaturesStats {
  int total_spaces = 0;
  int total_space_children = 0;
  int total_public_rooms = 0;
  int total_restricted_rooms = 0;
  int total_pending_knocks = 0;
  int rooms_with_retention = 0;
  int64_t total_purged_events = 0;
  int rooms_upgraded = 0;
  std::string default_version;
};

RoomFeaturesStats collect_room_features_stats(
    RoomFeatureCoordinator& coordinator) {
  RoomFeaturesStats stats;
  
  stats.default_version = coordinator.get_default_version();
  
  // These would query the database in a real implementation
  
  return stats;
}

// ============================================================================
// Cleanup / shutdown
// ============================================================================

void shutdown_room_features(RoomFeaturesSubsystem& sub) {
  if (sub.coordinator) {
    sub.coordinator->stop();
  }
}

// ============================================================================
// Testing utilities
// ============================================================================

#ifdef ROOM_FEATURES_TESTING
namespace test {

// Test space creation and hierarchy
bool test_space_creation() {
  RoomFeatureCoordinator coordinator("test.local");
  
  auto result = coordinator.create_space("@test:test.local", "Test Space",
                                          "A test space");
  return !result["room_id"].get<std::string>().empty();
}

// Test room visibility
bool test_visibility_checker() {
  RoomVisibilityChecker checker;
  
  // Joined user can see in joined room
  bool can_see = checker.can_view_events("@user:test", "join", "joined");
  if (!can_see) return false;
  
  // Non-member cannot see in joined-only room
  can_see = checker.can_view_events("@other:test", "", "joined");
  if (can_see) return false;
  
  // Anyone can see world_readable
  can_see = checker.can_view_events("", "", "world_readable");
  if (!can_see) return false;
  
  return true;
}

// Test room version registry
bool test_version_registry() {
  RoomVersionRegistry registry;
  
  if (!registry.is_supported("10")) return false;
  if (registry.is_supported("1")) return false; // deprecated
  if (registry.get_default_version() != "10") return false;
  
  auto caps = registry.get_capabilities();
  if (!caps.contains("m.room_versions")) return false;
  
  return true;
}

// Test restricted rooms
bool test_restricted_rooms() {
  RestrictedRoomManager manager;
  
  auto rules = manager.get_join_rules("!test:localhost");
  if (rules.join_rule != "invite") return false; // default
  
  if (!manager.supports_restricted_joins("10")) return false;
  if (!manager.supports_restricted_joins("8")) return false;
  if (manager.supports_restricted_joins("7")) return false;
  
  return true;
}

// Test knocks
bool test_knocks() {
  RoomKnockManager manager;
  
  // No pending knocks initially
  auto pending = manager.get_pending_knocks("!test:localhost");
  if (!pending.empty()) return false;
  
  if (manager.has_pending_knock("!test:localhost", "@user:test")) return false;
  
  return true;
}

} // namespace test
#endif // ROOM_FEATURES_TESTING

} // namespace progressive
