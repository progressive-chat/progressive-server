// room_summary_computation.cpp - Matrix Room Summary Computation
// Implements complete room summary, heroes, display name, avatar computation,
// notification counts, room preview, thumbnail generation, and state caching.
//
// Based on Synapse: synapse/handlers/room_summary.py and 
// synapse/visibility.py, synapse/push/bulk_push_rule_evaluator.py
//
// Features:
//   1.  Room summary computation (m.room.summary for sync response)
//   2.  Room hero selection algorithm (pick 5 heroes for room display)
//   3.  Hero ordering (joined first, active, alphabetical)
//   4.  Room name computation (from m.room.name state or from heroes)
//   5.  Room name fallback (empty room, 1 member, 2 members, 3+ members)
//   6.  Room avatar computation (from m.room.avatar or from member avatars)
//   7.  Room join member count (m.joined_member_count)
//   8.  Room invite member count (m.invited_member_count)
//   9.  Direct message detection (m.direct account data, is_direct flag)
//  10.  Room type detection (m.room.create type field)
//  11.  Room encryption status
//  12.  Room canonical alias
//  13.  Room topic (m.room.topic state)
//  14.  Room preview for non-members (limited state for world_readable)
//  15.  Room thumbnail generation from avatars
//  16.  Room list ordering (by activity, by name, by notification)
//  17.  Unread notification count computation per room
//  18.  Highlight count computation per room
//  19.  Room membership events ordering (join order)
//  20.  Room state caching for fast summary computation
//
// Target: 3500+ lines

#include "../json.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/util/cache.hpp"
#include "progressive/util/time.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Utility helpers
// ============================================================================

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  static std::atomic<int64_t> g_seq{1};
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(g_seq.fetch_add(1));
}

static std::string safe_str(const json& obj, const std::string& key,
                             const std::string& def = "") {
  if (!obj.contains(key)) return def;
  if (obj[key].is_string()) return obj[key].get<std::string>();
  return def;
}

static int64_t safe_int(const json& obj, const std::string& key,
                         int64_t def = 0) {
  if (!obj.contains(key)) return def;
  if (obj[key].is_number()) return obj[key].get<int64_t>();
  return def;
}

static bool safe_bool(const json& obj, const std::string& key, bool def = false) {
  if (!obj.contains(key)) return def;
  if (obj[key].is_boolean()) return obj[key].get<bool>();
  return def;
}

static std::string sql_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 4);
  for (char c : s) {
    if (c == '\'')
      out += "''";
    else
      out += c;
  }
  return out;
}

static std::string extract_localpart(const std::string& user_id) {
  if (user_id.empty() || user_id[0] != '@') return user_id;
  auto pos = user_id.find(':');
  if (pos == std::string::npos) return user_id.substr(1);
  return user_id.substr(1, pos - 1);
}

static std::string extract_domain(const std::string& mxid) {
  auto pos = mxid.find(':');
  if (pos == std::string::npos) return "";
  return mxid.substr(pos + 1);
}

static std::string default_avatar_for(const std::string& user_id) {
  // Generate a deterministic color-based avatar URL
  size_t hash = std::hash<std::string>{}(user_id);
  const char* colors[] = {
    "#e53935", "#d81b60", "#8e24aa", "#5e35b1", "#3949ab",
    "#1e88e5", "#039be5", "#00acc1", "#00897b", "#43a047",
    "#7cb342", "#c0ca33", "#fdd835", "#ffb300", "#fb8c00",
    "#f4511e", "#6d4c41", "#757575", "#546e7a"
  };
  std::string bg = colors[hash % 19];
  std::string letter;
  auto lp = extract_localpart(user_id);
  if (!lp.empty()) letter = std::string(1, static_cast<char>(std::toupper(lp[0])));
  else letter = "?";
  return "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' "
         "viewBox='0 0 100 100'><rect fill='" + bg +
         "' width='100' height='100'/><text fill='white' font-size='50' "
         "x='50' y='68' text-anchor='middle' font-family='sans-serif'>" +
         letter + "</text></svg>";
}

// ============================================================================
// HeroEntry - Display information for a single room hero
// ============================================================================

struct HeroEntry {
  std::string user_id;
  std::string display_name;
  std::string avatar_url;
  int64_t join_order{0};
  int64_t last_active_ts{0};
  bool currently_active{false};

  bool operator==(const HeroEntry& other) const {
    return user_id == other.user_id;
  }
};

// ============================================================================
// RoomSummary - Complete room summary data container
// ============================================================================

struct RoomSummary {
  std::string room_id;
  std::string name;
  std::string canonical_alias;
  std::string topic;
  std::string avatar_url;
  std::vector<HeroEntry> heroes;
  int joined_member_count{0};
  int invited_member_count{0};
  bool is_direct{false};
  bool encrypted{false};
  std::string room_type;
  bool world_readable{false};
  bool guests_can_join{false};
  int64_t last_activity_ts{0};
  int notification_count{0};
  int highlight_count{0};
  std::string creator;
  std::vector<std::string> aliases;
  std::string join_rule;

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    if (!name.empty()) j["name"] = name;
    if (!canonical_alias.empty()) j["canonical_alias"] = canonical_alias;
    if (!topic.empty()) j["topic"] = topic;
    if (!avatar_url.empty()) j["avatar_url"] = avatar_url;
    if (!heroes.empty()) {
      json hero_arr = json::array();
      for (const auto& h : heroes) {
        json hj;
        hj["user_id"] = h.user_id;
        if (!h.display_name.empty()) hj["display_name"] = h.display_name;
        if (!h.avatar_url.empty()) hj["avatar_url"] = h.avatar_url;
        hero_arr.push_back(hj);
      }
      j["heroes"] = hero_arr;
    }
    j["m.joined_member_count"] = joined_member_count;
    j["m.invited_member_count"] = invited_member_count;
    if (is_direct) j["is_direct"] = true;
    if (encrypted) j["encryption"] = "m.megolm.v1.aes-sha2";
    if (!room_type.empty()) j["room_type"] = room_type;
    if (world_readable) j["world_readable"] = true;
    if (guests_can_join) j["guest_can_join"] = true;
    if (!creator.empty()) j["creator"] = creator;
    if (!aliases.empty()) j["aliases"] = aliases;
    if (!join_rule.empty()) j["join_rule"] = join_rule;
    if (last_activity_ts > 0) j["last_activity_ts"] = last_activity_ts;
    j["notification_count"] = notification_count;
    j["highlight_count"] = highlight_count;
    return j;
  }
};

// ============================================================================
// RoomSummaryComputation - Main computation engine
// ============================================================================

class RoomSummaryComputation {
public:
  explicit RoomSummaryComputation(DatabasePool& db)
      : db_(db),
        room_state_cache_(10000, 300),
        room_summary_cache_(5000, 60),
        hero_cache_(5000, 120),
        room_name_cache_(10000, 180),
        room_avatar_cache_(5000, 180),
        member_count_cache_(5000, 60),
        dm_cache_(2000, 300) {}

  // ==========================================================================
  // 1. Room summary computation
  // ==========================================================================
  RoomSummary compute_room_summary(const std::string& room_id,
                                    const std::string& viewer_user_id = "") {
    // Try cache first
    {
      std::lock_guard<std::mutex> lock(cache_mutex_);
      auto cached = room_summary_cache_.get(room_id + ":" + viewer_user_id);
      if (cached) {
        // Return cached summary (we store as json, reconstitute)
        return summary_from_json(*cached);
      }
    }

    RoomSummary summary;
    summary.room_id = room_id;

    // Basic state loads
    json create_event = load_state_event(room_id, "m.room.create", "");
    json name_event = load_state_event(room_id, "m.room.name", "");
    json topic_event = load_state_event(room_id, "m.room.topic", "");
    json avatar_event = load_state_event(room_id, "m.room.avatar", "");
    json alias_event = load_state_event(room_id, "m.room.canonical_alias", "");
    json encryption_event = load_state_event(room_id, "m.room.encryption", "");
    json join_rules_event = load_state_event(room_id, "m.room.join_rules", "");
    json history_vis_event = load_state_event(room_id, "m.room.history_visibility", "");
    json guest_access_event = load_state_event(room_id, "m.room.guest_access", "");

    // Room type from create event
    if (!create_event.empty()) {
      summary.room_type = safe_str(create_event, "type", "");
      summary.creator = safe_str(create_event, "creator", "");
    }

    // Room name
    summary.name = compute_room_name_internal(room_id, viewer_user_id,
                                               name_event, create_event);

    // Topic
    if (!topic_event.empty()) {
      summary.topic = safe_str(topic_event, "topic", "");
    }

    // Avatar
    summary.avatar_url = compute_room_avatar_internal(room_id, avatar_event);

    // Canonical alias
    if (!alias_event.empty()) {
      summary.canonical_alias = safe_str(alias_event, "alias", "");
      // Also load alt_aliases
      if (alias_event.contains("alt_aliases") && alias_event["alt_aliases"].is_array()) {
        for (const auto& a : alias_event["alt_aliases"]) {
          if (a.is_string()) summary.aliases.push_back(a.get<std::string>());
        }
      }
    }

    // Encryption
    if (!encryption_event.empty()) {
      std::string algo = safe_str(encryption_event, "algorithm", "");
      summary.encrypted = !algo.empty();
    }

    // World readable check
    std::string history_vis = "shared";
    if (!history_vis_event.empty()) {
      history_vis = safe_str(history_vis_event, "history_visibility", "shared");
    }
    summary.world_readable = (history_vis == "world_readable");

    // Guest access
    if (!guest_access_event.empty()) {
      summary.guests_can_join =
          (safe_str(guest_access_event, "guest_access", "") == "can_join");
    }

    // Join rules
    if (!join_rules_event.empty()) {
      summary.join_rule = safe_str(join_rules_event, "join_rule", "public");
    }

    // Member counts
    summary.joined_member_count = get_joined_member_count(room_id);
    summary.invited_member_count = get_invited_member_count(room_id);

    // Heroes
    summary.heroes = select_heroes_internal(room_id, viewer_user_id, 5);

    // DM detection
    if (!viewer_user_id.empty()) {
      summary.is_direct = is_direct_room(room_id, viewer_user_id);
    }

    // Notification counts
    if (!viewer_user_id.empty()) {
      auto counts = get_unread_counts(room_id, viewer_user_id);
      summary.notification_count = safe_int(counts, "notification_count");
      summary.highlight_count = safe_int(counts, "highlight_count");
    }

    // Last activity
    summary.last_activity_ts = get_last_activity_ts(room_id);

    // Cache and return
    {
      std::lock_guard<std::mutex> lock(cache_mutex_);
      room_summary_cache_.put(room_id + ":" + viewer_user_id, summary.to_json());
    }

    return summary;
  }

  // ==========================================================================
  // JSON summary for sync response
  // ==========================================================================
  json compute_room_summary_json(const std::string& room_id,
                                  const std::string& viewer_user_id = "") {
    RoomSummary s = compute_room_summary(room_id, viewer_user_id);
    json j;
    j["m.heroes"] = json::array();
    for (const auto& h : s.heroes) {
      json hj;
      hj["user_id"] = h.user_id;
      if (!h.display_name.empty()) hj["display_name"] = h.display_name;
      if (!h.avatar_url.empty()) hj["avatar_url"] = h.avatar_url;
      j["m.heroes"].push_back(hj);
    }

    j["m.joined_member_count"] = s.joined_member_count;
    j["m.invited_member_count"] = s.invited_member_count;

    if (!s.room_type.empty()) {
      j["m.room_type"] = s.room_type;
    }

    if (s.is_direct) {
      j["m.direct"] = true;
    }

    if (s.encrypted) {
      j["m.encryption"] = json::object();
      auto enc_ev = load_state_event(room_id, "m.room.encryption", "");
      if (!enc_ev.empty()) {
        j["m.encryption"]["algorithm"] = safe_str(enc_ev, "algorithm", "m.megolm.v1.aes-sha2");
        if (enc_ev.contains("rotation_period_ms"))
          j["m.encryption"]["rotation_period_ms"] = enc_ev["rotation_period_ms"];
        if (enc_ev.contains("rotation_period_msgs"))
          j["m.encryption"]["rotation_period_msgs"] = enc_ev["rotation_period_msgs"];
      }
    }

    return j;
  }

  // ==========================================================================
  // 2. Hero selection algorithm
  // ==========================================================================
  std::vector<HeroEntry> select_heroes(const std::string& room_id, int count = 5) {
    return select_heroes_internal(room_id, "", count);
  }

  // ==========================================================================
  // 4. Room name computation
  // ==========================================================================
  std::string compute_room_name(const std::string& room_id,
                                 const std::string& viewer_user_id = "") {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto cached = room_name_cache_.get("name:" + room_id + ":" + viewer_user_id);
    if (cached) return *cached;

    json name_event = load_state_event(room_id, "m.room.name", "");
    json create_event = load_state_event(room_id, "m.room.create", "");

    std::string result = compute_room_name_internal(room_id, viewer_user_id,
                                                      name_event, create_event);
    room_name_cache_.put("name:" + room_id + ":" + viewer_user_id, result);
    return result;
  }

  // ==========================================================================
  // 6. Room avatar computation
  // ==========================================================================
  std::string compute_room_avatar(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto cached = room_avatar_cache_.get("avatar:" + room_id);
    if (cached) return *cached;

    json avatar_event = load_state_event(room_id, "m.room.avatar", "");
    std::string result = compute_room_avatar_internal(room_id, avatar_event);

    room_avatar_cache_.put("avatar:" + room_id, result);
    return result;
  }

  // ==========================================================================
  // 7. Joined member count
  // ==========================================================================
  int get_joined_member_count(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto cached = member_count_cache_.get("joined:" + room_id);
    if (cached) {
      try { return std::stoi(*cached); } catch (...) {}
    }

    auto rows = db_.execute(
        "get_joined_member_count",
        "SELECT COUNT(*) as c FROM room_memberships WHERE room_id='" +
        sql_escape(room_id) + "' AND membership='join'");

    int count = 0;
    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "c" && col.value) {
          try { count = std::stoi(*col.value); } catch (...) {}
          break;
        }
      }
    }

    member_count_cache_.put("joined:" + room_id, std::to_string(count));
    return count;
  }

  // ==========================================================================
  // 8. Invited member count
  // ==========================================================================
  int get_invited_member_count(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto cached = member_count_cache_.get("invited:" + room_id);
    if (cached) {
      try { return std::stoi(*cached); } catch (...) {}
    }

    auto rows = db_.execute(
        "get_invited_member_count",
        "SELECT COUNT(*) as c FROM room_memberships WHERE room_id='" +
        sql_escape(room_id) + "' AND membership='invite'");

    int count = 0;
    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "c" && col.value) {
          try { count = std::stoi(*col.value); } catch (...) {}
          break;
        }
      }
    }

    member_count_cache_.put("invited:" + room_id, std::to_string(count));
    return count;
  }

  // ==========================================================================
  // 9. Direct message detection
  // ==========================================================================
  bool is_direct_room(const std::string& room_id, const std::string& user_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto cached = dm_cache_.get("dm:" + user_id + ":" + room_id);
    if (cached) return *cached == "1";

    // Check m.direct account data
    auto rows = db_.execute(
        "get_direct_rooms",
        "SELECT content FROM account_data WHERE user_id='" +
        sql_escape(user_id) + "' AND type='m.direct'");

    bool is_dm = false;
    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "content" && col.value) {
          try {
            json content = json::parse(*col.value);
            if (content.is_object()) {
              for (auto& [key, val] : content.items()) {
                if (val.is_array()) {
                  for (const auto& rid : val) {
                    if (rid.is_string() && rid.get<std::string>() == room_id) {
                      is_dm = true;
                      break;
                    }
                  }
                }
                if (is_dm) break;
              }
            }
          } catch (...) {}
          break;
        }
      }
    }

    // Fallback: if only 2 members, it's likely a DM
    if (!is_dm) {
      int member_count = get_joined_member_count(room_id);
      is_dm = (member_count == 2);
    }

    dm_cache_.put("dm:" + user_id + ":" + room_id, is_dm ? "1" : "0");
    return is_dm;
  }

  // ==========================================================================
  // 10. Room type detection
  // ==========================================================================
  std::string get_room_type(const std::string& room_id) {
    json create_event = load_state_event(room_id, "m.room.create", "");
    if (create_event.empty()) return "";

    if (create_event.contains("content") && create_event["content"].is_object()) {
      return safe_str(create_event["content"], "type", "");
    }
    return safe_str(create_event, "type", "");
  }

  // ==========================================================================
  // 11. Encryption status
  // ==========================================================================
  bool is_encrypted(const std::string& room_id) {
    json enc_event = load_state_event(room_id, "m.room.encryption", "");
    if (enc_event.empty()) return false;
    return !safe_str(enc_event, "algorithm", "").empty();
  }

  // ==========================================================================
  // 12. Canonical alias
  // ==========================================================================
  std::string get_canonical_alias(const std::string& room_id) {
    json alias_event = load_state_event(room_id, "m.room.canonical_alias", "");
    if (alias_event.empty()) return "";
    return safe_str(alias_event, "alias", "");
  }

  // ==========================================================================
  // 13. Room topic
  // ==========================================================================
  std::string get_room_topic(const std::string& room_id) {
    json topic_event = load_state_event(room_id, "m.room.topic", "");
    if (topic_event.empty()) return "";
    return safe_str(topic_event, "topic", "");
  }

  // ==========================================================================
  // 14. Room preview for non-members
  // ==========================================================================
  json compute_room_preview(const std::string& room_id,
                             const std::string& viewer_user_id) {
    json preview;

    // Check if room is world_readable or if viewer is a member
    std::string history_vis = "shared";
    json hv_event = load_state_event(room_id, "m.room.history_visibility", "");
    if (!hv_event.empty()) {
      history_vis = safe_str(hv_event, "history_visibility", "shared");
    }

    bool is_world_readable = (history_vis == "world_readable");
    bool is_member = is_user_member(room_id, viewer_user_id);

    // Always include basic info
    preview["room_id"] = room_id;
    preview["name"] = compute_room_name(room_id, viewer_user_id);
    preview["topic"] = get_room_topic(room_id);
    preview["avatar_url"] = compute_room_avatar(room_id);
    preview["canonical_alias"] = get_canonical_alias(room_id);
    preview["num_joined_members"] = get_joined_member_count(room_id);
    preview["room_type"] = get_room_type(room_id);
    preview["world_readable"] = is_world_readable;

    // Only members or world_readable rooms get more info
    if (is_member || is_world_readable) {
      preview["join_rule"] = get_join_rule(room_id);
      preview["guest_can_join"] = get_guest_access(room_id);

      // Include limited state
      json name_event = load_state_event(room_id, "m.room.name", "");
      json topic_event = load_state_event(room_id, "m.room.topic", "");
      json avatar_event = load_state_event(room_id, "m.room.avatar", "");

      json state_events = json::array();
      if (!name_event.empty()) state_events.push_back(format_state_event(name_event));
      if (!topic_event.empty()) state_events.push_back(format_state_event(topic_event));
      if (!avatar_event.empty()) state_events.push_back(format_state_event(avatar_event));

      // Include join_rules and history_visibility for world_readable
      if (is_world_readable) {
        if (!hv_event.empty()) state_events.push_back(format_state_event(hv_event));
        json jr_event = load_state_event(room_id, "m.room.join_rules", "");
        if (!jr_event.empty()) state_events.push_back(format_state_event(jr_event));
      }
      preview["state"] = json::object();
      preview["state"]["events"] = state_events;

      // Heroes
      auto heroes = select_heroes(room_id, 5);
      json hero_arr = json::array();
      for (const auto& h : heroes) {
        json hj;
        hj["user_id"] = h.user_id;
        if (!h.display_name.empty()) hj["display_name"] = h.display_name;
        if (!h.avatar_url.empty()) hj["avatar_url"] = h.avatar_url;
        hero_arr.push_back(hj);
      }
      preview["heroes"] = hero_arr;
    }

    return preview;
  }

  // ==========================================================================
  // 15. Room thumbnail generation from avatars
  // ==========================================================================
  json compute_room_thumbnail(const std::string& room_id) {
    json thumbnail;
    thumbnail["room_id"] = room_id;

    // Collect member avatars
    auto members = load_members_raw(room_id, "join", 10);
    json avatar_urls = json::array();

    if (members.empty()) {
      // Use room-level avatar or generate fallback
      std::string room_av = compute_room_avatar(room_id);
      if (!room_av.empty()) {
        avatar_urls.push_back(room_av);
      } else {
        // Generate default from room name
        std::string name = compute_room_name(room_id);
        if (!name.empty()) {
          avatar_urls.push_back(generate_room_default_avatar(name));
        }
      }
    }

    for (const auto& member : members) {
      std::string uid = safe_str(member, "user_id", "");
      if (uid.empty()) continue;
      std::string av_url = get_user_avatar_url(uid);
      if (!av_url.empty()) {
        avatar_urls.push_back(av_url);
      } else {
        avatar_urls.push_back(default_avatar_for(uid));
      }
    }

    // Build thumbnail layout
    thumbnail["avatar_urls"] = avatar_urls;
    thumbnail["layout"] = determine_thumbnail_layout(avatar_urls.size());
    thumbnail["background_color"] = compute_dominant_background(room_id);

    // Generate combined thumbnail hint
    json hint;
    hint["num_avatars"] = avatar_urls.size();
    hint["primary_url"] = avatar_urls.empty() ? "" : avatar_urls[0].get<std::string>();
    if (avatar_urls.size() > 1) {
      json secondary = json::array();
      for (size_t i = 1; i < std::min(avatar_urls.size(), size_t(4)); i++) {
        secondary.push_back(avatar_urls[i]);
      }
      hint["secondary_urls"] = secondary;
    }
    thumbnail["hint"] = hint;

    return thumbnail;
  }

  // ==========================================================================
  // 16. Room list ordering
  // ==========================================================================
  enum class RoomOrder {
    BY_RECENT_ACTIVITY,
    BY_NAME_ALPHABETICAL,
    BY_NOTIFICATION_LEVEL,
    BY_JOINED_FIRST,
    BY_MEMBER_COUNT
  };

  json compute_room_list_ordering(const std::vector<std::string>& room_ids,
                                   const std::string& user_id,
                                   RoomOrder order = RoomOrder::BY_RECENT_ACTIVITY) {
    struct RoomOrderEntry {
      std::string room_id;
      std::string name;
      int64_t last_activity{0};
      int notification_count{0};
      int highlight_count{0};
      int member_count{0};
      int64_t join_ts{0};
    };

    std::vector<RoomOrderEntry> entries;
    entries.reserve(room_ids.size());

    for (const auto& rid : room_ids) {
      RoomOrderEntry entry;
      entry.room_id = rid;
      entry.name = compute_room_name(rid, user_id);
      entry.last_activity = get_last_activity_ts(rid);
      entry.member_count = get_joined_member_count(rid);
      entry.join_ts = get_user_join_ts(rid, user_id);

      auto counts = get_unread_counts(rid, user_id);
      entry.notification_count = safe_int(counts, "notification_count");
      entry.highlight_count = safe_int(counts, "highlight_count");

      entries.push_back(entry);
    }

    // Sort based on order type
    switch (order) {
      case RoomOrder::BY_RECENT_ACTIVITY:
        std::sort(entries.begin(), entries.end(),
                  [](const RoomOrderEntry& a, const RoomOrderEntry& b) {
                    if (a.highlight_count != b.highlight_count)
                      return a.highlight_count > b.highlight_count;
                    if (a.notification_count != b.notification_count)
                      return a.notification_count > b.notification_count;
                    return a.last_activity > b.last_activity;
                  });
        break;

      case RoomOrder::BY_NAME_ALPHABETICAL:
        std::sort(entries.begin(), entries.end(),
                  [](const RoomOrderEntry& a, const RoomOrderEntry& b) {
                    // Fold case-insensitive comparison
                    std::string na = a.name;
                    std::string nb = b.name;
                    std::transform(na.begin(), na.end(), na.begin(), ::tolower);
                    std::transform(nb.begin(), nb.end(), nb.begin(), ::tolower);
                    return na < nb;
                  });
        break;

      case RoomOrder::BY_NOTIFICATION_LEVEL:
        std::sort(entries.begin(), entries.end(),
                  [](const RoomOrderEntry& a, const RoomOrderEntry& b) {
                    int pa = a.highlight_count * 1000 + a.notification_count * 100;
                    int pb = b.highlight_count * 1000 + b.notification_count * 100;
                    if (pa != pb) return pa > pb;
                    return a.last_activity > b.last_activity;
                  });
        break;

      case RoomOrder::BY_JOINED_FIRST:
        std::sort(entries.begin(), entries.end(),
                  [](const RoomOrderEntry& a, const RoomOrderEntry& b) {
                    return a.join_ts > b.join_ts;
                  });
        break;

      case RoomOrder::BY_MEMBER_COUNT:
        std::sort(entries.begin(), entries.end(),
                  [](const RoomOrderEntry& a, const RoomOrderEntry& b) {
                    if (a.member_count != b.member_count)
                      return a.member_count > b.member_count;
                    return a.last_activity > b.last_activity;
                  });
        break;
    }

    // Build the ordered output
    json result = json::array();
    for (const auto& e : entries) {
      json entry;
      entry["room_id"] = e.room_id;
      entry["name"] = e.name;
      entry["last_activity"] = e.last_activity;
      entry["notification_count"] = e.notification_count;
      entry["highlight_count"] = e.highlight_count;
      entry["num_joined_members"] = e.member_count;

      // Compute tag priority
      entry["priority"] = compute_room_priority(e.highlight_count,
                                                  e.notification_count,
                                                  e.last_activity);

      // Add grouping info
      entry["group"] = determine_room_group(e);

      result.push_back(entry);
    }

    return result;
  }

  // ==========================================================================
  // 17. Unread notification count computation
  // ==========================================================================
  json get_unread_counts(const std::string& room_id, const std::string& user_id) {
    json result;
    result["notification_count"] = 0;
    result["highlight_count"] = 0;

    if (user_id.empty()) return result;

    auto rows = db_.execute(
        "get_unread_counts",
        "SELECT notif_count, highlight_count FROM event_push_summary "
        "WHERE user_id='" + sql_escape(user_id) + "' AND room_id='" +
        sql_escape(room_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "notif_count" && col.value) {
          try { result["notification_count"] = std::stoi(*col.value); } catch (...) {}
        }
        if (col.name == "highlight_count" && col.value) {
          try { result["highlight_count"] = std::stoi(*col.value); } catch (...) {}
        }
      }
    }

    // Also count from unread event_push_actions if summary table is empty
    if (result["notification_count"].get<int>() == 0 &&
        result["highlight_count"].get<int>() == 0) {
      auto action_rows = db_.execute(
          "count_unread_actions",
          "SELECT COUNT(*) as c FROM event_push_actions "
          "WHERE user_id='" + sql_escape(user_id) + "' AND room_id='" +
          sql_escape(room_id) + "' AND highlight=1");
      if (!action_rows.empty()) {
        for (const auto& col : action_rows[0]) {
          if (col.name == "c" && col.value) {
            try { result["highlight_count"] = std::stoi(*col.value); } catch (...) {}
            break;
          }
        }
      }

      auto notif_rows = db_.execute(
          "count_notif_actions",
          "SELECT COUNT(*) as c FROM event_push_actions "
          "WHERE user_id='" + sql_escape(user_id) + "' AND room_id='" +
          sql_escape(room_id) + "' AND notif=1");
      if (!notif_rows.empty()) {
        for (const auto& col : notif_rows[0]) {
          if (col.name == "c" && col.value) {
            try { result["notification_count"] = std::stoi(*col.value); } catch (...) {}
            break;
          }
        }
      }
    }

    return result;
  }

  // ==========================================================================
  // 18. Highlight count computation
  // ==========================================================================
  int get_highlight_count(const std::string& room_id, const std::string& user_id) {
    auto counts = get_unread_counts(room_id, user_id);
    return safe_int(counts, "highlight_count");
  }

  int get_notification_count(const std::string& room_id,
                               const std::string& user_id) {
    auto counts = get_unread_counts(room_id, user_id);
    return safe_int(counts, "notification_count");
  }

  // ==========================================================================
  // 19. Membership events ordering
  // ==========================================================================
  std::vector<std::string> get_membership_order(const std::string& room_id) {
    auto rows = db_.execute(
        "get_membership_order",
        "SELECT user_id FROM room_memberships WHERE room_id='" +
        sql_escape(room_id) + "' AND membership='join' "
        "ORDER BY event_stream_ordering ASC");

    std::vector<std::string> result;
    for (const auto& row : rows) {
      for (const auto& col : row) {
        if (col.name == "user_id" && col.value) {
          result.push_back(*col.value);
          break;
        }
      }
    }
    return result;
  }

  std::vector<std::pair<std::string, int64_t>> get_membership_order_with_ts(
      const std::string& room_id) {
    auto rows = db_.execute(
        "get_membership_order_ts",
        "SELECT user_id, origin_server_ts FROM room_memberships "
        "WHERE room_id='" + sql_escape(room_id) + "' AND membership='join' "
        "ORDER BY event_stream_ordering ASC");

    std::vector<std::pair<std::string, int64_t>> result;
    for (const auto& row : rows) {
      std::string uid;
      int64_t ts = 0;
      for (const auto& col : row) {
        if (col.name == "user_id" && col.value) uid = *col.value;
        if (col.name == "origin_server_ts" && col.value) {
          try { ts = std::stoll(*col.value); } catch (...) {}
        }
      }
      if (!uid.empty()) {
        result.emplace_back(uid, ts);
      }
    }
    return result;
  }

  // ==========================================================================
  // 20. State caching
  // ==========================================================================
  json get_cached_room_state(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto cached = room_state_cache_.get(room_id);
    if (cached) return *cached;

    json state = load_room_state_batch(room_id);
    room_state_cache_.put(room_id, state);
    return state;
  }

  void invalidate_cache(const std::string& room_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    room_state_cache_.put(room_id, json::object());
    room_summary_cache_.clear();
    hero_cache_.clear();
    // Keep name and avatar caches for read-heavy workloads, but
    // mark room's entries as stale
    room_name_cache_.put("name:" + room_id + ":*", "");
    member_count_cache_.put("joined:" + room_id, "");
    member_count_cache_.put("invited:" + room_id, "");
  }

  void warm_cache(const std::string& room_id, const std::string& user_id) {
    // Pre-compute and cache common room data
    get_cached_room_state(room_id);
    compute_room_summary(room_id, user_id);
    compute_room_name(room_id, user_id);
    compute_room_avatar(room_id);
    get_joined_member_count(room_id);
    get_invited_member_count(room_id);
    select_heroes(room_id, 5);
  }

  void bulk_warm_cache(const std::vector<std::string>& room_ids,
                        const std::string& user_id) {
    for (const auto& rid : room_ids) {
      warm_cache(rid, user_id);
    }
  }

private:
  DatabasePool& db_;

  // Caches with configurable TTLs
  util::LruCache<json> room_state_cache_;
  util::LruCache<json> room_summary_cache_;
  util::LruCache<std::vector<HeroEntry>> hero_cache_;
  util::LruCache<std::string> room_name_cache_;
  util::LruCache<std::string> room_avatar_cache_;
  util::LruCache<std::string> member_count_cache_;
  util::LruCache<std::string> dm_cache_;
  std::mutex cache_mutex_;

  // ========================================================================
  // Internal state loading helpers
  // ========================================================================

  json load_state_event(const std::string& room_id,
                         const std::string& event_type,
                         const std::string& state_key = "") {
    std::string sql =
        "SELECT * FROM current_state_events WHERE room_id='" +
        sql_escape(room_id) + "' AND type='" + sql_escape(event_type) +
        "' AND state_key='" + sql_escape(state_key) + "'";

    auto rows = db_.execute("load_state_event", sql);
    if (rows.empty()) return json();

    // Try events table as fallback
    if (rows.size() == 1 && rows[0].empty()) {
      rows = db_.execute(
          "load_state_event_fallback",
          "SELECT * FROM events WHERE room_id='" + sql_escape(room_id) +
          "' AND type='" + sql_escape(event_type) +
          "' AND state_key='" + sql_escape(state_key) +
          "' ORDER BY depth DESC LIMIT 1");
    }

    return row_to_event_json(rows);
  }

  json row_to_event_json(const RowList& rows) {
    if (rows.empty()) return json();

    json event;
    const auto& row = rows[0];

    for (const auto& col : row) {
      if (col.name == "event_id" && col.value)
        event["event_id"] = *col.value;
      else if (col.name == "type" && col.value)
        event["type"] = *col.value;
      else if (col.name == "sender" && col.value)
        event["sender"] = *col.value;
      else if (col.name == "state_key" && col.value)
        event["state_key"] = *col.value;
      else if (col.name == "room_id" && col.value)
        event["room_id"] = *col.value;
      else if (col.name == "origin_server_ts" && col.value)
        event["origin_server_ts"] = *col.value;
      else if (col.name == "depth" && col.value) {
        try { event["depth"] = std::stoll(*col.value); } catch (...) {}
      }
      else if (col.name == "content" && col.value) {
        try {
          event["content"] = json::parse(*col.value);
        } catch (...) {
          event["content"] = json::object();
        }
      }
    }

    // If event_id wasn't found, the row was empty
    if (!event.contains("event_id")) return json();

    return event;
  }

  std::vector<json> load_members(const std::string& room_id,
                                  const std::string& membership = "join") {
    auto rows = db_.execute(
        "load_members",
        "SELECT user_id FROM room_memberships WHERE room_id='" +
        sql_escape(room_id) + "' AND membership='" + sql_escape(membership) + "'");

    std::vector<json> members;
    members.reserve(rows.size());
    for (const auto& row : rows) {
      for (const auto& col : row) {
        if (col.name == "user_id" && col.value) {
          json m;
          m["user_id"] = *col.value;
          members.push_back(m);
          break;
        }
      }
    }
    return members;
  }

  std::vector<json> load_members_raw(const std::string& room_id,
                                      const std::string& membership,
                                      int limit = 100) {
    std::string sql =
        "SELECT user_id, sender, event_stream_ordering, origin_server_ts "
        "FROM room_memberships WHERE room_id='" + sql_escape(room_id) +
        "' AND membership='" + sql_escape(membership) + "' "
        "ORDER BY event_stream_ordering ASC LIMIT " + std::to_string(limit);

    auto rows = db_.execute("load_members_raw", sql);
    std::vector<json> members;
    members.reserve(rows.size());

    for (const auto& row : rows) {
      json m;
      for (const auto& col : row) {
        if (col.name == "user_id" && col.value)
          m["user_id"] = *col.value;
        else if (col.name == "sender" && col.value)
          m["sender"] = *col.value;
        else if (col.name == "event_stream_ordering" && col.value) {
          try { m["stream_ordering"] = std::stoll(*col.value); } catch (...) {}
        }
        else if (col.name == "origin_server_ts" && col.value)
          m["origin_server_ts"] = *col.value;
      }
      if (m.contains("user_id")) {
        members.push_back(m);
      }
    }
    return members;
  }

  std::string get_display_name(const std::string& user_id) {
    auto rows = db_.execute(
        "get_display_name",
        "SELECT display_name FROM profiles WHERE user_id='" +
        sql_escape(user_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "display_name" && col.value && !col.value->empty())
          return *col.value;
      }
    }

    // Fallback to localpart
    return extract_localpart(user_id);
  }

  std::string get_avatar_url(const std::string& user_id) {
    auto rows = db_.execute(
        "get_avatar_url",
        "SELECT avatar_url FROM profiles WHERE user_id='" +
        sql_escape(user_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "avatar_url" && col.value && !col.value->empty())
          return *col.value;
      }
    }
    return "";
  }

  std::string get_user_avatar_url(const std::string& user_id) {
    return get_avatar_url(user_id);
  }

  json load_account_data(const std::string& user_id,
                          const std::string& data_type) {
    auto rows = db_.execute(
        "load_account_data",
        "SELECT content FROM account_data WHERE user_id='" +
        sql_escape(user_id) + "' AND type='" + sql_escape(data_type) + "'");

    if (rows.empty()) return json();

    for (const auto& col : rows[0]) {
      if (col.name == "content" && col.value) {
        try {
          return json::parse(*col.value);
        } catch (...) {
          return json::object();
        }
      }
    }
    return json();
  }

  std::vector<std::string> get_joined_user_ids(const std::string& room_id) {
    auto members = load_members(room_id, "join");
    std::vector<std::string> result;
    result.reserve(members.size());
    for (const auto& m : members) {
      std::string uid = safe_str(m, "user_id", "");
      if (!uid.empty()) result.push_back(uid);
    }
    return result;
  }

  int64_t get_join_timestamp(const std::string& room_id,
                               const std::string& user_id) {
    auto rows = db_.execute(
        "get_join_timestamp",
        "SELECT origin_server_ts FROM room_memberships WHERE room_id='" +
        sql_escape(room_id) + "' AND user_id='" + sql_escape(user_id) +
        "' AND membership='join'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "origin_server_ts" && col.value) {
          try { return std::stoll(*col.value); } catch (...) { return 0; }
        }
      }
    }
    return 0;
  }

  int64_t get_user_join_ts(const std::string& room_id,
                             const std::string& user_id) {
    return get_join_timestamp(room_id, user_id);
  }

  int64_t get_last_active_ts(const std::string& room_id,
                               const std::string& user_id) {
    // Check presence table first
    auto rows = db_.execute(
        "get_last_active",
        "SELECT last_active_ts FROM presence_state WHERE user_id='" +
        sql_escape(user_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "last_active_ts" && col.value) {
          try { return std::stoll(*col.value); } catch (...) {}
        }
      }
    }

    // Fallback to last event timestamp in the room
    auto event_rows = db_.execute(
        "get_last_msg_ts",
        "SELECT MAX(origin_server_ts) as mts FROM events WHERE room_id='" +
        sql_escape(room_id) + "' AND sender='" + sql_escape(user_id) + "'");

    if (!event_rows.empty()) {
      for (const auto& col : event_rows[0]) {
        if (col.name == "mts" && col.value && !col.value->empty()) {
          try { return std::stoll(*col.value); } catch (...) {}
        }
      }
    }

    (void)room_id;
    return 0;
  }

  int64_t get_last_activity_ts(const std::string& room_id) {
    auto rows = db_.execute(
        "get_last_activity",
        "SELECT MAX(origin_server_ts) as mts FROM events WHERE room_id='" +
        sql_escape(room_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "mts" && col.value && !col.value->empty()) {
          try { return std::stoll(*col.value); } catch (...) {}
        }
      }
    }
    return 0;
  }

  // ========================================================================
  // Internal: Room name computation
  // ========================================================================

  std::string compute_room_name_internal(const std::string& room_id,
                                          const std::string& viewer_user_id,
                                          const json& name_event,
                                          const json& create_event) {
    // Step 1: m.room.name state event
    if (!name_event.empty()) {
      std::string content_name;
      if (name_event.contains("content") && name_event["content"].is_object()) {
        content_name = safe_str(name_event["content"], "name", "");
      }
      if (content_name.empty()) {
        content_name = safe_str(name_event, "name", "");
      }
      if (!content_name.empty()) {
        return content_name;
      }
    }

    // Step 2: Canonical alias
    std::string alias = get_canonical_alias(room_id);
    if (!alias.empty()) {
      return alias;
    }

    // Step 3: Compute name from heroes/members
    return room_name_from_heroes_internal(room_id, viewer_user_id);
  }

  std::string room_name_from_heroes(const std::vector<HeroEntry>& heroes,
                                     const std::string& viewer_user_id) {
    // Filter out the viewer from heroes if present
    std::vector<HeroEntry> filtered;
    for (const auto& h : heroes) {
      if (h.user_id != viewer_user_id) {
        filtered.push_back(h);
      }
    }

    size_t count = filtered.size();

    if (count == 0) {
      return "Empty Room";
    }

    if (count == 1) {
      std::string dn = filtered[0].display_name;
      if (dn.empty()) dn = extract_localpart(filtered[0].user_id);
      return dn;
    }

    if (count == 2) {
      std::string dn1 = filtered[0].display_name;
      if (dn1.empty()) dn1 = extract_localpart(filtered[0].user_id);
      std::string dn2 = filtered[1].display_name;
      if (dn2.empty()) dn2 = extract_localpart(filtered[1].user_id);
      return dn1 + " and " + dn2;
    }

    // 3+ members
    std::string dn1 = filtered[0].display_name;
    if (dn1.empty()) dn1 = extract_localpart(filtered[0].user_id);
    std::string dn2 = filtered[1].display_name;
    if (dn2.empty()) dn2 = extract_localpart(filtered[1].user_id);

    int remaining = static_cast<int>(count) - 2;
    return dn1 + ", " + dn2 + " and " + std::to_string(remaining) + " others";
  }

  std::string room_name_from_heroes_internal(const std::string& room_id,
                                               const std::string& viewer_user_id) {
    auto heroes = select_heroes_internal(room_id, viewer_user_id, 5);
    return room_name_from_heroes(heroes, viewer_user_id);
  }

  std::string room_name_fallback(const std::string& room_id,
                                  const std::string& viewer_user_id) {
    // If no display name is set and no members, fall back to room ID
    int count = get_joined_member_count(room_id);
    if (count == 0) {
      return "Empty Room";
    }
    // Use room ID as last resort
    return room_id;
  }

  // ========================================================================
  // Internal: Hero selection
  // ========================================================================

  std::vector<HeroEntry> select_heroes_internal(const std::string& room_id,
                                                  const std::string& viewer_user_id,
                                                  int count) {
    // Try cache
    {
      std::lock_guard<std::mutex> lock(cache_mutex_);
      auto cached = hero_cache_.get(room_id + ":" + std::to_string(count));
      if (cached) return *cached;
    }

    std::vector<HeroEntry> all_heroes;
    auto members = load_members_raw(room_id, "join", 500);

    // Build hero entries from members
    for (const auto& m : members) {
      std::string uid = safe_str(m, "user_id", "");
      if (uid.empty()) continue;

      HeroEntry hero;
      hero.user_id = uid;
      hero.display_name = get_display_name(uid);
      hero.avatar_url = get_avatar_url(uid);
      hero.join_order = safe_int(m, "stream_ordering", 0);
      hero.last_active_ts = get_last_active_ts(room_id, uid);
      hero.currently_active = (now_ms() - hero.last_active_ts) < 300000; // 5 min

      all_heroes.push_back(hero);
    }

    // Sort heroes: joined first, then active, then alphabetical
    std::sort(all_heroes.begin(), all_heroes.end(),
              [](const HeroEntry& a, const HeroEntry& b) {
                // Priority 1: Joined first (lower join_order = joined earlier)
                if (a.join_order != b.join_order)
                  return a.join_order < b.join_order;
                // Priority 2: Active users first
                if (a.currently_active != b.currently_active)
                  return a.currently_active > b.currently_active;
                // Priority 3: Recently active
                if (a.last_active_ts != b.last_active_ts)
                  return a.last_active_ts > b.last_active_ts;
                // Priority 4: Alphabetical by display_name
                std::string na = a.display_name.empty() ?
                    extract_localpart(a.user_id) : a.display_name;
                std::string nb = b.display_name.empty() ?
                    extract_localpart(b.user_id) : b.display_name;
                std::transform(na.begin(), na.end(), na.begin(), ::tolower);
                std::transform(nb.begin(), nb.end(), nb.begin(), ::tolower);
                return na < nb;
              });

    // Take top `count` heroes, but ensure viewer is included if present
    std::vector<HeroEntry> result;
    bool viewer_included = false;

    for (const auto& h : all_heroes) {
      if (static_cast<int>(result.size()) >= count) break;
      result.push_back(h);
      if (h.user_id == viewer_user_id) viewer_included = true;
    }

    // If viewer not in top `count`, replace the last hero with viewer
    if (!viewer_user_id.empty() && !viewer_included && !result.empty()) {
      for (const auto& h : all_heroes) {
        if (h.user_id == viewer_user_id) {
          result.back() = h;
          viewer_included = true;
          break;
        }
      }
    }

    // Cache result
    {
      std::lock_guard<std::mutex> lock(cache_mutex_);
      hero_cache_.put(room_id + ":" + std::to_string(count), result);
    }

    return result;
  }

  // ========================================================================
  // Internal: Room avatar computation
  // ========================================================================

  std::string compute_room_avatar_internal(const std::string& room_id,
                                            const json& avatar_event) {
    // Step 1: m.room.avatar state event
    if (!avatar_event.empty()) {
      std::string url;
      if (avatar_event.contains("content") && avatar_event["content"].is_object()) {
        url = safe_str(avatar_event["content"], "url", "");
      }
      if (url.empty()) {
        url = safe_str(avatar_event, "url", "");
      }
      if (!url.empty()) {
        return url;
      }
    }

    // Step 2: Use first hero's avatar (for DMs/small rooms)
    auto heroes = select_heroes_internal(room_id, "", 3);
    if (!heroes.empty() && !heroes[0].avatar_url.empty()) {
      return heroes[0].avatar_url;
    }

    // Step 3: Generate default avatar from room name
    std::string name = compute_room_name(room_id);
    return generate_room_default_avatar(name);
  }

  std::string generate_room_default_avatar(const std::string& name) {
    // Generate a deterministic SVG avatar from the room name
    size_t hash = std::hash<std::string>{}(name);
    const char* colors[] = {
      "#3949ab", "#00897b", "#43a047", "#7cb342", "#c0ca33",
      "#fdd835", "#ffb300", "#fb8c00", "#f4511e", "#6d4c41",
      "#757575", "#546e7a", "#8e24aa", "#5e35b1", "#1e88e5",
      "#039be5", "#00acc1", "#e53935", "#d81b60"
    };
    std::string bg = colors[hash % 19];

    std::string letter;
    if (!name.empty()) {
      // Find first alphanumeric character
      for (char c : name) {
        if (std::isalnum(static_cast<unsigned char>(c))) {
          letter = std::string(1, static_cast<char>(std::toupper(c)));
          break;
        }
      }
    }
    if (letter.empty()) letter = "#";

    return "data:image/svg+xml,"
           "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'>"
           "<rect fill='" + bg + "' width='100' height='100' rx='15'/>"
           "<text fill='white' font-size='50' font-weight='bold' "
           "x='50' y='68' text-anchor='middle' font-family='sans-serif'>" +
           letter + "</text></svg>";
  }

  // ========================================================================
  // Internal: Membership and access checks
  // ========================================================================

  bool is_user_member(const std::string& room_id, const std::string& user_id) {
    if (user_id.empty()) return false;

    auto rows = db_.execute(
        "is_user_member",
        "SELECT membership FROM room_memberships WHERE room_id='" +
        sql_escape(room_id) + "' AND user_id='" + sql_escape(user_id) + "'");

    if (rows.empty()) return false;

    for (const auto& col : rows[0]) {
      if (col.name == "membership" && col.value) {
        return *col.value == "join";
      }
    }
    return false;
  }

  std::string get_join_rule(const std::string& room_id) {
    json jr_event = load_state_event(room_id, "m.room.join_rules", "");
    if (jr_event.empty()) return "public";
    return safe_str(jr_event, "join_rule", "public");
  }

  bool get_guest_access(const std::string& room_id) {
    json ga_event = load_state_event(room_id, "m.room.guest_access", "");
    if (ga_event.empty()) return false;
    return safe_str(ga_event, "guest_access", "") == "can_join";
  }

  // ========================================================================
  // Internal: State batch loading
  // ========================================================================

  json load_room_state_batch(const std::string& room_id) {
    // Load all current state for a room in one query
    auto rows = db_.execute(
        "load_room_state_batch",
        "SELECT type, state_key, event_id, content FROM current_state_events "
        "WHERE room_id='" + sql_escape(room_id) + "'");

    json state = json::object();
    json events_list = json::array();

    for (const auto& row : rows) {
      json ev;
      std::string type, state_key, event_id, content_str;

      for (const auto& col : row) {
        if (col.name == "type" && col.value) type = *col.value;
        else if (col.name == "state_key" && col.value) state_key = *col.value;
        else if (col.name == "event_id" && col.value) event_id = *col.value;
        else if (col.name == "content" && col.value) content_str = *col.value;
      }

      ev["type"] = type;
      ev["state_key"] = state_key;
      ev["event_id"] = event_id;
      ev["room_id"] = room_id;

      try {
        ev["content"] = json::parse(content_str);
      } catch (...) {
        ev["content"] = json::object();
      }

      events_list.push_back(ev);

      // Also organize by type+state_key for quick lookup
      std::string key = type + "\x00" + state_key;
      if (!state.contains(key)) {
        state[key] = ev;
      }
    }

    state["_events"] = events_list;
    return state;
  }

  std::vector<json> load_recent_events(const std::string& room_id, int limit) {
    auto rows = db_.execute(
        "load_recent_events",
        "SELECT * FROM events WHERE room_id='" + sql_escape(room_id) +
        "' ORDER BY stream_ordering DESC LIMIT " + std::to_string(limit));

    std::vector<json> events;
    events.reserve(rows.size());

    for (const auto& row : rows) {
      json ev;
      for (const auto& col : row) {
        if (col.name == "event_id" && col.value)
          ev["event_id"] = *col.value;
        else if (col.name == "type" && col.value)
          ev["type"] = *col.value;
        else if (col.name == "sender" && col.value)
          ev["sender"] = *col.value;
        else if (col.name == "state_key" && col.value)
          ev["state_key"] = *col.value;
        else if (col.name == "room_id" && col.value)
          ev["room_id"] = *col.value;
        else if (col.name == "origin_server_ts" && col.value)
          ev["origin_server_ts"] = *col.value;
        else if (col.name == "stream_ordering" && col.value) {
          try { ev["stream_ordering"] = std::stoll(*col.value); } catch (...) {}
        }
        else if (col.name == "depth" && col.value) {
          try { ev["depth"] = std::stoll(*col.value); } catch (...) {}
        }
        else if (col.name == "content" && col.value) {
          try { ev["content"] = json::parse(*col.value); }
          catch (...) { ev["content"] = json::object(); }
        }
      }
      if (ev.contains("event_id")) {
        events.push_back(ev);
      }
    }
    return events;
  }

  // ========================================================================
  // Internal: Thumbnail helpers
  // ========================================================================

  std::string determine_thumbnail_layout(size_t count) {
    if (count == 0) return "empty";
    if (count == 1) return "single";
    if (count == 2) return "dual";
    if (count == 3) return "triple";
    if (count <= 4) return "quad";
    return "grid";
  }

  std::string compute_dominant_background(const std::string& room_id) {
    // Compute a deterministic color based on room ID
    size_t hash = std::hash<std::string>{}(room_id);
    const char* backgrounds[] = {
      "#1a1a2e", "#16213e", "#0f3460", "#533483",
      "#2d3436", "#636e72", "#b2bec3", "#dfe6e9",
      "#1e272e", "#485460", "#808e9b", "#d2dae2"
    };
    return backgrounds[hash % 12];
  }

  // ========================================================================
  // Internal: Priority and grouping
  // ========================================================================

  double compute_room_priority(int highlights, int notifications,
                                 int64_t last_activity) {
    // Higher priority = more important
    double priority = 0.0;

    // Highlights are most important
    priority += highlights * 1000.0;

    // Notifications second
    priority += notifications * 10.0;

    // Recent activity adds priority with a time decay
    int64_t age_ms = now_ms() - last_activity;
    if (last_activity > 0 && age_ms > 0) {
      // Decay factor: half-life of 1 hour
      double hours_ago = static_cast<double>(age_ms) / 3600000.0;
      double decay = std::pow(0.5, hours_ago);
      priority += decay * 5.0;
    }

    return priority;
  }

  struct RoomOrderEntry {
    std::string room_id;
    std::string name;
    int64_t last_activity{0};
    int notification_count{0};
    int highlight_count{0};
    int member_count{0};
    int64_t join_ts{0};
  };

  std::string determine_room_group(const RoomOrderEntry& entry) {
    // Group: Favourites (highlighted), Direct Messages, Rooms, Low Priority
    if (entry.highlight_count > 0) return "favourites";
    if (entry.member_count <= 2) return "direct_messages";
    if (entry.notification_count > 0) return "notifications";
    return "rooms";
  }

  // ========================================================================
  // Internal: State event formatting
  // ========================================================================

  json format_state_event(const json& event) {
    json formatted;
    formatted["type"] = safe_str(event, "type", "");
    formatted["state_key"] = safe_str(event, "state_key", "");
    formatted["sender"] = safe_str(event, "sender", "");
    formatted["event_id"] = safe_str(event, "event_id", "");
    formatted["room_id"] = safe_str(event, "room_id", "");

    if (event.contains("origin_server_ts")) {
      formatted["origin_server_ts"] = event["origin_server_ts"];
    }

    if (event.contains("content")) {
      formatted["content"] = event["content"];
    } else {
      formatted["content"] = json::object();
    }

    return formatted;
  }

  // ========================================================================
  // Internal: Summary JSON deserialization
  // ========================================================================

  RoomSummary summary_from_json(const json& j) {
    RoomSummary s;
    s.room_id = safe_str(j, "room_id", "");
    s.name = safe_str(j, "name", "");
    s.canonical_alias = safe_str(j, "canonical_alias", "");
    s.topic = safe_str(j, "topic", "");
    s.avatar_url = safe_str(j, "avatar_url", "");
    s.joined_member_count = safe_int(j, "m.joined_member_count");
    s.invited_member_count = safe_int(j, "m.invited_member_count");
    s.is_direct = safe_bool(j, "is_direct");
    s.encrypted = j.contains("encryption");
    s.room_type = safe_str(j, "room_type", "");
    s.world_readable = safe_bool(j, "world_readable");
    s.guests_can_join = safe_bool(j, "guest_can_join");
    s.last_activity_ts = safe_int(j, "last_activity_ts");
    s.notification_count = safe_int(j, "notification_count");
    s.highlight_count = safe_int(j, "highlight_count");
    s.creator = safe_str(j, "creator", "");
    s.join_rule = safe_str(j, "join_rule", "");

    if (j.contains("heroes") && j["heroes"].is_array()) {
      for (const auto& hj : j["heroes"]) {
        HeroEntry h;
        h.user_id = safe_str(hj, "user_id", "");
        h.display_name = safe_str(hj, "display_name", "");
        h.avatar_url = safe_str(hj, "avatar_url", "");
        s.heroes.push_back(h);
      }
    }

    if (j.contains("aliases") && j["aliases"].is_array()) {
      for (const auto& a : j["aliases"]) {
        if (a.is_string()) s.aliases.push_back(a.get<std::string>());
      }
    }

    return s;
  }
};

// ============================================================================
// RoomSummaryAggregator - Batch computation across multiple rooms
// ============================================================================

class RoomSummaryAggregator {
public:
  explicit RoomSummaryAggregator(DatabasePool& db)
      : computation_(db) {}

  // Compute summaries for all joined rooms of a user
  json compute_all_room_summaries(const std::string& user_id) {
    json result = json::object();
    result["join"] = json::object();
    result["invite"] = json::object();
    result["leave"] = json::object();

    // Joined rooms
    auto joined_rooms = get_user_rooms(user_id, "join");
    for (const auto& rid : joined_rooms) {
      result["join"][rid] = computation_.compute_room_summary_json(rid, user_id);
    }

    // Invited rooms
    auto invited_rooms = get_user_rooms(user_id, "invite");
    for (const auto& rid : invited_rooms) {
      result["invite"][rid] = computation_.compute_room_summary_json(rid, user_id);
    }

    // Left rooms (basic info only)
    auto left_rooms = get_user_rooms(user_id, "leave");
    for (const auto& rid : left_rooms) {
      json basic;
      basic["room_id"] = rid;
      basic["name"] = computation_.compute_room_name(rid, user_id);
      result["leave"][rid] = basic;
    }

    return result;
  }

  // Compute room list for the client (synced room list)
  json compute_room_list(const std::string& user_id,
                          const std::string& order_by = "recent") {
    auto joined_rooms = get_user_rooms(user_id, "join");

    std::vector<std::string> room_ids;
    room_ids.reserve(joined_rooms.size());
    for (const auto& rid : joined_rooms) {
      room_ids.push_back(rid);
    }

    RoomOrder order = RoomOrder::BY_RECENT_ACTIVITY;
    if (order_by == "name" || order_by == "alphabetical")
      order = RoomOrder::BY_NAME_ALPHABETICAL;
    else if (order_by == "notification" || order_by == "priority")
      order = RoomOrder::BY_NOTIFICATION_LEVEL;
    else if (order_by == "joined")
      order = RoomOrder::BY_JOINED_FIRST;

    return computation_.compute_room_list_ordering(room_ids, user_id, order);
  }

  // Bulk pre-warm caches for efficient sync
  void warm_sync_caches(const std::string& user_id) {
    auto joined_rooms = get_user_rooms(user_id, "join");

    std::vector<std::string> room_ids;
    room_ids.reserve(joined_rooms.size());
    for (const auto& rid : joined_rooms) {
      room_ids.push_back(rid);
    }

    computation_.bulk_warm_cache(room_ids, user_id);
  }

  // Invalidate all caches for a room (on new event)
  void on_new_event(const std::string& room_id) {
    computation_.invalidate_cache(room_id);
  }

private:
  RoomSummaryComputation computation_;

  std::vector<std::string> get_user_rooms(const std::string& user_id,
                                           const std::string& membership) {
    // Delegate to the computation's database
    // We need direct DB access, so use a helper
    auto& db = computation_.db_;
    auto rows = db.execute(
        "get_user_rooms",
        "SELECT room_id FROM room_memberships WHERE user_id='" +
        sql_escape(user_id) + "' AND membership='" + sql_escape(membership) + "'");

    std::vector<std::string> result;
    for (const auto& row : rows) {
      for (const auto& col : row) {
        if (col.name == "room_id" && col.value) {
          result.push_back(*col.value);
          break;
        }
      }
    }
    return result;
  }
};

// ============================================================================
// RoomSyncSummaryBuilder - builds the m.room.summary section for sync
// ============================================================================

class RoomSyncSummaryBuilder {
public:
  explicit RoomSyncSummaryBuilder(DatabasePool& db)
      : computation_(db) {}

  // Build the complete summary section for a sync response
  json build_sync_summary(const std::string& room_id,
                           const std::string& user_id,
                           bool include_heroes = true,
                           bool include_unread = true) {
    json summary;

    // Required fields per Matrix spec
    summary["m.joined_member_count"] = computation_.get_joined_member_count(room_id);
    summary["m.invited_member_count"] = computation_.get_invited_member_count(room_id);

    // Heroes
    if (include_heroes) {
      auto heroes = computation_.select_heroes(room_id, 5);
      json hero_arr = json::array();
      for (const auto& h : heroes) {
        json hj;
        hj["user_id"] = h.user_id;
        if (!h.display_name.empty()) hj["display_name"] = h.display_name;
        if (!h.avatar_url.empty()) hj["avatar_url"] = h.avatar_url;
        hero_arr.push_back(hj);
      }
      summary["m.heroes"] = hero_arr;
    }

    // Unread counts
    if (include_unread && !user_id.empty()) {
      auto counts = computation_.get_unread_counts(room_id, user_id);
      summary["m.notification_count"] = safe_int(counts, "notification_count");
      summary["m.highlight_count"] = safe_int(counts, "highlight_count");
    }

    // DM flag
    if (!user_id.empty() && computation_.is_direct_room(room_id, user_id)) {
      summary["m.direct"] = true;
    }

    // Encryption
    if (computation_.is_encrypted(room_id)) {
      summary["m.encryption"] = json::object();
      summary["m.encryption"]["algorithm"] = "m.megolm.v1.aes-sha2";
    }

    return summary;
  }

  // Build summary with all extras for initial sync
  json build_full_summary(const std::string& room_id,
                           const std::string& user_id) {
    RoomSummary s = computation_.compute_room_summary(room_id, user_id);
    return s.to_json();
  }

  // Build a minimal summary for left rooms
  json build_left_room_summary(const std::string& room_id,
                                const std::string& user_id) {
    json summary;
    summary["m.joined_member_count"] = computation_.get_joined_member_count(room_id);
    summary["m.invited_member_count"] = computation_.get_invited_member_count(room_id);
    return summary;
  }

  // Build an invite summary
  json build_invite_summary(const std::string& room_id,
                             const std::string& inviter_user_id,
                             const std::string& invitee_user_id) {
    json summary;
    summary["m.joined_member_count"] = computation_.get_joined_member_count(room_id);
    summary["m.invited_member_count"] = computation_.get_invited_member_count(room_id);

    // Include inviter as the single "hero"
    json inviter_hero;
    inviter_hero["user_id"] = inviter_user_id;
    inviter_hero["display_name"] = get_display_name_static(inviter_user_id);
    inviter_hero["avatar_url"] = get_avatar_url_static(inviter_user_id);
    summary["m.heroes"] = json::array({inviter_hero});

    // Include room name if available
    std::string name = computation_.compute_room_name(room_id);
    if (!name.empty()) {
      summary["m.room_name"] = name;
    }

    // Is direct
    if (computation_.is_direct_room(room_id, invitee_user_id)) {
      summary["m.direct"] = true;
    }

    return summary;
  }

private:
  RoomSummaryComputation computation_;

  static std::string get_display_name_static(const std::string& user_id) {
    auto localpart = extract_localpart(user_id);
    if (localpart.empty()) return user_id;
    return localpart;
  }

  static std::string get_avatar_url_static(const std::string& user_id) {
    return default_avatar_for(user_id);
  }
};

// ============================================================================
// RoomNotificationState - tracks notification state per room
// ============================================================================

class RoomNotificationState {
public:
  explicit RoomNotificationState(DatabasePool& db)
      : db_(db) {}

  // Get notification counts, respecting push rules
  json get_notification_state(const std::string& room_id,
                               const std::string& user_id) {
    json state;

    // Get push rule for this room
    auto push_rule = get_push_rule_for_room(user_id, room_id);

    state["room_id"] = room_id;
    state["notification_count"] = get_total_notification_count(room_id, user_id);
    state["highlight_count"] = get_total_highlight_count(room_id, user_id);
    state["has_unread"] = state["notification_count"].get<int>() > 0 ||
                           state["highlight_count"].get<int>() > 0;

    // Check if notifications are muted
    if (!push_rule.empty()) {
      json actions = push_rule.value("actions", json::array());
      bool muted = false;
      for (const auto& a : actions) {
        if (a.is_string()) {
          std::string action = a.get<std::string>();
          if (action == "dont_notify") muted = true;
        }
      }
      state["muted"] = muted;

      // Check if it's a default-override
      std::string rule_id = safe_str(push_rule, "rule_id", "");
      state["push_rule_id"] = rule_id;
    } else {
      state["muted"] = false;
    }

    // Determine notification level
    if (state["highlight_count"].get<int>() > 0) {
      state["notification_level"] = "highlight";
    } else if (state["notification_count"].get<int>() > 0 && !state["muted"].get<bool>()) {
      state["notification_level"] = "notify";
    } else if (state["notification_count"].get<int>() > 0 && state["muted"].get<bool>()) {
      state["notification_level"] = "muted";
    } else {
      state["notification_level"] = "default";
    }

    return state;
  }

  // Compute notification counts for multiple rooms at once
  json get_bulk_notification_states(const std::vector<std::string>& room_ids,
                                      const std::string& user_id) {
    json result = json::object();
    for (const auto& rid : room_ids) {
      result[rid] = get_notification_state(rid, user_id);
    }
    return result;
  }

  // Mark room as read (reset notification counts)
  void mark_room_read(const std::string& room_id, const std::string& user_id,
                       const std::string& event_id) {
    // Update read receipt
    db_.execute(
        "mark_room_read_receipt",
        "INSERT OR REPLACE INTO read_receipts (room_id, user_id, event_id, ts) "
        "VALUES ('" + sql_escape(room_id) + "','" + sql_escape(user_id) +
        "','" + sql_escape(event_id) + "'," + std::to_string(now_ms()) + ")");

    // Reset notification counts in push summary
    db_.execute(
        "reset_notif_counts",
        "UPDATE event_push_summary SET notif_count=0, highlight_count=0, "
        "last_receipt_event_id='" + sql_escape(event_id) +
        "' WHERE user_id='" + sql_escape(user_id) +
        "' AND room_id='" + sql_escape(room_id) + "'");
  }

private:
  DatabasePool& db_;

  int get_total_notification_count(const std::string& room_id,
                                     const std::string& user_id) {
    auto rows = db_.execute(
        "get_notif_count",
        "SELECT notif_count FROM event_push_summary WHERE user_id='" +
        sql_escape(user_id) + "' AND room_id='" + sql_escape(room_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "notif_count" && col.value) {
          try { return std::stoi(*col.value); } catch (...) {}
        }
      }
    }
    return 0;
  }

  int get_total_highlight_count(const std::string& room_id,
                                  const std::string& user_id) {
    auto rows = db_.execute(
        "get_highlight_count",
        "SELECT highlight_count FROM event_push_summary WHERE user_id='" +
        sql_escape(user_id) + "' AND room_id='" + sql_escape(room_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "highlight_count" && col.value) {
          try { return std::stoi(*col.value); } catch (...) {}
        }
      }
    }
    return 0;
  }

  json get_push_rule_for_room(const std::string& user_id,
                               const std::string& room_id) {
    auto rows = db_.execute(
        "get_push_rule",
        "SELECT rule_id, actions, conditions FROM push_rules "
        "WHERE user_id='" + sql_escape(user_id) +
        "' AND rule_id LIKE '%" + sql_escape(room_id) + "%'");

    if (!rows.empty()) {
      json rule;
      for (const auto& col : rows[0]) {
        if (col.name == "rule_id" && col.value) {
          rule["rule_id"] = *col.value;
        } else if (col.name == "actions" && col.value) {
          try { rule["actions"] = json::parse(*col.value); }
          catch (...) { rule["actions"] = json::array(); }
        } else if (col.name == "conditions" && col.value) {
          try { rule["conditions"] = json::parse(*col.value); }
          catch (...) { rule["conditions"] = json::array(); }
        }
      }
      return rule;
    }
    return json();
  }
};

// ============================================================================
// RoomActivityTracker - tracks room activity for ordering
// ============================================================================

class RoomActivityTracker {
public:
  explicit RoomActivityTracker(DatabasePool& db)
      : db_(db) {}

  // Record activity in a room (called when an event is sent)
  void record_activity(const std::string& room_id, int64_t timestamp_ms) {
    db_.execute(
        "record_room_activity",
        "INSERT OR REPLACE INTO room_activity (room_id, last_activity_ts) "
        "VALUES ('" + sql_escape(room_id) + "', " +
        std::to_string(timestamp_ms) + ")");

    // Also update in-memory cache
    std::lock_guard<std::mutex> lock(activity_mutex_);
    room_activity_[room_id] = timestamp_ms;
  }

  // Get last activity timestamp
  int64_t get_last_activity(const std::string& room_id) {
    // Check in-memory cache first
    {
      std::lock_guard<std::mutex> lock(activity_mutex_);
      auto it = room_activity_.find(room_id);
      if (it != room_activity_.end()) {
        return it->second;
      }
    }

    auto rows = db_.execute(
        "get_room_activity",
        "SELECT last_activity_ts FROM room_activity WHERE room_id='" +
        sql_escape(room_id) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "last_activity_ts" && col.value) {
          try {
            int64_t ts = std::stoll(*col.value);
            std::lock_guard<std::mutex> lock(activity_mutex_);
            room_activity_[room_id] = ts;
            return ts;
          } catch (...) {}
        }
      }
    }

    // Fallback: use events table
    auto event_rows = db_.execute(
        "get_room_activity_fallback",
        "SELECT MAX(origin_server_ts) as mts FROM events WHERE room_id='" +
        sql_escape(room_id) + "'");

    if (!event_rows.empty()) {
      for (const auto& col : event_rows[0]) {
        if (col.name == "mts" && col.value) {
          try {
            int64_t ts = std::stoll(*col.value);
            std::lock_guard<std::mutex> lock(activity_mutex_);
            room_activity_[room_id] = ts;
            return ts;
          } catch (...) {}
        }
      }
    }

    return 0;
  }

  // Get most active rooms for a user
  std::vector<std::string> get_most_active_rooms(const std::string& user_id,
                                                    int limit = 20) {
    auto rows = db_.execute(
        "get_most_active_rooms",
        "SELECT rm.room_id, COALESCE(ra.last_activity_ts, 0) as activity "
        "FROM room_memberships rm "
        "LEFT JOIN room_activity ra ON rm.room_id = ra.room_id "
        "WHERE rm.user_id='" + sql_escape(user_id) +
        "' AND rm.membership='join' "
        "ORDER BY activity DESC LIMIT " + std::to_string(limit));

    std::vector<std::string> result;
    for (const auto& row : rows) {
      for (const auto& col : row) {
        if (col.name == "room_id" && col.value) {
          result.push_back(*col.value);
          break;
        }
      }
    }
    return result;
  }

  // Clean up old activity records
  void cleanup_old_activity(int64_t older_than_ms) {
    db_.execute(
        "cleanup_room_activity",
        "DELETE FROM room_activity WHERE last_activity_ts < " +
        std::to_string(older_than_ms));
  }

private:
  DatabasePool& db_;
  std::mutex activity_mutex_;
  std::unordered_map<std::string, int64_t> room_activity_;
};

// ============================================================================
// RoomAliasResolver - resolves room aliases and handles canonical alias
// ============================================================================

class RoomAliasResolver {
public:
  explicit RoomAliasResolver(DatabasePool& db)
      : db_(db) {}

  // Get all aliases for a room
  std::vector<std::string> get_room_aliases(const std::string& room_id) {
    auto rows = db_.execute(
        "get_room_aliases",
        "SELECT room_alias FROM room_aliases WHERE room_id='" +
        sql_escape(room_id) + "'");

    std::vector<std::string> result;
    for (const auto& row : rows) {
      for (const auto& col : row) {
        if (col.name == "room_alias" && col.value) {
          result.push_back(*col.value);
          break;
        }
      }
    }
    return result;
  }

  // Resolve alias to room ID
  std::string resolve_alias(const std::string& alias) {
    auto rows = db_.execute(
        "resolve_alias",
        "SELECT room_id FROM room_aliases WHERE room_alias='" +
        sql_escape(alias) + "'");

    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "room_id" && col.value) {
          return *col.value;
        }
      }
    }
    return "";
  }

  // Set canonical alias
  void set_canonical_alias(const std::string& room_id,
                            const std::string& alias) {
    // Update or insert into current_state_events
    json content;
    content["alias"] = alias;
    std::string content_str = content.dump();

    int64_t now = now_ms();
    std::string event_id = "$canonical_alias_" + std::to_string(now);

    db_.execute(
        "set_canonical_alias",
        "INSERT OR REPLACE INTO current_state_events "
        "(event_id, room_id, type, state_key, content) "
        "VALUES ('" + sql_escape(event_id) + "','" + sql_escape(room_id) +
        "','m.room.canonical_alias','','" + sql_escape(content_str) + "')");
  }

  // Check if alias is available
  bool is_alias_available(const std::string& alias) {
    auto rows = db_.execute(
        "check_alias",
        "SELECT room_id FROM room_aliases WHERE room_alias='" +
        sql_escape(alias) + "'");
    return rows.empty();
  }

  // Get all published aliases (for room directory)
  std::vector<std::pair<std::string, std::string>> get_published_aliases() {
    auto rows = db_.execute(
        "get_published_aliases",
        "SELECT room_id, room_alias FROM room_aliases "
        "ORDER BY room_alias ASC");

    std::vector<std::pair<std::string, std::string>> result;
    for (const auto& row : rows) {
      std::string rid, alias;
      for (const auto& col : row) {
        if (col.name == "room_id" && col.value) rid = *col.value;
        if (col.name == "room_alias" && col.value) alias = *col.value;
      }
      if (!rid.empty() && !alias.empty()) {
        result.emplace_back(rid, alias);
      }
    }
    return result;
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// RoomDisplayNameFormatter - final formatting helpers
// ============================================================================

class RoomDisplayNameFormatter {
public:
  // Format display name for a room in a notification
  static std::string format_notification_name(const RoomSummary& summary,
                                               const std::string& sender_name) {
    if (!summary.name.empty()) {
      return summary.name;
    }
    if (summary.is_direct && !summary.heroes.empty()) {
      return summary.heroes[0].display_name;
    }
    if (!summary.heroes.empty()) {
      std::string names;
      for (size_t i = 0; i < std::min(summary.heroes.size(), size_t(3)); i++) {
        if (i > 0) names += ", ";
        names += summary.heroes[i].display_name;
      }
      return names;
    }
    return summary.canonical_alias.empty() ? summary.room_id : summary.canonical_alias;
  }

  // Format for room list display
  static std::string format_room_list_name(const RoomSummary& summary,
                                             const std::string& viewer_id) {
    // For DMs, show the other person's name
    if (summary.is_direct && summary.heroes.size() >= 2) {
      for (const auto& h : summary.heroes) {
        if (h.user_id != viewer_id) {
          if (!h.display_name.empty()) return h.display_name;
          return extract_localpart(h.user_id);
        }
      }
    }

    // Use room name if set
    if (!summary.name.empty()) return summary.name;

    // Use canonical alias
    if (!summary.canonical_alias.empty()) return summary.canonical_alias;

    // Use heroes
    if (!summary.heroes.empty()) {
      std::string names;
      size_t count = 0;
      for (const auto& h : summary.heroes) {
        if (h.user_id == viewer_id) continue;
        if (count > 0) names += ", ";
        names += h.display_name.empty() ? extract_localpart(h.user_id) : h.display_name;
        count++;
        if (count >= 3) break;
      }
      if (!names.empty()) return names;
    }

    return summary.room_id;
  }

  // Format for push notification title
  static std::string format_push_title(const RoomSummary& summary,
                                         const std::string& sender_name,
                                         const std::string& message_preview) {
    std::string title;

    if (summary.is_direct) {
      title = sender_name;
    } else {
      title = format_notification_name(summary, sender_name);
      if (!sender_name.empty()) {
        title += " (" + sender_name + ")";
      }
    }

    if (!message_preview.empty()) {
      title += ": " + message_preview;
    }

    return title;
  }

  // Generate room avatar URL for the client
  static std::string format_room_avatar(const RoomSummary& summary,
                                          const std::string& base_url) {
    if (!summary.avatar_url.empty()) {
      if (summary.avatar_url.find("mxc://") == 0) {
        return base_url + "/_matrix/media/v3/thumbnail/" +
               summary.avatar_url.substr(6) + "?width=96&height=96&method=crop";
      }
      return summary.avatar_url;
    }

    // Generate from heroes for DMs
    if (summary.is_direct && summary.heroes.size() >= 2) {
      for (const auto& h : summary.heroes) {
        if (!h.avatar_url.empty()) {
          if (h.avatar_url.find("mxc://") == 0) {
            return base_url + "/_matrix/media/v3/thumbnail/" +
                   h.avatar_url.substr(6) + "?width=96&height=96&method=crop";
          }
          return h.avatar_url;
        }
      }
    }

    return "";
  }
};

// ============================================================================
// RoomSummaryManager - Facade / orchestration class
// ============================================================================

class RoomSummaryManager {
public:
  RoomSummaryManager(DatabasePool& db)
      : db_(db),
        computation_(db),
        aggregator_(db),
        sync_builder_(db),
        notif_state_(db),
        activity_tracker_(db),
        alias_resolver_(db) {}

  // Get a complete room summary for any context
  json get_room_summary(const std::string& room_id,
                         const std::string& user_id = "",
                         const std::string& context = "sync") {
    if (context == "sync" || context == "initial_sync") {
      return sync_builder_.build_sync_summary(room_id, user_id);
    } else if (context == "full") {
      return sync_builder_.build_full_summary(room_id, user_id);
    } else if (context == "left") {
      return sync_builder_.build_left_room_summary(room_id, user_id);
    } else if (context == "preview") {
      return computation_.compute_room_preview(room_id, user_id);
    } else if (context == "invite") {
      return sync_builder_.build_invite_summary(room_id, user_id, user_id);
    }
    return computation_.compute_room_summary_json(room_id, user_id);
  }

  // Handle a new event in a room (invalidate caches, update activity)
  void on_room_event(const std::string& room_id,
                      const std::string& event_type,
                      const std::string& state_key = "") {
    // Invalidate caches
    computation_.invalidate_cache(room_id);

    // Record activity
    activity_tracker_.record_activity(room_id, now_ms());

    // Specific event type handling
    if (event_type == "m.room.name") {
      computation_.invalidate_cache(room_id);
    } else if (event_type == "m.room.member") {
      // Membership changed - invalidate member counts and heroes
      computation_.invalidate_cache(room_id);
    } else if (event_type == "m.room.avatar") {
      computation_.invalidate_cache(room_id);
    } else if (event_type == "m.room.canonical_alias") {
      computation_.invalidate_cache(room_id);
    } else if (event_type == "m.room.topic") {
      computation_.invalidate_cache(room_id);
    }
  }

  // Warm caches for efficient sync
  void prepare_sync(const std::string& user_id) {
    aggregator_.warm_sync_caches(user_id);
  }

  // Get notification state
  json get_notification_state(const std::string& room_id,
                               const std::string& user_id) {
    return notif_state_.get_notification_state(room_id, user_id);
  }

  // Mark room as read
  void mark_read(const std::string& room_id, const std::string& user_id,
                  const std::string& event_id) {
    notif_state_.mark_room_read(room_id, user_id, event_id);
  }

  // Access individual components
  RoomSummaryComputation& computation() { return computation_; }
  RoomSummaryAggregator& aggregator() { return aggregator_; }
  RoomSyncSummaryBuilder& sync_builder() { return sync_builder_; }
  RoomNotificationState& notification_state() { return notif_state_; }
  RoomActivityTracker& activity_tracker() { return activity_tracker_; }
  RoomAliasResolver& alias_resolver() { return alias_resolver_; }

private:
  DatabasePool& db_;
  RoomSummaryComputation computation_;
  RoomSummaryAggregator aggregator_;
  RoomSyncSummaryBuilder sync_builder_;
  RoomNotificationState notif_state_;
  RoomActivityTracker activity_tracker_;
  RoomAliasResolver alias_resolver_;
};

// ============================================================================
// Global room summary singleton (thread-safe)
// ============================================================================

static std::mutex g_manager_mutex;
static std::unique_ptr<RoomSummaryManager> g_room_summary_manager;

void initialize_room_summary(DatabasePool& db) {
  std::lock_guard<std::mutex> lock(g_manager_mutex);
  g_room_summary_manager = std::make_unique<RoomSummaryManager>(db);
}

RoomSummaryManager& get_room_summary_manager() {
  std::lock_guard<std::mutex> lock(g_manager_mutex);
  if (!g_room_summary_manager) {
    throw std::runtime_error("RoomSummaryManager not initialized. "
                              "Call initialize_room_summary() first.");
  }
  return *g_room_summary_manager;
}

// ============================================================================
// Convenience free functions for sync handler integration
// ============================================================================

json compute_room_summary_for_sync(const std::string& room_id,
                                    const std::string& user_id) {
  return get_room_summary_manager().get_room_summary(room_id, user_id, "sync");
}

json compute_room_summary_full(const std::string& room_id,
                                 const std::string& user_id) {
  return get_room_summary_manager().get_room_summary(room_id, user_id, "full");
}

std::string compute_room_display_name(const std::string& room_id,
                                       const std::string& user_id) {
  auto& mgr = get_room_summary_manager();
  return mgr.computation().compute_room_name(room_id, user_id);
}

std::string compute_room_avatar_url(const std::string& room_id) {
  auto& mgr = get_room_summary_manager();
  return mgr.computation().compute_room_avatar(room_id);
}

int compute_joined_member_count(const std::string& room_id) {
  auto& mgr = get_room_summary_manager();
  return mgr.computation().get_joined_member_count(room_id);
}

int compute_invited_member_count(const std::string& room_id) {
  auto& mgr = get_room_summary_manager();
  return mgr.computation().get_invited_member_count(room_id);
}

bool compute_is_direct_room(const std::string& room_id,
                              const std::string& user_id) {
  auto& mgr = get_room_summary_manager();
  return mgr.computation().is_direct_room(room_id, user_id);
}

json compute_room_heroes(const std::string& room_id, int count) {
  auto& mgr = get_room_summary_manager();
  auto heroes = mgr.computation().select_heroes(room_id, count);

  json result = json::array();
  for (const auto& h : heroes) {
    json hj;
    hj["user_id"] = h.user_id;
    if (!h.display_name.empty()) hj["display_name"] = h.display_name;
    if (!h.avatar_url.empty()) hj["avatar_url"] = h.avatar_url;
    result.push_back(hj);
  }
  return result;
}

json compute_unread_counts(const std::string& room_id,
                            const std::string& user_id) {
  auto& mgr = get_room_summary_manager();
  return mgr.computation().get_unread_counts(room_id, user_id);
}

void on_room_event_invalidate(const std::string& room_id,
                                const std::string& event_type,
                                const std::string& state_key) {
  if (g_room_summary_manager) {
    g_room_summary_manager->on_room_event(room_id, event_type, state_key);
  }
}

void warm_room_summary_cache(const std::string& user_id) {
  if (g_room_summary_manager) {
    g_room_summary_manager->prepare_sync(user_id);
  }
}

// ============================================================================
// Room summary event listener for cache invalidation
// ============================================================================

class RoomSummaryEventListener {
public:
  RoomSummaryEventListener() = default;

  void on_state_event(const std::string& room_id,
                       const std::string& event_type,
                       const std::string& state_key) {
    if (!g_room_summary_manager) return;

    // Invalidate on relevant state changes
    if (event_type == "m.room.name" ||
        event_type == "m.room.avatar" ||
        event_type == "m.room.topic" ||
        event_type == "m.room.canonical_alias" ||
        event_type == "m.room.join_rules" ||
        event_type == "m.room.guest_access" ||
        event_type == "m.room.history_visibility" ||
        event_type == "m.room.encryption" ||
        event_type == "m.room.create") {
      g_room_summary_manager->computation().invalidate_cache(room_id);
    }
  }

  void on_membership_event(const std::string& room_id,
                            const std::string& user_id,
                            const std::string& membership) {
    if (!g_room_summary_manager) return;

    // Membership changes affect heroes, counts, and DM status
    g_room_summary_manager->computation().invalidate_cache(room_id);

    // Record activity
    g_room_summary_manager->activity_tracker().record_activity(room_id, now_ms());
  }

  void on_message_event(const std::string& room_id,
                          const std::string& sender,
                          const std::string& event_type) {
    if (!g_room_summary_manager) return;

    // Message events update activity timestamps
    g_room_summary_manager->activity_tracker().record_activity(room_id, now_ms());
  }

  void on_receipt_event(const std::string& room_id,
                          const std::string& user_id,
                          const std::string& event_id) {
    if (!g_room_summary_manager) return;

    // Read receipts reset notification counts
    g_room_summary_manager->mark_read(room_id, user_id, event_id);
  }
};

// ============================================================================
// RoomSummaryBackgroundUpdater - periodic cache maintenance
// ============================================================================

class RoomSummaryBackgroundUpdater {
public:
  RoomSummaryBackgroundUpdater(DatabasePool& db, int interval_seconds = 300)
      : db_(db), interval_seconds_(interval_seconds), running_(false) {}

  void start() {
    if (running_) return;
    running_ = true;
    worker_thread_ = std::thread(&RoomSummaryBackgroundUpdater::run, this);
  }

  void stop() {
    running_ = false;
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
  }

  ~RoomSummaryBackgroundUpdater() {
    stop();
  }

private:
  DatabasePool& db_;
  int interval_seconds_;
  std::atomic<bool> running_;
  std::thread worker_thread_;

  void run() {
    while (running_) {
      try {
        // Get active rooms that need cache refresh
        int64_t threshold = now_ms() - (interval_seconds_ * 1000);

        auto rows = db_.execute(
            "get_stale_rooms",
            "SELECT room_id FROM room_activity WHERE last_activity_ts > " +
            std::to_string(threshold) + " ORDER BY last_activity_ts DESC LIMIT 100");

        if (g_room_summary_manager) {
          for (const auto& row : rows) {
            for (const auto& col : row) {
              if (col.name == "room_id" && col.value) {
                // Warm cache for this room
                g_room_summary_manager->computation()
                    .warm_cache(*col.value, "");
                break;
              }
            }
          }
        }

        // Clean up old activity records (older than 30 days)
        int64_t old_threshold = now_ms() - (30 * 24 * 3600 * 1000LL);
        auto& tracker = g_room_summary_manager ?
            g_room_summary_manager->activity_tracker() :
            RoomActivityTracker(db_);
        tracker.cleanup_old_activity(old_threshold);

      } catch (const std::exception& e) {
        // Log and continue
        (void)e;
      }

      // Sleep for interval
      for (int i = 0; i < interval_seconds_ && running_; i++) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    }
  }
};

// ============================================================================
// Public API: batch room summary for initial sync
// ============================================================================

json batch_compute_room_summaries(DatabasePool& db,
                                   const std::vector<std::string>& room_ids,
                                   const std::string& user_id) {
  RoomSummaryComputation computation(db);
  json result = json::object();

  for (const auto& rid : room_ids) {
    try {
      result[rid] = computation.compute_room_summary_json(rid, user_id);
    } catch (const std::exception& e) {
      json error;
      error["error"] = e.what();
      error["room_id"] = rid;
      result[rid] = error;
    }
  }

  return result;
}

// ============================================================================
// Public API: room name generation for arbitrary member sets
// ============================================================================

std::string generate_room_name_from_members(
    const std::vector<std::string>& member_ids,
    DatabasePool& db,
    const std::string& viewer_user_id) {

  if (member_ids.empty()) return "Empty Room";

  // Get display names
  std::vector<std::string> names;
  std::vector<std::string> filtered_ids;

  for (const auto& uid : member_ids) {
    if (uid == viewer_user_id) continue;
    filtered_ids.push_back(uid);
  }

  if (filtered_ids.empty()) {
    if (member_ids.size() == 1 && member_ids[0] == viewer_user_id) {
      return "Empty Room";
    }
    filtered_ids = member_ids;
  }

  // Load display names from DB
  for (const auto& uid : filtered_ids) {
    auto rows = db.execute(
        "get_display_name_public",
        "SELECT display_name FROM profiles WHERE user_id='" +
        sql_escape(uid) + "'");

    std::string dn;
    if (!rows.empty()) {
      for (const auto& col : rows[0]) {
        if (col.name == "display_name" && col.value && !col.value->empty()) {
          dn = *col.value;
          break;
        }
      }
    }
    if (dn.empty()) dn = extract_localpart(uid);
    names.push_back(dn);
  }

  if (names.size() == 1) {
    return names[0];
  } else if (names.size() == 2) {
    return names[0] + " and " + names[1];
  } else if (names.size() >= 3) {
    return names[0] + ", " + names[1] + " and " +
           std::to_string(names.size() - 2) + " others";
  }

  return "Empty Room";
}

}  // namespace progressive::handlers
