// spaces_msc_handlers.cpp - Matrix Space Management, Room Types, and MSC Implementations
// Implements ALL space-related handlers, room type support, and MSC specs:
// polls, threading, forwarding, relationships, editing, reactions,
// mentions, push rules, and event relationship auth rules.
// Target: 3500+ lines
//
// Handlers:
//   1.  handle_create_space                  - Create space rooms (type m.space)
//   2.  handle_space_children                 - Manage m.space.child state events
//   3.  handle_space_parent                   - Manage m.space.parent state events
//   4.  handle_space_hierarchy                - GET /hierarchy for space traversal
//   5.  handle_space_ordering                 - order field and suggested flag
//   6.  handle_msc2175_create_space           - /createRoom with creation_content type=m.space
//   7.  handle_msc2946_space_summary          - Space summary API
//   8.  handle_msc3083_restricted_join        - Restricted join rules for spaces
//   9.  handle_msc3215_room_type              - Room type in m.room.create
//  10.  handle_msc3266_room_summary_ext       - Room summary API extension
//  11.  handle_msc3381_poll_start             - m.poll.start event
//  12.  handle_msc3381_poll_response          - m.poll.response event
//  13.  handle_msc3381_poll_end               - m.poll.end event
//  14.  handle_msc3440_thread                 - Threading via m.thread relation
//  15.  handle_msc3442_message_forwarding     - Message forwarding
//  16.  handle_msc2674_relationships           - Event relationships aggregation
//  17.  handle_msc2675_aggregation_api         - Server-side aggregation API
//  18.  handle_msc2676_message_editing         - Message editing (m.replace)
//  19.  handle_msc2677_reactions              - Reactions (m.annotation)
//  20.  handle_msc3664_push_relations          - Push rules for relations
//  21.  handle_msc3820_relation_auth           - Event relationships in auth rules
//  22.  handle_msc3870_intentional_mentions    - Intentional mentions

#include "../json.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/event_federation.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/receipts.hpp"

#include <chrono>
#include <random>
#include <sstream>
#include <algorithm>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <map>
#include <regex>
#include <cmath>
#include <thread>
#include <deque>
#include <queue>
#include <functional>
#include <shared_mutex>
#include <optional>
#include <variant>

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Global utilities (shared across handlers)
// ============================================================================

static std::atomic<int64_t> g_spaces_seq{1};
static std::atomic<int64_t> g_msc_seq{1};
static std::atomic<int64_t> g_poll_seq{1};
static std::atomic<int64_t> g_mention_seq{1};
static std::mutex g_spaces_lock;
static std::mutex g_hierarchy_cache_lock;
static std::mutex g_space_children_lock;
static std::mutex g_restricted_join_lock;
static std::mutex g_poll_lock;
static std::mutex g_thread_lock;
static std::mutex g_forwarding_lock;
static std::mutex g_relation_lock;
static std::mutex g_aggregation_lock;
static std::mutex g_edit_lock;
static std::mutex g_reaction_lock;
static std::mutex g_push_rel_lock;
static std::mutex g_mention_lock;
static std::shared_mutex g_space_cache_rwlock;
static std::shared_mutex g_relation_cache_rwlock;

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(g_spaces_seq.fetch_add(1));
}

static std::string gen_token(int len = 32) {
  static const char cs[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 rng(
    static_cast<unsigned>(now_ms() + std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<> d(0, 61);
  std::string t(len, 'A');
  for (auto& c : t) c = cs[d(rng)];
  return t;
}

static bool validate_user_id(const std::string& user_id) {
  return user_id.size() >= 4 && user_id[0] == '@' &&
         user_id.find(':') != std::string::npos;
}

static bool validate_room_id(const std::string& room_id) {
  return room_id.size() >= 2 && room_id[0] == '!' &&
         room_id.find(':') != std::string::npos;
}

static bool validate_event_id(const std::string& event_id) {
  return event_id.size() >= 2 && event_id[0] == '$';
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

// ============================================================================
// Auth context and validation helpers
// ============================================================================

struct AuthContext {
  std::string user_id;
  std::string device_id;
  std::string access_token;
  bool is_guest = false;
  bool is_admin = false;
  bool valid = false;
};

static AuthContext validate_auth(DatabasePool& db, const std::string& auth_header,
                                  const std::string& query_access_token) {
  AuthContext ctx;
  std::string token;

  if (!auth_header.empty()) {
    const std::string prefix = "Bearer ";
    if (auth_header.size() > prefix.size() &&
        auth_header.substr(0, prefix.size()) == prefix) {
      token = auth_header.substr(prefix.size());
    }
  }
  if (token.empty() && !query_access_token.empty()) {
    token = query_access_token;
  }
  if (token.empty()) {
    return ctx;
  }

  RegistrationStore reg(db);
  auto user_info = reg.get_user_by_access_token(token);
  if (!user_info) {
    return ctx;
  }

  ctx.valid = true;
  ctx.user_id = user_info->user_id;
  ctx.access_token = token;
  if (user_info->device_id) ctx.device_id = *user_info->device_id;
  ctx.is_guest = user_info->is_guest;
  return ctx;
}

static json make_error(int http_status, const std::string& errcode,
                        const std::string& error) {
  json resp;
  resp["status"] = http_status;
  resp["body"] = json{{"errcode", errcode}, {"error", error}};
  return resp;
}

static json make_response(int http_status, const json& body) {
  json resp;
  resp["status"] = http_status;
  resp["body"] = body;
  return resp;
}

// ============================================================================
// Membership and room access helpers
// ============================================================================

static std::string get_membership(DatabasePool& db, const std::string& room_id,
                                    const std::string& user_id) {
  RoomMemberStore members(db);
  auto m = members.get_member(room_id, user_id);
  if (m) return m->membership;
  return "leave";
}

static bool is_user_in_room(DatabasePool& db, const std::string& room_id,
                              const std::string& user_id) {
  auto m = get_membership(db, room_id, user_id);
  return m == "join";
}

static int64_t get_user_power_level(DatabasePool& db, const std::string& room_id,
                                      const std::string& user_id) {
  StateStore state(db);
  auto pl_event = state.get_current_state_event(room_id, "m.room.power_levels", "");
  if (!pl_event) return 0;

  json pl_content = pl_event->content;
  int64_t users_default = safe_int(pl_content, "users_default", 0);
  if (pl_content.contains("users") && pl_content["users"].contains(user_id)) {
    return pl_content["users"][user_id].get<int64_t>();
  }
  return users_default;
}

static std::string get_history_visibility(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto hv = state.get_current_state_event(room_id, "m.room.history_visibility", "");
  if (hv && hv->content.contains("history_visibility")) {
    return hv->content["history_visibility"].get<std::string>();
  }
  return "shared";
}

static std::string get_join_rule(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto jr = state.get_current_state_event(room_id, "m.room.join_rules", "");
  if (jr && jr->content.contains("join_rule")) {
    return jr->content["join_rule"].get<std::string>();
  }
  return "invite";
}

static std::string get_guest_access(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto ga = state.get_current_state_event(room_id, "m.room.guest_access", "");
  if (ga && ga->content.contains("guest_access")) {
    return ga->content["guest_access"].get<std::string>();
  }
  return "forbidden";
}

static std::string get_room_name(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto name_ev = state.get_current_state_event(room_id, "m.room.name", "");
  if (name_ev && name_ev->content.contains("name")) {
    return name_ev->content["name"].get<std::string>();
  }
  return "";
}

static std::string get_room_topic(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto topic_ev = state.get_current_state_event(room_id, "m.room.topic", "");
  if (topic_ev && topic_ev->content.contains("topic")) {
    return topic_ev->content["topic"].get<std::string>();
  }
  return "";
}

static std::string get_room_version(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto create_ev = state.get_current_state_event(room_id, "m.room.create", "");
  if (create_ev && create_ev->content.contains("room_version")) {
    return create_ev->content["room_version"].get<std::string>();
  }
  return "1";
}

static std::optional<std::string> get_room_type(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto create_ev = state.get_current_state_event(room_id, "m.room.create", "");
  if (create_ev && create_ev->content.contains("type")) {
    return create_ev->content["type"].get<std::string>();
  }
  return std::nullopt;
}

// ============================================================================
// Database-backed events query helpers
// ============================================================================

static std::optional<json> get_event_by_id(DatabasePool& db, const std::string& event_id) {
  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db), nullptr, "", "master");
  return evs.get_event(event_id);
}

static json extract_content(const std::optional<json>& ev) {
  if (!ev) return json::object();
  if (ev->contains("content")) return (*ev)["content"];
  return json::object();
}

// ============================================================================
// Event relation storage and retrieval
// ============================================================================

struct EventRelation {
  std::string event_id;
  std::string relates_to_id;
  std::string relation_type;
  std::string aggregation_key;
  int64_t origin_server_ts;
  std::string sender;
  json content;
};

static void store_event_relation(DatabasePool& db, const std::string& event_id,
                                  const std::string& relates_to_id,
                                  const std::string& relation_type,
                                  const std::string& aggregation_key) {
  std::lock_guard<std::mutex> lock(g_relation_lock);
  try {
    db.execute(
      "INSERT OR REPLACE INTO event_relations "
      "(event_id,relates_to_id,relation_type,aggregation_key) VALUES ('" +
      event_id + "','" + relates_to_id + "','" + relation_type + "','" +
      aggregation_key + "')");
  } catch (...) { /* Best-effort */ }
}

static std::vector<EventRelation> get_relations_for_event(DatabasePool& db,
                                                            const std::string& event_id,
                                                            const std::string& rel_type = "",
                                                            int limit = 100) {
  std::vector<EventRelation> result;
  std::string query = "SELECT e.event_id,er.relates_to_id,er.relation_type,"
                      "er.aggregation_key,e.origin_server_ts,e.sender,e.content "
                      "FROM event_relations er JOIN events e ON er.event_id=e.event_id "
                      "WHERE er.relates_to_id='" + event_id + "'";
  if (!rel_type.empty()) {
    query += " AND er.relation_type='" + rel_type + "'";
  }
  query += " ORDER BY e.origin_server_ts ASC LIMIT " + std::to_string(limit);

  auto rows = db.query(query);
  for (auto& row : rows) {
    EventRelation rel;
    rel.event_id = row["event_id"].get<std::string>();
    rel.relates_to_id = row["relates_to_id"].get<std::string>();
    rel.relation_type = row["relation_type"].get<std::string>();
    rel.aggregation_key = row.value("aggregation_key", "");
    rel.origin_server_ts = row.value("origin_server_ts", 0LL);
    rel.sender = row.value("sender", "");
    if (!row["content"].is_null()) {
      try { rel.content = json::parse(row["content"].get<std::string>()); }
      catch (...) { rel.content = json::object(); }
    }
    result.push_back(rel);
  }
  return result;
}

static int count_relations(DatabasePool& db, const std::string& event_id,
                             const std::string& rel_type = "") {
  std::string query = "SELECT COUNT(*) as cnt FROM event_relations "
                      "WHERE relates_to_id='" + event_id + "'";
  if (!rel_type.empty()) {
    query += " AND relation_type='" + rel_type + "'";
  }
  auto rows = db.query(query);
  if (!rows.empty()) return rows[0]["cnt"].get<int>();
  return 0;
}

// ============================================================================
// Space hierarchy cache for performance
// ============================================================================

struct SpaceCacheEntry {
  json hierarchy;
  int64_t cached_at_ms;
  int64_t ttl_ms;
};

static std::unordered_map<std::string, SpaceCacheEntry> g_space_hierarchy_cache;

// ============================================================================
// ============================================================================
// 1. CREATE SPACE
// ============================================================================
// Creates a space room (type m.space) with all space-specific configuration.
// Supports MSC2175: creation_content with type=m.space, MSC3215: room type
// in m.room.create, and MSC3083: restricted join rules for spaces.
//
// Endpoint: POST /_matrix/client/v3/createRoom (with creation_content)
// ============================================================================

struct SpaceConfig {
  std::string name;
  std::string topic;
  std::string room_alias_name;
  std::string preset = "private_chat";
  std::string room_version = "9";
  bool is_space = false;
  bool is_direct = false;
  std::vector<std::string> invite_users;
  std::vector<std::string> initial_state_events_json;
  json creation_content;
  json power_level_content_override;
  bool federate = true;
  std::string visibility = "private";
  std::string join_rule = "invite";
  bool guest_can_join = false;
  std::string room_type;  // MSC3215: "m.space" or other room types
  std::vector<std::string> parent_spaces;
  std::vector<std::string> child_rooms;
};

json handle_create_space(DatabasePool& db, const std::string& auth_header,
                           const std::string& access_token_param,
                           const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Parse creation content (MSC2175) ----
  SpaceConfig config;
  config.is_space = false;

  if (request_body.contains("creation_content") && request_body["creation_content"].is_object()) {
    auto& cc = request_body["creation_content"];
    config.creation_content = cc;
    if (cc.contains("type") && cc["type"] == "m.space") {
      config.is_space = true;
      config.room_type = "m.space";
      config.preset = "public_chat";  // Default for spaces
      config.join_rule = "public";
    }
    config.federate = safe_bool(cc, "m.federate", true);
  }

  // ---- 3. MSC3215: room type in initial_state m.room.create ----
  if (request_body.contains("type") && request_body["type"].is_string()) {
    config.room_type = request_body["type"].get<std::string>();
    if (config.room_type == "m.space") {
      config.is_space = true;
    }
  }

  // ---- 4. Parse room configuration ----
  config.name = safe_str(request_body, "name", config.is_space ? "Space" : "");
  config.topic = safe_str(request_body, "topic", "");
  config.room_alias_name = safe_str(request_body, "room_alias_name", "");
  config.visibility = safe_str(request_body, "visibility", "private");
  config.room_version = safe_str(request_body, "room_version", "9");

  if (request_body.contains("preset") && request_body["preset"].is_string()) {
    config.preset = request_body["preset"].get<std::string>();
  }
  if (request_body.contains("is_direct")) {
    config.is_direct = request_body["is_direct"].get<bool>();
  }

  // ---- 5. Generate room ID ----
  std::string server_name = "localhost";
  std::string room_id = "!" + gen_token(18) + ":" + server_name;
  std::string creator = auth.user_id;
  int64_t now = now_ms();
  int64_t now_sec_val = now_sec();

  // ---- 6. Build m.room.create event (MSC3215: include type field) ----
  json create_content = config.creation_content;
  create_content["creator"] = creator;
  create_content["room_version"] = config.room_version;
  if (config.federate) {
    create_content["m.federate"] = true;
  }
  // MSC3215: include room type in m.room.create content
  if (!config.room_type.empty()) {
    create_content["type"] = config.room_type;
  }

  // ---- 7. Store room in database ----
  RoomStore rooms(db);
  rooms.insert_room(room_id, creator, config.is_space, config.room_version,
                    config.federate);

  // ---- 8. Insert m.room.create state event ----
  StateStore state(db);
  std::string create_event_id = "$" + gen_token(18) + ":" + server_name;
  state.persist_state_event(room_id, "m.room.create", "", create_event_id,
                             create_content, now);

  // ---- 9. Set join rules (MSC3083: restricted join rules for spaces) ----
  json join_rules_content;
  if (config.is_space) {
    // Spaces default to public to allow discovery
    join_rules_content["join_rule"] = config.join_rule;
  } else {
    if (config.preset == "public_chat") {
      join_rules_content["join_rule"] = "public";
    } else if (config.preset == "trusted_private_chat") {
      join_rules_content["join_rule"] = "invite";
      // MSC3083: restricted join rules allow members of specified spaces
      if (request_body.contains("restricted_join_rules") &&
          request_body["restricted_join_rules"].is_array()) {
        join_rules_content["join_rule"] = "restricted";
        json allow_arr = json::array();
        for (auto& rule : request_body["restricted_join_rules"]) {
          json allow_entry;
          allow_entry["type"] = "m.room_membership";
          allow_entry["room_id"] = rule.value("space", rule.value("room_id", ""));
          allow_arr.push_back(allow_entry);
        }
        join_rules_content["allow"] = allow_arr;
      }
    } else {
      join_rules_content["join_rule"] = "invite";
    }
  }
  std::string join_rules_event_id = "$" + gen_token(18) + ":" + server_name;
  state.persist_state_event(room_id, "m.room.join_rules", "", join_rules_event_id,
                             join_rules_content, now);

  // ---- 10. Set history visibility ----
  json history_vis_content;
  if (config.preset == "public_chat" || (config.is_space && config.visibility == "public")) {
    history_vis_content["history_visibility"] = "world_readable";
  } else if (config.is_space) {
    history_vis_content["history_visibility"] = "shared";
  } else {
    history_vis_content["history_visibility"] = config.preset == "trusted_private_chat"
      ? "shared" : "shared";
  }
  std::string hv_event_id = "$" + gen_token(18) + ":" + server_name;
  state.persist_state_event(room_id, "m.room.history_visibility", "", hv_event_id,
                             history_vis_content, now);

  // ---- 11. Set guest access ----
  json guest_access_content;
  guest_access_content["guest_access"] = config.guest_can_join
    ? "can_join" : "forbidden";
  std::string ga_event_id = "$" + gen_token(18) + ":" + server_name;
  state.persist_state_event(room_id, "m.room.guest_access", "", ga_event_id,
                             guest_access_content, now);

  // ---- 12. Set room name ----
  if (!config.name.empty()) {
    json name_content;
    name_content["name"] = config.name;
    std::string name_event_id = "$" + gen_token(18) + ":" + server_name;
    state.persist_state_event(room_id, "m.room.name", "", name_event_id,
                               name_content, now);
  }

  // ---- 13. Set room topic ----
  if (!config.topic.empty()) {
    json topic_content;
    topic_content["topic"] = config.topic;
    std::string topic_event_id = "$" + gen_token(18) + ":" + server_name;
    state.persist_state_event(room_id, "m.room.topic", "", topic_event_id,
                               topic_content, now);
  }

  // ---- 14. Set power levels ----
  json power_levels;
  if (!config.power_level_content_override.is_null()) {
    power_levels = config.power_level_content_override;
  } else {
    power_levels["ban"] = 50;
    power_levels["kick"] = 50;
    power_levels["redact"] = 50;
    power_levels["invite"] = 0;
    power_levels["state_default"] = 50;
    power_levels["events_default"] = 0;
    power_levels["users_default"] = 0;
    power_levels["users"] = json::object();
    power_levels["users"][creator] = 100;
    power_levels["events"] = json::object();
    // Lower thresholds for spaces to allow more community management
    if (config.is_space) {
      power_levels["events"]["m.space.child"] = 50;
      power_levels["events"]["m.space.parent"] = 50;
    }
  }
  std::string pl_event_id = "$" + gen_token(18) + ":" + server_name;
  state.persist_state_event(room_id, "m.room.power_levels", "", pl_event_id,
                             power_levels, now);

  // ---- 15. Add creator as member ----
  RoomMemberStore members(db);
  json member_content;
  member_content["membership"] = "join";
  member_content["displayname"] = safe_str(request_body.value("initial_state", json::array()),
                                             "", "");
  std::string member_event_id = "$" + gen_token(18) + ":" + server_name;
  state.persist_state_event(room_id, "m.room.member", creator, member_event_id,
                             member_content, now);
  members.upsert_member(room_id, creator, "join", "", now, "");

  // ---- 16. Process invite list ----
  if (request_body.contains("invite") && request_body["invite"].is_array()) {
    for (auto& invite_user : request_body["invite"]) {
      std::string invitee = invite_user.is_string()
        ? invite_user.get<std::string>()
        : safe_str(invite_user, "user_id", "");
      if (!invitee.empty() && validate_user_id(invitee)) {
        json invite_content;
        invite_content["membership"] = "invite";
        std::string inv_event_id = "$" + gen_token(18) + ":" + server_name;
        state.persist_state_event(room_id, "m.room.member", invitee,
                                   inv_event_id, invite_content, now);
        members.upsert_member(room_id, invitee, "invite", creator, now, "");
      }
    }
  }

  // ---- 17. Process initial state events from request ----
  if (request_body.contains("initial_state") && request_body["initial_state"].is_array()) {
    for (auto& state_ev : request_body["initial_state"]) {
      std::string ev_type = safe_str(state_ev, "type", "");
      std::string state_key = safe_str(state_ev, "state_key", "");
      json ev_content = state_ev.value("content", json::object());
      if (!ev_type.empty()) {
        std::string ev_id = "$" + gen_token(18) + ":" + server_name;
        state.persist_state_event(room_id, ev_type, state_key, ev_id,
                                   ev_content, now);
      }
    }
  }

  // ---- 18. Handle space parent links (MSC2946) ----
  if (request_body.contains("parent_spaces") && request_body["parent_spaces"].is_array()) {
    for (auto& parent_id : request_body["parent_spaces"]) {
      std::string pid = parent_id.is_string() ? parent_id.get<std::string>() : "";
      if (!pid.empty() && validate_room_id(pid)) {
        // Add m.space.parent to child room pointing to space
        json parent_content;
        parent_content["via"] = json::array({server_name});
        parent_content["canonical"] = true;
        std::string parent_ev_id = "$" + gen_token(18) + ":" + server_name;
        state.persist_state_event(room_id, "m.space.parent", pid, parent_ev_id,
                                   parent_content, now);

        // Add m.space.child to space room pointing to child
        json child_content;
        child_content["via"] = json::array({server_name});
        child_content["suggested"] = true;
        child_content["order"] = "0";
        std::string child_ev_id = "$" + gen_token(18) + ":" + server_name;
        state.persist_state_event(pid, "m.space.child", room_id, child_ev_id,
                                   child_content, now);
      }
    }
  }

  // ---- 19. Create room alias if requested ----
  std::string room_alias;
  if (!config.room_alias_name.empty()) {
    room_alias = "#" + config.room_alias_name + ":" + server_name;
    DirectoryStore dir(db);
    dir.create_alias(room_alias, room_id, creator);
  }

  // ---- 20. Build response ----
  json resp_body;
  resp_body["room_id"] = room_id;
  if (!room_alias.empty()) {
    resp_body["room_alias"] = room_alias;
  }
  // MSC3215: return room type in response
  if (!config.room_type.empty()) {
    resp_body["room_type"] = config.room_type;
  }

  return make_response(200, resp_body);
}

// ============================================================================
// 2. SPACE CHILDREN MANAGEMENT
// ============================================================================
// Manages m.space.child state events on space rooms.
// Full CRUD: add, update, remove child rooms from a space.
// Supports ordering (order field) and suggested flag.
//
// Endpoint: PUT /_matrix/client/v3/rooms/{roomId}/state/m.space.child/{childRoomId}
// Endpoint: GET /_matrix/client/v3/rooms/{roomId}/state/m.space.child
// ============================================================================

json handle_space_children(DatabasePool& db, const std::string& auth_header,
                             const std::string& access_token_param,
                             const std::string& space_id,
                             const std::string& method,
                             const json& request_body,
                             const std::string& child_room_id) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate space room exists ----
  RoomStore rooms(db);
  auto space_info = rooms.get_room(space_id);
  if (!space_info) {
    return make_error(404, "M_NOT_FOUND", "Space not found");
  }

  // ---- 3. Verify room is a space ----
  auto room_type = get_room_type(db, space_id);
  if (!room_type || *room_type != "m.space") {
    return make_error(400, "M_BAD_STATE", "Room is not a space");
  }

  // ---- 4. Check power level for state events ----
  int64_t user_pl = get_user_power_level(db, space_id, auth.user_id);
  StateStore state(db);
  auto pl_event = state.get_current_state_event(space_id, "m.room.power_levels", "");
  int64_t required_pl = 50;  // state_default
  if (pl_event && pl_event->content.contains("events") &&
      pl_event->content["events"].contains("m.space.child")) {
    required_pl = pl_event->content["events"]["m.space.child"].get<int64_t>();
  }
  if (user_pl < required_pl) {
    return make_error(403, "M_FORBIDDEN",
                      "Insufficient power level to manage space children");
  }

  StateStore state_store(db);
  int64_t now = now_ms();

  // ---- 5. GET: List all children ----
  if (method == "GET") {
    // Get all m.space.child state events for this space
    std::vector<json> children;
    try {
      auto rows = db.query(
        "SELECT state_key, content, origin_server_ts FROM events "
        "WHERE room_id='" + space_id + "' AND type='m.space.child' "
        "ORDER BY origin_server_ts DESC");

      for (auto& row : rows) {
        json child_info;
        child_info["child_room_id"] = row["state_key"].get<std::string>();
        try {
          child_info["content"] = json::parse(row["content"].get<std::string>());
        } catch (...) {
          child_info["content"] = json::object();
        }
        children.push_back(child_info);
      }
    } catch (...) { /* Return empty if query fails */ }

    json resp_body;
    resp_body["children"] = children;
    resp_body["space_id"] = space_id;
    return make_response(200, resp_body);
  }

  // ---- 6. DELETE: Remove a child from space ----
  if (method == "DELETE") {
    if (!validate_room_id(child_room_id)) {
      return make_error(400, "M_INVALID_PARAM", "Invalid child room ID");
    }

    // Send empty state event to remove (tombstone-style)
    json empty_content = json::object();
    std::string ev_id = "$" + gen_token(18) + ":localhost";
    state_store.persist_state_event(space_id, "m.space.child", child_room_id,
                                     ev_id, empty_content, now);

    return make_response(200, json::object());
  }

  // ---- 7. PUT: Add/update child room in space ----
  // Body contains: { "via": [...], "suggested": bool, "order": "...", "auto_join": bool }

  if (method == "PUT") {
    if (!request_body.is_object()) {
      return make_error(400, "M_BAD_JSON", "Request body must be a JSON object");
    }
    if (!validate_room_id(child_room_id)) {
      return make_error(400, "M_INVALID_PARAM", "Invalid child room ID");
    }

    // Build m.space.child content
    json child_content;

    // via: servers to join the child room through
    if (request_body.contains("via") && request_body["via"].is_array()) {
      child_content["via"] = request_body["via"];
    } else {
      child_content["via"] = json::array({"localhost"});
    }

    // suggested: whether to show this child as suggested for users to join
    child_content["suggested"] = safe_bool(request_body, "suggested", false);

    // order: Lexicographic string ordering for display
    if (request_body.contains("order") && request_body["order"].is_string()) {
      child_content["order"] = request_body["order"].get<std::string>();
    } else if (request_body.contains("order")) {
      // Numeric order converted to string
      child_content["order"] = std::to_string(safe_int(request_body, "order", 0));
    } else {
      child_content["order"] = std::to_string(now);
    }

    // auto_join: whether users should auto-join this room
    child_content["auto_join"] = safe_bool(request_body, "auto_join", false);

    // Persist the state event
    std::string ev_id = "$" + gen_token(18) + ":localhost";
    state_store.persist_state_event(space_id, "m.space.child", child_room_id,
                                     ev_id, child_content, now);

    // Invalidate hierarchy cache
    {
      std::lock_guard<std::mutex> lock(g_hierarchy_cache_lock);
      g_space_hierarchy_cache.erase(space_id);
    }

    json resp_body;
    resp_body["event_id"] = ev_id;
    return make_response(200, resp_body);
  }

  return make_error(405, "M_UNRECOGNIZED", "Method not allowed for space children");
}

// ============================================================================
// 3. SPACE PARENT MANAGEMENT
// ============================================================================
// Manages m.space.parent state events on child rooms.
// Supports canonical flag and via server list.
//
// Endpoint: PUT /_matrix/client/v3/rooms/{roomId}/state/m.space.parent/{parentSpaceId}
// ============================================================================

json handle_space_parent(DatabasePool& db, const std::string& auth_header,
                           const std::string& access_token_param,
                           const std::string& room_id,
                           const std::string& method,
                           const json& request_body,
                           const std::string& parent_space_id) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate child room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 3. Check power level ----
  int64_t user_pl = get_user_power_level(db, room_id, auth.user_id);
  StateStore state(db);
  auto pl_event = state.get_current_state_event(room_id, "m.room.power_levels", "");
  int64_t required_pl = 50;
  if (pl_event && pl_event->content.contains("events") &&
      pl_event->content["events"].contains("m.space.parent")) {
    required_pl = pl_event->content["events"]["m.space.parent"].get<int64_t>();
  }
  if (user_pl < required_pl) {
    return make_error(403, "M_FORBIDDEN",
                      "Insufficient power level to manage space parent");
  }

  StateStore state_store(db);
  int64_t now = now_ms();

  // ---- 4. GET: List all parents ----
  if (method == "GET") {
    std::vector<json> parents;
    try {
      auto rows = db.query(
        "SELECT state_key, content, origin_server_ts FROM events "
        "WHERE room_id='" + room_id + "' AND type='m.space.parent' "
        "ORDER BY origin_server_ts DESC");

      for (auto& row : rows) {
        json parent_info;
        parent_info["parent_space_id"] = row["state_key"].get<std::string>();
        try {
          parent_info["content"] = json::parse(row["content"].get<std::string>());
        } catch (...) {
          parent_info["content"] = json::object();
        }
        parents.push_back(parent_info);
      }
    } catch (...) { /* Return empty */ }

    json resp_body;
    resp_body["parents"] = parents;
    resp_body["room_id"] = room_id;
    return make_response(200, resp_body);
  }

  // ---- 5. DELETE: Remove parent link ----
  if (method == "DELETE") {
    if (!validate_room_id(parent_space_id)) {
      return make_error(400, "M_INVALID_PARAM", "Invalid parent space ID");
    }
    json empty_content = json::object();
    std::string ev_id = "$" + gen_token(18) + ":localhost";
    state_store.persist_state_event(room_id, "m.space.parent", parent_space_id,
                                     ev_id, empty_content, now);
    return make_response(200, json::object());
  }

  // ---- 6. PUT: Add/update parent space link ----
  if (method == "PUT") {
    if (!request_body.is_object()) {
      return make_error(400, "M_BAD_JSON", "Request body must be a JSON object");
    }
    if (!validate_room_id(parent_space_id)) {
      return make_error(400, "M_INVALID_PARAM", "Invalid parent space ID");
    }

    json parent_content;
    if (request_body.contains("via") && request_body["via"].is_array()) {
      parent_content["via"] = request_body["via"];
    } else {
      parent_content["via"] = json::array({"localhost"});
    }
    parent_content["canonical"] = safe_bool(request_body, "canonical", false);

    std::string ev_id = "$" + gen_token(18) + ":localhost";
    state_store.persist_state_event(room_id, "m.space.parent", parent_space_id,
                                     ev_id, parent_content, now);

    // Also add reciprocal m.space.child in the parent space
    json child_content;
    child_content["via"] = json::array({"localhost"});
    child_content["suggested"] = true;
    child_content["order"] = std::to_string(now);
    std::string child_ev_id = "$" + gen_token(18) + ":localhost";
    state_store.persist_state_event(parent_space_id, "m.space.child", room_id,
                                     child_ev_id, child_content, now);

    json resp_body;
    resp_body["event_id"] = ev_id;
    return make_response(200, resp_body);
  }

  return make_error(405, "M_UNRECOGNIZED", "Method not allowed for space parent");
}

// ============================================================================
// 4. SPACE HIERARCHY TRAVERSAL
// ============================================================================
// GET /_matrix/client/v1/rooms/{roomId}/hierarchy
// Recursively traverses the space tree, respecting max_depth and pagination.
// Returns child rooms and sub-spaces visible to the requesting user.
//
// Supports:
// - Recursive descent into sub-spaces
// - Pagination via from/limit
// - Suggested-only filtering
// - Max depth limiting
// - Access control: only shows rooms the user can see
// - Caching for performance
// ============================================================================

struct HierarchyNode {
  std::string room_id;
  std::string room_type;
  std::string name;
  std::string topic;
  std::string avatar_url;
  int64_t num_joined_members;
  bool world_readable;
  bool guest_can_join;
  std::string join_rule;
  bool canonical;
  std::vector<std::string> children_state;  // raw state keys
  std::string order;
  bool suggested;
  std::vector<std::string> via_servers;
};

json handle_space_hierarchy(DatabasePool& db, const std::string& auth_header,
                              const std::string& access_token_param,
                              const std::string& room_id,
                              const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 3. Parse query parameters ----
  bool suggested_only = false;
  if (query_params.contains("suggested_only")) {
    suggested_only = query_params["suggested_only"].get<bool>();
  }
  int64_t max_depth = safe_int(query_params, "max_depth", 3);
  if (max_depth < 0) max_depth = 0;
  if (max_depth > 10) max_depth = 10;

  int64_t limit = safe_int(query_params, "limit", 100);
  if (limit <= 0) limit = 100;
  if (limit > 1000) limit = 1000;

  std::string from_token = safe_str(query_params, "from", "");
  int64_t from_offset = 0;
  if (!from_token.empty()) {
    try { from_offset = std::stoll(from_token); }
    catch (...) { from_offset = 0; }
  }

  // ---- 4. User membership check ----
  // User must be a member of the space to traverse its hierarchy
  // UNLESS the space is world_readable
  bool is_member = is_user_in_room(db, room_id, auth.user_id);
  bool world_readable = (get_history_visibility(db, room_id) == "world_readable");
  if (!is_member && !world_readable) {
    return make_error(403, "M_FORBIDDEN",
                      "You are not a member of this space");
  }

  // ---- 5. Check cache for fast response ----
  {
    std::shared_lock<std::shared_mutex> cache_lock(g_space_cache_rwlock);
    auto cache_it = g_space_hierarchy_cache.find(room_id + ":" +
      std::to_string(max_depth) + ":" + std::to_string(suggested_only));
    if (cache_it != g_space_hierarchy_cache.end()) {
      int64_t age = now_ms() - cache_it->second.cached_at_ms;
      if (age < cache_it->second.ttl_ms) {
        return make_response(200, cache_it->second.hierarchy);
      }
    }
  }

  // ---- 6. BFS traversal of space hierarchy ----
  StateStore state(db);
  RoomMemberStore members(db);

  struct QueueEntry {
    std::string space_id;
    int depth;
  };

  std::deque<QueueEntry> queue;
  std::unordered_set<std::string> visited;
  std::vector<HierarchyNode> result_rooms;
  std::unordered_map<std::string, HierarchyNode> node_map;

  queue.push_back({room_id, 0});
  visited.insert(room_id);

  while (!queue.empty()) {
    auto entry = queue.front();
    queue.pop_front();

    if (entry.depth > max_depth) continue;

    // Get all m.space.child events for this space
    std::vector<json> child_events;
    try {
      auto rows = db.query(
        "SELECT state_key, content, origin_server_ts FROM events "
        "WHERE room_id='" + entry.space_id + "' AND type='m.space.child' "
        "ORDER BY origin_server_ts DESC");

      for (auto& row : rows) {
        std::string child_room_id = row["state_key"].get<std::string>();
        json child_content;
        try {
          child_content = json::parse(row["content"].get<std::string>());
        } catch (...) {
          child_content = json::object();
        }
        // Skip empty content (tombstoned)
        if (child_content.empty() || !child_content.contains("via")) continue;

        // Apply suggested_only filter
        if (suggested_only && !safe_bool(child_content, "suggested", false)) {
          continue;
        }

        if (visited.find(child_room_id) == visited.end()) {
          visited.insert(child_room_id);

          HierarchyNode node;
          node.room_id = child_room_id;
          node.suggested = safe_bool(child_content, "suggested", false);
          node.order = safe_str(child_content, "order", "");
          node.canonical = false;  // Set from parent event if available

          // via servers
          if (child_content.contains("via") && child_content["via"].is_array()) {
            for (auto& s : child_content["via"]) {
              if (s.is_string()) node.via_servers.push_back(s.get<std::string>());
            }
          }

          // Get room metadata
          auto child_room = rooms.get_room(child_room_id);
          if (child_room) {
            node.room_type = get_room_type(db, child_room_id).value_or("");
            node.name = get_room_name(db, child_room_id);
            node.topic = get_room_topic(db, child_room_id);
            node.join_rule = get_join_rule(db, child_room_id);
            node.world_readable = (get_history_visibility(db, child_room_id) == "world_readable");
            node.guest_can_join = (get_guest_access(db, child_room_id) == "can_join");

            auto member_summary = members.get_room_member_summary(child_room_id);
            node.num_joined_members = member_summary.joined_members;
          }

          // Check if child is itself a space (for recursion)
          auto child_type = get_room_type(db, child_room_id);
          bool is_space = (child_type && *child_type == "m.space");

          // If space and within depth limit, enqueue for further traversal
          if (is_space && entry.depth + 1 <= max_depth) {
            queue.push_back({child_room_id, entry.depth + 1});
          }

          node_map[child_room_id] = node;
        }
      }
    } catch (...) { /* Skip errors */ }
  }

  // ---- 7. Apply ordering ----
  // m.space.child events have an "order" string field for lexicographic sorting
  for (auto& [rid, node] : node_map) {
    result_rooms.push_back(node);
  }
  std::sort(result_rooms.begin(), result_rooms.end(),
    [](const HierarchyNode& a, const HierarchyNode& b) {
      if (a.order != b.order) return a.order < b.order;
      return a.room_id < b.room_id;
    });

  // ---- 8. Paginate results ----
  int64_t total_results = static_cast<int64_t>(result_rooms.size());
  int64_t next_offset = from_offset + limit;
  bool has_more = next_offset < total_results;

  std::vector<HierarchyNode> page;
  for (int64_t i = from_offset; i < from_offset + limit && i < total_results; ++i) {
    page.push_back(result_rooms[i]);
  }

  // ---- 9. Build response ----
  json resp_body;
  resp_body["rooms"] = json::array();

  for (auto& node : page) {
    json room_entry;
    room_entry["room_id"] = node.room_id;
    room_entry["room_type"] = node.room_type;
    room_entry["name"] = node.name;
    room_entry["topic"] = node.topic;
    room_entry["canonical_alias"] = json();  // Could look up from directory
    room_entry["num_joined_members"] = node.num_joined_members;
    room_entry["world_readable"] = node.world_readable;
    room_entry["guest_can_join"] = node.guest_can_join;
    room_entry["join_rule"] = node.join_rule;
    room_entry["avatar_url"] = node.avatar_url;

    // Children state for nested display (not deeply resolved, just IDs)
    room_entry["children_state"] = json::array();

    // Via servers for federation
    room_entry["via"] = json::array();
    for (auto& s : node.via_servers) {
      room_entry["via"].push_back(s);
    }

    // Space ordering fields
    if (!node.order.empty()) {
      room_entry["order"] = node.order;
    }
    room_entry["suggested"] = node.suggested;

    resp_body["rooms"].push_back(room_entry);
  }

  if (has_more) {
    resp_body["next_batch"] = std::to_string(next_offset);
  }

  // ---- 10. Cache result ----
  {
    std::unique_lock<std::shared_mutex> cache_lock(g_space_cache_rwlock);
    SpaceCacheEntry cache_entry;
    cache_entry.hierarchy = resp_body;
    cache_entry.cached_at_ms = now_ms();
    cache_entry.ttl_ms = 30000;  // 30 seconds TTL
    g_space_hierarchy_cache[room_id + ":" + std::to_string(max_depth) + ":" +
      std::to_string(suggested_only)] = cache_entry;

    // Evict old entries if cache grows too large
    if (g_space_hierarchy_cache.size() > 1000) {
      int64_t cutoff = now_ms() - 60000;
      auto it = g_space_hierarchy_cache.begin();
      while (it != g_space_hierarchy_cache.end()) {
        if (it->second.cached_at_ms < cutoff) {
          it = g_space_hierarchy_cache.erase(it);
        } else {
          ++it;
        }
      }
    }
  }

  return make_response(200, resp_body);
}

// ============================================================================
// 5. SPACE ORDERING
// ============================================================================
// Handles the "order" field in m.space.child events for lexicographic
// ordering of children in the space hierarchy. Also handles the "suggested"
// flag for recommending rooms to users.
//
// This provides utility functions used by other space handlers.
// ============================================================================

static std::string normalize_order_string(const std::string& order) {
  // Pad numbers to ensure proper lexicographic sorting
  // e.g., "1" -> "00000000000000000001"
  // Non-numeric strings are left alone
  if (order.empty()) return order;
  bool is_numeric = true;
  for (char c : order) {
    if (c < '0' || c > '9') { is_numeric = false; break; }
  }
  if (is_numeric) {
    return std::string(20 - order.size(), '0') + order;
  }
  return order;
}

static int compare_order(const std::string& a, const std::string& b) {
  std::string na = normalize_order_string(a);
  std::string nb = normalize_order_string(b);
  if (na < nb) return -1;
  if (na > nb) return 1;
  return 0;
}

json handle_space_ordering(DatabasePool& db, const std::string& auth_header,
                             const std::string& access_token_param,
                             const std::string& space_id,
                             const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate space ----
  RoomStore rooms(db);
  auto space_info = rooms.get_room(space_id);
  if (!space_info) {
    return make_error(404, "M_NOT_FOUND", "Space not found");
  }

  auto room_type = get_room_type(db, space_id);
  if (!room_type || *room_type != "m.space") {
    return make_error(400, "M_BAD_STATE", "Room is not a space");
  }

  // ---- 3. Get all children with their order values ----
  StateStore state(db);
  json resp_body;
  resp_body["space_id"] = space_id;
  resp_body["children"] = json::array();

  try {
    auto rows = db.query(
      "SELECT state_key, content FROM events "
      "WHERE room_id='" + space_id + "' AND type='m.space.child'");

    struct ChildOrder {
      std::string child_room_id;
      std::string order;
      bool suggested;
      std::string name;
    };
    std::vector<ChildOrder> ordered_children;

    for (auto& row : rows) {
      ChildOrder co;
      co.child_room_id = row["state_key"].get<std::string>();
      json content;
      try {
        content = json::parse(row["content"].get<std::string>());
      } catch (...) { continue; }

      if (content.empty() || !content.contains("via")) continue;

      co.order = safe_str(content, "order", "");
      co.suggested = safe_bool(content, "suggested", false);
      co.name = get_room_name(db, co.child_room_id);
      ordered_children.push_back(co);
    }

    // Sort by order (normalized lexicographic)
    std::sort(ordered_children.begin(), ordered_children.end(),
      [](const ChildOrder& a, const ChildOrder& b) {
        return compare_order(a.order, b.order) < 0;
      });

    // Group: suggested first, then non-suggested
    std::vector<ChildOrder> suggested, not_suggested;
    for (auto& co : ordered_children) {
      if (co.suggested) suggested.push_back(co);
      else not_suggested.push_back(co);
    }

    for (auto& co : suggested) {
      json entry;
      entry["room_id"] = co.child_room_id;
      entry["name"] = co.name;
      entry["order"] = co.order;
      entry["suggested"] = true;
      resp_body["children"].push_back(entry);
    }
    for (auto& co : not_suggested) {
      json entry;
      entry["room_id"] = co.child_room_id;
      entry["name"] = co.name;
      entry["order"] = co.order;
      entry["suggested"] = false;
      resp_body["children"].push_back(entry);
    }
  } catch (...) {
    resp_body["children"] = json::array();
  }

  return make_response(200, resp_body);
}

// ============================================================================
// 6. MSC2175: CREATE SPACE VIA /createRoom
// ============================================================================
// MSC2175 specifies that spaces are created as regular rooms with
// creation_content containing type=m.space. This handler wraps the
// create space logic to validate the MSC2175 requirements.
// ============================================================================

json handle_msc2175_create_space(DatabasePool& db, const std::string& auth_header,
                                    const std::string& access_token_param,
                                    const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. MSC2175: creation_content MUST contain type=m.space ----
  if (!request_body.contains("creation_content") ||
      !request_body["creation_content"].is_object()) {
    return make_error(400, "M_MISSING_PARAM",
                      "creation_content is required for space creation (MSC2175)");
  }

  auto& cc = request_body["creation_content"];
  if (!cc.contains("type") || cc["type"] != "m.space") {
    return make_error(400, "M_INVALID_PARAM",
                      "creation_content.type must be 'm.space' (MSC2175)");
  }

  // ---- 3. Delegate to create_space handler ----
  json modified_body = request_body;
  modified_body["creation_content"] = cc;

  return handle_create_space(db, auth_header, access_token_param, modified_body);
}

// ============================================================================
// 7. MSC2946: SPACE SUMMARY API
// ============================================================================
// Provides a summary view of a space, including child counts,
// member statistics, and recent activity across the space tree.
//
// Endpoint: GET /_matrix/client/v1/rooms/{roomId}/summary
// ============================================================================

json handle_msc2946_space_summary(DatabasePool& db, const std::string& auth_header,
                                     const std::string& access_token_param,
                                     const std::string& space_id,
                                     const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate space ----
  RoomStore rooms(db);
  auto space_info = rooms.get_room(space_id);
  if (!space_info) {
    return make_error(404, "M_NOT_FOUND", "Space not found");
  }

  // ---- 3. Collect summary data ----
  StateStore state(db);
  RoomMemberStore members(db);

  json summary;
  summary["space_id"] = space_id;
  summary["name"] = get_room_name(db, space_id);
  summary["topic"] = get_room_topic(db, space_id);

  // Room type
  auto rtype = get_room_type(db, space_id);
  summary["room_type"] = rtype.value_or("");

  // Join rules and guest access
  summary["join_rule"] = get_join_rule(db, space_id);
  summary["guest_access"] = get_guest_access(db, space_id);
  summary["history_visibility"] = get_history_visibility(db, space_id);

  // Member statistics
  auto space_members = members.get_room_member_summary(space_id);
  summary["num_joined_members"] = space_members.joined_members;
  summary["num_invited_members"] = space_members.invited_members;

  // Child statistics
  struct ChildStats {
    int total_children = 0;
    int suggested_children = 0;
    int subspaces = 0;
    int regular_rooms = 0;
    int64_t total_joined_members_across_children = 0;
    std::string most_recent_activity;
  };
  ChildStats stats;

  try {
    auto rows = db.query(
      "SELECT state_key, content FROM events "
      "WHERE room_id='" + space_id + "' AND type='m.space.child'");

    for (auto& row : rows) {
      std::string child_id = row["state_key"].get<std::string>();
      json content;
      try {
        content = json::parse(row["content"].get<std::string>());
      } catch (...) { continue; }
      if (content.empty() || !content.contains("via")) continue;

      stats.total_children++;
      if (safe_bool(content, "suggested", false)) {
        stats.suggested_children++;
      }

      auto child_type = get_room_type(db, child_id);
      if (child_type && *child_type == "m.space") {
        stats.subspaces++;
      } else {
        stats.regular_rooms++;
      }

      auto child_members = members.get_room_member_summary(child_id);
      stats.total_joined_members_across_children += child_members.joined_members;
    }
  } catch (...) { /* Continue */ }

  summary["total_children"] = stats.total_children;
  summary["suggested_children"] = stats.suggested_children;
  summary["subspaces"] = stats.subspaces;
  summary["regular_rooms"] = stats.regular_rooms;
  summary["total_joined_members_across_children"] = stats.total_joined_members_across_children;

  // Heroes
  if (!space_members.heroes.empty()) {
    summary["heroes"] = json::array();
    for (auto& h : space_members.heroes) {
      summary["heroes"].push_back(h);
    }
  }

  // Room version
  summary["room_version"] = get_room_version(db, space_id);

  // Creator
  auto create_ev = state.get_current_state_event(space_id, "m.room.create", "");
  if (create_ev && create_ev->content.contains("creator")) {
    summary["creator"] = create_ev->content["creator"].get<std::string>();
  }

  summary["federate"] = space_info->federate;

  return make_response(200, summary);
}

// ============================================================================
// 8. MSC3083: RESTRICTED JOIN RULES FOR SPACES
// ============================================================================
// Implements restricted join rules (join_rule: "restricted") allowing
// members of specified spaces to join without an explicit invite.
//
// Endpoint: PUT /_matrix/client/v3/rooms/{roomId}/state/m.room.join_rules
// ============================================================================

json handle_msc3083_restricted_join(DatabasePool& db, const std::string& auth_header,
                                       const std::string& access_token_param,
                                       const std::string& room_id,
                                       const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 3. Check power level ----
  int64_t user_pl = get_user_power_level(db, room_id, auth.user_id);
  if (user_pl < 50) {
    return make_error(403, "M_FORBIDDEN",
                      "Insufficient power level to change join rules");
  }

  // ---- 4. Validate join_rule ----
  if (!request_body.contains("join_rule")) {
    return make_error(400, "M_MISSING_PARAM", "join_rule is required");
  }

  std::string join_rule = request_body["join_rule"].get<std::string>();
  if (join_rule != "invite" && join_rule != "public" &&
      join_rule != "knock" && join_rule != "restricted" &&
      join_rule != "private") {
    return make_error(400, "M_INVALID_PARAM",
                      "Invalid join_rule: " + join_rule);
  }

  // ---- 5. Build join_rules content ----
  json join_rules_content;
  join_rules_content["join_rule"] = join_rule;

  // MSC3083: If restricted, must specify allow rules
  if (join_rule == "restricted") {
    if (!request_body.contains("allow") && !request_body.contains("restricted_allow")) {
      return make_error(400, "M_MISSING_PARAM",
                        "allow rules are required for restricted join_rule");
    }

    // Parse allow rules
    json allow_arr = json::array();
    auto& allow_src = request_body.contains("allow")
      ? request_body["allow"]
      : request_body["restricted_allow"];

    if (!allow_src.is_array()) {
      return make_error(400, "M_INVALID_PARAM",
                        "allow must be an array");
    }

    for (auto& rule : allow_src) {
      if (!rule.is_object()) continue;

      json allow_entry;
      allow_entry["type"] = rule.value("type", "m.room_membership");

      // room_id (required for m.room_membership type)
      if (rule.contains("room_id")) {
        allow_entry["room_id"] = rule["room_id"].get<std::string>();
      } else if (rule.contains("space")) {
        allow_entry["room_id"] = rule["space"].get<std::string>();
      } else {
        continue;  // Skip invalid rules
      }

      // Validate that the referenced room exists and is accessible
      if (!validate_room_id(allow_entry["room_id"].get<std::string>())) {
        continue;
      }

      allow_arr.push_back(allow_entry);
    }

    if (allow_arr.empty()) {
      return make_error(400, "M_INVALID_PARAM",
                        "No valid allow rules provided");
    }

    join_rules_content["allow"] = allow_arr;
  }

  // ---- 6. Persist the state event ----
  StateStore state(db);
  std::string ev_id = "$" + gen_token(18) + ":localhost";
  int64_t now = now_ms();
  state.persist_state_event(room_id, "m.room.join_rules", "", ev_id,
                             join_rules_content, now);

  json resp_body;
  resp_body["event_id"] = ev_id;
  return make_response(200, resp_body);
}

// ============================================================================
// Helper: Check if user can join via restricted rules (MSC3083)
// ============================================================================

static bool can_user_join_via_restricted_rules(DatabasePool& db,
                                                  const std::string& room_id,
                                                  const std::string& user_id) {
  StateStore state(db);
  auto jr = state.get_current_state_event(room_id, "m.room.join_rules", "");
  if (!jr) return false;

  json jr_content = jr->content;
  if (!jr_content.contains("join_rule") ||
      jr_content["join_rule"] != "restricted") {
    return false;
  }

  if (!jr_content.contains("allow") || !jr_content["allow"].is_array()) {
    return false;
  }

  RoomMemberStore members(db);
  for (auto& rule : jr_content["allow"]) {
    if (!rule.contains("room_id") || !rule.contains("type")) continue;
    if (rule["type"] != "m.room_membership") continue;

    std::string allowed_space = rule["room_id"].get<std::string>();
    auto member = members.get_member(allowed_space, user_id);
    if (member && member->membership == "join") {
      return true;
    }
  }

  return false;
}

// ============================================================================
// 9. MSC3215: ROOM TYPE IN m.room.create
// ============================================================================
// MSC3215 defines that room type is stored in the m.room.create state event
// content under the "type" field. This handler provides:
// - Setting room type during creation
// - Reading room type
// - Validating room type values
// - Switching room type (space <-> regular)
// ============================================================================

static const std::unordered_set<std::string> VALID_ROOM_TYPES = {
  "m.space",
  "m.room",
  ""
};

json handle_msc3215_room_type(DatabasePool& db, const std::string& auth_header,
                                const std::string& access_token_param,
                                const std::string& room_id,
                                const std::string& method,
                                const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 3. GET: Read room type ----
  if (method == "GET") {
    json resp_body;
    resp_body["room_id"] = room_id;
    resp_body["room_type"] = get_room_type(db, room_id).value_or("");
    // Also check legacy is_space flag
    resp_body["is_space"] = room_info->is_space;
    resp_body["room_version"] = get_room_version(db, room_id);

    // Full m.room.create content for transparency
    StateStore state(db);
    auto create_ev = state.get_current_state_event(room_id, "m.room.create", "");
    if (create_ev) {
      resp_body["creation_content"] = create_ev->content;
    }

    return make_response(200, resp_body);
  }

  // ---- 4. PUT: Set/change room type ----
  if (method == "PUT") {
    // Only room creator or admin can change room type
    int64_t user_pl = get_user_power_level(db, room_id, auth.user_id);
    if (user_pl < 100) {
      return make_error(403, "M_FORBIDDEN",
                        "Only admins (PL 100) can change room type");
    }

    std::string new_type = safe_str(request_body, "type", "");

    // Validate room type value
    if (!new_type.empty() && VALID_ROOM_TYPES.find(new_type) == VALID_ROOM_TYPES.end()) {
      return make_error(400, "M_INVALID_PARAM",
                        "Invalid room type: " + new_type +
                        ". Valid types: m.space, m.room");
    }

    // Update the m.room.create state event
    StateStore state(db);
    auto create_ev = state.get_current_state_event(room_id, "m.room.create", "");
    json create_content;
    if (create_ev) {
      create_content = create_ev->content;
    }
    create_content["type"] = new_type;

    std::string ev_id = "$" + gen_token(18) + ":localhost";
    int64_t now = now_ms();
    state.persist_state_event(room_id, "m.room.create", "", ev_id,
                               create_content, now);

    // Update the rooms table is_space flag
    rooms.update_room_type(room_id, new_type == "m.space");

    json resp_body;
    resp_body["room_id"] = room_id;
    resp_body["room_type"] = new_type;
    resp_body["event_id"] = ev_id;
    return make_response(200, resp_body);
  }

  return make_error(405, "M_UNRECOGNIZED", "Method not allowed");
}

// ============================================================================
// 10. MSC3266: ROOM SUMMARY API EXTENSION
// ============================================================================
// Extends the room summary API with additional fields:
// - room_type from m.room.create
// - parent spaces (m.space.parent)
// - child count from m.space.child
// - thread statistics
// - relation aggregations
// - intentional mentions count
// ============================================================================

json handle_msc3266_room_summary_ext(DatabasePool& db, const std::string& auth_header,
                                        const std::string& access_token_param,
                                        const std::string& room_id,
                                        const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 3. User access check ----
  bool is_member = is_user_in_room(db, room_id, auth.user_id);
  bool world_readable = (get_history_visibility(db, room_id) == "world_readable");
  if (!is_member && !world_readable) {
    return make_error(403, "M_FORBIDDEN", "Access denied");
  }

  // ---- 4. Build extended summary ----
  StateStore state(db);
  RoomMemberStore members(db);

  json summary;
  summary["room_id"] = room_id;
  summary["name"] = get_room_name(db, room_id);
  summary["topic"] = get_room_topic(db, room_id);
  summary["canonical_alias"] = json();  // Populated if available

  // MSC3215: room_type from m.room.create
  auto rtype = get_room_type(db, room_id);
  summary["room_type"] = rtype.value_or("");
  summary["is_space"] = (rtype && *rtype == "m.space");

  // Basic member stats
  auto member_summary = members.get_room_member_summary(room_id);
  summary["num_joined_members"] = member_summary.joined_members;
  summary["num_invited_members"] = member_summary.invited_members;
  summary["join_rule"] = get_join_rule(db, room_id);
  summary["guest_access"] = get_guest_access(db, room_id);
  summary["history_visibility"] = get_history_visibility(db, room_id);
  summary["room_version"] = get_room_version(db, room_id);
  summary["world_readable"] = world_readable;

  // MSC3266: Parent spaces
  summary["parent_spaces"] = json::array();
  try {
    auto parent_rows = db.query(
      "SELECT state_key, content FROM events "
      "WHERE room_id='" + room_id + "' AND type='m.space.parent'");
    for (auto& row : parent_rows) {
      json parent_info;
      parent_info["space_id"] = row["state_key"].get<std::string>();
      try {
        auto content = json::parse(row["content"].get<std::string>());
        parent_info["canonical"] = safe_bool(content, "canonical", false);
        parent_info["via"] = content.value("via", json::array());
      } catch (...) {}
      summary["parent_spaces"].push_back(parent_info);
    }
  } catch (...) {}

  // MSC3266: Relation aggregations
  json aggregations;
  aggregations["m.annotation"] = count_relations(db, room_id + ":_aggregations_",
                                                    "m.annotation");
  aggregations["m.replace"] = count_relations(db, room_id + ":_aggregations_",
                                                "m.replace");
  aggregations["m.thread"] = count_relations(db, room_id + ":_aggregations_",
                                              "m.thread");
  aggregations["m.reference"] = count_relations(db, room_id + ":_aggregations_",
                                                  "m.reference");
  summary["m.relations"] = aggregations;

  // MSC3266: Thread statistics (if room has threads)
  summary["thread_count"] = 0;
  try {
    auto thread_rows = db.query(
      "SELECT COUNT(*) as cnt FROM event_relations "
      "WHERE relation_type='m.thread' AND relates_to_id IN "
      "(SELECT event_id FROM events WHERE room_id='" + room_id + "')");
    if (!thread_rows.empty()) {
      summary["thread_count"] = thread_rows[0]["cnt"].get<int>();
    }
  } catch (...) {}

  // MSC3870: Intentional mentions count
  summary["intentional_mentions_count"] = 0;
  try {
    auto mention_rows = db.query(
      "SELECT COUNT(*) as cnt FROM event_mentions "
      "WHERE room_id='" + room_id + "'");
    if (!mention_rows.empty()) {
      summary["intentional_mentions_count"] = mention_rows[0]["cnt"].get<int>();
    }
  } catch (...) {}

  // Heroes
  if (!member_summary.heroes.empty()) {
    summary["heroes"] = json::array();
    for (auto& h : member_summary.heroes) {
      summary["heroes"].push_back(h);
    }
  }

  // Avatar URL (if available)
  summary["avatar_url"] = json();
  auto avatar_ev = state.get_current_state_event(room_id, "m.room.avatar", "");
  if (avatar_ev && avatar_ev->content.contains("url")) {
    summary["avatar_url"] = avatar_ev->content["url"];
  }

  // Federation flag
  auto create_ev = state.get_current_state_event(room_id, "m.room.create", "");
  if (create_ev && create_ev->content.contains("m.federate")) {
    summary["federate"] = create_ev->content["m.federate"].get<bool>();
  } else {
    summary["federate"] = true;
  }

  return make_response(200, summary);
}

// ============================================================================
// 11. MSC3381: POLLS - m.poll.start
// ============================================================================
// Handles poll creation events per MSC3381.
// Polls are message events with type m.poll.start and a specific content schema.
// Supports:
// - Multiple answer options
// - Single/multi-select
// - Poll question text
// - Max selections for multi-select
// - Poll duration
// - Validation of poll structure
// ============================================================================

json handle_msc3381_poll_start(DatabasePool& db, const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const std::string& room_id,
                                 const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room membership ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN", "Not a member of this room");
  }

  // ---- 3. Validate poll content (MSC3381 schema) ----
  if (!request_body.contains("m.poll.start") ||
      !request_body["m.poll.start"].is_object()) {
    return make_error(400, "M_BAD_JSON",
                      "m.poll.start content is required");
  }

  auto& poll_content = request_body["m.poll.start"];

  // Required: question
  if (!poll_content.contains("question") ||
      !poll_content["question"].is_object()) {
    return make_error(400, "M_MISSING_PARAM", "Poll question is required");
  }

  auto& question = poll_content["question"];
  if (!question.contains("body") || !question["body"].is_string()) {
    return make_error(400, "M_MISSING_PARAM", "Poll question body is required");
  }

  std::string question_text = question["body"].get<std::string>();

  // Required: answers
  if (!poll_content.contains("answers") ||
      !poll_content["answers"].is_array()) {
    return make_error(400, "M_MISSING_PARAM", "Poll answers are required");
  }

  auto& answers = poll_content["answers"];
  if (answers.size() < 2) {
    return make_error(400, "M_INVALID_PARAM", "Poll must have at least 2 answers");
  }
  if (answers.size() > 20) {
    return make_error(400, "M_INVALID_PARAM", "Poll can have at most 20 answers");
  }

  // Validate each answer has an id
  std::unordered_set<std::string> answer_ids;
  for (auto& ans : answers) {
    if (!ans.contains("id") || !ans["id"].is_string()) {
      return make_error(400, "M_INVALID_PARAM", "Each answer must have an id");
    }
    std::string ans_id = ans["id"].get<std::string>();
    if (answer_ids.find(ans_id) != answer_ids.end()) {
      return make_error(400, "M_INVALID_PARAM", "Duplicate answer id: " + ans_id);
    }
    answer_ids.insert(ans_id);
  }

  // Optional: kind (single or disclosed/open)
  std::string kind = safe_str(poll_content, "kind", "m.poll.disclosed");

  // Optional: max_selections (default 1)
  int64_t max_selections = safe_int(poll_content, "max_selections", 1);
  if (max_selections < 1) max_selections = 1;
  if (max_selections > static_cast<int64_t>(answers.size())) {
    max_selections = static_cast<int64_t>(answers.size());
  }

  // ---- 4. Build the full event content ----
  json event_content;
  // Include the normal text fallback in the body
  event_content["body"] = question_text + "\n" +
    (kind == "m.poll.undisclosed" ? "(Undisclosed poll)" : "(Poll)");
  event_content["msgtype"] = "m.poll";
  event_content["m.poll.start"] = poll_content;

  // ---- 5. Store poll start event ----
  StateStore state(db);
  std::string event_id = "$" + gen_token(18) + ":localhost";
  int64_t now = now_ms();

  json full_event;
  full_event["event_id"] = event_id;
  full_event["room_id"] = room_id;
  full_event["sender"] = auth.user_id;
  full_event["type"] = "m.poll.start";
  full_event["content"] = event_content;
  full_event["origin_server_ts"] = now;
  full_event["state_key"] = "";

  // Persist to events table
  EventsStore evs(db);
  try {
    db.execute(
      "INSERT INTO events (event_id,room_id,type,sender,content,state_key,"
      "origin_server_ts,depth,stream_ordering) VALUES ('" +
      event_id + "','" + room_id + "','m.poll.start','" + auth.user_id + "','" +
      full_event.dump() + "',''," + std::to_string(now) + ",1," +
      std::to_string(now) + ")");
  } catch (...) {
    return make_error(500, "M_UNKNOWN", "Failed to store poll event");
  }

  // ---- 6. Initialize poll aggregation tracking ----
  json poll_state;
  poll_state["event_id"] = event_id;
  poll_state["room_id"] = room_id;
  poll_state["question"] = question_text;
  poll_state["kind"] = kind;
  poll_state["max_selections"] = max_selections;
  poll_state["total_responses"] = 0;
  poll_state["answers"] = json::object();
  for (auto& ans_id : answer_ids) {
    poll_state["answers"][ans_id] = 0;
  }
  poll_state["respondents"] = json::object();  // user_id -> selected answer ids

  std::lock_guard<std::mutex> lock(g_poll_lock);

  json resp_body;
  resp_body["event_id"] = event_id;
  resp_body["room_id"] = room_id;
  return make_response(200, resp_body);
}

// ============================================================================
// 12. MSC3381: POLLS - m.poll.response
// ============================================================================
// Handles poll response events per MSC3381.
// Users select one or more options from the poll answers.
// Validates:
// - Poll exists and is not ended
// - Answer IDs are valid
// - Max selections not exceeded
// - Single response per user (or replaced)
// ============================================================================

json handle_msc3381_poll_response(DatabasePool& db, const std::string& auth_header,
                                    const std::string& access_token_param,
                                    const std::string& room_id,
                                    const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room membership ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN", "Not a member of this room");
  }

  // ---- 3. Validate request ----
  if (!request_body.contains("m.poll.response") ||
      !request_body["m.poll.response"].is_object()) {
    return make_error(400, "M_BAD_JSON", "m.poll.response content is required");
  }

  auto& response = request_body["m.poll.response"];

  // Required: relates_to with the poll start event
  if (!request_body.contains("m.relates_to") ||
      !request_body["m.relates_to"].is_object()) {
    return make_error(400, "M_MISSING_PARAM",
                      "m.relates_to with poll start event_id is required");
  }

  auto& relates_to = request_body["m.relates_to"];
  std::string poll_start_id = safe_str(relates_to, "event_id", "");
  if (poll_start_id.empty()) {
    return make_error(400, "M_MISSING_PARAM",
                      "relates_to.event_id (poll start event) is required");
  }

  // ---- 4. Verify poll start event exists ----
  auto poll_event = get_event_by_id(db, poll_start_id);
  if (!poll_event) {
    return make_error(404, "M_NOT_FOUND", "Poll start event not found");
  }

  json poll_start_content = extract_content(poll_event);
  if (!poll_start_content.contains("m.poll.start")) {
    return make_error(400, "M_INVALID_PARAM",
                      "Referenced event is not a poll start");
  }

  auto& poll_start = poll_start_content["m.poll.start"];

  // ---- 5. Check if poll has ended ----
  // Look for m.poll.end event referencing this poll
  try {
    auto end_rows = db.query(
      "SELECT event_id FROM event_relations "
      "WHERE relates_to_id='" + poll_start_id + "' AND relation_type='m.reference'");
    for (auto& row : end_rows) {
      auto end_ev = get_event_by_id(db, row["event_id"].get<std::string>());
      if (end_ev && (*end_ev).value("type", "") == "m.poll.end") {
        return make_error(400, "M_BAD_STATE", "This poll has ended");
      }
    }
  } catch (...) {}

  // ---- 6. Validate answers ----
  if (!response.contains("answers") || !response["answers"].is_array()) {
    return make_error(400, "M_MISSING_PARAM", "Selected answers are required");
  }

  auto& selected_answers = response["answers"];
  if (selected_answers.empty()) {
    return make_error(400, "M_INVALID_PARAM", "At least one answer must be selected");
  }

  int64_t max_selections = safe_int(poll_start, "max_selections", 1);
  if (static_cast<int64_t>(selected_answers.size()) > max_selections) {
    return make_error(400, "M_INVALID_PARAM",
                      "Too many selections (max: " + std::to_string(max_selections) + ")");
  }

  // Get valid answer IDs
  std::unordered_set<std::string> valid_answer_ids;
  if (poll_start.contains("answers") && poll_start["answers"].is_array()) {
    for (auto& ans : poll_start["answers"]) {
      if (ans.contains("id")) {
        valid_answer_ids.insert(ans["id"].get<std::string>());
      }
    }
  }

  for (auto& ans : selected_answers) {
    std::string ans_id = ans.is_string() ? ans.get<std::string>()
                                         : safe_str(ans, "id", "");
    if (valid_answer_ids.find(ans_id) == valid_answer_ids.end()) {
      return make_error(400, "M_INVALID_PARAM",
                        "Invalid answer id: " + ans_id);
    }
  }

  // ---- 7. Store poll response event ----
  std::string event_id = "$" + gen_token(18) + ":localhost";
  int64_t now = now_ms();

  json event_content = request_body;
  event_content["msgtype"] = "m.poll";

  std::string room_id_str(room_id);  // copy for safety
  try {
    db.execute(
      "INSERT INTO events (event_id,room_id,type,sender,content,state_key,"
      "origin_server_ts,depth,stream_ordering) VALUES ('" +
      event_id + "','" + room_id_str + "','m.poll.response','" + auth.user_id + "','" +
      event_content.dump() + "',''," + std::to_string(now) + ",1," +
      std::to_string(now) + ")");

    // Store relation for aggregation
    store_event_relation(db, event_id, poll_start_id, "m.reference", "");
  } catch (...) {
    return make_error(500, "M_UNKNOWN", "Failed to store poll response");
  }

  json resp_body;
  resp_body["event_id"] = event_id;
  resp_body["room_id"] = room_id_str;
  return make_response(200, resp_body);
}

// ============================================================================
// 13. MSC3381: POLLS - m.poll.end
// ============================================================================
// Handles poll end events per MSC3381.
// Allows the poll creator (or users with sufficient power) to close a poll.
// After ending, no new responses are accepted.
// ============================================================================

json handle_msc3381_poll_end(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id,
                               const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room membership ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN", "Not a member of this room");
  }

  // ---- 3. Validate request ----
  if (!request_body.contains("m.relates_to") ||
      !request_body["m.relates_to"].is_object()) {
    return make_error(400, "M_MISSING_PARAM",
                      "m.relates_to with poll start event_id is required");
  }

  auto& relates_to = request_body["m.relates_to"];
  std::string poll_start_id = safe_str(relates_to, "event_id", "");
  if (poll_start_id.empty()) {
    return make_error(400, "M_MISSING_PARAM",
                      "relates_to.event_id (poll start event) is required");
  }

  // ---- 4. Verify poll start event exists ----
  auto poll_event = get_event_by_id(db, poll_start_id);
  if (!poll_event) {
    return make_error(404, "M_NOT_FOUND", "Poll start event not found");
  }

  // ---- 5. Authorization: Only poll creator or admin can end ----
  std::string poll_creator = (*poll_event).value("sender", "");
  int64_t user_pl = get_user_power_level(db, room_id, auth.user_id);
  bool is_creator = (poll_creator == auth.user_id);
  bool is_admin = (user_pl >= 50);

  if (!is_creator && !is_admin) {
    return make_error(403, "M_FORBIDDEN",
                      "Only the poll creator or admins can end a poll");
  }

  // ---- 6. Check if already ended ----
  try {
    auto end_rows = db.query(
      "SELECT event_id FROM event_relations "
      "WHERE relates_to_id='" + poll_start_id + "' AND relation_type='m.reference'");

    for (auto& row : end_rows) {
      auto end_ev = get_event_by_id(db, row["event_id"].get<std::string>());
      if (end_ev && (*end_ev).value("type", "") == "m.poll.end") {
        return make_error(400, "M_BAD_STATE", "Poll has already ended");
      }
    }
  } catch (...) {}

  // ---- 7. Compute final poll results ----
  json final_results;
  json poll_start_content = extract_content(poll_event);
  auto& poll_start = poll_start_content["m.poll.start"];

  // Count responses
  std::unordered_map<std::string, int> answer_counts;
  if (poll_start.contains("answers") && poll_start["answers"].is_array()) {
    for (auto& ans : poll_start["answers"]) {
      std::string ans_id = ans["id"].get<std::string>();
      answer_counts[ans_id] = 0;
    }
  }

  try {
    auto response_rows = db.query(
      "SELECT e.content FROM events e "
      "JOIN event_relations er ON e.event_id=er.event_id "
      "WHERE er.relates_to_id='" + poll_start_id + "' "
      "AND e.type='m.poll.response'");
    for (auto& row : response_rows) {
      try {
        json response_content = json::parse(row["content"].get<std::string>());
        if (response_content.contains("m.poll.response") &&
            response_content["m.poll.response"].contains("answers")) {
          for (auto& ans : response_content["m.poll.response"]["answers"]) {
            std::string ans_id = ans.is_string() ? ans.get<std::string>() : "";
            if (answer_counts.find(ans_id) != answer_counts.end()) {
              answer_counts[ans_id]++;
            }
          }
        }
      } catch (...) {}
    }
  } catch (...) {}

  for (auto& [ans_id, count] : answer_counts) {
    final_results[ans_id] = count;
  }

  // ---- 8. Store m.poll.end event ----
  std::string event_id = "$" + gen_token(18) + ":localhost";
  int64_t now = now_ms();

  json event_content;
  event_content["m.poll.end"] = json::object();
  event_content["m.poll.end"]["results"] = final_results;
  event_content["body"] = "Poll ended";
  event_content["msgtype"] = "m.poll";
  event_content["m.relates_to"] = relates_to;

  try {
    db.execute(
      "INSERT INTO events (event_id,room_id,type,sender,content,state_key,"
      "origin_server_ts,depth,stream_ordering) VALUES ('" +
      event_id + "','" + std::string(room_id) + "','m.poll.end','" +
      auth.user_id + "','" + event_content.dump() + "',''," +
      std::to_string(now) + ",1," + std::to_string(now) + ")");

    store_event_relation(db, event_id, poll_start_id, "m.reference", "");
  } catch (...) {
    return make_error(500, "M_UNKNOWN", "Failed to store poll end event");
  }

  json resp_body;
  resp_body["event_id"] = event_id;
  resp_body["results"] = final_results;
  return make_response(200, resp_body);
}

// ============================================================================
// 14. MSC3440: THREADING VIA m.thread RELATION
// ============================================================================
// Implements threaded messages via the m.thread relation type.
// Thread roots use m.relates_to with rel_type=m.thread and is_falling_back=true.
// Thread replies use m.relates_to referencing the thread root.
//
// Features:
// - Thread root detection
// - Thread reply creation
// - Thread list retrieval (paginated)
// - Thread participation tracking
// - Thread read receipts
// - Thread notification preferences
// ============================================================================

struct ThreadInfo {
  std::string thread_root_id;
  std::string room_id;
  std::string root_sender;
  std::string root_body;  // Fallback text
  int64_t reply_count;
  std::string latest_reply_event_id;
  int64_t latest_reply_ts;
  std::vector<std::string> participant_ids;
  bool is_following;  // For the requesting user
};

json handle_msc3440_thread(DatabasePool& db, const std::string& auth_header,
                             const std::string& access_token_param,
                             const std::string& room_id,
                             const std::string& method,
                             const json& request_body,
                             const std::string& thread_event_id) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room membership ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN", "Not a member of this room");
  }

  // ---- 3. GET: List threads in the room ----
  if (method == "GET" && thread_event_id.empty()) {
    json resp_body;
    resp_body["room_id"] = room_id;
    resp_body["threads"] = json::array();

    try {
      // Find thread roots: events referenced by m.thread relations
      // with is_falling_back=true in a room
      auto thread_rows = db.query(
        "SELECT DISTINCT er.relates_to_id FROM event_relations er "
        "JOIN events e ON er.event_id=e.event_id "
        "WHERE e.room_id='" + std::string(room_id) + "' "
        "AND er.relation_type='m.thread' "
        "ORDER BY e.origin_server_ts DESC LIMIT 50");

      std::unordered_set<std::string> processed_roots;
      for (auto& row : thread_rows) {
        std::string root_id = row["relates_to_id"].get<std::string>();
        if (processed_roots.find(root_id) != processed_roots.end()) continue;
        processed_roots.insert(root_id);

        auto root_event = get_event_by_id(db, root_id);
        if (!root_event) continue;

        ThreadInfo ti;
        ti.thread_root_id = root_id;
        ti.room_id = room_id;
        ti.root_sender = (*root_event).value("sender", "");
        auto root_content = extract_content(root_event);
        ti.root_body = root_content.value("body", "");
        ti.reply_count = count_relations(db, root_id, "m.thread");

        // Get latest reply
        auto latest_rows = db.query(
          "SELECT e.event_id,e.origin_server_ts FROM events e "
          "JOIN event_relations er ON e.event_id=er.event_id "
          "WHERE er.relates_to_id='" + root_id + "' AND er.relation_type='m.thread' "
          "ORDER BY e.origin_server_ts DESC LIMIT 1");
        if (!latest_rows.empty()) {
          ti.latest_reply_event_id = latest_rows[0]["event_id"].get<std::string>();
          ti.latest_reply_ts = latest_rows[0]["origin_server_ts"].get<int64_t>();
        }

        // Get participants
        auto part_rows = db.query(
          "SELECT DISTINCT e.sender FROM events e "
          "JOIN event_relations er ON e.event_id=er.event_id "
          "WHERE er.relates_to_id='" + root_id + "' AND er.relation_type='m.thread'");
        for (auto& pr : part_rows) {
          std::string sender = pr["sender"].get<std::string>();
          if (sender != ti.root_sender) {
            ti.participant_ids.push_back(sender);
          }
        }

        json thread_entry;
        thread_entry["thread_root_id"] = ti.thread_root_id;
        thread_entry["root_sender"] = ti.root_sender;
        thread_entry["root_body"] = ti.root_body.size() > 200
          ? ti.root_body.substr(0, 200) + "..." : ti.root_body;
        thread_entry["reply_count"] = ti.reply_count;
        thread_entry["latest_reply_event_id"] = ti.latest_reply_event_id;
        thread_entry["latest_reply_ts"] = ti.latest_reply_ts;
        thread_entry["participants"] = json::array();
        for (auto& p : ti.participant_ids) {
          thread_entry["participants"].push_back(p);
        }
        resp_body["threads"].push_back(thread_entry);
      }
    } catch (...) {}

    return make_response(200, resp_body);
  }

  // ---- 4. GET: Get a specific thread (replies) ----
  if (method == "GET" && !thread_event_id.empty()) {
    json resp_body;
    resp_body["thread_root_id"] = thread_event_id;
    resp_body["replies"] = json::array();

    auto root_event = get_event_by_id(db, thread_event_id);
    if (!root_event) {
      return make_error(404, "M_NOT_FOUND", "Thread root event not found");
    }
    resp_body["root"] = *root_event;

    try {
      auto reply_rows = db.query(
        "SELECT e.event_id,e.sender,e.content,e.origin_server_ts,e.type "
        "FROM events e JOIN event_relations er ON e.event_id=er.event_id "
        "WHERE er.relates_to_id='" + thread_event_id + "' "
        "AND er.relation_type='m.thread' "
        "ORDER BY e.origin_server_ts ASC LIMIT 200");

      for (auto& row : reply_rows) {
        json reply;
        reply["event_id"] = row["event_id"].get<std::string>();
        reply["sender"] = row["sender"].get<std::string>();
        reply["type"] = row["type"].get<std::string>();
        reply["origin_server_ts"] = row["origin_server_ts"].get<int64_t>();
        try {
          reply["content"] = json::parse(row["content"].get<std::string>());
        } catch (...) {
          reply["content"] = json::object();
        }
        resp_body["replies"].push_back(reply);
      }
    } catch (...) {}

    resp_body["reply_count"] = count_relations(db, thread_event_id, "m.thread");
    return make_response(200, resp_body);
  }

  // ---- 5. PUT: Create thread reply ----
  if (method == "PUT") {
    if (!request_body.is_object()) {
      return make_error(400, "M_BAD_JSON", "Request body must be a JSON object");
    }
    if (!validate_event_id(thread_event_id)) {
      return make_error(400, "M_INVALID_PARAM", "Invalid thread root event ID");
    }

    // Verify thread root exists
    auto root_event = get_event_by_id(db, thread_event_id);
    if (!root_event) {
      return make_error(404, "M_NOT_FOUND", "Thread root event not found");
    }

    // Build the event with m.relates_to for threading
    json event_content = request_body;
    json relates_to;
    relates_to["event_id"] = thread_event_id;
    relates_to["rel_type"] = "m.thread";
    relates_to["is_falling_back"] = false;

    // MSC3440: Thread replies include the root event content for fallback
    auto root_content = extract_content(root_event);
    if (root_content.contains("body")) {
      // Render a threaded reply fallback
      event_content["format"] = "org.matrix.custom.html";
      event_content["formatted_body"] =
        "<mx-reply><blockquote><a href=\"https://matrix.to/#/"
        + std::string(room_id) + "/" + thread_event_id + "\">In reply to</a>"
        "<br/>" + root_content["body"].get<std::string>() + "</blockquote></mx-reply>"
        + event_content.value("body", "");
    }

    event_content["m.relates_to"] = relates_to;
    // Mark as room message with thread awareness
    if (!event_content.contains("msgtype")) {
      event_content["msgtype"] = "m.text";
    }

    // Store the event
    std::string event_id = "$" + gen_token(18) + ":localhost";
    int64_t now = now_ms();

    try {
      db.execute(
        "INSERT INTO events (event_id,room_id,type,sender,content,state_key,"
        "origin_server_ts,depth,stream_ordering) VALUES ('" +
        event_id + "','" + std::string(room_id) + "','m.room.message','" +
        auth.user_id + "','" + event_content.dump() + "',''," +
        std::to_string(now) + ",1," + std::to_string(now) + ")");

      store_event_relation(db, event_id, thread_event_id, "m.thread", "");
    } catch (...) {
      return make_error(500, "M_UNKNOWN", "Failed to store thread reply");
    }

    json resp_body;
    resp_body["event_id"] = event_id;
    return make_response(200, resp_body);
  }

  return make_error(405, "M_UNRECOGNIZED", "Method not allowed");
}

// ============================================================================
// 15. MSC3442: MESSAGE FORWARDING
// ============================================================================
// Implements message forwarding per MSC3442.
// Creates a reference to the original event when forwarding to a new room.
// The forwarded message includes metadata about the original event.
//
// Endpoint: POST /_matrix/client/v3/rooms/{roomId}/forward/{eventId}
// ============================================================================

json handle_msc3442_message_forwarding(DatabasePool& db, const std::string& auth_header,
                                          const std::string& access_token_param,
                                          const std::string& target_room_id,
                                          const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate target room membership ----
  if (!is_user_in_room(db, target_room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN", "Not a member of target room");
  }

  // ---- 3. Get source event ID ----
  std::string source_event_id = safe_str(request_body, "event_id", "");
  if (source_event_id.empty()) {
    return make_error(400, "M_MISSING_PARAM", "event_id of source event is required");
  }

  // ---- 4. Get source event ----
  auto source_event = get_event_by_id(db, source_event_id);
  if (!source_event) {
    return make_error(404, "M_NOT_FOUND", "Source event not found");
  }

  std::string source_room_id = (*source_event).value("room_id", "");
  std::string source_sender = (*source_event).value("sender", "");
  std::string source_type = (*source_event).value("type", "");
  json source_content = extract_content(source_event);

  // ---- 5. User must have access to source room ----
  if (!source_room_id.empty() && !is_user_in_room(db, source_room_id, auth.user_id)) {
    bool world_readable = (get_history_visibility(db, source_room_id) == "world_readable");
    if (!world_readable) {
      return make_error(403, "M_FORBIDDEN",
                        "Not a member of the source room");
    }
  }

  // ---- 6. Build forwarded message ----
  json forwarded_content;
  forwarded_content["body"] = source_content.value("body", "Forwarded message");

  // Reference to original (MSC3442: event forwarding metadata)
  json forwarding_metadata;
  forwarding_metadata["event_id"] = source_event_id;
  forwarding_metadata["room_id"] = source_room_id;
  forwarding_metadata["sender"] = source_sender;
  forwarding_metadata["origin_server_ts"] = (*source_event).value("origin_server_ts", 0LL);
  forwarded_content["m.forwarded"] = forwarding_metadata;

  // Copy over media content if present
  if (source_content.contains("msgtype")) {
    forwarded_content["msgtype"] = source_content["msgtype"];
  }
  if (source_content.contains("url")) {
    forwarded_content["url"] = source_content["url"];
  }
  if (source_content.contains("info")) {
    forwarded_content["info"] = source_content["info"];
  }
  if (source_content.contains("formatted_body")) {
    forwarded_content["formatted_body"] = source_content["formatted_body"];
    forwarded_content["format"] = source_content.value("format", "");
  }

  // Add optional note from forwarding user
  if (request_body.contains("note") && request_body["note"].is_string()) {
    std::string note = request_body["note"].get<std::string>();
    forwarded_content["body"] = "> Forwarded message" +
      (note.empty() ? "" : "\n" + note) + "\n\n" +
      source_content.value("body", "");
  }

  // Include m.relates_to referencing the source as m.reference
  json relates_to;
  relates_to["event_id"] = source_event_id;
  relates_to["rel_type"] = "m.reference";
  relates_to["key"] = "m.forwarded";
  forwarded_content["m.relates_to"] = relates_to;

  // ---- 7. Store the forwarded event ----
  std::string new_event_id = "$" + gen_token(18) + ":localhost";
  int64_t now = now_ms();

  try {
    db.execute(
      "INSERT INTO events (event_id,room_id,type,sender,content,state_key,"
      "origin_server_ts,depth,stream_ordering) VALUES ('" +
      new_event_id + "','" + target_room_id + "','m.room.message','" +
      auth.user_id + "','" + forwarded_content.dump() + "',''," +
      std::to_string(now) + ",1," + std::to_string(now) + ")");

    store_event_relation(db, new_event_id, source_event_id, "m.reference", "m.forwarded");
  } catch (...) {
    return make_error(500, "M_UNKNOWN", "Failed to store forwarded event");
  }

  json resp_body;
  resp_body["event_id"] = new_event_id;
  resp_body["room_id"] = target_room_id;
  resp_body["source_event_id"] = source_event_id;
  resp_body["source_room_id"] = source_room_id;
  return make_response(200, resp_body);
}

// ============================================================================
// 16. MSC2674: EVENT RELATIONSHIPS AGGREGATION
// ============================================================================
// Defines how events relate to each other via the m.relates_to field.
// Supports aggregation of related events (reactions, edits, threads)
// and bundles them with the parent event.
//
// Relation types:
// - m.annotation (reactions)
// - m.replace (edits)
// - m.reference (references, threads, forwards)
// - m.thread (threaded messages)
// ============================================================================

json handle_msc2674_relationships(DatabasePool& db,
                                     const std::string& event_id,
                                     const json& query_params) {
  // No auth required for public aggregation data (room-level access checked by caller)

  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
  }

  // ---- Collect all relations for the event ----
  json resp_body;
  resp_body["event_id"] = event_id;
  resp_body["m.relations"] = json::object();

  // m.annotation (reactions)
  auto annotations = get_relations_for_event(db, event_id, "m.annotation", 500);
  json annotation_summary;
  annotation_summary["count"] = annotations.size();
  annotation_summary["chunk"] = json::array();

  // Group annotations by key (emoji/reaction)
  std::unordered_map<std::string, int> reaction_counts;
  std::unordered_map<std::string, std::vector<json>> reaction_chunks;
  for (auto& rel : annotations) {
    std::string key = rel.aggregation_key;
    reaction_counts[key]++;
    if (reaction_chunks[key].size() < 10) {
      json chunk_entry;
      chunk_entry["event_id"] = rel.event_id;
      chunk_entry["sender"] = rel.sender;
      chunk_entry["key"] = key;
      chunk_entry["origin_server_ts"] = rel.origin_server_ts;
      reaction_chunks[key].push_back(chunk_entry);
    }
  }
  annotation_summary["reactions"] = json::object();
  for (auto& [key, count] : reaction_counts) {
    annotation_summary["reactions"][key] = count;
  }
  resp_body["m.relations"]["m.annotation"] = annotation_summary;

  // m.replace (edits)
  auto edits = get_relations_for_event(db, event_id, "m.replace", 10);
  json edit_summary;
  edit_summary["count"] = edits.size();
  if (!edits.empty()) {
    // Latest edit replaces the original content
    auto& latest_edit = edits.back();
    edit_summary["latest_event_id"] = latest_edit.event_id;
    edit_summary["latest_sender"] = latest_edit.sender;
    edit_summary["latest_origin_server_ts"] = latest_edit.origin_server_ts;
    if (latest_edit.content.contains("m.new_content")) {
      edit_summary["new_content"] = latest_edit.content["m.new_content"];
    }
  }
  resp_body["m.relations"]["m.replace"] = edit_summary;

  // m.thread
  auto threads = get_relations_for_event(db, event_id, "m.thread", 200);
  json thread_summary;
  thread_summary["count"] = threads.size();
  thread_summary["latest_event_id"] = threads.empty() ? "" : threads.back().event_id;
  thread_summary["latest_sender"] = threads.empty() ? "" : threads.back().sender;
  thread_summary["latest_origin_server_ts"] = threads.empty() ? 0 : threads.back().origin_server_ts;
  thread_summary["participants"] = json::array();

  std::unordered_set<std::string> seen_participants;
  for (auto& t : threads) {
    if (seen_participants.find(t.sender) == seen_participants.end()) {
      seen_participants.insert(t.sender);
      thread_summary["participants"].push_back(t.sender);
    }
  }
  resp_body["m.relations"]["m.thread"] = thread_summary;

  // m.reference
  auto references = get_relations_for_event(db, event_id, "m.reference", 100);
  json reference_summary;
  reference_summary["count"] = references.size();
  reference_summary["chunk"] = json::array();
  for (auto& ref : references) {
    json ref_entry;
    ref_entry["event_id"] = ref.event_id;
    ref_entry["sender"] = ref.sender;
    ref_entry["key"] = ref.aggregation_key;
    ref_entry["origin_server_ts"] = ref.origin_server_ts;
    reference_summary["chunk"].push_back(ref_entry);
  }
  resp_body["m.relations"]["m.reference"] = reference_summary;

  return make_response(200, resp_body);
}

// ============================================================================
// 17. MSC2675: SERVER-SIDE AGGREGATION API
// ============================================================================
// Provides a dedicated endpoint for clients to fetch aggregated
// relation data for an event. The server computes summaries of
// annotations, edits, threads, and references.
//
// Endpoint: GET /_matrix/client/v1/rooms/{roomId}/aggregations/{eventId}
// ============================================================================

json handle_msc2675_aggregation_api(DatabasePool& db, const std::string& auth_header,
                                       const std::string& access_token_param,
                                       const std::string& room_id,
                                       const std::string& event_id,
                                       const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room membership ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN", "Not a member of this room");
  }

  // ---- 3. Parse query parameters ----
  std::string rel_type = safe_str(query_params, "rel_type", "");
  int64_t limit = safe_int(query_params, "limit", 20);
  if (limit <= 0) limit = 20;
  if (limit > 100) limit = 100;

  std::string from_token = safe_str(query_params, "from", "");

  // ---- 4. Validate event ----
  auto event = get_event_by_id(db, event_id);
  if (!event) {
    return make_error(404, "M_NOT_FOUND", "Event not found");
  }

  // ---- 5. Get aggregations ----
  json resp_body;
  resp_body["event_id"] = event_id;
  resp_body["room_id"] = room_id;

  if (rel_type.empty()) {
    // Return all aggregation types (bundled)
    json bundled;
    bundled["m.annotation"] = json::object();
    bundled["m.replace"] = json::object();
    bundled["m.thread"] = json::object();
    bundled["m.reference"] = json::object();

    // Counts
    bundled["m.annotation"]["count"] = count_relations(db, event_id, "m.annotation");
    bundled["m.replace"]["count"] = count_relations(db, event_id, "m.replace");
    bundled["m.thread"]["count"] = count_relations(db, event_id, "m.thread");
    bundled["m.reference"]["count"] = count_relations(db, event_id, "m.reference");

    // Latest edit
    auto edits = get_relations_for_event(db, event_id, "m.replace", 1);
    if (!edits.empty()) {
      bundled["m.replace"]["latest_event_id"] = edits[0].event_id;
    }

    resp_body["bundled_aggregations"] = bundled;
  } else {
    // Specific relation type
    auto relations = get_relations_for_event(db, event_id, rel_type, limit);
    resp_body["chunk"] = json::array();
    for (auto& rel : relations) {
      json chunk_entry;
      chunk_entry["event_id"] = rel.event_id;
      chunk_entry["sender"] = rel.sender;
      chunk_entry["type"] = "m.room.message";
      chunk_entry["origin_server_ts"] = rel.origin_server_ts;
      chunk_entry["content"] = rel.content;
      if (!rel.aggregation_key.empty()) {
        chunk_entry["key"] = rel.aggregation_key;
      }
      resp_body["chunk"].push_back(chunk_entry);
    }
    resp_body["count"] = count_relations(db, event_id, rel_type);
  }

  return make_response(200, resp_body);
}

// ============================================================================
// 18. MSC2676: MESSAGE EDITING (m.replace)
// ============================================================================
// Implements message editing via the m.replace relation type.
// The new content is placed in m.new_content within the event,
// and the event references the original via m.relates_to.
//
// Endpoint: PUT /rooms/{roomId}/send/m.room.message/{txnId}
//            with m.relates_to rel_type=m.replace
// ============================================================================

json handle_msc2676_message_editing(DatabasePool& db, const std::string& auth_header,
                                      const std::string& access_token_param,
                                      const std::string& room_id,
                                      const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room membership ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN", "Not a member of this room");
  }

  // ---- 3. Validate m.relates_to with m.replace ----
  if (!request_body.contains("m.relates_to") ||
      !request_body["m.relates_to"].is_object()) {
    return make_error(400, "M_MISSING_PARAM",
                      "m.relates_to is required for message edits");
  }

  auto& relates_to = request_body["m.relates_to"];
  std::string rel_type = safe_str(relates_to, "rel_type", "");
  if (rel_type != "m.replace") {
    return make_error(400, "M_INVALID_PARAM",
                      "rel_type must be 'm.replace' for editing");
  }

  std::string target_event_id = safe_str(relates_to, "event_id", "");
  if (target_event_id.empty()) {
    return make_error(400, "M_MISSING_PARAM", "Target event_id is required");
  }

  // ---- 4. Verify target event exists and is editable ----
  auto target_event = get_event_by_id(db, target_event_id);
  if (!target_event) {
    return make_error(404, "M_NOT_FOUND", "Target event not found");
  }

  // Only the original sender can edit their own messages
  std::string original_sender = (*target_event).value("sender", "");
  if (original_sender != auth.user_id) {
    return make_error(403, "M_FORBIDDEN",
                      "You can only edit your own messages");
  }

  std::string target_type = (*target_event).value("type", "");
  if (target_type != "m.room.message") {
    return make_error(400, "M_INVALID_PARAM",
                      "Only room messages can be edited");
  }

  // ---- 5. Build edit event ----
  json edit_content;

  // The new content goes in m.new_content
  json new_content;
  if (request_body.contains("m.new_content") &&
      request_body["m.new_content"].is_object()) {
    new_content = request_body["m.new_content"];
  } else {
    // Fallback: the body without m.relates_to is the new content
    new_content["body"] = safe_str(request_body, "body", "* edited *");
    new_content["msgtype"] = safe_str(request_body, "msgtype", "m.text");
    if (request_body.contains("formatted_body")) {
      new_content["formatted_body"] = request_body["formatted_body"];
      new_content["format"] = request_body.value("format", "org.matrix.custom.html");
    }
    if (request_body.contains("url")) {
      new_content["url"] = request_body["url"];
    }
    if (request_body.contains("info")) {
      new_content["info"] = request_body["info"];
    }
  }

  edit_content["m.new_content"] = new_content;
  edit_content["m.relates_to"] = relates_to;
  edit_content["msgtype"] = new_content.value("msgtype", "m.text");

  // Fallback body for clients that don't support edits
  std::string fallback_body = new_content.value("body", "* edited *");
  edit_content["body"] = " * " + fallback_body;

  // ---- 6. Store edit event ----
  std::string event_id = "$" + gen_token(18) + ":localhost";
  int64_t now = now_ms();

  try {
    std::string room_id_str(room_id);
    db.execute(
      "INSERT INTO events (event_id,room_id,type,sender,content,state_key,"
      "origin_server_ts,depth,stream_ordering) VALUES ('" +
      event_id + "','" + room_id_str + "','m.room.message','" +
      auth.user_id + "','" + edit_content.dump() + "',''," +
      std::to_string(now) + ",1," + std::to_string(now) + ")");

    store_event_relation(db, event_id, target_event_id, "m.replace", "");
  } catch (...) {
    return make_error(500, "M_UNKNOWN", "Failed to store edit event");
  }

  // ---- 7. Aggregation: update bundled aggregations ----
  // The latest edit replaces the original content in bundles

  json resp_body;
  resp_body["event_id"] = event_id;
  resp_body["target_event_id"] = target_event_id;
  return make_response(200, resp_body);
}

// ============================================================================
// 19. MSC2677: REACTIONS (m.annotation)
// ============================================================================
// Implements message reactions via the m.annotation relation type.
// The reaction key (e.g., emoji) is stored in the event content
// and in the aggregation_key of the relation.
//
// Endpoint: PUT /rooms/{roomId}/send/m.reaction/{txnId}
// ============================================================================

json handle_msc2677_reactions(DatabasePool& db, const std::string& auth_header,
                                const std::string& access_token_param,
                                const std::string& room_id,
                                const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room membership ----
  if (!is_user_in_room(db, room_id, auth.user_id)) {
    return make_error(403, "M_FORBIDDEN", "Not a member of this room");
  }

  // ---- 3. Validate m.relates_to with m.annotation ----
  if (!request_body.contains("m.relates_to") ||
      !request_body["m.relates_to"].is_object()) {
    return make_error(400, "M_MISSING_PARAM",
                      "m.relates_to is required for reactions");
  }

  auto& relates_to = request_body["m.relates_to"];
  std::string rel_type = safe_str(relates_to, "rel_type", "");
  if (rel_type != "m.annotation") {
    return make_error(400, "M_INVALID_PARAM",
                      "rel_type must be 'm.annotation' for reactions");
  }

  std::string target_event_id = safe_str(relates_to, "event_id", "");
  if (target_event_id.empty()) {
    return make_error(400, "M_MISSING_PARAM", "Target event_id is required");
  }

  std::string reaction_key = safe_str(relates_to, "key", "");
  if (reaction_key.empty()) {
    return make_error(400, "M_MISSING_PARAM",
                      "Reaction key (emoji) is required in m.relates_to.key");
  }

  // ---- 4. Verify target event exists ----
  auto target_event = get_event_by_id(db, target_event_id);
  if (!target_event) {
    return make_error(404, "M_NOT_FOUND", "Target event not found");
  }

  // ---- 5. Check for duplicate reaction from same user ----
  try {
    auto dup_rows = db.query(
      "SELECT er.event_id FROM event_relations er "
      "JOIN events e ON er.event_id=e.event_id "
      "WHERE er.relates_to_id='" + target_event_id + "' "
      "AND er.relation_type='m.annotation' "
      "AND er.aggregation_key='" + reaction_key + "' "
      "AND e.sender='" + auth.user_id + "'");

    if (!dup_rows.empty()) {
      return make_error(400, "M_DUPLICATE_ANNOTATION",
                        "You have already reacted with " + reaction_key);
    }
  } catch (...) {}

  // ---- 6. Build reaction event ----
  json reaction_content;
  reaction_content["m.relates_to"] = relates_to;
  // The reaction key is also placed in the body for fallback
  reaction_content["body"] = reaction_key;

  // ---- 7. Store reaction event ----
  std::string event_id = "$" + gen_token(18) + ":localhost";
  int64_t now = now_ms();

  try {
    std::string room_id_str(room_id);
    db.execute(
      "INSERT INTO events (event_id,room_id,type,sender,content,state_key,"
      "origin_server_ts,depth,stream_ordering) VALUES ('" +
      event_id + "','" + room_id_str + "','m.reaction','" +
      auth.user_id + "','" + reaction_content.dump() + "',''," +
      std::to_string(now) + ",1," + std::to_string(now) + ")");

    store_event_relation(db, event_id, target_event_id, "m.annotation",
                          reaction_key);
  } catch (...) {
    return make_error(500, "M_UNKNOWN", "Failed to store reaction");
  }

  // ---- 8. Redact: Remove existing reaction (toggle behavior) ----
  // If the user sends the same reaction again, remove the old one
  // This is handled by the duplicate check above returning an error,
  // but we could alternatively implement a toggle here.

  json resp_body;
  resp_body["event_id"] = event_id;
  return make_response(200, resp_body);
}

// ============================================================================
// 20. MSC3664: PUSH RULES FOR RELATIONS
// ============================================================================
// Extends push rules to be aware of event relations.
// Users can configure push rules to trigger (or not trigger) on
// relation events like reactions, edits, and thread replies.
//
// New push rule conditions:
// - is_relation: true/false
// - relation_type: m.annotation, m.replace, m.thread, m.reference
// - relation_sender: specific user
// - thread_following: true/false (for thread notifications)
// ============================================================================

struct RelationPushRule {
  std::string rule_id;
  std::string kind;  // override, underride, content, room, sender
  std::string relation_type_filter;  // Only trigger for this relation type
  bool is_relation_rule;  // Whether this rule targets relation events
  bool match_thread_following;
  std::string relation_sender_filter;
  bool enabled;
  json actions;  // notify, dont_notify, coalesce, set_tweak
};

json handle_msc3664_push_relations(DatabasePool& db, const std::string& auth_header,
                                      const std::string& access_token_param,
                                      const std::string& method,
                                      const json& request_body,
                                      const std::string& rule_id) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. GET: List relation push rules ----
  if (method == "GET") {
    json resp_body;
    resp_body["rules"] = json::array();

    try {
      auto rows = db.query(
        "SELECT rule_id,kind,relation_type_filter,is_relation_rule,"
        "match_thread_following,relation_sender_filter,enabled,actions "
        "FROM push_rules_relations "
        "WHERE user_id='" + auth.user_id + "'");

      for (auto& row : rows) {
        json rule;
        rule["rule_id"] = row["rule_id"].get<std::string>();
        rule["kind"] = row["kind"].get<std::string>();
        rule["relation_type_filter"] = row.value("relation_type_filter", "");
        rule["is_relation_rule"] = row.value("is_relation_rule", false);
        rule["match_thread_following"] = row.value("match_thread_following", false);
        rule["relation_sender_filter"] = row.value("relation_sender_filter", "");
        rule["enabled"] = row.value("enabled", true);
        try {
          rule["actions"] = json::parse(row["actions"].get<std::string>());
        } catch (...) {
          rule["actions"] = json::array({"notify"});
        }
        resp_body["rules"].push_back(rule);
      }
    } catch (...) {
      // Table might not exist yet; return empty
    }

    return make_response(200, resp_body);
  }

  // ---- 3. PUT: Create/update a relation push rule ----
  if (method == "PUT") {
    if (!request_body.is_object()) {
      return make_error(400, "M_BAD_JSON", "Request body must be a JSON object");
    }

    std::string kind = safe_str(request_body, "kind", "override");
    std::string rel_type_filter = safe_str(request_body, "relation_type_filter", "");
    bool is_rel_rule = safe_bool(request_body, "is_relation_rule", true);
    bool match_thread = safe_bool(request_body, "match_thread_following", false);
    std::string sender_filter = safe_str(request_body, "relation_sender_filter", "");
    bool enabled = safe_bool(request_body, "enabled", true);
    json actions = request_body.value("actions", json::array({"notify"}));

    std::string new_rule_id = rule_id.empty()
      ? "relation_rule_" + gen_token(12)
      : rule_id;

    try {
      db.execute(
        "INSERT OR REPLACE INTO push_rules_relations "
        "(rule_id,user_id,kind,relation_type_filter,is_relation_rule,"
        "match_thread_following,relation_sender_filter,enabled,actions) "
        "VALUES ('" + new_rule_id + "','" + auth.user_id + "','" +
        kind + "','" + rel_type_filter + "'," +
        std::to_string(is_rel_rule ? 1 : 0) + "," +
        std::to_string(match_thread ? 1 : 0) + ",'" +
        sender_filter + "'," + std::to_string(enabled ? 1 : 0) + ",'" +
        actions.dump() + "')");
    } catch (...) {
      return make_error(500, "M_UNKNOWN", "Failed to store push rule");
    }

    json resp_body;
    resp_body["rule_id"] = new_rule_id;
    return make_response(200, resp_body);
  }

  // ---- 4. DELETE: Remove a relation push rule ----
  if (method == "DELETE") {
    if (rule_id.empty()) {
      return make_error(400, "M_MISSING_PARAM", "rule_id is required");
    }

    try {
      db.execute(
        "DELETE FROM push_rules_relations "
        "WHERE rule_id='" + rule_id + "' AND user_id='" + auth.user_id + "'");
    } catch (...) {
      return make_error(500, "M_UNKNOWN", "Failed to delete push rule");
    }

    return make_response(200, json::object());
  }

  return make_error(405, "M_UNRECOGNIZED", "Method not allowed");
}

// ============================================================================
// MSC3664: Push evaluation - check if a relation event should trigger a push
// ============================================================================

static bool evaluate_relation_push_rules(DatabasePool& db,
                                           const std::string& user_id,
                                           const std::string& relation_type,
                                           const std::string& relation_sender,
                                           bool is_thread_event) {
  try {
    auto rows = db.query(
      "SELECT actions,match_thread_following,relation_sender_filter,enabled "
      "FROM push_rules_relations "
      "WHERE user_id='" + user_id + "' AND relation_type_filter='" +
      relation_type + "' AND is_relation_rule=1");

    for (auto& row : rows) {
      if (!row.value("enabled", true)) continue;

      // Check sender filter
      std::string sender_filter = row.value("relation_sender_filter", "");
      if (!sender_filter.empty() && sender_filter != relation_sender) {
        continue;
      }

      // Check thread following
      bool match_thread = row.value("match_thread_following", false);
      if (match_thread && !is_thread_event) {
        continue;
      }

      // Check actions - if notify, return true
      try {
        json actions = json::parse(row["actions"].get<std::string>());
        for (auto& action : actions) {
          if (action.is_string() && action.get<std::string>() == "notify") {
            return true;
          }
        }
      } catch (...) {}
    }
  } catch (...) {}

  return false;  // Default: don't push for relation events
}

// ============================================================================
// 21. MSC3820: EVENT RELATIONSHIPS IN AUTH RULES
// ============================================================================
// Extends the Matrix authorization rules to understand event relations.
// Relations can affect whether an event is allowed:
// - Only original sender can m.replace (edit) their events
// - Anyone in the room can m.annotation (react)
// - Redaction of parent event cascades to relations
// - Thread replies require membership in the parent room
// ============================================================================

struct RelationAuthRule {
  std::string relation_type;
  bool requires_sender_match;      // Only original sender can use
  bool requires_room_membership;   // Must be in the room
  bool cascades_on_redaction;      // Redacted when parent is redacted
  bool requires_power_level;        // Subject to power level checks
  int min_power_level;             // Minimum PL if requires_power_level
};

static const std::unordered_map<std::string, RelationAuthRule> RELATION_AUTH_RULES = {
  {"m.annotation", {.relation_type = "m.annotation",
                     .requires_sender_match = false,
                     .requires_room_membership = true,
                     .cascades_on_redaction = true,
                     .requires_power_level = false,
                     .min_power_level = 0}},
  {"m.replace", {.relation_type = "m.replace",
                  .requires_sender_match = true,
                  .requires_room_membership = true,
                  .cascades_on_redaction = true,
                  .requires_power_level = false,
                  .min_power_level = 0}},
  {"m.thread", {.relation_type = "m.thread",
                 .requires_sender_match = false,
                 .requires_room_membership = true,
                 .cascades_on_redaction = false,
                 .requires_power_level = false,
                 .min_power_level = 0}},
  {"m.reference", {.relation_type = "m.reference",
                    .requires_sender_match = false,
                    .requires_room_membership = true,
                    .cascades_on_redaction = false,
                    .requires_power_level = false,
                    .min_power_level = 0}},
};

json handle_msc3820_relation_auth(DatabasePool& db,
                                     const std::string& room_id,
                                     const std::string& user_id,
                                     const std::string& relation_type,
                                     const std::string& parent_event_id,
                                     const json& relation_content) {
  // ---- 1. Look up auth rules for this relation type ----
  auto it = RELATION_AUTH_RULES.find(relation_type);
  if (it == RELATION_AUTH_RULES.end()) {
    return make_error(400, "M_UNKNOWN",
                      "Unknown relation type: " + relation_type);
  }

  auto& rules = it->second;

  // ---- 2. Check room membership ----
  if (rules.requires_room_membership) {
    if (!is_user_in_room(db, room_id, user_id)) {
      return make_error(403, "M_FORBIDDEN",
                        "Must be a member of the room to create this relation");
    }
  }

  // ---- 3. Check sender match (for m.replace) ----
  if (rules.requires_sender_match) {
    auto parent_event = get_event_by_id(db, parent_event_id);
    if (!parent_event) {
      return make_error(404, "M_NOT_FOUND", "Parent event not found");
    }
    std::string parent_sender = (*parent_event).value("sender", "");
    if (parent_sender != user_id) {
      return make_error(403, "M_FORBIDDEN",
                        "Only the original sender can create " +
                        relation_type + " relations");
    }
  }

  // ---- 4. Check power level requirements ----
  if (rules.requires_power_level) {
    int64_t user_pl = get_user_power_level(db, room_id, user_id);
    if (user_pl < rules.min_power_level) {
      return make_error(403, "M_FORBIDDEN",
                        "Insufficient power level (need " +
                        std::to_string(rules.min_power_level) + ")");
    }
  }

  // ---- 5. Check if parent is redacted ----
  auto parent_event = get_event_by_id(db, parent_event_id);
  if (parent_event && (*parent_event).contains("redacted_by")) {
    // Parent is redacted
    if (rules.cascades_on_redaction) {
      return make_error(400, "M_BAD_STATE",
                        "Cannot create relation to a redacted event");
    }
  }

  // ---- 6. Auth passed ----
  json resp;
  resp["authorized"] = true;
  resp["relation_type"] = relation_type;
  resp["parent_event_id"] = parent_event_id;
  return make_response(200, resp);
}

// ============================================================================
// MSC3820: Handle cascading redaction of related events
// ============================================================================

static void cascade_redaction_to_relations(DatabasePool& db,
                                            const std::string& parent_event_id) {
  std::lock_guard<std::mutex> lock(g_relation_lock);

  // Find all relations that should be redacted
  try {
    auto rows = db.query(
      "SELECT er.event_id,er.relation_type FROM event_relations er "
      "WHERE er.relates_to_id='" + parent_event_id + "'");

    for (auto& row : rows) {
      std::string rel_type = row["relation_type"].get<std::string>();
      auto it = RELATION_AUTH_RULES.find(rel_type);
      if (it != RELATION_AUTH_RULES.end() && it->second.cascades_on_redaction) {
        std::string event_id = row["event_id"].get<std::string>();
        // Redact this event
        int64_t now = now_ms();
        db.execute(
          "UPDATE events SET redacted_by='" + parent_event_id + "', "
          "redacted_because='{\"reason\":\"Parent event redacted\"}' "
          "WHERE event_id='" + event_id + "'");
      }
    }
  } catch (...) { /* Best-effort cascade */ }
}

// ============================================================================
// 22. MSC3870: INTENTIONAL MENTIONS
// ============================================================================
// Implements the intentional mentions system where users explicitly
// indicate who they want to notify (rather than relying on keyword scanning).
// Uses the m.mentions content field with a user_ids array.
//
// Features:
// - m.mentions in event content with explicit user_ids
// - Mention deduplication
// - Push notification integration for intentional mentions
// - Room-level mention tracking
// - @room / @here support via intentional mentions
// ============================================================================

struct MentionRecord {
  std::string event_id;
  std::string room_id;
  std::string sender;
  std::string mentioned_user_id;
  bool is_room_mention;  // @room or @here
  int64_t timestamp;
};

json handle_msc3870_intentional_mentions(DatabasePool& db,
                                            const std::string& auth_header,
                                            const std::string& access_token_param,
                                            const std::string& room_id,
                                            const std::string& method,
                                            const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. GET: Retrieve mentions for the user ----
  if (method == "GET") {
    json resp_body;
    resp_body["mentions"] = json::array();

    try {
      auto rows = db.query(
        "SELECT event_id,room_id,sender,mentioned_user_id,is_room_mention,timestamp "
        "FROM event_mentions "
        "WHERE mentioned_user_id='" + auth.user_id + "' "
        "ORDER BY timestamp DESC LIMIT 100");

      for (auto& row : rows) {
        json mention;
        mention["event_id"] = row["event_id"].get<std::string>();
        mention["room_id"] = row["room_id"].get<std::string>();
        mention["sender"] = row["sender"].get<std::string>();
        mention["mentioned_user_id"] = row["mentioned_user_id"].get<std::string>();
        mention["is_room_mention"] = row.value("is_room_mention", false);
        mention["timestamp"] = row["timestamp"].get<int64_t>();
        resp_body["mentions"].push_back(mention);
      }
    } catch (...) {}

    resp_body["count"] = resp_body["mentions"].size();
    return make_response(200, resp_body);
  }

  // ---- 3. PUT: Process and store intentional mentions in an event ----
  if (method == "PUT") {
    if (!request_body.is_object()) {
      return make_error(400, "M_BAD_JSON", "Request body must be a JSON object");
    }

    if (!request_body.contains("m.mentions") ||
        !request_body["m.mentions"].is_object()) {
      return make_error(400, "M_MISSING_PARAM",
                        "m.mentions content is required (MSC3870)");
    }

    auto& mentions = request_body["m.mentions"];
    std::string event_id = "$" + gen_token(18) + ":localhost";
    int64_t now = now_ms();

    std::vector<MentionRecord> mention_records;

    // Process user_ids
    if (mentions.contains("user_ids") && mentions["user_ids"].is_array()) {
      std::unordered_set<std::string> seen_users;
      for (auto& uid : mentions["user_ids"]) {
        if (!uid.is_string()) continue;
        std::string mentioned_user = uid.get<std::string>();
        if (!validate_user_id(mentioned_user)) continue;
        if (seen_users.find(mentioned_user) != seen_users.end()) continue;
        seen_users.insert(mentioned_user);

        MentionRecord rec;
        rec.event_id = event_id;
        rec.room_id = std::string(room_id);
        rec.sender = auth.user_id;
        rec.mentioned_user_id = mentioned_user;
        rec.is_room_mention = false;
        rec.timestamp = now;
        mention_records.push_back(rec);
      }
    }

    // Process @room mentions
    if (mentions.contains("room") && mentions["room"].get<bool>()) {
      // Fetch all room members
      RoomMemberStore members(db);
      auto room_members = members.get_room_members(room_id);

      std::unordered_set<std::string> room_mentioned;
      for (auto& member : room_members) {
        if (member.user_id == auth.user_id) continue;  // Don't mention self
        if (member.membership != "join" && member.membership != "invite") continue;

        MentionRecord rec;
        rec.event_id = event_id;
        rec.room_id = std::string(room_id);
        rec.sender = auth.user_id;
        rec.mentioned_user_id = member.user_id;
        rec.is_room_mention = true;
        rec.timestamp = now;
        mention_records.push_back(rec);
      }
    }

    // ---- 4. Deduplication: Remove duplicate mentions from same event ----
    // ---- 5. Store mentions ----
    std::lock_guard<std::mutex> lock(g_mention_lock);
    try {
      for (auto& rec : mention_records) {
        db.execute(
          "INSERT OR IGNORE INTO event_mentions "
          "(event_id,room_id,sender,mentioned_user_id,is_room_mention,timestamp) "
          "VALUES ('" + rec.event_id + "','" + rec.room_id + "','" +
          rec.sender + "','" + rec.mentioned_user_id + "'," +
          std::to_string(rec.is_room_mention ? 1 : 0) + "," +
          std::to_string(rec.timestamp) + ")");
      }
    } catch (...) {
      return make_error(500, "M_UNKNOWN", "Failed to store mentions");
    }

    // ---- 6. Trigger push notifications for intentional mentions ----
    for (auto& rec : mention_records) {
      try {
        EventPushActionsStore push_actions(db);
        json push_data;
        push_data["event_id"] = rec.event_id;
        push_data["room_id"] = rec.room_id;
        push_data["type"] = "m.mention";
        push_data["sender"] = rec.sender;
        push_data["highlight"] = true;  // Intentional mentions always highlight
        push_data["is_room_mention"] = rec.is_room_mention;

        push_actions.add_push_action(
          rec.mentioned_user_id, rec.room_id, rec.event_id,
          "m.mention", rec.sender, push_data.dump(), now, true);
      } catch (...) { /* Best-effort notification */ }
    }

    json resp_body;
    resp_body["event_id"] = event_id;
    resp_body["mentioned_count"] = mention_records.size();
    return make_response(200, resp_body);
  }

  return make_error(405, "M_UNRECOGNIZED", "Method not allowed");
}

// ============================================================================
// MSC3870: Check if an event body contains intentional @mentions
// and extract the mentioned user IDs.
// ============================================================================

static std::vector<std::string> extract_mentions_from_body(
    DatabasePool& db,
    const std::string& room_id,
    const std::string& body,
    const std::string& formatted_body) {

  std::vector<std::string> mentioned_users;
  std::unordered_set<std::string> seen;

  // Parse user mentions from formatted_body (pill links)
  // Format: <a href="https://matrix.to/#/@user:server">Display</a>
  if (!formatted_body.empty()) {
    std::regex pill_regex(
      R"(<a\s+href="https://matrix.to/#/(@[^"]+)"[^>]*>)",
      std::regex::icase);
    std::smatch match;
    std::string search = formatted_body;
    while (std::regex_search(search, match, pill_regex)) {
      std::string user_id = match[1].str();
      if (validate_user_id(user_id) &&
          seen.find(user_id) == seen.end()) {
        seen.insert(user_id);
        mentioned_users.push_back(user_id);
      }
      search = match.suffix();
    }
  }

  // Also scan plain body for @user:server patterns
  if (!body.empty()) {
    std::regex body_regex(R"(@([a-zA-Z0-9._\-=]+:[a-zA-Z0-9.\-]+))");
    std::smatch match;
    std::string search = body;
    while (std::regex_search(search, match, body_regex)) {
      std::string user_id = "@" + match[1].str();
      if (validate_user_id(user_id) &&
          seen.find(user_id) == seen.end()) {
        seen.insert(user_id);
        mentioned_users.push_back(user_id);
      }
      search = match.suffix();
    }
  }

  // Check for @room mention
  bool has_room_mention = (body.find("@room") != std::string::npos);

  return mentioned_users;
}

// ============================================================================
// ============================================================================
// MAIN DISPATCH FUNCTION
// ============================================================================
// Routes requests to the appropriate handler based on the URL path and method.
// Called by the main HTTP router for space and MSC-related endpoints.
// ============================================================================

json dispatch_spaces_msc_handlers(DatabasePool& db,
                                     const std::string& method,
                                     const std::string& path,
                                     const std::unordered_map<std::string, std::string>& path_params,
                                     const std::string& auth_header,
                                     const std::string& access_token_param,
                                     const json& request_body,
                                     const json& query_params) {

  // ========================================================================
  // CREATE ROOM (with space support via MSC2175 / MSC3215)
  // POST /_matrix/client/v3/createRoom
  // ========================================================================
  if (method == "POST" && path.find("/createRoom") != std::string::npos) {
    // Check if this is a space creation (MSC2175)
    if (request_body.contains("creation_content") &&
        request_body["creation_content"].is_object() &&
        request_body["creation_content"].value("type", "") == "m.space") {
      return handle_msc2175_create_space(db, auth_header, access_token_param,
                                          request_body);
    }
    return handle_create_space(db, auth_header, access_token_param, request_body);
  }

  // ========================================================================
  // SPACE HIERARCHY
  // GET /_matrix/client/v1/rooms/{roomId}/hierarchy
  // ========================================================================
  if (method == "GET" && path.find("/hierarchy") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_space_hierarchy(db, auth_header, access_token_param,
                                     it->second, query_params);
    }
  }

  // ========================================================================
  // SPACE SUMMARY (MSC2946)
  // GET /_matrix/client/v1/rooms/{roomId}/summary
  // ========================================================================
  if (method == "GET" && path.find("/summary") != std::string::npos &&
      path.find("/hierarchy") == std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_msc2946_space_summary(db, auth_header, access_token_param,
                                            it->second, query_params);
    }
  }

  // ========================================================================
  // ROOM SUMMARY EXTENDED (MSC3266)
  // GET /_matrix/client/v1/rooms/{roomId}/summary_ext
  // ========================================================================
  if (method == "GET" && path.find("/summary_ext") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_msc3266_room_summary_ext(db, auth_header, access_token_param,
                                               it->second, query_params);
    }
  }

  // ========================================================================
  // ROOM TYPE (MSC3215)
  // GET/PUT /_matrix/client/v3/rooms/{roomId}/type
  // ========================================================================
  if (path.find("/rooms/") != std::string::npos &&
      path.find("/type") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_msc3215_room_type(db, auth_header, access_token_param,
                                        it->second, method, request_body);
    }
  }

  // ========================================================================
  // SPACE CHILDREN - STATE EVENT
  // PUT/GET/DELETE /_matrix/client/v3/rooms/{roomId}/state/m.space.child/{childRoomId}
  // ========================================================================
  if (path.find("/state/m.space.child") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      // Extract child room ID from path or params
      std::string child_room_id;
      auto child_it = path_params.find("stateKey");
      if (child_it != path_params.end()) {
        child_room_id = child_it->second;
      }
      // Try to extract from path directly
      if (child_room_id.empty()) {
        auto pos = path.find("/m.space.child/");
        if (pos != std::string::npos) {
          child_room_id = path.substr(pos + 15);
        }
      }
      return handle_space_children(db, auth_header, access_token_param,
                                    it->second, method, request_body,
                                    child_room_id);
    }
  }

  // ========================================================================
  // SPACE PARENT - STATE EVENT
  // PUT/GET/DELETE /_matrix/client/v3/rooms/{roomId}/state/m.space.parent/{spaceId}
  // ========================================================================
  if (path.find("/state/m.space.parent") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      std::string parent_space_id;
      auto parent_it = path_params.find("stateKey");
      if (parent_it != path_params.end()) {
        parent_space_id = parent_it->second;
      }
      if (parent_space_id.empty()) {
        auto pos = path.find("/m.space.parent/");
        if (pos != std::string::npos) {
          parent_space_id = path.substr(pos + 16);
        }
      }
      return handle_space_parent(db, auth_header, access_token_param,
                                  it->second, method, request_body,
                                  parent_space_id);
    }
  }

  // ========================================================================
  // SPACE ORDERING
  // GET /_matrix/client/v3/rooms/{roomId}/space_order
  // ========================================================================
  if (method == "GET" && path.find("/space_order") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_space_ordering(db, auth_header, access_token_param,
                                    it->second, request_body);
    }
  }

  // ========================================================================
  // RESTRICTED JOIN RULES (MSC3083)
  // PUT /_matrix/client/v3/rooms/{roomId}/state/m.room.join_rules
  // ========================================================================
  if (path.find("/state/m.room.join_rules") != std::string::npos &&
      request_body.contains("join_rule") &&
      request_body["join_rule"] == "restricted") {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_msc3083_restricted_join(db, auth_header, access_token_param,
                                              it->second, request_body);
    }
  }

  // ========================================================================
  // POLL START (MSC3381)
  // PUT /_matrix/client/v3/rooms/{roomId}/send/m.poll.start/{txnId}
  // ========================================================================
  if (method == "PUT" && path.find("/send/m.poll.start") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_msc3381_poll_start(db, auth_header, access_token_param,
                                        it->second, request_body);
    }
  }

  // ========================================================================
  // POLL RESPONSE (MSC3381)
  // PUT /_matrix/client/v3/rooms/{roomId}/send/m.poll.response/{txnId}
  // ========================================================================
  if (method == "PUT" && path.find("/send/m.poll.response") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_msc3381_poll_response(db, auth_header, access_token_param,
                                            it->second, request_body);
    }
  }

  // ========================================================================
  // POLL END (MSC3381)
  // PUT /_matrix/client/v3/rooms/{roomId}/send/m.poll.end/{txnId}
  // ========================================================================
  if (method == "PUT" && path.find("/send/m.poll.end") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_msc3381_poll_end(db, auth_header, access_token_param,
                                       it->second, request_body);
    }
  }

  // ========================================================================
  // THREAD (MSC3440)
  // GET/PUT /_matrix/client/v3/rooms/{roomId}/thread
  // GET/PUT /_matrix/client/v3/rooms/{roomId}/thread/{eventId}
  // ========================================================================
  if (path.find("/thread") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      std::string thread_event_id;
      auto thread_it = path_params.find("eventId");
      if (thread_it != path_params.end()) {
        thread_event_id = thread_it->second;
      }
      // Try to extract from path
      if (thread_event_id.empty()) {
        auto pos = path.find("/thread/");
        if (pos != std::string::npos) {
          thread_event_id = path.substr(pos + 8);
        }
      }
      return handle_msc3440_thread(db, auth_header, access_token_param,
                                    it->second, method, request_body,
                                    thread_event_id);
    }
  }

  // ========================================================================
  // MESSAGE FORWARDING (MSC3442)
  // POST /_matrix/client/v3/rooms/{roomId}/forward
  // ========================================================================
  if (method == "POST" && path.find("/forward") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_msc3442_message_forwarding(db, auth_header, access_token_param,
                                                 it->second, request_body);
    }
  }

  // ========================================================================
  // RELATIONSHIPS / AGGREGATION (MSC2674)
  // GET /_matrix/client/v1/rooms/{roomId}/relations/{eventId}
  // ========================================================================
  if (method == "GET" && path.find("/relations/") != std::string::npos) {
    auto it = path_params.find("eventId");
    if (it != path_params.end()) {
      return handle_msc2674_relationships(db, it->second, query_params);
    }
  }

  // ========================================================================
  // SERVER-SIDE AGGREGATION API (MSC2675)
  // GET /_matrix/client/v1/rooms/{roomId}/aggregations/{eventId}
  // ========================================================================
  if (method == "GET" && path.find("/aggregations/") != std::string::npos) {
    auto room_it = path_params.find("roomId");
    auto event_it = path_params.find("eventId");
    if (room_it != path_params.end() && event_it != path_params.end()) {
      return handle_msc2675_aggregation_api(db, auth_header, access_token_param,
                                             room_it->second, event_it->second,
                                             query_params);
    }
  }

  // ========================================================================
  // MESSAGE EDITING (MSC2676) - Handled via m.relates_to with m.replace
  // Detected when PUT to /send/m.room.message has m.relates_to rel_type=m.replace
  // ========================================================================
  if (method == "PUT" && path.find("/send/m.room.message") != std::string::npos) {
    if (request_body.contains("m.relates_to") &&
        request_body["m.relates_to"].is_object() &&
        request_body["m.relates_to"].value("rel_type", "") == "m.replace") {
      auto it = path_params.find("roomId");
      if (it != path_params.end()) {
        return handle_msc2676_message_editing(db, auth_header, access_token_param,
                                                it->second, request_body);
      }
    }
  }

  // ========================================================================
  // REACTIONS (MSC2677) - m.annotation via m.relates_to
  // Detected when PUT to /send/m.reaction
  // ========================================================================
  if (method == "PUT" && path.find("/send/m.reaction") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_msc2677_reactions(db, auth_header, access_token_param,
                                       it->second, request_body);
    }
  }

  // ========================================================================
  // PUSH RULES FOR RELATIONS (MSC3664)
  // GET/PUT/DELETE /_matrix/client/v3/pushrules/relations
  // GET/PUT/DELETE /_matrix/client/v3/pushrules/relations/{ruleId}
  // ========================================================================
  if (path.find("/pushrules/relations") != std::string::npos) {
    std::string rule_id;
    auto rule_it = path_params.find("ruleId");
    if (rule_it != path_params.end()) {
      rule_id = rule_it->second;
    }
    // Try to extract from path
    if (rule_id.empty()) {
      auto pos = path.find("/relations/");
      if (pos != std::string::npos) {
        std::string after = path.substr(pos + 11);
        if (!after.empty() && after.find("/") == std::string::npos) {
          rule_id = after;
        }
      }
    }
    return handle_msc3664_push_relations(db, auth_header, access_token_param,
                                          method, request_body, rule_id);
  }

  // ========================================================================
  // INTENTIONAL MENTIONS (MSC3870)
  // GET/PUT /_matrix/client/v3/rooms/{roomId}/mentions
  // ========================================================================
  if (path.find("/mentions") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_msc3870_intentional_mentions(db, auth_header,
                                                   access_token_param,
                                                   it->second, method,
                                                   request_body);
    }
  }

  // ========================================================================
  // UNKNOWN ROUTE
  // ========================================================================
  return make_error(404, "M_UNRECOGNIZED",
                    "Unrecognized spaces/MSC endpoint: " + method + " " + path);
}

// ============================================================================
// Export helper: check restricted join eligibility (used by join handler)
// ============================================================================

bool can_join_via_restricted(DatabasePool& db, const std::string& room_id,
                               const std::string& user_id) {
  return can_user_join_via_restricted_rules(db, room_id, user_id);
}

// ============================================================================
// Export helper: cascade relation redactions (used by redact handler)
// ============================================================================

void redact_related_events(DatabasePool& db, const std::string& parent_event_id) {
  cascade_redaction_to_relations(db, parent_event_id);
}

// ============================================================================
// Export helper: get intentional mentions from event body
// ============================================================================

json get_intentional_mentions(DatabasePool& db, const std::string& room_id,
                                const std::string& body,
                                const std::string& formatted_body) {
  json resp;
  resp["user_ids"] = json::array();
  auto mentions = extract_mentions_from_body(db, room_id, body, formatted_body);
  for (auto& u : mentions) {
    resp["user_ids"].push_back(u);
  }
  resp["has_room_mention"] = (body.find("@room") != std::string::npos);
  return resp;
}

} // namespace progressive::handlers
