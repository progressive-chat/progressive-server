// room_handlers.cpp - Matrix Room Management Handlers
// Implements all room lifecycle handlers: create, join, leave, forget,
// invite, kick, ban, unban, aliases, upgrade, knock.
// Target: 3000+ lines
//
// Handlers:
//   1.  create_room    - POST /createRoom
//   2.  join_room      - POST /join/{roomIdOrAlias}
//   3.  leave_room     - POST /rooms/{roomId}/leave
//   4.  forget_room    - POST /rooms/{roomId}/forget
//   5.  invite_user    - POST /rooms/{roomId}/invite
//   6.  kick_user      - POST /rooms/{roomId}/kick
//   7.  ban_user       - POST /rooms/{roomId}/ban
//   8.  unban_user     - POST /rooms/{roomId}/unban
//   9.  create_alias   - PUT /directory/room/{roomAlias}
//  10.  get_alias      - GET /directory/room/{roomAlias}
//  11.  delete_alias   - DELETE /directory/room/{roomAlias}
//  12.  upgrade_room   - POST /rooms/{roomId}/upgrade
//  13.  knock           - POST /knock/{roomIdOrAlias}

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

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Global utilities (shared across handlers)
// ============================================================================

static std::atomic<int64_t> g_room_seq{1};
static std::mutex g_room_creation_lock;
static std::mutex g_alias_lock;

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(g_room_seq.fetch_add(1));
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

static bool validate_room_alias(const std::string& alias) {
  return alias.size() >= 2 && alias[0] == '#' &&
         alias.find(':') != std::string::npos;
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
// Room membership check helpers
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
  if (!pl_event) return (user_id.empty() ? 0 : 0);

  EventsStore evs(db);
  auto ev = evs.get_event(*pl_event);
  if (!ev) return 0;

  auto& content = (*ev)["content"];
  int64_t default_level = content.value("users_default", 0);

  if (content.contains("users") && content["users"].contains(user_id)) {
    return content["users"][user_id].get<int64_t>();
  }
  return default_level;
}

static int64_t get_required_power_level(DatabasePool& db,
    const std::string& room_id, const std::string& action) {
  StateStore state(db);
  auto pl_event = state.get_current_state_event(room_id, "m.room.power_levels", "");

  int64_t required = 50;
  if (!pl_event) return required;

  EventsStore evs(db);
  auto ev = evs.get_event(*pl_event);
  if (!ev || !(*ev).contains("content")) return required;

  auto& content = (*ev)["content"];
  if (action == "invite") required = content.value("invite", 0);
  else if (action == "kick") required = content.value("kick", 50);
  else if (action == "ban") required = content.value("ban", 50);
  else if (action == "redact") required = content.value("redact", 50);
  else if (action == "state_default") required = content.value("state_default", 50);
  else if (action == "events_default") required = content.value("events_default", 0);
  else if (action == "notifications.room") required = content.value("notifications", json::object()).value("room", 50);
  return required;
}

static bool has_power_to(DatabasePool& db, const std::string& room_id,
                           const std::string& user_id, const std::string& action) {
  int64_t user_pl = get_user_power_level(db, room_id, user_id);
  int64_t required = get_required_power_level(db, room_id, action);
  return user_pl >= required;
}

// ============================================================================
// Event building and persistence helpers
// ============================================================================

struct BuiltEvent {
  std::string event_id;
  std::string room_id;
  std::string sender;
  std::string type;
  std::optional<std::string> state_key;
  json content;
  int64_t origin_server_ts;
  int64_t stream_ordering;
  int64_t depth;
  std::vector<std::string> prev_events;
  std::vector<std::string> auth_events;
  std::string room_version;
};

static BuiltEvent build_base_event(DatabasePool& db, const std::string& room_id,
                                     const std::string& user_id,
                                     const std::string& event_type,
                                     const json& content,
                                     std::optional<std::string> state_key = std::nullopt,
                                     int64_t depth_override = 0) {
  BuiltEvent ev;
  ev.event_id = gen_id("$");
  ev.room_id = room_id;
  ev.sender = user_id;
  ev.type = event_type;
  ev.state_key = state_key;
  ev.content = content;
  ev.origin_server_ts = now_ms();
  ev.stream_ordering = now_ms();
  ev.room_version = "1";

  if (depth_override > 0) {
    ev.depth = depth_override;
  } else {
    EventFederationWorkerStore fed(db);
    auto info = fed.get_room_federation_info(room_id);
    ev.depth = info.event_count + 1;
    for (auto& ext : info.forward_extremities) {
      ev.prev_events.push_back(ext);
    }
  }

  if (event_type == "m.room.member" || event_type == "m.room.create" ||
      event_type == "m.room.power_levels" || event_type == "m.room.join_rules") {
    StateStore state(db);
    auto current = state.get_current_state(room_id);
    for (auto& [key, eid] : current) {
      if (key.first == "m.room.create" || key.first == "m.room.power_levels" ||
          key.first == "m.room.join_rules" || key.first == "m.room.member") {
        ev.auth_events.push_back(eid);
      }
    }
  }

  return ev;
}

static void persist_event(DatabasePool& db, const BuiltEvent& ev,
                           bool is_state = false) {
  EventsStore evs(db);

  EventData ed;
  ed.event_id = ev.event_id;
  ed.room_id = ev.room_id;
  ed.sender = ev.sender;
  ed.type = ev.type;
  ed.state_key = ev.state_key;
  ed.content = ev.content;
  ed.stream_ordering = ev.stream_ordering;
  ed.depth = ev.depth;
  ed.origin_server_ts = ev.origin_server_ts;
  ed.is_state_event = is_state;
  ed.format_version = 1;
  ed.room_version_id = ev.room_version;
  ed.instance_name = "master";
  ed.prev_event_ids = ev.prev_events;
  ed.auth_event_ids = ev.auth_events;

  json event_json;
  event_json["event_id"] = ev.event_id;
  event_json["room_id"] = ev.room_id;
  event_json["sender"] = ev.sender;
  event_json["type"] = ev.type;
  event_json["content"] = ev.content;
  event_json["origin_server_ts"] = ev.origin_server_ts;
  event_json["stream_ordering"] = ev.stream_ordering;
  event_json["depth"] = ev.depth;
  event_json["prev_events"] = ev.prev_events;
  event_json["auth_events"] = ev.auth_events;
  if (ev.state_key) event_json["state_key"] = *ev.state_key;

  auto txn = db.cursor("persist_event");
  if (txn) {
    std::string sql = "INSERT OR REPLACE INTO events "
                      "(event_id, room_id, sender, type, state_key, json, stream_ordering, "
                      "origin_server_ts, depth, outlier, instance_name) "
                      "VALUES (?,?,?,?,?,?,?,?,?,0,'master')";
    txn->execute(sql, {ev.event_id, ev.room_id, ev.sender, ev.type,
                       ev.state_key.value_or(""), event_json.dump(),
                       std::to_string(ev.stream_ordering),
                       std::to_string(ev.origin_server_ts),
                       std::to_string(ev.depth)});

    if (is_state && ev.state_key) {
      std::string state_sql = "INSERT OR REPLACE INTO current_state_events "
                              "(room_id, type, state_key, event_id) VALUES (?,?,?,?)";
      txn->execute(state_sql, {ev.room_id, ev.type, *ev.state_key, ev.event_id});
    }

    std::string stream_sql = "UPDATE stream_ordering SET stream_id = ?";
    txn->execute(stream_sql, {std::to_string(ev.stream_ordering)});

    txn->commit();
  }
}

// ============================================================================
// Federation push helper
// ============================================================================

static void push_event_to_federation(DatabasePool& db, const BuiltEvent& ev,
                                       const std::vector<std::string>& destinations) {
  for (auto& dest : destinations) {
    json pdu;
    pdu["event_id"] = ev.event_id;
    pdu["room_id"] = ev.room_id;
    pdu["sender"] = ev.sender;
    pdu["type"] = ev.type;
    pdu["content"] = ev.content;
    pdu["origin_server_ts"] = ev.origin_server_ts;
    pdu["depth"] = ev.depth;
    pdu["prev_events"] = ev.prev_events;
    pdu["auth_events"] = ev.auth_events;
    if (ev.state_key) pdu["state_key"] = *ev.state_key;
    pdu["origin"] = "localhost";

    std::string fed_sql = "INSERT OR REPLACE INTO federation_stream "
                          "(type, room_id, event_id, destination, json_data, stream_id) "
                          "VALUES ('pdu',?,?,?,?,?)";
    auto txn = db.cursor("fed_push");
    if (txn) {
      txn->execute(fed_sql, {ev.room_id, ev.event_id, dest, pdu.dump(),
                              std::to_string(now_ms())});
      txn->commit();
    }
  }
}

static std::vector<std::string> get_room_participating_servers(
    DatabasePool& db, const std::string& room_id) {
  std::vector<std::string> servers;
  RoomMemberStore members(db);
  auto all_members = members.get_joined_members(room_id);
  std::set<std::string> seen;
  for (auto& m : all_members) {
    auto pos = m.user_id.find(':');
    if (pos != std::string::npos) {
      std::string server = m.user_id.substr(pos + 1);
      if (seen.insert(server).second) {
        servers.push_back(server);
      }
    }
  }
  return servers;
}

// ============================================================================
// Room state resolution helper - resolves the current state for a room
// ============================================================================

static json resolve_room_state(DatabasePool& db, const std::string& room_id) {
  json state;
  state["events"] = json::array();

  StateStore state_store(db);
  EventsStore evs(db);
  auto current_state = state_store.get_current_state(room_id);

  for (auto& [key, eid] : current_state) {
    auto ev = evs.get_event(eid);
    if (ev) {
      state["events"].push_back(*ev);
    }
  }

  return state;
}

// ============================================================================
// ACL check helper - checks if server/user is allowed by room ACLs
// ============================================================================

static bool check_room_acl(DatabasePool& db, const std::string& room_id,
                             const std::string& server_name) {
  StateStore state(db);
  auto acl_event = state.get_current_state_event(room_id, "m.room.server_acl", "");
  if (!acl_event) return true; // No ACL = allow

  EventsStore evs(db);
  auto ev = evs.get_event(*acl_event);
  if (!ev) return true;

  auto& content = (*ev)["content"];

  // Check if server is explicitly denied
  if (content.contains("deny") && content["deny"].is_array()) {
    for (auto& rule : content["deny"]) {
      std::string pattern = rule.value("pattern", "");
      if (!pattern.empty()) {
        std::regex re(pattern);
        if (std::regex_match(server_name, re)) return false;
      }
    }
  }

  // Check if server is explicitly allowed (if allow list exists, deny by default)
  if (content.contains("allow") && content["allow"].is_array()) {
    for (auto& rule : content["allow"]) {
      std::string pattern = rule.value("pattern", "");
      if (!pattern.empty()) {
        std::regex re(pattern);
        if (std::regex_match(server_name, re)) return true;
      }
    }
    return content["allow"].empty(); // empty allow list = allow all
  }

  return true;
}

// ============================================================================
// Join rules check helper
// ============================================================================

static std::string get_join_rule(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto jr_event = state.get_current_state_event(room_id, "m.room.join_rules", "");
  if (!jr_event) return "invite";

  EventsStore evs(db);
  auto ev = evs.get_event(*jr_event);
  if (!ev) return "invite";

  return (*ev)["content"].value("join_rule", "invite");
}

// ============================================================================
// Guest access check
// ============================================================================

static std::string get_guest_access(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto ga_event = state.get_current_state_event(room_id, "m.room.guest_access", "");
  if (!ga_event) return "forbidden";

  EventsStore evs(db);
  auto ev = evs.get_event(*ga_event);
  if (!ev) return "forbidden";

  return (*ev)["content"].value("guest_access", "forbidden");
}

// ============================================================================
// Room version retrieval
// ============================================================================

static std::string get_room_version(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto create_ev = state.get_create_event(room_id);
  if (create_ev && create_ev->contains("content") &&
      (*create_ev)["content"].contains("room_version")) {
    return (*create_ev)["content"]["room_version"].get<std::string>();
  }
  return "1";
}

// ============================================================================
// Membership event sender - sends a m.room.member event and updates membership
// ============================================================================

struct MembershipResult {
  std::string event_id;
  std::string room_id;
  int64_t stream_ordering;
  bool success;
};

static MembershipResult send_membership_event(
    DatabasePool& db, const std::string& room_id,
    const std::string& sender, const std::string& target_user_id,
    const std::string& membership, const json& extra_content = json::object()) {
  MembershipResult result;
  result.room_id = room_id;
  result.stream_ordering = now_ms();
  result.success = false;

  json content = extra_content;
  content["membership"] = membership;

  // Add displayname if known
  ProfileStore profile(db);
  auto display_name = profile.get_display_name(target_user_id);
  if (display_name) content["displayname"] = *display_name;

  auto avatar_url = profile.get_avatar_url(target_user_id);
  if (avatar_url) content["avatar_url"] = *avatar_url;

  auto ev = build_base_event(db, room_id, sender,
                               "m.room.member", content,
                               target_user_id);
  ev.event_id = gen_id("$mem");
  persist_event(db, ev, true);
  result.event_id = ev.event_id;

  // Update room membership table
  RoomMemberStore members(db);
  members.update_membership(room_id, target_user_id, sender, membership,
                            ev.event_id, ev.stream_ordering);

  result.success = true;
  return result;
}

// ============================================================================
// 1. CREATE ROOM HANDLER
// ============================================================================
// POST /_matrix/client/v3/createRoom
//
// Creates a new room with full configuration:
// - Room version, visibility, preset
// - Name, topic, alias
// - Initial state events, creation content
// - Power level overrides
// - Invite list
// - IS Direct flag
// ============================================================================

json handle_create_room(DatabasePool& db, const std::string& auth_header,
                          const std::string& access_token_param,
                          const json& request_body) {
  // ---- 1. Validate authentication ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (auth.is_guest) {
    return make_error(403, "M_FORBIDDEN", "Guest users cannot create rooms");
  }

  std::string creator = auth.user_id;

  // ---- 2. Parse room configuration ----
  std::string room_version = request_body.value("room_version", "1");
  std::string visibility = request_body.value("visibility", "private");
  std::string preset = request_body.value("preset", "");
  bool is_direct = request_body.value("is_direct", false);

  // Optional room name
  std::optional<std::string> room_name;
  if (request_body.contains("name") && request_body["name"].is_string()) {
    room_name = request_body["name"].get<std::string>();
  }

  // Optional topic
  std::optional<std::string> room_topic;
  if (request_body.contains("topic") && request_body["topic"].is_string()) {
    room_topic = request_body["topic"].get<std::string>();
  }

  // Optional room alias name (without # or server part)
  std::optional<std::string> room_alias_name;
  if (request_body.contains("room_alias_name") && request_body["room_alias_name"].is_string()) {
    room_alias_name = request_body["room_alias_name"].get<std::string>();
    // Validate alias name format
    if (room_alias_name->find(':') != std::string::npos) {
      return make_error(400, "M_INVALID_PARAM",
                        "room_alias_name should not include server part");
    }
  }

  // Invite list
  std::vector<std::string> invite_list;
  if (request_body.contains("invite") && request_body["invite"].is_array()) {
    for (auto& uid : request_body["invite"]) {
      if (uid.is_string()) {
        std::string u = uid.get<std::string>();
        if (validate_user_id(u)) {
          invite_list.push_back(u);
        }
      }
    }
  }

  // Invite by third-party ID (3pid)
  std::vector<std::pair<std::string, std::string>> invite_3pid_list;
  if (request_body.contains("invite_3pid") && request_body["invite_3pid"].is_array()) {
    for (auto& pid : request_body["invite_3pid"]) {
      std::string medium = pid.value("medium", "");
      std::string address = pid.value("address", "");
      if (!medium.empty() && !address.empty()) {
        invite_3pid_list.emplace_back(medium, address);
      }
    }
  }

  // Initial state events (predefined state to set)
  std::optional<json> initial_state;
  if (request_body.contains("initial_state") && request_body["initial_state"].is_array()) {
    initial_state = request_body["initial_state"];
  }

  // Creation content (m.federate, predecessor, type)
  json creation_content = request_body.value("creation_content", json::object());

  // Power level content override
  std::optional<json> power_level_content_override;
  if (request_body.contains("power_level_content_override") &&
      request_body["power_level_content_override"].is_object()) {
    power_level_content_override = request_body["power_level_content_override"];
  }

  // ---- 3. Validate room version ----
  static const std::set<std::string> valid_versions = {
    "1","2","3","4","5","6","7","8","9","10","11"
  };
  if (valid_versions.find(room_version) == valid_versions.end()) {
    return make_error(400, "M_UNSUPPORTED_ROOM_VERSION",
                      "Unsupported room version: " + room_version);
  }

  // ---- 4. Validate visibility ----
  if (visibility != "public" && visibility != "private") {
    return make_error(400, "M_INVALID_PARAM",
                      "Visibility must be 'public' or 'private'");
  }

  // ---- 5. Generate room ID ----
  std::string room_id;
  {
    std::lock_guard<std::mutex> lock(g_room_creation_lock);
    room_id = "!" + gen_id("room") + ":localhost";
  }

  // ---- 6. Create the room in the database ----
  RoomStore rooms(db);
  RoomVersion rv;
  rv.identifier = room_version;
  rooms.store_room(room_id, creator, (visibility == "public"), rv);

  int64_t so = now_ms();

  // ---- 7. Determine preset configuration ----
  std::string effective_visibility = visibility;
  std::string join_rule = (visibility == "public") ? "public" : "invite";
  std::string history_visibility = (visibility == "public") ? "world_readable" : "shared";
  std::string guest_access = "forbidden";

  if (!preset.empty()) {
    if (preset == "private_chat") {
      join_rule = "invite";
      history_visibility = "shared";
      guest_access = "can_join";
      is_direct = true;
    } else if (preset == "trusted_private_chat") {
      join_rule = "invite";
      history_visibility = "shared";
      guest_access = "can_join";
      is_direct = true;
      // All invitees get same power level as creator
    } else if (preset == "public_chat") {
      join_rule = "public";
      history_visibility = "shared";
      guest_access = "forbidden";
      effective_visibility = "public";
    }
  }

  // ---- 8. Send m.room.create event ----
  {
    json create_content;
    create_content["creator"] = creator;
    create_content["room_version"] = room_version;

    if (creation_content.contains("m.federate")) {
      create_content["m.federate"] = creation_content["m.federate"];
    } else {
      create_content["m.federate"] = true; // default: federate
    }
    if (creation_content.contains("predecessor")) {
      create_content["predecessor"] = creation_content["predecessor"];
    }
    if (creation_content.contains("type")) {
      create_content["type"] = creation_content["type"];
    }

    auto create_ev = build_base_event(db, room_id, creator,
                                        "m.room.create", create_content,
                                        std::string(""), 0);
    create_ev.event_id = gen_id("$create");
    create_ev.depth = 1;
    persist_event(db, create_ev, true);
  }

  // ---- 9. Send m.room.power_levels event ----
  {
    json pl_content;
    if (power_level_content_override) {
      pl_content = *power_level_content_override;
    } else {
      pl_content["ban"] = 50;
      pl_content["kick"] = 50;
      pl_content["redact"] = 50;
      pl_content["invite"] = 0;
      pl_content["events_default"] = 0;
      pl_content["state_default"] = 50;
      pl_content["users_default"] = 0;
      pl_content["events"] = json::object();
      pl_content["events"]["m.room.name"] = 50;
      pl_content["events"]["m.room.power_levels"] = 100;
      pl_content["events"]["m.room.tombstone"] = 100;
      pl_content["events"]["m.room.history_visibility"] = 100;
      pl_content["events"]["m.room.canonical_alias"] = 50;
      pl_content["events"]["m.room.avatar"] = 50;
      pl_content["events"]["m.room.server_acl"] = 100;
      pl_content["events"]["m.room.encryption"] = 100;
      pl_content["users"] = json::object();
      pl_content["users"][creator] = 100;

      // For trusted_private_chat, all invitees get power level 100
      if (preset == "trusted_private_chat") {
        for (auto& uid : invite_list) {
          pl_content["users"][uid] = 100;
        }
      }
    }

    auto pl_ev = build_base_event(db, room_id, creator,
                                    "m.room.power_levels", pl_content,
                                    std::string(""), 1);
    pl_ev.event_id = gen_id("$pl");
    persist_event(db, pl_ev, true);
  }

  // ---- 10. Send m.room.join_rules event ----
  {
    json jr_content;
    jr_content["join_rule"] = join_rule;

    auto jr_ev = build_base_event(db, room_id, creator,
                                    "m.room.join_rules", jr_content,
                                    std::string(""), 1);
    jr_ev.event_id = gen_id("$jr");
    persist_event(db, jr_ev, true);
  }

  // ---- 11. Send m.room.history_visibility event ----
  {
    json hv_content;
    hv_content["history_visibility"] = history_visibility;

    auto hv_ev = build_base_event(db, room_id, creator,
                                    "m.room.history_visibility", hv_content,
                                    std::string(""), 1);
    hv_ev.event_id = gen_id("$hv");
    persist_event(db, hv_ev, true);
  }

  // ---- 12. Send m.room.guest_access event ----
  {
    json ga_content;
    ga_content["guest_access"] = guest_access;

    auto ga_ev = build_base_event(db, room_id, creator,
                                    "m.room.guest_access", ga_content,
                                    std::string(""), 1);
    ga_ev.event_id = gen_id("$ga");
    persist_event(db, ga_ev, true);
  }

  // ---- 13. Send m.room.name if provided ----
  if (room_name && !room_name->empty()) {
    json name_content;
    name_content["name"] = *room_name;

    auto name_ev = build_base_event(db, room_id, creator,
                                      "m.room.name", name_content,
                                      std::string(""), 1);
    name_ev.event_id = gen_id("$name");
    persist_event(db, name_ev, true);
  }

  // ---- 14. Send m.room.topic if provided ----
  if (room_topic && !room_topic->empty()) {
    json topic_content;
    topic_content["topic"] = *room_topic;

    auto topic_ev = build_base_event(db, room_id, creator,
                                       "m.room.topic", topic_content,
                                       std::string(""), 1);
    topic_ev.event_id = gen_id("$topic");
    persist_event(db, topic_ev, true);
  }

  // ---- 15. Process initial_state events (if provided) ----
  if (initial_state) {
    for (auto& state_ev : *initial_state) {
      std::string ev_type = state_ev.value("type", "");
      std::string state_key = state_ev.value("state_key", "");
      json ev_content = state_ev.value("content", json::object());

      if (!ev_type.empty()) {
        // Skip m.room.create, m.room.power_levels, m.room.join_rules
        // which were already handled
        if (ev_type == "m.room.create" || ev_type == "m.room.power_levels" ||
            ev_type == "m.room.join_rules" || ev_type == "m.room.member") {
          continue;
        }
        auto is_ev = build_base_event(db, room_id, creator,
                                        ev_type, ev_content, state_key, 1);
        is_ev.event_id = gen_id("$is");
        persist_event(db, is_ev, true);
      }
    }
  }

  // ---- 16. Create room alias if specified ----
  std::string room_alias;
  if (room_alias_name) {
    room_alias = "#" + *room_alias_name + ":localhost";

    // Validate alias does not already exist
    DirectoryStore dir(db);
    auto existing = dir.get_room_id(room_alias);
    if (existing) {
      return make_error(409, "M_ROOM_IN_USE",
                        "Room alias already exists: " + room_alias);
    }

    dir.create_alias(room_alias, room_id, creator);
  }

  // ---- 17. Join the creator to the room ----
  RoomMemberStore members(db);
  std::string join_event_id = gen_id("$join");
  members.update_membership(room_id, creator, creator, "join", join_event_id, so);

  // Send m.room.member event for creator
  {
    json member_content;
    member_content["membership"] = "join";
    member_content["displayname"] = creator;

    auto mem_ev = build_base_event(db, room_id, creator,
                                     "m.room.member", member_content,
                                     creator, 1);
    mem_ev.event_id = join_event_id;
    persist_event(db, mem_ev, true);
  }

  // ---- 18. Invite users from invite list ----
  for (auto& uid : invite_list) {
    std::string invite_event_id = gen_id("$inv");
    members.update_membership(room_id, uid, creator, "invite", invite_event_id, so);

    json inv_content;
    inv_content["membership"] = "invite";
    inv_content["displayname"] = uid;

    auto inv_ev = build_base_event(db, room_id, creator,
                                     "m.room.member", inv_content, uid, 1);
    inv_ev.event_id = invite_event_id;
    persist_event(db, inv_ev, true);

    // Push to federation for invited user's server
    if (uid.find(':') != std::string::npos) {
      std::string target_server = uid.substr(uid.find(':') + 1);
      if (target_server != "localhost") {
        push_event_to_federation(db, inv_ev, {target_server});
      }
    }
  }

  // ---- 19. Handle 3pid invites ----
  for (auto& [medium, address] : invite_3pid_list) {
    // Create a third-party invite event
    json tp_content;
    tp_content["medium"] = medium;
    tp_content["address"] = address;
    tp_content["display_name"] = address;
    tp_content["key_validity_url"] = "";
    tp_content["public_key"] = gen_token(32);

    auto tp_ev = build_base_event(db, room_id, creator,
                                    "m.room.third_party_invite", tp_content,
                                    gen_token(16), 1);
    tp_ev.event_id = gen_id("$tpi");
    persist_event(db, tp_ev, true);
  }

  // ---- 20. Set is_direct flag if needed ----
  if (is_direct && invite_list.size() == 1) {
    // Store m.direct account data for the creator
    json direct_content;
    direct_content[invite_list[0]] = json::array({room_id});

    auto direct_ev = build_base_event(db, room_id, creator,
                                        "m.direct", direct_content,
                                        std::nullopt, 1);
    direct_ev.event_id = gen_id("$dir");
    persist_event(db, direct_ev, false);
  }

  // ---- 21. Return room_id and alias ----
  json body;
  body["room_id"] = room_id;
  if (!room_alias.empty()) {
    body["room_alias"] = room_alias;
  }

  return make_response(200, body);
}

// ============================================================================
// 2. JOIN ROOM HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/join
// POST /_matrix/client/v3/join/{roomIdOrAlias}
//
// Joins a room by room ID or room alias. Handles:
// - Room alias resolution
// - Membership state validation
// - Join rules enforcement
// - Guest access checks
// - Federation make_join / send_join flow
// - Third-party signed invites
// ============================================================================

json handle_join_room(DatabasePool& db, const std::string& auth_header,
                       const std::string& access_token_param,
                       const std::string& room_id_or_alias,
                       const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Resolve room ID from alias if needed ----
  std::string room_id = room_id_or_alias;
  std::vector<std::string> server_names;
  std::string via_servers;

  if (!room_id_or_alias.empty() && room_id_or_alias[0] == '#') {
    // Room alias - resolve to room ID
    DirectoryStore dir(db);
    auto resolved = dir.get_room_id(room_id_or_alias);
    if (!resolved) {
      return make_error(404, "M_NOT_FOUND",
                        "Room alias not found: " + room_id_or_alias);
    }
    room_id = *resolved;

    // Get servers for federation join
    auto servers = dir.get_servers_for_alias(room_id_or_alias);
    for (auto& s : servers) {
      server_names.push_back(s);
    }
  }

  // Parse server_name from request body for federation join
  if (request_body.contains("server_name")) {
    const auto& sn = request_body["server_name"];
    if (sn.is_array()) {
      for (auto& s : sn) {
        if (s.is_string()) server_names.push_back(s.get<std::string>());
      }
    } else if (sn.is_string()) {
      server_names.push_back(sn.get<std::string>());
    }
  }

  // Parse via from query params in request body
  if (request_body.contains("via") && request_body["via"].is_array()) {
    for (auto& v : request_body["via"]) {
      if (v.is_string()) server_names.push_back(v.get<std::string>());
    }
  }

  // ---- 3. Validate room exists ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    // Room doesn't exist locally - try federation join
    if (!server_names.empty()) {
      // In a full implementation, would call make_join/send_join
      // on remote servers. Here we return a useful error.
      return make_error(404, "M_NOT_FOUND",
                        "Room not found on this server. Try joining via: " +
                        (server_names.empty() ? "federation" : server_names[0]));
    }
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 4. Check current membership ----
  RoomMemberStore members(db);
  auto current_member = members.get_member(room_id, auth.user_id);
  std::string current_membership = "leave";
  if (current_member) {
    current_membership = current_member->membership;
  }

  // ---- 5. Validate membership transition ----
  if (current_membership == "join") {
    // Already joined - return room_id (idempotent)
    json body;
    body["room_id"] = room_id;
    return make_response(200, body);
  }

  if (current_membership == "ban") {
    return make_error(403, "M_FORBIDDEN", "You are banned from this room");
  }

  // ---- 6. Check join rules ----
  std::string join_rule = get_join_rule(db, room_id);

  if (join_rule == "invite" && current_membership != "invite") {
    return make_error(403, "M_FORBIDDEN",
                      "You are not invited to this room");
  }

  if (join_rule == "knock" && current_membership != "invite") {
    return make_error(403, "M_FORBIDDEN",
                      "This room requires knocking. Use /knock endpoint first.");
  }

  if (join_rule == "restricted" && current_membership != "invite") {
    // Restricted rooms: check if user is in an allowed room
    bool can_join_restricted = false;
    StateStore state(db);
    auto jr_ev_id = state.get_current_state_event(room_id, "m.room.join_rules", "");
    if (jr_ev_id) {
      EventsStore evs(db);
      auto jr_ev = evs.get_event(*jr_ev_id);
      if (jr_ev && (*jr_ev)["content"].contains("allow")) {
        for (auto& allow_rule : (*jr_ev)["content"]["allow"]) {
          std::string allow_type = allow_rule.value("type", "");
          if (allow_type == "m.room_membership") {
            std::string allow_room = allow_rule.value("room_id", "");
            if (!allow_room.empty() && is_user_in_room(db, allow_room, auth.user_id)) {
              can_join_restricted = true;
              break;
            }
          }
        }
      }
    }
    if (!can_join_restricted) {
      return make_error(403, "M_FORBIDDEN",
                        "You are not allowed to join this restricted room");
    }
  }

  if (join_rule == "public") {
    // Anyone can join
  }

  // ---- 7. Guest access check ----
  if (auth.is_guest) {
    std::string guest_access = get_guest_access(db, room_id);
    if (guest_access != "can_join") {
      return make_error(403, "M_FORBIDDEN",
                        "Guest access not allowed in this room");
    }
  }

  // ---- 8. Reason for join (optional) ----
  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string()) {
    reason = request_body["reason"].get<std::string>();
  }

  // ---- 9. Third-party signed invite ----
  std::optional<json> third_party_signed;
  if (request_body.contains("third_party_signed") &&
      request_body["third_party_signed"].is_object()) {
    third_party_signed = request_body["third_party_signed"];
  }

  // ---- 10. Perform the join ----
  int64_t stream_ordering = now_ms();
  std::string join_event_id = gen_id("$join");

  json member_content;
  member_content["membership"] = "join";
  if (reason) member_content["reason"] = *reason;
  if (third_party_signed) member_content["third_party_signed"] = *third_party_signed;

  // Add displayname
  ProfileStore profile(db);
  auto display_name = profile.get_display_name(auth.user_id);
  if (display_name) member_content["displayname"] = *display_name;
  auto avatar_url = profile.get_avatar_url(auth.user_id);
  if (avatar_url) member_content["avatar_url"] = *avatar_url;

  // Build and persist the join event
  auto join_ev = build_base_event(db, room_id, auth.user_id,
                                     "m.room.member", member_content,
                                     auth.user_id);
  join_ev.event_id = join_event_id;
  join_ev.stream_ordering = stream_ordering;
  persist_event(db, join_ev, true);

  // Update membership table
  members.update_membership(room_id, auth.user_id, auth.user_id, "join",
                            join_event_id, stream_ordering);

  // ---- 11. Push join to federation ----
  auto participating_servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, join_ev, participating_servers);

  // ---- 12. Handle knock acceptance ----
  // If user knocked before, the knock is now accepted (implicit)

  // ---- 13. Resolve state and return ----
  json body;
  body["room_id"] = room_id;

  // Optionally return room summary
  if (request_body.value("include_summary", false)) {
    auto member_summary = members.get_room_member_summary(room_id);
    body["summary"] = json::object();
    body["summary"]["m.joined_member_count"] = member_summary.joined_members;
    body["summary"]["m.invited_member_count"] = member_summary.invited_members;
  }

  return make_response(200, body);
}

// ============================================================================
// 3. LEAVE ROOM HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/leave
//
// Leaves a room. A user can leave a room they are currently in
// (join, invite, knock states). Sends m.room.member event with
// membership=leave. Updates room membership table.
// ============================================================================

json handle_leave_room(DatabasePool& db, const std::string& auth_header,
                        const std::string& access_token_param,
                        const std::string& room_id,
                        const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 4. Check current membership ----
  RoomMemberStore members(db);
  auto current_member = members.get_member(room_id, auth.user_id);
  if (!current_member) {
    return make_error(404, "M_NOT_FOUND",
                      "User is not a member of this room");
  }

  std::string current_membership = current_member->membership;

  // ---- 5. Validate membership transition ----
  if (current_membership == "leave") {
    // Already left - idempotent return
    return make_response(200, json::object());
  }

  if (current_membership == "ban") {
    return make_error(403, "M_FORBIDDEN",
                      "Cannot leave a room you are banned from");
  }

  // ---- 6. Optional reason ----
  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string()) {
    reason = request_body["reason"].get<std::string>();
  }

  // ---- 7. Send leave event ----
  int64_t stream_ordering = now_ms();
  std::string leave_event_id = gen_id("$leave");

  json member_content;
  member_content["membership"] = "leave";
  if (reason) member_content["reason"] = *reason;

  auto leave_ev = build_base_event(db, room_id, auth.user_id,
                                     "m.room.member", member_content,
                                     auth.user_id);
  leave_ev.event_id = leave_event_id;
  leave_ev.stream_ordering = stream_ordering;
  persist_event(db, leave_ev, true);

  // ---- 8. Update membership table ----
  members.update_membership(room_id, auth.user_id, auth.user_id, "leave",
                            leave_event_id, stream_ordering);

  // ---- 9. Push leave to federation ----
  auto participating_servers = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, leave_ev, participating_servers);

  // ---- 10. Return success ----
  return make_response(200, json::object());
}

// ============================================================================
// 4. FORGET ROOM HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/forget
//
// Forgets a room the user has left. This removes the room from the
// user's room list. The user must have already left the room.
// Sets the forgotten flag in the room_memberships table.
// ============================================================================

json handle_forget_room(DatabasePool& db, const std::string& auth_header,
                         const std::string& access_token_param,
                         const std::string& room_id,
                         const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 4. Check membership - must have left ----
  RoomMemberStore members(db);
  auto current_member = members.get_member(room_id, auth.user_id);
  if (!current_member || current_member->membership != "leave") {
    return make_error(400, "M_BAD_STATE",
                      "User must leave the room before forgetting it");
  }

  // ---- 5. Mark room as forgotten ----
  members.forget_membership(auth.user_id, room_id, true);

  // ---- 6. Return success ----
  return make_response(200, json::object());
}

// ============================================================================
// 5. INVITE USER HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/invite
//
// Invites a user to a room. Requires:
// - The inviter must be in the room (membership=join)
// - The inviter must have power level >= invite
// - The target user must not already be in the room
// Sends m.room.member event with membership=invite.
// ============================================================================

json handle_invite_user(DatabasePool& db, const std::string& auth_header,
                         const std::string& access_token_param,
                         const std::string& room_id,
                         const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Validate request body ----
  if (!request_body.contains("user_id") || !request_body["user_id"].is_string()) {
    return make_error(400, "M_MISSING_PARAM", "Missing user_id parameter");
  }

  std::string target_user_id = request_body["user_id"].get<std::string>();

  if (!validate_user_id(target_user_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid user ID: " + target_user_id);
  }

  // Cannot invite yourself
  if (target_user_id == auth.user_id) {
    return make_error(400, "M_INVALID_PARAM", "Cannot invite yourself");
  }

  // ---- 4. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 5. Check inviter's membership ----
  RoomMemberStore members(db);
  auto inviter_member = members.get_member(room_id, auth.user_id);
  if (!inviter_member || inviter_member->membership != "join") {
    return make_error(403, "M_FORBIDDEN",
                      "You must be a member of the room to invite others");
  }

  // ---- 6. Check inviter's power level ----
  if (!has_power_to(db, room_id, auth.user_id, "invite")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to invite users");
  }

  // ---- 7. Check target user's current membership ----
  auto target_member = members.get_member(room_id, target_user_id);
  if (target_member) {
    std::string target_membership = target_member->membership;
    if (target_membership == "join") {
      return make_error(400, "M_BAD_STATE",
                        target_user_id + " is already in the room");
    }
    if (target_membership == "ban") {
      return make_error(403, "M_FORBIDDEN",
                        target_user_id + " is banned from the room");
    }
    if (target_membership == "invite") {
      // Already invited - idempotent
      return make_response(200, json::object());
    }
  }

  // ---- 8. Optional reason ----
  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string()) {
    reason = request_body["reason"].get<std::string>();
  }

  // ---- 9. Check if target user exists locally ----
  RegistrationStore reg(db);
  auto target_user_info = reg.get_user_by_id(target_user_id);
  bool target_is_local = target_user_info.has_value();

  // ---- 10. Create and send invite event ----
  int64_t stream_ordering = now_ms();
  std::string invite_event_id = gen_id("$invite");

  json member_content;
  member_content["membership"] = "invite";
  member_content["displayname"] = target_user_id;
  if (reason) member_content["reason"] = *reason;

  // If target is local, include their display name
  if (target_user_info) {
    if (!target_user_info->display_name.empty()) {
      member_content["displayname"] = target_user_info->display_name;
    }
    if (target_user_info->avatar_url) {
      member_content["avatar_url"] = *target_user_info->avatar_url;
    }
  }

  auto invite_ev = build_base_event(db, room_id, auth.user_id,
                                      "m.room.member", member_content,
                                      target_user_id);
  invite_ev.event_id = invite_event_id;
  invite_ev.stream_ordering = stream_ordering;
  persist_event(db, invite_ev, true);

  // ---- 11. Update membership ----
  members.update_membership(room_id, target_user_id, auth.user_id, "invite",
                            invite_event_id, stream_ordering);

  // ---- 12. Handle federation invite ----
  std::string target_server = "localhost";
  if (target_user_id.find(':') != std::string::npos) {
    target_server = target_user_id.substr(target_user_id.find(':') + 1);
  }

  if (target_server != "localhost") {
    // Send invite to target user's homeserver
    push_event_to_federation(db, invite_ev, {target_server});

    // Also notify other participating servers
    auto participating = get_room_participating_servers(db, room_id);
    push_event_to_federation(db, invite_ev, participating);
  } else {
    // Local user - notify via local push
  }

  // ---- 13. Return success ----
  return make_response(200, json::object());
}

// ============================================================================
// 6. KICK USER HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/kick
//
// Kicks a user from a room. Requires:
// - The kicker must be in the room (membership=join)
// - The kicker must have power level >= kick
// - The target user must be in the room
// Sends m.room.member event with membership=leave.
// ============================================================================

json handle_kick_user(DatabasePool& db, const std::string& auth_header,
                       const std::string& access_token_param,
                       const std::string& room_id,
                       const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Validate request body ----
  if (!request_body.contains("user_id") || !request_body["user_id"].is_string()) {
    return make_error(400, "M_MISSING_PARAM", "Missing user_id parameter");
  }

  std::string target_user_id = request_body["user_id"].get<std::string>();

  if (!validate_user_id(target_user_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid user ID: " + target_user_id);
  }

  // ---- 4. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 5. Check kicker's membership and power level ----
  RoomMemberStore members(db);

  // Check kicker is in room
  auto kicker_member = members.get_member(room_id, auth.user_id);
  if (!kicker_member || kicker_member->membership != "join") {
    return make_error(403, "M_FORBIDDEN",
                      "You must be a member of the room to kick users");
  }

  // Check power level for kick
  if (!has_power_to(db, room_id, auth.user_id, "kick")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to kick users");
  }

  // ---- 6. Check target user's membership ----
  auto target_member = members.get_member(room_id, target_user_id);
  if (!target_member) {
    return make_error(404, "M_NOT_FOUND",
                      target_user_id + " is not a member of this room");
  }

  std::string target_membership = target_member->membership;

  if (target_membership == "leave") {
    // Already left - idempotent
    return make_response(200, json::object());
  }

  // Cannot kick someone with higher or equal power level
  int64_t kicker_pl = get_user_power_level(db, room_id, auth.user_id);
  int64_t target_pl = get_user_power_level(db, room_id, target_user_id);
  if (target_pl >= kicker_pl && target_user_id != auth.user_id) {
    return make_error(403, "M_FORBIDDEN",
                      "Cannot kick a user with equal or higher power level");
  }

  // ---- 7. Optional reason ----
  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string()) {
    reason = request_body["reason"].get<std::string>();
  }

  // ---- 8. Create and send kick event ----
  int64_t stream_ordering = now_ms();
  std::string kick_event_id = gen_id("$kick");

  json member_content;
  member_content["membership"] = "leave";
  if (reason) member_content["reason"] = *reason;

  auto kick_ev = build_base_event(db, room_id, auth.user_id,
                                    "m.room.member", member_content,
                                    target_user_id);
  kick_ev.event_id = kick_event_id;
  kick_ev.stream_ordering = stream_ordering;
  persist_event(db, kick_ev, true);

  // ---- 9. Update membership ----
  members.update_membership(room_id, target_user_id, auth.user_id, "leave",
                            kick_event_id, stream_ordering);

  // ---- 10. Push to federation ----
  auto participating = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, kick_ev, participating);

  // ---- 11. Return success ----
  return make_response(200, json::object());
}

// ============================================================================
// 7. BAN USER HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/ban
//
// Bans a user from a room. Requires:
// - The banner must be in the room (membership=join)
// - The banner must have power level >= ban
// Sends m.room.member event with membership=ban.
// Also updates server ACL if applicable.
// ============================================================================

json handle_ban_user(DatabasePool& db, const std::string& auth_header,
                      const std::string& access_token_param,
                      const std::string& room_id,
                      const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Validate request body ----
  if (!request_body.contains("user_id") || !request_body["user_id"].is_string()) {
    return make_error(400, "M_MISSING_PARAM", "Missing user_id parameter");
  }

  std::string target_user_id = request_body["user_id"].get<std::string>();

  if (!validate_user_id(target_user_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid user ID: " + target_user_id);
  }

  // ---- 4. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 5. Check banner's membership and power level ----
  RoomMemberStore members(db);

  auto banner_member = members.get_member(room_id, auth.user_id);
  if (!banner_member || banner_member->membership != "join") {
    return make_error(403, "M_FORBIDDEN",
                      "You must be a member of the room to ban users");
  }

  // Check power level for ban
  if (!has_power_to(db, room_id, auth.user_id, "ban")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to ban users");
  }

  // ---- 6. Check target user's current state ----
  auto target_member = members.get_member(room_id, target_user_id);

  if (target_member && target_member->membership == "ban") {
    // Already banned - idempotent
    return make_response(200, json::object());
  }

  // Cannot ban someone with higher or equal power level
  int64_t banner_pl = get_user_power_level(db, room_id, auth.user_id);
  int64_t target_pl = get_user_power_level(db, room_id, target_user_id);
  if (target_pl >= banner_pl && target_user_id != auth.user_id) {
    return make_error(403, "M_FORBIDDEN",
                      "Cannot ban a user with equal or higher power level");
  }

  // ---- 7. Optional reason ----
  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string()) {
    reason = request_body["reason"].get<std::string>();
  }

  // ---- 8. Create and send ban event ----
  int64_t stream_ordering = now_ms();
  std::string ban_event_id = gen_id("$ban");

  json member_content;
  member_content["membership"] = "ban";
  if (reason) member_content["reason"] = *reason;

  auto ban_ev = build_base_event(db, room_id, auth.user_id,
                                   "m.room.member", member_content,
                                   target_user_id);
  ban_ev.event_id = ban_event_id;
  ban_ev.stream_ordering = stream_ordering;
  persist_event(db, ban_ev, true);

  // ---- 9. Update membership ----
  members.update_membership(room_id, target_user_id, auth.user_id, "ban",
                            ban_event_id, stream_ordering);

  // ---- 10. Optionally update server ACL ----
  // If target is a remote user, consider adding their server to ACL deny
  if (target_user_id.find(':') != std::string::npos) {
    std::string target_server = target_user_id.substr(target_user_id.find(':') + 1);
    if (target_server != "localhost") {
      // In a full implementation, would update m.room.server_acl state event
      // to deny the target user's server
      StateStore state(db);
      auto acl_event = state.get_current_state_event(room_id, "m.room.server_acl", "");
      if (acl_event) {
        EventsStore evs(db);
        auto acl_ev = evs.get_event(*acl_event);
        if (acl_ev) {
          json acl_content = (*acl_ev)["content"];
          if (acl_content.contains("deny") && acl_content["deny"].is_array()) {
            bool already_denied = false;
            for (auto& rule : acl_content["deny"]) {
              if (rule.value("pattern", "") == target_server) {
                already_denied = true;
                break;
              }
            }
            if (!already_denied) {
              json deny_rule;
              deny_rule["pattern"] = target_server;
              deny_rule["reason"] = "Banned user from server";
              acl_content["deny"].push_back(deny_rule);

              auto acl_update = build_base_event(db, room_id, auth.user_id,
                                                  "m.room.server_acl", acl_content,
                                                  std::string(""), stream_ordering);
              acl_update.event_id = gen_id("$acl");
              persist_event(db, acl_update, true);
            }
          }
        }
      }
    }
  }

  // ---- 11. Push to federation ----
  auto participating = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, ban_ev, participating);

  // ---- 12. Return success ----
  return make_response(200, json::object());
}

// ============================================================================
// 8. UNBAN USER HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/unban
//
// Unbans a user from a room. Requires:
// - The unbanner must be in the room (membership=join)
// - The unbanner must have power level >= ban
// - The target user must currently be banned
// Sends m.room.member event with membership=leave.
// ============================================================================

json handle_unban_user(DatabasePool& db, const std::string& auth_header,
                        const std::string& access_token_param,
                        const std::string& room_id,
                        const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Validate request body ----
  if (!request_body.contains("user_id") || !request_body["user_id"].is_string()) {
    return make_error(400, "M_MISSING_PARAM", "Missing user_id parameter");
  }

  std::string target_user_id = request_body["user_id"].get<std::string>();

  if (!validate_user_id(target_user_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid user ID: " + target_user_id);
  }

  // ---- 4. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 5. Check unbanner's membership and power level ----
  RoomMemberStore members(db);

  auto unbanner_member = members.get_member(room_id, auth.user_id);
  if (!unbanner_member || unbanner_member->membership != "join") {
    return make_error(403, "M_FORBIDDEN",
                      "You must be a member of the room to unban users");
  }

  // Check power level for ban (same as ban - unban requires ban privilege)
  if (!has_power_to(db, room_id, auth.user_id, "ban")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to unban users");
  }

  // ---- 6. Check target user is banned ----
  auto target_member = members.get_member(room_id, target_user_id);
  if (!target_member || target_member->membership != "ban") {
    return make_error(400, "M_BAD_STATE",
                      target_user_id + " is not banned from this room");
  }

  // ---- 7. Optional reason ----
  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string()) {
    reason = request_body["reason"].get<std::string>();
  }

  // ---- 8. Create and send unban event (membership=leave) ----
  int64_t stream_ordering = now_ms();
  std::string unban_event_id = gen_id("$unban");

  json member_content;
  member_content["membership"] = "leave";
  if (reason) member_content["reason"] = *reason;

  auto unban_ev = build_base_event(db, room_id, auth.user_id,
                                     "m.room.member", member_content,
                                     target_user_id);
  unban_ev.event_id = unban_event_id;
  unban_ev.stream_ordering = stream_ordering;
  persist_event(db, unban_ev, true);

  // ---- 9. Update membership ----
  members.update_membership(room_id, target_user_id, auth.user_id, "leave",
                            unban_event_id, stream_ordering);

  // ---- 10. Push to federation ----
  auto participating = get_room_participating_servers(db, room_id);
  push_event_to_federation(db, unban_ev, participating);

  // ---- 11. Return success ----
  return make_response(200, json::object());
}

// ============================================================================
// 9. CREATE ALIAS HANDLER
// ============================================================================
// PUT /_matrix/client/v3/directory/room/{roomAlias}
//
// Creates a room alias mapping. Requires:
// - The user must be authenticated
// - The alias must be on the local server
// - The user must have permission (room admin or create canonical alias)
// - The room must exist
// ============================================================================

json handle_create_alias(DatabasePool& db, const std::string& auth_header,
                          const std::string& access_token_param,
                          const std::string& room_alias,
                          const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate alias format ----
  if (!validate_room_alias(room_alias)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room alias: " + room_alias);
  }

  // ---- 3. Check alias is on local server ----
  DirectoryStore dir(db);
  if (!dir.is_local_alias(room_alias)) {
    return make_error(400, "M_INVALID_PARAM",
                      "Can only create aliases on the local server");
  }

  // ---- 4. Check alias doesn't already exist ----
  auto existing = dir.get_room_id(room_alias);
  if (existing) {
    // Check if the existing mapping points to the same room
    if (request_body.contains("room_id") &&
        request_body["room_id"].is_string()) {
      if (*existing == request_body["room_id"].get<std::string>()) {
        // Same mapping - idempotent
        return make_response(200, json::object());
      }
    }
    return make_error(409, "M_ROOM_IN_USE",
                      "Room alias already exists: " + room_alias);
  }

  // ---- 5. Validate room_id in request ----
  if (!request_body.contains("room_id") || !request_body["room_id"].is_string()) {
    return make_error(400, "M_MISSING_PARAM", "Missing room_id parameter");
  }

  std::string room_id = request_body["room_id"].get<std::string>();

  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID: " + room_id);
  }

  // ---- 6. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found: " + room_id);
  }

  // ---- 7. Check user has permission to create alias ----
  RoomMemberStore members(db);
  auto member = members.get_member(room_id, auth.user_id);
  if (!member || member->membership != "join") {
    return make_error(403, "M_FORBIDDEN",
                      "You must be a member of the room to create an alias");
  }

  // Check power level for canonical alias creation
  int64_t user_pl = get_user_power_level(db, room_id, auth.user_id);
  int64_t required_pl = get_required_power_level(db, room_id, "state_default");
  // canonical_alias event requires the state_default power level
  if (user_pl < required_pl) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to create room aliases");
  }

  // ---- 8. Create the alias ----
  dir.create_alias(room_alias, room_id, auth.user_id);

  // ---- 9. Optionally update canonical alias ----
  // If this is the first alias, set it as canonical
  auto aliases = dir.get_aliases_for_room(room_id);
  if (aliases.size() == 1) {
    // Set as canonical alias
    json ca_content;
    ca_content["alias"] = room_alias;
    ca_content["alt_aliases"] = json::array();

    auto ca_ev = build_base_event(db, room_id, auth.user_id,
                                    "m.room.canonical_alias", ca_content,
                                    std::string(""));
    ca_ev.event_id = gen_id("$ca");
    persist_event(db, ca_ev, true);
  } else {
    // Update alt_aliases in canonical alias
    StateStore state(db);
    auto ca_event_id = state.get_current_state_event(room_id, "m.room.canonical_alias", "");
    if (ca_event_id) {
      EventsStore evs(db);
      auto ca_ev_data = evs.get_event(*ca_event_id);
      if (ca_ev_data) {
        json ca_content = (*ca_ev_data)["content"];
        if (!ca_content.contains("alt_aliases") || !ca_content["alt_aliases"].is_array()) {
          ca_content["alt_aliases"] = json::array();
        }

        // Add all aliases except the canonical one
        std::string canonical = ca_content.value("alias", "");
        json alt_aliases_arr = json::array();
        for (auto& a : aliases) {
          if (a != canonical) {
            alt_aliases_arr.push_back(a);
          }
        }
        ca_content["alt_aliases"] = alt_aliases_arr;

        auto ca_update = build_base_event(db, room_id, auth.user_id,
                                            "m.room.canonical_alias", ca_content,
                                            std::string(""));
        ca_update.event_id = gen_id("$ca");
        persist_event(db, ca_update, true);
      }
    }
  }

  // ---- 10. Return success ----
  return make_response(200, json::object());
}

// ============================================================================
// 10. GET ALIAS HANDLER
// ============================================================================
// GET /_matrix/client/v3/directory/room/{roomAlias}
//
// Looks up a room alias and returns the room ID and list of servers.
// No authentication required (public endpoint).
// ============================================================================

json handle_get_alias(DatabasePool& db, const std::string& auth_header,
                       const std::string& access_token_param,
                       const std::string& room_alias,
                       const json& request_body) {
  // ---- 1. Validate alias format ----
  if (!validate_room_alias(room_alias)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room alias: " + room_alias);
  }

  // ---- 2. Look up alias ----
  DirectoryStore dir(db);
  auto room_id = dir.get_room_id(room_alias);
  if (!room_id) {
    return make_error(404, "M_NOT_FOUND",
                      "Room alias not found: " + room_alias);
  }

  // ---- 3. Get servers for this alias ----
  auto servers = dir.get_servers_for_alias(room_alias);

  // ---- 4. Build response ----
  json body;
  body["room_id"] = *room_id;
  body["servers"] = json::array();
  for (auto& s : servers) {
    body["servers"].push_back(s);
  }

  // Add local server if not present
  bool has_local = false;
  for (auto& s : servers) {
    if (s == "localhost") {
      has_local = true;
      break;
    }
  }
  if (!has_local) {
    body["servers"].push_back("localhost");
  }

  return make_response(200, body);
}

// ============================================================================
// 11. DELETE ALIAS HANDLER
// ============================================================================
// DELETE /_matrix/client/v3/directory/room/{roomAlias}
//
// Deletes a room alias. Requires:
// - The user must be authenticated
// - The alias must exist
// - The user must have permission (room admin or alias creator)
// ============================================================================

json handle_delete_alias(DatabasePool& db, const std::string& auth_header,
                          const std::string& access_token_param,
                          const std::string& room_alias,
                          const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate alias format ----
  if (!validate_room_alias(room_alias)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room alias: " + room_alias);
  }

  // ---- 3. Look up alias ----
  DirectoryStore dir(db);
  auto room_id = dir.get_room_id(room_alias);
  if (!room_id) {
    return make_error(404, "M_NOT_FOUND",
                      "Room alias not found: " + room_alias);
  }

  // ---- 4. Check permission ----
  // User must either be:
  // - The alias creator
  // - A room admin (power level >= state_default)
  // - A server admin
  auto creator = dir.get_alias_creator(room_alias);
  bool is_creator = (creator && *creator == auth.user_id);

  RoomMemberStore members(db);
  auto member = members.get_member(*room_id, auth.user_id);
  bool is_room_member = (member && member->membership == "join");

  bool has_power = false;
  if (is_room_member) {
    int64_t user_pl = get_user_power_level(db, *room_id, auth.user_id);
    int64_t state_default = get_required_power_level(db, *room_id, "state_default");
    has_power = (user_pl >= state_default);
  }

  // Check server admin
  RegistrationStore reg(db);
  bool is_server_admin = reg.is_server_admin(auth.user_id);

  if (!is_creator && !has_power && !is_server_admin) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to delete this alias");
  }

  // ---- 5. Delete the alias ----
  dir.delete_alias(room_alias);

  // ---- 6. Update canonical alias if this was referenced ----
  StateStore state(db);
  EventsStore evs(db);
  auto ca_event_id = state.get_current_state_event(*room_id, "m.room.canonical_alias", "");
  if (ca_event_id) {
    auto ca_ev = evs.get_event(*ca_event_id);
    if (ca_ev) {
      json ca_content = (*ca_ev)["content"];
      bool needs_update = false;

      // Check if this was the canonical alias
      if (ca_content.contains("alias") && ca_content["alias"].get<std::string>() == room_alias) {
        // Remove canonical, set first alt as new canonical
        if (ca_content.contains("alt_aliases") &&
            ca_content["alt_aliases"].is_array() &&
            !ca_content["alt_aliases"].empty()) {
          ca_content["alias"] = ca_content["alt_aliases"][0];
          needs_update = true;
        } else {
          ca_content.erase("alias");
          needs_update = true;
        }
      }

      // Remove from alt_aliases
      if (ca_content.contains("alt_aliases") && ca_content["alt_aliases"].is_array()) {
        json new_alt = json::array();
        for (auto& a : ca_content["alt_aliases"]) {
          if (a.is_string() && a.get<std::string>() != room_alias) {
            new_alt.push_back(a);
          } else {
            needs_update = true;
          }
        }
        if (needs_update) {
          ca_content["alt_aliases"] = new_alt;
        }
      }

      if (needs_update) {
        auto ca_update = build_base_event(db, *room_id, auth.user_id,
                                            "m.room.canonical_alias", ca_content,
                                            std::string(""));
        ca_update.event_id = gen_id("$ca");
        persist_event(db, ca_update, true);
      }
    }
  }

  // ---- 7. Return success ----
  return make_response(200, json::object());
}

// ============================================================================
// 12. UPGRADE ROOM HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/upgrade
//
// Upgrades a room to a new version. Creates a new room with the
// same configuration, sends a tombstone event in the old room,
// and returns the new room ID.
// ============================================================================

json handle_upgrade_room(DatabasePool& db, const std::string& auth_header,
                          const std::string& access_token_param,
                          const std::string& room_id,
                          const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Validate new version ----
  if (!request_body.contains("new_version") || !request_body["new_version"].is_string()) {
    return make_error(400, "M_MISSING_PARAM", "Missing new_version parameter");
  }

  std::string new_version = request_body["new_version"].get<std::string>();

  static const std::set<std::string> valid_versions = {
    "1","2","3","4","5","6","7","8","9","10","11"
  };
  if (valid_versions.find(new_version) == valid_versions.end()) {
    return make_error(400, "M_UNSUPPORTED_ROOM_VERSION",
                      "Unsupported room version: " + new_version);
  }

  // ---- 4. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 5. Check user's membership ----
  RoomMemberStore members(db);
  auto member = members.get_member(room_id, auth.user_id);
  if (!member || member->membership != "join") {
    return make_error(403, "M_FORBIDDEN",
                      "You must be a member of the room to upgrade it");
  }

  // ---- 6. Check user has power to upgrade ----
  // Upgrading requires tombstone power (typically 100)
  if (!has_power_to(db, room_id, auth.user_id, "ban")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to upgrade this room");
  }

  // ---- 7. Get current room version ----
  std::string current_version = get_room_version(db, room_id);
  if (current_version == new_version) {
    return make_error(400, "M_BAD_STATE",
                      "Room is already at version " + new_version);
  }

  // ---- 8. Gather room configuration for cloning ----
  StateStore state(db);
  EventsStore evs(db);

  // Get room name
  std::optional<std::string> room_name;
  auto name_event_id = state.get_current_state_event(room_id, "m.room.name", "");
  if (name_event_id) {
    auto ev = evs.get_event(*name_event_id);
    if (ev && (*ev)["content"].contains("name")) {
      room_name = (*ev)["content"]["name"].get<std::string>();
    }
  }

  // Get room topic
  std::optional<std::string> room_topic;
  auto topic_event_id = state.get_current_state_event(room_id, "m.room.topic", "");
  if (topic_event_id) {
    auto ev = evs.get_event(*topic_event_id);
    if (ev && (*ev)["content"].contains("topic")) {
      room_topic = (*ev)["content"]["topic"].get<std::string>();
    }
  }

  // Get join rules
  std::string join_rule = get_join_rule(db, room_id);
  bool is_public = (join_rule == "public");

  // ---- 9. Create the new replacement room ----
  std::string new_room_id;
  {
    std::lock_guard<std::mutex> lock(g_room_creation_lock);
    new_room_id = "!" + gen_id("upgrade") + ":localhost";
  }

  RoomVersion rv;
  rv.identifier = new_version;
  rooms.store_room(new_room_id, auth.user_id, is_public, rv);

  int64_t so = now_ms();

  // ---- 10. Send m.room.create in new room with predecessor ----
  {
    json create_content;
    create_content["creator"] = auth.user_id;
    create_content["room_version"] = new_version;

    // Set predecessor pointing to old room
    json predecessor;
    predecessor["room_id"] = room_id;
    predecessor["event_id"] = ""; // last known event
    create_content["predecessor"] = predecessor;

    auto create_ev = build_base_event(db, new_room_id, auth.user_id,
                                        "m.room.create", create_content,
                                        std::string(""), 0);
    create_ev.event_id = gen_id("$create");
    create_ev.depth = 1;
    persist_event(db, create_ev, true);
  }

  // ---- 11. Copy power levels ----
  {
    auto pl_event_id = state.get_current_state_event(room_id, "m.room.power_levels", "");
    json pl_content;
    if (pl_event_id) {
      auto pl_ev = evs.get_event(*pl_event_id);
      if (pl_ev) {
        pl_content = (*pl_ev)["content"];
        // Ensure creator is admin
        if (pl_content.contains("users")) {
          pl_content["users"][auth.user_id] = 100;
        }
      }
    } else {
      pl_content["ban"] = 50;
      pl_content["kick"] = 50;
      pl_content["invite"] = 0;
      pl_content["events_default"] = 0;
      pl_content["state_default"] = 50;
      pl_content["users_default"] = 0;
      pl_content["users"] = json::object();
      pl_content["users"][auth.user_id] = 100;
    }

    auto pl_ev = build_base_event(db, new_room_id, auth.user_id,
                                    "m.room.power_levels", pl_content,
                                    std::string(""), 1);
    pl_ev.event_id = gen_id("$pl");
    persist_event(db, pl_ev, true);
  }

  // ---- 12. Copy join rules ----
  {
    json jr_content;
    jr_content["join_rule"] = join_rule;
    auto jr_ev = build_base_event(db, new_room_id, auth.user_id,
                                    "m.room.join_rules", jr_content,
                                    std::string(""), 1);
    jr_ev.event_id = gen_id("$jr");
    persist_event(db, jr_ev, true);
  }

  // ---- 13. Copy history visibility ----
  {
    auto hv_event_id = state.get_current_state_event(room_id, "m.room.history_visibility", "");
    json hv_content;
    hv_content["history_visibility"] = "shared";
    if (hv_event_id) {
      auto hv_ev = evs.get_event(*hv_event_id);
      if (hv_ev) hv_content = (*hv_ev)["content"];
    }
    auto hv_new = build_base_event(db, new_room_id, auth.user_id,
                                    "m.room.history_visibility", hv_content,
                                    std::string(""), 1);
    hv_new.event_id = gen_id("$hv");
    persist_event(db, hv_new, true);
  }

  // ---- 14. Copy guest access ----
  {
    auto ga_event_id = state.get_current_state_event(room_id, "m.room.guest_access", "");
    json ga_content;
    ga_content["guest_access"] = "forbidden";
    if (ga_event_id) {
      auto ga_ev = evs.get_event(*ga_event_id);
      if (ga_ev) ga_content = (*ga_ev)["content"];
    }
    auto ga_new = build_base_event(db, new_room_id, auth.user_id,
                                    "m.room.guest_access", ga_content,
                                    std::string(""), 1);
    ga_new.event_id = gen_id("$ga");
    persist_event(db, ga_new, true);
  }

  // ---- 15. Copy room name ----
  if (room_name && !room_name->empty()) {
    json name_content;
    name_content["name"] = *room_name;
    auto name_ev = build_base_event(db, new_room_id, auth.user_id,
                                      "m.room.name", name_content,
                                      std::string(""), 1);
    name_ev.event_id = gen_id("$name");
    persist_event(db, name_ev, true);
  }

  // ---- 16. Copy room topic ----
  if (room_topic && !room_topic->empty()) {
    json topic_content;
    topic_content["topic"] = *room_topic;
    auto topic_ev = build_base_event(db, new_room_id, auth.user_id,
                                       "m.room.topic", topic_content,
                                       std::string(""), 1);
    topic_ev.event_id = gen_id("$topic");
    persist_event(db, topic_ev, true);
  }

  // ---- 17. Join creator to new room ----
  std::string join_event_id = gen_id("$join");
  members.update_membership(new_room_id, auth.user_id, auth.user_id,
                            "join", join_event_id, so);

  json member_content;
  member_content["membership"] = "join";
  member_content["displayname"] = auth.user_id;
  auto mem_ev = build_base_event(db, new_room_id, auth.user_id,
                                   "m.room.member", member_content,
                                   auth.user_id, 1);
  mem_ev.event_id = join_event_id;
  persist_event(db, mem_ev, true);

  // ---- 18. Send tombstone event in old room ----
  {
    json tombstone_content;
    tombstone_content["body"] = "This room has been replaced";
    tombstone_content["replacement_room"] = new_room_id;

    auto tombstone_ev = build_base_event(db, room_id, auth.user_id,
                                           "m.room.tombstone", tombstone_content,
                                           std::string(""));
    tombstone_ev.event_id = gen_id("$tomb");
    persist_event(db, tombstone_ev, true);

    // Push tombstone to federation
    auto participating = get_room_participating_servers(db, room_id);
    push_event_to_federation(db, tombstone_ev, participating);
  }

  // ---- 19. Return new room ID ----
  json body;
  body["replacement_room"] = new_room_id;
  return make_response(200, body);
}

// ============================================================================
// 13. KNOCK HANDLER
// ============================================================================
// POST /_matrix/client/v3/knock/{roomIdOrAlias}
//
// Knocks on a room to request membership. For rooms with join_rule
// "knock", users can send a knock event to request to join.
// Room admins can then accept or deny the knock.
// ============================================================================

json handle_knock(DatabasePool& db, const std::string& auth_header,
                   const std::string& access_token_param,
                   const std::string& room_id_or_alias,
                   const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Resolve room ID from alias if needed ----
  std::string room_id = room_id_or_alias;
  std::vector<std::string> server_names;

  if (!room_id_or_alias.empty() && room_id_or_alias[0] == '#') {
    DirectoryStore dir(db);
    auto resolved = dir.get_room_id(room_id_or_alias);
    if (!resolved) {
      return make_error(404, "M_NOT_FOUND",
                        "Room alias not found: " + room_id_or_alias);
    }
    room_id = *resolved;
    auto servers = dir.get_servers_for_alias(room_id_or_alias);
    for (auto& s : servers) server_names.push_back(s);
  }

  // Parse server_name from request body
  if (request_body.contains("server_name")) {
    const auto& sn = request_body["server_name"];
    if (sn.is_array()) {
      for (auto& s : sn) {
        if (s.is_string()) server_names.push_back(s.get<std::string>());
      }
    } else if (sn.is_string()) {
      server_names.push_back(sn.get<std::string>());
    }
  }

  // ---- 3. Validate room ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 4. Check current membership ----
  RoomMemberStore members(db);
  auto current_member = members.get_member(room_id, auth.user_id);

  if (current_member) {
    std::string current_membership = current_member->membership;
    if (current_membership == "join") {
      return make_error(400, "M_BAD_STATE",
                        "You are already a member of this room");
    }
    if (current_membership == "ban") {
      return make_error(403, "M_FORBIDDEN",
                        "You are banned from this room");
    }
    if (current_membership == "knock") {
      // Already knocked - idempotent
      json body;
      body["room_id"] = room_id;
      return make_response(200, body);
    }
  }

  // ---- 5. Check join rules allow knocking ----
  std::string join_rule = get_join_rule(db, room_id);
  if (join_rule != "knock" && join_rule != "knock_restricted") {
    return make_error(403, "M_FORBIDDEN",
                      "This room does not allow knocking. Join rule: " + join_rule);
  }

  // ---- 6. For knock_restricted, check allow rules ----
  if (join_rule == "knock_restricted") {
    StateStore state(db);
    auto jr_ev_id = state.get_current_state_event(room_id, "m.room.join_rules", "");
    bool can_knock_restricted = false;
    if (jr_ev_id) {
      EventsStore evs(db);
      auto jr_ev = evs.get_event(*jr_ev_id);
      if (jr_ev && (*jr_ev)["content"].contains("allow")) {
        for (auto& allow_rule : (*jr_ev)["content"]["allow"]) {
          std::string allow_type = allow_rule.value("type", "");
          if (allow_type == "m.room_membership") {
            std::string allow_room = allow_rule.value("room_id", "");
            if (!allow_room.empty() && is_user_in_room(db, allow_room, auth.user_id)) {
              can_knock_restricted = true;
              break;
            }
          }
        }
      }
    }
    if (!can_knock_restricted) {
      return make_error(403, "M_FORBIDDEN",
                        "You are not allowed to knock on this restricted room");
    }
  }

  // ---- 7. Optional reason ----
  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string()) {
    reason = request_body["reason"].get<std::string>();
  }

  // ---- 8. Create and send knock event ----
  int64_t stream_ordering = now_ms();
  std::string knock_event_id = gen_id("$knock");

  json member_content;
  member_content["membership"] = "knock";
  if (reason) member_content["reason"] = *reason;

  // Add displayname
  ProfileStore profile(db);
  auto display_name = profile.get_display_name(auth.user_id);
  if (display_name) member_content["displayname"] = *display_name;
  auto avatar_url = profile.get_avatar_url(auth.user_id);
  if (avatar_url) member_content["avatar_url"] = *avatar_url;

  auto knock_ev = build_base_event(db, room_id, auth.user_id,
                                     "m.room.member", member_content,
                                     auth.user_id);
  knock_ev.event_id = knock_event_id;
  knock_ev.stream_ordering = stream_ordering;
  persist_event(db, knock_ev, true);

  // ---- 9. Update membership ----
  members.update_membership(room_id, auth.user_id, auth.user_id, "knock",
                            knock_event_id, stream_ordering);

  // ---- 10. Push knock to federation ----
  auto participating = get_room_participating_servers(db, room_id);
  if (!participating.empty()) {
    push_event_to_federation(db, knock_ev, participating);
  }

  // ---- 11. Return room ID ----
  json body;
  body["room_id"] = room_id;
  return make_response(200, body);
}

// ============================================================================
// 14. ANSWER KNOCK HELPER - Accept or Deny a Knock
// ============================================================================
// Used by room admins to accept or deny knock requests.
// Accept: sends membership=invite or membership=join event for the target user.
// Deny: sends membership=leave event (effectively rejecting the knock).

json handle_answer_knock(DatabasePool& db, const std::string& auth_header,
                          const std::string& access_token_param,
                          const std::string& room_id,
                          const std::string& target_user_id,
                          bool accept,
                          const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID and target user ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }
  if (!validate_user_id(target_user_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid user ID");
  }

  // ---- 3. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 4. Check answerer's membership and power ----
  RoomMemberStore members(db);
  auto answerer = members.get_member(room_id, auth.user_id);
  if (!answerer || answerer->membership != "join") {
    return make_error(403, "M_FORBIDDEN",
                      "You must be a member of the room to answer knocks");
  }

  if (!has_power_to(db, room_id, auth.user_id, "invite")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to answer knocks");
  }

  // ---- 5. Check target user has knocked ----
  auto target = members.get_member(room_id, target_user_id);
  if (!target || target->membership != "knock") {
    return make_error(400, "M_BAD_STATE",
                      target_user_id + " has not knocked on this room");
  }

  // ---- 6. Optional reason ----
  std::optional<std::string> reason;
  if (request_body.contains("reason") && request_body["reason"].is_string()) {
    reason = request_body["reason"].get<std::string>();
  }

  // ---- 7. Accept or deny the knock ----
  int64_t stream_ordering = now_ms();

  if (accept) {
    // Accept knock -> invite user to room
    std::string invite_event_id = gen_id("$invite");

    json member_content;
    member_content["membership"] = "invite";
    member_content["displayname"] = target_user_id;
    if (reason) member_content["reason"] = *reason;

    auto invite_ev = build_base_event(db, room_id, auth.user_id,
                                        "m.room.member", member_content,
                                        target_user_id);
    invite_ev.event_id = invite_event_id;
    invite_ev.stream_ordering = stream_ordering;
    persist_event(db, invite_ev, true);

    members.update_membership(room_id, target_user_id, auth.user_id, "invite",
                              invite_event_id, stream_ordering);

    // Push to federation
    if (target_user_id.find(':') != std::string::npos) {
      std::string target_server = target_user_id.substr(target_user_id.find(':') + 1);
      push_event_to_federation(db, invite_ev, {target_server});
    }

    json body;
    body["membership"] = "invite";
    body["room_id"] = room_id;
    return make_response(200, body);
  } else {
    // Deny knock -> set membership back to leave
    std::string leave_event_id = gen_id("$leave");

    json member_content;
    member_content["membership"] = "leave";
    if (reason) member_content["reason"] = *reason;

    auto leave_ev = build_base_event(db, room_id, auth.user_id,
                                       "m.room.member", member_content,
                                       target_user_id);
    leave_ev.event_id = leave_event_id;
    leave_ev.stream_ordering = stream_ordering;
    persist_event(db, leave_ev, true);

    members.update_membership(room_id, target_user_id, auth.user_id, "leave",
                              leave_event_id, stream_ordering);

    // Push to federation
    if (target_user_id.find(':') != std::string::npos) {
      std::string target_server = target_user_id.substr(target_user_id.find(':') + 1);
      push_event_to_federation(db, leave_ev, {target_server});
    }

    json body;
    body["membership"] = "leave";
    body["room_id"] = room_id;
    return make_response(200, body);
  }
}

// ============================================================================
// 15. ROOM VISIBILITY MANAGEMENT
// ============================================================================
// GET/PUT /_matrix/client/v3/directory/list/room/{roomId}
//
// Sets or retrieves the visibility of a room in the public room directory.
// - GET: returns the current visibility (public or private)
// - PUT: sets the visibility to public or private

json handle_get_room_visibility(DatabasePool& db, const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const std::string& room_id,
                                 const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 4. Get visibility from directory store ----
  DirectoryStore dir(db);
  auto visibility = dir.get_room_visibility(room_id);

  json body;
  body["visibility"] = visibility.value_or("private");
  body["room_id"] = room_id;

  return make_response(200, body);
}

json handle_set_room_visibility(DatabasePool& db, const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const std::string& room_id,
                                 const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Validate visibility param ----
  if (!request_body.contains("visibility") || !request_body["visibility"].is_string()) {
    return make_error(400, "M_MISSING_PARAM", "Missing visibility parameter");
  }

  std::string visibility = request_body["visibility"].get<std::string>();
  if (visibility != "public" && visibility != "private") {
    return make_error(400, "M_INVALID_PARAM",
                      "Visibility must be 'public' or 'private'");
  }

  // ---- 4. Check room exists ----
  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 5. Check user's power level ----
  if (!has_power_to(db, room_id, auth.user_id, "state_default")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to change room visibility");
  }

  // ---- 6. Update visibility in directory and room store ----
  DirectoryStore dir(db);
  dir.set_room_visibility(room_id, visibility);
  rooms.set_room_is_public(room_id, visibility == "public");

  return make_response(200, json::object());
}

// ============================================================================
// ROOM HANDLER ROUTER - Dispatches to individual handlers
// ============================================================================
// Matches HTTP path + method and delegates to the correct handler function.
// Used by the REST servlet layer to process room-related requests.

json route_room_handler(DatabasePool& db, const std::string& auth_header,
                         const std::string& access_token_param,
                         const std::string& method,
                         const std::string& path,
                         const json& request_body,
                         const std::map<std::string, std::string>& path_params) {

  // ========================================================================
  // CREATE ROOM
  // POST /_matrix/client/v3/createRoom
  // ========================================================================
  if (method == "POST" && path.find("/createRoom") != std::string::npos) {
    return handle_create_room(db, auth_header, access_token_param, request_body);
  }

  // ========================================================================
  // JOIN ROOM
  // POST /_matrix/client/v3/join/{roomIdOrAlias}
  // POST /_matrix/client/v3/rooms/{roomId}/join
  // ========================================================================
  if (method == "POST") {
    // /join/{roomIdOrAlias}
    auto join_pos = path.find("/join/");
    if (join_pos != std::string::npos) {
      std::string room_id_or_alias = path.substr(join_pos + 6);
      return handle_join_room(db, auth_header, access_token_param,
                              room_id_or_alias, request_body);
    }

    // /rooms/{roomId}/join
    auto rooms_join_pos = path.find("/rooms/");
    if (rooms_join_pos != std::string::npos && path.find("/join") != std::string::npos) {
      auto it = path_params.find("roomId");
      if (it != path_params.end()) {
        return handle_join_room(db, auth_header, access_token_param,
                                it->second, request_body);
      }
    }
  }

  // ========================================================================
  // LEAVE ROOM
  // POST /_matrix/client/v3/rooms/{roomId}/leave
  // ========================================================================
  if (method == "POST" && path.find("/leave") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_leave_room(db, auth_header, access_token_param,
                               it->second, request_body);
    }
  }

  // ========================================================================
  // FORGET ROOM
  // POST /_matrix/client/v3/rooms/{roomId}/forget
  // ========================================================================
  if (method == "POST" && path.find("/forget") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_forget_room(db, auth_header, access_token_param,
                                it->second, request_body);
    }
  }

  // ========================================================================
  // INVITE USER
  // POST /_matrix/client/v3/rooms/{roomId}/invite
  // ========================================================================
  if (method == "POST" && path.find("/invite") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_invite_user(db, auth_header, access_token_param,
                                it->second, request_body);
    }
  }

  // ========================================================================
  // KICK USER
  // POST /_matrix/client/v3/rooms/{roomId}/kick
  // ========================================================================
  if (method == "POST" && path.find("/kick") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_kick_user(db, auth_header, access_token_param,
                              it->second, request_body);
    }
  }

  // ========================================================================
  // BAN USER
  // POST /_matrix/client/v3/rooms/{roomId}/ban
  // ========================================================================
  if (method == "POST" && path.find("/ban") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_ban_user(db, auth_header, access_token_param,
                             it->second, request_body);
    }
  }

  // ========================================================================
  // UNBAN USER
  // POST /_matrix/client/v3/rooms/{roomId}/unban
  // ========================================================================
  if (method == "POST" && path.find("/unban") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_unban_user(db, auth_header, access_token_param,
                               it->second, request_body);
    }
  }

  // ========================================================================
  // DIRECTORY ROOM ALIAS - GET
  // GET /_matrix/client/v3/directory/room/{roomAlias}
  // ========================================================================
  if (method == "GET" && path.find("/directory/room/") != std::string::npos) {
    auto it = path_params.find("roomAlias");
    if (it != path_params.end()) {
      return handle_get_alias(db, auth_header, access_token_param,
                              "%23" + it->second, request_body);
      // Note: The alias might need URL decoding. The real implementation
      // handles this via the HTTP framework. %23 is '#' URL-encoded.
    }
  }

  // ========================================================================
  // DIRECTORY ROOM ALIAS - PUT (CREATE)
  // PUT /_matrix/client/v3/directory/room/{roomAlias}
  // ========================================================================
  if (method == "PUT" && path.find("/directory/room/") != std::string::npos) {
    auto it = path_params.find("roomAlias");
    if (it != path_params.end()) {
      return handle_create_alias(db, auth_header, access_token_param,
                                 it->second, request_body);
    }
  }

  // ========================================================================
  // DIRECTORY ROOM ALIAS - DELETE
  // DELETE /_matrix/client/v3/directory/room/{roomAlias}
  // ========================================================================
  if (method == "DELETE" && path.find("/directory/room/") != std::string::npos) {
    auto it = path_params.find("roomAlias");
    if (it != path_params.end()) {
      return handle_delete_alias(db, auth_header, access_token_param,
                                 it->second, request_body);
    }
  }

  // ========================================================================
  // UPGRADE ROOM
  // POST /_matrix/client/v3/rooms/{roomId}/upgrade
  // ========================================================================
  if (method == "POST" && path.find("/upgrade") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_upgrade_room(db, auth_header, access_token_param,
                                 it->second, request_body);
    }
  }

  // ========================================================================
  // KNOCK
  // POST /_matrix/client/v3/knock/{roomIdOrAlias}
  // ========================================================================
  if (method == "POST") {
    auto knock_pos = path.find("/knock/");
    if (knock_pos != std::string::npos) {
      std::string room_id_or_alias = path.substr(knock_pos + 7);
      return handle_knock(db, auth_header, access_token_param,
                          room_id_or_alias, request_body);
    }
  }

  // ========================================================================
  // UNKNOWN ROUTE
  // ========================================================================
  return make_error(404, "M_UNRECOGNIZED",
                    "Unrecognized room endpoint: " + method + " " + path);
}

// ============================================================================
// Additional room state helper: fetch full room summary
// ============================================================================
// Returns a summary object with member counts, join rules, and room metadata.
// Used by clients to display room previews before joining.

json get_room_summary(DatabasePool& db, const std::string& room_id) {
  json summary;

  RoomStore rooms(db);
  RoomMemberStore members(db);
  StateStore state(db);
  EventsStore evs(db);

  // Member counts
  auto ms = members.get_room_member_summary(room_id);
  summary["num_joined_members"] = ms.joined_members;
  summary["num_invited_members"] = ms.invited_members;
  summary["m.joined_member_count"] = ms.joined_members;
  summary["m.invited_member_count"] = ms.invited_members;

  // Join rules
  summary["join_rule"] = get_join_rule(db, room_id);

  // Guest access
  summary["guest_access"] = get_guest_access(db, room_id);

  // Room version
  summary["room_version"] = get_room_version(db, room_id);

  // Heroes (users to show when previewing the room)
  if (!ms.heroes.empty()) {
    summary["m.heroes"] = json::array();
    for (auto& h : ms.heroes) {
      summary["m.heroes"].push_back(h);
    }
  }

  // Room name
  auto name_ev_id = state.get_current_state_event(room_id, "m.room.name", "");
  if (name_ev_id) {
    auto ev = evs.get_event(*name_ev_id);
    if (ev && (*ev)["content"].contains("name")) {
      summary["name"] = (*ev)["content"]["name"];
    }
  }

  // Room topic
  auto topic_ev_id = state.get_current_state_event(room_id, "m.room.topic", "");
  if (topic_ev_id) {
    auto ev = evs.get_event(*topic_ev_id);
    if (ev && (*ev)["content"].contains("topic")) {
      summary["topic"] = (*ev)["content"]["topic"];
    }
  }

  // Canonical alias
  auto ca_ev_id = state.get_current_state_event(room_id, "m.room.canonical_alias", "");
  if (ca_ev_id) {
    auto ev = evs.get_event(*ca_ev_id);
    if (ev && (*ev)["content"].contains("alias")) {
      summary["canonical_alias"] = (*ev)["content"]["alias"];
    }
  }

  // Avatar
  auto av_ev_id = state.get_current_state_event(room_id, "m.room.avatar", "");
  if (av_ev_id) {
    auto ev = evs.get_event(*av_ev_id);
    if (ev && (*ev)["content"].contains("url")) {
      summary["avatar_url"] = (*ev)["content"]["url"];
    }
  }

  // Encryption
  auto enc_ev_id = state.get_current_state_event(room_id, "m.room.encryption", "");
  summary["is_encrypted"] = enc_ev_id.has_value();

  // Room create info
  auto create_ev = state.get_create_event(room_id);
  if (create_ev && create_ev->contains("content")) {
    auto& cc = (*create_ev)["content"];
    if (cc.contains("creator")) summary["creator"] = cc["creator"];
    if (cc.contains("m.federate")) summary["m.federate"] = cc["m.federate"];
    if (cc.contains("type")) summary["room_type"] = cc["type"];
  }

  // Visibility
  DirectoryStore dir(db);
  auto visibility = dir.get_room_visibility(room_id);
  summary["visibility"] = visibility.value_or("private");

  return summary;
}

} // namespace progressive::handlers
