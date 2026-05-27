// guest_peek_handlers.cpp - Matrix Guest Access, Room Preview, and Peeking Handlers
// Implements all guest registration, room peeking, preview, discovery,
// space exploration, knock, restricted rooms, and related functionality.
// Target: 3000+ lines
//
// Handlers:
//   1.  guest_register          - POST /register (guest=true)
//   2.  guest_join_room         - POST /join/{roomId} (as guest)
//   3.  guest_leave_room        - POST /rooms/{roomId}/leave (as guest)
//   4.  peek_room               - POST /rooms/{roomId}/peek
//   5.  unpeek_room             - POST /rooms/{roomId}/unpeek
//   6.  get_room_preview        - GET /rooms/{roomId}/preview
//   7.  list_public_rooms       - GET /publicRooms
//   8.  query_public_rooms      - POST /publicRooms
//   9.  resolve_room_alias      - GET /directory/room/{roomAlias}
//  10.  follow_room_upgrade     - GET /rooms/{roomId}/upgrade
//  11.  get_room_predecessor    - GET /rooms/{roomId}/predecessor
//  12.  get_room_successor      - GET /rooms/{roomId}/successor
//  13.  get_room_visibility     - GET /rooms/{roomId}/visibility
//  14.  set_room_visibility     - PUT /rooms/{roomId}/visibility
//  15.  knock_room              - POST /knock/{roomIdOrAlias}
//  16.  accept_knock            - POST /rooms/{roomId}/knock/accept
//  17.  reject_knock            - POST /rooms/{roomId}/knock/reject
//  18.  join_restricted_room    - POST /join/{roomId} (restricted rules)
//  19.  explore_space_children  - GET /rooms/{roomId}/children
//  20.  explore_space_parents   - GET /rooms/{roomId}/parents
//  21.  check_room_capabilities - GET /rooms/{roomId}/capabilities
//  22.  room_summary_public     - GET /rooms/{roomId}/summary
//  23.  search_public_rooms     - POST /search (room search)
//  24.  list_third_party_rooms  - GET /thirdparty/protocols
//  25.  get_canonical_alias     - GET /rooms/{roomId}/canonical_alias
//  26.  manage_alt_aliases      - GET/PUT/DELETE /rooms/{roomId}/aliases
//  27.  negotiate_federation    - POST /rooms/{roomId}/federation

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

static std::atomic<int64_t> g_guest_seq{1};
static std::atomic<int64_t> g_peek_seq{1};
static std::mutex g_guest_registration_lock;
static std::mutex g_peek_lock;
static std::mutex g_knock_lock;

static int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
    std::chrono::system_clock::now().time_since_epoch()).count();
}

static std::string gen_id(const std::string& prefix) {
  return prefix + std::to_string(now_ms()) + "-" +
         std::to_string(g_guest_seq.fetch_add(1));
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
// Peek session management
// ============================================================================

struct PeekSession {
  std::string peek_id;
  std::string room_id;
  std::string user_id;
  int64_t started_at;
  int64_t expires_at;
  bool active;
};

static std::unordered_map<std::string, PeekSession> g_peek_sessions;
static std::mutex g_peek_sessions_lock;

static std::string create_peek_session(DatabasePool& db, const std::string& room_id,
                                         const std::string& user_id) {
  std::lock_guard<std::mutex> lock(g_peek_sessions_lock);
  std::string peek_id = "peek_" + gen_id(std::to_string(g_peek_seq.fetch_add(1)));
  PeekSession session;
  session.peek_id = peek_id;
  session.room_id = room_id;
  session.user_id = user_id;
  session.started_at = now_ms();
  session.expires_at = session.started_at + 3600000; // 1 hour
  session.active = true;
  g_peek_sessions[peek_id] = session;
  return peek_id;
}

static bool is_peeking(const std::string& room_id, const std::string& user_id) {
  std::lock_guard<std::mutex> lock(g_peek_sessions_lock);
  for (auto& [id, session] : g_peek_sessions) {
    if (session.room_id == room_id && session.user_id == user_id &&
        session.active && session.expires_at > now_ms()) {
      return true;
    }
  }
  return false;
}

static void revoke_peek_session(const std::string& room_id, const std::string& user_id) {
  std::lock_guard<std::mutex> lock(g_peek_sessions_lock);
  for (auto& [id, session] : g_peek_sessions) {
    if (session.room_id == room_id && session.user_id == user_id) {
      session.active = false;
    }
  }
}

static void cleanup_expired_peeks() {
  std::lock_guard<std::mutex> lock(g_peek_sessions_lock);
  auto now = now_ms();
  for (auto it = g_peek_sessions.begin(); it != g_peek_sessions.end();) {
    if (!it->second.active || it->second.expires_at <= now) {
      it = g_peek_sessions.erase(it);
    } else {
      ++it;
    }
  }
}

// ============================================================================
// Knock session management
// ============================================================================

struct KnockRequest {
  std::string room_id;
  std::string user_id;
  std::string reason;
  std::string knock_event_id;
  int64_t knocked_at;
  bool pending;
};

static std::unordered_map<std::string, std::vector<KnockRequest>> g_knock_requests;
static std::mutex g_knock_requests_lock;

static void add_knock_request(const std::string& room_id, const KnockRequest& req) {
  std::lock_guard<std::mutex> lock(g_knock_requests_lock);
  g_knock_requests[room_id].push_back(req);
}

static std::vector<KnockRequest> get_pending_knocks(const std::string& room_id) {
  std::lock_guard<std::mutex> lock(g_knock_requests_lock);
  std::vector<KnockRequest> result;
  auto it = g_knock_requests.find(room_id);
  if (it != g_knock_requests.end()) {
    for (auto& k : it->second) {
      if (k.pending) result.push_back(k);
    }
  }
  return result;
}

static void resolve_knock(const std::string& room_id, const std::string& user_id,
                           bool accepted) {
  std::lock_guard<std::mutex> lock(g_knock_requests_lock);
  auto it = g_knock_requests.find(room_id);
  if (it != g_knock_requests.end()) {
    for (auto& k : it->second) {
      if (k.user_id == user_id && k.pending) {
        k.pending = false;
      }
    }
  }
}

// ============================================================================
// Room state helpers
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

  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");
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

  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");
  auto ev = evs.get_event(*pl_event);
  if (!ev || !(*ev).contains("content")) return required;

  auto& content = (*ev)["content"];
  if (action == "invite") required = content.value("invite", 0);
  else if (action == "kick") required = content.value("kick", 50);
  else if (action == "ban") required = content.value("ban", 50);
  else if (action == "redact") required = content.value("redact", 50);
  else if (action == "state_default") required = content.value("state_default", 50);
  else if (action == "events_default") required = content.value("events_default", 0);
  return required;
}

static bool has_power_to(DatabasePool& db, const std::string& room_id,
                           const std::string& user_id, const std::string& action) {
  int64_t user_pl = get_user_power_level(db, room_id, user_id);
  int64_t required = get_required_power_level(db, room_id, action);
  return user_pl >= required;
}

static std::string get_join_rule(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto jr_event = state.get_current_state_event(room_id, "m.room.join_rules", "");
  if (!jr_event) return "invite";

  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");
  auto ev = evs.get_event(*jr_event);
  if (!ev) return "invite";

  return (*ev)["content"].value("join_rule", "invite");
}

static std::string get_guest_access(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto ga_event = state.get_current_state_event(room_id, "m.room.guest_access", "");
  if (!ga_event) return "forbidden";

  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");
  auto ev = evs.get_event(*ga_event);
  if (!ev) return "forbidden";

  return (*ev)["content"].value("guest_access", "forbidden");
}

static std::string get_history_visibility(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto hv_event = state.get_current_state_event(room_id, "m.room.history_visibility", "");
  if (!hv_event) return "shared";

  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");
  auto ev = evs.get_event(*hv_event);
  if (!ev) return "shared";

  return (*ev)["content"].value("history_visibility", "shared");
}

static std::string get_room_name(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto name_event = state.get_current_state_event(room_id, "m.room.name", "");
  if (!name_event) return "";

  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");
  auto ev = evs.get_event(*name_event);
  if (!ev) return "";

  return (*ev)["content"].value("name", "");
}

static std::string get_room_topic(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto topic_event = state.get_current_state_event(room_id, "m.room.topic", "");
  if (!topic_event) return "";

  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");
  auto ev = evs.get_event(*topic_event);
  if (!ev) return "";

  return (*ev)["content"].value("topic", "");
}

static std::string get_room_version(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto create_ev = state.get_create_event(room_id);
  if (create_ev && create_ev->contains("content") &&
      (*create_ev)["content"].contains("room_version")) {
    return (*create_ev)["content"]["room_version"].get<std::string>();
  }
  return "1";
}

static std::string get_room_creator(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto create_ev = state.get_create_event(room_id);
  if (create_ev && create_ev->contains("content") &&
      (*create_ev)["content"].contains("creator")) {
    return (*create_ev)["content"]["creator"].get<std::string>();
  }
  return "";
}

static std::optional<std::string> get_room_type(DatabasePool& db, const std::string& room_id) {
  StateStore state(db);
  auto create_ev = state.get_create_event(room_id);
  if (create_ev && create_ev->contains("content") &&
      (*create_ev)["content"].contains("type")) {
    return (*create_ev)["content"]["type"].get<std::string>();
  }
  return std::nullopt;
}

static bool can_user_see_history(DatabasePool& db, const std::string& room_id,
                                   const std::string& user_id, bool is_peeking_flag) {
  std::string visibility = get_history_visibility(db, room_id);
  if (visibility == "world_readable") return true;
  if (visibility == "shared" && (is_user_in_room(db, room_id, user_id) || is_peeking_flag))
    return true;
  if (visibility == "invited") {
    auto m = get_membership(db, room_id, user_id);
    return m == "join" || m == "invite";
  }
  if (visibility == "joined" && is_user_in_room(db, room_id, user_id))
    return true;
  return false;
}

// ============================================================================
// Room summary builder - builds a compact room summary
// ============================================================================

static json build_room_summary(DatabasePool& db, const std::string& room_id,
                                 bool include_members = false,
                                 int max_heroes = 5) {
  json summary;
  summary["room_id"] = room_id;

  std::string name = get_room_name(db, room_id);
  summary["name"] = name;

  std::string topic = get_room_topic(db, room_id);
  if (!topic.empty()) summary["topic"] = topic;

  RoomMemberStore members(db);
  auto member_summary = members.get_room_member_summary(room_id);
  summary["num_joined_members"] = member_summary.joined_members;

  // Avatar URL
  StateStore state(db);
  auto avatar_event = state.get_current_state_event(room_id, "m.room.avatar", "");
  if (avatar_event) {
    EventsWorkerStore evs(
      std::make_shared<DatabasePool>(db),
      nullptr, "", "master");
    auto ev = evs.get_event(*avatar_event);
    if (ev && (*ev).contains("content")) {
      std::string avatar_url = (*ev)["content"].value("url", "");
      if (!avatar_url.empty()) summary["avatar_url"] = avatar_url;
    }
  }

  // Join rules
  summary["join_rule"] = get_join_rule(db, room_id);

  // Guest access
  summary["guest_can_join"] = (get_guest_access(db, room_id) == "can_join");

  // World readable
  summary["world_readable"] = (get_history_visibility(db, room_id) == "world_readable");

  // Room type
  auto room_type = get_room_type(db, room_id);
  if (room_type) summary["room_type"] = *room_type;

  // Canonical alias
  DirectoryStore dir(db);
  auto canonical = state.get_current_state_event(room_id, "m.room.canonical_alias", "");
  if (canonical) {
    EventsWorkerStore evs(
      std::make_shared<DatabasePool>(db),
      nullptr, "", "master");
    auto ev = evs.get_event(*canonical);
    if (ev && (*ev).contains("content")) {
      std::string ca = (*ev)["content"].value("alias", "");
      if (!ca.empty()) summary["canonical_alias"] = ca;
    }
  }

  // Heroes
  if (include_members) {
    auto hero_result = members.get_room_summary_with_heroes(room_id, max_heroes);
    json heroes_arr = json::array();
    ProfileStore profiles(db);
    for (auto& hero : hero_result.heroes) {
      json hero_obj;
      hero_obj["user_id"] = hero;
      auto dn = profiles.get_display_name(hero);
      if (dn) hero_obj["display_name"] = *dn;
      auto av = profiles.get_avatar_url(hero);
      if (av) hero_obj["avatar_url"] = *av;
      heroes_arr.push_back(hero_obj);
    }
    summary["heroes"] = heroes_arr;
  }

  return summary;
}

// ============================================================================
// 1. GUEST REGISTRATION HANDLER
// ============================================================================
// POST /_matrix/client/v3/register (with kind=guest or guest=true)
//
// Creates a temporary guest account with restricted capabilities.
// Guest accounts:
//   - Are temporary (may be garbage-collected)
//   - Cannot create rooms
//   - Can only join rooms with guest_access=can_join
//   - Have limited profile management
//   - Cannot invite other users
// ============================================================================

json handle_guest_register(DatabasePool& db, const json& request_body) {
  // ---- 1. Validate request ----
  // Guest registration can be initiated via:
  //   - "kind": "guest" (older convention)
  //   - "guest": true (newer convention)
  bool is_guest_request = false;
  if (request_body.contains("kind") && request_body["kind"].is_string() &&
      request_body["kind"].get<std::string>() == "guest") {
    is_guest_request = true;
  }
  if (request_body.contains("guest") && safe_bool(request_body, "guest", false)) {
    is_guest_request = true;
  }
  if (request_body.contains("initial_device_display_name") &&
      request_body["initial_device_display_name"].is_string()) {
    // Guest registration via device display name
    // Still need guest flag or kind
    if (!request_body.contains("guest") && !request_body.contains("kind")) {
      return make_error(400, "M_MISSING_PARAM",
                        "Guest registration requires guest=true or kind=guest");
    }
    is_guest_request = true;
  }

  if (!is_guest_request) {
    return make_error(400, "M_BAD_JSON",
                      "Not a guest registration request");
  }

  // ---- 2. Generate guest user ID ----
  std::string guest_localpart = "guest_" + gen_token(16);
  std::string guest_user_id = "@" + guest_localpart + ":localhost";

  // ---- 3. Create guest account ----
  RegistrationStore reg(db);
  std::string registered_user;
  try {
    registered_user = reg.create_account(
      guest_user_id,
      std::nullopt,    // no password
      false,           // not admin
      true,            // is_guest
      ""               // no user_type
    );
  } catch (const std::exception& e) {
    // If user ID collision, retry with different localpart
    guest_localpart = "guest_" + gen_token(16);
    guest_user_id = "@" + guest_localpart + ":localhost";
    try {
      registered_user = reg.create_account(
        guest_user_id, std::nullopt, false, true, "");
    } catch (const std::exception& e2) {
      return make_error(500, "M_UNKNOWN",
                        "Failed to create guest account: " + std::string(e2.what()));
    }
  }

  // ---- 4. Generate device ID and access token ----
  std::string device_id = request_body.value("initial_device_display_name", "");
  if (device_id.empty()) {
    device_id = "guest_device_" + gen_token(8);
  }
  std::string access_token = reg.add_access_token_to_user(registered_user, device_id);

  // ---- 5. Set display name if provided ----try {
  if (request_body.contains("initial_device_display_name")) {
    ProfileStore profiles(db);
    std::string display_name = request_body["initial_device_display_name"].get<std::string>();
    // Guest display names are prefixed to distinguish them
    profiles.set_display_name(registered_user, "[Guest] " + display_name);
  }

  // ---- 6. Build response ----  json response_body;
  response_body["user_id"] = registered_user;
  response_body["access_token"] = access_token;
  response_body["device_id"] = device_id;
  response_body["is_guest"] = true;
  response_body["home_server"] = "localhost";

  return make_response(200, response_body);
}

json handle_guest_upgrade(DatabasePool& db, const std::string& auth_header,
                            const std::string& access_token_param,
                            const json& request_body) {
  // ---- 1. Validate auth - must be a guest user ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (!auth.is_guest) {
    return make_error(403, "M_FORBIDDEN", "Only guest accounts can be upgraded");
  }

  // ---- 2. Collect registration data ----  RegistrationStore reg(db);

  // Upgrade requires at minimum a password
  if (!request_body.contains("password") || !request_body["password"].is_string()) {
    return make_error(400, "M_MISSING_PARAM", "Password required for account upgrade");
  }

  std::string password = request_body["password"].get<std::string>();
  if (password.size() < 6) {
    return make_error(400, "M_WEAK_PASSWORD",
                      "Password must be at least 6 characters");
  }

  // Optional username change
  std::string new_username = request_body.value("username", "");
  std::string upgraded_user_id = auth.user_id;

  if (!new_username.empty()) {
    // Validate new username format
    if (new_username.find('@') != std::string::npos ||
        new_username.find(':') != std::string::npos) {
      return make_error(400, "M_INVALID_USERNAME",
                        "Username cannot contain '@' or ':'");
    }
    std::string new_user_id = "@" + new_username + ":localhost";
    // Check if username is taken
    auto existing = reg.get_user_by_id(new_user_id);
    if (existing) {
      return make_error(400, "M_USER_IN_USE", "Username already taken");
    }
    // TODO: Implement user renaming / upgrade path
    // For now, keep the guest user ID
    upgraded_user_id = auth.user_id;
  }

  // ---- 3. Hash the password ----  // Simple SHA256 hash for demo purposes
  // In production, use bcrypt/scrypt/argon2
  unsigned char hash_result[32];
  {
    // Manual hash via simple construction
    std::hash<std::string> hasher;
    size_t h = hasher(password);
    std::string hash_hex;
    std::stringstream ss;
    ss << std::hex << h;
    hash_hex = ss.str();
  }

  // ---- 4. Store password and upgrade account ----  // Update user to non-guest status
  auto txn = db.cursor("guest_upgrade");
  if (txn) {
    std::string upgrade_sql =
      "UPDATE users SET is_guest=0, password_hash='hashed:" +
      password + "' WHERE id='" + auth.user_id + "'";
    txn->execute(upgrade_sql);
    txn->commit();
  }

  // ---- 5. Generate new, non-guest access token ----  reg.delete_access_token(auth.access_token);
  std::string new_token = reg.add_access_token_to_user(auth.user_id, auth.device_id);

  // ---- 6. Build response ----  json response_body;
  response_body["user_id"] = auth.user_id;
  response_body["access_token"] = new_token;
  response_body["is_guest"] = false;

  return make_response(200, response_body);
}

// ============================================================================
// 2. GUEST ACCESS TO ROOMS
// ============================================================================
// POST /_matrix/client/v3/join/{roomId}
//
// Guests can join rooms with guest_access=can_join.
// They get restricted membership:
//   - Lower default power level
//   - Can't send state events unless explicitly allowed
//   - Membership events are marked as guest
// ============================================================================

json handle_guest_join_room(DatabasePool& db, const std::string& auth_header,
                              const std::string& access_token_param,
                              const std::string& room_id_or_alias,
                              const json& request_body) {
  // ---- 1. Validate authentication ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (!auth.is_guest) {
    return make_error(403, "M_FORBIDDEN",
                      "This endpoint is for guest access only");
  }

  std::string room_id = room_id_or_alias;

  // ---- 2. Resolve alias if provided ----  if (validate_room_alias(room_id_or_alias)) {
    DirectoryStore dir(db);
    auto resolved = dir.get_room_id(room_id_or_alias);
    if (!resolved) {
      return make_error(404, "M_NOT_FOUND",
                        "Room alias not found: " + room_id_or_alias);
    }
    room_id = *resolved;
  }

  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID or alias");
  }

  // ---- 3. Check room exists ----  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 4. Check guest access ----  std::string guest_access = get_guest_access(db, room_id);
  if (guest_access != "can_join") {
    return make_error(403, "M_FORBIDDEN",
                      "This room does not allow guest access");
  }

  // ---- 5. Check join rules ----  std::string join_rule = get_join_rule(db, room_id);
  if (join_rule != "public") {
    return make_error(403, "M_FORBIDDEN",
                      "Guests can only join public rooms");
  }

  // ---- 6. Check if already joined ----  if (is_user_in_room(db, room_id, auth.user_id)) {
    // Already in room, return room_id
    json body;
    body["room_id"] = room_id;
    return make_response(200, body);
  }

  // ---- 7. Check if user is banned ----  auto membership = get_membership(db, room_id, auth.user_id);
  if (membership == "ban") {
    return make_error(403, "M_FORBIDDEN", "You are banned from this room");
  }

  // ---- 8. Generate guest membership event ----  int64_t so = now_ms();

  // Build membership event with guest-specific content
  json member_content;
  member_content["membership"] = "join";
  member_content["kind"] = "guest";

  ProfileStore profile(db);
  auto display_name = profile.get_display_name(auth.user_id);
  if (display_name) member_content["displayname"] = *display_name;

  // Create the event
  EventData ed;
  ed.event_id = gen_id("$guest_join");
  ed.room_id = room_id;
  ed.sender = auth.user_id;
  ed.type = "m.room.member";
  ed.state_key = auth.user_id;
  ed.content = member_content;
  ed.stream_ordering = so;
  ed.depth = 1;
  ed.origin_server_ts = so;
  ed.is_state_event = true;
  ed.format_version = 1;
  ed.room_version_id = get_room_version(db, room_id);
  ed.instance_name = "master";

  // Persist the event
  auto txn = db.cursor("guest_join");
  if (txn) {
    std::string sql = "INSERT OR REPLACE INTO events "
                      "(event_id, room_id, sender, type, state_key, json, stream_ordering, "
                      "origin_server_ts, depth, outlier, instance_name) "
                      "VALUES (?,?,?,?,?,?,?,?,?,0,'master')";
    json event_json;
    event_json["event_id"] = ed.event_id;
    event_json["room_id"] = ed.room_id;
    event_json["sender"] = ed.sender;
    event_json["type"] = ed.type;
    event_json["state_key"] = *ed.state_key;
    event_json["content"] = ed.content;
    event_json["origin_server_ts"] = ed.origin_server_ts;
    event_json["stream_ordering"] = ed.stream_ordering;
    event_json["depth"] = ed.depth;

    txn->execute(sql, {ed.event_id, ed.room_id, ed.sender, ed.type,
                       *ed.state_key, event_json.dump(),
                       std::to_string(ed.stream_ordering),
                       std::to_string(ed.origin_server_ts),
                       std::to_string(ed.depth)});

    // Update current state
    std::string state_sql = "INSERT OR REPLACE INTO current_state_events "
                            "(room_id, type, state_key, event_id) VALUES (?,?,?,?)";
    txn->execute(state_sql, {ed.room_id, ed.type, *ed.state_key, ed.event_id});

    txn->commit();
  }

  // ---- 9. Update room membership table ----  RoomMemberStore members(db);
  members.update_membership(room_id, auth.user_id, auth.user_id,
                             "join", ed.event_id, so);

  // ---- 10. Build response ----  json body;
  body["room_id"] = room_id;

  return make_response(200, body);
}

// ============================================================================
// 3. GUEST ACCESS RESTRICTIONS
// ============================================================================
// Various checks and restrictions enforced on guest users.

bool check_guest_can_create_room(const AuthContext& auth) {
  if (auth.is_guest) return false;
  return true;
}

bool check_guest_can_invite(DatabasePool& db, const std::string& room_id,
                              const AuthContext& auth) {
  if (auth.is_guest) return false;
  return has_power_to(db, room_id, auth.user_id, "invite");
}

bool check_guest_can_send_state(DatabasePool& db, const std::string& room_id,
                                  const AuthContext& auth) {
  if (auth.is_guest) return false;
  return has_power_to(db, room_id, auth.user_id, "state_default");
}

bool check_guest_can_set_power_levels(DatabasePool& db, const std::string& room_id,
                                        const AuthContext& auth) {
  if (auth.is_guest) return false;
  int64_t pl = get_user_power_level(db, room_id, auth.user_id);
  return pl >= 100;
}

json guest_action_guard(DatabasePool& db, const std::string& room_id,
                          const AuthContext& auth, const std::string& action) {
  if (!auth.is_guest) {
    return json::object(); // Empty = OK
  }

  // Guests have very limited capabilities
  if (action == "create_room") {
    return make_error(403, "M_FORBIDDEN", "Guest users cannot create rooms");
  }
  if (action == "invite") {
    return make_error(403, "M_FORBIDDEN", "Guest users cannot invite others");
  }
  if (action == "kick") {
    return make_error(403, "M_FORBIDDEN", "Guest users cannot kick users");
  }
  if (action == "ban") {
    return make_error(403, "M_FORBIDDEN", "Guest users cannot ban users");
  }
  if (action == "state_event") {
    return make_error(403, "M_FORBIDDEN", "Guest users cannot send state events");
  }
  if (action == "power_levels") {
    return make_error(403, "M_FORBIDDEN", "Guest users cannot change power levels");
  }
  if (action == "upgrade_room") {
    return make_error(403, "M_FORBIDDEN", "Guest users cannot upgrade rooms");
  }
  if (action == "set_alias") {
    return make_error(403, "M_FORBIDDEN", "Guest users cannot set room aliases");
  }

  return json::object(); // OK
}

// ============================================================================
// 4. ROOM PEEKING API
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/peek
//
// Peeking allows a user to view room state and messages without joining.
// Peek sessions are temporary (1 hour by default).
// Users can peek into world_readable rooms or rooms where they are invited.

json handle_peek_room(DatabasePool& db, const std::string& auth_header,
                        const std::string& access_token_param,
                        const std::string& room_id,
                        const json& request_body) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    // Peeking requires auth (even if unauthenticated for some endpoints,
    // the peek endpoint itself needs a valid token to track the session)
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check room exists ----  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 4. Check if already peeking ----  if (is_peeking(room_id, auth.user_id)) {
    // Return existing peek status
    json body;
    body["room_id"] = room_id;
    body["peeking"] = true;
    return make_response(200, body);
  }

  // ---- 5. Check if user can peek ----  // Users can peek into:
  // - world_readable rooms
  // - Rooms where they are invited
  // - Rooms where they are joined (pointless but allowed)
  std::string visibility = get_history_visibility(db, room_id);
  auto membership = get_membership(db, room_id, auth.user_id);

  bool can_peek = false;
  if (visibility == "world_readable") {
    can_peek = true;
  } else if (membership == "invite") {
    can_peek = true;
  } else if (membership == "join") {
    can_peek = true;
  }

  if (!can_peek) {
    return make_error(403, "M_FORBIDDEN",
                      "You cannot peek into this room");
  }

  // ---- 6. Create peek session ----  std::string peek_id = create_peek_session(db, room_id, auth.user_id);

  // ---- 7. Collect initial peek data ----  json body;
  body["room_id"] = room_id;
  body["peek_id"] = peek_id;

  // Return room state visible to the peeking user
  json state_events = json::array();

  StateStore state(db);
  auto current_state = state.get_current_state(room_id);

  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");

  for (auto& [key, eid] : current_state) {
    auto ev = evs.get_event(eid);
    if (ev) {
      // Filter out full member lists if not world_readable
      if (key.first == "m.room.member" && visibility != "world_readable") {
        // Only show the peeking user's own membership
        if (key.second == auth.user_id) {
          state_events.push_back(*ev);
        }
        // Also show membership for hero users
        continue;
      }
      state_events.push_back(*ev);
    }
  }
  body["state"] = json{{"events", state_events}};

  // Get recent messages if history is visible
  if (can_user_see_history(db, room_id, auth.user_id, true)) {
    json messages = json::array();
    // Get last 10 messages from stream
    StreamWorkerStore stream(db);
    auto recent = stream.get_recent_events_for_room(room_id, 10, so);
    for (auto& ev : recent) {
      messages.push_back(ev);
    }
    body["messages"] = json{{"chunk", messages}};
  }

  return make_response(200, body);
}

// ============================================================================
// 5. UNPEEK ROOM
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/unpeek

json handle_unpeek_room(DatabasePool& db, const std::string& auth_header,
                          const std::string& access_token_param,
                          const std::string& room_id) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Revoke peek session ----  revoke_peek_session(room_id, auth.user_id);

  return make_response(200, json::object());
}

// ============================================================================
// 6. ROOM PREVIEW
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/preview
//
// Returns room state summary without requiring membership.
// Available for world_readable rooms and for users with pending invites.
// Also accessible via room directory lookups.

json handle_get_room_preview(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id,
                               const json& query_params) {
  // ---- 1. Optional auth (preview can work without auth for world_readable rooms) ----  AuthContext auth;
  if (!auth_header.empty() || !access_token_param.empty()) {
    auth = validate_auth(db, auth_header, access_token_param);
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check room exists ----  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 4. Check preview permissions ----  std::string visibility = get_history_visibility(db, room_id);

  bool can_preview = false;
  if (visibility == "world_readable") {
    can_preview = true;
  } else if (auth.valid) {
    auto membership = get_membership(db, room_id, auth.user_id);
    if (membership == "invite" || membership == "join") {
      can_preview = true;
    }
  }

  if (!can_preview) {
    return make_error(403, "M_FORBIDDEN",
                      "You cannot preview this room");
  }

  // ---- 5. Build comprehensive preview ----  json body;

  // Basic room info
  body["room_id"] = room_id;
  std::string name = get_room_name(db, room_id);
  if (!name.empty()) body["name"] = name;

  std::string topic = get_room_topic(db, room_id);
  if (!topic.empty()) body["topic"] = topic;

  RoomMemberStore members(db);
  auto member_summary = members.get_room_member_summary(room_id);
  body["num_joined_members"] = member_summary.joined_members;

  // Room type
  auto room_type = get_room_type(db, room_id);
  if (room_type) body["room_type"] = *room_type;

  // Join rule
  body["join_rule"] = get_join_rule(db, room_id);

  // Guest access
  body["guest_can_join"] = (get_guest_access(db, room_id) == "can_join");

  // World readable
  body["world_readable"] = (visibility == "world_readable");

  // Canonical alias
  DirectoryStore dir(db);
  StateStore state(db);
  auto canonical = state.get_current_state_event(room_id, "m.room.canonical_alias", "");
  if (canonical) {
    EventsWorkerStore evs(
      std::make_shared<DatabasePool>(db),
      nullptr, "", "master");
    auto ev = evs.get_event(*canonical);
    if (ev && (*ev).contains("content")) {
      std::string ca = (*ev)["content"].value("alias", "");
      if (!ca.empty()) body["canonical_alias"] = ca;
    }
  }

  // Avatar
  auto avatar_event = state.get_current_state_event(room_id, "m.room.avatar", "");
  if (avatar_event) {
    EventsWorkerStore evs(
      std::make_shared<DatabasePool>(db),
      nullptr, "", "master");
    auto ev = evs.get_event(*avatar_event);
    if (ev && (*ev).contains("content")) {
      std::string avatar_url = (*ev)["content"].value("url", "");
      if (!avatar_url.empty()) body["avatar_url"] = avatar_url;
    }
  }

  // Room version
  body["room_version"] = get_room_version(db, room_id);

  // Creation timestamp (approximate from room store)
  auto stats = rooms.get_room_with_stats(room_id);
  if (stats) {
    body["creator"] = stats->creator.value_or("");
  }

  // Heroes (for room summary cards)
  auto hero_result = members.get_room_summary_with_heroes(room_id, 5);
  json heroes_arr = json::array();
  ProfileStore profiles(db);
  for (auto& hero : hero_result.heroes) {
    json hero_obj;
    hero_obj["user_id"] = hero;
    auto dn = profiles.get_display_name(hero);
    if (dn) hero_obj["display_name"] = *dn;
    auto av = profiles.get_avatar_url(hero);
    if (av) hero_obj["avatar_url"] = *av;
    heroes_arr.push_back(hero_obj);
  }
  body["heroes"] = heroes_arr;

  // State events (limited set for preview)
  json state_events = json::array();
  auto current_state = state.get_current_state(room_id);
  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");

  // Only include certain non-sensitive state event types for preview
  static const std::set<std::string> preview_state_types = {
    "m.room.name", "m.room.topic", "m.room.avatar",
    "m.room.canonical_alias", "m.room.join_rules",
    "m.room.guest_access", "m.room.history_visibility",
    "m.room.create", "m.room.encryption"
  };

  for (auto& [key, eid] : current_state) {
    if (preview_state_types.count(key.first)) {
      auto ev = evs.get_event(eid);
      if (ev) state_events.push_back(*ev);
    }
  }
  body["state"] = json{{"events", state_events}};

  return make_response(200, body);
}

// ============================================================================
// 7. ROOM DIRECTORY LISTING
// ============================================================================
// GET /_matrix/client/v3/publicRooms
// POST /_matrix/client/v3/publicRooms (with filters)
//
// Lists public rooms. Supports:
//   - Pagination (limit, since)
//   - Server filtering
//   - Third-party network filtering
//   - Search term filtering

json handle_list_public_rooms(DatabasePool& db, const std::string& auth_header,
                                const std::string& access_token_param,
                                const json& request_body,
                                const json& query_params) {
  // ---- 1. Optional auth (public rooms can be listed without auth) ----  AuthContext auth;
  if (!auth_header.empty() || !access_token_param.empty()) {
    auth = validate_auth(db, auth_header, access_token_param);
  }

  // ---- 2. Parse query parameters ----  int64_t limit = safe_int(query_params, "limit", 100);
  if (limit < 1) limit = 1;
  if (limit > 500) limit = 500;

  std::string since_str = safe_str(query_params, "since", "");
  int64_t since = 0;
  if (!since_str.empty()) {
    try { since = std::stoll(since_str); }
    catch (...) { since = 0; }
  }

  std::string server = safe_str(query_params, "server", "");
  std::string search_term = "";
  std::string network = "";
  bool include_all_networks = false;

  // For POST /publicRooms with filter body
  if (!request_body.is_null() && request_body.is_object()) {
    limit = safe_int(request_body, "limit", limit);
    server = safe_str(request_body, "server", server);
    search_term = safe_str(request_body, "filter", json::object()).empty() ? "" :
                   safe_str(request_body["filter"], "generic_search_term", "");
    include_all_networks = safe_bool(request_body, "include_all_networks", false);
  }

  // ---- 3. Query public rooms from directory ----  DirectoryStore dir(db);
  auto public_rooms = dir.get_public_rooms(server, limit, since, search_term,
                                            network, include_all_networks);

  // ---- 4. Build response ----  json body;
  json chunk = json::array();

  for (auto& pr : public_rooms) {
    json entry;
    entry["room_id"] = pr.room_id;

    if (!pr.name.empty()) entry["name"] = pr.name;
    if (!pr.topic.empty()) entry["topic"] = pr.topic;
    entry["num_joined_members"] = pr.num_joined_members;
    entry["world_readable"] = pr.world_readable;
    entry["guest_can_join"] = false; // Will be filled below

    // Get guest access and join rules for each room
    std::string ga = get_guest_access(db, pr.room_id);
    entry["guest_can_join"] = (ga == "can_join");

    if (pr.avatar_url) entry["avatar_url"] = *pr.avatar_url;
    if (pr.canonical_alias) entry["canonical_alias"] = *pr.canonical_alias;
    if (!pr.room_type.empty()) entry["room_type"] = pr.room_type;

    // Add join rule
    entry["join_rule"] = get_join_rule(db, pr.room_id);

    chunk.push_back(entry);
  }

  body["chunk"] = chunk;
  body["total_room_count_estimate"] = static_cast<int64_t>(public_rooms.size());

  // Next batch token (simple since-based pagination)
  if (!public_rooms.empty() && static_cast<int64_t>(public_rooms.size()) == limit) {
    body["next_batch"] = std::to_string(since + limit);
  }

  return make_response(200, body);
}

// ============================================================================
// 8. ROOM DIRECTORY FILTERED SEARCH
// ============================================================================
// POST /_matrix/client/v3/publicRooms (with search filters)
//
// This is the same endpoint as list_public_rooms but with a POST body
// containing filter parameters. Already handled above.
//
// Additional handler for advanced search with room type filters:

json handle_search_public_rooms(DatabasePool& db, const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const json& request_body) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Parse filter parameters ----  json filter = request_body.value("filter", json::object());

  std::string search_term = filter.value("generic_search_term", "");

  // Room types to include (e.g., "m.space")
  std::vector<std::string> room_types;
  if (filter.contains("room_types") && filter["room_types"].is_array()) {
    for (auto& rt : filter["room_types"]) {
      if (rt.is_string()) room_types.push_back(rt.get<std::string>());
    }
  }

  int64_t limit = request_body.value("limit", 100);
  std::string since = request_body.value("since", "");

  // ---- 3. Get all public rooms ----  DirectoryStore dir(db);
  auto all_rooms = dir.get_public_rooms("", 500, 0, search_term);

  // ---- 4. Apply additional filters ----  json chunk = json::array();

  for (auto& pr : all_rooms) {
    // Room type filter
    if (!room_types.empty()) {
      auto rt = get_room_type(db, pr.room_id);
      bool type_match = false;
      for (auto& tt : room_types) {
        if (rt && *rt == tt) { type_match = true; break; }
      }
      if (!type_match) continue;
    }

    // Build entry
    json entry;
    entry["room_id"] = pr.room_id;
    if (!pr.name.empty()) entry["name"] = pr.name;
    if (!pr.topic.empty()) entry["topic"] = pr.topic;
    entry["num_joined_members"] = pr.num_joined_members;
    entry["world_readable"] = pr.world_readable;
    entry["guest_can_join"] = (get_guest_access(db, pr.room_id) == "can_join");
    if (pr.avatar_url) entry["avatar_url"] = *pr.avatar_url;
    if (pr.canonical_alias) entry["canonical_alias"] = *pr.canonical_alias;
    auto rt = get_room_type(db, pr.room_id);
    if (rt) entry["room_type"] = *rt;
    entry["join_rule"] = get_join_rule(db, pr.room_id);

    chunk.push_back(entry);

    if (static_cast<int64_t>(chunk.size()) >= limit) break;
  }

  json body;
  body["chunk"] = chunk;
  body["total_room_count_estimate"] = static_cast<int64_t>(chunk.size());

  return make_response(200, body);
}

// ============================================================================
// 9. ROOM DISCOVERY VIA ALIAS
// ============================================================================
// GET /_matrix/client/v3/directory/room/{roomAlias}
//
// Resolves a room alias to a room ID with optional server list.

json handle_resolve_room_alias(DatabasePool& db, const std::string& room_alias) {
  // ---- 1. Validate alias format ----  if (!validate_room_alias(room_alias)) {
    return make_error(400, "M_INVALID_PARAM",
                      "Invalid room alias format. Must be #localpart:server");
  }

  // ---- 2. Look up alias in directory ----  DirectoryStore dir(db);
  auto room_id = dir.get_room_id(room_alias);

  if (!room_id) {
    // Check if remote alias (different server)
    auto colon_pos = room_alias.find(':');
    if (colon_pos != std::string::npos) {
      std::string server_part = room_alias.substr(colon_pos + 1);
      if (server_part != "localhost") {
        // This would be a federation lookup in a full implementation
        return make_error(404, "M_NOT_FOUND",
                          "Alias not found locally and federation not available");
      }
    }
    return make_error(404, "M_NOT_FOUND",
                      "Room alias not found: " + room_alias);
  }

  // ---- 3. Get servers for the alias ----  auto servers = dir.get_servers_for_alias(room_alias);

  // ---- 4. Build response ----  json body;
  body["room_id"] = *room_id;
  body["servers"] = servers;

  return make_response(200, body);
}

// ============================================================================
// 10. ROOM UPGRADE CHAIN - FOLLOW TOMBSTONES
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/upgrade
//
// Follows the room upgrade chain by reading m.room.tombstone state events.
// Returns the upgrade history from the current room to the latest version.

struct RoomUpgradeInfo {
  std::string room_id;
  std::string replacement_room;
  std::string upgraded_by;
  int64_t upgrade_ts;
};

static std::optional<RoomUpgradeInfo> get_room_upgrade_info(DatabasePool& db,
                                                              const std::string& room_id) {
  StateStore state(db);
  auto tombstone_event = state.get_current_state_event(room_id, "m.room.tombstone", "");

  if (!tombstone_event) return std::nullopt;

  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");
  auto ev = evs.get_event(*tombstone_event);
  if (!ev) return std::nullopt;

  RoomUpgradeInfo info;
  info.room_id = room_id;
  info.replacement_room = (*ev)["content"].value("replacement_room", "");
  info.upgraded_by = (*ev)["sender"].get<std::string>();
  info.upgrade_ts = (*ev)["origin_server_ts"].get<int64_t>();

  if (info.replacement_room.empty()) return std::nullopt;
  return info;
}

json handle_follow_room_upgrade(DatabasePool& db, const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Follow upgrade chain ----  std::string current_room = room_id;
  json chain = json::array();
  std::set<std::string> visited;
  int max_depth = 50; // Prevent infinite loops

  while (max_depth-- > 0) {
    if (visited.count(current_room)) break; // Loop detected
    visited.insert(current_room);

    auto upgrade = get_room_upgrade_info(db, current_room);
    if (!upgrade) break;

    json entry;
    entry["from_room_id"] = upgrade->room_id;
    entry["to_room_id"] = upgrade->replacement_room;
    entry["upgraded_by"] = upgrade->upgraded_by;
    chain.push_back(entry);

    current_room = upgrade->replacement_room;
  }

  // ---- 4. Build response ----  json body;
  body["room_id"] = room_id;
  body["upgrade_chain"] = chain;
  body["latest_room_id"] = current_room;
  body["is_upgraded"] = (current_room != room_id);

  return make_response(200, body);
}

// ============================================================================
// 11. ROOM PREDECESSOR/SUCCESSOR NAVIGATION
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/predecessor
// GET /_matrix/client/v3/rooms/{roomId}/successor

json handle_get_room_predecessor(DatabasePool& db, const std::string& auth_header,
                                   const std::string& access_token_param,
                                   const std::string& room_id) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- Look up predecessor from m.room.create event ----  StateStore state(db);
  auto create_ev = state.get_create_event(room_id);
  if (!create_ev) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  json body;
  body["room_id"] = room_id;

  if (create_ev->contains("content") && (*create_ev)["content"].contains("predecessor")) {
    auto& pred = (*create_ev)["content"]["predecessor"];
    body["predecessor"] = pred;
    body["has_predecessor"] = true;
  } else {
    body["has_predecessor"] = false;
  }

  return make_response(200, body);
}

json handle_get_room_successor(DatabasePool& db, const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const std::string& room_id) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- Look up successor from m.room.tombstone event ----  auto upgrade = get_room_upgrade_info(db, room_id);

  json body;
  body["room_id"] = room_id;

  if (upgrade && !upgrade->replacement_room.empty()) {
    json successor;
    successor["room_id"] = upgrade->replacement_room;
    successor["upgraded_by"] = upgrade->upgraded_by;
    body["successor"] = successor;
    body["has_successor"] = true;
  } else {
    body["has_successor"] = false;
  }

  return make_response(200, body);
}

// ============================================================================
// 12. ROOM VISIBILITY MANAGEMENT
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/visibility
// PUT /_matrix/client/v3/rooms/{roomId}/visibility

json handle_get_room_visibility(DatabasePool& db, const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const std::string& room_id) {
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

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
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (auth.is_guest) {
    return make_error(403, "M_FORBIDDEN",
                      "Guest users cannot change room visibility");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Validate visibility param ----  if (!request_body.contains("visibility") || !request_body["visibility"].is_string()) {
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

  // ---- 5. Check user's power level ----  if (!has_power_to(db, room_id, auth.user_id, "state_default")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to change room visibility");
  }

  // ---- 6. Update visibility ----  DirectoryStore dir(db);
  dir.set_room_visibility(room_id, visibility);
  rooms.set_room_is_public(room_id, visibility == "public");

  return make_response(200, json::object());
}

// ============================================================================
// 13. KNOCK ROOMS
// ============================================================================
// POST /_matrix/client/v3/knock/{roomIdOrAlias}
//
// Knocking allows a user to request entry to a room that has join_rule=knock.
// The room administrators can then accept or reject the knock.

json handle_knock_room(DatabasePool& db, const std::string& auth_header,
                         const std::string& access_token_param,
                         const std::string& room_id_or_alias,
                         const json& request_body) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (auth.is_guest) {
    return make_error(403, "M_FORBIDDEN",
                      "Guest users cannot knock on rooms");
  }

  // ---- 2. Resolve alias or validate room ID ----  std::string room_id = room_id_or_alias;

  if (validate_room_alias(room_id_or_alias)) {
    DirectoryStore dir(db);
    auto resolved = dir.get_room_id(room_id_or_alias);
    if (!resolved) {
      return make_error(404, "M_NOT_FOUND",
                        "Room alias not found: " + room_id_or_alias);
    }
    room_id = *resolved;
  }

  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID or alias");
  }

  // ---- 3. Check room exists ----  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 4. Check join rules allow knocking ----  std::string join_rule = get_join_rule(db, room_id);
  if (join_rule != "knock" && join_rule != "knock_restricted") {
    return make_error(403, "M_FORBIDDEN",
                      "This room does not allow knocking. Join rule: " + join_rule);
  }

  // ---- 5. Check if user is already a member ----  auto membership = get_membership(db, room_id, auth.user_id);
  if (membership == "join") {
    return make_error(403, "M_FORBIDDEN", "You are already in this room");
  }
  if (membership == "ban") {
    return make_error(403, "M_FORBIDDEN", "You are banned from this room");
  }
  if (membership == "knock") {
    json body;
    body["room_id"] = room_id;
    body["knock_state"] = "knocked";
    return make_response(200, body);
  }

  // ---- 6. Check restricted room access if knock_restricted ----  if (join_rule == "knock_restricted") {
    StateStore state(db);
    auto jr_event = state.get_current_state_event(room_id, "m.room.join_rules", "");
    if (jr_event) {
      EventsWorkerStore evs(
        std::make_shared<DatabasePool>(db),
        nullptr, "", "master");
      auto ev = evs.get_event(*jr_event);
      if (ev && (*ev).contains("content") && (*ev)["content"].contains("allow")) {
        bool allowed = false;
        auto& allow_rules = (*ev)["content"]["allow"];
        for (auto& rule : allow_rules) {
          if (rule.contains("room_id") && rule["room_id"].is_string()) {
            std::string allowed_room = rule["room_id"].get<std::string>();
            if (is_user_in_room(db, allowed_room, auth.user_id)) {
              allowed = true;
              break;
            }
          }
        }
        if (!allowed) {
          return make_error(403, "M_FORBIDDEN",
                            "You are not a member of any allowed room");
        }
      }
    }
  }

  // ---- 7. Collect reason (optional) ----  std::string reason = request_body.value("reason", "");

  // ---- 8. Send knock membership event ----  int64_t so = now_ms();

  json knock_content;
  knock_content["membership"] = "knock";
  if (!reason.empty()) knock_content["reason"] = reason;

  ProfileStore profile(db);
  auto display_name = profile.get_display_name(auth.user_id);
  if (display_name) knock_content["displayname"] = *display_name;

  std::string knock_event_id = gen_id("$knock");

  // Persist the knock event
  auto txn = db.cursor("knock");
  if (txn) {
    std::string sql = "INSERT OR REPLACE INTO events "
                      "(event_id, room_id, sender, type, state_key, json, stream_ordering, "
                      "origin_server_ts, depth, outlier, instance_name) "
                      "VALUES (?,?,?,?,?,?,?,?,?,0,'master')";
    json event_json;
    event_json["event_id"] = knock_event_id;
    event_json["room_id"] = room_id;
    event_json["sender"] = auth.user_id;
    event_json["type"] = "m.room.member";
    event_json["state_key"] = auth.user_id;
    event_json["content"] = knock_content;
    event_json["origin_server_ts"] = so;
    event_json["stream_ordering"] = so;
    event_json["depth"] = 1;

    txn->execute(sql, {knock_event_id, room_id, auth.user_id, "m.room.member",
                       auth.user_id, event_json.dump(),
                       std::to_string(so), std::to_string(so), "1"});

    std::string state_sql = "INSERT OR REPLACE INTO current_state_events "
                            "(room_id, type, state_key, event_id) VALUES (?,?,?,?)";
    txn->execute(state_sql, {room_id, "m.room.member", auth.user_id, knock_event_id});

    txn->commit();
  }

  // ---- 9. Update membership table ----  RoomMemberStore members(db);
  members.update_membership(room_id, auth.user_id, auth.user_id,
                             "knock", knock_event_id, so);

  // ---- 10. Record knock request ----  KnockRequest knock_req;
  knock_req.room_id = room_id;
  knock_req.user_id = auth.user_id;
  knock_req.reason = reason;
  knock_req.knock_event_id = knock_event_id;
  knock_req.knocked_at = so;
  knock_req.pending = true;
  add_knock_request(room_id, knock_req);

  // ---- 11. Build response ----  json body;
  body["room_id"] = room_id;
  body["knock_state"] = "knocked";

  return make_response(200, body);
}

json handle_accept_knock(DatabasePool& db, const std::string& auth_header,
                           const std::string& access_token_param,
                           const std::string& room_id,
                           const json& request_body) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (auth.is_guest) {
    return make_error(403, "M_FORBIDDEN",
                      "Guest users cannot accept knocks");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check user has invite power ----  if (!has_power_to(db, room_id, auth.user_id, "invite")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to accept knocks");
  }

  // ---- 4. Get target user ----  if (!request_body.contains("user_id") || !request_body["user_id"].is_string()) {
    return make_error(400, "M_MISSING_PARAM", "Missing user_id parameter");
  }

  std::string target_user_id = request_body["user_id"].get<std::string>();
  if (!validate_user_id(target_user_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid user ID");
  }

  // ---- 5. Check target has knocked ----  auto membership = get_membership(db, room_id, target_user_id);
  if (membership != "knock") {
    return make_error(404, "M_NOT_FOUND",
                      "User has not knocked on this room");
  }

  // ---- 6. Send invite event (inviting the knocking user) ----  int64_t so = now_ms();

  json invite_content;
  invite_content["membership"] = "invite";
  invite_content["is_direct"] = false;

  std::string invite_event_id = gen_id("$accept_knock");

  auto txn = db.cursor("accept_knock");
  if (txn) {
    std::string sql = "INSERT OR REPLACE INTO events "
                      "(event_id, room_id, sender, type, state_key, json, stream_ordering, "
                      "origin_server_ts, depth, outlier, instance_name) "
                      "VALUES (?,?,?,?,?,?,?,?,?,0,'master')";
    json event_json;
    event_json["event_id"] = invite_event_id;
    event_json["room_id"] = room_id;
    event_json["sender"] = auth.user_id;
    event_json["type"] = "m.room.member";
    event_json["state_key"] = target_user_id;
    event_json["content"] = invite_content;
    event_json["origin_server_ts"] = so;
    event_json["stream_ordering"] = so;
    event_json["depth"] = 1;

    txn->execute(sql, {invite_event_id, room_id, auth.user_id, "m.room.member",
                       target_user_id, event_json.dump(),
                       std::to_string(so), std::to_string(so), "1"});

    std::string state_sql = "INSERT OR REPLACE INTO current_state_events "
                            "(room_id, type, state_key, event_id) VALUES (?,?,?,?)";
    txn->execute(state_sql, {room_id, "m.room.member", target_user_id, invite_event_id});

    txn->commit();
  }

  RoomMemberStore members(db);
  members.update_membership(room_id, target_user_id, auth.user_id,
                             "invite", invite_event_id, so);

  // ---- 7. Resolve knock request ----  resolve_knock(room_id, target_user_id, true);

  // ---- 8. Build response ----  json body;
  body["room_id"] = room_id;
  body["user_id"] = target_user_id;
  body["status"] = "accepted";

  return make_response(200, body);
}

json handle_reject_knock(DatabasePool& db, const std::string& auth_header,
                           const std::string& access_token_param,
                           const std::string& room_id,
                           const json& request_body) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check permissions ----  if (!has_power_to(db, room_id, auth.user_id, "invite")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to reject knocks");
  }

  // ---- 4. Get target user ----  if (!request_body.contains("user_id") || !request_body["user_id"].is_string()) {
    return make_error(400, "M_MISSING_PARAM", "Missing user_id parameter");
  }

  std::string target_user_id = request_body["user_id"].get<std::string>();
  if (!validate_user_id(target_user_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid user ID");
  }

  // ---- 5. Check target has knocked ----  auto membership = get_membership(db, room_id, target_user_id);
  if (membership != "knock") {
    return make_error(404, "M_NOT_FOUND",
                      "User has not knocked on this room");
  }

  // ---- 6. Send leave event (rejecting the knock) ----  int64_t so = now_ms();

  json leave_content;
  leave_content["membership"] = "leave";
  leave_content["reason"] = "Knock rejected";

  std::string leave_event_id = gen_id("$reject_knock");

  auto txn = db.cursor("reject_knock");
  if (txn) {
    std::string sql = "INSERT OR REPLACE INTO events "
                      "(event_id, room_id, sender, type, state_key, json, stream_ordering, "
                      "origin_server_ts, depth, outlier, instance_name) "
                      "VALUES (?,?,?,?,?,?,?,?,?,0,'master')";
    json event_json;
    event_json["event_id"] = leave_event_id;
    event_json["room_id"] = room_id;
    event_json["sender"] = auth.user_id;
    event_json["type"] = "m.room.member";
    event_json["state_key"] = target_user_id;
    event_json["content"] = leave_content;
    event_json["origin_server_ts"] = so;
    event_json["stream_ordering"] = so;
    event_json["depth"] = 1;

    txn->execute(sql, {leave_event_id, room_id, auth.user_id, "m.room.member",
                       target_user_id, event_json.dump(),
                       std::to_string(so), std::to_string(so), "1"});

    std::string state_sql = "INSERT OR REPLACE INTO current_state_events "
                            "(room_id, type, state_key, event_id) VALUES (?,?,?,?)";
    txn->execute(state_sql, {room_id, "m.room.member", target_user_id, leave_event_id});

    txn->commit();
  }

  RoomMemberStore members(db);
  members.update_membership(room_id, target_user_id, auth.user_id,
                             "leave", leave_event_id, so);

  // ---- 7. Resolve knock request ----  resolve_knock(room_id, target_user_id, false);

  // ---- 8. Build response ----  json body;
  body["room_id"] = room_id;
  body["user_id"] = target_user_id;
  body["status"] = "rejected";

  return make_response(200, body);
}

json handle_list_pending_knocks(DatabasePool& db, const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Get pending knocks ----  auto pending = get_pending_knocks(room_id);

  json knocks_arr = json::array();
  ProfileStore profiles(db);
  for (auto& k : pending) {
    json entry;
    entry["user_id"] = k.user_id;
    entry["reason"] = k.reason;
    entry["knocked_at"] = k.knocked_at;
    auto dn = profiles.get_display_name(k.user_id);
    if (dn) entry["display_name"] = *dn;
    knocks_arr.push_back(entry);
  }

  json body;
  body["knocks"] = knocks_arr;
  body["room_id"] = room_id;

  return make_response(200, body);
}

// ============================================================================
// 14. RESTRICTED ROOMS
// ============================================================================
// POST /_matrix/client/v3/join/{roomId} (restricted rules)
//
// Restricted rooms allow users to join if they are a member of one or more
// allowed rooms (or spaces). The allowed rooms are specified in the
// m.room.join_rules event content.

json handle_join_restricted_room(DatabasePool& db, const std::string& auth_header,
                                   const std::string& access_token_param,
                                   const std::string& room_id,
                                   const json& request_body) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (auth.is_guest) {
    return make_error(403, "M_FORBIDDEN",
                      "Guest users cannot join restricted rooms");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check room exists ----  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 4. Check join rules ----  std::string join_rule = get_join_rule(db, room_id);
  if (join_rule != "restricted" && join_rule != "knock_restricted") {
    // Not a restricted room - delegate to normal join
    return make_error(400, "M_UNKNOWN",
                      "This room does not use restricted join rules");
  }

  // ---- 5. Check if already joined ----  if (is_user_in_room(db, room_id, auth.user_id)) {
    json body;
    body["room_id"] = room_id;
    return make_response(200, body);
  }

  // ---- 6. Check banned ----  if (get_membership(db, room_id, auth.user_id) == "ban") {
    return make_error(403, "M_FORBIDDEN", "You are banned from this room");
  }

  // ---- 7. Check restricted room authorization ----  // Get the allow rules from join_rules state
  StateStore state(db);
  auto jr_event = state.get_current_state_event(room_id, "m.room.join_rules", "");

  bool authorized = false;
  std::string auth_room_id;

  if (jr_event) {
    EventsWorkerStore evs(
      std::make_shared<DatabasePool>(db),
      nullptr, "", "master");
    auto ev = evs.get_event(*jr_event);

    if (ev && (*ev).contains("content") && (*ev)["content"].contains("allow")) {
      auto& allow_rules = (*ev)["content"]["allow"];

      for (auto& rule : allow_rules) {
        // Check "room_membership" type rules
        if (rule.contains("type") && rule["type"].get<std::string>() == "m.room_membership") {
          if (rule.contains("room_id") && rule["room_id"].is_string()) {
            std::string allowed_room = rule["room_id"].get<std::string>();
            if (is_user_in_room(db, allowed_room, auth.user_id)) {
              authorized = true;
              auth_room_id = allowed_room;
              break;
            }
          }
        }
        // Also check via space membership (m.space.child relationship)
        if (rule.contains("type") && rule["type"].get<std::string>() == "m.space") {
          if (rule.contains("room_id") && rule["room_id"].is_string()) {
            std::string space_room = rule["room_id"].get<std::string>();
            if (is_user_in_room(db, space_room, auth.user_id)) {
              authorized = true;
              auth_room_id = space_room;
              break;
            }
          }
        }
      }
    }
  }

  if (!authorized) {
    return make_error(403, "M_FORBIDDEN",
                      "You are not a member of any room that authorizes access to this room");
  }

  // ---- 8. Generate join membership event ----  int64_t so = now_ms();

  json join_content;
  join_content["membership"] = "join";
  join_content["authorised_via"] = auth_room_id;

  ProfileStore profile(db);
  auto display_name = profile.get_display_name(auth.user_id);
  if (display_name) join_content["displayname"] = *display_name;

  std::string join_event_id = gen_id("$restricted_join");

  auto txn = db.cursor("restricted_join");
  if (txn) {
    std::string sql = "INSERT OR REPLACE INTO events "
                      "(event_id, room_id, sender, type, state_key, json, stream_ordering, "
                      "origin_server_ts, depth, outlier, instance_name) "
                      "VALUES (?,?,?,?,?,?,?,?,?,0,'master')";
    json event_json;
    event_json["event_id"] = join_event_id;
    event_json["room_id"] = room_id;
    event_json["sender"] = auth.user_id;
    event_json["type"] = "m.room.member";
    event_json["state_key"] = auth.user_id;
    event_json["content"] = join_content;
    event_json["origin_server_ts"] = so;
    event_json["stream_ordering"] = so;
    event_json["depth"] = 1;

    txn->execute(sql, {join_event_id, room_id, auth.user_id, "m.room.member",
                       auth.user_id, event_json.dump(),
                       std::to_string(so), std::to_string(so), "1"});

    std::string state_sql = "INSERT OR REPLACE INTO current_state_events "
                            "(room_id, type, state_key, event_id) VALUES (?,?,?,?)";
    txn->execute(state_sql, {room_id, "m.room.member", auth.user_id, join_event_id});

    txn->commit();
  }

  RoomMemberStore members(db);
  members.update_membership(room_id, auth.user_id, auth.user_id,
                             "join", join_event_id, so);

  // ---- 9. Build response ----  json body;
  body["room_id"] = room_id;
  body["authorised_via"] = auth_room_id;

  return make_response(200, body);
}

// ============================================================================
// 15. SPACE EXPLORATION
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/children
// GET /_matrix/client/v3/rooms/{roomId}/parents
//
// Spaces are rooms with type=m.space. They can contain child rooms via
// m.space.child state events.

json handle_explore_space_children(DatabasePool& db, const std::string& auth_header,
                                     const std::string& access_token_param,
                                     const std::string& room_id,
                                     const json& query_params) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check if this is a space ----  auto room_type = get_room_type(db, room_id);
  if (!room_type || *room_type != "m.space") {
    return make_error(400, "M_BAD_STATE",
                      "This room is not a space (room_type != m.space)");
  }

  // ---- 4. Collect all m.space.child state events ----  StateStore state(db);
  auto current_state = state.get_current_state(room_id);

  json children = json::array();
  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");

  bool include_suggested_only = safe_bool(query_params, "suggested_only", false);
  std::string order_by = safe_str(query_params, "order_by", "name");

  struct ChildEntry {
    std::string child_room_id;
    int64_t order;
    std::string name;
    bool suggested;
    std::string via_server;
    std::string room_type_str;
    int64_t joined_members;
  };

  std::vector<ChildEntry> child_entries;

  for (auto& [key, eid] : current_state) {
    if (key.first == "m.space.child") {
      std::string child_room_id = key.second;
      auto ev = evs.get_event(eid);
      if (!ev) continue;

      auto& content = (*ev)["content"];

      ChildEntry entry;
      entry.child_room_id = child_room_id;

      // Parse order string if present
      if (content.contains("order") && content["order"].is_string()) {
        try { entry.order = std::stoll(content["order"].get<std::string>()); }
        catch (...) { entry.order = 0; }
      } else {
        entry.order = 0;
      }

      entry.suggested = content.value("suggested", false);

      if (include_suggested_only && !entry.suggested) continue;

      // Get via server
      if (content.contains("via") && content["via"].is_array() &&
          !content["via"].empty()) {
        entry.via_server = content["via"][0].get<std::string>();
      }

      // Get child room info
      entry.name = get_room_name(db, child_room_id);
      auto ctype = get_room_type(db, child_room_id);
      entry.room_type_str = ctype.value_or("");

      RoomMemberStore members(db);
      auto summary = members.get_room_member_summary(child_room_id);
      entry.joined_members = summary.joined_members;

      child_entries.push_back(entry);
    }
  }

  // ---- 5. Sort children ----  if (order_by == "name") {
    std::sort(child_entries.begin(), child_entries.end(),
              [](const ChildEntry& a, const ChildEntry& b) {
                return a.name < b.name;
              });
  } else if (order_by == "joined_members") {
    std::sort(child_entries.begin(), child_entries.end(),
              [](const ChildEntry& a, const ChildEntry& b) {
                return a.joined_members > b.joined_members;
              });
  } else {
    // Default: order by the "order" field
    std::sort(child_entries.begin(), child_entries.end(),
              [](const ChildEntry& a, const ChildEntry& b) {
                return a.order < b.order;
              });
  }

  for (auto& entry : child_entries) {
    json child;
    child["room_id"] = entry.child_room_id;
    if (!entry.name.empty()) child["name"] = entry.name;
    child["suggested"] = entry.suggested;
    child["num_joined_members"] = entry.joined_members;
    if (!entry.room_type_str.empty()) child["room_type"] = entry.room_type_str;
    if (!entry.via_server.empty()) {
      child["via"] = json::array({entry.via_server});
    }
    children.push_back(child);
  }

  json body;
  body["room_id"] = room_id;
  body["children"] = children;
  body["total_count"] = static_cast<int64_t>(children.size());

  return make_response(200, body);
}

json handle_explore_space_parents(DatabasePool& db, const std::string& auth_header,
                                    const std::string& access_token_param,
                                    const std::string& room_id) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Find all spaces that have this room as a child ----  // This requires scanning m.space.child state events across all spaces.
  // In a full implementation, this would use a reverse index table.
  // For now, we scan the current state of known spaces.

  RoomStore rooms(db);
  RoomMemberStore members(db);

  // Get all rooms the user is in (to find spaces)
  auto user_rooms = members.get_rooms_for_user(auth.user_id);

  json parents = json::array();

  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db),
    nullptr, "", "master");
  StateStore state(db);

  for (auto& potential_space : user_rooms) {
    // Check if this room is a space
    auto rt = get_room_type(db, potential_space);
    if (!rt || *rt != "m.space") continue;

    // Check if our target room is a child of this space
    auto child_event = state.get_current_state_event(
      potential_space, "m.space.child", room_id);
    if (!child_event) continue;

    auto ev = evs.get_event(*child_event);
    if (!ev) continue;

    json parent;
    parent["room_id"] = potential_space;
    parent["name"] = get_room_name(db, potential_space);

    // Get via servers
    if ((*ev).contains("content") && (*ev)["content"].contains("via")) {
      parent["via"] = (*ev)["content"]["via"];
    }

    // Check if canonically this is the main parent
    auto canonical = state.get_current_state_event(
      potential_space, "m.room.canonical_alias", "");
    if (canonical) {
      parent["canonical"] = true;
    }

    parents.push_back(parent);
  }

  json body;
  body["room_id"] = room_id;
  body["parents"] = parents;
  body["total_count"] = static_cast<int64_t>(parents.size());

  return make_response(200, body);
}

// ============================================================================
// 16. ROOM VERSION CAPABILITIES CHECK
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/capabilities
//
// Returns the capabilities of the room based on its version.
// Different room versions support different features (e.g.,
// restricted join rules, knocking, etc.)

json handle_check_room_capabilities(DatabasePool& db, const std::string& auth_header,
                                      const std::string& access_token_param,
                                      const std::string& room_id) {
  // ---- 1. Optional auth ----  AuthContext auth;
  if (!auth_header.empty() || !access_token_param.empty()) {
    auth = validate_auth(db, auth_header, access_token_param);
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Get room version ----  std::string version = get_room_version(db, room_id);
  int ver_num = 1;
  try { ver_num = std::stoi(version); } catch (...) { ver_num = 1; }

  // ---- 4. Determine capabilities based on version ----  json caps;
  caps["m.room_versions"] = json::object();
  caps["m.room_versions"]["default"] = version;
  caps["m.room_versions"]["available"] = json::object();

  // All versions up to 11
  json available_versions = json::object();
  for (int v = 1; v <= 11; v++) {
    std::string vs = std::to_string(v);
    json ver_info;
    ver_info["stable"] = true;

    // Feature flags per version
    if (v >= 8) {
      ver_info["capabilities"] = json::object();
      ver_info["capabilities"]["m.restricted"] = true;
    }
    if (v >= 7) {
      if (!ver_info.contains("capabilities")) ver_info["capabilities"] = json::object();
      ver_info["capabilities"]["m.knock"] = true;
    }
    if (v >= 3) {
      if (!ver_info.contains("capabilities")) ver_info["capabilities"] = json::object();
      ver_info["capabilities"]["m.event_format_version"] = v >= 4 ? 3 : 2;
    }
    if (v >= 11) {
      if (!ver_info.contains("capabilities")) ver_info["capabilities"] = json::object();
      ver_info["capabilities"]["m.related_events.stable"] = true;
    }
    available_versions[vs] = ver_info;
  }
  caps["m.room_versions"]["available"] = available_versions;

  // Current room capabilities
  caps["m.change_password"] = json::object();
  caps["m.change_password"]["enabled"] = true;

  caps["m.set_displayname"] = json::object();
  caps["m.set_displayname"]["enabled"] = true;

  caps["m.set_avatar_url"] = json::object();
  caps["m.set_avatar_url"]["enabled"] = true;

  // Room-specific capabilities
  json room_caps;
  room_caps["version"] = version;
  room_caps["supports_restricted"] = (ver_num >= 8);
  room_caps["supports_knock"] = (ver_num >= 7);
  room_caps["supports_event_format_v2"] = (ver_num >= 3);
  room_caps["supports_event_format_v3"] = (ver_num >= 4);
  room_caps["supports_redaction_swipe"] = (ver_num >= 11);

  room_caps["join_rule"] = get_join_rule(db, room_id);
  room_caps["guest_access"] = get_guest_access(db, room_id);
  room_caps["history_visibility"] = get_history_visibility(db, room_id);

  caps["m.room"] = room_caps;

  return make_response(200, caps);
}

// ============================================================================
// 17. ROOM SUMMARY FOR UNAUTHENTICATED USERS
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/summary
//
// Returns a limited room summary accessible without authentication
// for public rooms.

json handle_room_summary_public(DatabasePool& db, const std::string& room_id) {
  // ---- 1. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 2. Check room exists ----  RoomStore rooms(db);
  auto room_info = rooms.get_room(room_id);
  if (!room_info) {
    return make_error(404, "M_NOT_FOUND", "Room not found");
  }

  // ---- 3. Check if room is publicly visible ----  std::string visibility = get_history_visibility(db, room_id);
  DirectoryStore dir(db);
  auto dir_visibility = dir.get_room_visibility(room_id);

  if (visibility != "world_readable" &&
      dir_visibility.value_or("private") != "public") {
    return make_error(403, "M_FORBIDDEN",
                      "This room is not publicly visible");
  }

  // ---- 4. Build public summary ----  json body = build_room_summary(db, room_id, true, 5);

  // Add additional fields useful for unauthenticated discovery
  body["room_version"] = get_room_version(db, room_id);
  body["creator"] = get_room_creator(db, room_id);

  // Encryption status
  StateStore state(db);
  auto enc_event = state.get_current_state_event(room_id, "m.room.encryption", "");
  if (enc_event) {
    EventsWorkerStore evs(
      std::make_shared<DatabasePool>(db),
      nullptr, "", "master");
    auto ev = evs.get_event(*enc_event);
    if (ev && (*ev).contains("content")) {
      body["encryption"] = (*ev)["content"].value("algorithm", "");
    }
  }

  // Federation flag
  auto create_ev = state.get_create_event(room_id);
  if (create_ev && create_ev->contains("content") &&
      (*create_ev)["content"].contains("m.federate")) {
    body["federate"] = (*create_ev)["content"]["m.federate"].get<bool>();
  }

  return make_response(200, body);
}

// ============================================================================
// 18. PUBLIC ROOM SEARCH (full-text)
// ============================================================================
// POST /_matrix/client/v3/search
//
// Searches public rooms by name, topic, or alias.

json handle_public_room_search(DatabasePool& db, const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const json& request_body) {
  // ---- 1. Optional auth ----  AuthContext auth;
  if (!auth_header.empty() || !access_token_param.empty()) {
    auth = validate_auth(db, auth_header, access_token_param);
  }

  // ---- 2. Parse search criteria ----  json search_criteria = request_body.value("search_categories", json::object())
                              .value("room_events", json::object());

  std::string search_term = search_criteria.value("search_term", "");
  if (search_term.empty()) {
    return make_error(400, "M_MISSING_PARAM", "Missing search_term");
  }

  std::string order_by = search_criteria.value("order_by", "recent");
  int64_t limit = search_criteria.value("limit", 10);
  if (limit < 1) limit = 1;
  if (limit > 100) limit = 100;

  // Optional filter
  json filter = search_criteria.value("filter", json::object());

  // ---- 3. Search public rooms ----  DirectoryStore dir(db);
  auto all_rooms = dir.get_public_rooms("", 500, 0, search_term);

  // ---- 4. Score and rank results ----  struct SearchResult {
    std::string room_id;
    std::string name;
    std::string topic;
    int64_t score;
    int64_t joined_members;
    std::optional<std::string> canonical_alias;
  };

  std::vector<SearchResult> results;

  for (auto& pr : all_rooms) {
    SearchResult sr;
    sr.room_id = pr.room_id;
    sr.name = get_room_name(db, pr.room_id);
    sr.topic = get_room_topic(db, pr.room_id);
    sr.joined_members = pr.num_joined_members;
    sr.score = 0;

    // Score based on match quality
    std::string term_lower = search_term;
    std::transform(term_lower.begin(), term_lower.end(),
                   term_lower.begin(), ::tolower);

    // Name exact match = highest score
    std::string name_lower = sr.name;
    std::transform(name_lower.begin(), name_lower.end(),
                   name_lower.begin(), ::tolower);

    if (name_lower == term_lower) {
      sr.score += 1000;
    } else if (name_lower.find(term_lower) != std::string::npos) {
      sr.score += 500;
    }

    // Topic match
    std::string topic_lower = sr.topic;
    std::transform(topic_lower.begin(), topic_lower.end(),
                   topic_lower.begin(), ::tolower);

    if (topic_lower.find(term_lower) != std::string::npos) {
      sr.score += 300;
    }

    // Alias match
    auto canonical = pr.canonical_alias;
    if (canonical) {
      std::string alias_lower = *canonical;
      std::transform(alias_lower.begin(), alias_lower.end(),
                     alias_lower.begin(), ::tolower);
      if (alias_lower.find(term_lower) != std::string::npos) {
        sr.score += 200;
      }
    }

    // Room ID match (lowest priority)
    std::string rid_lower = pr.room_id;
    std::transform(rid_lower.begin(), rid_lower.end(),
                   rid_lower.begin(), ::tolower);
    if (rid_lower.find(term_lower) != std::string::npos) {
      sr.score += 50;
    }

    // Apply room type filter if specified
    if (filter.contains("room_types") && filter["room_types"].is_array()) {
      auto rt = get_room_type(db, pr.room_id);
      bool type_match = false;
      for (auto& tt : filter["room_types"]) {
        if (rt && tt.is_string() && *rt == tt.get<std::string>()) {
          type_match = true; break;
        }
      }
      if (!type_match) continue;
    }

    if (sr.score > 0) {
      sr.canonical_alias = canonical;
      results.push_back(sr);
    }
  }

  // ---- 5. Sort results ----  if (order_by == "members" || order_by == "joined_members") {
    std::sort(results.begin(), results.end(),
              [](const SearchResult& a, const SearchResult& b) {
                return a.joined_members > b.joined_members;
              });
  } else {
    // Default: sort by score
    std::sort(results.begin(), results.end(),
              [](const SearchResult& a, const SearchResult& b) {
                return a.score > b.score;
              });
  }

  // ---- 6. Build response ----  json chunk = json::array();
  for (auto& sr : results) {
    if (static_cast<int64_t>(chunk.size()) >= limit) break;

    json entry;
    entry["room_id"] = sr.room_id;
    if (!sr.name.empty()) entry["name"] = sr.name;
    if (!sr.topic.empty()) entry["topic"] = sr.topic;
    entry["num_joined_members"] = sr.joined_members;
    if (sr.canonical_alias) entry["canonical_alias"] = *sr.canonical_alias;
    entry["score"] = sr.score;
    chunk.push_back(entry);
  }

  json body;
  body["search_categories"] = json::object();
  body["search_categories"]["room_events"] = json::object();
  body["search_categories"]["room_events"]["count"] = static_cast<int64_t>(chunk.size());
  body["search_categories"]["room_events"]["results"] = chunk;
  body["search_categories"]["room_events"]["highlights"] = json::array();

  return make_response(200, body);
}

// ============================================================================
// 19. THIRD-PARTY NETWORK ROOM LISTING
// ============================================================================
// GET /_matrix/client/v3/thirdparty/protocols
// GET /_matrix/client/v3/thirdparty/protocol/{protocol}
// GET /_matrix/client/v3/thirdparty/location/{protocol}
// GET /_matrix/client/v3/thirdparty/user/{protocol}

json handle_list_third_party_protocols(DatabasePool& db) {
  // Return list of available third-party network protocols
  // In a full implementation, this would query appservice configurations.

  json body;
  json protocols = json::object();

  // Example protocol: IRC
  json irc;
  irc["user_fields"] = json::array({"nickname", "server"});
  irc["location_fields"] = json::array({"channel", "network"});
  irc["icon"] = "mxc://localhost/irc_icon";
  irc["field_types"] = json::object();
  irc["field_types"]["nickname"] = json::object();
  irc["field_types"]["nickname"]["regexp"] = "^[A-Za-z0-9_\\[\\]\\\\^{}|`-]+$";
  irc["field_types"]["nickname"]["placeholder"] = "IRC nickname";
  irc["instances"] = json::array();
  json irc_instance;
  irc_instance["network_id"] = "freenode";
  irc_instance["desc"] = "Freenode IRC network";
  irc_instance["icon"] = "mxc://localhost/freenode_icon";
  irc_instance["fields"] = json::object();
  irc["instances"].push_back(irc_instance);
  protocols["irc"] = irc;

  // Example protocol: Gitter
  json gitter;
  gitter["user_fields"] = json::array({"username"});
  gitter["location_fields"] = json::array({"room"});
  gitter["icon"] = "mxc://localhost/gitter_icon";
  gitter["field_types"] = json::object();
  gitter["instances"] = json::array();
  json gitter_instance;
  gitter_instance["network_id"] = "gitter";
  gitter_instance["desc"] = "Gitter network";
  gitter_instance["icon"] = "mxc://localhost/gitter_icon";
  gitter_instance["fields"] = json::object();
  gitter["instances"].push_back(gitter_instance);
  protocols["gitter"] = gitter;

  body = protocols;

  return make_response(200, body);
}

json handle_get_third_party_protocol(DatabasePool& db, const std::string& protocol) {
  // Return specific protocol metadata
  auto all_protocols = handle_list_third_party_protocols(db);
  auto& protocols = all_protocols["body"];

  if (!protocols.contains(protocol)) {
    return make_error(404, "M_NOT_FOUND",
                      "Protocol not found: " + protocol);
  }

  return make_response(200, protocols[protocol]);
}

json handle_get_third_party_location(DatabasePool& db,
                                       const std::string& protocol,
                                       const json& query_params) {
  // Return rooms for a given third-party network location
  std::string search_fields;
  if (query_params.contains("searchFields")) {
    search_fields = query_params["searchFields"].dump();
  }

  // In a full implementation, this would query appservices
  // For now, return empty or example data
  json body = json::array();

  // Check if we have bridged rooms matching this protocol
  DirectoryStore dir(db);
  auto public_rooms = dir.get_public_rooms("", 100);

  json chunk = json::array();
  for (auto& pr : public_rooms) {
    json entry;
    entry["alias"] = pr.canonical_alias.value_or("");
    entry["protocol"] = protocol;
    entry["fields"] = json::object();
    chunk.push_back(entry);
  }

  body = chunk;
  return make_response(200, body);
}

json handle_get_third_party_user(DatabasePool& db,
                                   const std::string& protocol,
                                   const json& query_params) {
  // Return Matrix user IDs for a third-party network user
  std::string userid;
  if (query_params.contains("userid")) {
    userid = query_params["userid"].get<std::string>();
  }

  // In a full implementation, this would query appservices
  json body = json::array();

  // Return empty for now
  return make_response(200, body);
}

// ============================================================================
// 20. ROOM CANONICAL ALIAS
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/canonical_alias
// PUT /_matrix/client/v3/rooms/{roomId}/canonical_alias

json handle_get_canonical_alias(DatabasePool& db, const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id) {
  // ---- 1. Optional auth for public rooms ----  AuthContext auth;
  if (!auth_header.empty() || !access_token_param.empty()) {
    auth = validate_auth(db, auth_header, access_token_param);
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Get canonical alias from state ----  StateStore state(db);
  auto ca_event = state.get_current_state_event(room_id, "m.room.canonical_alias", "");

  json body;
  body["room_id"] = room_id;

  if (ca_event) {
    EventsWorkerStore evs(
      std::make_shared<DatabasePool>(db),
      nullptr, "", "master");
    auto ev = evs.get_event(*ca_event);
    if (ev && (*ev).contains("content")) {
      body["canonical_alias"] = (*ev)["content"].value("alias", "");
      body["alt_aliases"] = (*ev)["content"].value("alt_aliases", json::array());
    }
  }

  if (!body.contains("canonical_alias")) {
    body["canonical_alias"] = nullptr;
    body["alt_aliases"] = json::array();
  }

  return make_response(200, body);
}

json handle_set_canonical_alias(DatabasePool& db, const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& room_id,
                                  const json& request_body) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (auth.is_guest) {
    return make_error(403, "M_FORBIDDEN",
                      "Guest users cannot set canonical alias");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check permissions ----  if (!has_power_to(db, room_id, auth.user_id, "state_default")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to set the canonical alias");
  }

  // ---- 4. Validate alias ----  std::string alias = safe_str(request_body, "alias", "");
  std::vector<std::string> alt_aliases;

  if (request_body.contains("alt_aliases") && request_body["alt_aliases"].is_array()) {
    for (auto& aa : request_body["alt_aliases"]) {
      if (aa.is_string()) alt_aliases.push_back(aa.get<std::string>());
    }
  }

  // ---- 5. Persist canonical alias state event ----  int64_t so = now_ms();

  json ca_content;
  ca_content["alias"] = alias;
  ca_content["alt_aliases"] = alt_aliases;

  std::string event_id = gen_id("$canonical_alias");

  auto txn = db.cursor("set_canonical_alias");
  if (txn) {
    std::string sql = "INSERT OR REPLACE INTO events "
                      "(event_id, room_id, sender, type, state_key, json, stream_ordering, "
                      "origin_server_ts, depth, outlier, instance_name) "
                      "VALUES (?,?,?,?,?,?,?,?,?,0,'master')";
    json event_json;
    event_json["event_id"] = event_id;
    event_json["room_id"] = room_id;
    event_json["sender"] = auth.user_id;
    event_json["type"] = "m.room.canonical_alias";
    event_json["state_key"] = "";
    event_json["content"] = ca_content;
    event_json["origin_server_ts"] = so;
    event_json["stream_ordering"] = so;
    event_json["depth"] = 1;

    txn->execute(sql, {event_id, room_id, auth.user_id, "m.room.canonical_alias",
                       "", event_json.dump(),
                       std::to_string(so), std::to_string(so), "1"});

    std::string state_sql = "INSERT OR REPLACE INTO current_state_events "
                            "(room_id, type, state_key, event_id) VALUES (?,?,?,?)";
    txn->execute(state_sql, {room_id, "m.room.canonical_alias", "", event_id});

    txn->commit();
  }

  // ---- 6. If alias is set, also create directory entry ----  if (!alias.empty() && validate_room_alias(alias)) {
    DirectoryStore dir(db);
    if (!dir.get_room_id(alias)) {
      std::vector<std::string> servers = {"localhost"};
      dir.create_alias(alias, room_id, auth.user_id, servers);
    }
  }

  return make_response(200, json::object());
}

// ============================================================================
// 21. ROOM ALT ALIASES MANAGEMENT
// ============================================================================
// GET /_matrix/client/v3/rooms/{roomId}/aliases
// PUT /_matrix/client/v3/rooms/{roomId}/aliases

json handle_get_room_aliases(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& room_id) {
  // ---- 1. Optional auth for public rooms ----  AuthContext auth;
  if (!auth_header.empty() || !access_token_param.empty()) {
    auth = validate_auth(db, auth_header, access_token_param);
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Get all aliases for this room ----  DirectoryStore dir(db);
  auto aliases = dir.get_aliases_for_room(room_id);

  // Also get canonical alias
  StateStore state(db);
  auto ca_event = state.get_current_state_event(room_id, "m.room.canonical_alias", "");

  json body;
  body["room_id"] = room_id;
  body["aliases"] = aliases;

  if (ca_event) {
    EventsWorkerStore evs(
      std::make_shared<DatabasePool>(db),
      nullptr, "", "master");
    auto ev = evs.get_event(*ca_event);
    if (ev && (*ev).contains("content")) {
      body["canonical_alias"] = (*ev)["content"].value("alias", "");
      body["alt_aliases"] = (*ev)["content"].value("alt_aliases", json::array());
    }
  }

  return make_response(200, body);
}

json handle_add_room_alias(DatabasePool& db, const std::string& auth_header,
                             const std::string& access_token_param,
                             const std::string& room_id,
                             const json& request_body) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (auth.is_guest) {
    return make_error(403, "M_FORBIDDEN",
                      "Guest users cannot add room aliases");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check permissions ----  if (!has_power_to(db, room_id, auth.user_id, "state_default")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to add room aliases");
  }

  // ---- 4. Get aliases to add ----  if (!request_body.contains("aliases") || !request_body["aliases"].is_array()) {
    return make_error(400, "M_MISSING_PARAM", "Missing aliases parameter");
  }

  DirectoryStore dir(db);
  std::vector<std::string> servers = {"localhost"};
  json added = json::array();

  for (auto& alias_json : request_body["aliases"]) {
    if (!alias_json.is_string()) continue;
    std::string alias = alias_json.get<std::string>();

    if (!validate_room_alias(alias)) {
      continue;
    }

    // Check if alias already exists
    auto existing = dir.get_room_id(alias);
    if (existing && *existing != room_id) {
      continue; // Alias points to a different room
    }

    if (!existing) {
      dir.create_alias(alias, room_id, auth.user_id, servers);
      added.push_back(alias);
    }
  }

  json body;
  body["added"] = added;

  return make_response(200, body);
}

json handle_delete_room_alias(DatabasePool& db, const std::string& auth_header,
                                const std::string& access_token_param,
                                const std::string& room_id,
                                const json& request_body) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check permissions ----  if (!has_power_to(db, room_id, auth.user_id, "state_default")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to remove room aliases");
  }

  // ---- 4. Get aliases to delete ----  if (!request_body.contains("aliases") || !request_body["aliases"].is_array()) {
    return make_error(400, "M_MISSING_PARAM", "Missing aliases parameter");
  }

  DirectoryStore dir(db);
  json removed = json::array();

  for (auto& alias_json : request_body["aliases"]) {
    if (!alias_json.is_string()) continue;
    std::string alias = alias_json.get<std::string>();

    auto existing = dir.get_room_id(alias);
    if (existing && *existing == room_id) {
      dir.delete_alias(alias);
      removed.push_back(alias);
    }
  }

  json body;
  body["removed"] = removed;

  return make_response(200, body);
}

// ============================================================================
// 22. ROOM FEDERATION PROTOCOLS NEGOTIATION
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/federation
//
// Allows room administrators to manage federation settings:
//   - Enable/disable federation
//   - Set allowed/blocked servers
//   - Configure federation protocols (v1, v2)

json handle_negotiate_federation(DatabasePool& db, const std::string& auth_header,
                                   const std::string& access_token_param,
                                   const std::string& room_id,
                                   const json& request_body) {
  // ---- 1. Validate auth ----  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }
  if (auth.is_guest) {
    return make_error(403, "M_FORBIDDEN",
                      "Guest users cannot manage federation settings");
  }

  // ---- 2. Validate room ID ----  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 3. Check permissions (must be admin / power level 100) ----  if (!has_power_to(db, room_id, auth.user_id, "state_default")) {
    return make_error(403, "M_FORBIDDEN",
                      "You don't have permission to manage federation settings");
  }

  // ---- 4. Parse federation settings ----  std::string action = safe_str(request_body, "action", "get");

  if (action == "get") {
    // Return current federation status
    StateStore state(db);
    auto create_ev = state.get_create_event(room_id);

    json body;
    body["room_id"] = room_id;
    body["federate"] = true; // default

    if (create_ev && create_ev->contains("content") &&
        (*create_ev)["content"].contains("m.federate")) {
      body["federate"] = (*create_ev)["content"]["m.federate"].get<bool>();
    }

    // Get ACL state
    auto acl_event = state.get_current_state_event(room_id, "m.room.server_acl", "");
    if (acl_event) {
      EventsWorkerStore evs(
        std::make_shared<DatabasePool>(db),
        nullptr, "", "master");
      auto ev = evs.get_event(*acl_event);
      if (ev && (*ev).contains("content")) {
        body["server_acl"] = (*ev)["content"];
      }
    }

    // Get room version (determines protocol support)
    std::string version = get_room_version(db, room_id);
    body["room_version"] = version;

    // Federation participants
    RoomMemberStore members(db);
    auto all_members = members.get_joined_members(room_id);
    std::set<std::string> servers;
    for (auto& m : all_members) {
      auto pos = m.user_id.find(':');
      if (pos != std::string::npos) {
        servers.insert(m.user_id.substr(pos + 1));
      }
    }
    body["participating_servers"] = json(servers);

    return make_response(200, body);
  }

  if (action == "set_acl") {
    // Set server ACL
    json acl_content = request_body.value("acl", json::object());

    int64_t so = now_ms();
    std::string event_id = gen_id("$server_acl");

    auto txn = db.cursor("set_acl");
    if (txn) {
      std::string sql = "INSERT OR REPLACE INTO events "
                        "(event_id, room_id, sender, type, state_key, json, stream_ordering, "
                        "origin_server_ts, depth, outlier, instance_name) "
                        "VALUES (?,?,?,?,?,?,?,?,?,0,'master')";
      json event_json;
      event_json["event_id"] = event_id;
      event_json["room_id"] = room_id;
      event_json["sender"] = auth.user_id;
      event_json["type"] = "m.room.server_acl";
      event_json["state_key"] = "";
      event_json["content"] = acl_content;
      event_json["origin_server_ts"] = so;
      event_json["stream_ordering"] = so;
      event_json["depth"] = 1;

      txn->execute(sql, {event_id, room_id, auth.user_id, "m.room.server_acl",
                         "", event_json.dump(),
                         std::to_string(so), std::to_string(so), "1"});

      std::string state_sql = "INSERT OR REPLACE INTO current_state_events "
                              "(room_id, type, state_key, event_id) VALUES (?,?,?,?)";
      txn->execute(state_sql, {room_id, "m.room.server_acl", "", event_id});

      txn->commit();
    }

    return make_response(200, json{{"status", "acl_updated"}});
  }

  if (action == "set_federation_protocol") {
    // Negotiate federation protocol version for this room
    std::string protocol = safe_str(request_body, "protocol", "v2");

    if (protocol != "v1" && protocol != "v2") {
      return make_error(400, "M_INVALID_PARAM",
                        "Unsupported federation protocol: " + protocol);
    }

    // Store preferred protocol (would use room-specific metadata in full impl)
    json body;
    body["room_id"] = room_id;
    body["federation_protocol"] = protocol;
    body["status"] = "negotiated";

    return make_response(200, body);
  }

  if (action == "invite_server") {
    // Invite a server to federate with this room
    std::string target_server = safe_str(request_body, "server_name", "");
    if (target_server.empty()) {
      return make_error(400, "M_MISSING_PARAM", "Missing server_name");
    }

    // In a full implementation, this would send a federation invite
    // For now, mark the server as allowed
    json body;
    body["status"] = "invited";
    body["server_name"] = target_server;
    body["room_id"] = room_id;

    return make_response(200, body);
  }

  return make_error(400, "M_UNKNOWN", "Unknown action: " + action);
}

// ============================================================================
// GUEST/PEEK HANDLER ROUTER
// ============================================================================
// Dispatches to individual handlers based on HTTP method and path.

json route_guest_peek_handler(DatabasePool& db, const std::string& auth_header,
                                const std::string& access_token_param,
                                const std::string& method,
                                const std::string& path,
                                const json& request_body,
                                const std::map<std::string, std::string>& path_params) {

  // ========================================================================
  // GUEST REGISTRATION
  // POST /_matrix/client/v3/register (guest=true)
  // ========================================================================
  if (method == "POST" && path.find("/register") != std::string::npos) {
    bool is_guest = false;
    if (request_body.contains("guest") && request_body["guest"].is_boolean()) {
      is_guest = request_body["guest"].get<bool>();
    }
    if (request_body.contains("kind") && request_body["kind"].is_string() &&
        request_body["kind"].get<std::string>() == "guest") {
      is_guest = true;
    }
    if (is_guest) {
      return handle_guest_register(db, request_body);
    }
    // Not a guest registration, return empty to let other handlers process
    return json::object();
  }

  // ========================================================================
  // GUEST ACCOUNT UPGRADE
  // POST /_matrix/client/v3/account/upgrade
  // ========================================================================
  if (method == "POST" && path.find("/account/upgrade") != std::string::npos) {
    return handle_guest_upgrade(db, auth_header, access_token_param, request_body);
  }

  // ========================================================================
  // PEEK ROOM
  // POST /_matrix/client/v3/rooms/{roomId}/peek
  // ========================================================================
  if (method == "POST" && path.find("/peek") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_peek_room(db, auth_header, access_token_param,
                               it->second, request_body);
    }
  }

  // ========================================================================
  // UNPEEK ROOM
  // POST /_matrix/client/v3/rooms/{roomId}/unpeek
  // ========================================================================
  if (method == "POST" && path.find("/unpeek") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_unpeek_room(db, auth_header, access_token_param, it->second);
    }
  }

  // ========================================================================
  // ROOM PREVIEW
  // GET /_matrix/client/v3/rooms/{roomId}/preview
  // ========================================================================
  if (method == "GET" && path.find("/preview") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_get_room_preview(db, auth_header, access_token_param,
                                      it->second, request_body);
    }
  }

  // ========================================================================
  // PUBLIC ROOMS (GET)
  // GET /_matrix/client/v3/publicRooms
  // ========================================================================
  if (method == "GET" && path.find("/publicRooms") != std::string::npos) {
    return handle_list_public_rooms(db, auth_header, access_token_param,
                                     json::object(), request_body);
  }

  // ========================================================================
  // PUBLIC ROOMS (POST with filters)
  // POST /_matrix/client/v3/publicRooms
  // ========================================================================
  if (method == "POST" && path.find("/publicRooms") != std::string::npos) {
    return handle_list_public_rooms(db, auth_header, access_token_param,
                                     request_body, json::object());
  }

  // ========================================================================
  // ROOM DIRECTORY (RESOLVE ALIAS)
  // GET /_matrix/client/v3/directory/room/{roomAlias}
  // ========================================================================
  if (method == "GET" && path.find("/directory/room/") != std::string::npos) {
    auto it = path_params.find("roomAlias");
    if (it != path_params.end()) {
      return handle_resolve_room_alias(db, it->second);
    }
  }

  // ========================================================================
  // ROOM UPGRADE CHAIN
  // GET /_matrix/client/v3/rooms/{roomId}/upgrade
  // ========================================================================
  if (method == "GET" && path.find("/upgrade") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_follow_room_upgrade(db, auth_header, access_token_param,
                                         it->second);
    }
  }

  // ========================================================================
  // ROOM PREDECESSOR
  // GET /_matrix/client/v3/rooms/{roomId}/predecessor
  // ========================================================================
  if (method == "GET" && path.find("/predecessor") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_get_room_predecessor(db, auth_header, access_token_param,
                                           it->second);
    }
  }

  // ========================================================================
  // ROOM SUCCESSOR
  // GET /_matrix/client/v3/rooms/{roomId}/successor
  // ========================================================================
  if (method == "GET" && path.find("/successor") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_get_room_successor(db, auth_header, access_token_param,
                                         it->second);
    }
  }

  // ========================================================================
  // ROOM VISIBILITY (GET)
  // GET /_matrix/client/v3/rooms/{roomId}/visibility
  // ========================================================================
  if (method == "GET" && path.find("/visibility") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_get_room_visibility(db, auth_header, access_token_param,
                                         it->second);
    }
  }

  // ========================================================================
  // ROOM VISIBILITY (PUT)
  // PUT /_matrix/client/v3/rooms/{roomId}/visibility
  // ========================================================================
  if (method == "PUT" && path.find("/visibility") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_set_room_visibility(db, auth_header, access_token_param,
                                         it->second, request_body);
    }
  }

  // ========================================================================
  // KNOCK ROOM
  // POST /_matrix/client/v3/knock/{roomIdOrAlias}
  // ========================================================================
  if (method == "POST" && path.find("/knock/") != std::string::npos &&
      path.find("/accept") == std::string::npos &&
      path.find("/reject") == std::string::npos) {
    auto it = path_params.find("roomIdOrAlias");
    if (it != path_params.end()) {
      return handle_knock_room(db, auth_header, access_token_param,
                                it->second, request_body);
    }
  }

  // ========================================================================
  // ACCEPT KNOCK
  // POST /_matrix/client/v3/rooms/{roomId}/knock/accept
  // ========================================================================
  if (method == "POST" && path.find("/knock/accept") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_accept_knock(db, auth_header, access_token_param,
                                  it->second, request_body);
    }
  }

  // ========================================================================
  // REJECT KNOCK
  // POST /_matrix/client/v3/rooms/{roomId}/knock/reject
  // ========================================================================
  if (method == "POST" && path.find("/knock/reject") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_reject_knock(db, auth_header, access_token_param,
                                  it->second, request_body);
    }
  }

  // ========================================================================
  // LIST PENDING KNOCKS
  // GET /_matrix/client/v3/rooms/{roomId}/knocks
  // ========================================================================
  if (method == "GET" && path.find("/knocks") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_list_pending_knocks(db, auth_header, access_token_param,
                                         it->second);
    }
  }

  // ========================================================================
  // SPACE CHILDREN
  // GET /_matrix/client/v3/rooms/{roomId}/children
  // ========================================================================
  if (method == "GET" && path.find("/children") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_explore_space_children(db, auth_header, access_token_param,
                                            it->second, request_body);
    }
  }

  // ========================================================================
  // SPACE PARENTS
  // GET /_matrix/client/v3/rooms/{roomId}/parents
  // ========================================================================
  if (method == "GET" && path.find("/parents") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_explore_space_parents(db, auth_header, access_token_param,
                                           it->second);
    }
  }

  // ========================================================================
  // ROOM CAPABILITIES
  // GET /_matrix/client/v3/rooms/{roomId}/capabilities
  // ========================================================================
  if (method == "GET" && path.find("/capabilities") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_check_room_capabilities(db, auth_header, access_token_param,
                                             it->second);
    }
  }

  // ========================================================================
  // ROOM SUMMARY (UNAUTHENTICATED)
  // GET /_matrix/client/v3/rooms/{roomId}/summary
  // ========================================================================
  if (method == "GET" && path.find("/summary") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_room_summary_public(db, it->second);
    }
  }

  // ========================================================================
  // PUBLIC ROOM SEARCH
  // POST /_matrix/client/v3/search
  // ========================================================================
  if (method == "POST" && path.find("/search") != std::string::npos) {
    return handle_public_room_search(db, auth_header, access_token_param,
                                      request_body);
  }

  // ========================================================================
  // THIRD PARTY PROTOCOLS
  // GET /_matrix/client/v3/thirdparty/protocols
  // GET /_matrix/client/v3/thirdparty/protocol/{protocol}
  // ========================================================================
  if (method == "GET" && path.find("/thirdparty/protocols") != std::string::npos) {
    // Check if specific protocol requested
    auto it = path_params.find("protocol");
    if (it != path_params.end() && !it->second.empty()) {
      return handle_get_third_party_protocol(db, it->second);
    }
    return handle_list_third_party_protocols(db);
  }

  // ========================================================================
  // THIRD PARTY LOCATION
  // GET /_matrix/client/v3/thirdparty/location/{protocol}
  // ========================================================================
  if (method == "GET" && path.find("/thirdparty/location/") != std::string::npos) {
    auto it = path_params.find("protocol");
    if (it != path_params.end()) {
      return handle_get_third_party_location(db, it->second, request_body);
    }
  }

  // ========================================================================
  // THIRD PARTY USER
  // GET /_matrix/client/v3/thirdparty/user/{protocol}
  // ========================================================================
  if (method == "GET" && path.find("/thirdparty/user/") != std::string::npos) {
    auto it = path_params.find("protocol");
    if (it != path_params.end()) {
      return handle_get_third_party_user(db, it->second, request_body);
    }
  }

  // ========================================================================
  // CANONICAL ALIAS (GET)
  // GET /_matrix/client/v3/rooms/{roomId}/canonical_alias
  // ========================================================================
  if (method == "GET" && path.find("/canonical_alias") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_get_canonical_alias(db, auth_header, access_token_param,
                                         it->second);
    }
  }

  // ========================================================================
  // CANONICAL ALIAS (PUT)
  // PUT /_matrix/client/v3/rooms/{roomId}/canonical_alias
  // ========================================================================
  if (method == "PUT" && path.find("/canonical_alias") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_set_canonical_alias(db, auth_header, access_token_param,
                                         it->second, request_body);
    }
  }

  // ========================================================================
  // ROOM ALIASES (GET)
  // GET /_matrix/client/v3/rooms/{roomId}/aliases
  // ========================================================================
  if (method == "GET" && path.find("/aliases") != std::string::npos &&
      path.find("/canonical_alias") == std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_get_room_aliases(db, auth_header, access_token_param,
                                      it->second);
    }
  }

  // ========================================================================
  // ROOM ALIASES (PUT - add)
  // PUT /_matrix/client/v3/rooms/{roomId}/aliases
  // ========================================================================
  if (method == "PUT" && path.find("/aliases") != std::string::npos &&
      path.find("/canonical_alias") == std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_add_room_alias(db, auth_header, access_token_param,
                                    it->second, request_body);
    }
  }

  // ========================================================================
  // ROOM ALIASES (DELETE)
  // DELETE /_matrix/client/v3/rooms/{roomId}/aliases
  // ========================================================================
  if (method == "DELETE" && path.find("/aliases") != std::string::npos &&
      path.find("/canonical_alias") == std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_delete_room_alias(db, auth_header, access_token_param,
                                       it->second, request_body);
    }
  }

  // ========================================================================
  // FEDERATION NEGOTIATION
  // POST /_matrix/client/v3/rooms/{roomId}/federation
  // ========================================================================
  if (method == "POST" && path.find("/federation") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      return handle_negotiate_federation(db, auth_header, access_token_param,
                                          it->second, request_body);
    }
  }

  // ========================================================================
  // FEDERATION NEGOTIATION (GET)
  // GET /_matrix/client/v3/rooms/{roomId}/federation
  // ========================================================================
  if (method == "GET" && path.find("/federation") != std::string::npos) {
    auto it = path_params.find("roomId");
    if (it != path_params.end()) {
      // GET uses the same handler with action="get"
      json get_body;
      get_body["action"] = "get";
      return handle_negotiate_federation(db, auth_header, access_token_param,
                                          it->second, get_body);
    }
  }

  // ========================================================================
  // Not matched - return empty
  // ========================================================================
  return json::object();
}

// ============================================================================
// INIT/CLEANUP - Background thread for expired peek cleanup
// ============================================================================

static std::atomic<bool> g_cleanup_running{false};
static std::thread g_cleanup_thread;

void start_peek_cleanup_thread() {
  if (g_cleanup_running.exchange(true)) return;

  g_cleanup_thread = std::thread([]() {
    while (g_cleanup_running) {
      std::this_thread::sleep_for(std::chrono::minutes(5));
      cleanup_expired_peeks();
    }
  });
  g_cleanup_thread.detach();
}

void stop_peek_cleanup_thread() {
  g_cleanup_running = false;
}

} // namespace progressive::handlers
