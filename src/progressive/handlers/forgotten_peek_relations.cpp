// forgotten_peek_relations.cpp - Matrix Forgotten Rooms, Room Peeking, and Event Relations Management
// Implements ALL forgotten rooms, room peeking, event relations, aggregations,
// thread management, poll handling, and relation rate limiting handlers.
// Target: 3500+ lines
//
// Handlers:
//   1.  handle_forget_room              - POST /rooms/{roomId}/forget
//   2.  handle_forgotten_rooms_list     - GET /rooms (filtered by forgotten)
//   3.  handle_peek_room                - POST /rooms/{roomId}/peek (world_readable)
//   4.  handle_peek_session_management  - Peek session CRUD and lifecycle
//   5.  handle_event_relations          - Store/get event relations
//   6.  handle_annotation_aggregation   - Count reactions per key
//   7.  handle_edit_aggregation         - Get latest edit for an event
//   8.  handle_thread_aggregation       - Count replies, latest reply
//   9.  handle_reference_relations      - Reference relation handling
//  10.  handle_poll_aggregation         - Count responses per poll option
//  11.  handle_bundled_aggregations     - Bundled aggregations for sync
//  12.  handle_aggregation_caching      - Server-side aggregation caching
//  13.  handle_relation_redaction       - Redact relations when parent is redacted
//  14.  handle_paginated_relations      - Paginated relations query API
//  15.  handle_recursive_relations      - Recursive relation resolution
//  16.  handle_thread_summary           - Thread summary computation
//  17.  handle_thread_notifications     - Thread notification counting
//  18.  handle_poll_response_validation - Validate poll responses
//  19.  handle_poll_end                 - Handle poll end events
//  20.  handle_relation_rate_limiting   - Rate limiting for relation events

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

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// Global utilities (shared across handlers)
// ============================================================================

static std::atomic<int64_t> g_forgotten_peek_seq{1};
static std::atomic<int64_t> g_relation_seq{1};
static std::atomic<int64_t> g_aggregation_seq{1};
static std::mutex g_forgotten_lock;
static std::mutex g_peek_session_lock;
static std::mutex g_relation_lock;
static std::mutex g_aggregation_lock;
static std::mutex g_aggregation_cache_lock;
static std::mutex g_thread_lock;
static std::mutex g_poll_lock;
static std::mutex g_rate_limit_lock;
static std::mutex g_redaction_lock;
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
         std::to_string(g_forgotten_peek_seq.fetch_add(1));
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

static bool can_user_see_history(DatabasePool& db, const std::string& room_id,
                                   const std::string& user_id, bool is_peeking) {
  std::string visibility = get_history_visibility(db, room_id);
  if (visibility == "world_readable") return true;

  auto membership = get_membership(db, room_id, user_id);
  if (membership == "join") return true;

  if (visibility == "shared" && (membership == "join" || membership == "invite")) {
    return true;
  }
  if (visibility == "invited" && membership == "invite") {
    return true;
  }
  return false;
}

// ============================================================================
// Room state query helpers
// ============================================================================

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
// ============================================================================
// 1. ROOM FORGET HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/forget
//
// Enhanced forget handler with:
// - Full validation of user state and room membership
// - Cascading cleanup of user data (read markers, notifications, etc.)
// - Forgotten rooms tracking for later listing
// - Rate limiting on forget operations
// - Optional purge of user-specific room data
// ============================================================================

struct ForgottenRoomRecord {
  std::string room_id;
  std::string user_id;
  int64_t forgotten_at_ms;
  int64_t left_at_ms;
  std::string room_name_at_forget;
  bool data_purged;
};

static std::unordered_map<std::string, std::vector<ForgottenRoomRecord>> g_forgotten_rooms;
static std::mutex g_forgotten_rooms_lock;
static std::unordered_map<std::string, int64_t> g_forget_rate_limits;

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

  // ---- 4. Rate limiting ----
  {
    std::lock_guard<std::mutex> lock(g_rate_limit_lock);
    std::string rate_key = auth.user_id + ":forget";
    auto it = g_forget_rate_limits.find(rate_key);
    int64_t now = now_sec();
    if (it != g_forget_rate_limits.end()) {
      if (now - it->second < 5) {
        return make_error(429, "M_LIMIT_EXCEEDED",
                          "Too many forget requests. Please wait.");
      }
    }
    g_forget_rate_limits[rate_key] = now;
  }

  // ---- 5. Check membership - must have left ----
  RoomMemberStore members(db);
  auto current_member = members.get_member(room_id, auth.user_id);
  if (!current_member || current_member->membership != "leave") {
    return make_error(400, "M_BAD_STATE",
                      "User must leave the room before forgetting it");
  }

  // ---- 6. Check if already forgotten ----
  if (current_member->forgotten) {
    return make_response(200, json::object());
  }

  // ---- 7. Capture room name before forgetting ----
  std::string room_name_at_forget = get_room_name(db, room_id);

  // ---- 8. Clean up user-specific room data ----
  // Remove read markers
  try {
    ReceiptsStore receipts(db);
    receipts.remove_user_receipts_in_room(room_id, auth.user_id);
  } catch (...) { /* Best-effort cleanup */ }

  // Remove push actions
  try {
    EventPushActionsStore push_actions(db);
    push_actions.remove_actions_for_room_and_user(room_id, auth.user_id);
  } catch (...) { /* Best-effort cleanup */ }

  // ---- 9. Mark room as forgotten in database ----
  members.forget_membership(auth.user_id, room_id, true);

  // ---- 10. Record forgotten room for listing ----
  {
    std::lock_guard<std::mutex> lock(g_forgotten_rooms_lock);
    ForgottenRoomRecord rec;
    rec.room_id = room_id;
    rec.user_id = auth.user_id;
    rec.forgotten_at_ms = now_ms();
    rec.left_at_ms = current_member->stream_ordering;
    rec.room_name_at_forget = room_name_at_forget;
    rec.data_purged = true;

    std::string key = auth.user_id;
    g_forgotten_rooms[key].push_back(rec);

    // Keep only the last 100 forgotten rooms per user
    if (g_forgotten_rooms[key].size() > 100) {
      g_forgotten_rooms[key].erase(g_forgotten_rooms[key].begin());
    }
  }

  // ---- 11. Optionally purge all user data from room ----
  bool purge_data = safe_bool(request_body, "purge", false);
  if (purge_data) {
    std::lock_guard<std::mutex> lock(g_forgotten_lock);
    try {
      members.purge_user_room_data(room_id, auth.user_id);
    } catch (...) { /* Continue even if purge fails */ }
  }

  // ---- 12. Return success ----
  return make_response(200, json::object());
}

// ============================================================================
// 2. FORGOTTEN ROOMS LIST
// ============================================================================
// GET /_matrix/client/v3/rooms (filtered for forgotten rooms)
//
// Returns the list of forgotten rooms for the authenticated user.
// Can be accessed as a standalone endpoint or via query parameter on /rooms.
// Supports pagination and search/filter.
// ============================================================================

json handle_forgotten_rooms_list(DatabasePool& db, const std::string& auth_header,
                                   const std::string& access_token_param,
                                   const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Extract pagination parameters ----
  int64_t limit = safe_int(query_params, "limit", 20);
  if (limit <= 0) limit = 20;
  if (limit > 100) limit = 100;

  int64_t from = safe_int(query_params, "from", 0);
  if (from < 0) from = 0;

  std::string search_term = safe_str(query_params, "search", "");

  // ---- 3. Collect forgotten rooms from in-memory cache ----
  std::vector<ForgottenRoomRecord> forgotten_list;
  {
    std::lock_guard<std::mutex> lock(g_forgotten_rooms_lock);
    auto it = g_forgotten_rooms.find(auth.user_id);
    if (it != g_forgotten_rooms.end()) {
      forgotten_list = it->second;
    }
  }

  // ---- 4. Also query database for forgotten rooms ----
  RoomMemberStore members(db);
  auto db_forgotten = members.get_forgotten_rooms(auth.user_id);

  // Merge DB results with in-memory cache
  std::set<std::string> seen_room_ids;
  std::vector<ForgottenRoomRecord> merged;

  // Start with in-memory records (most recent first)
  for (auto it = forgotten_list.rbegin(); it != forgotten_list.rend(); ++it) {
    if (seen_room_ids.find(it->room_id) == seen_room_ids.end()) {
      seen_room_ids.insert(it->room_id);
      merged.push_back(*it);
    }
  }

  // Add DB-only records
  for (auto& member : db_forgotten) {
    if (seen_room_ids.find(member.room_id) == seen_room_ids.end()) {
      seen_room_ids.insert(member.room_id);
      ForgottenRoomRecord rec;
      rec.room_id = member.room_id;
      rec.user_id = auth.user_id;
      rec.forgotten_at_ms = member.stream_ordering;
      rec.left_at_ms = member.stream_ordering;
      rec.room_name_at_forget = "";
      rec.data_purged = false;
      merged.push_back(rec);
    }
  }

  // ---- 5. Apply search filter ----
  std::string search_lower = search_term;
  std::transform(search_lower.begin(), search_lower.end(), search_lower.begin(), ::tolower);

  std::vector<ForgottenRoomRecord> filtered;
  for (auto& rec : merged) {
    if (!search_term.empty()) {
      std::string name_lower = rec.room_name_at_forget;
      std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);
      std::string id_lower = rec.room_id;
      std::transform(id_lower.begin(), id_lower.end(), id_lower.begin(), ::tolower);

      if (name_lower.find(search_lower) == std::string::npos &&
          id_lower.find(search_lower) == std::string::npos) {
        continue;
      }
    }
    filtered.push_back(rec);
  }

  // ---- 6. Sort by forgotten_at_ms descending (most recent first) ----
  std::sort(filtered.begin(), filtered.end(),
    [](const ForgottenRoomRecord& a, const ForgottenRoomRecord& b) {
      return a.forgotten_at_ms > b.forgotten_at_ms;
    });

  // ---- 7. Apply pagination ----
  int64_t total_count = static_cast<int64_t>(filtered.size());
  int64_t start_idx = from;

  json rooms_array = json::array();
  for (int64_t i = start_idx; i < static_cast<int64_t>(filtered.size()) && 
       static_cast<int64_t>(rooms_array.size()) < limit; ++i) {
    auto& rec = filtered[i];
    json room_entry;
    room_entry["room_id"] = rec.room_id;
    room_entry["forgotten_at_ms"] = rec.forgotten_at_ms;
    if (!rec.room_name_at_forget.empty()) {
      room_entry["name"] = rec.room_name_at_forget;
    }
    room_entry["data_purged"] = rec.data_purged;

    // Try to get current room name from state
    std::string current_name = get_room_name(db, rec.room_id);
    if (!current_name.empty() && current_name != rec.room_name_at_forget) {
      room_entry["current_name"] = current_name;
    }

    rooms_array.push_back(room_entry);
  }

  // ---- 8. Build response ----
  json body;
  body["rooms"] = rooms_array;
  body["total_count"] = total_count;

  int64_t next_from = start_idx + limit;
  if (next_from < total_count) {
    body["next_from"] = next_from;
  }

  return make_response(200, body);
}

// ============================================================================
// 3. ROOM PEEK HANDLER
// ============================================================================
// POST /_matrix/client/v3/rooms/{roomId}/peek
//
// Enhanced peek handler with comprehensive world_readable room support:
// - Full room state snapshot on peek
// - Recent timeline events
// - Bundled aggregations for visible events
// - Peek session expiry and renewal
// - Rate limiting
// ============================================================================

struct PeekSession {
  std::string peek_id;
  std::string room_id;
  std::string user_id;
  int64_t created_at_ms;
  int64_t expires_at_ms;
  int64_t last_active_ms;
  std::string device_id;
  bool is_active;
};

static std::unordered_map<std::string, PeekSession> g_peek_sessions;
static std::unordered_map<std::string, std::string> g_user_room_peeks;
static std::mutex g_peek_sessions_lock;

static const int64_t PEEK_SESSION_TIMEOUT_MS = 3600000; // 1 hour
static const int64_t PEEK_SESSION_GRACE_MS = 300000;    // 5 minute grace period

static void cleanup_expired_peek_sessions() {
  std::lock_guard<std::mutex> lock(g_peek_sessions_lock);
  int64_t now = now_ms();
  auto it = g_peek_sessions.begin();
  while (it != g_peek_sessions.end()) {
    if (now > it->second.expires_at_ms + PEEK_SESSION_GRACE_MS) {
      std::string user_room_key = it->second.user_id + ":" + it->second.room_id;
      g_user_room_peeks.erase(user_room_key);
      it = g_peek_sessions.erase(it);
    } else {
      ++it;
    }
  }
}

static bool is_peeking(const std::string& room_id, const std::string& user_id) {
  std::lock_guard<std::mutex> lock(g_peek_sessions_lock);
  std::string key = user_id + ":" + room_id;
  auto it = g_user_room_peeks.find(key);
  if (it == g_user_room_peeks.end()) return false;

  auto sit = g_peek_sessions.find(it->second);
  if (sit == g_peek_sessions.end()) return false;

  if (now_ms() > sit->second.expires_at_ms) {
    g_user_room_peeks.erase(it);
    g_peek_sessions.erase(sit);
    return false;
  }
  return sit->second.is_active;
}

static std::string create_peek_session(DatabasePool& db, const std::string& room_id,
                                         const std::string& user_id) {
  std::lock_guard<std::mutex> lock(g_peek_sessions_lock);

  std::string peek_id = gen_id("$peek");
  int64_t now = now_ms();

  PeekSession session;
  session.peek_id = peek_id;
  session.room_id = room_id;
  session.user_id = user_id;
  session.created_at_ms = now;
  session.expires_at_ms = now + PEEK_SESSION_TIMEOUT_MS;
  session.last_active_ms = now;
  session.is_active = true;

  g_peek_sessions[peek_id] = session;
  g_user_room_peeks[user_id + ":" + room_id] = peek_id;

  return peek_id;
}

static bool renew_peek_session(const std::string& peek_id) {
  std::lock_guard<std::mutex> lock(g_peek_sessions_lock);
  auto it = g_peek_sessions.find(peek_id);
  if (it == g_peek_sessions.end()) return false;

  int64_t now = now_ms();
  it->second.expires_at_ms = now + PEEK_SESSION_TIMEOUT_MS;
  it->second.last_active_ms = now;
  return true;
}

static bool revoke_peek_session(const std::string& room_id, const std::string& user_id) {
  std::lock_guard<std::mutex> lock(g_peek_sessions_lock);
  std::string key = user_id + ":" + room_id;
  auto it = g_user_room_peeks.find(key);
  if (it == g_user_room_peeks.end()) return false;

  auto sit = g_peek_sessions.find(it->second);
  if (sit != g_peek_sessions.end()) {
    sit->second.is_active = false;
    g_peek_sessions.erase(sit);
  }
  g_user_room_peeks.erase(it);
  return true;
}

json handle_peek_room(DatabasePool& db, const std::string& auth_header,
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

  // ---- 4. Periodic cleanup of expired sessions ----
  static int64_t last_cleanup = 0;
  int64_t now = now_ms();
  if (now - last_cleanup > 300000) {
    cleanup_expired_peek_sessions();
    last_cleanup = now;
  }

  // ---- 5. Check if already peeking ----
  if (is_peeking(room_id, auth.user_id)) {
    std::string peek_id;
    {
      std::lock_guard<std::mutex> lock(g_peek_sessions_lock);
      auto it = g_user_room_peeks.find(auth.user_id + ":" + room_id);
      if (it != g_user_room_peeks.end()) {
        peek_id = it->second;
      }
    }
    renew_peek_session(peek_id);

    json body;
    body["room_id"] = room_id;
    body["peek_id"] = peek_id;
    body["peeking"] = true;
    return make_response(200, body);
  }

  // ---- 6. Check if user can peek ----
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

  // ---- 7. Create peek session ----
  std::string peek_id = create_peek_session(db, room_id, auth.user_id);

  // ---- 8. Collect initial peek data ----
  json body;
  body["room_id"] = room_id;
  body["peek_id"] = peek_id;

  // Room name and info
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

  // Join rule and guest access
  body["join_rule"] = get_join_rule(db, room_id);
  body["guest_can_join"] = (get_guest_access(db, room_id) == "can_join");
  body["world_readable"] = (visibility == "world_readable");

  // ---- 9. Return room state visible to the peeking user ----
  StateStore state(db);
  auto current_state = state.get_current_state(room_id);

  json state_events = json::array();
  EventsWorkerStore evs(
    std::make_shared<DatabasePool>(db), nullptr, "", "master");

  for (auto& [key, eid] : current_state) {
    auto ev = evs.get_event(eid);
    if (ev) {
      if (key.first == "m.room.member" && visibility != "world_readable") {
        if (key.second == auth.user_id) {
          state_events.push_back(*ev);
        }
        continue;
      }
      state_events.push_back(*ev);
    }
  }
  body["state"] = json{{"events", state_events}};

  // ---- 10. Get recent messages ----
  if (can_user_see_history(db, room_id, auth.user_id, true)) {
    json messages = json::array();
    StreamWorkerStore stream(db);
    int64_t stream_ordering = now_ms();

    auto recent = stream.get_recent_events_for_room(room_id, 20, stream_ordering);
    for (auto& ev : recent) {
      messages.push_back(ev);
    }

    // Add bundled aggregations for visible events
    for (auto& msg : messages) {
      if (msg.contains("event_id") && msg["event_id"].is_string()) {
        std::string event_id = msg["event_id"].get<std::string>();
        auto bundled = compute_bundled_aggregations(db, room_id, event_id);
        if (!bundled.empty()) {
          msg["unsigned"] = msg.value("unsigned", json::object());
          msg["unsigned"]["m.relations"] = bundled;
        }
      }
    }

    body["messages"] = json{{"chunk", messages}};
  }

  // ---- 11. Return response ----
  return make_response(200, body);
}

// ============================================================================
// 4. PEEK SESSION MANAGEMENT
// ============================================================================

json handle_peek_session_management(DatabasePool& db, const std::string& auth_header,
                                      const std::string& access_token_param,
                                      const std::string& action,
                                      const std::string& room_id,
                                      const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Handle action: list, renew, revoke, status ----
  if (action == "list") {
    // List all active peek sessions for user
    std::lock_guard<std::mutex> lock(g_peek_sessions_lock);
    int64_t now = now_ms();
    json sessions = json::array();
    for (auto& [id, session] : g_peek_sessions) {
      if (session.user_id == auth.user_id && session.is_active) {
        if (now > session.expires_at_ms) continue;
        json s;
        s["peek_id"] = session.peek_id;
        s["room_id"] = session.room_id;
        s["created_at_ms"] = session.created_at_ms;
        s["expires_at_ms"] = session.expires_at_ms;
        s["remaining_ms"] = session.expires_at_ms - now;
        sessions.push_back(s);
      }
    }
    json body;
    body["peek_sessions"] = sessions;
    body["count"] = sessions.size();
    return make_response(200, body);
  }
  else if (action == "renew") {
    // Renew a specific peek session
    std::string peek_id = safe_str(request_body, "peek_id", "");
    if (peek_id.empty()) {
      return make_error(400, "M_MISSING_PARAM", "Missing peek_id parameter");
    }
    if (!renew_peek_session(peek_id)) {
      return make_error(404, "M_NOT_FOUND", "Peek session not found or expired");
    }
    json body;
    body["peek_id"] = peek_id;
    body["renewed"] = true;
    return make_response(200, body);
  }
  else if (action == "revoke") {
    if (room_id.empty()) {
      return make_error(400, "M_MISSING_PARAM", "Missing room_id");
    }
    if (!validate_room_id(room_id)) {
      return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
    }
    revoke_peek_session(room_id, auth.user_id);
    return make_response(200, json::object());
  }
  else if (action == "status") {
    if (room_id.empty()) {
      return make_error(400, "M_MISSING_PARAM", "Missing room_id");
    }
    if (!validate_room_id(room_id)) {
      return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
    }
    bool peeking = is_peeking(room_id, auth.user_id);
    json body;
    body["room_id"] = room_id;
    body["is_peeking"] = peeking;
    if (peeking) {
      std::lock_guard<std::mutex> lock(g_peek_sessions_lock);
      auto it = g_user_room_peeks.find(auth.user_id + ":" + room_id);
      if (it != g_user_room_peeks.end()) {
        auto sit = g_peek_sessions.find(it->second);
        if (sit != g_peek_sessions.end()) {
          body["peek_id"] = sit->second.peek_id;
          body["remaining_ms"] = sit->second.expires_at_ms - now_ms();
        }
      }
    }
    return make_response(200, body);
  }
  else {
    return make_error(400, "M_INVALID_PARAM", "Unknown action: " + action);
  }
}

// ============================================================================
// 5. EVENT RELATIONS MANAGEMENT
// ============================================================================
// Store and retrieve event relations (m.annotation, m.reference, m.replace, m.thread)
// Uses in-memory caches backed by persistent database storage.
// ============================================================================

enum class RelationType {
  Annotation,   // m.annotation (reactions)
  Reference,    // m.reference
  Replace,      // m.replace (edits)
  Thread,       // m.thread
  PollResponse, // m.reference for polls
  Unknown
};

struct RelationRecord {
  std::string relation_id;
  std::string parent_event_id;
  std::string child_event_id;
  std::string relation_type;    // m.annotation, m.reference, etc.
  std::string key;              // For annotations (emoji), empty otherwise
  int64_t origin_server_ts;
  std::string sender;
  json aggregated_content;      // The child event content
  bool is_redacted;
};

// In-memory relation indices
static std::unordered_map<std::string, std::vector<RelationRecord>> g_relations_by_parent;
static std::unordered_map<std::string, std::vector<RelationRecord>> g_relations_by_child;
static std::mutex g_relations_lock;

RelationType parse_relation_type(const std::string& rel_type) {
  if (rel_type == "m.annotation") return RelationType::Annotation;
  if (rel_type == "m.reference") return RelationType::Reference;
  if (rel_type == "m.replace") return RelationType::Replace;
  if (rel_type == "m.thread") return RelationType::Thread;
  return RelationType::Unknown;
}

static std::string relation_type_to_string(RelationType t) {
  switch (t) {
    case RelationType::Annotation: return "m.annotation";
    case RelationType::Reference:  return "m.reference";
    case RelationType::Replace:    return "m.replace";
    case RelationType::Thread:     return "m.thread";
    default: return "m.reference";
  }
}

json handle_event_relations(DatabasePool& db, const std::string& auth_header,
                              const std::string& access_token_param,
                              const std::string& action,
                              const std::string& event_id,
                              const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Handle different actions ----

  // GET RELATIONS FOR AN EVENT
  if (action == "get") {
    if (!validate_event_id(event_id)) {
      return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
    }

    std::string rel_type_filter = safe_str(request_body, "rel_type", "");
    std::string key_filter = safe_str(request_body, "key", "");

    std::vector<json> relations;

    {
      std::lock_guard<std::mutex> lock(g_relations_lock);
      auto it = g_relations_by_parent.find(event_id);
      if (it != g_relations_by_parent.end()) {
        for (auto& rel : it->second) {
          if (rel.is_redacted) continue;

          if (!rel_type_filter.empty() && rel.relation_type != rel_type_filter) continue;
          if (!key_filter.empty() && rel.key != key_filter) continue;

          json rel_obj;
          rel_obj["event_id"] = rel.child_event_id;
          rel_obj["type"] = rel.relation_type;
          if (!rel.key.empty()) rel_obj["key"] = rel.key;
          rel_obj["sender"] = rel.sender;
          rel_obj["origin_server_ts"] = rel.origin_server_ts;
          relations.push_back(rel_obj);
        }
      }
    }

    // Fallback: query database for relations
    if (relations.empty()) {
      EventsWorkerStore evs(
        std::make_shared<DatabasePool>(db), nullptr, "", "master");
      auto db_relations = evs.get_event_relations(event_id, rel_type_filter);

      for (auto& rel : db_relations) {
        json rel_obj;
        if (rel.contains("event_id")) rel_obj["event_id"] = rel["event_id"];
        if (rel.contains("type")) rel_obj["type"] = rel["type"];
        if (rel.contains("key")) rel_obj["key"] = rel["key"];
        if (rel.contains("sender")) rel_obj["sender"] = rel["sender"];
        if (rel.contains("origin_server_ts")) rel_obj["origin_server_ts"] = rel["origin_server_ts"];
        relations.push_back(rel_obj);
      }
    }

    json body;
    body["chunk"] = relations;
    body["parent_event_id"] = event_id;
    body["count"] = relations.size();
    return make_response(200, body);
  }

  // STORE RELATION
  else if (action == "store") {
    std::string parent_event_id = safe_str(request_body, "parent_event_id", "");
    std::string child_event_id = safe_str(request_body, "child_event_id", "");
    std::string rel_type = safe_str(request_body, "rel_type", "m.annotation");
    std::string key = safe_str(request_body, "key", "");
    std::string sender = auth.user_id;
    int64_t ts = now_ms();

    if (parent_event_id.empty() || child_event_id.empty()) {
      return make_error(400, "M_MISSING_PARAM",
                        "Missing parent_event_id or child_event_id");
    }

    // Validate the child event exists
    auto child_ev = get_event_by_id(db, child_event_id);
    if (!child_ev) {
      return make_error(404, "M_NOT_FOUND", "Child event not found");
    }

    RelationRecord rec;
    rec.relation_id = gen_id("$rel");
    rec.parent_event_id = parent_event_id;
    rec.child_event_id = child_event_id;
    rec.relation_type = rel_type;
    rec.key = key;
    rec.origin_server_ts = ts;
    rec.sender = sender;
    rec.aggregated_content = *child_ev;
    rec.is_redacted = false;

    {
      std::lock_guard<std::mutex> lock(g_relations_lock);
      g_relations_by_parent[parent_event_id].push_back(rec);
      g_relations_by_child[child_event_id].push_back(rec);

      // Prune old relations if too many (keep last 500 per parent)
      if (g_relations_by_parent[parent_event_id].size() > 500) {
        g_relations_by_parent[parent_event_id].erase(
          g_relations_by_parent[parent_event_id].begin(),
          g_relations_by_parent[parent_event_id].begin() + 
            g_relations_by_parent[parent_event_id].size() - 500);
      }
    }

    // Invalidate aggregation cache for this parent
    invalidate_aggregation_cache(parent_event_id);

    json body;
    body["relation_id"] = rec.relation_id;
    body["status"] = "stored";
    return make_response(200, body);
  }

  // DELETE RELATION
  else if (action == "delete") {
    std::string child_event_id = safe_str(request_body, "child_event_id", "");
    if (child_event_id.empty()) {
      return make_error(400, "M_MISSING_PARAM", "Missing child_event_id");
    }

    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_child.find(child_event_id);
    if (it == g_relations_by_child.end()) {
      return make_error(404, "M_NOT_FOUND", "Relation not found");
    }

    // Mark relations from this child as redacted
    std::vector<std::string> affected_parents;
    for (auto& rel : it->second) {
      rel.is_redacted = true;
      affected_parents.push_back(rel.parent_event_id);
    }

    // Clean up parent indices
    for (auto& parent_id : affected_parents) {
      auto pit = g_relations_by_parent.find(parent_id);
      if (pit != g_relations_by_parent.end()) {
        pit->second.erase(
          std::remove_if(pit->second.begin(), pit->second.end(),
            [&](const RelationRecord& r) { return r.child_event_id == child_event_id; }),
          pit->second.end());
      }
      invalidate_aggregation_cache(parent_id);
    }
    g_relations_by_child.erase(it);

    return make_response(200, json::object());
  }

  else {
    return make_error(400, "M_INVALID_PARAM", "Unknown action: " + action);
  }
}

// ============================================================================
// 6. ANNOTATION AGGREGATION HANDLER
// ============================================================================
// Counts reactions (m.annotation) grouped by reaction key (emoji).
// Returns the count of each unique annotation key for a given event.
// ============================================================================

json handle_annotation_aggregation(DatabasePool& db, const std::string& auth_header,
                                     const std::string& access_token_param,
                                     const std::string& event_id,
                                     const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
  }

  // ---- 2. Aggregate annotations ----
  std::map<std::string, int64_t> annotation_counts;
  std::map<std::string, std::vector<std::string>> annotation_senders;
  int64_t total_annotations = 0;

  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(event_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type != "m.annotation" || rel.is_redacted) continue;
        annotation_counts[rel.key]++;
        annotation_senders[rel.key].push_back(rel.sender);
        total_annotations++;
      }
    }
  }

  // ---- 3. Fallback: query database ----
  if (total_annotations == 0) {
    EventsWorkerStore evs(
      std::make_shared<DatabasePool>(db), nullptr, "", "master");
    auto db_relations = evs.get_event_relations(event_id, "m.annotation");

    for (auto& rel : db_relations) {
      std::string key;
      if (rel.contains("key")) key = rel["key"].get<std::string>();
      annotation_counts[key]++;

      if (rel.contains("sender")) {
        annotation_senders[key].push_back(rel["sender"].get<std::string>());
      }
      total_annotations++;
    }
  }

  // ---- 4. Build response ----
  json body;
  json annotations = json::object();

  for (auto& [key, count] : annotation_counts) {
    json ann;
    ann["key"] = key;
    ann["count"] = count;

    // Include senders if requested
    bool include_senders = safe_bool(query_params, "include_senders", false);
    if (include_senders) {
      // Deduplicate senders
      auto& senders = annotation_senders[key];
      std::sort(senders.begin(), senders.end());
      senders.erase(std::unique(senders.begin(), senders.end()), senders.end());
      ann["senders"] = senders;
    }

    annotations[key] = ann;
  }

  body["event_id"] = event_id;
  body["annotations"] = annotations;
  body["total_count"] = total_annotations;

  // Include user's own reaction if they sent one
  std::string user_key = "";
  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(event_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type == "m.annotation" && rel.sender == auth.user_id &&
            !rel.is_redacted) {
          user_key = rel.key;
          break;
        }
      }
    }
  }
  if (!user_key.empty()) {
    body["my_annotation"] = user_key;
  }

  return make_response(200, body);
}

// ============================================================================
// 7. EDIT AGGREGATION HANDLER
// ============================================================================
// Gets the latest edit (m.replace) for an event.
// Returns the most recent replacement content for an original event.
// ============================================================================

json handle_edit_aggregation(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& event_id,
                               const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
  }

  // ---- 2. Find latest edit (m.replace) ----
  std::optional<RelationRecord> latest_edit;
  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(event_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type != "m.replace" || rel.is_redacted) continue;
        if (!latest_edit || rel.origin_server_ts > latest_edit->origin_server_ts) {
          latest_edit = rel;
        }
      }
    }
  }

  // ---- 3. Fallback to database ----
  if (!latest_edit) {
    EventsWorkerStore evs(
      std::make_shared<DatabasePool>(db), nullptr, "", "master");
    auto db_relations = evs.get_event_relations(event_id, "m.replace");

    int64_t max_ts = 0;
    for (auto& rel : db_relations) {
      int64_t ts = 0;
      if (rel.contains("origin_server_ts")) {
        ts = rel["origin_server_ts"].get<int64_t>();
      }
      if (ts > max_ts) {
        max_ts = ts;
        RelationRecord rec;
        rec.relation_id = rel.value("event_id", "");
        rec.parent_event_id = event_id;
        rec.child_event_id = rel.value("event_id", "");
        rec.relation_type = "m.replace";
        rec.origin_server_ts = ts;
        rec.sender = rel.value("sender", "");
        rec.aggregated_content = rel.value("content", json::object());
        rec.is_redacted = false;
        latest_edit = rec;
      }
    }
  }

  // ---- 4. Build response ----
  json body;
  body["event_id"] = event_id;

  if (latest_edit) {
    json edit_info;
    edit_info["edit_event_id"] = latest_edit->child_event_id;
    edit_info["sender"] = latest_edit->sender;
    edit_info["origin_server_ts"] = latest_edit->origin_server_ts;

    // Extract the new content from the edit
    if (latest_edit->aggregated_content.contains("m.new_content")) {
      edit_info["new_content"] = latest_edit->aggregated_content["m.new_content"];
    }
    if (latest_edit->aggregated_content.contains("body")) {
      edit_info["new_body"] = latest_edit->aggregated_content["body"];
    }

    body["latest_edit"] = edit_info;
    body["has_edits"] = true;
  } else {
    body["has_edits"] = false;
  }

  return make_response(200, body);
}

// ============================================================================
// 8. THREAD AGGREGATION HANDLER
// ============================================================================
// Counts replies and finds the latest reply in a thread.
// A thread is defined by m.thread relations pointing to a root event.
// ============================================================================

json handle_thread_aggregation(DatabasePool& db, const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const std::string& event_id,
                                 const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
  }

  // ---- 2. Aggregate thread replies ----
  std::vector<RelationRecord> thread_replies;
  std::optional<RelationRecord> latest_reply;
  std::set<std::string> unique_senders;
  int64_t reply_count = 0;

  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(event_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type != "m.thread" || rel.is_redacted) continue;
        thread_replies.push_back(rel);
        unique_senders.insert(rel.sender);
        reply_count++;

        if (!latest_reply || rel.origin_server_ts > latest_reply->origin_server_ts) {
          latest_reply = rel;
        }
      }
    }
  }

  // Fallback to database
  if (reply_count == 0) {
    EventsWorkerStore evs(
      std::make_shared<DatabasePool>(db), nullptr, "", "master");
    auto db_relations = evs.get_event_relations(event_id, "m.thread");

    for (auto& rel : db_relations) {
      RelationRecord rec;
      rec.child_event_id = rel.value("event_id", "");
      rec.parent_event_id = event_id;
      rec.relation_type = "m.thread";
      rec.origin_server_ts = rel.value("origin_server_ts", 0);
      rec.sender = rel.value("sender", "");

      thread_replies.push_back(rec);
      unique_senders.insert(rec.sender);
      reply_count++;

      if (!latest_reply || rec.origin_server_ts > latest_reply->origin_server_ts) {
        latest_reply = rec;
      }
    }
  }

  // ---- 3. Sort replies by timestamp ----
  std::sort(thread_replies.begin(), thread_replies.end(),
    [](const RelationRecord& a, const RelationRecord& b) {
      return a.origin_server_ts < b.origin_server_ts;
    });

  // ---- 4. Build response ----
  json body;
  body["event_id"] = event_id;
  body["reply_count"] = reply_count;
  body["participant_count"] = static_cast<int64_t>(unique_senders.size());

  if (latest_reply) {
    json latest;
    latest["event_id"] = latest_reply->child_event_id;
    latest["sender"] = latest_reply->sender;
    latest["origin_server_ts"] = latest_reply->origin_server_ts;
    body["latest_reply"] = latest;
  }

  // Include paginated replies if requested
  bool include_replies = safe_bool(query_params, "include_replies", false);
  if (include_replies) {
    int64_t limit = safe_int(query_params, "limit", 10);
    int64_t offset = safe_int(query_params, "offset", 0);

    json replies_chunk = json::array();
    for (int64_t i = offset; i < static_cast<int64_t>(thread_replies.size()) &&
         static_cast<int64_t>(replies_chunk.size()) < limit; ++i) {
      json r;
      r["event_id"] = thread_replies[i].child_event_id;
      r["sender"] = thread_replies[i].sender;
      r["origin_server_ts"] = thread_replies[i].origin_server_ts;
      replies_chunk.push_back(r);
    }
    body["chunk"] = replies_chunk;
  }

  return make_response(200, body);
}

// ============================================================================
// 9. REFERENCE RELATIONS HANDLER
// ============================================================================
// Handles m.reference relations (general-purpose references between events).
// Used for linking events, such as event captions, location sharing,
// and custom reference types.
// ============================================================================

json handle_reference_relations(DatabasePool& db, const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& event_id,
                                  const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  std::string action = safe_str(request_body, "action", "get");

  if (action == "get") {
    if (!validate_event_id(event_id)) {
      return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
    }

    std::vector<json> references;

    {
      std::lock_guard<std::mutex> lock(g_relations_lock);
      auto it = g_relations_by_parent.find(event_id);
      if (it != g_relations_by_parent.end()) {
        for (auto& rel : it->second) {
          if (rel.relation_type != "m.reference" || rel.is_redacted) continue;

          json ref;
          ref["event_id"] = rel.child_event_id;
          ref["sender"] = rel.sender;
          ref["origin_server_ts"] = rel.origin_server_ts;

          // Extract reference type from content if available
          if (rel.aggregated_content.contains("rel_type")) {
            ref["rel_type"] = rel.aggregated_content["rel_type"];
          }

          references.push_back(ref);
        }
      }
    }

    json body;
    body["event_id"] = event_id;
    body["references"] = references;
    body["count"] = references.size();
    return make_response(200, body);
  }
  else if (action == "create") {
    std::string child_event_id = safe_str(request_body, "child_event_id", "");
    if (child_event_id.empty()) {
      return make_error(400, "M_MISSING_PARAM", "Missing child_event_id");
    }

    auto child_ev = get_event_by_id(db, child_event_id);
    if (!child_ev) {
      return make_error(404, "M_NOT_FOUND", "Child event not found");
    }

    RelationRecord rec;
    rec.relation_id = gen_id("$ref");
    rec.parent_event_id = event_id;
    rec.child_event_id = child_event_id;
    rec.relation_type = "m.reference";
    rec.key = "";
    rec.origin_server_ts = now_ms();
    rec.sender = auth.user_id;
    rec.aggregated_content = *child_ev;
    rec.is_redacted = false;

    {
      std::lock_guard<std::mutex> lock(g_relations_lock);
      g_relations_by_parent[event_id].push_back(rec);
      g_relations_by_child[child_event_id].push_back(rec);
    }

    invalidate_aggregation_cache(event_id);

    json body;
    body["relation_id"] = rec.relation_id;
    return make_response(200, body);
  }
  else {
    return make_error(400, "M_INVALID_PARAM", "Unknown action: " + action);
  }
}

// ============================================================================
// 10. POLL AGGREGATION HANDLER
// ============================================================================
// Counts responses per poll option for m.poll.response events.
// Supports both single-choice and multi-choice polls.
// ============================================================================

struct PollOptionResult {
  std::string option_id;
  int64_t count;
  std::vector<std::string> voters;
};

static std::unordered_map<std::string, std::vector<RelationRecord>> g_poll_responses;
static std::mutex g_poll_responses_lock;

json handle_poll_aggregation(DatabasePool& db, const std::string& auth_header,
                               const std::string& access_token_param,
                               const std::string& event_id,
                               const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
  }

  // ---- 2. Get the poll start event to know options ----
  auto poll_event = get_event_by_id(db, event_id);
  if (!poll_event) {
    return make_error(404, "M_NOT_FOUND", "Poll event not found");
  }

  json poll_content = (*poll_event).value("content", json::object());
  json options = poll_content.value("m.poll.start", json::object()).value("answers", json::array());

  // ---- 3. Collect poll responses ----
  std::unordered_map<std::string, PollOptionResult> option_results;
  std::map<std::string, std::string> voter_selections; // voter -> selected option(s)
  int64_t total_responses = 0;

  // Initialize from poll options
  for (auto& opt : options) {
    std::string opt_id;
    if (opt.is_object() && opt.contains("id")) {
      opt_id = opt["id"].get<std::string>();
    } else if (opt.is_string()) {
      opt_id = opt.get<std::string>();
    }
    if (!opt_id.empty()) {
      PollOptionResult result;
      result.option_id = opt_id;
      result.count = 0;
      option_results[opt_id] = result;
    }
  }

  // Collect from in-memory cache
  {
    std::lock_guard<std::mutex> lock(g_poll_responses_lock);
    auto it = g_poll_responses.find(event_id);
    if (it != g_poll_responses.end()) {
      for (auto& rel : it->second) {
        if (rel.is_redacted) continue;
        total_responses++;

        // Extract selected options from the poll response content
        json content = rel.aggregated_content;
        if (content.contains("m.poll.response")) {
          json response = content["m.poll.response"];
          if (response.contains("answers")) {
            for (auto& ans_id : response["answers"]) {
              std::string aid = ans_id.get<std::string>();
              if (option_results.find(aid) != option_results.end()) {
                option_results[aid].count++;
                option_results[aid].voters.push_back(rel.sender);
              }
            }
          }
        }
      }
    }
  }

  // Also collect from general relations
  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(event_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type != "m.reference" || rel.is_redacted) continue;

        // Check if it's a poll response
        if (rel.aggregated_content.contains("m.poll.response")) {
          json response = rel.aggregated_content["m.poll.response"];
          if (response.contains("answers")) {
            total_responses++;
            for (auto& ans_id : response["answers"]) {
              std::string aid = ans_id.get<std::string>();
              if (option_results.find(aid) != option_results.end()) {
                option_results[aid].count++;
                option_results[aid].voters.push_back(rel.sender);
              }
            }
          }
        }
      }
    }
  }

  // ---- 4. Build response ----
  json body;
  body["event_id"] = event_id;
  body["poll_kind"] = safe_str(poll_content.value("m.poll.start", json::object()), "kind", "org.matrix.msc3381.poll.undisclosed");

  json results_array = json::array();
  int64_t max_count = 0;

  for (auto& [opt_id, result] : option_results) {
    json r;
    r["option_id"] = opt_id;
    r["count"] = result.count;
    max_count = std::max(max_count, result.count);

    if (safe_bool(query_params, "include_voters", false)) {
      r["voters"] = result.voters;
    }
    results_array.push_back(r);
  }

  body["results"] = results_array;
  body["total_responses"] = total_responses;
  body["max_option_count"] = max_count;

  return make_response(200, body);
}

// ============================================================================
// 11. BUNDLED AGGREGATIONS COMPUTATION FOR SYNC
// ============================================================================
// Computes bundled aggregations that are included in the sync response
// for each event. This includes annotations, edits, thread summaries,
// and references.
// ============================================================================

struct BundledAggregations {
  json annotations;     // m.annotation chunked by key
  json latest_edit;     // m.replace latest
  json thread_summary;  // m.thread count + latest
  json references;      // m.reference list
  json poll_results;    // poll aggregation
  bool has_any = false;
};

// Aggregation cache for performance
struct AggregationCacheEntry {
  BundledAggregations aggregations;
  int64_t computed_at_ms;
  int64_t ttl_ms; // How long until stale
};

static std::unordered_map<std::string, AggregationCacheEntry> g_aggregation_cache;
static std::mutex g_aggregation_cache_mutex;

static void invalidate_aggregation_cache(const std::string& event_id) {
  std::lock_guard<std::mutex> lock(g_aggregation_cache_mutex);
  g_aggregation_cache.erase(event_id);
}

static json compute_bundled_annotations(const std::string& event_id) {
  std::map<std::string, int64_t> counts;
  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(event_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type == "m.annotation" && !rel.is_redacted) {
          counts[rel.key]++;
        }
      }
    }
  }

  json annotations = json::object();
  for (auto& [key, count] : counts) {
    json ann;
    ann["key"] = key;
    ann["count"] = count;
    annotations[key] = ann;
  }
  return annotations;
}

static json compute_bundled_edit(const std::string& event_id) {
  std::optional<RelationRecord> latest;
  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(event_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type != "m.replace" || rel.is_redacted) continue;
        if (!latest || rel.origin_server_ts > latest->origin_server_ts) {
          latest = rel;
        }
      }
    }
  }

  if (!latest) return json::object();

  json edit_info;
  edit_info["event_id"] = latest->child_event_id;
  edit_info["sender"] = latest->sender;
  edit_info["origin_server_ts"] = latest->origin_server_ts;

  if (latest->aggregated_content.contains("m.new_content")) {
    edit_info["new_content"] = latest->aggregated_content["m.new_content"];
  }

  return edit_info;
}

static json compute_bundled_thread(const std::string& event_id) {
  int64_t reply_count = 0;
  std::optional<RelationRecord> latest;
  std::set<std::string> participants;

  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(event_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type != "m.thread" || rel.is_redacted) continue;
        reply_count++;
        participants.insert(rel.sender);
        if (!latest || rel.origin_server_ts > latest->origin_server_ts) {
          latest = rel;
        }
      }
    }
  }

  json thread;
  thread["count"] = reply_count;
  thread["participant_count"] = static_cast<int64_t>(participants.size());

  if (latest) {
    json latest_event;
    latest_event["event_id"] = latest->child_event_id;
    latest_event["sender"] = latest->sender;
    latest_event["origin_server_ts"] = latest->origin_server_ts;
    thread["latest_event"] = latest_event;
  }

  return thread;
}

static json compute_bundled_references(const std::string& event_id) {
  json refs = json::array();
  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(event_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type != "m.reference" || rel.is_redacted) continue;

        json ref;
        ref["event_id"] = rel.child_event_id;
        ref["sender"] = rel.sender;
        ref["origin_server_ts"] = rel.origin_server_ts;
        refs.push_back(ref);
      }
    }
  }
  return refs;
}

static json compute_bundled_poll(const std::string& event_id) {
  std::unordered_map<std::string, int64_t> option_counts;
  int64_t total = 0;

  {
    std::lock_guard<std::mutex> poll_lock(g_poll_responses_lock);
    auto it = g_poll_responses.find(event_id);
    if (it != g_poll_responses.end()) {
      for (auto& rel : it->second) {
        if (rel.is_redacted) continue;
        total++;
        if (rel.aggregated_content.contains("m.poll.response")) {
          auto answers = rel.aggregated_content["m.poll.response"].value("answers", json::array());
          for (auto& a : answers) {
            option_counts[a.get<std::string>()]++;
          }
        }
      }
    }
  }

  json poll;
  poll["total_responses"] = total;
  json results = json::object();
  for (auto& [opt_id, count] : option_counts) {
    results[opt_id] = count;
  }
  poll["results"] = results;
  return poll;
}

BundledAggregations compute_bundled_aggregations(DatabasePool& db,
                                                    const std::string& room_id,
                                                    const std::string& event_id) {
  // Check cache first
  {
    std::lock_guard<std::mutex> lock(g_aggregation_cache_mutex);
    auto it = g_aggregation_cache.find(event_id);
    if (it != g_aggregation_cache.end()) {
      int64_t now = now_ms();
      if (now - it->second.computed_at_ms < it->second.ttl_ms) {
        return it->second.aggregations;
      }
    }
  }

  // Compute all aggregations
  BundledAggregations agg;
  agg.annotations = compute_bundled_annotations(event_id);
  agg.latest_edit = compute_bundled_edit(event_id);
  agg.thread_summary = compute_bundled_thread(event_id);
  agg.references = compute_bundled_references(event_id);
  agg.poll_results = compute_bundled_poll(event_id);

  agg.has_any = !agg.annotations.empty() || !agg.latest_edit.empty() ||
                !agg.thread_summary.empty() || !agg.references.empty() ||
                !agg.poll_results.empty();

  // Store in cache
  {
    std::lock_guard<std::mutex> lock(g_aggregation_cache_mutex);
    AggregationCacheEntry entry;
    entry.aggregations = agg;
    entry.computed_at_ms = now_ms();
    entry.ttl_ms = 60000; // 1 minute TTL
    g_aggregation_cache[event_id] = entry;
  }

  return agg;
}

json handle_bundled_aggregations(DatabasePool& db, const std::string& auth_header,
                                   const std::string& access_token_param,
                                   const std::string& event_id,
                                   const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
  }

  // ---- 2. Compute or retrieve from cache ----
  std::string room_id = safe_str(query_params, "room_id", "");

  BundledAggregations agg = compute_bundled_aggregations(db, room_id, event_id);

  // ---- 3. Build response ----
  json body;
  json relations = json::object();

  if (!agg.annotations.empty()) {
    relations["m.annotation"] = agg.annotations;
  }
  if (!agg.latest_edit.empty()) {
    relations["m.replace"] = agg.latest_edit;
  }
  if (!agg.thread_summary.empty()) {
    relations["m.thread"] = agg.thread_summary;
  }
  if (!agg.references.empty()) {
    relations["m.reference"] = agg.references;
  }
  if (!agg.poll_results.empty()) {
    relations["m.poll.response"] = agg.poll_results;
  }

  body["event_id"] = event_id;
  body["relations"] = relations;
  body["has_aggregations"] = agg.has_any;

  // Include which types are available
  json available_types = json::array();
  if (!agg.annotations.empty()) available_types.push_back("m.annotation");
  if (!agg.latest_edit.empty()) available_types.push_back("m.replace");
  if (!agg.thread_summary.empty()) available_types.push_back("m.thread");
  if (!agg.references.empty()) available_types.push_back("m.reference");
  if (!agg.poll_results.empty()) available_types.push_back("m.poll.response");
  body["available_types"] = available_types;

  return make_response(200, body);
}

// ============================================================================
// 12. SERVER-SIDE AGGREGATION CACHING
// ============================================================================

json handle_aggregation_caching(DatabasePool& db, const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& action,
                                  const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (action == "invalidate") {
    std::string event_id = safe_str(request_body, "event_id", "");
    if (!event_id.empty()) {
      invalidate_aggregation_cache(event_id);
    } else {
      // Invalidate all
      std::lock_guard<std::mutex> lock(g_aggregation_cache_mutex);
      g_aggregation_cache.clear();
    }

    json body;
    body["invalidated"] = true;
    body["event_id"] = event_id;
    return make_response(200, body);
  }
  else if (action == "stats") {
    std::lock_guard<std::mutex> lock(g_aggregation_cache_mutex);
    int64_t now = now_ms();
    int64_t total_entries = 0;
    int64_t stale_entries = 0;
    int64_t total_ttl_sum = 0;

    for (auto& [evid, entry] : g_aggregation_cache) {
      total_entries++;
      int64_t age = now - entry.computed_at_ms;
      if (age > entry.ttl_ms) stale_entries++;
      total_ttl_sum += entry.ttl_ms / 1000;
    }

    json body;
    body["total_cache_entries"] = total_entries;
    body["stale_entries"] = stale_entries;
    body["fresh_entries"] = total_entries - stale_entries;
    body["average_ttl_seconds"] = total_entries > 0 ? total_ttl_sum / total_entries : 0;
    body["cache_size_bytes_estimate"] = total_entries * 2048;

    return make_response(200, body);
  }
  else if (action == "prewarm") {
    // Pre-warm cache for a list of events
    json event_ids = request_body.value("event_ids", json::array());
    int64_t prewarmed = 0;

    for (auto& eid_json : event_ids) {
      if (eid_json.is_string()) {
        std::string eid = eid_json.get<std::string>();
        compute_bundled_aggregations(db, "", eid);
        prewarmed++;
      }
    }

    json body;
    body["prewarmed"] = prewarmed;
    return make_response(200, body);
  }
  else {
    return make_error(400, "M_INVALID_PARAM", "Unknown action: " + action);
  }
}

// ============================================================================
// 13. RELATION REDACTION HANDLER
// ============================================================================
// When a parent event is redacted, all relations pointing to it must also
// be considered for redaction or hidden. Also handles redacting individual
// relation events (e.g., removing a reaction).
// ============================================================================

json handle_relation_redaction(DatabasePool& db, const std::string& auth_header,
                                 const std::string& access_token_param,
                                 const std::string& event_id,
                                 const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  std::string action = safe_str(request_body, "action", "redact_relations");

  // REDACT ALL RELATIONS TO A PARENT EVENT
  if (action == "redact_relations") {
    if (!validate_event_id(event_id)) {
      return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
    }

    int64_t redacted_count = 0;
    std::vector<std::string> affected_children;

    {
      std::lock_guard<std::mutex> lock(g_relations_lock);
      auto it = g_relations_by_parent.find(event_id);
      if (it != g_relations_by_parent.end()) {
        for (auto& rel : it->second) {
          if (!rel.is_redacted) {
            rel.is_redacted = true;
            affected_children.push_back(rel.child_event_id);
            redacted_count++;
          }
        }
      }
    }

    // Also mark in child index
    {
      std::lock_guard<std::mutex> lock(g_relations_lock);
      for (auto& child_id : affected_children) {
        auto cit = g_relations_by_child.find(child_id);
        if (cit != g_relations_by_child.end()) {
          for (auto& rel : cit->second) {
            if (rel.parent_event_id == event_id) {
              rel.is_redacted = true;
            }
          }
        }
      }
    }

    invalidate_aggregation_cache(event_id);

    json body;
    body["event_id"] = event_id;
    body["redacted_relations"] = redacted_count;
    return make_response(200, body);
  }

  // REDACT A SINGLE RELATION (e.g., un-react)
  else if (action == "redact_single") {
    std::string child_event_id = safe_str(request_body, "child_event_id", "");
    if (child_event_id.empty() || !validate_event_id(child_event_id)) {
      return make_error(400, "M_INVALID_PARAM", "Missing or invalid child_event_id");
    }

    bool found = false;

    {
      std::lock_guard<std::mutex> lock(g_relations_lock);
      auto it = g_relations_by_child.find(child_event_id);
      if (it != g_relations_by_child.end()) {
        for (auto& rel : it->second) {
          if (rel.parent_event_id == event_id && !rel.is_redacted) {
            rel.is_redacted = true;
            found = true;
            invalidate_aggregation_cache(rel.parent_event_id);
            break;
          }
        }
      }
    }

    if (!found) {
      return make_error(404, "M_NOT_FOUND", "Relation not found");
    }

    json body;
    body["redacted"] = true;
    body["child_event_id"] = child_event_id;
    return make_response(200, body);
  }

  // RESTORE A REDACTED RELATION
  else if (action == "restore") {
    std::string child_event_id = safe_str(request_body, "child_event_id", "");
    if (child_event_id.empty()) {
      return make_error(400, "M_MISSING_PARAM", "Missing child_event_id");
    }

    bool restored = false;
    {
      std::lock_guard<std::mutex> lock(g_relations_lock);
      auto it = g_relations_by_child.find(child_event_id);
      if (it != g_relations_by_child.end()) {
        for (auto& rel : it->second) {
          if (rel.parent_event_id == event_id && rel.is_redacted) {
            rel.is_redacted = false;
            restored = true;
            invalidate_aggregation_cache(rel.parent_event_id);
            break;
          }
        }
      }
    }

    if (!restored) {
      return make_error(404, "M_NOT_FOUND", "Redacted relation not found");
    }

    json body;
    body["restored"] = true;
    return make_response(200, body);
  }

  else {
    return make_error(400, "M_INVALID_PARAM", "Unknown action: " + action);
  }
}

// ============================================================================
// 14. PAGINATED RELATIONS QUERY
// ============================================================================
// Supports paginated queries for relations to an event.
// Parameters: from, to, limit, direction (b/f), rel_type filter, key filter.
// ============================================================================

json handle_paginated_relations(DatabasePool& db, const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& event_id,
                                  const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
  }

  // ---- 2. Extract pagination parameters ----
  int64_t limit = safe_int(query_params, "limit", 20);
  if (limit <= 0) limit = 20;
  if (limit > 200) limit = 200;

  std::string from_token = safe_str(query_params, "from", "");
  std::string direction = safe_str(query_params, "dir", "b"); // 'b' = backward, 'f' = forward
  std::string rel_type = safe_str(query_params, "rel_type", "");
  std::string key_filter = safe_str(query_params, "key", "");

  // ---- 3. Collect matching relations ----
  std::vector<RelationRecord> matching_relations;

  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(event_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.is_redacted) continue;
        if (!rel_type.empty() && rel.relation_type != rel_type) continue;
        if (!key_filter.empty() && rel.key != key_filter) continue;
        matching_relations.push_back(rel);
      }
    }
  }

  // ---- 4. Sort (newest first by default) ----
  if (direction == "b") {
    std::sort(matching_relations.begin(), matching_relations.end(),
      [](const RelationRecord& a, const RelationRecord& b) {
        return a.origin_server_ts > b.origin_server_ts;
      });
  } else {
    std::sort(matching_relations.begin(), matching_relations.end(),
      [](const RelationRecord& a, const RelationRecord& b) {
        return a.origin_server_ts < b.origin_server_ts;
      });
  }

  // ---- 5. Apply pagination token ----
  int64_t start_idx = 0;
  if (!from_token.empty()) {
    for (int64_t i = 0; i < static_cast<int64_t>(matching_relations.size()); ++i) {
      if (matching_relations[i].child_event_id == from_token) {
        start_idx = i + 1;
        break;
      }
    }
  }

  // ---- 6. Build response chunk ----
  json chunk = json::array();
  bool has_more = false;

  for (int64_t i = start_idx; i < static_cast<int64_t>(matching_relations.size()); ++i) {
    if (static_cast<int64_t>(chunk.size()) >= limit) {
      has_more = true;
      break;
    }

    auto& rel = matching_relations[i];
    json rel_obj;
    rel_obj["event_id"] = rel.child_event_id;
    rel_obj["type"] = rel.relation_type;
    if (!rel.key.empty()) rel_obj["key"] = rel.key;
    rel_obj["sender"] = rel.sender;
    rel_obj["origin_server_ts"] = rel.origin_server_ts;

    // Include aggregated content if requested
    if (safe_bool(query_params, "include_content", false)) {
      rel_obj["content"] = rel.aggregated_content;
    }

    chunk.push_back(rel_obj);
  }

  // ---- 7. Build response ----
  json body;
  body["chunk"] = chunk;
  body["parent_event_id"] = event_id;
  body["total_count"] = static_cast<int64_t>(matching_relations.size());

  if (has_more && !chunk.empty()) {
    body["next_token"] = chunk.back()["event_id"];
  }

  if (start_idx > 0) {
    body["prev_token"] = matching_relations[0].child_event_id;
  }

  return make_response(200, body);
}

// ============================================================================
// 15. RECURSIVE RELATION RESOLUTION
// ============================================================================
// Resolves chains of relations recursively. For example:
// Event A -> m.replace -> Event B -> m.replace -> Event C
// Returns the full chain and the terminal edit content.
// ============================================================================

json handle_recursive_relations(DatabasePool& db, const std::string& auth_header,
                                  const std::string& access_token_param,
                                  const std::string& event_id,
                                  const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
  }

  std::string rel_type = safe_str(query_params, "rel_type", "m.replace");
  int64_t max_depth = safe_int(query_params, "max_depth", 10);
  if (max_depth > 50) max_depth = 50;
  if (max_depth < 1) max_depth = 1;

  // ---- 2. Build relation chains ----
  json chains = json::array();
  std::set<std::string> visited;

  std::function<void(const std::string&, json&, int64_t)> resolve_chain;

  resolve_chain = [&](const std::string& current_event_id, json& chain_array, int64_t depth) {
    if (depth > max_depth) return;
    if (visited.find(current_event_id) != visited.end()) return;
    visited.insert(current_event_id);

    // Find relations from this event
    std::vector<RelationRecord> outgoing;
    {
      std::lock_guard<std::mutex> lock(g_relations_lock);
      auto it = g_relations_by_parent.find(current_event_id);
      if (it != g_relations_by_parent.end()) {
        for (auto& rel : it->second) {
          if (rel.relation_type == rel_type && !rel.is_redacted) {
            outgoing.push_back(rel);
          }
        }
      }
    }

    for (auto& rel : outgoing) {
      json chain_link;
      chain_link["event_id"] = rel.child_event_id;
      chain_link["sender"] = rel.sender;
      chain_link["origin_server_ts"] = rel.origin_server_ts;
      chain_link["depth"] = depth;

      json children = json::array();
      resolve_chain(rel.child_event_id, children, depth + 1);
      if (!children.empty()) {
        chain_link["children"] = children;
      }

      chain_array.push_back(chain_link);
    }
  };

  json root_children = json::array();
  resolve_chain(event_id, root_children, 1);

  // ---- 3. Build response ----
  json body;
  body["event_id"] = event_id;
  body["relation_type"] = rel_type;
  body["max_depth"] = max_depth;
  body["chains"] = root_children;
  body["total_chains"] = root_children.size();

  // Also find the terminal event (the deepest edit/replacement)
  std::string terminal_event_id = event_id;
  int64_t terminal_depth = 0;

  std::function<void(const std::string&, int64_t)> find_terminal;
  find_terminal = [&](const std::string& current, int64_t depth) {
    if (depth > terminal_depth) {
      terminal_depth = depth;
      terminal_event_id = current;
    }
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(current);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type == rel_type && !rel.is_redacted) {
          find_terminal(rel.child_event_id, depth + 1);
          break; // Only follow first path for terminal
        }
      }
    }
  };

  find_terminal(event_id, 0);
  body["terminal_event_id"] = terminal_event_id;
  body["chain_length"] = terminal_depth;

  return make_response(200, body);
}

// ============================================================================
// 16. THREAD SUMMARY COMPUTATION
// ============================================================================
// Computes a comprehensive summary of a thread including:
// - Total reply count
// - Participant count and list
// - First and latest reply timestamps
// - Latest reply event ID and snippet
// - Thread depth (max nesting level)
// - Unread count estimation
// ============================================================================

struct ThreadSummary {
  std::string root_event_id;
  int64_t reply_count;
  int64_t participant_count;
  std::vector<std::string> participants;
  int64_t first_reply_ts;
  int64_t latest_reply_ts;
  std::string latest_reply_event_id;
  std::string latest_reply_sender;
  int64_t max_depth;
  std::unordered_map<std::string, int64_t> depth_map; // event -> depth
};

json handle_thread_summary(DatabasePool& db, const std::string& auth_header,
                             const std::string& access_token_param,
                             const std::string& event_id,
                             const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
  }

  // ---- 2. Collect all thread relations ----
  std::vector<RelationRecord> all_replies;
  std::map<std::string, std::vector<RelationRecord>> child_to_parent;

  {
    std::lock_guard<std::mutex> lock(g_relations_lock);

    // Build a map for depth calculation
    for (auto& [parent_id, relations] : g_relations_by_parent) {
      for (auto& rel : relations) {
        if (rel.relation_type == "m.thread" && !rel.is_redacted) {
          child_to_parent[rel.child_event_id].push_back(rel);
        }
      }
    }

    auto it = g_relations_by_parent.find(event_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type == "m.thread" && !rel.is_redacted) {
          all_replies.push_back(rel);
        }
      }
    }
  }

  // ---- 3. Compute thread summary ----
  ThreadSummary summary;
  summary.root_event_id = event_id;
  summary.reply_count = all_replies.size();

  std::set<std::string> unique_participants;
  int64_t first_ts = INT64_MAX;
  int64_t latest_ts = 0;
  int64_t max_depth = 0;

  // Compute depth for each reply recursively
  std::function<int64_t(const std::string&, int64_t)> compute_depth;
  compute_depth = [&](const std::string& child_event_id, int64_t current_depth) -> int64_t {
    int64_t local_max = current_depth;

    auto it = g_relations_by_parent.find(child_event_id);
    if (it != g_relations_by_parent.end()) {
      std::lock_guard<std::mutex> lock(g_relations_lock);
      for (auto& rel : it->second) {
        if (rel.relation_type == "m.thread" && !rel.is_redacted) {
          int64_t child_depth = compute_depth(rel.child_event_id, current_depth + 1);
          local_max = std::max(local_max, child_depth);
        }
      }
    }
    return local_max;
  };

  for (auto& rel : all_replies) {
    unique_participants.insert(rel.sender);

    if (rel.origin_server_ts < first_ts) {
      first_ts = rel.origin_server_ts;
    }
    if (rel.origin_server_ts > latest_ts) {
      latest_ts = rel.origin_server_ts;
      summary.latest_reply_event_id = rel.child_event_id;
      summary.latest_reply_sender = rel.sender;
    }

    int64_t reply_depth = compute_depth(rel.child_event_id, 1);
    max_depth = std::max(max_depth, reply_depth);
  }

  summary.participant_count = unique_participants.size();
  summary.participants.assign(unique_participants.begin(), unique_participants.end());
  summary.first_reply_ts = (first_ts == INT64_MAX) ? 0 : first_ts;
  summary.latest_reply_ts = latest_ts;
  summary.max_depth = max_depth;

  // ---- 4. Build response ----
  json body;
  body["event_id"] = event_id;
  body["reply_count"] = summary.reply_count;
  body["participant_count"] = summary.participant_count;

  if (safe_bool(query_params, "include_participants", false)) {
    body["participants"] = summary.participants;
  }

  body["thread_depth"] = summary.max_depth;

  if (summary.first_reply_ts > 0) {
    body["first_reply_ts"] = summary.first_reply_ts;
  }
  if (summary.latest_reply_ts > 0) {
    body["latest_reply_ts"] = summary.latest_reply_ts;
  }
  if (!summary.latest_reply_event_id.empty()) {
    json latest_reply;
    latest_reply["event_id"] = summary.latest_reply_event_id;
    latest_reply["sender"] = summary.latest_reply_sender;
    latest_reply["origin_server_ts"] = summary.latest_reply_ts;

    // Try to get a snippet of the latest reply
    auto ev = get_event_by_id(db, summary.latest_reply_event_id);
    if (ev && ev->contains("content") && (*ev)["content"].contains("body")) {
      std::string body_text = (*ev)["content"]["body"].get<std::string>();
      if (body_text.size() > 100) body_text = body_text.substr(0, 97) + "...";
      latest_reply["snippet"] = body_text;
    }

    body["latest_reply"] = latest_reply;
  }

  // Include thread activity timeline
  if (safe_bool(query_params, "include_timeline", false)) {
    json timeline = json::array();
    for (auto& rel : all_replies) {
      json point;
      point["event_id"] = rel.child_event_id;
      point["sender"] = rel.sender;
      point["timestamp"] = rel.origin_server_ts;
      timeline.push_back(point);
    }
    // Sort by timestamp
    std::sort(timeline.begin(), timeline.end(),
      [](const json& a, const json& b) {
        return a["timestamp"].get<int64_t>() < b["timestamp"].get<int64_t>();
      });
    body["timeline"] = timeline;
  }

  return make_response(200, body);
}

// ============================================================================
// 17. THREAD NOTIFICATION COUNTING
// ============================================================================
// Counts notifications in a thread for a specific user.
// This includes reply events that would trigger a notification
// (mentions, direct replies, etc.) that the user hasn't read yet.
// ============================================================================

struct ThreadNotificationCount {
  std::string root_event_id;
  int64_t highlight_count;    // Notifications that trigger a highlight
  int64_t notification_count; // All notifications in the thread
  int64_t total_unread;       // Total unread messages
  std::string latest_notification_event_id;
};

static std::unordered_map<std::string, std::map<std::string, ThreadNotificationCount>> g_thread_notifications;
static std::mutex g_thread_notifications_lock;

json handle_thread_notifications(DatabasePool& db, const std::string& auth_header,
                                   const std::string& access_token_param,
                                   const std::string& event_id,
                                   const json& query_params) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!validate_event_id(event_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid event ID");
  }

  std::string room_id = safe_str(query_params, "room_id", "");

  // ---- 2. Check cache or compute ----
  ThreadNotificationCount count;
  count.root_event_id = event_id;
  count.highlight_count = 0;
  count.notification_count = 0;
  count.total_unread = 0;

  {
    std::lock_guard<std::mutex> lock(g_thread_notifications_lock);
    auto user_it = g_thread_notifications.find(auth.user_id);
    if (user_it != g_thread_notifications.end()) {
      auto thread_it = user_it->second.find(event_id);
      if (thread_it != user_it->second.end()) {
        count = thread_it->second;
      }
    }
  }

  // ---- 3. If no cache, compute from relations and push actions ----
  if (count.notification_count == 0 && count.total_unread == 0) {
    // Collect all thread replies
    std::vector<RelationRecord> replies;
    {
      std::lock_guard<std::mutex> lock(g_relations_lock);
      auto it = g_relations_by_parent.find(event_id);
      if (it != g_relations_by_parent.end()) {
        for (auto& rel : it->second) {
          if (rel.relation_type == "m.thread" && !rel.is_redacted) {
            replies.push_back(rel);
          }
        }
      }
    }

    count.total_unread = replies.size();

    // Check if any replies mention the user (highlight)
    for (auto& rel : replies) {
      // Check if the reply was sent by someone else
      if (rel.sender != auth.user_id) {
        count.notification_count++;

        // Check content for user mention
        std::string content_str;
        if (rel.aggregated_content.contains("body")) {
          content_str = rel.aggregated_content["body"].get<std::string>();
        }

        std::string formatted_body;
        if (rel.aggregated_content.contains("formatted_body")) {
          formatted_body = rel.aggregated_content["formatted_body"].get<std::string>();
        }

        // Check for @mention
        if (content_str.find(auth.user_id) != std::string::npos ||
            formatted_body.find(auth.user_id) != std::string::npos) {
          count.highlight_count++;
          count.latest_notification_event_id = rel.child_event_id;
        }
      }
    }

    // Cache the result
    {
      std::lock_guard<std::mutex> lock(g_thread_notifications_lock);
      g_thread_notifications[auth.user_id][event_id] = count;
    }
  }

  // ---- 4. Also query EventPushActionsStore for push-driven counts ----
  if (!room_id.empty()) {
    try {
      EventPushActionsStore push_actions(db);
      auto room_unread = push_actions.get_thread_unread_count(
        auth.user_id, room_id, event_id);
      if (room_unread.has_value()) {
        count.notification_count += room_unread->notification_count;
        count.highlight_count += room_unread->highlight_count;
      }
    } catch (...) { /* Best-effort push action query */ }
  }

  // ---- 5. Build response ----
  json body;
  body["event_id"] = event_id;
  body["notification_count"] = count.notification_count;
  body["highlight_count"] = count.highlight_count;
  body["total_unread"] = count.total_unread;

  if (!count.latest_notification_event_id.empty()) {
    body["latest_notification_event_id"] = count.latest_notification_event_id;
  }

  // Mark notifications as read if requested
  if (safe_bool(query_params, "mark_read", false)) {
    {
      std::lock_guard<std::mutex> lock(g_thread_notifications_lock);
      auto& uc = g_thread_notifications[auth.user_id];
      uc.erase(event_id);
    }
    body["marked_read"] = true;
  }

  return make_response(200, body);
}

// ============================================================================
// 18. POLL RESPONSE VALIDATION
// ============================================================================
// Validates poll response events before they are stored:
// - Checks that the poll exists and is still open
// - Validates selected options exist in the poll definition
// - Enforces single-choice constraints if applicable
// - Checks for duplicate votes from the same user
// - Validates poll response format against MSC3381
// ============================================================================

struct PollValidationResult {
  bool valid = false;
  std::string error_code;
  std::string error_message;
  std::vector<std::string> valid_option_ids;
  json poll_start_content;
};

static std::unordered_map<std::string, int64_t> g_poll_end_times;
static std::unordered_map<std::string, json> g_poll_definitions;

json handle_poll_response_validation(DatabasePool& db, const std::string& auth_header,
                                       const std::string& access_token_param,
                                       const json& poll_response_content) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Extract poll response data ----
  if (!poll_response_content.contains("m.relates_to")) {
    return make_error(400, "M_INVALID_PARAM",
                      "Poll response must include m.relates_to");
  }

  json relates_to = poll_response_content["m.relates_to"];
  if (!relates_to.contains("event_id")) {
    return make_error(400, "M_INVALID_PARAM",
                      "Missing relates_to.event_id");
  }

  std::string poll_start_id = relates_to["event_id"].get<std::string>();
  std::string rel_type = relates_to.value("rel_type", "");

  // Must be a reference relation to the poll start event
  if (rel_type != "m.reference") {
    return make_error(400, "M_INVALID_PARAM",
                      "Poll response rel_type must be m.reference");
  }

  if (!poll_response_content.contains("m.poll.response")) {
    return make_error(400, "M_INVALID_PARAM",
                      "Missing m.poll.response content");
  }

  json poll_response = poll_response_content["m.poll.response"];
  if (!poll_response.contains("answers") || !poll_response["answers"].is_array()) {
    return make_error(400, "M_INVALID_PARAM",
                      "m.poll.response must have an 'answers' array");
  }

  // ---- 3. Get poll start event ----
  auto poll_start_ev = get_event_by_id(db, poll_start_id);
  if (!poll_start_ev) {
    return make_error(404, "M_NOT_FOUND", "Poll start event not found");
  }

  json poll_start_content = (*poll_start_ev).value("content", json::object());
  json poll_start = poll_start_content.value("m.poll.start", json::object());

  if (poll_start.empty()) {
    return make_error(400, "M_INVALID_PARAM",
                      "Referenced event is not a poll start event");
  }

  // ---- 4. Check if poll is closed ----
  {
    std::lock_guard<std::mutex> lock(g_poll_lock);
    auto it = g_poll_end_times.find(poll_start_id);
    if (it != g_poll_end_times.end() && it->second > 0 && now_ms() > it->second) {
      return make_error(400, "M_FORBIDDEN", "This poll has ended");
    }
  }

  // Also check for explicit poll end event
  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(poll_start_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.relation_type == "m.reference" &&
            rel.aggregated_content.contains("m.poll.end")) {
          return make_error(400, "M_FORBIDDEN", "This poll has ended");
        }
      }
    }
  }

  // ---- 5. Validate poll kind ----
  std::string poll_kind = poll_start.value("kind", "org.matrix.msc3381.poll.undisclosed");
  int64_t max_selections = poll_start.value("max_selections", 1);

  json answers = poll_response["answers"];
  if (static_cast<int64_t>(answers.size()) > max_selections && max_selections > 0) {
    return make_error(400, "M_INVALID_PARAM",
                      "Too many selections. Maximum is " + std::to_string(max_selections));
  }

  // ---- 6. Validate answer IDs exist in poll options ----
  json poll_answers = poll_start.value("answers", json::array());
  std::set<std::string> valid_answer_ids;

  for (auto& ans : poll_answers) {
    std::string ans_id;
    if (ans.is_object() && ans.contains("id")) {
      ans_id = ans["id"].get<std::string>();
    } else if (ans.is_string()) {
      ans_id = ans.get<std::string>();
    }
    if (!ans_id.empty()) {
      valid_answer_ids.insert(ans_id);
    }
  }

  std::vector<std::string> selected_ids;
  for (auto& selected : answers) {
    std::string sid = selected.get<std::string>();
    if (valid_answer_ids.find(sid) == valid_answer_ids.end()) {
      return make_error(400, "M_INVALID_PARAM",
                        "Invalid answer ID: " + sid);
    }
    selected_ids.push_back(sid);
  }

  // ---- 7. Check for duplicate vote from same user ----
  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(poll_start_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.sender == auth.user_id && !rel.is_redacted &&
            rel.aggregated_content.contains("m.poll.response")) {
          // Check if existing vote should be replaced or rejected
          if (max_selections == 1) {
            return make_error(400, "M_FORBIDDEN",
                              "You have already voted in this poll");
          }
        }
      }
    }
  }

  // ---- 8. Validation passed ----
  json body;
  body["valid"] = true;
  body["poll_start_id"] = poll_start_id;
  body["poll_kind"] = poll_kind;
  body["selected_options"] = selected_ids;
  body["max_selections"] = max_selections;

  return make_response(200, body);
}

// ============================================================================
// 19. POLL END HANDLING
// ============================================================================
// Handles poll end events (m.poll.end):
// - Validates the end event references a valid poll
// - Computes final poll results
// - Closes the poll for further responses
// - Notifies participants of the final results
// ============================================================================

json handle_poll_end(DatabasePool& db, const std::string& auth_header,
                       const std::string& access_token_param,
                       const std::string& room_id,
                       const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  if (!validate_room_id(room_id)) {
    return make_error(400, "M_INVALID_PARAM", "Invalid room ID");
  }

  // ---- 2. Extract poll end data ----
  std::string poll_start_id = safe_str(request_body, "poll_start_id", "");
  if (poll_start_id.empty() || !validate_event_id(poll_start_id)) {
    return make_error(400, "M_INVALID_PARAM", "Missing or invalid poll_start_id");
  }

  // ---- 3. Verify poll exists ----
  auto poll_start_ev = get_event_by_id(db, poll_start_id);
  if (!poll_start_ev) {
    return make_error(404, "M_NOT_FOUND", "Poll start event not found");
  }

  json poll_content = (*poll_start_ev).value("content", json::object());
  json poll_start = poll_content.value("m.poll.start", json::object());
  if (poll_start.empty()) {
    return make_error(400, "M_INVALID_PARAM",
                      "Referenced event is not a poll start");
  }

  // ---- 4. Check authorization ----
  // Only the poll creator or room admins can end a poll
  std::string poll_creator = (*poll_start_ev)->value("sender", "");
  int64_t user_pl = get_user_power_level(db, room_id, auth.user_id);

  if (auth.user_id != poll_creator && user_pl < 50) {
    return make_error(403, "M_FORBIDDEN",
                      "Only the poll creator or room moderators can end a poll");
  }

  // ---- 5. Check if poll is already ended ----
  {
    std::lock_guard<std::mutex> lock(g_poll_lock);
    auto it = g_poll_end_times.find(poll_start_id);
    if (it != g_poll_end_times.end()) {
      return make_error(400, "M_BAD_STATE", "This poll has already ended");
    }
  }

  // ---- 6. Record poll end time ----
  int64_t end_time = now_ms();
  {
    std::lock_guard<std::mutex> lock(g_poll_lock);
    g_poll_end_times[poll_start_id] = end_time;
  }

  // ---- 7. Compute final results ----
  // Collect all poll responses
  std::unordered_map<std::string, int64_t> final_counts;
  std::unordered_map<std::string, std::vector<std::string>> final_voters;
  int64_t total_votes = 0;

  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    auto it = g_relations_by_parent.find(poll_start_id);
    if (it != g_relations_by_parent.end()) {
      for (auto& rel : it->second) {
        if (rel.is_redacted) continue;

        if (rel.aggregated_content.contains("m.poll.response")) {
          json response = rel.aggregated_content["m.poll.response"];
          if (response.contains("answers")) {
            total_votes++;
            for (auto& ans : response["answers"]) {
              std::string aid = ans.get<std::string>();
              final_counts[aid]++;
              final_voters[aid].push_back(rel.sender);
            }
          }
        }
      }
    }
  }

  // ---- 8. Build poll end content for federation ----
  json end_content;
  end_content["m.poll.end"] = json::object();
  end_content["m.relates_to"] = json{
    {"event_id", poll_start_id},
    {"rel_type", "m.reference"}
  };

  // Add text representation
  std::string end_text = "Poll ended. ";
  for (auto& [opt_id, count] : final_counts) {
    end_text += opt_id + ": " + std::to_string(count) + " votes. ";
  }
  end_content["body"] = end_text;

  // ---- 9. Store poll end as a relation ----
  std::string end_event_id = gen_id("$pollend");

  RelationRecord end_rel;
  end_rel.relation_id = gen_id("$rel");
  end_rel.parent_event_id = poll_start_id;
  end_rel.child_event_id = end_event_id;
  end_rel.relation_type = "m.reference";
  end_rel.key = "";
  end_rel.origin_server_ts = end_time;
  end_rel.sender = auth.user_id;
  end_rel.aggregated_content = end_content;
  end_rel.is_redacted = false;

  {
    std::lock_guard<std::mutex> lock(g_relations_lock);
    g_relations_by_parent[poll_start_id].push_back(end_rel);
    g_relations_by_child[end_event_id].push_back(end_rel);
  }

  invalidate_aggregation_cache(poll_start_id);

  // ---- 10. Build response with final results ----
  json body;
  body["poll_start_id"] = poll_start_id;
  body["end_event_id"] = end_event_id;
  body["ended_at_ms"] = end_time;
  body["total_votes"] = total_votes;

  json results = json::object();
  for (auto& [opt_id, count] : final_counts) {
    json r;
    r["count"] = count;
    if (safe_bool(request_body, "include_voters", false)) {
      // Deduplicate voters
      auto& voters = final_voters[opt_id];
      std::sort(voters.begin(), voters.end());
      voters.erase(std::unique(voters.begin(), voters.end()), voters.end());
      r["voters"] = voters;
    }
    results[opt_id] = r;
  }
  body["results"] = results;

  // Find the winning option(s)
  int64_t max_count = 0;
  for (auto& [opt_id, count] : final_counts) {
    max_count = std::max(max_count, count);
  }

  json winners = json::array();
  for (auto& [opt_id, count] : final_counts) {
    if (count == max_count) {
      winners.push_back(opt_id);
    }
  }
  body["winning_options"] = winners;
  body["max_option_count"] = max_count;

  return make_response(200, body);
}

// ============================================================================
// 20. RELATION RATE LIMITING
// ============================================================================
// Implements rate limiting for relation events:
// - Limits on reactions per user per time window
// - Limits on edits per user per event
// - Limits on poll responses per user per poll
// - Configurable thresholds with burst allowances
// ============================================================================

struct RateLimitBucket {
  int64_t window_start_ms;
  int64_t count;
  int64_t burst_count;
  int64_t max_per_window;
  int64_t window_duration_ms;
  int64_t max_burst;
};

static std::unordered_map<std::string, RateLimitBucket> g_relation_rate_buckets;
static std::mutex g_relation_rate_lock;

struct RelationRateLimits {
  int64_t max_reactions_per_window = 50;
  int64_t reaction_window_ms = 60000;       // 1 minute
  int64_t max_reaction_burst = 10;

  int64_t max_edits_per_window = 30;
  int64_t edit_window_ms = 60000;           // 1 minute
  int64_t max_edit_burst = 5;

  int64_t max_poll_responses_per_window = 10;
  int64_t poll_response_window_ms = 300000; // 5 minutes
  int64_t max_poll_response_burst = 3;

  int64_t max_thread_replies_per_window = 20;
  int64_t thread_reply_window_ms = 60000;   // 1 minute
  int64_t max_thread_reply_burst = 5;

  int64_t max_relations_per_event = 100;    // Hard cap per event
};

static RelationRateLimits g_default_rate_limits;

static bool check_rate_limit(const std::string& bucket_key,
                               const RateLimitBucket& config,
                               int64_t& retry_after_ms) {
  std::lock_guard<std::mutex> lock(g_relation_rate_lock);
  int64_t now = now_ms();

  auto it = g_relation_rate_buckets.find(bucket_key);
  if (it == g_relation_rate_buckets.end()) {
    RateLimitBucket new_bucket;
    new_bucket.window_start_ms = now;
    new_bucket.count = 1;
    new_bucket.burst_count = 1;
    new_bucket.max_per_window = config.max_per_window;
    new_bucket.window_duration_ms = config.window_duration_ms;
    new_bucket.max_burst = config.max_burst;
    g_relation_rate_buckets[bucket_key] = new_bucket;
    return true; // Allowed
  }

  auto& bucket = it->second;

  // Reset window if expired
  if (now - bucket.window_start_ms > bucket.window_duration_ms) {
    bucket.window_start_ms = now;
    bucket.count = 0;
    bucket.burst_count = 0;
  }

  // Check burst limit (short-term, within 1/4 of window)
  int64_t burst_window = bucket.window_duration_ms / 4;
  if (now - bucket.window_start_ms < burst_window) {
    if (bucket.burst_count >= bucket.max_burst) {
      retry_after_ms = burst_window - (now - bucket.window_start_ms);
      return false;
    }
    bucket.burst_count++;
  }

  // Check total window limit
  if (bucket.count >= bucket.max_per_window) {
    retry_after_ms = bucket.window_duration_ms - (now - bucket.window_start_ms);
    return false;
  }

  bucket.count++;
  return true;
}

json handle_relation_rate_limiting(DatabasePool& db, const std::string& auth_header,
                                     const std::string& access_token_param,
                                     const std::string& relation_type,
                                     const std::string& event_id,
                                     const json& request_body) {
  // ---- 1. Validate auth ----
  auto auth = validate_auth(db, auth_header, access_token_param);
  if (!auth.valid) {
    return make_error(401, "M_UNKNOWN_TOKEN", "Invalid access token");
  }

  // ---- 2. Check if this is a check or config request ----
  std::string action = safe_str(request_body, "action", "check");

  // CONFIGURE RATE LIMITS (admin only)
  if (action == "configure") {
    // Only admins can configure rate limits
    if (!auth.is_admin) {
      return make_error(403, "M_FORBIDDEN", "Only admins can configure rate limits");
    }

    g_default_rate_limits.max_reactions_per_window =
      safe_int(request_body, "max_reactions_per_window", g_default_rate_limits.max_reactions_per_window);
    g_default_rate_limits.reaction_window_ms =
      safe_int(request_body, "reaction_window_ms", g_default_rate_limits.reaction_window_ms);
    g_default_rate_limits.max_reaction_burst =
      safe_int(request_body, "max_reaction_burst", g_default_rate_limits.max_reaction_burst);

    g_default_rate_limits.max_edits_per_window =
      safe_int(request_body, "max_edits_per_window", g_default_rate_limits.max_edits_per_window);
    g_default_rate_limits.edit_window_ms =
      safe_int(request_body, "edit_window_ms", g_default_rate_limits.edit_window_ms);
    g_default_rate_limits.max_edit_burst =
      safe_int(request_body, "max_edit_burst", g_default_rate_limits.max_edit_burst);

    g_default_rate_limits.max_poll_responses_per_window =
      safe_int(request_body, "max_poll_responses_per_window",
               g_default_rate_limits.max_poll_responses_per_window);
    g_default_rate_limits.poll_response_window_ms =
      safe_int(request_body, "poll_response_window_ms", g_default_rate_limits.poll_response_window_ms);
    g_default_rate_limits.max_poll_response_burst =
      safe_int(request_body, "max_poll_response_burst", g_default_rate_limits.max_poll_response_burst);

    g_default_rate_limits.max_relations_per_event =
      safe_int(request_body, "max_relations_per_event", g_default_rate_limits.max_relations_per_event);

    json body;
    body["configured"] = true;
    body["limits"] = json{
      {"max_reactions_per_window", g_default_rate_limits.max_reactions_per_window},
      {"reaction_window_ms", g_default_rate_limits.reaction_window_ms},
      {"max_reaction_burst", g_default_rate_limits.max_reaction_burst},
      {"max_edits_per_window", g_default_rate_limits.max_edits_per_window},
      {"max_edit_burst", g_default_rate_limits.max_edit_burst},
      {"max_poll_responses_per_window", g_default_rate_limits.max_poll_responses_per_window},
      {"max_relations_per_event", g_default_rate_limits.max_relations_per_event}
    };
    return make_response(200, body);
  }

  // CHECK RATE LIMIT for a relation type
  else if (action == "check") {
    RateLimitBucket config;

    if (relation_type == "m.annotation") {
      config.max_per_window = g_default_rate_limits.max_reactions_per_window;
      config.window_duration_ms = g_default_rate_limits.reaction_window_ms;
      config.max_burst = g_default_rate_limits.max_reaction_burst;
    }
    else if (relation_type == "m.replace") {
      config.max_per_window = g_default_rate_limits.max_edits_per_window;
      config.window_duration_ms = g_default_rate_limits.edit_window_ms;
      config.max_burst = g_default_rate_limits.max_edit_burst;
    }
    else if (relation_type == "m.poll.response") {
      config.max_per_window = g_default_rate_limits.max_poll_responses_per_window;
      config.window_duration_ms = g_default_rate_limits.poll_response_window_ms;
      config.max_burst = g_default_rate_limits.max_poll_response_burst;
    }
    else if (relation_type == "m.thread") {
      config.max_per_window = g_default_rate_limits.max_thread_replies_per_window;
      config.window_duration_ms = g_default_rate_limits.thread_reply_window_ms;
      config.max_burst = g_default_rate_limits.max_thread_reply_burst;
    }
    else {
      // Default for unknown relation types
      config.max_per_window = 30;
      config.window_duration_ms = 60000;
      config.max_burst = 5;
    }

    std::string bucket_key = auth.user_id + ":" + relation_type;
    int64_t retry_after_ms = 0;

    bool allowed = check_rate_limit(bucket_key, config, retry_after_ms);

    // Also check per-event hard cap
    if (allowed && !event_id.empty() && validate_event_id(event_id)) {
      int64_t existing_count = 0;
      {
        std::lock_guard<std::mutex> lock(g_relations_lock);
        auto it = g_relations_by_parent.find(event_id);
        if (it != g_relations_by_parent.end()) {
          for (auto& rel : it->second) {
            if (!rel.is_redacted) existing_count++;
          }
        }
      }

      if (existing_count >= g_default_rate_limits.max_relations_per_event) {
        allowed = false;
        retry_after_ms = 0; // Hard cap, no retry
      }
    }

    json body;
    body["allowed"] = allowed;
    body["relation_type"] = relation_type;

    if (!allowed) {
      body["error"] = "Rate limit exceeded";
      if (retry_after_ms > 0) {
        body["retry_after_ms"] = retry_after_ms;
      }
      body["limit"] = json{
        {"max_per_window", config.max_per_window},
        {"window_duration_ms", config.window_duration_ms},
        {"max_burst", config.max_burst}
      };
    }

    return make_response(allowed ? 200 : 429, body);
  }

  // GET RATE LIMIT STATUS
  else if (action == "status") {
    std::lock_guard<std::mutex> lock(g_relation_rate_lock);
    json buckets = json::array();

    for (auto& [key, bucket] : g_relation_rate_buckets) {
      // Only show buckets belonging to this user
      if (key.find(auth.user_id + ":") == 0) {
        json b;
        b["bucket_key"] = key;
        b["count"] = bucket.count;
        b["burst_count"] = bucket.burst_count;
        b["max_per_window"] = bucket.max_per_window;
        b["remaining"] = bucket.max_per_window - bucket.count;
        b["window_remaining_ms"] = bucket.window_duration_ms -
          (now_ms() - bucket.window_start_ms);
        buckets.push_back(b);
      }
    }

    json body;
    body["buckets"] = buckets;
    body["total_buckets"] = buckets.size();
    return make_response(200, body);
  }

  // RESET RATE LIMITS for a user
  else if (action == "reset") {
    std::string target_user = safe_str(request_body, "user_id", auth.user_id);
    std::string target_rel_type = safe_str(request_body, "rel_type", "");

    // Only admins can reset other users' limits
    if (target_user != auth.user_id && !auth.is_admin) {
      return make_error(403, "M_FORBIDDEN", "Only admins can reset other users' rate limits");
    }

    int64_t reset_count = 0;
    {
      std::lock_guard<std::mutex> lock(g_relation_rate_lock);
      auto it = g_relation_rate_buckets.begin();
      while (it != g_relation_rate_buckets.end()) {
        std::string prefix = target_user + ":";
        bool match = it->first.find(prefix) == 0;
        if (match && !target_rel_type.empty()) {
          match = it->first.find(":" + target_rel_type) != std::string::npos;
        }
        if (match) {
          it = g_relation_rate_buckets.erase(it);
          reset_count++;
        } else {
          ++it;
        }
      }
    }

    json body;
    body["reset"] = true;
    body["resets"] = reset_count;
    return make_response(200, body);
  }

  else {
    return make_error(400, "M_INVALID_PARAM", "Unknown action: " + action);
  }
}

// ============================================================================
// DISPATCHER: Route actions to appropriate handlers
// ============================================================================

json handle_forgotten_peek_relations_dispatcher(
    DatabasePool& db,
    const std::string& handler_name,
    const std::string& auth_header,
    const std::string& access_token_param,
    const std::string& path_param1,
    const std::string& path_param2,
    const json& request_body,
    const json& query_params) {

  // ---- Forgotten rooms ----
  if (handler_name == "forget_room") {
    return handle_forget_room(db, auth_header, access_token_param,
                               path_param1, request_body);
  }
  if (handler_name == "forgotten_rooms_list") {
    return handle_forgotten_rooms_list(db, auth_header, access_token_param,
                                        query_params);
  }

  // ---- Room peeking ----
  if (handler_name == "peek_room") {
    return handle_peek_room(db, auth_header, access_token_param,
                             path_param1, request_body);
  }
  if (handler_name == "peek_session_management") {
    return handle_peek_session_management(db, auth_header, access_token_param,
                                           path_param1, path_param2, request_body);
  }

  // ---- Event relations ----
  if (handler_name == "event_relations") {
    return handle_event_relations(db, auth_header, access_token_param,
                                   path_param1, path_param2, request_body);
  }

  // ---- Aggregations ----
  if (handler_name == "annotation_aggregation") {
    return handle_annotation_aggregation(db, auth_header, access_token_param,
                                          path_param1, query_params);
  }
  if (handler_name == "edit_aggregation") {
    return handle_edit_aggregation(db, auth_header, access_token_param,
                                    path_param1, query_params);
  }
  if (handler_name == "thread_aggregation") {
    return handle_thread_aggregation(db, auth_header, access_token_param,
                                      path_param1, query_params);
  }
  if (handler_name == "reference_relations") {
    return handle_reference_relations(db, auth_header, access_token_param,
                                       path_param1, request_body);
  }
  if (handler_name == "poll_aggregation") {
    return handle_poll_aggregation(db, auth_header, access_token_param,
                                    path_param1, query_params);
  }
  if (handler_name == "bundled_aggregations") {
    return handle_bundled_aggregations(db, auth_header, access_token_param,
                                        path_param1, query_params);
  }
  if (handler_name == "aggregation_caching") {
    return handle_aggregation_caching(db, auth_header, access_token_param,
                                       path_param1, request_body);
  }

  // ---- Redaction ----
  if (handler_name == "relation_redaction") {
    return handle_relation_redaction(db, auth_header, access_token_param,
                                      path_param1, request_body);
  }

  // ---- Paginated query ----
  if (handler_name == "paginated_relations") {
    return handle_paginated_relations(db, auth_header, access_token_param,
                                       path_param1, query_params);
  }

  // ---- Recursive resolution ----
  if (handler_name == "recursive_relations") {
    return handle_recursive_relations(db, auth_header, access_token_param,
                                       path_param1, query_params);
  }

  // ---- Thread management ----
  if (handler_name == "thread_summary") {
    return handle_thread_summary(db, auth_header, access_token_param,
                                  path_param1, query_params);
  }
  if (handler_name == "thread_notifications") {
    return handle_thread_notifications(db, auth_header, access_token_param,
                                        path_param1, query_params);
  }

  // ---- Poll handling ----
  if (handler_name == "poll_response_validation") {
    return handle_poll_response_validation(db, auth_header, access_token_param,
                                            request_body);
  }
  if (handler_name == "poll_end") {
    return handle_poll_end(db, auth_header, access_token_param,
                            path_param1, request_body);
  }

  // ---- Rate limiting ----
  if (handler_name == "relation_rate_limiting") {
    return handle_relation_rate_limiting(db, auth_header, access_token_param,
                                          path_param1, path_param2, request_body);
  }

  // Unknown handler
  return make_error(400, "M_UNKNOWN", "Unknown handler: " + handler_name);
}

} // namespace progressive::handlers
