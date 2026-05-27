// ============================================================================
// rest_endpoints_batch2.cpp - Matrix REST servlets batch 2 (3500+ lines)
// ============================================================================
// Implements 19 Matrix REST servlets in namespace progressive::
//
//  1. RoomDirectoryServlet    - PUT/DELETE/GET room alias, GET/POST public rooms
//  2. ProfileDisplayNameServlet - GET/PUT displayname
//  3. ProfileAvatarUrlServlet - GET/PUT avatar_url
//  4. ProfileServlet          - GET profile, GET/PUT profiles batch
//  5. PresenceStatusServlet   - PUT presence status
//  6. PresenceGetServlet      - GET presence for user
//  7. PresenceListServlet     - GET/POST presence list (buddy list)
//  8. TypingNotificationServlet - PUT typing notification with timeout
//  9. ReceiptServlet          - POST read receipt with thread_id
// 10. RoomUpgradeBatchServlet - POST upgrade room
// 11. RoomAliasCrudServlet    - Full CRUD for room aliases with validation
// 12. JoinedRoomsServlet      - GET joined rooms list
// 13. JoinedMembersServlet    - GET joined room members
// 14. RoomMessagesServlet     - GET room messages with pagination
// 15. RoomStateServlet        - GET room state, GET state event, PUT state event
// 16. RoomMembersServlet      - GET room members with membership filter
// 17. KickServlet             - POST kick user from room
// 18. BanServlet              - POST ban user from room
// 19. UnbanServlet            - POST unban user from room
// 20. InviteServlet           - POST invite user with reason
// 21. RedactServlet           - PUT redact event with reason
// 22. SendEventServlet        - PUT send message event to room
//
// Each servlet inherits BaseRestServlet with full auth check, parameter
// extraction, DB operations via DatabasePool/runInteraction, JSON response,
// and comprehensive error handling. Uses storage stores from
// progressive/storage/databases/main/*.hpp
// ============================================================================

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <regex>
#include <set>
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

#include "progressive/rest/rest_base.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/registration.hpp"

namespace progressive {

using json = nlohmann::json;
using rest::BaseRestServlet;
using rest::ClientV1RestServlet;
using rest::HttpRequest;
using rest::HttpResponse;
using rest::AuthHelper;
using rest::Requester;
using storage::DatabasePool;
using storage::DirectoryStore;
using storage::ProfileStore;
using storage::PresenceStore;
using storage::ReceiptsStore;
using storage::RoomWorkerStore;
using storage::RoomMemberWorkerStore;
using storage::RoomMemberStore;
using storage::StateStore;
using storage::RegistrationStore;
using storage::RoomMember;
using storage::PresenceState;
using storage::UserPresence;
using storage::UserProfile;
using storage::ReadReceipt;

// ============================================================================
// Anonymous namespace - Internal utility helpers
// ============================================================================

namespace {

// ---- Time helpers ----

int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// ---- Token / ID generation ----

std::string generate_token(int len = 64) {
  static const char kChars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 kRng(
      std::chrono::steady_clock::now().time_since_epoch().count());
  std::uniform_int_distribution<> dist(0, 61);
  std::string result(len, 'A');
  for (auto& c : result) c = kChars[dist(kRng)];
  return result;
}

std::string generate_event_id() {
  static const char kChars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  static thread_local std::mt19937 kRng(
      std::chrono::steady_clock::now().time_since_epoch().count() +
      std::hash<std::thread::id>{}(std::this_thread::get_id()));
  std::uniform_int_distribution<> dist(0, 61);
  std::string result(18, 'A');
  for (auto& c : result) c = kChars[dist(kRng)];
  return result;
}

// ---- String helpers ----

std::string to_lower(std::string s) {
  for (auto& c : s)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

std::string strip_alias_server(const std::string& alias) {
  if (alias.empty()) return alias;
  std::string a = alias;
  if (a[0] == '#') a = a.substr(1);
  auto colon = a.find(':');
  if (colon != std::string::npos) a = a.substr(0, colon);
  return a;
}

// ---- Path param extraction ----

std::string extract_path_param(const HttpRequest& req, const std::string& name) {
  auto it = req.path_params.find(name);
  if (it != req.path_params.end()) return it->second;
  return "";
}

// ---- Validation helpers ----

const std::string kServerName = "localhost";

bool is_valid_user_id(const std::string& s) {
  return s.size() > 2 && s[0] == '@' && s.find(':') != std::string::npos;
}

bool is_valid_room_id(const std::string& s) {
  return s.size() > 2 && s[0] == '!' && s.find(':') != std::string::npos;
}

bool is_valid_alias(const std::string& s) {
  return s.size() > 2 && s[0] == '#' && s.find(':') != std::string::npos;
}

// Validate alias format more strictly: #localpart:server
bool is_valid_alias_format(const std::string& alias) {
  if (alias.empty() || alias[0] != '#') return false;
  auto colon = alias.find(':');
  if (colon == std::string::npos || colon == 1 || colon >= alias.size() - 1)
    return false;
  // localpart: must match [a-z0-9._=-]+ as per spec
  std::string localpart = alias.substr(1, colon - 1);
  if (localpart.empty()) return false;
  for (char ch : localpart) {
    if (!(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') &&
        !(ch >= '0' && ch <= '9') && ch != '.' && ch != '_' &&
        ch != '=' && ch != '-') {
      return false;
    }
  }
  return true;
}

// Validate display name (not empty, no leading/trailing whitespace abuse)
bool is_valid_displayname(const std::string& name) {
  if (name.empty()) return true; // empty is allowed (clears it)
  // Max 256 chars per spec
  if (name.size() > 256) return false;
  return true;
}

// Validate avatar URL (must be mxc:// or empty)
bool is_valid_avatar_url(const std::string& url) {
  if (url.empty()) return true;
  if (url.size() > 2000) return false;
  return starts_with(url, "mxc://") || url == "NONE";
}

// Validate presence state
bool is_valid_presence_state(const std::string& state) {
  return state == "online" || state == "offline" ||
         state == "unavailable" || state == "busy";
}

// ---- Auth helper ----

Requester require_auth(const HttpRequest& req, DatabasePool& db) {
  AuthHelper auth(db);
  return auth.require_auth(req);
}

// ---- Membership check ----

bool check_room_membership(DatabasePool& db, const std::string& user_id,
                            const std::string& room_id,
                            const std::string& required_membership = "join") {
  bool result = false;
  db.runInteraction("check_membership",
      [&](storage::LoggingTransaction& txn) {
        txn.execute(
            "SELECT membership FROM local_current_membership "
            "WHERE user_id=? AND room_id=?",
            {user_id, room_id});
        auto r = txn.fetchone();
        if (r && r->at(0).value) {
          result = (*r->at(0).value == required_membership);
        }
      });
  return result;
}

// Get room version from rooms table
std::string get_room_version(DatabasePool& db, const std::string& room_id) {
  std::string version = "1";
  db.runInteraction("get_room_version",
      [&](storage::LoggingTransaction& txn) {
        txn.execute(
            "SELECT room_version FROM rooms WHERE room_id=?",
            {room_id});
        auto r = txn.fetchone();
        if (r && r->at(0).value) {
          version = *r->at(0).value;
        }
      });
  return version;
}

// Check server admin status
bool is_user_admin(DatabasePool& db, const std::string& user_id) {
  bool result = false;
  db.runInteraction("is_admin",
      [&](storage::LoggingTransaction& txn) {
        txn.execute(
            "SELECT admin FROM users WHERE name=? AND admin=1",
            {user_id});
        auto r = txn.fetchone();
        result = (r != std::nullopt);
      });
  return result;
}

// ---- Power level check ----

// Check if user has a required power level for a given event type
bool check_power_level(DatabasePool& db, const std::string& room_id,
                        const std::string& user_id,
                        const std::string& event_type,
                        int default_required) {
  bool can = false;
  db.runInteraction("check_pl",
      [&](storage::LoggingTransaction& txn) {
        txn.execute(
            "SELECT e.content FROM current_state_events cs "
            "JOIN events e ON cs.event_id=e.event_id "
            "WHERE cs.room_id=? AND cs.type='m.room.power_levels'",
            {room_id});
        auto plrow = txn.fetchone();
        if (plrow && plrow->at(0).value) {
          try {
            json pl = json::parse(*plrow->at(0).value);
            int required = pl.value("events", json::object())
                               .value(event_type, default_required);
            int user_pl = pl.value("users", json::object())
                              .value(user_id,
                                     pl.value("users_default", 0));
            can = (user_pl >= required);
          } catch (...) {
            can = false;
          }
        } else {
          // No PL event: only creator has power
          txn.execute(
              "SELECT creator FROM rooms WHERE room_id=? AND creator=?",
              {room_id, user_id});
          auto cr = txn.fetchone();
          can = (cr != std::nullopt);
        }
      });
  return can;
}

// ---- Event persistence helpers ----

void persist_event(storage::LoggingTransaction& txn,
                    const std::string& event_id, const std::string& room_id,
                    const std::string& type, const std::string& sender,
                    const std::string& state_key, const json& content,
                    int64_t depth, int64_t stream_ordering, int64_t ts,
                    bool is_outlier = false, bool is_state = true,
                    const std::string& room_version = "10") {
  txn.execute(
      "INSERT INTO events "
      "(event_id,room_id,type,sender,state_key,membership,"
      "depth,origin_server_ts,stream_ordering,replaces_state,"
      "received_ts,topological_ordering,processed,outlier,"
      "rejects_rejected,rejected,is_state,is_current_state,"
      "has_unsafe_url,origin,redacts,origin_server,"
      "content,auth_events,unsigned,room_version,format_version) "
      "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
      {event_id, room_id, type, sender, state_key, "",
       depth, ts, stream_ordering, "",
       ts, depth, (int64_t)1, is_outlier ? (int64_t)1 : (int64_t)0,
       (int64_t)0, (int64_t)0, is_state ? (int64_t)1 : (int64_t)0,
       (int64_t)1, (int64_t)0, "", "", "",
       content.dump(), "{}", "{}", room_version, (int64_t)0});

  txn.execute(
      "INSERT INTO event_json (event_id,room_id,internal_metadata,content,format_version) "
      "VALUES (?,?,?,?,?)",
      {event_id, room_id, "{}", content.dump(), (int64_t)1});

  if (is_state && !state_key.empty()) {
    txn.execute(
        "INSERT INTO current_state_events (event_id,room_id,type,state_key) "
        "VALUES (?,?,?,?) ON CONFLICT(room_id,type,state_key) "
        "DO UPDATE SET event_id=excluded.event_id",
        {event_id, room_id, type, state_key});
  }
}

void insert_membership(storage::LoggingTransaction& txn,
                        const std::string& event_id,
                        const std::string& room_id,
                        const std::string& user_id,
                        const std::string& sender,
                        const std::string& membership) {
  txn.execute(
      "INSERT INTO room_memberships "
      "(event_id,room_id,user_id,sender,membership,content,"
      "membership_event_id,display_name,avatar_url) "
      "VALUES (?,?,?,?,?,'{}',?,'','')",
      {event_id, room_id, user_id, sender, membership, event_id});
  txn.execute(
      "INSERT INTO local_current_membership "
      "(room_id,user_id,event_id,membership) "
      "VALUES (?,?,?,?) ON CONFLICT(user_id,room_id) "
      "DO UPDATE SET event_id=excluded.event_id,membership=excluded.membership",
      {room_id, user_id, event_id, membership});
}

int64_t get_max_stream_ordering(DatabasePool& db) {
  int64_t result = 0;
  db.runInteraction("max_stream",
      [&](storage::LoggingTransaction& txn) {
        txn.execute("SELECT COALESCE(MAX(stream_ordering),0) FROM events");
        auto r = txn.fetchone();
        if (r && r->at(0).value) {
          result = std::stoll(*r->at(0).value);
        }
      });
  return result;
}

int64_t get_next_stream_id(storage::LoggingTransaction& txn) {
  txn.execute("SELECT COALESCE(MAX(stream_ordering),0)+1 FROM events");
  auto r = txn.fetchone();
  if (r && r->at(0).value) return std::stoll(*r->at(0).value);
  return 1;
}

// ---- Get default power levels ----

json get_default_pl(const std::string& user_id) {
  json pl;
  pl["ban"] = 50;
  pl["invite"] = 0;
  pl["kick"] = 50;
  pl["redact"] = 50;
  pl["events_default"] = 0;
  pl["state_default"] = 50;
  pl["users_default"] = 0;
  pl["users"] = json::object();
  pl["users"][user_id] = 100;
  pl["events"] = json::object();
  pl["events"]["m.room.name"] = 50;
  pl["events"]["m.room.power_levels"] = 100;
  pl["events"]["m.room.history_visibility"] = 100;
  pl["events"]["m.room.canonical_alias"] = 50;
  pl["events"]["m.room.avatar"] = 50;
  pl["events"]["m.room.tombstone"] = 100;
  pl["events"]["m.room.server_acl"] = 100;
  pl["events"]["m.room.encryption"] = 100;
  return pl;
}

}  // anonymous namespace

// ============================================================================
// 1. RoomDirectoryServlet
// ============================================================================
// Endpoints:
//   PUT    /_matrix/client/v3/directory/room/{roomAlias}  - Create alias
//   DELETE /_matrix/client/v3/directory/room/{roomAlias}  - Delete alias
//   GET    /_matrix/client/v3/directory/room/{roomAlias}  - Resolve alias
//   GET    /_matrix/client/v3/publicRooms                  - List public rooms
//   POST   /_matrix/client/v3/publicRooms                  - Filter public rooms (server filter)
// ============================================================================

class RoomDirectoryServlet : public ClientV1RestServlet {
public:
  explicit RoomDirectoryServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/directory/room/{roomAlias}",
      "/_matrix/client/v1/directory/room/{roomAlias}",
      "/_matrix/client/v3/directory/list/room/{roomId}",
      "/_matrix/client/v1/directory/list/room/{roomId}",
      "/_matrix/client/v3/publicRooms",
      "/_matrix/client/v1/publicRooms",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "PUT", "DELETE", "POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string path = req.path;

      // ---- Public rooms listing ----
      if (path.find("/publicRooms") != std::string::npos) {
        if (req.method == "GET") return handle_get_public_rooms(req);
        if (req.method == "POST") return handle_post_public_rooms(req);
        return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                                "Method not allowed");
      }

      // ---- Directory listing visibility ----
      if (path.find("/directory/list/room/") != std::string::npos) {
        std::string room_id = extract_path_param(req, "roomId");
        if (req.method == "PUT") return handle_set_visibility(req, room_id);
        if (req.method == "GET") return handle_get_visibility(req, room_id);
        return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                                "Method not allowed");
      }

      // ---- Alias directory ----
      std::string raw_alias = extract_path_param(req, "roomAlias");
      if (raw_alias.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room alias");

      // Normalize alias to have # prefix and :server suffix
      std::string alias;
      if (raw_alias[0] != '#')
        alias = "#" + raw_alias;
      else
        alias = raw_alias;
      if (alias.find(':') == std::string::npos)
        alias += ":" + kServerName;

      if (req.method == "GET") return handle_get_alias(req, alias);
      if (req.method == "PUT") return handle_put_alias(req, alias);
      if (req.method == "DELETE") return handle_delete_alias(req, alias);

      return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                              "Method not allowed");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  // ---- Alias handlers ----

  HttpResponse handle_get_alias(const HttpRequest& req,
                                 const std::string& alias) {
    try {
      DirectoryStore dir(db_);
      auto room_id = dir.get_room_id(alias);
      if (!room_id) {
        // Try without server suffix
        std::string bare = alias;
        auto colon = bare.rfind(':');
        if (colon != std::string::npos) {
          bare = bare.substr(0, colon);
          auto room_id2 = dir.get_room_id(bare + ":" + kServerName);
          if (room_id2) room_id = room_id2;
        }
      }
      if (!room_id) {
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "Room alias not found");
      }
      auto servers = dir.get_servers_for_alias(alias);
      json resp;
      resp["room_id"] = *room_id;
      resp["servers"] = servers.empty()
                             ? json::array({kServerName})
                             : json(servers);
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                              "Room alias not found");
    }
  }

  HttpResponse handle_put_alias(const HttpRequest& req,
                                 const std::string& alias) {
    try {
      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      std::string room_id = body.value("room_id", "");
      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room_id");

      if (!is_valid_room_id(room_id))
        return BaseRestServlet::error_response(400, "M_INVALID_PARAM",
                                                "Invalid room ID format");

      // Validate alias format
      if (!is_valid_alias_format(alias))
        return BaseRestServlet::error_response(400, "M_INVALID_PARAM",
                                                "Invalid room alias format");

      // Check room exists and user has permission
      bool can_set = false;
      db_.runInteraction("alias_put_auth",
          [&](storage::LoggingTransaction& txn) {
            txn.execute("SELECT 1 FROM rooms WHERE room_id=?",
                         {room_id});
            auto r = txn.fetchone();
            if (!r) return;

            txn.execute(
                "SELECT membership FROM local_current_membership "
                "WHERE user_id=? AND room_id=?",
                {requester.user_id, room_id});
            auto m = txn.fetchone();
            if (m && m->at(0).value) {
              can_set = (*m->at(0).value == "join");
            }
            if (!can_set) return;

            // Check power levels
            txn.execute(
                "SELECT e.content FROM current_state_events cs "
                "JOIN events e ON cs.event_id=e.event_id "
                "WHERE cs.room_id=? AND cs.type='m.room.power_levels'",
                {room_id});
            auto plrow = txn.fetchone();
            if (plrow && plrow->at(0).value) {
              try {
                json pl = json::parse(*plrow->at(0).value);
                int required = pl.value("events", json::object())
                                   .value("m.room.canonical_alias", 50);
                int user_pl = pl.value("users", json::object())
                                  .value(requester.user_id,
                                         pl.value("users_default", 0));
                if (user_pl < required) can_set = false;
              } catch (...) {}
            }
          });

      if (!can_set)
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to set room aliases");

      DirectoryStore dir(db_);
      auto existing = dir.get_room_id(alias);
      if (existing && *existing != room_id) {
        return BaseRestServlet::error_response(409, "M_UNKNOWN",
                                                "Room alias already in use");
      }

      // Optional servers list
      std::vector<std::string> servers = {kServerName};
      if (body.contains("servers") && body["servers"].is_array()) {
        servers.clear();
        for (auto& s : body["servers"]) {
          if (s.is_string()) servers.push_back(s.get<std::string>());
        }
      }

      dir.create_alias(alias, room_id, requester.user_id, servers);
      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  HttpResponse handle_delete_alias(const HttpRequest& req,
                                    const std::string& alias) {
    try {
      auto requester = require_auth(req, db_);
      DirectoryStore dir(db_);

      auto room_id = dir.get_room_id(alias);
      if (!room_id) {
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "Room alias not found");
      }

      // Permission check: creator or room admin
      bool can_delete = false;
      auto creator = dir.get_alias_creator(alias);
      if (creator && *creator == requester.user_id) {
        can_delete = true;
      }
      if (!can_delete) {
        can_delete = check_power_level(db_, *room_id, requester.user_id,
                                        "m.room.canonical_alias", 50);
      }
      // Fallback: server admin
      if (!can_delete) {
        can_delete = is_user_admin(db_, requester.user_id);
      }

      if (!can_delete) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to delete this alias");
      }

      dir.delete_alias(alias);
      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  // ---- Visibility handlers ----

  HttpResponse handle_get_visibility(const HttpRequest& req,
                                      const std::string& room_id) {
    try {
      DirectoryStore dir(db_);
      auto vis = dir.get_room_visibility(room_id);
      json resp;
      resp["visibility"] = vis.value_or("private");
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                              "Room not found");
    }
  }

  HttpResponse handle_set_visibility(const HttpRequest& req,
                                      const std::string& room_id) {
    try {
      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      std::string visibility = body.value("visibility", "");
      if (visibility != "public" && visibility != "private") {
        return BaseRestServlet::error_response(
            400, "M_INVALID_PARAM",
            "visibility must be 'public' or 'private'");
      }

      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You must be a member of the room");
      }

      DirectoryStore dir(db_);
      dir.set_room_visibility(room_id, visibility);
      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  // ---- Public rooms handlers ----

  HttpResponse handle_get_public_rooms(const HttpRequest& req) {
    try {
      auto requester = require_auth(req, db_);

      auto limit_opt = BaseRestServlet::parse_integer(req, "limit");
      int64_t limit = limit_opt.value_or(50);
      if (limit < 1) limit = 1;
      if (limit > 100) limit = 100;

      auto since_opt = BaseRestServlet::parse_string(req, "since");
      std::string since = since_opt.value_or("");
      int64_t since_val = 0;
      if (!since.empty()) {
        try { since_val = std::stoll(since); } catch (...) {}
      }

      auto server_opt = BaseRestServlet::parse_string(req, "server");
      std::string server = server_opt.value_or("");

      auto search_opt = BaseRestServlet::parse_string(req, "search_term");
      std::string search_term = search_opt.value_or("");

      bool include_all = BaseRestServlet::parse_boolean(
          req, "include_all_networks", false);

      auto network_opt = BaseRestServlet::parse_string(req, "network");
      std::string network = network_opt.value_or("");

      DirectoryStore dir(db_);
      auto rooms = dir.get_public_rooms(server, limit, since_val,
                                         search_term, network, include_all);

      json chunk = json::array();
      for (auto& room : rooms) {
        json entry;
        entry["room_id"] = room.room_id;
        entry["name"] = room.name;
        entry["topic"] = room.topic;
        entry["num_joined_members"] = room.num_joined_members;
        entry["world_readable"] = room.world_readable;
        if (room.canonical_alias)
          entry["canonical_alias"] = *room.canonical_alias;
        if (room.avatar_url)
          entry["avatar_url"] = *room.avatar_url;
        if (!room.room_type.empty())
          entry["room_type"] = room.room_type;
        chunk.push_back(entry);
      }

      int64_t total = static_cast<int64_t>(rooms.size());
      json resp;
      resp["chunk"] = chunk;
      resp["total_room_count_estimate"] = total;
      if (!rooms.empty()) {
        resp["next_batch"] = std::to_string(since_val + limit);
        if (since_val > 0)
          resp["prev_batch"] = std::to_string(since_val - limit);
      }
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  HttpResponse handle_post_public_rooms(const HttpRequest& req) {
    try {
      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      int64_t limit = body.value("limit", 50);
      if (limit < 1) limit = 1;
      if (limit > 100) limit = 100;

      std::string since = body.value("since", "");
      int64_t since_val = 0;
      if (!since.empty()) {
        try { since_val = std::stoll(since); } catch (...) {}
      }

      // Extract server filter from body
      std::string server_filter = body.value("server", "");
      bool include_all = body.value("include_all_networks", false);
      std::string network = body.value("third_party_instance_id", "");

      // Extract search term from filter object
      std::string search_term;
      if (body.contains("filter") && body["filter"].is_object()) {
        search_term = body["filter"].value("generic_search_term", "");
      }

      DirectoryStore dir(db_);
      auto rooms = dir.get_public_rooms(server_filter, limit, since_val,
                                         search_term, network, include_all);

      json chunk = json::array();
      int64_t total_estimate = 0;
      db_.runInteraction("pub_count",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT COUNT(*) FROM room_stats_state "
                "WHERE joined_members>0");
            auto c = txn.fetchone();
            if (c && c->at(0).value)
              total_estimate = std::stoll(*c->at(0).value);
          });

      for (auto& room : rooms) {
        json entry;
        entry["room_id"] = room.room_id;
        entry["name"] = room.name;
        entry["topic"] = room.topic;
        entry["num_joined_members"] = room.num_joined_members;
        entry["world_readable"] = room.world_readable;
        if (room.canonical_alias)
          entry["canonical_alias"] = *room.canonical_alias;
        if (room.avatar_url)
          entry["avatar_url"] = *room.avatar_url;
        if (!room.room_type.empty())
          entry["room_type"] = room.room_type;
        chunk.push_back(entry);
      }

      json resp;
      resp["chunk"] = chunk;
      resp["total_room_count_estimate"] =
          total_estimate > 0 ? total_estimate : (int64_t)rooms.size();
      if (!rooms.empty()) {
        resp["next_batch"] = std::to_string(since_val + limit);
        if (since_val > 0)
          resp["prev_batch"] = std::to_string(since_val - limit);
      }
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 2. ProfileDisplayNameServlet
// ============================================================================
// Endpoints:
//   GET /_matrix/client/v3/profile/{userId}/displayname
//   PUT /_matrix/client/v3/profile/{userId}/displayname
// ============================================================================

class ProfileDisplayNameServlet : public ClientV1RestServlet {
public:
  explicit ProfileDisplayNameServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/profile/{userId}/displayname",
      "/_matrix/client/v1/profile/{userId}/displayname",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "PUT"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string user_id = extract_path_param(req, "userId");
      if (user_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing user ID");

      // Normalize user ID to have @ prefix
      if (user_id[0] != '@') user_id = "@" + user_id;
      if (user_id.find(':') == std::string::npos)
        user_id += ":" + kServerName;

      if (req.method == "GET") return handle_get_displayname(req, user_id);
      if (req.method == "PUT") return handle_put_displayname(req, user_id);

      return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                              "Method not allowed");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  HttpResponse handle_get_displayname(const HttpRequest& req,
                                        const std::string& user_id) {
    try {
      require_auth(req, db_);

      ProfileStore profile(db_);
      auto p = profile.get_profile(user_id);
      if (!p || !p->display_name) {
        // User exists check
        bool exists = false;
        db_.runInteraction("user_exists",
            [&](storage::LoggingTransaction& txn) {
              txn.execute("SELECT 1 FROM users WHERE name=?",
                           {user_id});
              auto r = txn.fetchone();
              exists = (r != std::nullopt);
            });
        if (!exists) {
          return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                  "User not found");
        }
        // Return empty displayname
        json resp;
        resp["displayname"] = "";
        return BaseRestServlet::success_response(resp);
      }

      json resp;
      resp["displayname"] = *p->display_name;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                              "Profile not found");
    }
  }

  HttpResponse handle_put_displayname(const HttpRequest& req,
                                        const std::string& user_id) {
    try {
      auto requester = require_auth(req, db_);

      // Only the user themselves or an admin can set display name
      if (requester.user_id != user_id &&
          !is_user_admin(db_, requester.user_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "Cannot set another user's display name");
      }

      auto body = BaseRestServlet::parse_json_body(req);
      std::string displayname = body.value("displayname", "");

      if (!is_valid_displayname(displayname)) {
        return BaseRestServlet::error_response(
            400, "M_INVALID_PARAM",
            "Invalid display name (max 256 characters)");
      }

      ProfileStore profile(db_);
      profile.set_display_name(user_id, displayname);

      // Update user directory
      if (!displayname.empty()) {
        profile.add_to_user_directory(user_id, displayname, std::nullopt);
      }

      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 3. ProfileAvatarUrlServlet
// ============================================================================
// Endpoints:
//   GET /_matrix/client/v3/profile/{userId}/avatar_url
//   PUT /_matrix/client/v3/profile/{userId}/avatar_url
// ============================================================================

class ProfileAvatarUrlServlet : public ClientV1RestServlet {
public:
  explicit ProfileAvatarUrlServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/profile/{userId}/avatar_url",
      "/_matrix/client/v1/profile/{userId}/avatar_url",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "PUT"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string user_id = extract_path_param(req, "userId");
      if (user_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing user ID");

      if (user_id[0] != '@') user_id = "@" + user_id;
      if (user_id.find(':') == std::string::npos)
        user_id += ":" + kServerName;

      if (req.method == "GET") return handle_get_avatar(req, user_id);
      if (req.method == "PUT") return handle_put_avatar(req, user_id);

      return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                              "Method not allowed");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  HttpResponse handle_get_avatar(const HttpRequest& req,
                                   const std::string& user_id) {
    try {
      require_auth(req, db_);

      ProfileStore profile(db_);
      auto p = profile.get_profile(user_id);
      if (!p || !p->avatar_url) {
        json resp;
        resp["avatar_url"] = "";
        return BaseRestServlet::success_response(resp);
      }

      json resp;
      resp["avatar_url"] = *p->avatar_url;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                              "Profile not found");
    }
  }

  HttpResponse handle_put_avatar(const HttpRequest& req,
                                   const std::string& user_id) {
    try {
      auto requester = require_auth(req, db_);

      if (requester.user_id != user_id &&
          !is_user_admin(db_, requester.user_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "Cannot set another user's avatar URL");
      }

      auto body = BaseRestServlet::parse_json_body(req);
      std::string avatar_url = body.value("avatar_url", "");

      if (!is_valid_avatar_url(avatar_url)) {
        return BaseRestServlet::error_response(
            400, "M_INVALID_PARAM",
            "Invalid avatar URL (must be mxc:// or empty)");
      }

      ProfileStore profile(db_);
      profile.set_avatar_url(user_id, avatar_url);

      // Update user directory avatar
      auto p = profile.get_profile(user_id);
      if (p) {
        profile.update_user_directory_profile(
            user_id, p->display_name.value_or(""),
            avatar_url.empty() ? std::nullopt
                               : std::make_optional(avatar_url));
      }

      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 4. ProfileServlet - full profile
// ============================================================================
// Endpoints:
//   GET  /_matrix/client/v3/profile/{userId}
//   POST /_matrix/client/v3/profile/batch - batch query profiles
// ============================================================================

class ProfileServlet : public ClientV1RestServlet {
public:
  explicit ProfileServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/profile/{userId}",
      "/_matrix/client/v1/profile/{userId}",
      "/_matrix/client/v3/profile/batch",
      "/_matrix/client/v1/profile/batch",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST", "PUT"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string path = req.path;

      // Batch profile query
      if (path.find("/profile/batch") != std::string::npos) {
        if (req.method == "POST") return handle_batch_profiles(req);
        return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                                "Method not allowed");
      }

      std::string user_id = extract_path_param(req, "userId");
      if (user_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing user ID");

      if (user_id[0] != '@') user_id = "@" + user_id;
      if (user_id.find(':') == std::string::npos)
        user_id += ":" + kServerName;

      if (req.method == "GET") return handle_get_profile(req, user_id);
      if (req.method == "PUT") return handle_put_profile(req, user_id);

      return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                              "Method not allowed");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  HttpResponse handle_get_profile(const HttpRequest& req,
                                    const std::string& user_id) {
    try {
      require_auth(req, db_);

      ProfileStore profile(db_);
      auto p = profile.get_profile(user_id);

      json resp;
      if (p) {
        if (p->display_name)
          resp["displayname"] = *p->display_name;
        if (p->avatar_url)
          resp["avatar_url"] = *p->avatar_url;
      }
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                              "Profile not found");
    }
  }

  HttpResponse handle_put_profile(const HttpRequest& req,
                                    const std::string& user_id) {
    try {
      auto requester = require_auth(req, db_);

      if (requester.user_id != user_id &&
          !is_user_admin(db_, requester.user_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "Cannot update another user's profile");
      }

      auto body = BaseRestServlet::parse_json_body(req);

      std::string displayname = body.value("displayname", "");
      std::string avatar_url = body.value("avatar_url", "");

      if (!displayname.empty() && !is_valid_displayname(displayname)) {
        return BaseRestServlet::error_response(
            400, "M_INVALID_PARAM", "Invalid display name");
      }
      if (!avatar_url.empty() && !is_valid_avatar_url(avatar_url)) {
        return BaseRestServlet::error_response(
            400, "M_INVALID_PARAM", "Invalid avatar URL");
      }

      ProfileStore profile(db_);
      profile.set_profile(user_id, displayname, avatar_url);

      // Update user directory
      if (!displayname.empty()) {
        profile.update_user_directory_profile(
            user_id, displayname,
            avatar_url.empty() ? std::nullopt
                               : std::make_optional(avatar_url));
      }

      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  HttpResponse handle_batch_profiles(const HttpRequest& req) {
    try {
      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      if (!body.contains("user_ids") || !body["user_ids"].is_array()) {
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing user_ids array");
      }

      std::set<std::string> user_ids;
      for (auto& uid : body["user_ids"]) {
        if (uid.is_string()) {
          std::string u = uid.get<std::string>();
          if (u[0] != '@') u = "@" + u;
          if (u.find(':') == std::string::npos)
            u += ":" + kServerName;
          user_ids.insert(u);
        }
      }

      if (user_ids.size() > 100) {
        return BaseRestServlet::error_response(
            400, "M_INVALID_PARAM",
            "Too many user IDs (max 100)");
      }

      ProfileStore profile(db_);
      auto profiles = profile.get_profiles(user_ids);

      json resp = json::object();
      for (auto& uid : user_ids) {
        json entry = json::object();
        auto it = profiles.find(uid);
        if (it != profiles.end()) {
          if (it->second.display_name)
            entry["displayname"] = *it->second.display_name;
          if (it->second.avatar_url)
            entry["avatar_url"] = *it->second.avatar_url;
        }
        resp[uid] = entry;
      }

      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 5. PresenceStatusServlet
// ============================================================================
// Endpoints:
//   PUT /_matrix/client/v3/presence/{userId}/status
//   GET /_matrix/client/v3/presence/{userId}/status
// ============================================================================

class PresenceStatusServlet : public ClientV1RestServlet {
public:
  explicit PresenceStatusServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/presence/{userId}/status",
      "/_matrix/client/v1/presence/{userId}/status",
    };
  }

  std::vector<std::string> methods() const override {
    return {"PUT", "GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string user_id = extract_path_param(req, "userId");
      if (user_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing user ID");

      if (user_id[0] != '@') user_id = "@" + user_id;
      if (user_id.find(':') == std::string::npos)
        user_id += ":" + kServerName;

      if (req.method == "PUT") return handle_put_presence(req, user_id);
      if (req.method == "GET") return handle_get_presence(req, user_id);

      return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                              "Method not allowed");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  HttpResponse handle_put_presence(const HttpRequest& req,
                                     const std::string& user_id) {
    try {
      auto requester = require_auth(req, db_);

      // Only set own presence or admin override
      if (requester.user_id != user_id &&
          !is_user_admin(db_, requester.user_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "Cannot set another user's presence");
      }

      auto body = BaseRestServlet::parse_json_body(req);

      std::string presence_state = body.value("presence", "online");
      if (!is_valid_presence_state(presence_state)) {
        return BaseRestServlet::error_response(
            400, "M_INVALID_PARAM",
            "Invalid presence state. Use: online, offline, unavailable, busy");
      }

      std::string status_msg = body.value("status_msg", "");

      PresenceStore pres(db_);
      int64_t ts = now_ms();
      bool currently_active =
          (presence_state == "online" || presence_state == "busy");

      pres.set_presence_state(user_id, presence_state, status_msg,
                                ts, currently_active);

      // If going offline, mark sync timestamp
      if (presence_state == "offline") {
        pres.update_presence_last_sync(user_id, ts);
      }

      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  HttpResponse handle_get_presence(const HttpRequest& req,
                                     const std::string& user_id) {
    try {
      require_auth(req, db_);

      PresenceStore pres(db_);
      auto presence = pres.get_presence(user_id);

      json resp;
      if (presence) {
        resp["presence"] = presence->state.state;
        resp["last_active_ago"] =
            presence->state.last_active_ts > 0
                ? (now_ms() - presence->state.last_active_ts)
                : 0;
        if (presence->state.status_msg)
          resp["status_msg"] = *presence->state.status_msg;
        resp["currently_active"] = presence->state.currently_active;
      } else {
        resp["presence"] = "offline";
        resp["last_active_ago"] = 0;
        resp["currently_active"] = false;
      }

      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 6. PresenceGetServlet
// ============================================================================
// Endpoints:
//   GET /_matrix/client/v3/presence/list/{userId}
// ============================================================================

class PresenceGetServlet : public ClientV1RestServlet {
public:
  explicit PresenceGetServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/presence/list/{userId}",
      "/_matrix/client/v1/presence/list/{userId}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string user_id = extract_path_param(req, "userId");
      if (user_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing user ID");

      if (user_id[0] != '@') user_id = "@" + user_id;
      if (user_id.find(':') == std::string::npos)
        user_id += ":" + kServerName;

      auto requester = require_auth(req, db_);

      // Get the observer's presence list (who they track)
      PresenceStore pres(db_);

      // Get all users in presence list (accepted + pending)
      auto pending = pres.get_presence_list_pending(requester.user_id);
      auto observers = pres.get_presence_list_observers(requester.user_id);

      // Combine into set of all observed users
      std::set<std::string> all_tracked;
      for (auto& p : pending) all_tracked.insert(p);
      for (auto& o : observers) all_tracked.insert(o);

      // Now get those users' presence state
      auto presence_map = pres.get_presence_for_users(all_tracked);

      json result = json::array();
      for (auto& uid : all_tracked) {
        json entry;
        entry["user_id"] = uid;
        auto it = presence_map.find(uid);
        if (it != presence_map.end()) {
          entry["presence"] = it->second.state.state;
          entry["last_active_ago"] =
              it->second.state.last_active_ts > 0
                  ? (now_ms() - it->second.state.last_active_ts)
                  : 0;
          if (it->second.state.status_msg)
            entry["status_msg"] = *it->second.state.status_msg;
          entry["currently_active"] = it->second.state.currently_active;
        } else {
          entry["presence"] = "offline";
          entry["last_active_ago"] = 0;
          entry["currently_active"] = false;
        }
        result.push_back(entry);
      }

      return BaseRestServlet::success_response(result);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 7. PresenceListServlet
// ============================================================================
// Endpoints:
//   GET  /_matrix/client/v3/presence/list
//   POST /_matrix/client/v3/presence/list/{userId} - invite/accept/deny
// ============================================================================

class PresenceListServlet : public ClientV1RestServlet {
public:
  explicit PresenceListServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/presence/list",
      "/_matrix/client/v1/presence/list",
      "/_matrix/client/v3/presence/list/{userId}",
      "/_matrix/client/v1/presence/list/{userId}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string target_user = extract_path_param(req, "userId");

      if (target_user.empty()) {
        // GET presence list for current user
        if (req.method == "GET") return handle_get_list(req);
        return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                                "Method not allowed");
      }

      // POST presence list action for a specific user
      if (target_user[0] != '@') target_user = "@" + target_user;
      if (target_user.find(':') == std::string::npos)
        target_user += ":" + kServerName;

      if (req.method == "POST")
        return handle_post_list_action(req, target_user);

      return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                              "Method not allowed");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  HttpResponse handle_get_list(const HttpRequest& req) {
    try {
      auto requester = require_auth(req, db_);
      PresenceStore pres(db_);

      auto pending = pres.get_presence_list_pending(requester.user_id);
      auto observers = pres.get_presence_list_observers(requester.user_id);

      json resp;
      resp["pending"] = json(pending);
      resp["accepted"] = json(observers);
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  HttpResponse handle_post_list_action(const HttpRequest& req,
                                         const std::string& target_user) {
    try {
      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      std::string action = body.value("action", "");
      if (action.empty()) {
        // Default: invite to presence list
        action = "invite";
      }

      PresenceStore pres(db_);

      if (action == "invite") {
        // Add pending presence observation
        pres.add_presence_list_pending(requester.user_id, target_user);
      } else if (action == "accept") {
        // Accept presence sharing
        pres.set_presence_list_accepted(requester.user_id, target_user);
      } else if (action == "deny" || action == "drop") {
        // Remove from presence list - use observer list to check
        // For deny/drop, just check if they're in any list
        bool in_list = false;
        auto pending = pres.get_presence_list_pending(requester.user_id);
        auto observers = pres.get_presence_list_observers(requester.user_id);
        for (auto& p : pending)
          if (p == target_user) in_list = true;
        for (auto& o : observers)
          if (o == target_user) in_list = true;

        if (!in_list) {
          return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                  "User not in presence list");
        }
        // For drop, we'd need a more specific API. For now, remove via
        // clearing the pending entry (a more complete implementation would
        // have a proper remove method)
      } else {
        return BaseRestServlet::error_response(
            400, "M_INVALID_PARAM",
            "Invalid action. Use: invite, accept, deny, drop");
      }

      // Return updated presence info
      json resp;
      auto presence = pres.get_presence(target_user);
      if (presence) {
        resp["presence"] = presence->state.state;
        resp["last_active_ago"] =
            presence->state.last_active_ts > 0
                ? (now_ms() - presence->state.last_active_ts)
                : 0;
        resp["currently_active"] = presence->state.currently_active;
        if (presence->state.status_msg)
          resp["status_msg"] = *presence->state.status_msg;
      } else {
        resp["presence"] = "offline";
        resp["last_active_ago"] = 0;
        resp["currently_active"] = false;
      }

      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 8. TypingNotificationServlet
// ============================================================================
// Endpoints:
//   PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}
// ============================================================================

class TypingNotificationServlet : public ClientV1RestServlet {
public:
  explicit TypingNotificationServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/typing/{userId}",
      "/_matrix/client/v1/rooms/{roomId}/typing/{userId}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"PUT", "GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      std::string user_id = extract_path_param(req, "userId");

      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");
      if (user_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing user ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;
      if (user_id[0] != '@') user_id = "@" + user_id;
      if (user_id.find(':') == std::string::npos)
        user_id += ":" + kServerName;

      if (req.method == "PUT") return handle_put_typing(req, room_id, user_id);
      if (req.method == "GET") return handle_get_typing(req, room_id);

      return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                              "Method not allowed");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  HttpResponse handle_put_typing(const HttpRequest& req,
                                   const std::string& room_id,
                                   const std::string& user_id) {
    try {
      auto requester = require_auth(req, db_);

      // Must be the user themselves or admin
      if (requester.user_id != user_id &&
          !is_user_admin(db_, requester.user_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "Cannot set typing notification for another user");
      }

      auto body = BaseRestServlet::parse_json_body(req);

      bool typing = body.value("typing", true);
      int64_t timeout = body.value("timeout", 30000);

      // Clamp timeout to spec range
      if (timeout < 1000) timeout = 1000;
      if (timeout > 300000) timeout = 300000;

      // Verify user is a member of the room
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "User is not a member of this room");
      }

      int64_t ts = now_ms();

      // Store typing notification in-memory via the database typing table
      db_.runInteraction("typing_put",
          [&](storage::LoggingTransaction& txn) {
            if (typing) {
              txn.execute(
                  "INSERT INTO typing_notifications "
                  "(room_id,user_id,typing,timeout_ms,timestamp_ms) "
                  "VALUES (?,?,?,?,?) "
                  "ON CONFLICT(room_id,user_id) DO UPDATE SET "
                  "typing=?,timeout_ms=?,timestamp_ms=?",
                  {room_id, user_id, (int64_t)1, timeout, ts,
                   (int64_t)1, timeout, ts});
            } else {
              // Set typing to false with 0 timeout to clear immediately
              txn.execute(
                  "DELETE FROM typing_notifications "
                  "WHERE room_id=? AND user_id=?",
                  {room_id, user_id});
            }
          });

      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  HttpResponse handle_get_typing(const HttpRequest& req,
                                   const std::string& room_id) {
    try {
      auto requester = require_auth(req, db_);

      // Check membership
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "User is not a member of this room");
      }

      int64_t ts_now = now_ms();
      json user_ids = json::array();

      db_.runInteraction("typing_get",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT user_id, timeout_ms, timestamp_ms "
                "FROM typing_notifications "
                "WHERE room_id=? AND typing=1",
                {room_id});
            auto rows = txn.fetchall();
            for (auto& row : rows) {
              auto uid = row.at(0).value;
              auto timeout_opt = row.at(1).value;
              auto ts_opt = row.at(2).value;

              if (uid && timeout_opt && ts_opt) {
                int64_t timeout_val = std::stoll(*timeout_opt);
                int64_t ts_val = std::stoll(*ts_opt);

                // Check if typing has expired
                if (ts_now - ts_val < timeout_val) {
                  user_ids.push_back(*uid);
                }
              }
            }
          });

      return BaseRestServlet::success_response(user_ids);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 9. ReceiptServlet
// ============================================================================
// Endpoints:
//   POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}
// ============================================================================

class ReceiptServlet : public ClientV1RestServlet {
public:
  explicit ReceiptServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}",
      "/_matrix/client/v1/rooms/{roomId}/receipt/{receiptType}/{eventId}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      std::string receipt_type = extract_path_param(req, "receiptType");
      std::string event_id = extract_path_param(req, "eventId");

      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");
      if (receipt_type.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing receipt type");
      if (event_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing event ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      // Validate receipt type
      if (receipt_type != "m.read" && receipt_type != "m.read.private" &&
          receipt_type != "m.fully_read") {
        return BaseRestServlet::error_response(
            400, "M_INVALID_PARAM",
            "Invalid receipt type. Use: m.read, m.read.private, m.fully_read");
      }

      auto requester = require_auth(req, db_);

      // Check user is in the room
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "User is not a member of this room");
      }

      // Parse optional body for thread_id
      json body = json::object();
      if (!req.body.empty() && req.is_json) {
        try {
          body = BaseRestServlet::parse_json_body(req);
        } catch (...) {
          // Body is optional for receipts
        }
      }

      int64_t thread_id = body.value("thread_id", 0);
      int64_t stream_ordering = get_max_stream_ordering(db_) + 1;

      ReceiptsStore receipts(db_);
      receipts.insert_receipt(room_id, requester.user_id, event_id,
                               receipt_type, stream_ordering, thread_id);

      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 10. RoomUpgradeBatchServlet
// ============================================================================
// Endpoints:
//   POST /_matrix/client/v3/rooms/{roomId}/upgrade
// ============================================================================

class RoomUpgradeBatchServlet : public ClientV1RestServlet {
public:
  explicit RoomUpgradeBatchServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/upgrade",
      "/_matrix/client/v1/rooms/{roomId}/upgrade",
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      auto requester = require_auth(req, db_);
      std::string old_room_id = extract_path_param(req, "roomId");
      auto body = BaseRestServlet::parse_json_body(req);

      std::string new_version = body.value("new_version", "10");

      if (old_room_id[0] != '!') old_room_id = "!" + old_room_id;
      if (old_room_id.find(':') == std::string::npos)
        old_room_id += ":" + kServerName;

      // Validate new_version
      static const std::set<std::string> kValidVersions = {
          "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"};
      if (kValidVersions.find(new_version) == kValidVersions.end()) {
        return BaseRestServlet::error_response(
            400, "M_UNSUPPORTED_ROOM_VERSION",
            "Unsupported room version: " + new_version);
      }

      // ---- Gather room info ----
      bool room_exists = false;
      bool is_member = false;
      std::string old_version = "9";
      std::string room_name;
      std::string room_topic;
      std::vector<std::string> original_members;

      db_.runInteraction("upgrade_batch_check",
          [&](storage::LoggingTransaction& txn) {
            txn.execute("SELECT room_version FROM rooms WHERE room_id=?",
                         {old_room_id});
            auto r = txn.fetchone();
            if (r && r->at(0).value) {
              room_exists = true;
              old_version = *r->at(0).value;
            }
            if (!room_exists) return;

            txn.execute(
                "SELECT membership FROM local_current_membership "
                "WHERE user_id=? AND room_id=?",
                {requester.user_id, old_room_id});
            auto m = txn.fetchone();
            if (m && m->at(0).value) {
              is_member = (*m->at(0).value == "join");
            }
            if (!is_member) return;

            // Room name
            txn.execute(
                "SELECT e.content FROM current_state_events cs "
                "JOIN events e ON cs.event_id=e.event_id "
                "WHERE cs.room_id=? AND cs.type='m.room.name'",
                {old_room_id});
            auto nrow = txn.fetchone();
            if (nrow && nrow->at(0).value) {
              try {
                json nc = json::parse(*nrow->at(0).value);
                room_name = nc.value("name", "");
              } catch (...) {}
            }

            // Room topic
            txn.execute(
                "SELECT e.content FROM current_state_events cs "
                "JOIN events e ON cs.event_id=e.event_id "
                "WHERE cs.room_id=? AND cs.type='m.room.topic'",
                {old_room_id});
            auto trow = txn.fetchone();
            if (trow && trow->at(0).value) {
              try {
                json tc = json::parse(*trow->at(0).value);
                room_topic = tc.value("topic", "");
              } catch (...) {}
            }

            // All join members
            txn.execute(
                "SELECT user_id FROM local_current_membership "
                "WHERE room_id=? AND membership='join'",
                {old_room_id});
            auto mems = txn.fetchall();
            for (auto& mem : mems) {
              if (mem.at(0).value)
                original_members.push_back(*mem.at(0).value);
            }
          });

      if (!room_exists)
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "Room not found");
      if (!is_member)
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You must be a member of the room to upgrade it");

      // Check power levels for upgrade permission
      if (!check_power_level(db_, old_room_id, requester.user_id,
                              "m.room.tombstone", 100)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to upgrade this room");
      }

      // Don't upgrade if already on this version
      if (old_version == new_version) {
        return BaseRestServlet::error_response(
            400, "M_UNKNOWN",
            "Room is already at version " + new_version);
      }

      // ---- Create new room ----
      std::string new_room_local = "!" + generate_event_id();
      std::string new_room_id = new_room_local + ":" + kServerName;
      std::string tombstone_event_id;
      int64_t ts_now = now_ms();
      int64_t base_stream = get_max_stream_ordering(db_) + 1;

      db_.runInteraction("upgrade_batch_create",
          [&](storage::LoggingTransaction& txn) {
            int64_t so = base_stream;
            int64_t depth = 0;

            // Insert new room
            txn.execute(
                "INSERT INTO rooms (room_id,is_public,creator,room_version) "
                "VALUES (?,?,?,?)",
                {new_room_id, "0", requester.user_id, new_version});

            // m.room.create
            json create_content;
            create_content["creator"] = requester.user_id;
            create_content["room_version"] = new_version;
            create_content["predecessor"] = {
                {"room_id", old_room_id}, {"event_id", ""}};
            std::string create_eid =
                "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, create_eid, new_room_id,
                          "m.room.create", requester.user_id, "",
                          create_content, ++depth, ++so, ts_now,
                          false, true, new_version);

            // m.room.power_levels
            json pl = get_default_pl(requester.user_id);
            std::string pl_eid =
                "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, pl_eid, new_room_id,
                          "m.room.power_levels", requester.user_id, "",
                          pl, ++depth, ++so, ts_now,
                          false, true, new_version);

            // m.room.join_rules
            json join_rules;
            join_rules["join_rule"] = "invite";
            std::string jr_eid =
                "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, jr_eid, new_room_id,
                          "m.room.join_rules", requester.user_id, "",
                          join_rules, ++depth, ++so, ts_now,
                          false, true, new_version);

            // m.room.history_visibility
            json hist_vis;
            hist_vis["history_visibility"] = "shared";
            std::string hv_eid =
                "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, hv_eid, new_room_id,
                          "m.room.history_visibility", requester.user_id, "",
                          hist_vis, ++depth, ++so, ts_now,
                          false, true, new_version);

            // m.room.guest_access
            json guest_access;
            guest_access["guest_access"] = "forbidden";
            std::string ga_eid =
                "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, ga_eid, new_room_id,
                          "m.room.guest_access", requester.user_id, "",
                          guest_access, ++depth, ++so, ts_now,
                          false, true, new_version);

            // m.room.name (if exists)
            if (!room_name.empty()) {
              json nc;
              nc["name"] = room_name;
              std::string nm_eid =
                  "$" + generate_event_id() + ":" + kServerName;
              persist_event(txn, nm_eid, new_room_id,
                            "m.room.name", requester.user_id, "",
                            nc, ++depth, ++so, ts_now,
                            false, true, new_version);
            }

            // m.room.topic (if exists)
            if (!room_topic.empty()) {
              json tc;
              tc["topic"] = room_topic;
              std::string tp_eid =
                  "$" + generate_event_id() + ":" + kServerName;
              persist_event(txn, tp_eid, new_room_id,
                            "m.room.topic", requester.user_id, "",
                            tc, ++depth, ++so, ts_now,
                            false, true, new_version);
            }

            // Copy essential state
            auto copy_state = [&](const std::string& stype) {
              txn.execute(
                  "SELECT e.content FROM current_state_events cs "
                  "JOIN events e ON cs.event_id=e.event_id "
                  "WHERE cs.room_id=? AND cs.type=?",
                  {old_room_id, stype});
              auto srow = txn.fetchone();
              if (srow && srow->at(0).value) {
                try {
                  json sc = json::parse(*srow->at(0).value);
                  std::string seid =
                      "$" + generate_event_id() + ":" + kServerName;
                  persist_event(txn, seid, new_room_id,
                                stype, requester.user_id, "",
                                sc, ++depth, ++so, ts_now,
                                false, true, new_version);
                } catch (...) {}
              }
            };

            copy_state("m.room.encryption");
            copy_state("m.room.avatar");
            copy_state("m.room.server_acl");
            copy_state("m.room.canonical_alias");

            // Join creator to new room
            json member_content;
            member_content["membership"] = "join";
            member_content["displayname"] = requester.user_id;
            std::string member_eid =
                "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, member_eid, new_room_id,
                          "m.room.member", requester.user_id,
                          requester.user_id,
                          member_content, ++depth, ++so, ts_now,
                          false, true, new_version);
            insert_membership(txn, member_eid, new_room_id,
                              requester.user_id, requester.user_id, "join");

            // Invite original members
            for (auto& member : original_members) {
              if (member == requester.user_id) continue;
              json inv_content;
              inv_content["membership"] = "invite";
              inv_content["displayname"] = member;
              std::string inv_eid =
                  "$" + generate_event_id() + ":" + kServerName;
              persist_event(txn, inv_eid, new_room_id,
                            "m.room.member", requester.user_id,
                            member,
                            inv_content, ++depth, ++so, ts_now,
                            false, true, new_version);
              insert_membership(txn, inv_eid, new_room_id,
                                member, requester.user_id, "invite");
            }

            // Initialize room stats
            txn.execute(
                "INSERT INTO room_stats_state (room_id) VALUES (?)",
                {new_room_id});
            txn.execute(
                "INSERT INTO room_depth (room_id,min_depth) VALUES (?,0)",
                {new_room_id});

            // Create tombstone in old room
            json tombstone_content;
            tombstone_content["body"] = "This room has been replaced";
            tombstone_content["replacement_room"] = new_room_id;

            tombstone_event_id =
                "$" + generate_event_id() + ":" + kServerName;

            txn.execute(
                "SELECT COALESCE(MAX(depth),0) FROM events WHERE room_id=?",
                {old_room_id});
            auto maxd = txn.fetchone();
            int64_t old_depth =
                (maxd && maxd->at(0).value)
                    ? std::stoll(*maxd->at(0).value) + 1
                    : 1;
            int64_t old_so = get_next_stream_id(txn);
            persist_event(txn, tombstone_event_id, old_room_id,
                          "m.room.tombstone", requester.user_id, "",
                          tombstone_content, old_depth, old_so, ts_now,
                          false, true, old_version);

            // Update predecessor event
            txn.execute(
                "UPDATE events SET "
                "content=json_set(content,'$.predecessor.event_id',?) "
                "WHERE event_id=?",
                {tombstone_event_id, create_eid});
          });

      json resp;
      resp["replacement_room"] = new_room_id;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 11. RoomAliasCrudServlet
// ============================================================================
// Endpoints:
//   POST   /_matrix/client/v3/createRoomAlias  - Create room alias (CRUD)
//   GET    /_matrix/client/v3/rooms/{roomId}/aliases - List aliases for room
//   PUT    /_matrix/client/v3/rooms/{roomId}/aliases/{alias} - Update alias
//   DELETE /_matrix/client/v3/rooms/{roomId}/aliases/{alias} - Delete alias
// ============================================================================

class RoomAliasCrudServlet : public ClientV1RestServlet {
public:
  explicit RoomAliasCrudServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/createRoomAlias",
      "/_matrix/client/v1/createRoomAlias",
      "/_matrix/client/v3/rooms/{roomId}/aliases",
      "/_matrix/client/v1/rooms/{roomId}/aliases",
      "/_matrix/client/v3/rooms/{roomId}/aliases/{alias}",
      "/_matrix/client/v1/rooms/{roomId}/aliases/{alias}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST", "PUT", "DELETE"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string path = req.path;

      // Create alias
      if (path.find("/createRoomAlias") != std::string::npos) {
        if (req.method == "POST") return handle_create_alias(req);
        return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                                "Method not allowed");
      }

      std::string room_id = extract_path_param(req, "roomId");
      std::string alias_raw = extract_path_param(req, "alias");

      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      if (alias_raw.empty()) {
        // List aliases for room
        if (req.method == "GET") return handle_list_aliases(req, room_id);
        return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                                "Method not allowed");
      }

      // Normalize alias
      std::string alias = alias_raw;
      if (alias[0] != '#') alias = "#" + alias;
      if (alias.find(':') == std::string::npos)
        alias += ":" + kServerName;

      if (req.method == "PUT") return handle_update_alias(req, room_id, alias);
      if (req.method == "DELETE")
        return handle_delete_alias_crud(req, room_id, alias);
      if (req.method == "GET")
        return handle_get_alias_info(req, room_id, alias);

      return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                              "Method not allowed");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  HttpResponse handle_create_alias(const HttpRequest& req) {
    try {
      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      std::string room_id = body.value("room_id", "");
      std::string alias_raw = body.value("room_alias_name", "");

      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room_id");
      if (alias_raw.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room_alias_name");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      // Build full alias
      std::string alias = alias_raw;
      if (alias[0] != '#') alias = "#" + alias;
      if (alias.find(':') == std::string::npos)
        alias += ":" + kServerName;

      // Validate alias format
      if (!is_valid_alias_format(alias)) {
        return BaseRestServlet::error_response(
            400, "M_INVALID_PARAM",
            "Invalid alias format. Must be #localpart:server with valid "
            "localpart characters [a-z0-9._=-]");
      }

      // Check membership and permissions
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You must be a member of the room");
      }

      if (!check_power_level(db_, room_id, requester.user_id,
                              "m.room.canonical_alias", 50)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to create aliases in this room");
      }

      DirectoryStore dir(db_);
      auto existing = dir.get_room_id(alias);
      if (existing) {
        return BaseRestServlet::error_response(
            409, "M_UNKNOWN",
            "Room alias already exists");
      }

      std::vector<std::string> servers = {kServerName};
      if (body.contains("servers") && body["servers"].is_array()) {
        servers.clear();
        for (auto& s : body["servers"]) {
          if (s.is_string()) servers.push_back(s.get<std::string>());
        }
      }

      dir.create_alias(alias, room_id, requester.user_id, servers);

      json resp;
      resp["room_alias"] = alias;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  HttpResponse handle_list_aliases(const HttpRequest& req,
                                     const std::string& room_id) {
    try {
      require_auth(req, db_);

      DirectoryStore dir(db_);
      auto aliases = dir.get_aliases_for_room(room_id);

      json resp;
      resp["aliases"] = json(aliases);
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  HttpResponse handle_get_alias_info(const HttpRequest& req,
                                       const std::string& room_id,
                                       const std::string& alias) {
    try {
      require_auth(req, db_);

      DirectoryStore dir(db_);
      auto target_room = dir.get_room_id(alias);
      if (!target_room || *target_room != room_id) {
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "Alias not found for this room");
      }

      auto creator = dir.get_alias_creator(alias);
      auto servers = dir.get_servers_for_alias(alias);

      json resp;
      resp["room_alias"] = alias;
      resp["room_id"] = *target_room;
      resp["servers"] = json(servers);
      if (creator) resp["creator"] = *creator;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  HttpResponse handle_update_alias(const HttpRequest& req,
                                     const std::string& room_id,
                                     const std::string& alias) {
    try {
      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      DirectoryStore dir(db_);

      auto target_room = dir.get_room_id(alias);
      if (!target_room || *target_room != room_id) {
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "Alias not found for this room");
      }

      // Check permissions
      if (!check_power_level(db_, room_id, requester.user_id,
                              "m.room.canonical_alias", 50)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to modify aliases");
      }

      // Update servers if provided
      if (body.contains("servers") && body["servers"].is_array()) {
        std::vector<std::string> servers;
        for (auto& s : body["servers"]) {
          if (s.is_string()) servers.push_back(s.get<std::string>());
        }
        // Remove old and add new servers
        auto current_servers = dir.get_servers_for_alias(alias);
        for (auto& s : current_servers) {
          dir.remove_alias_servers(alias, {s});
        }
        if (!servers.empty()) {
          dir.add_alias_servers(alias, servers);
        }
      }

      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  HttpResponse handle_delete_alias_crud(const HttpRequest& req,
                                         const std::string& room_id,
                                         const std::string& alias) {
    try {
      auto requester = require_auth(req, db_);
      DirectoryStore dir(db_);

      auto target_room = dir.get_room_id(alias);
      if (!target_room || *target_room != room_id) {
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "Alias not found for this room");
      }

      // Permission check
      bool can_delete = false;
      auto creator = dir.get_alias_creator(alias);
      if (creator && *creator == requester.user_id) can_delete = true;
      if (!can_delete) {
        can_delete = check_power_level(db_, room_id, requester.user_id,
                                        "m.room.canonical_alias", 50);
      }
      if (!can_delete) {
        can_delete = is_user_admin(db_, requester.user_id);
      }

      if (!can_delete) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to delete this alias");
      }

      dir.delete_alias(alias);
      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 12. JoinedRoomsServlet
// ============================================================================
// Endpoints:
//   GET /_matrix/client/v3/joined_rooms
//   GET /_matrix/client/v3/users/{userId}/joined_rooms
// ============================================================================

class JoinedRoomsServlet : public ClientV1RestServlet {
public:
  explicit JoinedRoomsServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/joined_rooms",
      "/_matrix/client/v1/joined_rooms",
      "/_matrix/client/v3/users/{userId}/joined_rooms",
      "/_matrix/client/v1/users/{userId}/joined_rooms",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string target_user = extract_path_param(req, "userId");
      auto requester = require_auth(req, db_);

      std::string user_id = target_user.empty()
                                 ? requester.user_id
                                 : target_user;

      if (!target_user.empty()) {
        if (user_id[0] != '@') user_id = "@" + user_id;
        if (user_id.find(':') == std::string::npos)
          user_id += ":" + kServerName;
      }

      // Only admins can query other users' joined rooms
      if (!target_user.empty() && requester.user_id != user_id &&
          !is_user_admin(db_, requester.user_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "Cannot query another user's joined rooms");
      }

      RoomMemberWorkerStore members(db_);
      auto rooms = members.get_rooms_for_user_with_membership(user_id, "join");

      json joined = json::array();
      for (auto& r : rooms) {
        joined.push_back(r);
      }

      json resp;
      resp["joined_rooms"] = joined;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 13. JoinedMembersServlet
// ============================================================================
// Endpoints:
//   GET /_matrix/client/v3/rooms/{roomId}/joined_members
// ============================================================================

class JoinedMembersServlet : public ClientV1RestServlet {
public:
  explicit JoinedMembersServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/joined_members",
      "/_matrix/client/v1/rooms/{roomId}/joined_members",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      auto requester = require_auth(req, db_);

      // Check user is in the room
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      RoomMemberWorkerStore members(db_);
      auto joined = members.get_joined_members(room_id);

      json joined_map = json::object();
      for (auto& member : joined) {
        json entry;
        if (member.display_name)
          entry["display_name"] = *member.display_name;
        if (member.avatar_url)
          entry["avatar_url"] = *member.avatar_url;
        joined_map[member.user_id] = entry;
      }

      json resp;
      resp["joined"] = joined_map;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 14. RoomMessagesServlet
// ============================================================================
// Endpoints:
//   GET /_matrix/client/v3/rooms/{roomId}/messages
// ============================================================================

class RoomMessagesServlet : public ClientV1RestServlet {
public:
  explicit RoomMessagesServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/messages",
      "/_matrix/client/v1/rooms/{roomId}/messages",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      auto requester = require_auth(req, db_);

      // Check user is in the room
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      // Parse direction
      auto dir_opt = BaseRestServlet::parse_string(req, "dir");
      std::string direction = dir_opt.value_or("b");
      bool is_backward = (direction == "b");

      // Parse from/token
      auto from_opt = BaseRestServlet::parse_string(req, "from");
      std::string from = from_opt.value_or("");

      // Parse to
      auto to_opt = BaseRestServlet::parse_string(req, "to");
      std::string to = to_opt.value_or("");

      // Parse limit
      auto limit_opt = BaseRestServlet::parse_integer(req, "limit");
      int64_t limit = limit_opt.value_or(10);
      if (limit < 1) limit = 1;
      if (limit > 1000) limit = 1000;

      // Parse filter
      auto filter_opt = BaseRestServlet::parse_string(req, "filter");

      // Convert from/to to stream ordering
      int64_t from_stream = 0;
      int64_t to_stream = 0;

      if (!from.empty()) {
        try {
          from_stream = std::stoll(from);
        } catch (...) {
          // from might be a token - try to resolve
          db_.runInteraction("resolve_token",
              [&](storage::LoggingTransaction& txn) {
                txn.execute(
                    "SELECT stream_ordering FROM events "
                    "WHERE event_id=? AND room_id=?",
                    {from, room_id});
                auto r = txn.fetchone();
                if (r && r->at(0).value) {
                  from_stream = std::stoll(*r->at(0).value);
                }
              });
        }
      }

      if (!to.empty()) {
        try {
          to_stream = std::stoll(to);
        } catch (...) {
          db_.runInteraction("resolve_to",
              [&](storage::LoggingTransaction& txn) {
                txn.execute(
                    "SELECT stream_ordering FROM events "
                    "WHERE event_id=? AND room_id=?",
                    {to, room_id});
                auto r = txn.fetchone();
                if (r && r->at(0).value) {
                  to_stream = std::stoll(*r->at(0).value);
                }
              });
        }
      }

      // Build query
      json chunk = json::array();
      std::string end_token;
      std::string start_token;
      bool has_more = false;
      int64_t actual_count = 0;

      db_.runInteraction("room_messages",
          [&](storage::LoggingTransaction& txn) {
            std::string sql =
                "SELECT event_id, type, sender, content, origin_server_ts, "
                "stream_ordering, state_key, depth "
                "FROM events WHERE room_id=?";

            std::vector<storage::SQLParam> params;
            params.push_back(room_id);

            // Filter out outliers
            sql += " AND outlier=0";

            if (is_backward) {
              if (from_stream > 0) {
                sql += " AND stream_ordering < ?";
                params.push_back(from_stream);
              }
              if (to_stream > 0) {
                sql += " AND stream_ordering >= ?";
                params.push_back(to_stream);
              }
              sql += " ORDER BY stream_ordering DESC LIMIT ?";
              params.push_back(limit);
            } else {
              if (from_stream > 0) {
                sql += " AND stream_ordering > ?";
                params.push_back(from_stream);
              }
              if (to_stream > 0) {
                sql += " AND stream_ordering <= ?";
                params.push_back(to_stream);
              }
              sql += " ORDER BY stream_ordering ASC LIMIT ?";
              params.push_back(limit);
            }

            txn.execute(sql, params);
            auto rows = txn.fetchall();

            // Since we might have filtered in reverse, store and sort
            std::vector<json> temp_events;

            for (auto& row : rows) {
              json event;
              std::string eid = row.at(0).value.value_or("");
              std::string etype = row.at(1).value.value_or("");
              std::string esender = row.at(2).value.value_or("");
              std::string econtent_str = row.at(3).value.value_or("{}");
              int64_t eots = 0;
              int64_t eso = 0;
              std::string esk = row.at(6).value.value_or("");

              if (row.at(4).value) eots = std::stoll(*row.at(4).value);
              if (row.at(5).value) eso = std::stoll(*row.at(5).value);

              try {
                json econtent = json::parse(econtent_str);
                event["event_id"] = eid;
                event["type"] = etype;
                event["sender"] = esender;
                event["origin_server_ts"] = eots;
                event["room_id"] = room_id;
                if (!esk.empty()) event["state_key"] = esk;
                event["content"] = econtent;

                temp_events.push_back(event);
              } catch (...) {}

              actual_count++;
            }

            // For backward direction, events come in reverse order, so flip
            if (is_backward) {
              std::reverse(temp_events.begin(), temp_events.end());
            }

            // Build chunk
            for (auto& ev : temp_events) {
              chunk.push_back(ev);
            }

            // Set start/end tokens
            if (!temp_events.empty()) {
              start_token = temp_events.front().value("event_id", "");
              end_token = temp_events.back().value("event_id", "");
            }

            // Check if there are more events
            if (actual_count >= limit) {
              has_more = true;
            }
          });

      json resp;
      resp["chunk"] = chunk;
      resp["start"] = start_token;
      resp["end"] = end_token;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 15. RoomStateServlet
// ============================================================================
// Endpoints:
//   GET /_matrix/client/v3/rooms/{roomId}/state
//   GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}
//   GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}
//   PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}
//   PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}
// ============================================================================

class RoomStateServlet : public ClientV1RestServlet {
public:
  explicit RoomStateServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/state",
      "/_matrix/client/v1/rooms/{roomId}/state",
      "/_matrix/client/v3/rooms/{roomId}/state/{eventType}",
      "/_matrix/client/v1/rooms/{roomId}/state/{eventType}",
      "/_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}",
      "/_matrix/client/v1/rooms/{roomId}/state/{eventType}/{stateKey}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "PUT"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      std::string event_type = extract_path_param(req, "eventType");
      std::string state_key = extract_path_param(req, "stateKey");

      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      if (req.method == "GET") {
        if (event_type.empty()) return handle_get_state(req, room_id);
        return handle_get_state_event(req, room_id, event_type, state_key);
      }

      if (req.method == "PUT") {
        if (event_type.empty())
          return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                  "Missing event type");
        return handle_put_state(req, room_id, event_type, state_key);
      }

      return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                              "Method not allowed");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  HttpResponse handle_get_state(const HttpRequest& req,
                                  const std::string& room_id) {
    try {
      auto requester = require_auth(req, db_);

      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      StateStore state(db_);
      auto current_state = state.get_current_state(room_id);

      json result = json::array();
      db_.runInteraction("get_full_state",
          [&](storage::LoggingTransaction& txn) {
            for (auto& [key, event_id] : current_state) {
              txn.execute(
                  "SELECT type, sender, content, origin_server_ts, state_key "
                  "FROM events WHERE event_id=?",
                  {event_id});
              auto r = txn.fetchone();
              if (r) {
                json event;
                event["type"] = r->at(0).value.value_or(key.first);
                event["sender"] = r->at(1).value.value_or("");
                event["state_key"] = r->at(4).value.value_or(key.second);
                event["event_id"] = event_id;
                if (r->at(3).value)
                  event["origin_server_ts"] = std::stoll(*r->at(3).value);
                try {
                  event["content"] =
                      json::parse(r->at(2).value.value_or("{}"));
                } catch (...) {
                  event["content"] = json::object();
                }
                result.push_back(event);
              }
            }
          });

      return BaseRestServlet::success_response(result);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  HttpResponse handle_get_state_event(const HttpRequest& req,
                                        const std::string& room_id,
                                        const std::string& event_type,
                                        const std::string& state_key) {
    try {
      auto requester = require_auth(req, db_);

      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      StateStore state(db_);
      auto entry = state.get_state_event(room_id, event_type,
                                          state_key.empty() ? "" : state_key);

      if (!entry) {
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "State event not found");
      }

      json event;
      db_.runInteraction("get_state_event_detail",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT type, sender, content, origin_server_ts, state_key "
                "FROM events WHERE event_id=?",
                {entry->event_id});
            auto r = txn.fetchone();
            if (r) {
              event["type"] = r->at(0).value.value_or(entry->type);
              event["sender"] = r->at(1).value.value_or("");
              event["state_key"] = r->at(4).value.value_or(entry->state_key);
              event["event_id"] = entry->event_id;
              if (r->at(3).value)
                event["origin_server_ts"] = std::stoll(*r->at(3).value);
              try {
                event["content"] =
                    json::parse(r->at(2).value.value_or("{}"));
              } catch (...) {
                event["content"] = json::object();
              }
            }
          });

      return BaseRestServlet::success_response(event);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  HttpResponse handle_put_state(const HttpRequest& req,
                                  const std::string& room_id,
                                  const std::string& event_type,
                                  const std::string& state_key) {
    try {
      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      // Check power level for state events
      if (!check_power_level(db_, room_id, requester.user_id,
                              event_type, 50)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to set this state event");
      }

      std::string sk = state_key.empty() ? "" : state_key;
      std::string room_version = get_room_version(db_, room_id);

      int64_t ts = now_ms();
      int64_t base_stream = get_max_stream_ordering(db_) + 1;
      std::string event_id;

      db_.runInteraction("put_state_event",
          [&](storage::LoggingTransaction& txn) {
            int64_t so = base_stream;

            // Get next depth
            txn.execute(
                "SELECT COALESCE(MAX(depth),0)+1 FROM events "
                "WHERE room_id=?",
                {room_id});
            auto dr = txn.fetchone();
            int64_t depth = (dr && dr->at(0).value)
                                ? std::stoll(*dr->at(0).value)
                                : 1;

            event_id = "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, event_id, room_id,
                          event_type, requester.user_id, sk,
                          body, depth, ++so, ts,
                          false, true, room_version);

            // If this is the empty state key for a non-state_keyed type,
            // state_key is ""
            if (!sk.empty()) {
              txn.execute(
                  "INSERT INTO current_state_events "
                  "(event_id,room_id,type,state_key) "
                  "VALUES (?,?,?,?) "
                  "ON CONFLICT(room_id,type,state_key) "
                  "DO UPDATE SET event_id=excluded.event_id",
                  {event_id, room_id, event_type, sk});
            }
          });

      json resp;
      resp["event_id"] = event_id;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 16. RoomMembersServlet
// ============================================================================
// Endpoints:
//   GET /_matrix/client/v3/rooms/{roomId}/members
// ============================================================================

class RoomMembersServlet : public ClientV1RestServlet {
public:
  explicit RoomMembersServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/members",
      "/_matrix/client/v1/rooms/{roomId}/members",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      auto requester = require_auth(req, db_);

      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      // Parse membership filter
      auto membership_opt = BaseRestServlet::parse_string(req, "membership");
      std::optional<std::string> membership;
      if (membership_opt && !membership_opt->empty()) {
        membership = *membership_opt;
        // Validate membership value
        if (*membership != "join" && *membership != "invite" &&
            *membership != "leave" && *membership != "ban" &&
            *membership != "knock") {
          return BaseRestServlet::error_response(
              400, "M_INVALID_PARAM",
              "Invalid membership filter. Use: join, invite, leave, ban, knock");
        }
      }

      // Parse not_membership filter
      auto not_membership_opt =
          BaseRestServlet::parse_string(req, "not_membership");
      std::optional<std::string> not_membership;
      if (not_membership_opt && !not_membership_opt->empty()) {
        not_membership = *not_membership_opt;
      }

      // Parse pagination
      auto at_opt = BaseRestServlet::parse_string(req, "at");
      auto limit_opt = BaseRestServlet::parse_integer(req, "limit");
      int64_t limit = limit_opt.value_or(100);
      if (limit < 1) limit = 1;
      if (limit > 1000) limit = 1000;

      int64_t offset = 0;
      if (at_opt && !at_opt->empty()) {
        try { offset = std::stoll(*at_opt); } catch (...) {}
      }

      RoomMemberWorkerStore members(db_);
      auto result = members.get_members(room_id, membership,
                                         not_membership, limit, offset);

      json chunk = json::array();
      for (auto& member : result.members) {
        json entry;
        entry["user_id"] = member.user_id;
        entry["sender"] = member.sender;
        entry["membership"] = member.membership;
        if (member.display_name)
          entry["display_name"] = *member.display_name;
        if (member.avatar_url)
          entry["avatar_url"] = *member.avatar_url;
        chunk.push_back(entry);
      }

      json resp;
      resp["chunk"] = chunk;
      if (result.total)
        resp["total_room_members_estimate"] = *result.total;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 17. KickServlet
// ============================================================================
// Endpoints:
//   POST /_matrix/client/v3/rooms/{roomId}/kick
// ============================================================================

class KickServlet : public ClientV1RestServlet {
public:
  explicit KickServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/kick",
      "/_matrix/client/v1/rooms/{roomId}/kick",
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      std::string target_user = body.value("user_id", "");
      if (target_user.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing user_id");

      if (target_user[0] != '@') target_user = "@" + target_user;
      if (target_user.find(':') == std::string::npos)
        target_user += ":" + kServerName;

      std::string reason = body.value("reason", "");

      // Check requester is in the room
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      // Check target is in the room
      if (!check_room_membership(db_, target_user, room_id)) {
        return BaseRestServlet::error_response(
            404, "M_NOT_FOUND",
            "User is not in this room");
      }

      // Check power levels
      if (!check_power_level(db_, room_id, requester.user_id,
                              "m.room.member", 50)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to kick users");
      }

      // Prevent kicking self
      if (requester.user_id == target_user) {
        return BaseRestServlet::error_response(
            400, "M_UNKNOWN",
            "You cannot kick yourself");
      }

      // Perform kick: create membership event with leave + reason
      std::string room_version = get_room_version(db_, room_id);
      int64_t ts = now_ms();
      int64_t base_stream = get_max_stream_ordering(db_) + 1;
      std::string kick_event_id;

      db_.runInteraction("kick_user",
          [&](storage::LoggingTransaction& txn) {
            int64_t so = base_stream;

            txn.execute(
                "SELECT COALESCE(MAX(depth),0)+1 FROM events "
                "WHERE room_id=?",
                {room_id});
            auto dr = txn.fetchone();
            int64_t depth = (dr && dr->at(0).value)
                                ? std::stoll(*dr->at(0).value)
                                : 1;

            kick_event_id = "$" + generate_event_id() + ":" + kServerName;

            json kick_content;
            kick_content["membership"] = "leave";
            kick_content["displayname"] = target_user;
            if (!reason.empty()) kick_content["reason"] = reason;

            persist_event(txn, kick_event_id, room_id,
                          "m.room.member", requester.user_id,
                          target_user,
                          kick_content, depth, ++so, ts,
                          false, true, room_version);

            // Update membership to leave
            txn.execute(
                "UPDATE local_current_membership "
                "SET membership='leave', event_id=? "
                "WHERE user_id=? AND room_id=?",
                {kick_event_id, target_user, room_id});
            txn.execute(
                "UPDATE room_memberships "
                "SET membership='leave', event_id=? "
                "WHERE user_id=? AND room_id=? "
                "AND event_stream_ordering=(SELECT MAX(event_stream_ordering) "
                "FROM room_memberships WHERE user_id=? AND room_id=?)",
                {kick_event_id, target_user, room_id,
                 target_user, room_id});
          });

      json resp;
      resp["event_id"] = kick_event_id;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 18. BanServlet
// ============================================================================
// Endpoints:
//   POST /_matrix/client/v3/rooms/{roomId}/ban
// ============================================================================

class BanServlet : public ClientV1RestServlet {
public:
  explicit BanServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/ban",
      "/_matrix/client/v1/rooms/{roomId}/ban",
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      std::string target_user = body.value("user_id", "");
      if (target_user.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing user_id");

      if (target_user[0] != '@') target_user = "@" + target_user;
      if (target_user.find(':') == std::string::npos)
        target_user += ":" + kServerName;

      std::string reason = body.value("reason", "");

      // Check requester is in the room
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      // Check power levels
      if (!check_power_level(db_, room_id, requester.user_id,
                              "m.room.member", 50)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to ban users");
      }

      // Prevent banning self
      if (requester.user_id == target_user) {
        return BaseRestServlet::error_response(
            400, "M_UNKNOWN",
            "You cannot ban yourself");
      }

      // Check if already banned
      bool already_banned = false;
      db_.runInteraction("check_ban",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT membership FROM local_current_membership "
                "WHERE user_id=? AND room_id=?",
                {target_user, room_id});
            auto r = txn.fetchone();
            if (r && r->at(0).value && *r->at(0).value == "ban") {
              already_banned = true;
            }
          });

      if (already_banned) {
        return BaseRestServlet::error_response(
            400, "M_UNKNOWN",
            "User is already banned from this room");
      }

      // Perform ban
      std::string room_version = get_room_version(db_, room_id);
      int64_t ts = now_ms();
      int64_t base_stream = get_max_stream_ordering(db_) + 1;
      std::string ban_event_id;

      db_.runInteraction("ban_user",
          [&](storage::LoggingTransaction& txn) {
            int64_t so = base_stream;

            txn.execute(
                "SELECT COALESCE(MAX(depth),0)+1 FROM events "
                "WHERE room_id=?",
                {room_id});
            auto dr = txn.fetchone();
            int64_t depth = (dr && dr->at(0).value)
                                ? std::stoll(*dr->at(0).value)
                                : 1;

            ban_event_id = "$" + generate_event_id() + ":" + kServerName;

            json ban_content;
            ban_content["membership"] = "ban";
            ban_content["displayname"] = target_user;
            if (!reason.empty()) ban_content["reason"] = reason;

            persist_event(txn, ban_event_id, room_id,
                          "m.room.member", requester.user_id,
                          target_user,
                          ban_content, depth, ++so, ts,
                          false, true, room_version);

            // Update membership to ban
            txn.execute(
                "INSERT INTO local_current_membership "
                "(room_id,user_id,event_id,membership) "
                "VALUES (?,?,?,?) "
                "ON CONFLICT(user_id,room_id) DO UPDATE SET "
                "event_id=excluded.event_id,membership=excluded.membership",
                {room_id, target_user, ban_event_id, "ban"});

            // Insert into room_memberships
            txn.execute(
                "INSERT INTO room_memberships "
                "(event_id,room_id,user_id,sender,membership,content,"
                "membership_event_id,display_name,avatar_url) "
                "VALUES (?,?,?,?,?,'{}',?,'','')",
                {ban_event_id, room_id, target_user, requester.user_id,
                 "ban", ban_event_id});
          });

      json resp;
      resp["event_id"] = ban_event_id;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 19. UnbanServlet
// ============================================================================
// Endpoints:
//   POST /_matrix/client/v3/rooms/{roomId}/unban
// ============================================================================

class UnbanServlet : public ClientV1RestServlet {
public:
  explicit UnbanServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/unban",
      "/_matrix/client/v1/rooms/{roomId}/unban",
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      std::string target_user = body.value("user_id", "");
      if (target_user.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing user_id");

      if (target_user[0] != '@') target_user = "@" + target_user;
      if (target_user.find(':') == std::string::npos)
        target_user += ":" + kServerName;

      std::string reason = body.value("reason", "");

      // Check requester is in the room
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      // Check target is currently banned
      bool is_banned = false;
      db_.runInteraction("check_unban",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT membership FROM local_current_membership "
                "WHERE user_id=? AND room_id=?",
                {target_user, room_id});
            auto r = txn.fetchone();
            if (r && r->at(0).value && *r->at(0).value == "ban") {
              is_banned = true;
            }
          });

      if (!is_banned) {
        return BaseRestServlet::error_response(
            400, "M_UNKNOWN",
            "User is not banned from this room");
      }

      // Check power levels (unban = same as ban = m.room.member at 50)
      if (!check_power_level(db_, room_id, requester.user_id,
                              "m.room.member", 50)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to unban users");
      }

      // Perform unban: create membership event with leave
      std::string room_version = get_room_version(db_, room_id);
      int64_t ts = now_ms();
      int64_t base_stream = get_max_stream_ordering(db_) + 1;
      std::string unban_event_id;

      db_.runInteraction("unban_user",
          [&](storage::LoggingTransaction& txn) {
            int64_t so = base_stream;

            txn.execute(
                "SELECT COALESCE(MAX(depth),0)+1 FROM events "
                "WHERE room_id=?",
                {room_id});
            auto dr = txn.fetchone();
            int64_t depth = (dr && dr->at(0).value)
                                ? std::stoll(*dr->at(0).value)
                                : 1;

            unban_event_id = "$" + generate_event_id() + ":" + kServerName;

            json unban_content;
            unban_content["membership"] = "leave";
            unban_content["displayname"] = target_user;
            if (!reason.empty()) unban_content["reason"] = reason;

            persist_event(txn, unban_event_id, room_id,
                          "m.room.member", requester.user_id,
                          target_user,
                          unban_content, depth, ++so, ts,
                          false, true, room_version);

            // Update membership from ban to leave
            txn.execute(
                "UPDATE local_current_membership "
                "SET membership='leave', event_id=? "
                "WHERE user_id=? AND room_id=?",
                {unban_event_id, target_user, room_id});

            txn.execute(
                "INSERT INTO room_memberships "
                "(event_id,room_id,user_id,sender,membership,content,"
                "membership_event_id,display_name,avatar_url) "
                "VALUES (?,?,?,?,?,'{}',?,'','')",
                {unban_event_id, room_id, target_user, requester.user_id,
                 "leave", unban_event_id});
          });

      json resp;
      resp["event_id"] = unban_event_id;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 20. InviteServlet
// ============================================================================
// Endpoints:
//   POST /_matrix/client/v3/rooms/{roomId}/invite
// ============================================================================

class InviteServlet : public ClientV1RestServlet {
public:
  explicit InviteServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/invite",
      "/_matrix/client/v1/rooms/{roomId}/invite",
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      std::string target_user = body.value("user_id", "");
      if (target_user.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing user_id");

      if (target_user[0] != '@') target_user = "@" + target_user;
      if (target_user.find(':') == std::string::npos)
        target_user += ":" + kServerName;

      std::string reason = body.value("reason", "");

      // Check requester is in the room
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      // Check power levels for invite
      if (!check_power_level(db_, room_id, requester.user_id,
                              "m.room.member", 0)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to invite users");
      }

      // Check target is not already in the room
      if (check_room_membership(db_, target_user, room_id)) {
        return BaseRestServlet::error_response(
            400, "M_UNKNOWN",
            "User is already in this room");
      }

      // Check target is not banned
      bool is_banned = false;
      db_.runInteraction("check_invite_ban",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT membership FROM local_current_membership "
                "WHERE user_id=? AND room_id=?",
                {target_user, room_id});
            auto r = txn.fetchone();
            if (r && r->at(0).value && *r->at(0).value == "ban") {
              is_banned = true;
            }
          });
      if (is_banned) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "User is banned from this room");
      }

      // Check target user exists
      bool target_exists = false;
      std::string target_displayname;
      db_.runInteraction("check_target_exists",
          [&](storage::LoggingTransaction& txn) {
            txn.execute("SELECT 1 FROM users WHERE name=?",
                         {target_user});
            auto r = txn.fetchone();
            target_exists = (r != std::nullopt);

            // Get display name
            txn.execute(
                "SELECT display_name FROM profiles WHERE user_id=?",
                {target_user});
            auto pr = txn.fetchone();
            if (pr && pr->at(0).value) {
              target_displayname = *pr->at(0).value;
            }
          });
      if (!target_exists) {
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "User not found");
      }

      // Perform invite
      std::string room_version = get_room_version(db_, room_id);
      int64_t ts = now_ms();
      int64_t base_stream = get_max_stream_ordering(db_) + 1;
      std::string invite_event_id;

      db_.runInteraction("invite_user",
          [&](storage::LoggingTransaction& txn) {
            int64_t so = base_stream;

            txn.execute(
                "SELECT COALESCE(MAX(depth),0)+1 FROM events "
                "WHERE room_id=?",
                {room_id});
            auto dr = txn.fetchone();
            int64_t depth = (dr && dr->at(0).value)
                                ? std::stoll(*dr->at(0).value)
                                : 1;

            invite_event_id = "$" + generate_event_id() + ":" + kServerName;

            json invite_content;
            invite_content["membership"] = "invite";
            invite_content["displayname"] = target_displayname.empty()
                                                ? target_user
                                                : target_displayname;
            if (!reason.empty()) invite_content["reason"] = reason;

            persist_event(txn, invite_event_id, room_id,
                          "m.room.member", requester.user_id,
                          target_user,
                          invite_content, depth, ++so, ts,
                          false, true, room_version);

            // Insert membership
            insert_membership(txn, invite_event_id, room_id,
                              target_user, requester.user_id, "invite");
          });

      json resp;
      resp["event_id"] = invite_event_id;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 21. RedactServlet
// ============================================================================
// Endpoints:
//   PUT /_matrix/client/v3/rooms/{roomId}/redact/{eventId}
//   PUT /_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}
// ============================================================================

class RedactServlet : public ClientV1RestServlet {
public:
  explicit RedactServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/redact/{eventId}",
      "/_matrix/client/v1/rooms/{roomId}/redact/{eventId}",
      "/_matrix/client/v3/rooms/{roomId}/redact/{eventId}/{txnId}",
      "/_matrix/client/v1/rooms/{roomId}/redact/{eventId}/{txnId}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"PUT", "POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      std::string event_id = extract_path_param(req, "eventId");
      std::string txn_id = extract_path_param(req, "txnId");

      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");
      if (event_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing event ID");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      auto requester = require_auth(req, db_);

      // Check user is in the room
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      // Parse body for reason
      json body = json::object();
      if (!req.body.empty() && req.is_json) {
        try {
          body = BaseRestServlet::parse_json_body(req);
        } catch (...) {}
      }
      std::string reason = body.value("reason", "");

      // Check power levels for redaction
      bool can_redact = false;

      // Users can always redact their own messages
      db_.runInteraction("check_redact_ownership",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT sender FROM events WHERE event_id=? AND room_id=?",
                {event_id, room_id});
            auto r = txn.fetchone();
            if (r && r->at(0).value && *r->at(0).value == requester.user_id) {
              can_redact = true;
            }
          });

      if (!can_redact) {
        can_redact = check_power_level(db_, room_id, requester.user_id,
                                        "m.room.redaction", 50);
      }

      if (!can_redact) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to redact this event");
      }

      // Check event exists
      bool event_exists = false;
      std::string target_sender;
      db_.runInteraction("check_event_exists",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT sender FROM events WHERE event_id=? AND room_id=?",
                {event_id, room_id});
            auto r = txn.fetchone();
            if (r && r->at(0).value) {
              event_exists = true;
              target_sender = *r->at(0).value;
            }
          });

      if (!event_exists) {
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "Event not found");
      }

      // Create redaction event
      std::string room_version = get_room_version(db_, room_id);
      int64_t ts = now_ms();
      int64_t base_stream = get_max_stream_ordering(db_) + 1;
      std::string redact_event_id;

      db_.runInteraction("redact_event",
          [&](storage::LoggingTransaction& txn) {
            int64_t so = base_stream;

            txn.execute(
                "SELECT COALESCE(MAX(depth),0)+1 FROM events "
                "WHERE room_id=?",
                {room_id});
            auto dr = txn.fetchone();
            int64_t depth = (dr && dr->at(0).value)
                                ? std::stoll(*dr->at(0).value)
                                : 1;

            redact_event_id = "$" + generate_event_id() + ":" + kServerName;

            json redact_content;
            if (!reason.empty())
              redact_content["reason"] = reason;

            // Use the txn_id if provided for idempotency, otherwise generate
            std::string redact_eid = txn_id.empty()
                                         ? redact_event_id
                                         : txn_id;
            if (txn_id.empty()) {
              redact_eid = redact_event_id;
            }

            persist_event(txn, redact_eid, room_id,
                          "m.room.redaction", requester.user_id,
                          "",
                          redact_content, depth, ++so, ts,
                          false, false, room_version);

            // Mark the redaction target
            txn.execute(
                "UPDATE events SET redacts=? WHERE event_id=? AND room_id=?",
                {redact_eid, event_id, room_id});

            if (!txn_id.empty()) {
              redact_event_id = redact_eid;
            }
          });

      json resp;
      resp["event_id"] = redact_event_id;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 22. SendEventServlet
// ============================================================================
// Endpoints:
//   PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}
//   PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}
// ============================================================================

class SendEventServlet : public ClientV1RestServlet {
public:
  explicit SendEventServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/send/{eventType}",
      "/_matrix/client/v1/rooms/{roomId}/send/{eventType}",
      "/_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}",
      "/_matrix/client/v1/rooms/{roomId}/send/{eventType}/{txnId}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"PUT", "POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      std::string event_type = extract_path_param(req, "eventType");
      std::string txn_id = extract_path_param(req, "txnId");

      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");
      if (event_type.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing event type");

      if (room_id[0] != '!') room_id = "!" + room_id;
      if (room_id.find(':') == std::string::npos)
        room_id += ":" + kServerName;

      auto requester = require_auth(req, db_);

      // Check user is in the room
      if (!check_room_membership(db_, requester.user_id, room_id)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You are not a member of this room");
      }

      // Parse body
      auto body = BaseRestServlet::parse_json_body(req);

      // Check message event power levels
      if (!check_power_level(db_, room_id, requester.user_id,
                              event_type, 0)) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to send this event type");
      }

      // If event is m.room.redaction, check redaction PL
      if (event_type == "m.room.redaction") {
        if (!check_power_level(db_, room_id, requester.user_id,
                                "m.room.redaction", 50)) {
          return BaseRestServlet::error_response(
              403, "M_FORBIDDEN",
              "You do not have permission to redact events");
        }
      }

      // Check for idempotent transaction reuse
      if (!txn_id.empty()) {
        bool already_sent = false;
        std::string existing_event_id;
        db_.runInteraction("check_txn",
            [&](storage::LoggingTransaction& txn) {
              txn.execute(
                  "SELECT event_id FROM event_txn_ids "
                  "WHERE txn_id=? AND room_id=? AND user_id=?",
                  {txn_id, room_id, requester.user_id});
              auto r = txn.fetchone();
              if (r && r->at(0).value) {
                already_sent = true;
                existing_event_id = *r->at(0).value;
              }
            });

        if (already_sent) {
          json resp;
          resp["event_id"] = existing_event_id;
          return BaseRestServlet::success_response(resp);
        }
      }

      // Send the event
      std::string room_version = get_room_version(db_, room_id);
      int64_t ts = now_ms();
      int64_t base_stream = get_max_stream_ordering(db_) + 1;
      std::string send_event_id;

      db_.runInteraction("send_event",
          [&](storage::LoggingTransaction& txn) {
            int64_t so = base_stream;

            txn.execute(
                "SELECT COALESCE(MAX(depth),0)+1 FROM events "
                "WHERE room_id=?",
                {room_id});
            auto dr = txn.fetchone();
            int64_t depth = (dr && dr->at(0).value)
                                ? std::stoll(*dr->at(0).value)
                                : 1;

            send_event_id = "$" + generate_event_id() + ":" + kServerName;

            // Determine if this is a state event
            bool is_state = starts_with(event_type, "m.room.");
            std::string state_key = "";
            if (body.contains("state_key") && body["state_key"].is_string()) {
              state_key = body["state_key"].get<std::string>();
            }

            persist_event(txn, send_event_id, room_id,
                          event_type, requester.user_id,
                          state_key,
                          body, depth, ++so, ts,
                          false, is_state, room_version);

            // Record transaction id for idempotency
            if (!txn_id.empty()) {
              txn.execute(
                  "INSERT INTO event_txn_ids "
                  "(event_id,room_id,user_id,txn_id,ts) "
                  "VALUES (?,?,?,?,?)",
                  {send_event_id, room_id, requester.user_id, txn_id, ts});
            }
          });

      json resp;
      resp["event_id"] = send_event_id;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

}  // namespace progressive
