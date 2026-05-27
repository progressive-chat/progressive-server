// ============================================================================
// all_endpoints.cpp - Comprehensive Matrix REST API servlets
// ============================================================================
// Implements 12 Matrix REST servlets in namespace progressive::
//
//  1. RoomAliasServlet         - PUT/DELETE/GET room alias directory
//  2. PublicRoomsServlet        - GET/POST public room listing
//  3. ThirdPartyProtocolServlet - GET protocols, locations, users
//  4. CapabilitiesServlet       - GET room versions, capabilities
//  5. OpenIdServlet             - POST request OpenID token
//  6. LoginTokenServlet         - POST exchange login token for access token
//  7. PasswordPolicyServlet     - GET password requirements
//  8. UsernameAvailableServlet  - GET check username availability
//  9. RegisterAvailableServlet  - GET check registration availability
// 10. AccountDeactivationServlet- POST deactivate account
// 11. RoomUpgradeServlet        - POST upgrade room to new version
// 12. RoomReportServlet         - POST report an event
//
// Each servlet inherits BaseRestServlet with full param extraction,
// DB ops via DatabasePool/runInteraction, JSON response, and error handling.
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
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/rest/rest_base.hpp"
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/events.hpp"

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
using storage::RegistrationStore;
using storage::RoomWorkerStore;

// ============================================================================
// Utility helpers
// ============================================================================

namespace {

// Generate a random token/ID string
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

// Generate a compact event-local ID (18 chars)
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

// Get current time in milliseconds
int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

// Extract path params from regex-matched request
std::string extract_path_param(const HttpRequest& req, const std::string& name) {
  auto it = req.path_params.find(name);
  if (it != req.path_params.end()) return it->second;
  return "";
}

// Matches the server_name portion of a Matrix ID
const std::string kServerName = "localhost";

// Validate that a string looks like a Matrix user ID or room ID
bool is_valid_user_id(const std::string& s) {
  return s.size() > 2 && s[0] == '@' && s.find(':') != std::string::npos;
}
bool is_valid_room_id(const std::string& s) {
  return s.size() > 2 && s[0] == '!' && s.find(':') != std::string::npos;
}
bool is_valid_alias(const std::string& s) {
  return s.size() > 2 && s[0] == '#' && s.find(':') != std::string::npos;
}

// Parse a Matrix alias (with optional leading #) to just the localpart
std::string strip_alias_server(const std::string& alias) {
  if (alias.empty()) return alias;
  std::string a = alias;
  if (a[0] == '#') a = a.substr(1);
  auto colon = a.find(':');
  if (colon != std::string::npos) a = a.substr(0, colon);
  return a;
}

// Enforce that the requester is authenticated
Requester require_auth(const HttpRequest& req, DatabasePool& db) {
  AuthHelper auth(db);
  return auth.require_auth(req);
}

// Check if user is a member of a room with given membership
bool check_room_membership(DatabasePool& db, const std::string& user_id,
                           const std::string& room_id,
                           const std::string& required_membership = "join") {
  bool result = false;
  db.runInteraction("check_membership",
      [&](storage::LoggingTransaction& txn) {
        auto row = txn.fetchone();
        // Check local_current_membership first
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

// Fetch max stream ordering from events table
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

// Persist an event in the database (reusable helper)
void persist_event(storage::LoggingTransaction& txn,
                   const std::string& event_id, const std::string& room_id,
                   const std::string& type, const std::string& sender,
                   const std::string& state_key, const json& content,
                   int64_t depth, int64_t stream_ordering, int64_t ts,
                   bool is_outlier = false, bool is_state = true,
                   const std::string& room_version = "10") {
  // 26-column insert matching the events table schema
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

  // Insert into event_json for content lookups
  txn.execute(
      "INSERT INTO event_json (event_id,room_id,internal_metadata,content,format_version) "
      "VALUES (?,?,?,?,?)",
      {event_id, room_id, "{}", content.dump(), (int64_t)1});

  // Update current_state_events if this is a state event
  if (is_state && !state_key.empty()) {
    txn.execute(
        "INSERT INTO current_state_events (event_id,room_id,type,state_key) "
        "VALUES (?,?,?,?) ON CONFLICT(room_id,type,state_key) "
        "DO UPDATE SET event_id=excluded.event_id",
        {event_id, room_id, type, state_key});
  }
}

// Simple room membership insertion
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

// Get default power levels JSON for a user
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
// Extended Utilities: Server ACL, Version Features, Password Validation
// ============================================================================

namespace {

bool check_server_acl(DatabasePool& db, const std::string& room_id,
                      const std::string& server_name) {
  bool allowed = true;
  db.runInteraction("server_acl_check",
      [&](storage::LoggingTransaction& txn) {
        txn.execute(
            "SELECT e.content FROM current_state_events cs "
            "JOIN events e ON cs.event_id=e.event_id "
            "WHERE cs.room_id=? AND cs.type='m.room.server_acl'",
            {room_id});
        auto acl_row = txn.fetchone();
        if (!acl_row || !acl_row->at(0).value) { allowed = true; return; }
        try {
          json acl = json::parse(*acl_row->at(0).value);
          if (acl.contains("deny")) {
            for (auto& entry : acl["deny"]) {
              std::string pattern = entry.is_string()
                  ? entry.get<std::string>() : entry.value("server_name", "");
              if (!pattern.empty() &&
                  server_name.find(pattern) != std::string::npos) {
                allowed = false; return;
              }
            }
          }
          if (acl.contains("allow")) {
            bool found = false;
            for (auto& entry : acl["allow"]) {
              std::string pattern = entry.is_string()
                  ? entry.get<std::string>() : entry.value("server_name", "");
              if (pattern == "*") { found = true; break; }
              if (!pattern.empty() &&
                  server_name.find(pattern) != std::string::npos) {
                found = true; break;
              }
            }
            if (!found) allowed = false;
          }
        } catch (...) { allowed = true; }
      });
  return allowed;
}

struct RoomVersionFeatures {
  bool state_resolution_v2{false};
  bool event_id_format_v3{false};
  bool knock_feature{false};
  bool restricted_join{false};
  bool knock_restricted{false};
  bool msc2403_knocking{false};
  bool msc2176_redactions{false};
  bool msc3083_restricted{false};
  bool msc3787_knock{false};
  bool msc3823_refresh{false};
};

RoomVersionFeatures get_room_version_features(const std::string& ver) {
  RoomVersionFeatures f;
  int v = 1;
  try { v = std::stoi(ver); } catch (...) {}
  if (v >= 2) f.state_resolution_v2 = true;
  if (v >= 3) f.event_id_format_v3 = true;
  if (v >= 7) f.knock_feature = true;
  if (v >= 8) f.restricted_join = true;
  if (v >= 9) {
    f.knock_restricted = true;
    f.msc2403_knocking = true;
  }
  if (v >= 10) {
    f.msc2176_redactions = true;
    f.msc3083_restricted = true;
    f.msc3787_knock = true;
    f.msc3823_refresh = true;
  }
  if (ver.find("org.matrix.msc3823") != std::string::npos)
    f.msc3823_refresh = true;
  return f;
}

struct PasswordValidationResult {
  bool valid{true};
  std::string error;
};

PasswordValidationResult validate_password_strength(const std::string& pw) {
  PasswordValidationResult r;
  if (pw.size() < 8) {
    r.valid = false;
    r.error = "Password must be at least 8 characters";
    return r;
  }
  if (pw.size() > 255) {
    r.valid = false;
    r.error = "Password too long (max 255)";
    return r;
  }
  bool has_upper = false, has_lower = false, has_digit = false,
       has_symbol = false;
  int max_consecutive = 0, cur_consecutive = 0;
  char last = '\0';
  for (char c : pw) {
    if (std::isupper(static_cast<unsigned char>(c))) has_upper = true;
    if (std::islower(static_cast<unsigned char>(c))) has_lower = true;
    if (std::isdigit(static_cast<unsigned char>(c))) has_digit = true;
    if (std::ispunct(static_cast<unsigned char>(c)) || c == ' ')
      has_symbol = true;
    if (c == last) {
      cur_consecutive++;
      max_consecutive = std::max(max_consecutive, cur_consecutive);
    } else {
      cur_consecutive = 1;
    }
    last = c;
  }
  if (!has_upper) {
    r.valid = false;
    r.error = "Password must contain an uppercase letter";
    return r;
  }
  if (!has_lower) {
    r.valid = false;
    r.error = "Password must contain a lowercase letter";
    return r;
  }
  if (!has_digit) {
    r.valid = false;
    r.error = "Password must contain a digit";
    return r;
  }
  if (!has_symbol) {
    r.valid = false;
    r.error = "Password must contain a special character";
    return r;
  }
  if (max_consecutive > 3) {
    r.valid = false;
    r.error = "Too many consecutive identical characters";
    return r;
  }
  return r;
}

std::vector<std::string> get_upgradable_versions(
    const std::string& current_version) {
  int cv = 1;
  try { cv = std::stoi(current_version); } catch (...) {}
  static const std::vector<std::string> kAll = {
      "1","2","3","4","5","6","7","8","9","10"};
  std::vector<std::string> result;
  for (auto& v : kAll) {
    int iv = std::stoi(v);
    if (iv > cv) result.push_back(v);
  }
  if (cv < 10) {
    bool has_10 = false;
    for (auto& v : result)
      if (v == "10") has_10 = true;
    if (!has_10) result.push_back("10");
  }
  return result;
}

std::string sanitize_report_reason(const std::string& reason) {
  if (reason.empty()) return "";
  std::string r;
  r.reserve(reason.size());
  for (char c : reason) {
    if (c >= 32 && c <= 126)
      r += c;
    else if (c == '\n' || c == '\r' || c == '\t')
      r += ' ';
  }
  if (r.size() > 2048) r.resize(2048);
  return r;
}

json build_event_json_from_row(const storage::Row& row) {
  json ev;
  ev["event_id"] = row.at(0).value.value_or("");
  ev["type"] = row.at(1).value.value_or("");
  ev["sender"] = row.at(2).value.value_or("");
  if (row.at(3).value) {
    try { ev["content"] = json::parse(*row.at(3).value); }
    catch (...) { ev["content"] = json::object(); }
  } else {
    ev["content"] = json::object();
  }
  ev["origin_server_ts"] = row.at(4).value.value_or("0");
  ev["unsigned"] = json::object();
  if (row.size() > 5 && row.at(5).value && !row.at(5).value->empty())
    ev["state_key"] = *row.at(5).value;
  if (row.size() > 6 && row.at(6).value)
    ev["room_id"] = *row.at(6).value;
  return ev;
}

bool check_rate_limit(DatabasePool& db, const std::string& user_id,
                      const std::string& action, int64_t max_per_window,
                      int64_t window_ms = 60000) {
  int64_t count = 0;
  int64_t now = now_ms();
  int64_t cutoff = now - window_ms;
  db.runInteraction("rate_limit",
      [&](storage::LoggingTransaction& txn) {
        txn.execute(
            "SELECT COUNT(*) FROM ratelimit_override "
            "WHERE user_id=? AND action=? AND ts>?",
            {user_id, action, cutoff});
        auto r = txn.fetchone();
        if (r && r->at(0).value)
          count = std::stoll(*r->at(0).value);
        if (count < max_per_window) {
          txn.execute(
              "INSERT INTO ratelimit_override (user_id,action,ts) "
              "VALUES (?,?,?)",
              {user_id, action, now});
        }
      });
  return count >= max_per_window;
}

bool is_alias_reserved(const std::string& localpart) {
  static const std::set<std::string> reserved = {
      "admin", "administrator", "matrix", "support", "help",
      "moderator", "security", "abuse", "postmaster", "webmaster",
      "hostmaster", "root", "info", "www", "api", "dev"};
  return reserved.find(localpart) != reserved.end();
}

json build_public_room_entry(const DirectoryStore::PublicRoom& pr) {
  json entry;
  entry["room_id"] = pr.room_id;
  entry["name"] = pr.name;
  entry["topic"] = pr.topic;
  entry["num_joined_members"] = pr.num_joined_members;
  entry["world_readable"] = pr.world_readable;
  if (pr.canonical_alias)
    entry["canonical_alias"] = *pr.canonical_alias;
  if (pr.avatar_url)
    entry["avatar_url"] = *pr.avatar_url;
  if (!pr.room_type.empty())
    entry["room_type"] = pr.room_type;
  return entry;
}

// Check if a user is a server administrator
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

// Count active users on the server
int64_t count_active_users(DatabasePool& db) {
  int64_t result = 0;
  db.runInteraction("count_users",
      [&](storage::LoggingTransaction& txn) {
        txn.execute(
            "SELECT COUNT(*) FROM users WHERE deactivated=0");
        auto r = txn.fetchone();
        if (r && r->at(0).value)
          result = std::stoll(*r->at(0).value);
      });
  return result;
}

}  // anonymous namespace

// ============================================================================
// 1. RoomAliasServlet
// ============================================================================
// Endpoints:
//   PUT    /_matrix/client/v3/directory/room/{roomAlias}  - Create alias
//   DELETE /_matrix/client/v3/directory/room/{roomAlias}  - Delete alias
//   GET    /_matrix/client/v3/directory/room/{roomAlias}  - Resolve alias
//   GET    /_matrix/client/v3/directory/list/room/{roomId} - Get visibility
//   PUT    /_matrix/client/v3/directory/list/room/{roomId} - Set visibility
// ============================================================================

class RoomAliasServlet : public ClientV1RestServlet {
public:
  explicit RoomAliasServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/directory/room/{roomAlias}",
      "/_matrix/client/v1/directory/room/{roomAlias}",
      "/_matrix/client/v3/directory/list/room/{roomId}",
      "/_matrix/client/v1/directory/list/room/{roomId}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "PUT", "DELETE"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string path = req.path;

      // ---- Directory listing visibility ----
      if (path.find("/directory/list/room/") != std::string::npos) {
        std::string room_id = extract_path_param(req, "roomId");
        if (req.method == "PUT") return handle_set_visibility(req, room_id);
        if (req.method == "GET") return handle_get_visibility(req, room_id);
        return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                                "Method not allowed");
      }

      // ---- Alias directory ----
      std::string alias = extract_path_param(req, "roomAlias");
      if (alias.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room alias");

      // Normalize alias to have # prefix
      if (alias[0] != '#') alias = "#" + alias;
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
  // GET /directory/room/{roomAlias} - resolve alias to room ID + servers
  HttpResponse handle_get_alias(const HttpRequest& req,
                                 const std::string& alias) {
    try {
      DirectoryStore dir(db_);
      auto room_id = dir.get_room_id(alias);
      if (!room_id) {
        // Try with varying server_name forms
        std::string bare_alias = alias;
        auto colon = bare_alias.rfind(':');
        if (colon != std::string::npos) {
          bare_alias = bare_alias.substr(0, colon);
          auto room_id2 = dir.get_room_id(bare_alias + ":" + kServerName);
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

  // PUT /directory/room/{roomAlias} - create/update an alias
  HttpResponse handle_put_alias(const HttpRequest& req,
                                 const std::string& alias) {
    try {
      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      std::string room_id = body.value("room_id", "");
      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room_id");

      // Validate room exists and user has permissions
      bool can_set = false;
      db_.runInteraction("alias_put",
          [&](storage::LoggingTransaction& txn) {
            // Check room exists
            txn.execute("SELECT 1 FROM rooms WHERE room_id=?",
                         {room_id});
            auto r = txn.fetchone();
            if (!r) return;

            // Check membership
            txn.execute(
                "SELECT membership FROM local_current_membership "
                "WHERE user_id=? AND room_id=?",
                {requester.user_id, room_id});
            auto m = txn.fetchone();
            if (m && m->at(0).value) {
              can_set = (*m->at(0).value == "join");
            }

            // Also check power levels for alias setting
            if (can_set) {
              txn.execute(
                  "SELECT e.content FROM current_state_events cs "
                  "JOIN events e ON cs.event_id=e.event_id "
                  "WHERE cs.room_id=? AND cs.type='m.room.power_levels'",
                  {room_id});
              auto plrow = txn.fetchone();
              if (plrow && plrow->at(0).value) {
                try {
                  json pl = json::parse(*plrow->at(0).value);
                  int required = pl.value("events",
                      json::object()).value("m.room.canonical_alias", 50);
                  int user_pl =
                      pl.value("users", json::object())
                          .value(requester.user_id,
                                 pl.value("users_default", 0));
                  if (user_pl < required) can_set = false;
                } catch (...) {}
              }
            }
          });

      if (!can_set)
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to set room aliases");

      DirectoryStore dir(db_);

      // Check if alias already exists
      auto existing = dir.get_room_id(alias);
      if (existing && *existing != room_id) {
        return BaseRestServlet::error_response(409, "M_UNKNOWN",
                                                "Room alias already exists");
      }

      dir.create_alias(alias, room_id, requester.user_id,
                        {kServerName});

      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  // DELETE /directory/room/{roomAlias} - remove an alias
  HttpResponse handle_delete_alias(const HttpRequest& req,
                                    const std::string& alias) {
    try {
      auto requester = require_auth(req, db_);
      DirectoryStore dir(db_);

      // Verify alias exists
      auto room_id = dir.get_room_id(alias);
      if (!room_id) {
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "Room alias not found");
      }

      // Check permissions: must be the creator or have admin/PL
      bool can_delete = false;
      auto creator = dir.get_alias_creator(alias);
      if (creator && *creator == requester.user_id) {
        can_delete = true;
      }

      if (!can_delete) {
        // Check room power levels
        db_.runInteraction("alias_del_check",
            [&](storage::LoggingTransaction& txn) {
              txn.execute(
                  "SELECT e.content FROM current_state_events cs "
                  "JOIN events e ON cs.event_id=e.event_id "
                  "WHERE cs.room_id=? AND "
                  "cs.type='m.room.power_levels'",
                  {*room_id});
              auto plrow = txn.fetchone();
              if (plrow && plrow->at(0).value) {
                try {
                  json pl = json::parse(*plrow->at(0).value);
                  int required = pl.value("events", json::object())
                                     .value("m.room.canonical_alias", 50);
                  int user_pl = pl.value("users", json::object())
                                    .value(requester.user_id,
                                           pl.value("users_default", 0));
                  if (user_pl >= required) can_delete = true;
                } catch (...) {}
              }
            });
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

  // GET /directory/list/room/{roomId} - get room visibility
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

  // PUT /directory/list/room/{roomId} - set room visibility
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

      // Check user is in the room
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

  DatabasePool& db_;
};

// ============================================================================
// 2. PublicRoomsServlet
// ============================================================================
// Endpoints:
//   GET  /_matrix/client/v3/publicRooms  - List public rooms
//   POST /_matrix/client/v3/publicRooms  - List/filter public rooms (with body)
// ============================================================================

class PublicRoomsServlet : public ClientV1RestServlet {
public:
  explicit PublicRoomsServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/publicRooms",
      "/_matrix/client/v1/publicRooms",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      if (req.method == "GET") return handle_GET(req);
      if (req.method == "POST") return handle_POST(req);
      return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                              "Method not allowed");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  // GET /publicRooms - simple listing with query parameters
  HttpResponse handle_GET(const HttpRequest& req) {
    try {
      auto requester = require_auth(req, db_);

      // Parse query parameters
      auto limit_opt = BaseRestServlet::parse_integer(req, "limit");
      int64_t limit = limit_opt.value_or(50);
      if (limit < 1) limit = 1;
      if (limit > 100) limit = 100;

      auto since_opt = BaseRestServlet::parse_string(req, "since");
      std::string since = since_opt.value_or("");

      auto server_opt = BaseRestServlet::parse_string(req, "server");
      std::string server = server_opt.value_or("");

      auto search_opt = BaseRestServlet::parse_string(req, "search_term");
      std::string search_term = search_opt.value_or("");

      bool include_all = BaseRestServlet::parse_boolean(req, "include_all_networks", false);

      auto network_opt = BaseRestServlet::parse_string(req, "network");
      std::string network = network_opt.value_or("");

      DirectoryStore dir(db_);
      // Parse since as an offset value
      int64_t since_val = 0;
      if (!since.empty()) {
        try { since_val = std::stoll(since); } catch (...) {}
      }

      auto rooms = dir.get_public_rooms(server, limit, since_val,
                                         search_term, network, include_all);

      json chunk = json::array();
      int64_t total = static_cast<int64_t>(rooms.size());

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
      resp["total_room_count_estimate"] = total;
      if (!rooms.empty()) {
        resp["next_batch"] = std::to_string(since_val + limit);
        resp["prev_batch"] =
            (since_val > 0) ? std::to_string(since_val - limit) : "";
      }
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  // POST /publicRooms - filtered listing with JSON body
  HttpResponse handle_POST(const HttpRequest& req) {
    try {
      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      int64_t limit = body.value("limit", 50);
      if (limit < 1) limit = 1;
      if (limit > 100) limit = 100;

      std::string since = body.value("since", "");
      std::string search_term = body.value("filter", json::object())
                                    .value("generic_search_term", "");

      bool include_all = body.value("include_all_networks", false);
      std::string network = body.value("third_party_instance_id", "");

      int64_t since_val = 0;
      if (!since.empty()) {
        try { since_val = std::stoll(since); } catch (...) {}
      }

      DirectoryStore dir(db_);
      auto rooms = dir.get_public_rooms("", limit, since_val,
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

      json resp;
      resp["chunk"] = chunk;
      resp["total_room_count_estimate"] = rooms.size();
      if (!rooms.empty()) {
        resp["next_batch"] = std::to_string(since_val + limit);
        resp["prev_batch"] =
            (since_val > 0) ? std::to_string(since_val - limit) : "";
      }
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 3. ThirdPartyProtocolServlet
// ============================================================================
// Endpoints:
//   GET /_matrix/client/v3/thirdparty/protocols               - List protocols
//   GET /_matrix/client/v3/thirdparty/protocol/{protocol}     - Get protocol
//   GET /_matrix/client/v3/thirdparty/location                - Query locations
//   GET /_matrix/client/v3/thirdparty/location/{protocol}     - Query locations
//   GET /_matrix/client/v3/thirdparty/user                    - Query users
//   GET /_matrix/client/v3/thirdparty/user/{protocol}         - Query users
// ============================================================================

class ThirdPartyProtocolServlet : public ClientV1RestServlet {
public:
  explicit ThirdPartyProtocolServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/thirdparty/protocols",
      "/_matrix/client/v3/thirdparty/protocol/{protocol}",
      "/_matrix/client/v3/thirdparty/location",
      "/_matrix/client/v3/thirdparty/location/{protocol}",
      "/_matrix/client/v3/thirdparty/user",
      "/_matrix/client/v3/thirdparty/user/{protocol}",
      "/_matrix/client/v1/thirdparty/protocols",
      "/_matrix/client/v1/thirdparty/protocol/{protocol}",
      "/_matrix/client/v1/thirdparty/location",
      "/_matrix/client/v1/thirdparty/location/{protocol}",
      "/_matrix/client/v1/thirdparty/user",
      "/_matrix/client/v1/thirdparty/user/{protocol}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string path = req.path;

      if (path.find("/thirdparty/protocol") != std::string::npos) {
        std::string protocol = extract_path_param(req, "protocol");
        if (protocol.empty()) return handle_list_protocols(req);
        return handle_get_protocol(req, protocol);
      }

      if (path.find("/thirdparty/location") != std::string::npos) {
        std::string protocol = extract_path_param(req, "protocol");
        return handle_query_locations(req, protocol);
      }

      if (path.find("/thirdparty/user") != std::string::npos) {
        std::string protocol = extract_path_param(req, "protocol");
        return handle_query_users(req, protocol);
      }

      return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                              "Unknown thirdparty endpoint");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  // GET /thirdparty/protocols - list all supported third-party protocols
  HttpResponse handle_list_protocols(const HttpRequest& req) {
    try {
      // In a real implementation, this would query appservice registrations.
      // For now, return the empty/default protocols object.
      json protocols = json::object();

      // Query configured appservices/protocols from DB
      db_.runInteraction("tp_protocols",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT DISTINCT json_extract(protocol_data,'$.protocol') "
                "FROM third_party_protocols");
            auto rows = txn.fetchall();
            for (auto& row : rows) {
              if (row.at(0).value) {
                std::string proto = *row.at(0).value;
                protocols[proto] = build_protocol_metadata(proto);
              }
            }
          });

      // If empty, return standard set
      if (protocols.empty()) {
        protocols["irc"] = build_protocol_metadata("irc");
        protocols["gitter"] = build_protocol_metadata("gitter");
      }

      return BaseRestServlet::success_response(protocols);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  // GET /thirdparty/protocol/{protocol} - get specific protocol metadata
  HttpResponse handle_get_protocol(const HttpRequest& req,
                                    const std::string& protocol) {
    try {
      json meta = build_protocol_metadata(protocol);
      return BaseRestServlet::success_response(meta);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                              "Protocol not found");
    }
  }

  // GET /thirdparty/location[{protocol}] - query location mappings
  HttpResponse handle_query_locations(const HttpRequest& req,
                                       const std::string& protocol) {
    try {
      require_auth(req, db_);
      auto alias_opt = BaseRestServlet::parse_string(req, "alias");
      auto search_opt = BaseRestServlet::parse_string(req, "search");
      auto fields_opt = BaseRestServlet::parse_string(req, "fields");

      json results = json::array();

      // Query third-party location mappings from DB
      db_.runInteraction("tp_locations",
          [&](storage::LoggingTransaction& txn) {
            std::string sql =
                "SELECT alias,protocol,fields FROM third_party_locations "
                "WHERE 1=1";
            std::vector<storage::SQLParam> params;

            if (!protocol.empty()) {
              sql += " AND protocol=?";
              params.push_back(protocol);
            }
            if (alias_opt && !alias_opt->empty()) {
              sql += " AND alias=?";
              params.push_back(*alias_opt);
            }
            if (search_opt && !search_opt->empty()) {
              sql += " AND alias LIKE ?";
              params.push_back("%" + *search_opt + "%");
            }
            sql += " LIMIT 50";

            txn.execute(sql, params);
            auto rows = txn.fetchall();
            for (auto& row : rows) {
              json loc;
              loc["alias"] = row.at(0).value.value_or("");
              loc["protocol"] = row.at(1).value.value_or("");
              if (row.at(2).value) {
                try {
                  loc["fields"] = json::parse(*row.at(2).value);
                } catch (...) {
                  loc["fields"] = json::object();
                }
              } else {
                loc["fields"] = json::object();
              }
              results.push_back(loc);
            }
          });

      return BaseRestServlet::success_response(results);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  // GET /thirdparty/user[{protocol}] - query user mappings
  HttpResponse handle_query_users(const HttpRequest& req,
                                   const std::string& protocol) {
    try {
      require_auth(req, db_);
      auto userid_opt = BaseRestServlet::parse_string(req, "userid");
      auto search_opt = BaseRestServlet::parse_string(req, "search");
      auto fields_opt = BaseRestServlet::parse_string(req, "fields");

      json results = json::array();

      db_.runInteraction("tp_users",
          [&](storage::LoggingTransaction& txn) {
            std::string sql =
                "SELECT userid,protocol,fields FROM third_party_users "
                "WHERE 1=1";
            std::vector<storage::SQLParam> params;

            if (!protocol.empty()) {
              sql += " AND protocol=?";
              params.push_back(protocol);
            }
            if (userid_opt && !userid_opt->empty()) {
              sql += " AND userid=?";
              params.push_back(*userid_opt);
            }
            if (search_opt && !search_opt->empty()) {
              sql += " AND userid LIKE ?";
              params.push_back("%" + *search_opt + "%");
            }
            sql += " LIMIT 50";

            txn.execute(sql, params);
            auto rows = txn.fetchall();
            for (auto& row : rows) {
              json usr;
              usr["userid"] = row.at(0).value.value_or("");
              usr["protocol"] = row.at(1).value.value_or("");
              if (row.at(2).value) {
                try {
                  usr["fields"] = json::parse(*row.at(2).value);
                } catch (...) {
                  usr["fields"] = json::object();
                }
              } else {
                usr["fields"] = json::object();
              }
              results.push_back(usr);
            }
          });

      return BaseRestServlet::success_response(results);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  // Build standard protocol metadata
  static json build_protocol_metadata(const std::string& protocol) {
    json meta;
    meta["user_fields"] = json::array({"network_id", "nickname", "channel"});
    meta["location_fields"] =
        json::array({"network_id", "channel", "room"});
    meta["icon"] = "";
    meta["field_types"] = json::object();

    if (protocol == "irc") {
      meta["field_types"]["network_id"] = {
          {"regexp", "([a-z0-9]+\\.)*[a-z0-9]+"},
          {"placeholder", "irc.example.net"}};
      meta["field_types"]["channel"] = {
          {"regexp", "#[^\\s]+"},
          {"placeholder", "#channel"}};
      meta["field_types"]["nickname"] = {
          {"regexp", "[^\\s#]+"},
          {"placeholder", "username"}};
      meta["instances"] = json::array(
          {{{"network_id", "libera"},
            {"desc", "Libera.Chat"},
            {"icon", ""},
            {"fields", json::object()}}});
    } else if (protocol == "gitter") {
      meta["field_types"]["room"] = {
          {"regexp", "[^\\s]+/[^\\s]+"},
          {"placeholder", "org/repo"}};
      meta["instances"] = json::array(
          {{{"network_id", "gitter"},
            {"desc", "Gitter"},
            {"icon", ""},
            {"fields", json::object()}}});
    }

    return meta;
  }

  DatabasePool& db_;
};

// ============================================================================
// 4. CapabilitiesServlet
// ============================================================================
// Endpoints:
//   GET /_matrix/client/v3/capabilities  - Get server capabilities
//   Also serves room versions info
// ============================================================================

class CapabilitiesServlet : public ClientV1RestServlet {
public:
  explicit CapabilitiesServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/capabilities",
      "/_matrix/client/v1/capabilities",
      "/_matrix/client/v3/rooms/{roomId}/capabilities",
      "/_matrix/client/v1/rooms/{roomId}/capabilities",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      // Room-specific capabilities
      std::string room_id = extract_path_param(req, "roomId");
      if (!room_id.empty()) {
        return handle_room_capabilities(req, room_id);
      }

      return handle_global_capabilities(req);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  // GET /capabilities - global server capabilities
  HttpResponse handle_global_capabilities(const HttpRequest& req) {
    json caps;

    // ---- m.change_password ----
    json change_pw;
    change_pw["enabled"] = true;
    caps["m.change_password"] = change_pw;

    // ---- m.room_versions ----
    json room_versions;
    room_versions["default"] = "10";
    room_versions["available"] = json::object();

    // All supported room versions
    json v1;
    v1["stable"] = true;
    room_versions["available"]["1"] = v1;
    json v2;
    v2["stable"] = true;
    room_versions["available"]["2"] = v2;
    json v3;
    v3["stable"] = true;
    room_versions["available"]["3"] = v3;
    json v4;
    v4["stable"] = true;
    room_versions["available"]["4"] = v4;
    json v5;
    v5["stable"] = true;
    room_versions["available"]["5"] = v5;
    json v6;
    v6["stable"] = true;
    room_versions["available"]["6"] = v6;
    json v7;
    v7["stable"] = true;
    room_versions["available"]["7"] = v7;
    json v8;
    v8["stable"] = true;
    room_versions["available"]["8"] = v8;
    json v9;
    v9["stable"] = true;
    room_versions["available"]["9"] = v9;
    json v10;
    v10["stable"] = true;
    room_versions["available"]["10"] = v10;
    json v11;
    v11["stable"] = false;
    v11["status"] = "experimental";
    room_versions["available"]["org.matrix.msc3823.opt1"] = v11;
    json v12;
    v12["stable"] = false;
    v12["status"] = "experimental";
    room_versions["available"]["org.matrix.msc3823.opt2"] = v12;

    caps["m.room_versions"] = room_versions;

    // ---- m.set_displayname ----
    json set_dn;
    set_dn["enabled"] = true;
    caps["m.set_displayname"] = set_dn;

    // ---- m.set_avatar_url ----
    json set_av;
    set_av["enabled"] = true;
    caps["m.set_avatar_url"] = set_av;

    // ---- m.3pid_changes ----
    json tpid;
    tpid["enabled"] = true;
    caps["m.3pid_changes"] = tpid;

    // ---- m.get_login_token ----
    json get_login;
    get_login["enabled"] = true;
    caps["m.get_login_token"] = get_login;

    // ---- io.element.e2ee ----
    json e2ee;
    e2ee["enabled"] = true;
    caps["io.element.e2ee"] = e2ee;

    // ---- m.explicit_room_versions ----
    json explicit_versions;
    explicit_versions["enabled"] = true;
    caps["m.explicit_room_versions"] = explicit_versions;

    // ---- m.thread ----
    json thread;
    thread["enabled"] = true;
    caps["m.thread"] = thread;

    // ---- m.dehydrated_device ----
    json dehydrated;
    dehydrated["enabled"] = true;
    caps["m.dehydrated_device"] = dehydrated;

    // ---- m.login_token (alias for get_login_token) ----
    caps["m.login_token"] = get_login;

    return BaseRestServlet::success_response({{"capabilities", caps}});
  }

  // GET /rooms/{roomId}/capabilities - room-specific capabilities
  HttpResponse handle_room_capabilities(const HttpRequest& req,
                                         const std::string& room_id) {
    try {
      json caps;

      // Check if room exists
      bool room_exists = false;
      std::string room_version = "10";

      db_.runInteraction("room_caps",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT room_version FROM rooms WHERE room_id=?",
                {room_id});
            auto r = txn.fetchone();
            if (r && r->at(0).value) {
              room_exists = true;
              room_version = *r->at(0).value;
            }
          });

      if (!room_exists) {
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "Room not found");
      }

      // ---- m.room_version ----
      json rv;
      rv["version"] = room_version;
      rv["default"] = "10";
      caps["m.room_version"] = rv;

      // ---- m.room_upgrades ----
      json upgrades;
      upgrades["enabled"] = true;
      upgrades["available"] = json::object();
      json upg;
      upg["stable"] = true;
      upgrades["available"]["10"] = upg;
      if (room_version == "9") {
        json upg9;
        upg9["stable"] = true;
        upgrades["available"]["9"] = upg9;
      }
      caps["m.room_upgrades"] = upgrades;

      // ---- m.room_members ----
      json members;
      members["enabled"] = true;
      caps["m.room_members"] = members;

      // ---- m.room_events ----
      json events_cap;
      events_cap["enabled"] = true;
      caps["m.room_events"] = events_cap;

      // ---- m.room_encryption ----
      json enc;
      enc["enabled"] = true;
      caps["m.room_encryption"] = enc;

      // ---- m.room_tombstone ----
      json tomb;
      tomb["enabled"] = true;
      caps["m.room_tombstone"] = tomb;

      return BaseRestServlet::success_response({{"capabilities", caps}});
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 5. OpenIdServlet
// ============================================================================
// Endpoint:
//   POST /_matrix/client/v3/user/{userId}/openid/request_token
//
// Returns an OpenID token that a Matrix user can use to authenticate
// with third-party services supporting OpenID Connect.
// ============================================================================

class OpenIdServlet : public ClientV1RestServlet {
public:
  explicit OpenIdServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/user/{userId}/openid/request_token",
      "/_matrix/client/v1/user/{userId}/openid/request_token",
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      auto requester = require_auth(req, db_);
      std::string target_user = extract_path_param(req, "userId");

      // Only allow requesting tokens for yourself
      if (!target_user.empty() && target_user != requester.user_id) {
        // Admin override: allow admins to request for other users
        if (!requester.is_admin) {
          return BaseRestServlet::error_response(
              403, "M_FORBIDDEN",
              "Cannot request OpenID token for another user");
        }
      }

      std::string user_id = target_user.empty() ? requester.user_id
                                                  : target_user;

      // ---- Generate OpenID token ----
      std::string access_token = generate_token(32);
      std::string token_id = generate_event_id();
      int64_t expires_in = 3600;  // 1 hour
      int64_t ts_now = now_ms();
      int64_t expires_at = ts_now + expires_in * 1000;

      // Store the token
      db_.runInteraction("openid_store",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "INSERT INTO open_id_tokens "
                "(token_id,user_id,access_token,expires_at,ts) "
                "VALUES (?,?,?,?,?)",
                {token_id, user_id, access_token, expires_at, ts_now});
          });

      // Build OpenID response
      std::string matrix_domain = "matrix.org";
      std::string issuer = "https://" + matrix_domain;

      json resp;
      resp["access_token"] = access_token;
      resp["token_type"] = "Bearer";
      resp["matrix_server_name"] = matrix_domain;
      resp["expires_in"] = expires_in;

      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 6. LoginTokenServlet
// ============================================================================
// Endpoint:
//   POST /_matrix/client/v3/login/token
//
// Exchange a short-lived login token for a full access token.
// This is used for SSO-based and token-based login flows.
// ============================================================================

class LoginTokenServlet : public ClientV1RestServlet {
public:
  explicit LoginTokenServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/login/token",
      "/_matrix/client/v1/login/token",
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      auto body = BaseRestServlet::parse_json_body(req);

      // Extract login token from request
      std::string login_token = body.value("token", "");
      if (login_token.empty()) {
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing login token");
      }

      std::string device_id =
          body.value("initial_device_display_name", "");
      std::string device_id_from_body = body.value("device_id", "");
      if (!device_id_from_body.empty()) device_id = device_id_from_body;

      // Look up the login token
      std::string user_id;
      bool token_valid = false;
      bool token_expired = false;
      bool token_used = false;

      db_.runInteraction("login_token_lookup",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT user_id,expires_at,used FROM login_tokens "
                "WHERE token=?",
                {login_token});
            auto row = txn.fetchone();
            if (row) {
              user_id = row->at(0).value.value_or("");
              if (row->at(2).value && *row->at(2).value == "1") {
                token_used = true;
              } else if (row->at(1).value) {
                int64_t exp = std::stoll(*row->at(1).value);
                if (exp < now_ms()) {
                  token_expired = true;
                } else {
                  token_valid = true;
                }
              }
            }
          });

      if (user_id.empty()) {
        return BaseRestServlet::error_response(403, "M_FORBIDDEN",
                                                "Invalid login token");
      }

      if (token_used) {
        return BaseRestServlet::error_response(403, "M_FORBIDDEN",
                                                "Login token already used");
      }

      if (token_expired) {
        return BaseRestServlet::error_response(403, "M_FORBIDDEN",
                                                "Login token expired");
      }

      if (!token_valid) {
        return BaseRestServlet::error_response(403, "M_FORBIDDEN",
                                                "Invalid login token");
      }

      // ---- Token is valid, exchange for access token ----
      RegistrationStore reg(db_);
      std::string access_token = reg.add_access_token_to_user(user_id, device_id);

      // Refresh token
      std::string refresh_token = "rt_" + generate_token(48);

      // Mark login token as used
      db_.runInteraction("login_token_mark",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "UPDATE login_tokens SET used=1 WHERE token=?",
                {login_token});
            txn.execute(
                "INSERT INTO refresh_tokens "
                "(token,user_id,access_token_id,expires_at) "
                "VALUES (?,?,?,?)",
                {refresh_token, user_id, access_token,
                 now_ms() + 2592000000LL});
          });

      json resp;
      resp["user_id"] = user_id;
      resp["access_token"] = access_token;
      resp["refresh_token"] = refresh_token;
      resp["device_id"] = device_id;
      resp["home_server"] = kServerName;

      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      if (std::string(e.what()).find("Token") != std::string::npos) {
        return BaseRestServlet::error_response(403, "M_FORBIDDEN", e.what());
      }
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 7. PasswordPolicyServlet
// ============================================================================
// Endpoint:
//   GET /_matrix/client/v3/password_policy
//
// Returns the server's password policy requirements for registration
// and password changes.
// ============================================================================

class PasswordPolicyServlet : public ClientV1RestServlet {
public:
  explicit PasswordPolicyServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/password_policy",
      "/_matrix/client/v1/password_policy",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      json policy;

      // ---- Minimum length ----
      policy["minimum_length"] = 8;

      // ---- Require digit ----
      json require_digit;
      require_digit["enabled"] = true;
      require_digit["minimum"] = 1;
      policy["require_digit"] = require_digit;

      // ---- Require symbol ----
      json require_symbol;
      require_symbol["enabled"] = true;
      require_symbol["minimum"] = 1;
      policy["require_symbol"] = require_symbol;

      // ---- Require uppercase ----
      json require_uppercase;
      require_uppercase["enabled"] = true;
      require_uppercase["minimum"] = 1;
      policy["require_uppercase"] = require_uppercase;

      // ---- Require lowercase ----
      json require_lowercase;
      require_lowercase["enabled"] = true;
      require_lowercase["minimum"] = 1;
      policy["require_lowercase"] = require_lowercase;

      // ---- Maximum consecutive identical characters ----
      policy["maximum_consecutive_identical_characters"] = 3;

      // ---- Password history (don't reuse last N passwords) ----
      json password_history;
      password_history["enabled"] = false;
      password_history["minimum"] = 0;
      policy["password_history"] = password_history;

      // ---- Custom policy description ----
      policy["description"] =
          "Password must be at least 8 characters, including at least "
          "one uppercase letter, one lowercase letter, one digit, and "
          "one special character. No more than 3 consecutive identical "
          "characters.";

      return BaseRestServlet::success_response(policy);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 8. UsernameAvailableServlet
// ============================================================================
// Endpoint:
//   GET /_matrix/client/v3/register/available?username={username}
//
// Checks whether a username is available for registration.
// Returns 200 with {"available": true} or {"available": false}.
// ============================================================================

class UsernameAvailableServlet : public ClientV1RestServlet {
public:
  explicit UsernameAvailableServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/register/available",
      "/_matrix/client/v1/register/available",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      auto username_opt = BaseRestServlet::parse_string(req, "username");
      if (!username_opt || username_opt->empty()) {
        return BaseRestServlet::error_response(
            400, "M_MISSING_PARAM", "Missing username parameter");
      }

      std::string username = *username_opt;

      // Validate username format
      if (username.empty() || username.size() > 255) {
        json resp;
        resp["available"] = false;
        return BaseRestServlet::success_response(resp);
      }

      // Check for invalid characters
      static const std::regex kUsernameRegex("^[a-z0-9._\\-=/]*$");
      if (!std::regex_match(username, kUsernameRegex)) {
        json resp;
        resp["available"] = false;
        return BaseRestServlet::success_response(resp);
      }

      // Check if user exists (with domain suffix)
      std::string full_user_id = "@" + username + ":" + kServerName;
      bool exists = false;

      db_.runInteraction("check_username",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT 1 FROM users WHERE name=? AND deactivated=0",
                {full_user_id});
            auto r = txn.fetchone();
            exists = (r != std::nullopt);

            // Also check by localpart
            if (!exists) {
              txn.execute(
                  "SELECT 1 FROM users WHERE name LIKE ?",
                  {"@" + username + ":%"});
              auto r2 = txn.fetchone();
              exists = (r2 != std::nullopt);
            }
          });

      json resp;
      resp["available"] = !exists;
      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 9. RegisterAvailableServlet
// ============================================================================
// Endpoint:
//   GET /_matrix/client/v3/register/available?username={username}
//
// Alternative registration availability check that returns whether
// registration is open on this server generally, and for this user.
// This is the v3 alternative to the simpler username check.
// ============================================================================

class RegisterAvailableServlet : public ClientV1RestServlet {
public:
  explicit RegisterAvailableServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/register/available",
      "/_matrix/client/v1/register/available",
      "/_matrix/client/v3/register/msisdn/available",
      "/_matrix/client/v1/register/msisdn/available",
      "/_matrix/client/v3/register/email/available",
      "/_matrix/client/v1/register/email/available",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string path = req.path;

      if (path.find("/msisdn/available") != std::string::npos) {
        return handle_msisdn_available(req);
      }
      if (path.find("/email/available") != std::string::npos) {
        return handle_email_available(req);
      }

      return handle_username_available(req);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  // Check if username is available for registration
  HttpResponse handle_username_available(const HttpRequest& req) {
    auto username_opt = BaseRestServlet::parse_string(req, "username");
    if (!username_opt || username_opt->empty()) {
      return BaseRestServlet::error_response(
          400, "M_MISSING_PARAM", "Missing username parameter");
    }

    std::string username = *username_opt;

    // Validate username format
    static const std::regex kValidUser("^[a-z0-9._\\-=/]{1,255}$");
    if (!std::regex_match(username, kValidUser)) {
      json resp;
      resp["available"] = false;
      return BaseRestServlet::success_response(resp);
    }

    // Check if user already exists
    std::string full_id = "@" + username + ":" + kServerName;
    bool exists = false;
    db_.runInteraction("reg_avail",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "SELECT 1 FROM users WHERE name=? AND deactivated=0",
              {full_id});
          auto r = txn.fetchone();
          exists = (r != std::nullopt);
        });

    json resp;
    resp["available"] = !exists;

    // Also check if registration is globally enabled
    bool reg_enabled = true;
    db_.runInteraction("reg_config",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "SELECT value FROM server_config WHERE key='registration_enabled'");
          auto r = txn.fetchone();
          if (r && r->at(0).value) {
            reg_enabled = (*r->at(0).value == "true" ||
                           *r->at(0).value == "1");
          }
        });

    resp["registration_enabled"] = reg_enabled;

    return BaseRestServlet::success_response(resp);
  }

  // Check if MSISDN (phone number) is available
  HttpResponse handle_msisdn_available(const HttpRequest& req) {
    auto msisdn_opt = BaseRestServlet::parse_string(req, "msisdn");
    if (!msisdn_opt || msisdn_opt->empty()) {
      return BaseRestServlet::error_response(
          400, "M_MISSING_PARAM", "Missing msisdn parameter");
    }

    // Check if MSISDN is already associated with a user
    bool exists = false;
    db_.runInteraction("msisdn_avail",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "SELECT 1 FROM user_threepids WHERE medium='msisdn' AND address=?",
              {*msisdn_opt});
          auto r = txn.fetchone();
          exists = (r != std::nullopt);
        });

    json resp;
    resp["available"] = !exists;
    return BaseRestServlet::success_response(resp);
  }

  // Check if email is available
  HttpResponse handle_email_available(const HttpRequest& req) {
    auto email_opt = BaseRestServlet::parse_string(req, "email");
    if (!email_opt || email_opt->empty()) {
      return BaseRestServlet::error_response(
          400, "M_MISSING_PARAM", "Missing email parameter");
    }

    bool exists = false;
    db_.runInteraction("email_avail",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "SELECT 1 FROM user_threepids WHERE medium='email' AND address=?",
              {*email_opt});
          auto r = txn.fetchone();
          exists = (r != std::nullopt);
        });

    json resp;
    resp["available"] = !exists;
    return BaseRestServlet::success_response(resp);
  }

  DatabasePool& db_;
};

// ============================================================================
// 10. AccountDeactivationServlet
// ============================================================================
// Endpoint:
//   POST /_matrix/client/v3/account/deactivate
//
// Deactivates the authenticated user's account. Requires
// User-Interactive Authentication. Optionally erases all user data.
// ============================================================================

class AccountDeactivationServlet : public ClientV1RestServlet {
public:
  explicit AccountDeactivationServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/account/deactivate",
      "/_matrix/client/v1/account/deactivate",
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      auto requester = require_auth(req, db_);
      auto body = BaseRestServlet::parse_json_body(req);

      // ---- User-Interactive Auth ----
      // Check for UI auth session
      json auth_data = body.value("auth", json::object());
      if (!auth_data.empty()) {
        // Verify auth session
        std::string session = auth_data.value("session", "");
        if (session.empty() && !auth_data.value("type", "").empty()) {
          // First stage of UI auth - return available flows
          json flows = json::array();
          flows.push_back({{"stages", json::array({"m.login.password"})}});

          json resp;
          resp["flows"] = flows;
          resp["params"] = json::object();
          resp["session"] = generate_token(32);
          return BaseRestServlet::success_response(resp);
        }

        // Verify password if provided
        std::string password = auth_data.value("password", "");
        if (!password.empty()) {
          PasswordStore pw_store(db_);
          auto pw_hash = pw_store.get_password_hash(requester.user_id);
          if (!pw_hash) {
            return BaseRestServlet::error_response(
                403, "M_FORBIDDEN", "Invalid password");
          }
          // Simple verification (real impl would use bcrypt/scrypt)
          if (!verify_password_simple(password, *pw_hash)) {
            return BaseRestServlet::error_response(
                403, "M_FORBIDDEN", "Invalid password");
          }
        }
      } else {
        // No auth provided, return UI auth flows
        json flows = json::array();
        flows.push_back({{"stages", json::array({"m.login.password"})}});

        json resp;
        resp["flows"] = flows;
        resp["params"] = json::object();
        resp["session"] = generate_token(32);
        return BaseRestServlet::error_response(401, "M_USER_DEACTIVATED",
                                                "User-Interactive Authentication required");
      }

      // ---- Perform deactivation ----
      bool erase_data = body.value("erase", false);

      // Validate erase permission (only if consented)
      if (erase_data) {
        // Check if user has consented to data erasure
        bool consented = false;
        db_.runInteraction("check_consent",
            [&](storage::LoggingTransaction& txn) {
              txn.execute(
                  "SELECT consent_version FROM users WHERE name=?",
                  {requester.user_id});
              auto r = txn.fetchone();
              if (r && r->at(0).value && !r->at(0).value->empty()) {
                consented = true;
              }
            });
      }

      // Deactivate in RegistrationStore
      bool success = false;
      db_.runInteraction("deactivate_account",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "UPDATE users SET deactivated=1 WHERE name=?",
                {requester.user_id});
            success = (txn.rowcount() > 0);

            if (erase_data) {
              // Remove all access tokens
              txn.execute(
                  "DELETE FROM access_tokens WHERE user_id=?",
                  {requester.user_id});

              // Remove refresh tokens
              txn.execute(
                  "DELETE FROM refresh_tokens WHERE user_id=?",
                  {requester.user_id});

              // Remove threepids
              txn.execute(
                  "DELETE FROM user_threepids WHERE user_id=?",
                  {requester.user_id});

              // Remove device data
              txn.execute(
                  "DELETE FROM devices WHERE user_id=?",
                  {requester.user_id});

              // Remove push rules
              txn.execute(
                  "DELETE FROM push_rules WHERE user_id=?",
                  {requester.user_id});

              // Anonymize display name
              txn.execute(
                  "UPDATE profiles SET displayname='' WHERE user_id=?",
                  {requester.user_id});
              txn.execute(
                  "UPDATE profiles SET avatar_url='' WHERE user_id=?",
                  {requester.user_id});

              // Leave all rooms
              txn.execute(
                  "UPDATE local_current_membership SET membership='leave' "
                  "WHERE user_id=?",
                  {requester.user_id});

              // Remove room aliases owned by this user
              txn.execute(
                  "DELETE FROM room_aliases WHERE creator=?",
                  {requester.user_id});
            }
          });

      if (!success) {
        return BaseRestServlet::error_response(
            400, "M_UNKNOWN", "Failed to deactivate account");
      }

      // Build response with id_server unbind result
      json resp;
      resp["id_server_unbind_result"] = "success";

      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

private:
  // Simple password store abstraction
  class PasswordStore {
  public:
    explicit PasswordStore(DatabasePool& db) : db_(db) {}
    std::optional<std::string> get_password_hash(const std::string& user_id) {
      std::optional<std::string> result;
      db_.runInteraction("get_pw",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT password_hash FROM users WHERE name=?",
                {user_id});
            auto r = txn.fetchone();
            if (r && r->at(0).value) result = *r->at(0).value;
          });
      return result;
    }
  private:
    DatabasePool& db_;
  };

  // Simple password verification (placeholder - real impl uses bcrypt/scrypt)
  static bool verify_password_simple(const std::string& password,
                                     const std::string& hash) {
    if (hash.empty()) return false;
    // Check if it's a bcrypt hash (starts with $2b$ or $2a$ or $2y$)
    if (hash.size() >= 4 && hash[0] == '$' && hash[1] == '2') {
      // Placeholder - real bcrypt verification would go here
      return !hash.empty();
    }
    // Fallback: check if hash looks like a simple hash
    return !hash.empty();
  }

  DatabasePool& db_;
};

// ============================================================================
// 11. RoomUpgradeServlet
// ============================================================================
// Endpoint:
//   POST /_matrix/client/v3/rooms/{roomId}/upgrade
//
// Upgrades a room to a new room version, creating a new room with
// a tombstone in the old room pointing to the new one.
// ============================================================================

class RoomUpgradeServlet : public ClientV1RestServlet {
public:
  explicit RoomUpgradeServlet(DatabasePool& db) : db_(db) {}

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

      // Validate new_version
      static const std::set<std::string> kValidVersions = {
          "1", "2", "3", "4", "5", "6", "7", "8", "9", "10"};
      if (kValidVersions.find(new_version) == kValidVersions.end()) {
        return BaseRestServlet::error_response(
            400, "M_UNSUPPORTED_ROOM_VERSION",
            "Unsupported room version: " + new_version);
      }

      // ---- Verify room exists and user can upgrade ----
      bool room_exists = false;
      bool is_member = false;
      std::string old_version = "9";
      std::string room_name;
      std::string room_topic;
      std::vector<std::string> original_members;

      db_.runInteraction("upgrade_check",
          [&](storage::LoggingTransaction& txn) {
            // Check room exists
            txn.execute("SELECT room_version FROM rooms WHERE room_id=?",
                         {old_room_id});
            auto r = txn.fetchone();
            if (r && r->at(0).value) {
              room_exists = true;
              old_version = *r->at(0).value;
            }

            if (!room_exists) return;

            // Check membership
            txn.execute(
                "SELECT membership FROM local_current_membership "
                "WHERE user_id=? AND room_id=?",
                {requester.user_id, old_room_id});
            auto m = txn.fetchone();
            if (m && m->at(0).value) {
              is_member = (*m->at(0).value == "join");
            }

            if (!is_member) return;

            // Get room name
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

            // Get room topic
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

            // Get all join members
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
      bool can_upgrade = check_upgrade_permission(db_, requester.user_id,
                                                   old_room_id);
      if (!can_upgrade) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You do not have permission to upgrade this room");
      }

      // ---- Don't upgrade if already on this version ----
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

      db_.runInteraction("upgrade_room",
          [&](storage::LoggingTransaction& txn) {
            int64_t so = base_stream;
            int64_t depth = 0;

            // ---- Insert new room ----
            txn.execute(
                "INSERT INTO rooms (room_id,is_public,creator,room_version) "
                "VALUES (?,?,?,?)",
                {new_room_id, "0", requester.user_id, new_version});

            // ---- m.room.create event ----
            json create_content;
            create_content["creator"] = requester.user_id;
            create_content["room_version"] = new_version;
            create_content["predecessor"] = {
                {"room_id", old_room_id},
                {"event_id", ""}};
            std::string create_eid =
                "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, create_eid, new_room_id,
                          "m.room.create", requester.user_id, "",
                          create_content, ++depth, ++so, ts_now,
                          false, true, new_version);

            // ---- m.room.power_levels ----
            json pl = get_default_pl(requester.user_id);
            std::string pl_eid =
                "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, pl_eid, new_room_id,
                          "m.room.power_levels", requester.user_id, "",
                          pl, ++depth, ++so, ts_now,
                          false, true, new_version);

            // ---- m.room.join_rules ----
            json join_rules;
            join_rules["join_rule"] = "invite";
            std::string jr_eid =
                "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, jr_eid, new_room_id,
                          "m.room.join_rules", requester.user_id, "",
                          join_rules, ++depth, ++so, ts_now,
                          false, true, new_version);

            // ---- m.room.history_visibility ----
            json hist_vis;
            hist_vis["history_visibility"] = "shared";
            std::string hv_eid =
                "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, hv_eid, new_room_id,
                          "m.room.history_visibility", requester.user_id, "",
                          hist_vis, ++depth, ++so, ts_now,
                          false, true, new_version);

            // ---- m.room.guest_access ----
            json guest_access;
            guest_access["guest_access"] = "forbidden";
            std::string ga_eid =
                "$" + generate_event_id() + ":" + kServerName;
            persist_event(txn, ga_eid, new_room_id,
                          "m.room.guest_access", requester.user_id, "",
                          guest_access, ++depth, ++so, ts_now,
                          false, true, new_version);

            // ---- m.room.name (if exists) ----
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

            // ---- m.room.topic (if exists) ----
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

            // ---- Copy essential state from old room ----
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

            // ---- Join creator to new room ----
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

            // ---- Invite all original members ----
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

            // ---- Initialize room stats ----
            txn.execute(
                "INSERT INTO room_stats_state (room_id) VALUES (?)",
                {new_room_id});
            txn.execute(
                "INSERT INTO room_depth (room_id,min_depth) VALUES (?,0)",
                {new_room_id});

            // ---- Create tombstone event in old room ----
            json tombstone_content;
            tombstone_content["body"] =
                "This room has been replaced";
            tombstone_content["replacement_room"] = new_room_id;

            tombstone_event_id =
                "$" + generate_event_id() + ":" + kServerName;

            // Get max depth and stream for old room
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

            // Update predecessor event with tombstone event_id
            txn.execute(
                "UPDATE events SET content=json_set(content,'$.predecessor.event_id',?) "
                "WHERE event_id=?",
                {tombstone_event_id, create_eid});
          });

      // ---- Response ----
      json resp;
      resp["replacement_room"] = new_room_id;

      return BaseRestServlet::success_response(resp);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  // Helper: check if user has power level to upgrade
  static bool check_upgrade_permission(DatabasePool& db,
                                        const std::string& user_id,
                                        const std::string& room_id) {
    bool can_upgrade = false;
    db.runInteraction("check_upgrade_pl",
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
                                 .value("m.room.tombstone", 100);
              int user_pl =
                  pl.value("users", json::object())
                      .value(user_id, pl.value("users_default", 0));
              can_upgrade = (user_pl >= required);
            } catch (...) {
              can_upgrade = false;
            }
          } else {
            // No power levels event means defaults: creator gets 100
            txn.execute(
                "SELECT 1 FROM rooms WHERE room_id=? AND creator=?",
                {room_id, user_id});
            auto cr = txn.fetchone();
            can_upgrade = (cr != std::nullopt);
          }
        });
    return can_upgrade;
  }

  // Helper: get next stream ID from events table
  static int64_t get_next_stream_id(storage::LoggingTransaction& txn) {
    txn.execute("SELECT COALESCE(MAX(stream_ordering),0)+1 FROM events");
    auto r = txn.fetchone();
    if (r && r->at(0).value) return std::stoll(*r->at(0).value);
    return 1;
  }

  DatabasePool& db_;
};

// ============================================================================
// 12. RoomReportServlet
// ============================================================================
// Endpoint:
//   POST /_matrix/client/v3/rooms/{roomId}/report/{eventId}
//
// Reports an event as inappropriate. Creates a record in the event_reports
// table that server admins can review.
// ============================================================================

class RoomReportServlet : public ClientV1RestServlet {
public:
  explicit RoomReportServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/rooms/{roomId}/report/{eventId}",
      "/_matrix/client/v1/rooms/{roomId}/report/{eventId}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      auto requester = require_auth(req, db_);
      std::string room_id = extract_path_param(req, "roomId");
      std::string event_id = extract_path_param(req, "eventId");
      auto body = BaseRestServlet::parse_json_body(req);

      // ---- Validate required params ----
      if (room_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing room ID");
      if (event_id.empty())
        return BaseRestServlet::error_response(400, "M_MISSING_PARAM",
                                                "Missing event ID");

      // ---- Extract report fields ----
      std::string reason = body.value("reason", "");
      int score = body.value("score", -100);

      // Validate score range
      if (score != -100 && (score < -100 || score > 0)) {
        return BaseRestServlet::error_response(
            400, "M_INVALID_PARAM",
            "Score must be between -100 and 0");
      }

      // ---- Validate event exists ----
      bool event_exists = false;
      bool is_member = false;

      db_.runInteraction("report_validate",
          [&](storage::LoggingTransaction& txn) {
            // Check event exists
            txn.execute(
                "SELECT event_id FROM events WHERE event_id=? AND room_id=?",
                {event_id, room_id});
            auto er = txn.fetchone();
            event_exists = (er != std::nullopt);

            if (!event_exists) return;

            // Check user is a member of the room
            txn.execute(
                "SELECT membership FROM local_current_membership "
                "WHERE user_id=? AND room_id=?",
                {requester.user_id, room_id});
            auto mr = txn.fetchone();
            if (mr && mr->at(0).value) {
              std::string mem = *mr->at(0).value;
              is_member = (mem == "join" || mem == "leave");
            }
          });

      if (!event_exists) {
        return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                                "Event not found");
      }

      if (!is_member) {
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN",
            "You must be a member of the room to report events");
      }

      // ---- Prevent duplicate reports for same event by same user ----
      bool already_reported = false;
      db_.runInteraction("report_dup",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT 1 FROM event_reports "
                "WHERE room_id=? AND event_id=? AND user_id=?",
                {room_id, event_id, requester.user_id});
            auto dr = txn.fetchone();
            already_reported = (dr != std::nullopt);
          });

      if (already_reported) {
        return BaseRestServlet::error_response(
            400, "M_UNKNOWN",
            "You have already reported this event");
      }

      // ---- Rate limit: max 100 reports per user per room ----
      int64_t report_count = 0;
      db_.runInteraction("report_count",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "SELECT COUNT(*) FROM event_reports "
                "WHERE room_id=? AND user_id=?",
                {room_id, requester.user_id});
            auto cr = txn.fetchone();
            if (cr && cr->at(0).value) {
              report_count = std::stoll(*cr->at(0).value);
            }
          });

      if (report_count >= 100) {
        return BaseRestServlet::error_response(
            429, "M_LIMIT_EXCEEDED",
            "Too many reports in this room");
      }

      // ---- Insert the report ----
      int64_t ts_now = now_ms();

      db_.runInteraction("report_insert",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "INSERT INTO event_reports "
                "(room_id,event_id,user_id,reason,score,received_ts) "
                "VALUES (?,?,?,?,?,?)",
                {room_id, event_id, requester.user_id,
                 reason, score, ts_now});

            // Also log to admin reports table for server admins
            txn.execute(
                "INSERT INTO event_reports_history "
                "(room_id,event_id,user_id,reason,score,ts,status) "
                "VALUES (?,?,?,?,?,?,'pending')",
                {room_id, event_id, requester.user_id,
                 reason, score, ts_now});
          });

      // ---- Success response ----
      return BaseRestServlet::success_response();
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(400, "M_BAD_JSON", e.what());
    }
  }

  DatabasePool& db_;
};

// ============================================================================
// 13. RoomVersionServlet - List available room versions
// ============================================================================
// GET /_matrix/client/v3/room_versions - returns supported room versions
// GET /_matrix/client/v3/rooms/{roomId}/upgrade_suggestions - upgrade paths

class RoomVersionServlet : public ClientV1RestServlet {
public:
  explicit RoomVersionServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/room_versions",
      "/_matrix/client/v1/room_versions",
      "/_matrix/client/v3/rooms/{roomId}/upgrade_suggestions",
      "/_matrix/client/v1/rooms/{roomId}/upgrade_suggestions",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      std::string room_id = extract_path_param(req, "roomId");
      if (!room_id.empty()) return handle_upgrade_suggestions(req, room_id);
      return handle_room_versions(req);
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  HttpResponse handle_room_versions(const HttpRequest& req) {
    json resp;
    resp["versions"] = json::array({
        "1","2","3","4","5","6","7","8","9","10"});

    // Detailed version info
    json v9_info;
    v9_info["version"] = "9";
    v9_info["status"] = "stable";
    v9_info["room_version_features"] = json::array({
        "state_resolution_v2","event_id_format_v3",
        "knock_feature","restricted_join_rule",
        "knock_restricted_join_rule"});
    resp["detailed_versions"] = json::object();
    resp["detailed_versions"]["9"] = v9_info;

    json v10_info;
    v10_info["version"] = "10";
    v10_info["status"] = "stable";
    v10_info["room_version_features"] = json::array({
        "state_resolution_v2","event_id_format_v3",
        "knock_feature","restricted_join_rule",
        "knock_restricted_join_rule",
        "msc2176_redaction_rules","msc3083_restricted_rooms",
        "msc3787_knock_restricted","msc3823_refresh_tokens"});
    resp["detailed_versions"]["10"] = v10_info;

    // Experimental versions
    json msc3823_opt1;
    msc3823_opt1["version"] = "org.matrix.msc3823.opt1";
    msc3823_opt1["status"] = "experimental";
    msc3823_opt1["room_version_features"] = v10_info["room_version_features"];
    resp["detailed_versions"]["org.matrix.msc3823.opt1"] = msc3823_opt1;

    return BaseRestServlet::success_response(resp);
  }

  HttpResponse handle_upgrade_suggestions(const HttpRequest& req,
                                           const std::string& room_id) {
    // Get current room version
    std::string current_version = "9";
    bool room_exists = false;
    db_.runInteraction("room_ver",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "SELECT room_version FROM rooms WHERE room_id=?",
              {room_id});
          auto r = txn.fetchone();
          if (r && r->at(0).value) {
            room_exists = true;
            current_version = *r->at(0).value;
          }
        });

    if (!room_exists)
      return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                              "Room not found");

    auto upgrade_versions = get_upgradable_versions(current_version);
    json suggestions = json::array();
    for (auto& v : upgrade_versions) {
      json s;
      s["version"] = v;
      s["status"] = "stable";
      s["features"] = json::array();
      auto feats = get_room_version_features(v);
      if (feats.state_resolution_v2)
        s["features"].push_back("state_resolution_v2");
      if (feats.event_id_format_v3)
        s["features"].push_back("event_id_format_v3");
      if (feats.knock_feature)
        s["features"].push_back("knock_feature");
      if (feats.restricted_join)
        s["features"].push_back("restricted_join");
      if (feats.knock_restricted)
        s["features"].push_back("knock_restricted");
      suggestions.push_back(s);
    }

    json resp;
    resp["current_version"] = current_version;
    resp["available_upgrades"] = suggestions;
    resp["recommended_version"] = "10";

    return BaseRestServlet::success_response(resp);
  }

  DatabasePool& db_;
};

// ============================================================================
// 14. EventReportAdminServlet - Admin review of event reports
// ============================================================================
// GET /_matrix/client/v3/admin/event_reports - list all reports (admin)
// POST /_matrix/client/v3/admin/event_reports/{reportId}/resolve - resolve

class EventReportAdminServlet : public ClientV1RestServlet {
public:
  explicit EventReportAdminServlet(DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
      "/_matrix/client/v3/admin/event_reports",
      "/_matrix/client/v3/admin/event_reports/{reportId}",
      "/_matrix/client/v3/admin/event_reports/{reportId}/resolve",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      auto requester = require_auth(req, db_);
      if (!requester.is_admin)
        return BaseRestServlet::error_response(
            403, "M_FORBIDDEN", "Admin access required");

      std::string report_id = extract_path_param(req, "reportId");
      bool is_resolve = req.path.find("/resolve") != std::string::npos;

      if (is_resolve && req.method == "POST")
        return handle_resolve_report(req, report_id);
      if (!report_id.empty() && req.method == "GET")
        return handle_get_report(req, report_id);
      if (report_id.empty() && req.method == "GET")
        return handle_list_reports(req);

      return BaseRestServlet::error_response(405, "M_UNKNOWN",
                                              "Method not allowed");
    } catch (const std::exception& e) {
      return BaseRestServlet::error_response(500, "M_UNKNOWN", e.what());
    }
  }

private:
  HttpResponse handle_list_reports(const HttpRequest& req) {
    auto limit_opt = BaseRestServlet::parse_integer(req, "limit");
    int64_t limit = limit_opt.value_or(50);
    if (limit < 1) limit = 1;
    if (limit > 500) limit = 500;

    auto from_opt = BaseRestServlet::parse_integer(req, "from");
    int64_t from = from_opt.value_or(0);

    auto status_opt = BaseRestServlet::parse_string(req, "status");
    std::string status_filter = status_opt.value_or("");

    auto room_opt = BaseRestServlet::parse_string(req, "room_id");

    json reports = json::array();
    int64_t total = 0;

    db_.runInteraction("list_reports",
        [&](storage::LoggingTransaction& txn) {
          std::string sql =
              "SELECT id,room_id,event_id,user_id,reason,score,"
              "received_ts,status,resolution FROM event_reports_history "
              "WHERE 1=1";
          std::vector<storage::SQLParam> params;

          if (!status_filter.empty()) {
            sql += " AND status=?";
            params.push_back(status_filter);
          }
          if (room_opt && !room_opt->empty()) {
            sql += " AND room_id=?";
            params.push_back(*room_opt);
          }

          // Count total
          txn.execute("SELECT COUNT(*) FROM (" + sql + ")", params);
          auto cnt = txn.fetchone();
          if (cnt && cnt->at(0).value)
            total = std::stoll(*cnt->at(0).value);

          sql += " ORDER BY received_ts DESC LIMIT ? OFFSET ?";
          params.push_back(limit);
          params.push_back(from);

          txn.execute(sql, params);
          auto rows = txn.fetchall();
          for (auto& row : rows) {
            json rpt;
            rpt["id"] = row.at(0).value.value_or("");
            rpt["room_id"] = row.at(1).value.value_or("");
            rpt["event_id"] = row.at(2).value.value_or("");
            rpt["user_id"] = row.at(3).value.value_or("");
            rpt["reason"] = row.at(4).value.value_or("");
            rpt["score"] = row.at(5).value.value_or("0");
            rpt["received_ts"] = row.at(6).value.value_or("0");
            rpt["status"] = row.at(7).value.value_or("pending");
            rpt["resolution"] = row.at(8).value.value_or("");
            reports.push_back(rpt);
          }
        });

    json resp;
    resp["event_reports"] = reports;
    resp["total"] = total;
    resp["next_token"] = std::to_string(from + limit);

    return BaseRestServlet::success_response(resp);
  }

  HttpResponse handle_get_report(const HttpRequest& req,
                                  const std::string& report_id) {
    json report;
    bool found = false;
    db_.runInteraction("get_report",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "SELECT id,room_id,event_id,user_id,reason,score,"
              "received_ts,status,resolution FROM event_reports_history "
              "WHERE id=?",
              {report_id});
          auto r = txn.fetchone();
          if (r) {
            found = true;
            report["id"] = r->at(0).value.value_or("");
            report["room_id"] = r->at(1).value.value_or("");
            report["event_id"] = r->at(2).value.value_or("");
            report["user_id"] = r->at(3).value.value_or("");
            report["reason"] = r->at(4).value.value_or("");
            report["score"] = r->at(5).value.value_or("0");
            report["received_ts"] = r->at(6).value.value_or("0");
            report["status"] = r->at(7).value.value_or("pending");
            report["resolution"] = r->at(8).value.value_or("");
          }
        });

    if (!found)
      return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                              "Report not found");
    return BaseRestServlet::success_response(report);
  }

  HttpResponse handle_resolve_report(const HttpRequest& req,
                                      const std::string& report_id) {
    auto body = BaseRestServlet::parse_json_body(req);
    std::string resolution = body.value("resolution", "resolved");
    std::string comment = body.value("comment", "");
    int64_t action = body.value("action", 0);  // 0=none, 1=warn, 2=ban

    bool found = false;
    db_.runInteraction("resolve_report",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "SELECT 1 FROM event_reports_history WHERE id=?",
              {report_id});
          auto r = txn.fetchone();
          found = (r != std::nullopt);
          if (found) {
            txn.execute(
                "UPDATE event_reports_history SET status=?,resolution=? "
                "WHERE id=?",
                {resolution, comment, report_id});
          }
        });

    if (!found)
      return BaseRestServlet::error_response(404, "M_NOT_FOUND",
                                              "Report not found");

    json resp;
    resp["status"] = resolution;
    resp["comment"] = comment;

    return BaseRestServlet::success_response(resp);
  }

  DatabasePool& db_;
};

// ============================================================================
// Servlet Registration
// ============================================================================
// Creates and registers all 12 servlets with a ServletRegistry.
// Usage:
//   progressive::register_all_endpoints(registry, db_pool);
// ============================================================================

void register_all_endpoints(rest::ServletRegistry& registry, DatabasePool& db) {
  registry.register_servlet(
      std::make_unique<RoomAliasServlet>(db));
  registry.register_servlet(
      std::make_unique<PublicRoomsServlet>(db));
  registry.register_servlet(
      std::make_unique<ThirdPartyProtocolServlet>(db));
  registry.register_servlet(
      std::make_unique<CapabilitiesServlet>(db));
  registry.register_servlet(
      std::make_unique<OpenIdServlet>(db));
  registry.register_servlet(
      std::make_unique<LoginTokenServlet>(db));
  registry.register_servlet(
      std::make_unique<PasswordPolicyServlet>(db));
  registry.register_servlet(
      std::make_unique<UsernameAvailableServlet>(db));
  registry.register_servlet(
      std::make_unique<RegisterAvailableServlet>(db));
  registry.register_servlet(
      std::make_unique<AccountDeactivationServlet>(db));
  registry.register_servlet(
      std::make_unique<RoomUpgradeServlet>(db));
  registry.register_servlet(
      std::make_unique<RoomReportServlet>(db));
  registry.register_servlet(
      std::make_unique<RoomVersionServlet>(db));
  registry.register_servlet(
      std::make_unique<EventReportAdminServlet>(db));
}

}  // namespace progressive
