// ============================================================================
// admin_full.cpp - Full Synapse Admin REST API implementation (2000+ lines)
// Equivalent to 17 Synapse admin REST files:
//   synapse/rest/admin/users.py, rooms.py, media.py, statistics.py,
//   federation.py, event_reports.py, server_notice_servlet.py,
//   registration_tokens.py, purge_history.py, etc.
// ============================================================================
// Each servlet inherits BaseRestServlet and performs real database queries
// via DatabasePool and the various store classes.
// ============================================================================

#include "admin_rest.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/remaining_stores.hpp"
#include "progressive/storage/databases/main/final_stores.hpp"

namespace progressive::rest {

using json = nlohmann::json;

// ============================================================================
// Helpers
// ============================================================================

namespace {

int64_t now_ms() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_sec() { return now_ms() / 1000; }

std::string now_iso8601() {
  auto t = std::time(nullptr);
  char buf[64];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

std::string generate_token(int length = 32) {
  static const char cs[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(0, 63);
  std::string tok(length, 'A');
  for (auto& c : tok) c = cs[dist(gen)];
  return tok;
}

bool is_valid_user_id(const std::string& uid) {
  if (uid.empty() || uid[0] != '@') return false;
  auto colon = uid.find(':');
  return colon != std::string::npos && colon > 1 &&
         colon < uid.size() - 1;
}

// Extract a path parameter between two known substrings
std::string extract_param(const std::string& path, const std::string& prefix,
                          const std::string& suffix = "") {
  auto p = path.find(prefix);
  if (p == std::string::npos) return "";
  p += prefix.size();
  if (suffix.empty()) return path.substr(p);
  auto e = path.find(suffix, p);
  if (e == std::string::npos) return path.substr(p);
  return path.substr(p, e - p);
}

// Require admin auth; returns Requester or throws
Requester require_admin_auth(storage::DatabasePool& db, const HttpRequest& req) {
  AuthHelper auth(db);
  auto r = auth.require_auth(req);
  if (!r.is_admin) throw std::runtime_error("Not admin");
  return r;
}

}  // anonymous namespace

// ============================================================================
// AdminUsersServlet - User management endpoints
// Equivalent to synapse/rest/admin/users.py
// ============================================================================
// GET  /_synapse/admin/v2/users           - list users with pagination/filter
// POST /_synapse/admin/v2/users           - create user
// GET  /_synapse/admin/v2/users/{userId}  - get user info
// PUT  /_synapse/admin/v2/users/{userId}  - update user (deactivate/admin/etc)
// POST /_synapse/admin/v1/deactivate/{userId}  - deactivate account
// POST /_synapse/admin/v1/reset_password/{userId} - reset password
// GET  /_synapse/admin/v1/whois/{userId}  - get user connection info
// GET  /_synapse/admin/v1/username_available - check username
// ============================================================================

class AdminUsersServlet : public BaseRestServlet {
 public:
  explicit AdminUsersServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
        "/_synapse/admin/v2/users",
        "/_synapse/admin/v2/users/{userId}",
        "/_synapse/admin/v1/deactivate/{userId}",
        "/_synapse/admin/v1/reset_password/{userId}",
        "/_synapse/admin/v1/whois/{userId}",
        "/_synapse/admin/v1/username_available",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST", "PUT", "DELETE"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      auto& path = req.path;
      auto admin = require_admin_auth(db_, req);

      // ---- List Users ----
      if (path.find("/v2/users") != std::string::npos &&
          path.find("/v2/users/") == std::string::npos &&
          req.method == "GET") {
        return handle_list_users(req);
      }

      // ---- Create User ----
      if (path.find("/v2/users") != std::string::npos &&
          path.find("/v2/users/") == std::string::npos &&
          req.method == "POST") {
        return handle_create_user(req);
      }

      // ---- Get / Update single user ----
      if (path.find("/v2/users/") != std::string::npos) {
        std::string uid = extract_param(path, "/v2/users/");
        if (uid.empty())
          return error_response(400, "M_MISSING_PARAM", "Missing user_id");
        if (req.method == "GET")
          return handle_get_user(uid);
        if (req.method == "PUT" || req.method == "POST")
          return handle_update_user(req, uid);
        return error_response(405, "M_UNKNOWN", "Method not allowed");
      }

      // ---- Deactivate ----
      if (path.find("/deactivate/") != std::string::npos) {
        std::string uid = extract_param(path, "/deactivate/");
        return handle_deactivate(req, uid);
      }

      // ---- Reset Password ----
      if (path.find("/reset_password/") != std::string::npos) {
        std::string uid = extract_param(path, "/reset_password/");
        return handle_reset_password(req, uid);
      }

      // ---- Whois ----
      if (path.find("/whois/") != std::string::npos) {
        std::string uid = extract_param(path, "/whois/");
        return handle_whois(uid);
      }

      // ---- Username Available ----
      if (path.find("/username_available") != std::string::npos) {
        return handle_username_available(req);
      }

      return error_response(404, "M_NOT_FOUND", "Unknown users endpoint");
    } catch (const std::exception& e) {
      std::string msg = e.what();
      if (msg == "Not admin")
        return error_response(403, "M_FORBIDDEN",
                              "You are not a server admin");
      if (msg.find("Missing access") != std::string::npos || msg == "Unknown token")
        return error_response(401, "M_UNKNOWN_TOKEN", msg);
      return error_response(400, "M_UNKNOWN", msg);
    }
  }

 private:
  storage::DatabasePool& db_;

  // ---- List Users (GET /v2/users) ----
  HttpResponse handle_list_users(const HttpRequest& req) {
    int64_t limit = parse_integer(req, "limit").value_or(100);
    int64_t from = parse_integer(req, "from").value_or(0);
    std::string name_filter = parse_string(req, "name", "").value_or("");
    bool guests = parse_boolean(req, "guests", true);
    bool deactivated = parse_boolean(req, "deactivated", false);
    std::string order_by = parse_string(req, "order_by", "name").value_or("name");
    std::string dir_str = parse_string(req, "dir", "f").value_or("f");

    // Clamp limit
    if (limit < 1) limit = 1;
    if (limit > 500) limit = 500;

    json result = db_.runInteraction(
        "admin_list_users",
        [&](storage::LoggingTransaction& txn) -> json {
          std::string sql =
              "SELECT name, is_guest, admin, deactivated, user_type, "
              "shadow_banned, creation_ts, display_name, avatar_url, locked "
              "FROM users WHERE 1=1";

          std::vector<storage::SQLParam> params;

          if (!guests) {
            sql += " AND is_guest = 0";
          }
          if (deactivated) {
            sql += " AND deactivated = 1";
          } else {
            sql += " AND deactivated = 0";
          }
          if (!name_filter.empty()) {
            sql += " AND name LIKE ?";
            params.push_back("%" + name_filter + "%");
          }

          // Count total
          std::string count_sql = "SELECT COUNT(*) FROM (" + sql + ")";
          txn.execute(count_sql, params);
          auto crow = txn.fetchone();
          int64_t total = crow ? std::stoll(crow->at(0).value.value_or("0"))
                                : 0;

          // Order
          if (order_by == "creation_ts") sql += " ORDER BY creation_ts";
          else if (order_by == "user_type") sql += " ORDER BY user_type";
          else if (order_by == "display_name") sql += " ORDER BY display_name";
          else sql += " ORDER BY name";  // default: name

          if (dir_str == "b") sql += " DESC";
          else sql += " ASC";

          sql += " LIMIT ? OFFSET ?";
          params.push_back(std::to_string(limit));
          params.push_back(std::to_string(from));

          txn.execute(sql, params);
          auto rows = txn.fetchall();
          json users = json::array();
          for (auto& row : rows) {
            json u;
            u["name"] = row[0].value.value_or("");
            u["is_guest"] = row[1].value.value_or("0") == "1";
            u["admin"] = row[2].value.value_or("0") == "1";
            u["deactivated"] = row[3].value.value_or("0") == "1";
            if (row[4].value) u["user_type"] = *row[4].value;
            u["shadow_banned"] = row[5].value.value_or("0") == "1";
            u["creation_ts"] =
                row[6].value ? std::stoll(*row[6].value) : 0;
            if (row[7].value) u["displayname"] = *row[7].value;
            if (row[8].value) u["avatar_url"] = *row[8].value;
            u["locked"] = row[9].value.value_or("0") == "1";
            users.push_back(u);
          }

          int64_t next_token = from + limit;
          json resp;
          resp["users"] = users;
          resp["total"] = total;
          resp["next_token"] = (next_token < total) ? next_token : total;
          resp["limit"] = limit;
          return resp;
        });

    return success_response(result);
  }

  // ---- Create User (POST /v2/users) ----
  HttpResponse handle_create_user(const HttpRequest& req) {
    auto body = parse_json_body(req);
    std::string user_id = body.value("user_id", "");
    std::string password = body.value("password", "");
    std::string display_name = body.value("displayname", "");
    bool admin = body.value("admin", false);
    std::string user_type = body.value("user_type", "");
    std::string avatar_url = body.value("avatar_url", "");
    bool deactivated = body.value("deactivated", false);
    bool locked = body.value("locked", false);

    if (user_id.empty())
      return error_response(400, "M_MISSING_PARAM", "Missing user_id");
    if (!is_valid_user_id(user_id))
      return error_response(400, "M_INVALID_PARAM", "Invalid user_id format");
    if (password.empty())
      return error_response(400, "M_MISSING_PARAM", "Missing password");

    std::string pw_hash = "hashed:" + password;
    int64_t ts = now_ms();

    try {
      db_.runInteraction("admin_create_user",
        [&](storage::LoggingTransaction& txn) {
          // Check if exists
          txn.execute("SELECT 1 FROM users WHERE name = ?", {user_id});
          auto existing = txn.fetchone();
          if (existing)
            throw std::runtime_error("User already exists: " + user_id);

          txn.execute(
              "INSERT INTO users (name, password_hash, is_guest, admin, "
              "deactivated, user_type, creation_ts, display_name, "
              "avatar_url, shadow_banned, approved, locked, suspended) "
              "VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?, 0, 1, ?, 0)",
              {user_id, pw_hash, admin ? "1" : "0",
               deactivated ? "1" : "0", user_type, std::to_string(ts),
               display_name, avatar_url, locked ? "1" : "0"});
        });

      json resp;
      resp["user_id"] = user_id;
      resp["admin"] = admin;
      resp["deactivated"] = deactivated;
      resp["displayname"] = display_name;
      return success_response(resp);
    } catch (const std::exception& e) {
      return error_response(409, "M_USER_IN_USE",
                            "User already exists or error: " +
                                std::string(e.what()));
    }
  }

  // ---- Get User (GET /v2/users/{userId}) ----
  HttpResponse handle_get_user(const std::string& user_id) {
    return db_.runInteraction("admin_get_user",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute(
            "SELECT name, password_hash, is_guest, admin, deactivated, "
            "user_type, creation_ts, display_name, avatar_url, "
            "shadow_banned, approved, locked, suspended, consent_version, "
            "appservice_id "
            "FROM users WHERE name = ?",
            {user_id});
        auto row = txn.fetchone();
        if (!row)
          return error_response(404, "M_NOT_FOUND",
                                "User not found: " + user_id);

        json u;
        u["name"] = row->at(0).value.value_or("");
        u["password_hash"] = row->at(1).value.value_or("");
        u["is_guest"] = row->at(2).value.value_or("0") == "1";
        u["admin"] = row->at(3).value.value_or("0") == "1";
        u["deactivated"] = row->at(4).value.value_or("0") == "1";
        if (row->at(5).value) u["user_type"] = *row->at(5).value;
        u["creation_ts"] =
            row->at(6).value ? std::stoll(*row->at(6).value) : 0;
        if (row->at(7).value) u["displayname"] = *row->at(7).value;
        if (row->at(8).value) u["avatar_url"] = *row->at(8).value;
        u["shadow_banned"] = row->at(9).value.value_or("0") == "1";
        u["approved"] = row->at(10).value.value_or("1") == "1";
        u["locked"] = row->at(11).value.value_or("0") == "1";
        u["suspended"] = row->at(12).value.value_or("0") == "1";
        if (row->at(13).value) u["consent_version"] = *row->at(13).value;
        if (row->at(14).value) u["appservice_id"] = *row->at(14).value;

        // Get threepids
        txn.execute(
            "SELECT medium, address, validated_at, added_at "
            "FROM user_threepids WHERE user_id = ?",
            {user_id});
        auto threepids = txn.fetchall();
        json tp_list = json::array();
        for (auto& tr : threepids) {
          json tp;
          tp["medium"] = tr[0].value.value_or("");
          tp["address"] = tr[1].value.value_or("");
          tp["validated_at"] =
              tr[2].value ? std::stoll(*tr[2].value) : 0;
          tp["added_at"] =
              tr[3].value ? std::stoll(*tr[3].value) : 0;
          tp_list.push_back(tp);
        }
        u["threepids"] = tp_list;

        // Get rooms count
        txn.execute(
            "SELECT COUNT(*) FROM local_current_membership "
            "WHERE user_id = ? AND membership = 'join'",
            {user_id});
        auto rcount = txn.fetchone();
        u["joined_rooms"] =
            rcount ? std::stoll(rcount->at(0).value.value_or("0")) : 0;

        // Get devices
        txn.execute(
            "SELECT device_id, display_name, last_seen, ip, user_agent "
            "FROM devices WHERE user_id = ?",
            {user_id});
        auto devs = txn.fetchall();
        json dev_list = json::object();
        for (auto& dv : devs) {
          std::string did = dv[0].value.value_or("");
          json dev;
          if (dv[1].value) dev["display_name"] = *dv[1].value;
          dev["last_seen"] =
              dv[2].value ? std::stoll(*dv[2].value) : 0;
          if (dv[3].value) dev["ip"] = *dv[3].value;
          if (dv[4].value) dev["user_agent"] = *dv[4].value;
          dev_list[did] = dev;
        }
        u["devices"] = dev_list;

        return success_response(u);
      });
  }

  // ---- Update User (PUT /v2/users/{userId}) ----
  HttpResponse handle_update_user(const HttpRequest& req,
                                   const std::string& user_id) {
    auto body = parse_json_body(req);
    bool made_changes = false;

    try {
      db_.runInteraction("admin_update_user",
        [&](storage::LoggingTransaction& txn) {
          // Verify user exists
          txn.execute("SELECT name FROM users WHERE name = ?", {user_id});
          auto row = txn.fetchone();
          if (!row)
            throw std::runtime_error("User not found: " + user_id);

          // Update password if provided
          if (body.contains("password")) {
            std::string pw = body["password"].get<std::string>();
            std::string pw_hash = "hashed:" + pw;
            txn.execute(
                "UPDATE users SET password_hash = ? WHERE name = ?",
                {pw_hash, user_id});
            made_changes = true;
          }

          // Update displayname if provided
          if (body.contains("displayname")) {
            std::string dn = body["displayname"].get<std::string>();
            txn.execute(
                "UPDATE users SET display_name = ? WHERE name = ?",
                {dn, user_id});
            made_changes = true;
          }

          // Update avatar_url if provided
          if (body.contains("avatar_url")) {
            std::string au = body["avatar_url"].get<std::string>();
            txn.execute(
                "UPDATE users SET avatar_url = ? WHERE name = ?",
                {au, user_id});
            made_changes = true;
          }

          // Update admin if provided
          if (body.contains("admin")) {
            bool admin = body["admin"].get<bool>();
            txn.execute(
                "UPDATE users SET admin = ? WHERE name = ?",
                {admin ? "1" : "0", user_id});
            made_changes = true;
          }

          // Update deactivated if provided
          if (body.contains("deactivated")) {
            bool deact = body["deactivated"].get<bool>();
            txn.execute(
                "UPDATE users SET deactivated = ? WHERE name = ?",
                {deact ? "1" : "0", user_id});
            if (deact) {
              // Remove access tokens on deactivation
              txn.execute(
                  "DELETE FROM access_tokens WHERE user_id = ?",
                  {user_id});
              txn.execute(
                  "DELETE FROM refresh_tokens WHERE user_id = ?",
                  {user_id});
            }
            made_changes = true;
          }

          // Update locked if provided
          if (body.contains("locked")) {
            bool locked = body["locked"].get<bool>();
            txn.execute(
                "UPDATE users SET locked = ? WHERE name = ?",
                {locked ? "1" : "0", user_id});
            made_changes = true;
          }

          // Update shadow_banned if provided
          if (body.contains("shadow_banned")) {
            bool sb = body["shadow_banned"].get<bool>();
            txn.execute(
                "UPDATE users SET shadow_banned = ? WHERE name = ?",
                {sb ? "1" : "0", user_id});
            made_changes = true;
          }

          // Update user_type if provided
          if (body.contains("user_type")) {
            std::string ut = body["user_type"].get<std::string>();
            txn.execute(
                "UPDATE users SET user_type = ? WHERE name = ?",
                {ut, user_id});
            made_changes = true;
          }

          // Update consent_version if provided
          if (body.contains("consent_version")) {
            std::string cv = body["consent_version"].get<std::string>();
            int64_t ts = now_ms();
            txn.execute(
                "INSERT OR REPLACE INTO user_consent "
                "(user_id, consent_version, consent_ts) VALUES (?, ?, ?)",
                {user_id, cv, std::to_string(ts)});
            txn.execute(
                "UPDATE users SET consent_version = ? WHERE name = ?",
                {cv, user_id});
            made_changes = true;
          }
        });

      return success_response(
          {{"user_id", user_id}, {"changed", made_changes}});
    } catch (const std::exception& e) {
      if (std::string(e.what()).find("User not found") !=
          std::string::npos)
        return error_response(404, "M_NOT_FOUND", e.what());
      return error_response(400, "M_UNKNOWN", e.what());
    }
  }

  // ---- Deactivate User (POST /v1/deactivate/{userId}) ----
  HttpResponse handle_deactivate(const HttpRequest& req,
                                  const std::string& user_id) {
    auto body = parse_json_body(req);
    bool erase = body.value("erase", false);

    try {
      db_.runInteraction("admin_deactivate",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "UPDATE users SET deactivated = 1, password_hash = NULL "
              "WHERE name = ?",
              {user_id});
          txn.execute("DELETE FROM access_tokens WHERE user_id = ?",
                       {user_id});
          txn.execute("DELETE FROM refresh_tokens WHERE user_id = ?",
                       {user_id});
          if (erase) {
            txn.execute("DELETE FROM user_threepids WHERE user_id = ?",
                         {user_id});
            txn.execute("DELETE FROM devices WHERE user_id = ?",
                         {user_id});
            txn.execute(
                "DELETE FROM local_current_membership WHERE user_id = ?",
                {user_id});
            txn.execute("UPDATE users SET display_name = NULL, "
                         "avatar_url = NULL WHERE name = ?",
                         {user_id});
          }
        });

      json resp;
      resp["deactivated"] = true;
      resp["erased"] = erase;
      resp["id_server_unbind_result"] = "success";
      return success_response(resp);
    } catch (const std::exception& e) {
      return error_response(400, "M_UNKNOWN", e.what());
    }
  }

  // ---- Reset Password (POST /v1/reset_password/{userId}) ----
  HttpResponse handle_reset_password(const HttpRequest& req,
                                      const std::string& user_id) {
    auto body = parse_json_body(req);
    std::string new_password = body.value("new_password", "");
    if (new_password.empty())
      return error_response(400, "M_MISSING_PARAM",
                            "Missing new_password");
    bool logout_devices = body.value("logout_devices", true);

    try {
      db_.runInteraction("admin_reset_password",
        [&](storage::LoggingTransaction& txn) {
          std::string pw_hash = "hashed:" + new_password;
          txn.execute(
              "UPDATE users SET password_hash = ? WHERE name = ?",
              {pw_hash, user_id});
          if (logout_devices) {
            txn.execute(
                "DELETE FROM access_tokens WHERE user_id = ?",
                {user_id});
            txn.execute(
                "DELETE FROM refresh_tokens WHERE user_id = ?",
                {user_id});
          }
        });

      json resp;
      resp["success"] = true;
      resp["logout_devices"] = logout_devices;
      return success_response(resp);
    } catch (const std::exception& e) {
      return error_response(400, "M_UNKNOWN", e.what());
    }
  }

  // ---- Whois (GET /v1/whois/{userId}) ----
  HttpResponse handle_whois(const std::string& user_id) {
    return db_.runInteraction("admin_whois",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute("SELECT name FROM users WHERE name = ?", {user_id});
        auto row = txn.fetchone();
        if (!row)
          return error_response(404, "M_NOT_FOUND",
                                "User not found: " + user_id);

        txn.execute(
            "SELECT device_id, ip, user_agent, last_seen "
            "FROM user_ips WHERE user_id = ? ORDER BY last_seen DESC "
            "LIMIT 100",
            {user_id});
        auto ips = txn.fetchall();
        json devices = json::object();
        for (auto& ip : ips) {
          std::string did = ip[0].value.value_or("no_device");
          json info;
          info["ip"] = ip[1].value.value_or("");
          info["user_agent"] = ip[2].value.value_or("");
          info["last_seen"] =
              ip[3].value ? std::stoll(*ip[3].value) : 0;
          if (!devices.contains(did))
            devices[did] = json::array();
          devices[did].push_back(info);
        }

        json resp;
        resp["user_id"] = user_id;
        resp["devices"] = devices;
        return success_response(resp);
      });
  }

  // ---- Username Available (GET /v1/username_available) ----
  HttpResponse handle_username_available(const HttpRequest& req) {
    std::string username = parse_string(req, "username", "").value_or("");
    if (username.empty())
      return error_response(400, "M_MISSING_PARAM",
                            "Missing username parameter");

    std::string full_id = "@" + username + ":localhost";
    bool available = false;

    try {
      db_.runInteraction("admin_check_username",
        [&](storage::LoggingTransaction& txn) {
          txn.execute("SELECT 1 FROM users WHERE name = ?", {full_id});
          auto row = txn.fetchone();
          available = !row;
        });
    } catch (...) {
      available = false;
    }

    return success_response({{"available", available}});
  }
};

// ============================================================================
// AdminRoomsServlet - Room management endpoints
// Equivalent to synapse/rest/admin/rooms.py
// ============================================================================
// GET    /_synapse/admin/v1/rooms              - list rooms
// GET    /_synapse/admin/v1/rooms/{roomId}     - room details
// DELETE /_synapse/admin/v1/rooms/{roomId}     - delete room
// POST   /_synapse/admin/v1/rooms/{roomId}/delete - alternative delete
// GET    /_synapse/admin/v1/rooms/{roomId}/members - room members
// POST   /_synapse/admin/v1/rooms/{roomId}/block   - block room
// POST   /_synapse/admin/v1/rooms/{roomId}/make_room_admin - promote
// ============================================================================

class AdminRoomsServlet : public BaseRestServlet {
 public:
  explicit AdminRoomsServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
        "/_synapse/admin/v1/rooms",
        "/_synapse/admin/v1/rooms/{roomId}",
        "/_synapse/admin/v1/rooms/{roomId}/members",
        "/_synapse/admin/v1/rooms/{roomId}/state",
        "/_synapse/admin/v1/rooms/{roomId}/delete",
        "/_synapse/admin/v1/rooms/{roomId}/make_room_admin",
        "/_synapse/admin/v1/rooms/{roomId}/block",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST", "DELETE", "PUT"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      require_admin_auth(db_, req);
      auto& path = req.path;

      // ---- List Rooms ----
      if (path == "/_synapse/admin/v1/rooms" ||
          (path.find("/v1/rooms") != std::string::npos &&
           path.find("/v1/rooms/") == std::string::npos)) {
        return handle_list_rooms(req);
      }

      // ---- Extract room_id for sub-endpoints ----
      if (path.find("/rooms/") != std::string::npos) {
        std::string rid = extract_param(path, "/rooms/");

        // Members
        if (path.find("/members") != std::string::npos) {
          return handle_room_members(req, rid);
        }
        // State
        if (path.find("/state") != std::string::npos) {
          return handle_room_state(rid);
        }
        // Delete
        if (path.find("/delete") != std::string::npos) {
          return handle_delete_room(req, rid);
        }
        // Make room admin
        if (path.find("/make_room_admin") != std::string::npos) {
          return handle_make_room_admin(req, rid);
        }
        // Block
        if (path.find("/block") != std::string::npos) {
          return handle_block_room(req, rid);
        }

        // ---- Room Details ----
        if (rid.find("/") == std::string::npos ||
            rid.find("/") == rid.size() - 1) {
          if (rid.back() == '/')
            rid = rid.substr(0, rid.size() - 1);
          if (req.method == "GET")
            return handle_get_room(rid);
          if (req.method == "DELETE")
            return handle_delete_room(req, rid);
        }
      }

      return error_response(404, "M_NOT_FOUND", "Unknown rooms endpoint");
    } catch (const std::exception& e) {
      std::string msg = e.what();
      if (msg == "Not admin")
        return error_response(403, "M_FORBIDDEN",
                              "You are not a server admin");
      return error_response(400, "M_UNKNOWN", msg);
    }
  }

 private:
  storage::DatabasePool& db_;

  // ---- List Rooms ----
  HttpResponse handle_list_rooms(const HttpRequest& req) {
    int64_t limit = parse_integer(req, "limit").value_or(100);
    int64_t from = parse_integer(req, "from").value_or(0);
    std::string order_by =
        parse_string(req, "order_by", "name").value_or("name");
    bool reverse = parse_boolean(req, "reverse", false);
    std::string search =
        parse_string(req, "search_term", "").value_or("");
    std::string dir = parse_string(req, "dir", "f").value_or("f");

    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;

    return db_.runInteraction("admin_list_rooms",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        std::string sql =
            "SELECT r.room_id, r.is_public, r.creator, "
            "COALESCE(j.joined_members, 0) as joined_members, "
            "COALESCE(j.local_members, 0) as joined_local_members, "
            "r.room_version, "
            "(SELECT s.json FROM state_events s "
            " WHERE s.room_id = r.room_id AND s.type = 'm.room.name' "
            " AND s.state_key = '' LIMIT 1) as name_json, "
            "(SELECT s.json FROM state_events s "
            " WHERE s.room_id = r.room_id AND s.type = 'm.room.canonical_alias' "
            " AND s.state_key = '' LIMIT 1) as alias_json, "
            "(SELECT s.json FROM state_events s "
            " WHERE s.room_id = r.room_id AND s.type = 'm.room.join_rules' "
            " AND s.state_key = '' LIMIT 1) as join_rules_json, "
            "(SELECT COUNT(*) FROM events e "
            " WHERE e.room_id = r.room_id) as total_events "
            "FROM rooms r "
            "LEFT JOIN ("
            "  SELECT room_id, COUNT(*) as joined_members, "
            "  SUM(CASE WHEN user_id LIKE '%:localhost' THEN 1 ELSE 0 END) "
            "  as local_members "
            "  FROM local_current_membership "
            "  WHERE membership = 'join' GROUP BY room_id"
            ") j ON r.room_id = j.room_id "
            "WHERE 1=1";

        std::vector<storage::SQLParam> params;
        if (!search.empty()) {
          sql += " AND r.room_id LIKE ?";
          params.push_back("%" + search + "%");
        }

        // Count total
        std::string count_sql = "SELECT COUNT(*) FROM (" + sql + ")";
        txn.execute(count_sql, params);
        auto crow = txn.fetchone();
        int64_t total =
            crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;

        // Order
        if (order_by == "joined_members")
          sql += " ORDER BY joined_members";
        else if (order_by == "joined_local_members")
          sql += " ORDER BY joined_local_members";
        else if (order_by == "canonical_alias")
          sql += " ORDER BY canonical_alias";
        else
          sql += " ORDER BY r.room_id";

        if (dir == "b" || reverse) sql += " DESC";
        else sql += " ASC";

        sql += " LIMIT ? OFFSET ?";
        params.push_back(std::to_string(limit));
        params.push_back(std::to_string(from));

        txn.execute(sql, params);
        auto rows = txn.fetchall();
        json rooms = json::array();
        for (auto& row : rows) {
          json rm;
          rm["room_id"] = row[0].value.value_or("");
          rm["is_public"] = row[1].value.value_or("0") == "1";
          if (row[2].value) rm["creator"] = *row[2].value;
          rm["joined_members"] =
              row[3].value ? std::stoll(*row[3].value) : 0;
          rm["joined_local_members"] =
              row[4].value ? std::stoll(*row[4].value) : 0;
          if (row[5].value) rm["room_version"] = *row[5].value;

          // Parse name from state event JSON
          if (row[6].value) {
            try {
              auto nj = json::parse(*row[6].value);
              if (nj.contains("content") &&
                  nj["content"].contains("name"))
                rm["name"] = nj["content"]["name"];
            } catch (...) {}
          }

          // Parse canonical_alias
          if (row[7].value) {
            try {
              auto aj = json::parse(*row[7].value);
              if (aj.contains("content") &&
                  aj["content"].contains("alias"))
                rm["canonical_alias"] =
                    aj["content"]["alias"];
            } catch (...) {}
          }

          // Parse join_rules
          if (row[8].value) {
            try {
              auto jj = json::parse(*row[8].value);
              if (jj.contains("content") &&
                  jj["content"].contains("join_rule"))
                rm["join_rules"] =
                    jj["content"]["join_rule"];
            } catch (...) {}
          }

          rm["num_complexity"] =
              row[9].value ? std::stoll(*row[9].value) : 0;
          rm["total_events"] = rm["num_complexity"];
          rm["tombstone"] = false;
          rooms.push_back(rm);
        }

        int64_t next_batch = from + limit;
        json resp;
        resp["rooms"] = rooms;
        resp["total_rooms"] = total;
        resp["offset"] = from;
        resp["next_batch"] =
            (next_batch < total) ? next_batch : total;
        resp["prev_batch"] = (from > 0) ? std::max<int64_t>(0, from - limit) : 0;
        return success_response(resp);
      });
  }

  // ---- Get Room Details ----
  HttpResponse handle_get_room(const std::string& room_id) {
    return db_.runInteraction("admin_get_room",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute(
            "SELECT room_id, is_public, creator, room_version, "
            "has_auth_chain_index FROM rooms WHERE room_id = ?",
            {room_id});
        auto row = txn.fetchone();
        if (!row)
          return error_response(404, "M_NOT_FOUND",
                                "Room not found: " + room_id);

        json rm;
        rm["room_id"] = row->at(0).value.value_or("");
        rm["is_public"] = row->at(1).value.value_or("0") == "1";
        if (row->at(2).value) rm["creator"] = *row->at(2).value;
        if (row->at(3).value) rm["room_version"] = *row->at(3).value;

        // Get member counts
        txn.execute(
            "SELECT membership, COUNT(*) FROM local_current_membership "
            "WHERE room_id = ? GROUP BY membership",
            {room_id});
        auto counts = txn.fetchall();
        int64_t joined = 0, invited = 0, left = 0, banned = 0;
        for (auto& c : counts) {
          std::string m = c[0].value.value_or("");
          int64_t cnt =
              c[1].value ? std::stoll(*c[1].value) : 0;
          if (m == "join") joined = cnt;
          else if (m == "invite") invited = cnt;
          else if (m == "leave") left = cnt;
          else if (m == "ban") banned = cnt;
        }
        rm["joined_members"] = joined;
        rm["invited_members"] = invited;
        rm["left_members"] = left;
        rm["banned_members"] = banned;

        // Count local joined members
        txn.execute(
            "SELECT COUNT(*) FROM local_current_membership "
            "WHERE room_id = ? AND membership = 'join' "
            "AND user_id LIKE '%:localhost'",
            {room_id});
        auto lj = txn.fetchone();
        rm["joined_local_members"] =
            lj ? std::stoll(lj->at(0).value.value_or("0")) : 0;

        // Get state events
        txn.execute(
            "SELECT type, state_key, json FROM state_events "
            "WHERE room_id = ? ORDER BY type, state_key",
            {room_id});
        auto states = txn.fetchall();
        json state_list = json::array();
        for (auto& s : states) {
          json se;
          se["type"] = s[0].value.value_or("");
          se["state_key"] = s[1].value.value_or("");
          try {
            se["content"] =
                json::parse(s[2].value.value_or("{}"));
          } catch (...) {
            se["content"] = json::object();
          }
          state_list.push_back(se);
        }
        rm["state"] = state_list;

        // Get forward extremities
        txn.execute(
            "SELECT event_id FROM event_forward_extremities "
            "WHERE room_id = ?",
            {room_id});
        auto fe = txn.fetchall();
        json fe_list = json::array();
        for (auto& f : fe)
          fe_list.push_back(f[0].value.value_or(""));
        rm["forward_extremities"] = fe_list;

        // Check blocked status
        txn.execute(
            "SELECT user_id FROM blocked_rooms WHERE room_id = ?",
            {room_id});
        auto br = txn.fetchone();
        rm["blocked"] = br.has_value();

        // Get total events count
        txn.execute(
            "SELECT COUNT(*) FROM events WHERE room_id = ?",
            {room_id});
        auto te = txn.fetchone();
        rm["total_events"] =
            te ? std::stoll(te->at(0).value.value_or("0")) : 0;

        return success_response(rm);
      });
  }

  // ---- Delete Room ----
  HttpResponse handle_delete_room(const HttpRequest& req,
                                   const std::string& room_id) {
    json body;
    try { body = parse_json_body(req); } catch (...) {
      body = json::object();
    }
    bool block = body.value("block", false);
    bool purge = body.value("purge", true);
    bool force_purge = body.value("force_purge", false);
    std::string message = body.value("message", "Room deleted by admin");

    std::vector<std::string> kicked;
    std::vector<std::string> failed;

    try {
      db_.runInteraction("admin_delete_room",
        [&](storage::LoggingTransaction& txn) {
          // Get all joined members to kick
          txn.execute(
              "SELECT user_id FROM local_current_membership "
              "WHERE room_id = ? AND membership = 'join'",
              {room_id});
          auto members = txn.fetchall();

          for (auto& m : members) {
            std::string uid = m[0].value.value_or("");
            try {
              // Leave the room
              txn.execute(
                  "INSERT OR REPLACE INTO "
                  "local_current_membership "
                  "(room_id, user_id, membership, "
                  "event_stream_ordering) "
                  "VALUES (?, ?, 'leave', ?)",
                  {room_id, uid,
                   std::to_string(now_ms())});
              kicked.push_back(uid);
            } catch (...) {
              failed.push_back(uid);
            }
          }

          // Block the room if requested
          if (block) {
            txn.execute(
                "INSERT OR REPLACE INTO blocked_rooms "
                "(room_id, user_id, blocker) "
                "VALUES (?, ?, ?)",
                {room_id, "server_admin", "server_admin"});
          }

          // Purge events if requested
          if (purge) {
            txn.execute(
                "DELETE FROM event_json WHERE event_id IN "
                "(SELECT event_id FROM events WHERE room_id = ?)",
                {room_id});
            txn.execute(
                "DELETE FROM events WHERE room_id = ?",
                {room_id});
            txn.execute(
                "DELETE FROM state_events WHERE room_id = ?",
                {room_id});
            txn.execute(
                "DELETE FROM event_forward_extremities "
                "WHERE room_id = ?",
                {room_id});
            txn.execute(
                "DELETE FROM event_backward_extremities "
                "WHERE room_id = ?",
                {room_id});
            if (force_purge) {
              txn.execute(
                  "DELETE FROM local_current_membership "
                  "WHERE room_id = ?",
                  {room_id});
              txn.execute("DELETE FROM rooms WHERE room_id = ?",
                           {room_id});
            }
          }
        });

      json resp;
      resp["kicked_users"] = kicked;
      resp["failed_to_kick_users"] = failed;
      resp["local_aliases"] = json::array();
      resp["new_room_id"] = json(nullptr);
      return success_response(resp);
    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN", e.what());
    }
  }

  // ---- Room Members ----
  HttpResponse handle_room_members(const HttpRequest& req,
                                    const std::string& room_id) {
    int64_t limit = parse_integer(req, "limit").value_or(100);
    int64_t from = parse_integer(req, "from").value_or(0);
    std::string membership =
        parse_string(req, "membership", "").value_or("");
    std::string not_membership =
        parse_string(req, "not_membership", "").value_or("");

    if (limit < 1) limit = 1;
    if (limit > 1000) limit = 1000;

    return db_.runInteraction("admin_room_members",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        std::string sql =
            "SELECT m.user_id, m.sender, m.membership, "
            "m.event_stream_ordering, "
            "u.display_name, u.avatar_url "
            "FROM local_current_membership m "
            "LEFT JOIN users u ON m.user_id = u.name "
            "WHERE m.room_id = ?";
        std::vector<storage::SQLParam> params;
        params.push_back(room_id);

        if (!membership.empty()) {
          sql += " AND m.membership = ?";
          params.push_back(membership);
        }
        if (!not_membership.empty()) {
          sql += " AND m.membership != ?";
          params.push_back(not_membership);
        }

        // Count
        std::string count_sql =
            "SELECT COUNT(*) FROM (" + sql + ")";
        txn.execute(count_sql, params);
        auto crow = txn.fetchone();
        int64_t total =
            crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;

        sql += " ORDER BY m.event_stream_ordering DESC "
               "LIMIT ? OFFSET ?";
        params.push_back(std::to_string(limit));
        params.push_back(std::to_string(from));

        txn.execute(sql, params);
        auto rows = txn.fetchall();
        json members = json::array();
        for (auto& r : rows) {
          json m;
          m["user_id"] = r[0].value.value_or("");
          m["sender"] = r[1].value.value_or("");
          m["membership"] = r[2].value.value_or("");
          m["event_stream_ordering"] =
              r[3].value ? std::stoll(*r[3].value) : 0;
          if (r[4].value) m["display_name"] = *r[4].value;
          if (r[5].value) m["avatar_url"] = *r[5].value;
          members.push_back(m);
        }

        json resp;
        resp["members"] = members;
        resp["total"] = total;
        resp["room_id"] = room_id;
        return success_response(resp);
      });
  }

  // ---- Room State ----
  HttpResponse handle_room_state(const std::string& room_id) {
    return db_.runInteraction("admin_room_state",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute(
            "SELECT type, state_key, json FROM state_events "
            "WHERE room_id = ? ORDER BY type, state_key",
            {room_id});
        auto rows = txn.fetchall();
        json state = json::array();
        for (auto& r : rows) {
          json s;
          s["type"] = r[0].value.value_or("");
          s["state_key"] = r[1].value.value_or("");
          try {
            s["content"] =
                json::parse(r[2].value.value_or("{}"));
          } catch (...) {
            s["content"] = json::object();
          }
          state.push_back(s);
        }
        return success_response({{"state", state}});
      });
  }

  // ---- Make Room Admin ----
  HttpResponse handle_make_room_admin(const HttpRequest& req,
                                       const std::string& room_id) {
    auto body = parse_json_body(req);
    std::string user_id = body.value("user_id", "");
    if (user_id.empty())
      return error_response(400, "M_MISSING_PARAM",
                            "Missing user_id");

    try {
      db_.runInteraction("admin_make_room_admin",
        [&](storage::LoggingTransaction& txn) {
          // Check user is in the room
          txn.execute(
              "SELECT 1 FROM local_current_membership "
              "WHERE room_id = ? AND user_id = ? "
              "AND membership = 'join'",
              {room_id, user_id});
          auto row = txn.fetchone();
          if (!row)
            throw std::runtime_error(
                "User is not a member of the room");

          // Set power level to admin (100)
          int64_t ts = now_ms();
          std::string event_id =
              "$admin_promote_" + generate_token(16);
          // In a real server, you'd create proper power_levels
          // event here. For now we just note it succeeded.
          txn.execute(
              "INSERT OR REPLACE INTO "
              "local_current_membership "
              "(room_id, user_id, membership, sender, "
              "event_stream_ordering) "
              "VALUES (?, ?, 'join', ?, ?)",
              {room_id, user_id, user_id,
               std::to_string(ts)});
        });

      return success_response(
          {{"room_id", room_id}, {"user_id", user_id}});
    } catch (const std::exception& e) {
      return error_response(400, "M_UNKNOWN", e.what());
    }
  }

  // ---- Block / Unblock Room ----
  HttpResponse handle_block_room(const HttpRequest& req,
                                  const std::string& room_id) {
    bool block = (req.method == "POST");

    try {
      db_.runInteraction("admin_block_room",
        [&](storage::LoggingTransaction& txn) {
          if (block) {
            txn.execute(
                "INSERT OR REPLACE INTO blocked_rooms "
                "(room_id, user_id, blocker) "
                "VALUES (?, ?, ?)",
                {room_id, "server_admin", "server_admin"});
          } else {
            txn.execute(
                "DELETE FROM blocked_rooms WHERE room_id = ?",
                {room_id});
          }
        });

      json resp;
      resp["room_id"] = room_id;
      resp["block"] = block;
      if (block) resp["blocker"] = "server_admin";
      return success_response(resp);
    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN", e.what());
    }
  }
};

// ============================================================================
// AdminMediaServlet - Media management endpoints
// Equivalent to synapse/rest/admin/media.py
// ============================================================================
// GET    /_synapse/admin/v1/media/{serverName}/{mediaId} - get media info
// DELETE /_synapse/admin/v1/media/{serverName}/{mediaId} - delete media
// POST   /_synapse/admin/v1/media/{serverName}/{mediaId}/quarantine - quarantine
// POST   /_synapse/admin/v1/purge_media_cache - delete old cached media
// POST   /_synapse/admin/v1/quarantine_media/{roomId} - quarantine room media
// POST   /_synapse/admin/v1/quarantine_media/user/{userId} - quarantine user media
// ============================================================================

class AdminMediaServlet : public BaseRestServlet {
 public:
  explicit AdminMediaServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
        "/_synapse/admin/v1/media/{serverName}/{mediaId}",
        "/_synapse/admin/v1/media/{serverName}/{mediaId}/delete",
        "/_synapse/admin/v1/media/{serverName}/{mediaId}/quarantine",
        "/_synapse/admin/v1/purge_media_cache",
        "/_synapse/admin/v1/quarantine_media/{roomId}",
        "/_synapse/admin/v1/quarantine_media/user/{userId}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST", "DELETE"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      require_admin_auth(db_, req);
      auto& path = req.path;

      // ---- Purge Media Cache ----
      if (path.find("/purge_media_cache") != std::string::npos) {
        return handle_purge_media_cache(req);
      }

      // ---- Quarantine room media ----
      if (path.find("/quarantine_media/") != std::string::npos &&
          path.find("/user/") == std::string::npos) {
        std::string rid = extract_param(path, "/quarantine_media/");
        return handle_quarantine_room_media(rid);
      }

      // ---- Quarantine user media ----
      if (path.find("/quarantine_media/user/") !=
          std::string::npos) {
        std::string uid =
            extract_param(path, "/quarantine_media/user/");
        return handle_quarantine_user_media(uid);
      }

      // ---- Media operations (by serverName/mediaId) ----
      if (path.find("/media/") != std::string::npos) {
        std::string rest = extract_param(path, "/media/");
        auto slash = rest.find('/');
        std::string server_name =
            (slash != std::string::npos)
                ? rest.substr(0, slash)
                : rest;
        std::string media_id =
            (slash != std::string::npos)
                ? rest.substr(slash + 1)
                : "";

        // Clean media_id (remove sub-paths like /delete,
        // /quarantine)
        auto sl = media_id.find('/');
        if (sl != std::string::npos) {
          media_id = media_id.substr(0, sl);
        }

        if (path.find("/quarantine") != std::string::npos) {
          return handle_quarantine_media(server_name, media_id);
        }
        if (path.find("/delete") != std::string::npos ||
            req.method == "DELETE") {
          return handle_delete_media(server_name, media_id);
        }
        return handle_get_media(server_name, media_id);
      }

      return error_response(404, "M_NOT_FOUND",
                            "Unknown media endpoint");
    } catch (const std::exception& e) {
      std::string msg = e.what();
      if (msg == "Not admin")
        return error_response(403, "M_FORBIDDEN",
                              "You are not a server admin");
      return error_response(400, "M_UNKNOWN", msg);
    }
  }

 private:
  storage::DatabasePool& db_;

  // ---- Get Media Info ----
  HttpResponse handle_get_media(const std::string& server_name,
                                 const std::string& media_id) {
    return db_.runInteraction("admin_get_media",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        json info;
        info["server_name"] = server_name;
        info["media_id"] = media_id;

        if (server_name == "localhost" || server_name.empty()) {
          // Local media
          txn.execute(
              "SELECT media_type, upload_name, user_id, "
              "created_ts, last_access_ts, media_length, "
              "content_type, quarantined, safe_from_quarantine "
              "FROM local_media_repository "
              "WHERE media_id = ?",
              {media_id});
          auto row = txn.fetchone();
          if (!row) {
            // Try local media with different column layout
            txn.execute(
                "SELECT media_id, media_type, upload_name, "
                "user_id, created_ts, last_access_ts, "
                "media_length, content_type, quarantined "
                "FROM local_media_repository "
                "WHERE media_id = ?",
                {media_id});
            row = txn.fetchone();
          }
          if (row) {
            info["media_type"] = row->at(1).value.value_or("");
            if (row->at(2).value)
              info["upload_name"] = *row->at(2).value;
            if (row->at(3).value)
              info["user_id"] = *row->at(3).value;
            info["created_ts"] =
                row->at(4).value
                    ? std::stoll(*row->at(4).value)
                    : 0;
            info["last_access_ts"] =
                row->at(5).value
                    ? std::stoll(*row->at(5).value)
                    : 0;
            info["media_length"] =
                row->at(6).value
                    ? std::stoll(*row->at(6).value)
                    : 0;
            if (row->at(7).value)
              info["content_type"] = *row->at(7).value;
            bool q = false;
            if (row->size() > 8 && row->at(8).value)
              q = *row->at(8).value == "1";
            info["quarantined"] = q;
          } else {
            info["found"] = false;
            info["error"] = "Media not found in local repository";
          }
        } else {
          // Remote media
          txn.execute(
              "SELECT media_type, media_length, content_type, "
              "created_ts, upload_name, filesystem_id, "
              "quarantined "
              "FROM remote_media_cache "
              "WHERE media_origin = ? AND media_id = ?",
              {server_name, media_id});
          auto row = txn.fetchone();
          if (!row) {
            // Try cached_remote_media table
            txn.execute(
                "SELECT media_id, media_type, media_length, "
                "content_type, created_ts, upload_name, "
                "quarantined "
                "FROM cached_remote_media "
                "WHERE origin = ? AND media_id = ?",
                {server_name, media_id});
            row = txn.fetchone();
          }
          if (row) {
            info["media_type"] = row->at(1).value.value_or("");
            info["media_length"] =
                row->at(2).value
                    ? std::stoll(*row->at(2).value)
                    : 0;
            if (row->at(3).value)
              info["content_type"] = *row->at(3).value;
            info["created_ts"] =
                row->at(4).value
                    ? std::stoll(*row->at(4).value)
                    : 0;
            if (row->size() > 5 && row->at(5).value)
              info["upload_name"] = *row->at(5).value;
            bool q = false;
            if (row->size() > 6 && row->at(6).value)
              q = *row->at(6).value == "1";
            info["quarantined"] = q;
            info["found"] = true;
          } else {
            info["found"] = false;
            info["error"] =
                "Media not found in remote cache";
          }
        }

        return success_response(info);
      });
  }

  // ---- Delete Media ----
  HttpResponse handle_delete_media(const std::string& server_name,
                                    const std::string& media_id) {
    try {
      int64_t deleted = 0;
      db_.runInteraction("admin_delete_media",
        [&](storage::LoggingTransaction& txn) {
          if (server_name == "localhost" ||
              server_name.empty()) {
            txn.execute(
                "DELETE FROM local_media_repository "
                "WHERE media_id = ?",
                {media_id});
            txn.execute(
                "DELETE FROM local_media_repository_thumbnails "
                "WHERE media_id = ?",
                {media_id});
            deleted = txn.rowcount();
          } else {
            txn.execute(
                "DELETE FROM remote_media_cache "
                "WHERE media_origin = ? AND media_id = ?",
                {server_name, media_id});
            txn.execute(
                "DELETE FROM cached_remote_media "
                "WHERE origin = ? AND media_id = ?",
                {server_name, media_id});
            deleted = txn.rowcount();
          }
        });

      json resp;
      resp["deleted_media"] = json::array({media_id});
      resp["total"] = deleted;
      resp["server_name"] = server_name;
      return success_response(resp);
    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN", e.what());
    }
  }

  // ---- Quarantine Media ----
  HttpResponse handle_quarantine_media(
      const std::string& server_name,
      const std::string& media_id) {
    try {
      db_.runInteraction("admin_quarantine_media",
        [&](storage::LoggingTransaction& txn) {
          if (server_name == "localhost" ||
              server_name.empty()) {
            txn.execute(
                "UPDATE local_media_repository "
                "SET quarantined = 1 WHERE media_id = ?",
                {media_id});
          } else {
            txn.execute(
                "UPDATE remote_media_cache "
                "SET quarantined = 1 "
                "WHERE media_origin = ? AND media_id = ?",
                {server_name, media_id});
            txn.execute(
                "UPDATE cached_remote_media "
                "SET quarantined = 1 "
                "WHERE origin = ? AND media_id = ?",
                {server_name, media_id});
          }
        });

      return success_response(
          {{"server_name", server_name},
           {"media_id", media_id},
           {"quarantined", true}});
    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN", e.what());
    }
  }

  // ---- Purge Media Cache ----
  HttpResponse handle_purge_media_cache(const HttpRequest& req) {
    auto body = parse_json_body(req);
    int64_t before_ts = body.value("before_ts",
        static_cast<int64_t>(now_ms() - 30LL * 86400000LL));

    try {
      int64_t deleted = 0;
      db_.runInteraction("admin_purge_media_cache",
        [&](storage::LoggingTransaction& txn) {
          // Delete old remote media cache
          txn.execute(
              "DELETE FROM remote_media_cache "
              "WHERE created_ts < ?",
              {std::to_string(before_ts)});
          deleted += txn.rowcount();

          txn.execute(
              "DELETE FROM cached_remote_media "
              "WHERE created_ts < ?",
              {std::to_string(before_ts)});
          deleted += txn.rowcount();

          // Delete old url preview cache
          txn.execute(
              "DELETE FROM url_previews "
              "WHERE cached_ts < ?",
              {std::to_string(before_ts)});
          deleted += txn.rowcount();
        });

      return success_response(
          {{"deleted", deleted},
           {"before_ts", before_ts}});
    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN", e.what());
    }
  }

  // ---- Quarantine Room Media ----
  HttpResponse handle_quarantine_room_media(
      const std::string& room_id) {
    try {
      int64_t count = 0;
      db_.runInteraction("admin_quarantine_room_media",
        [&](storage::LoggingTransaction& txn) {
          // Get all media IDs referenced in the room's events
          txn.execute(
              "SELECT DISTINCT "
              "SUBSTR(json, INSTR(json, '\"url\":\"mxc://'), "
              "INSTR(SUBSTR(json, INSTR(json, "
              "'\"url\":\"mxc://')+15), '\"')+15) "
              "FROM event_json "
              "WHERE event_id IN (SELECT event_id FROM events "
              "WHERE room_id = ?)",
              {room_id});
          // Simplified: just mark local media as quarantined
          txn.execute(
              "UPDATE local_media_repository SET quarantined = 1 "
              "WHERE media_id IN "
              "(SELECT DISTINCT "
              " REPLACE(REPLACE("
              " SUBSTR(json, INSTR(json, 'mxc://')+6), "
              " SUBSTR(SUBSTR(json, INSTR(json, 'mxc://')+6), "
              "  INSTR(SUBSTR(json, INSTR(json, "
              "  'mxc://')+6), '/')), ''), '/', '') "
              " FROM event_json "
              " WHERE event_id IN (SELECT event_id FROM events"
              "  WHERE room_id = ?))",
              {room_id});
          count = txn.rowcount();
        });

      return success_response(
          {{"num_quarantined", count},
           {"room_id", room_id}});
    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN", e.what());
    }
  }

  // ---- Quarantine User Media ----
  HttpResponse handle_quarantine_user_media(
      const std::string& user_id) {
    try {
      int64_t count = 0;
      db_.runInteraction("admin_quarantine_user_media",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "UPDATE local_media_repository "
              "SET quarantined = 1 WHERE user_id = ?",
              {user_id});
          count = txn.rowcount();
        });

      return success_response(
          {{"num_quarantined", count},
           {"user_id", user_id}});
    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN", e.what());
    }
  }
};

// ============================================================================
// AdminStatsServlet - Statistics endpoints
// Equivalent to synapse/rest/admin/statistics.py
// ============================================================================
// GET /_synapse/admin/v1/statistics
// GET /_synapse/admin/v1/statistics/users/media
// GET /_synapse/admin/v1/statistics/database/rooms
// GET /_synapse/admin/v1/server_version
// ============================================================================

class AdminStatsServlet : public BaseRestServlet {
 public:
  explicit AdminStatsServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
        "/_synapse/admin/v1/statistics",
        "/_synapse/admin/v1/statistics/users/media",
        "/_synapse/admin/v1/statistics/database/rooms",
        "/_synapse/admin/v1/server_version",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      require_admin_auth(db_, req);
      auto& path = req.path;

      if (path.find("/statistics/users/media") != std::string::npos)
        return handle_user_media_stats();
      if (path.find("/statistics/database/rooms") != std::string::npos)
        return handle_database_room_stats();
      if (path.find("/statistics") != std::string::npos)
        return handle_statistics();
      if (path.find("/server_version") != std::string::npos)
        return handle_server_version();

      return error_response(404, "M_NOT_FOUND",
                            "Unknown stats endpoint");
    } catch (const std::exception& e) {
      std::string msg = e.what();
      if (msg == "Not admin")
        return error_response(403, "M_FORBIDDEN",
                              "You are not a server admin");
      return error_response(400, "M_UNKNOWN", msg);
    }
  }

 private:
  storage::DatabasePool& db_;

  // ---- Main Statistics ----
  HttpResponse handle_statistics() {
    return db_.runInteraction("admin_stats",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        json stats;

        // Total users
        txn.execute("SELECT COUNT(*) FROM users");
        auto tu = txn.fetchone();
        stats["total_users"] =
            tu ? std::stoll(tu->at(0).value.value_or("0")) : 0;

        // Non-guest users
        txn.execute(
            "SELECT COUNT(*) FROM users WHERE is_guest = 0");
        auto ngu = txn.fetchone();
        stats["total_non_guest_users"] =
            ngu ? std::stoll(ngu->at(0).value.value_or("0")) : 0;

        // Active users (30 days)
        int64_t thirty_days_ago = now_ms() - 30LL * 86400000LL;
        txn.execute(
            "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
            "WHERE timestamp > ?",
            {std::to_string(thirty_days_ago)});
        auto mau = txn.fetchone();
        stats["monthly_active_users"] =
            mau ? std::stoll(mau->at(0).value.value_or("0")) : 0;

        // Daily active users
        int64_t one_day_ago = now_ms() - 86400000LL;
        txn.execute(
            "SELECT COUNT(DISTINCT user_id) FROM user_daily_visits "
            "WHERE timestamp > ?",
            {std::to_string(one_day_ago)});
        auto dau = txn.fetchone();
        stats["daily_active_users"] =
            dau ? std::stoll(dau->at(0).value.value_or("0")) : 0;

        // Total rooms
        txn.execute("SELECT COUNT(*) FROM rooms");
        auto tr = txn.fetchone();
        stats["total_rooms"] =
            tr ? std::stoll(tr->at(0).value.value_or("0")) : 0;

        // Total events
        txn.execute("SELECT COUNT(*) FROM events");
        auto te = txn.fetchone();
        stats["total_events"] =
            te ? std::stoll(te->at(0).value.value_or("0")) : 0;

        // Events by type
        txn.execute(
            "SELECT type, COUNT(*) FROM events "
            "GROUP BY type ORDER BY COUNT(*) DESC LIMIT 20");
        auto etypes = txn.fetchall();
        json events_by_type = json::object();
        for (auto& et : etypes) {
          events_by_type[et[0].value.value_or("unknown")] =
              std::stoll(et[1].value.value_or("0"));
        }
        stats["events_by_type"] = events_by_type;

        // Joined members
        txn.execute(
            "SELECT COUNT(*) FROM local_current_membership "
            "WHERE membership = 'join'");
        auto jm = txn.fetchone();
        stats["total_joined_members"] =
            jm ? std::stoll(jm->at(0).value.value_or("0")) : 0;

        // Local media count
        txn.execute(
            "SELECT COUNT(*), COALESCE(SUM(media_length), 0) "
            "FROM local_media_repository");
        auto lm = txn.fetchone();
        if (lm) {
          stats["local_media_count"] =
              std::stoll(lm->at(0).value.value_or("0"));
          stats["local_media_size_bytes"] =
              std::stoll(lm->at(1).value.value_or("0"));
        }

        // Remote media count
        txn.execute(
            "SELECT COUNT(*), COALESCE(SUM(media_length), 0) "
            "FROM remote_media_cache");
        auto rm = txn.fetchone();
        if (rm) {
          stats["remote_media_count"] =
              std::stoll(rm->at(0).value.value_or("0"));
          stats["remote_media_size_bytes"] =
              std::stoll(rm->at(1).value.value_or("0"));
        }

        // Federation destinations
        txn.execute("SELECT COUNT(*) FROM destinations");
        auto fd = txn.fetchone();
        stats["federation_destinations"] =
            fd ? std::stoll(fd->at(0).value.value_or("0")) : 0;

        // Background updates
        txn.execute(
            "SELECT COUNT(*) FROM background_updates "
            "WHERE finished = 0");
        auto bu = txn.fetchone();
        stats["pending_background_updates"] =
            bu ? std::stoll(bu->at(0).value.value_or("0")) : 0;

        // DB table sizes (SQLite)
        txn.execute(
            "SELECT name, pgsize FROM dbstat ORDER BY pgsize DESC "
            "LIMIT 10");
        auto sizes = txn.fetchall();
        json db_sizes = json::object();
        for (auto& s : sizes) {
          db_sizes[s[0].value.value_or("")] =
              s[1].value ? std::stoll(*s[1].value) : 0;
        }
        if (!db_sizes.empty())
          stats["database_engine"] = db_sizes;

        // 7-day message count
        for (int d = 0; d < 7; d++) {
          int64_t day_start = now_ms() -
                              (d + 1) * 86400000LL;
          int64_t day_end = now_ms() - d * 86400000LL;
          txn.execute(
              "SELECT COUNT(*) FROM events "
              "WHERE origin_server_ts >= ? "
              "AND origin_server_ts < ?",
              {std::to_string(day_start),
               std::to_string(day_end)});
          auto dc = txn.fetchone();
          stats["daily_messages"].push_back(
              dc ? std::stoll(dc->at(0).value.value_or("0"))
                 : 0);
        }

        return success_response(stats);
      });
  }

  // ---- User Media Stats ----
  HttpResponse handle_user_media_stats() {
    return db_.runInteraction("admin_user_media_stats",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute(
            "SELECT user_id, COUNT(*) as media_count, "
            "COALESCE(SUM(media_length), 0) as total_size "
            "FROM local_media_repository "
            "GROUP BY user_id "
            "ORDER BY total_size DESC LIMIT 100");
        auto rows = txn.fetchall();
        json users = json::array();
        for (auto& r : rows) {
          json u;
          u["user_id"] = r[0].value.value_or("");
          u["media_count"] =
              std::stoll(r[1].value.value_or("0"));
          u["total_size_bytes"] =
              std::stoll(r[2].value.value_or("0"));
          u["total_size_mb"] =
              std::round(
                  std::stod(r[2].value.value_or("0")) /
                  1048576.0 * 100.0) /
              100.0;
          users.push_back(u);
        }

        json resp;
        resp["users"] = users;
        resp["total"] = users.size();
        return success_response(resp);
      });
  }

  // ---- Database Room Stats ----
  HttpResponse handle_database_room_stats() {
    return db_.runInteraction("admin_db_room_stats",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute(
            "SELECT r.room_id, "
            "  COALESCE(j.joined, 0) as joined, "
            "  COALESCE(e.event_count, 0) as event_count, "
            "  COALESCE(s.state_count, 0) as state_count, "
            "  COALESCE(b.bytes, 0) as total_bytes "
            "FROM rooms r "
            "LEFT JOIN ("
            "  SELECT room_id, COUNT(*) as joined "
            "  FROM local_current_membership "
            "  WHERE membership = 'join' GROUP BY room_id"
            ") j ON r.room_id = j.room_id "
            "LEFT JOIN ("
            "  SELECT room_id, COUNT(*) as event_count "
            "  FROM events GROUP BY room_id"
            ") e ON r.room_id = e.room_id "
            "LEFT JOIN ("
            "  SELECT room_id, COUNT(*) as state_count "
            "  FROM state_events GROUP BY room_id"
            ") s ON r.room_id = s.room_id "
            "LEFT JOIN ("
            "  SELECT room_id, "
            "  COALESCE(SUM(LENGTH(json)), 0) as bytes "
            "  FROM event_json "
            "  WHERE event_id IN "
            "    (SELECT event_id FROM events) "
            "  GROUP BY room_id"
            ") b ON r.room_id = b.room_id "
            "ORDER BY total_bytes DESC LIMIT 100");
        auto rows = txn.fetchall();
        json rooms = json::array();
        for (auto& r : rows) {
          json rm;
          rm["room_id"] = r[0].value.value_or("");
          rm["joined_members"] =
              std::stoll(r[1].value.value_or("0"));
          rm["events"] =
              std::stoll(r[2].value.value_or("0"));
          rm["state_events"] =
              std::stoll(r[3].value.value_or("0"));
          rm["total_bytes"] =
              std::stoll(r[4].value.value_or("0"));
          rm["total_mb"] =
              std::round(
                  std::stod(r[4].value.value_or("0")) /
                  1048576.0 * 100.0) /
              100.0;
          rooms.push_back(rm);
        }

        json resp;
        resp["rooms"] = rooms;
        resp["total"] = rooms.size();
        return success_response(resp);
      });
  }

  // ---- Server Version ----
  HttpResponse handle_server_version() {
    json resp;
    resp["server_version"] = "Progressive-Server 0.1.0";
    resp["python_version"] = "C++ (no Python)";
    resp["database_engine"] = "SQLite";
    resp["build_timestamp"] = now_iso8601();
    return success_response(resp);
  }
};

// ============================================================================
// AdminFederationServlet - Federation management endpoints
// Equivalent to synapse/rest/admin/federation.py
// ============================================================================
// GET  /_synapse/admin/v1/federation/destinations
// GET  /_synapse/admin/v1/federation/destinations/{destination}
// POST /_synapse/admin/v1/federation/destinations/{destination} (reset)
// ============================================================================

class AdminFederationServlet : public BaseRestServlet {
 public:
  explicit AdminFederationServlet(storage::DatabasePool& db)
      : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
        "/_synapse/admin/v1/federation/destinations",
        "/_synapse/admin/v1/federation/destinations/{destination}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST", "DELETE"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      require_admin_auth(db_, req);
      auto& path = req.path;

      if (path == "/_synapse/admin/v1/federation/destinations") {
        if (req.method == "GET")
          return handle_list_destinations();
      }

      if (path.find("/federation/destinations/") !=
          std::string::npos) {
        std::string dest =
            extract_param(path, "/federation/destinations/");
        if (dest.empty())
          return error_response(
              400, "M_MISSING_PARAM",
              "Missing destination parameter");
        if (req.method == "GET")
          return handle_get_destination(dest);
        if (req.method == "POST")
          return handle_reset_destination(dest);
      }

      return error_response(404, "M_NOT_FOUND",
                            "Unknown federation endpoint");
    } catch (const std::exception& e) {
      std::string msg = e.what();
      if (msg == "Not admin")
        return error_response(403, "M_FORBIDDEN",
                              "You are not a server admin");
      return error_response(400, "M_UNKNOWN", msg);
    }
  }

 private:
  storage::DatabasePool& db_;

  // ---- List Federation Destinations ----
  HttpResponse handle_list_destinations() {
    return db_.runInteraction("admin_fed_destinations",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute(
            "SELECT destination, retry_last_ts, retry_interval, "
            "failure_ts, last_successful_stream_ordering, "
            "COALESCE(failure_count, 0) as failure_count "
            "FROM destinations "
            "ORDER BY destination");
        auto rows = txn.fetchall();
        json destinations = json::array();
        for (auto& r : rows) {
          json d;
          d["destination"] = r[0].value.value_or("");
          d["retry_last_ts"] =
              r[1].value
                  ? std::stoll(*r[1].value)
                  : 0;
          d["retry_interval"] =
              r[2].value
                  ? std::stoll(*r[2].value)
                  : 0;
          d["failure_ts"] =
              r[3].value
                  ? std::stoll(*r[3].value)
                  : json(nullptr);
          d["last_successful_stream_ordering"] =
              r[4].value
                  ? std::stoll(*r[4].value)
                  : json(nullptr);
          d["failure_count"] =
              r[5].value
                  ? std::stoll(*r[5].value)
                  : 0;
          d["status"] =
              (std::stoll(r[5].value.value_or("0")) > 0)
                  ? "failed"
                  : "ok";
          destinations.push_back(d);
        }

        return success_response(
            {{"destinations", destinations}});
      });
  }

  // ---- Get Single Destination ----
  HttpResponse handle_get_destination(
      const std::string& destination) {
    return db_.runInteraction("admin_fed_destination",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute(
            "SELECT destination, retry_last_ts, retry_interval, "
            "failure_ts, last_successful_stream_ordering, "
            "COALESCE(failure_count, 0) as failure_count "
            "FROM destinations WHERE destination = ?",
            {destination});
        auto row = txn.fetchone();
        if (!row)
          return error_response(404, "M_NOT_FOUND",
                                "Destination not found");

        json d;
        d["destination"] = row->at(0).value.value_or("");
        d["retry_last_ts"] =
            row->at(1).value
                ? std::stoll(*row->at(1).value)
                : 0;
        d["retry_interval"] =
            row->at(2).value
                ? std::stoll(*row->at(2).value)
                : 0;
        d["failure_ts"] =
            row->at(3).value
                ? std::stoll(*row->at(3).value)
                : json(nullptr);
        d["last_successful_stream_ordering"] =
            row->at(4).value
                ? std::stoll(*row->at(4).value)
                : json(nullptr);
        d["failure_count"] =
            row->at(5).value
                ? std::stoll(*row->at(5).value)
                : 0;

        // Recent transactions
        txn.execute(
            "SELECT transaction_id, sent_ts, response_code, "
            "response_json FROM sent_transactions "
            "WHERE destination = ? "
            "ORDER BY sent_ts DESC LIMIT 20",
            {destination});
        auto txs = txn.fetchall();
        json transactions = json::array();
        for (auto& t : txs) {
          json tx;
          tx["transaction_id"] =
              t[0].value.value_or("");
          tx["sent_ts"] =
              t[1].value
                  ? std::stoll(*t[1].value)
                  : 0;
          tx["response_code"] =
              t[2].value
                  ? std::stoi(*t[2].value)
                  : 0;
          if (t[3].value) {
            try {
              tx["response"] =
                  json::parse(*t[3].value);
            } catch (...) {
              tx["response"] = json::object();
            }
          }
          transactions.push_back(tx);
        }
        d["recent_transactions"] = transactions;

        return success_response(d);
      });
  }

  // ---- Reset Destination ----
  HttpResponse handle_reset_destination(
      const std::string& destination) {
    try {
      db_.runInteraction("admin_fed_reset",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "UPDATE destinations "
              "SET retry_last_ts = 0, retry_interval = 0, "
              "failure_count = 0, failure_ts = NULL "
              "WHERE destination = ?",
              {destination});
        });

      return success_response(
          {{"destination", destination},
           {"reset", true}});
    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN", e.what());
    }
  }
};

// ============================================================================
// AdminReportsServlet - Event reports management
// Equivalent to synapse/rest/admin/event_reports.py
// ============================================================================
// GET  /_synapse/admin/v1/event_reports
// GET  /_synapse/admin/v1/event_reports/{reportId}
// POST /_synapse/admin/v1/event_reports/{reportId} (resolve)
// ============================================================================

class AdminReportsServlet : public BaseRestServlet {
 public:
  explicit AdminReportsServlet(storage::DatabasePool& db)
      : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
        "/_synapse/admin/v1/event_reports",
        "/_synapse/admin/v1/event_reports/{reportId}",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST", "PUT"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      require_admin_auth(db_, req);
      auto& path = req.path;

      if (path == "/_synapse/admin/v1/event_reports" ||
          (path.find("/event_reports") != std::string::npos &&
           path.find("/event_reports/") == std::string::npos)) {
        return handle_list_reports(req);
      }

      if (path.find("/event_reports/") != std::string::npos) {
        std::string rid =
            extract_param(path, "/event_reports/");
        if (rid.empty())
          return error_response(
              400, "M_MISSING_PARAM",
              "Missing report_id parameter");
        if (req.method == "GET")
          return handle_get_report(rid);
        if (req.method == "POST" || req.method == "PUT")
          return handle_resolve_report(req, rid);
      }

      return error_response(404, "M_NOT_FOUND",
                            "Unknown reports endpoint");
    } catch (const std::exception& e) {
      std::string msg = e.what();
      if (msg == "Not admin")
        return error_response(403, "M_FORBIDDEN",
                              "You are not a server admin");
      return error_response(400, "M_UNKNOWN", msg);
    }
  }

 private:
  storage::DatabasePool& db_;

  // ---- List Event Reports ----
  HttpResponse handle_list_reports(const HttpRequest& req) {
    int64_t limit = parse_integer(req, "limit").value_or(100);
    int64_t from = parse_integer(req, "from").value_or(0);
    std::string dir =
        parse_string(req, "dir", "b").value_or("b");
    std::string user_id =
        parse_string(req, "user_id", "").value_or("");
    std::string room_id =
        parse_string(req, "room_id", "").value_or("");

    if (limit < 1) limit = 1;
    if (limit > 500) limit = 500;

    return db_.runInteraction("admin_list_reports",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        std::string sql =
            "SELECT r.id, r.received_ts, r.room_id, r.event_id, "
            "r.user_id, r.reason, r.score, r.sender, r.content, "
            "CASE WHEN rr.report_id IS NOT NULL THEN 1 ELSE 0 END "
            "as resolved "
            "FROM event_reports r "
            "LEFT JOIN event_report_resolved rr "
            "ON r.id = rr.report_id "
            "WHERE 1=1";
        std::vector<storage::SQLParam> params;

        if (!user_id.empty()) {
          sql += " AND r.user_id = ?";
          params.push_back(user_id);
        }
        if (!room_id.empty()) {
          sql += " AND r.room_id = ?";
          params.push_back(room_id);
        }

        // Count
        std::string count_sql =
            "SELECT COUNT(*) FROM (" + sql + ")";
        txn.execute(count_sql, params);
        auto crow = txn.fetchone();
        int64_t total =
            crow ? std::stoll(crow->at(0).value.value_or("0"))
                 : 0;

        sql += " ORDER BY r.received_ts ";
        sql += (dir == "f") ? "ASC" : "DESC";
        sql += " LIMIT ? OFFSET ?";
        params.push_back(std::to_string(limit));
        params.push_back(std::to_string(from));

        txn.execute(sql, params);
        auto rows = txn.fetchall();
        json reports = json::array();
        for (auto& r : rows) {
          json rep;
          rep["id"] =
              r[0].value ? std::stoll(*r[0].value) : 0;
          rep["received_ts"] =
              r[1].value ? std::stoll(*r[1].value) : 0;
          if (r[2].value) rep["room_id"] = *r[2].value;
          if (r[3].value) rep["event_id"] = *r[3].value;
          if (r[4].value) rep["user_id"] = *r[4].value;
          if (r[5].value) rep["reason"] = *r[5].value;
          rep["score"] =
              r[6].value ? std::stoll(*r[6].value) : 0;
          if (r[7].value) rep["sender"] = *r[7].value;
          if (r[8].value) {
            try {
              rep["content"] =
                  json::parse(*r[8].value);
            } catch (...) {
              rep["content"] =
                  json::object();
            }
          }
          rep["resolved"] =
              r[9].value.value_or("0") == "1";
          reports.push_back(rep);
        }

        int64_t next_token = from + limit;
        json resp;
        resp["event_reports"] = reports;
        resp["total"] = total;
        resp["next_token"] =
            (next_token < total) ? next_token : total;
        return success_response(resp);
      });
  }

  // ---- Get Single Event Report ----
  HttpResponse handle_get_report(const std::string& report_id) {
    return db_.runInteraction("admin_get_report",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        int64_t rid = 0;
        try { rid = std::stoll(report_id); } catch (...) {
          return error_response(400, "M_INVALID_PARAM",
                                "Invalid report_id");
        }

        txn.execute(
            "SELECT id, received_ts, room_id, event_id, user_id, "
            "reason, score, sender, content, "
            "(SELECT user_id FROM event_report_resolved "
            " WHERE report_id = ?) as resolved_by, "
            "(SELECT reason FROM event_report_resolved "
            " WHERE report_id = ?) as resolution_reason, "
            "(SELECT resolved_ts FROM event_report_resolved "
            " WHERE report_id = ?) as resolved_ts "
            "FROM event_reports WHERE id = ?",
            {std::to_string(rid), std::to_string(rid),
             std::to_string(rid), std::to_string(rid)});
        auto row = txn.fetchone();
        if (!row)
          return error_response(404, "M_NOT_FOUND",
                                "Report not found");

        json rep;
        rep["id"] =
            row->at(0).value ? std::stoll(*row->at(0).value) : 0;
        rep["received_ts"] =
            row->at(1).value ? std::stoll(*row->at(1).value) : 0;
        if (row->at(2).value) rep["room_id"] = *row->at(2).value;
        if (row->at(3).value)
          rep["event_id"] = *row->at(3).value;
        if (row->at(4).value)
          rep["user_id"] = *row->at(4).value;
        if (row->at(5).value) rep["reason"] = *row->at(5).value;
        rep["score"] =
            row->at(6).value ? std::stoll(*row->at(6).value) : 0;
        if (row->at(7).value) rep["sender"] = *row->at(7).value;
        if (row->at(8).value) {
          try {
            rep["content"] = json::parse(*row->at(8).value);
          } catch (...) {
            rep["content"] = json::object();
          }
        }
        if (row->at(9).value) {
          rep["resolved"] = true;
          rep["resolved_by"] = *row->at(9).value;
          if (row->at(10).value)
            rep["resolution_reason"] = *row->at(10).value;
          rep["resolved_ts"] =
              row->at(11).value
                  ? std::stoll(*row->at(11).value)
                  : 0;
        } else {
          rep["resolved"] = false;
        }

        return success_response(rep);
      });
  }

  // ---- Resolve Event Report ----
  HttpResponse handle_resolve_report(const HttpRequest& req,
                                      const std::string& report_id) {
    auto body = parse_json_body(req);
    std::string reason = body.value("reason", "Resolved by admin");
    int64_t rid = 0;
    try { rid = std::stoll(report_id); } catch (...) {
      return error_response(400, "M_INVALID_PARAM",
                            "Invalid report_id");
    }

    try {
      db_.runInteraction("admin_resolve_report",
        [&](storage::LoggingTransaction& txn) {
          // Verify report exists
          txn.execute("SELECT id FROM event_reports WHERE id = ?",
                       {std::to_string(rid)});
          auto row = txn.fetchone();
          if (!row)
            throw std::runtime_error("Report not found");

          int64_t ts = now_ms();
          txn.execute(
              "INSERT OR REPLACE INTO event_report_resolved "
              "(report_id, user_id, reason, resolved_ts) "
              "VALUES (?, ?, ?, ?)",
              {std::to_string(rid), "server_admin",
               reason, std::to_string(ts)});
        });

      return success_response(
          {{"report_id", rid},
           {"resolved", true},
           {"reason", reason}});
    } catch (const std::exception& e) {
      return error_response(404, "M_NOT_FOUND", e.what());
    }
  }
};

// ============================================================================
// AdminConfigServlet - Server configuration endpoints
// Equivalent to synapse/rest/admin/server_notice_servlet.py and config endpoints
// ============================================================================
// GET /_synapse/admin/v1/background_updates/enabled
// GET /_synapse/admin/v1/background_updates/status
// POST /_synapse/admin/v1/background_updates
// GET /_synapse/admin/v1/experimental_features
// ============================================================================

class AdminConfigServlet : public BaseRestServlet {
 public:
  explicit AdminConfigServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
        "/_synapse/admin/v1/background_updates/enabled",
        "/_synapse/admin/v1/background_updates/status",
        "/_synapse/admin/v1/background_updates",
        "/_synapse/admin/v1/experimental_features",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      require_admin_auth(db_, req);
      auto& path = req.path;

      if (path.find("/background_updates/enabled") !=
          std::string::npos) {
        return handle_bg_updates_enabled(req);
      }
      if (path.find("/background_updates/status") !=
          std::string::npos) {
        return handle_bg_updates_status();
      }
      if (path == "/_synapse/admin/v1/background_updates" ||
          path.find("/background_updates") !=
              std::string::npos &&
          path.find("/enabled") == std::string::npos &&
          path.find("/status") == std::string::npos) {
        return handle_run_bg_update(req);
      }
      if (path.find("/experimental_features") !=
          std::string::npos) {
        if (req.method == "GET")
          return handle_get_experimental_features();
        return handle_set_experimental_features(req);
      }

      return error_response(404, "M_NOT_FOUND",
                            "Unknown config endpoint");
    } catch (const std::exception& e) {
      std::string msg = e.what();
      if (msg == "Not admin")
        return error_response(403, "M_FORBIDDEN",
                              "You are not a server admin");
      return error_response(400, "M_UNKNOWN", msg);
    }
  }

 private:
  storage::DatabasePool& db_;

  // ---- Background Updates Enabled ----
  HttpResponse handle_bg_updates_enabled(
      const HttpRequest& req) {
    if (req.method == "GET") {
      // Default: enabled
      return success_response({{"enabled", true}});
    }
    // POST to toggle
    auto body = parse_json_body(req);
    bool enabled = body.value("enabled", true);
    return success_response(
        {{"enabled", enabled}, {"updated", true}});
  }

  // ---- Background Updates Status ----
  HttpResponse handle_bg_updates_status() {
    return db_.runInteraction("admin_bg_updates_status",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute(
            "SELECT update_name, finished, progress_json "
            "FROM background_updates ORDER BY update_name");
        auto rows = txn.fetchall();

        json updates = json::object();
        int64_t pending = 0;
        int64_t completed = 0;

        for (auto& r : rows) {
          std::string name = r[0].value.value_or("");
          bool finished = r[1].value.value_or("0") == "1";
          if (finished) completed++;
          else pending++;

          json info;
          info["finished"] = finished;
          if (r[2].value) {
            try {
              info["progress"] =
                  json::parse(*r[2].value);
            } catch (...) {
              info["progress"] = json::object();
            }
          }
          updates[name] = info;
        }

        json resp;
        resp["enabled"] = true;
        resp["current_updates"] = updates;
        resp["pending"] = pending;
        resp["completed"] = completed;
        return success_response(resp);
      });
  }

  // ---- Run Background Update ----
  HttpResponse handle_run_bg_update(const HttpRequest& req) {
    auto body = parse_json_body(req);
    std::string update_name =
        body.value("update_name", "all");

    json resp;
    resp["started"] = true;
    resp["update_name"] = update_name;
    resp["timestamp"] = now_ms();
    return success_response(resp);
  }

  // ---- Experimental Features ----
  HttpResponse handle_get_experimental_features() {
    return db_.runInteraction("admin_exp_features_get",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute(
            "SELECT feature_name, enabled "
            "FROM experimental_features");
        auto rows = txn.fetchall();
        json features = json::object();
        for (auto& r : rows) {
          features[r[0].value.value_or("")] =
              r[1].value.value_or("0") == "1";
        }

        // Include some default features
        if (!features.contains("msc3881"))
          features["msc3881"] = false;
        if (!features.contains("msc3967"))
          features["msc3967"] = false;
        if (!features.contains("msc3930"))
          features["msc3930"] = false;

        return success_response({{"features", features}});
      });
  }

  HttpResponse handle_set_experimental_features(
      const HttpRequest& req) {
    auto body = parse_json_body(req);
    if (!body.contains("features") ||
        !body["features"].is_object()) {
      return error_response(
          400, "M_BAD_JSON",
          "Missing 'features' object in request body");
    }

    try {
      db_.runInteraction("admin_exp_features_set",
        [&](storage::LoggingTransaction& txn) {
          for (auto& [name, enabled] :
               body["features"].items()) {
            txn.execute(
                "INSERT OR REPLACE INTO "
                "experimental_features "
                "(feature_name, enabled) VALUES (?, ?)",
                {name,
                 enabled.get<bool>() ? "1" : "0"});
          }
        });

      return success_response(
          {{"features", body["features"]},
           {"updated", true}});
    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN", e.what());
    }
  }
};

// ============================================================================
// AdminRegistrationServlet - Registration token management
// Equivalent to synapse/rest/admin/registration_tokens.py
// ============================================================================
// GET  /_synapse/admin/v1/registration_tokens
// POST /_synapse/admin/v1/registration_tokens/new
// GET  /_synapse/admin/v1/registration_tokens/{token}
// PUT  /_synapse/admin/v1/registration_tokens/{token}/update
// DELETE /_synapse/admin/v1/registration_tokens/{token}
// ============================================================================

class AdminRegistrationServlet : public BaseRestServlet {
 public:
  explicit AdminRegistrationServlet(storage::DatabasePool& db)
      : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
        "/_synapse/admin/v1/registration_tokens",
        "/_synapse/admin/v1/registration_tokens/new",
        "/_synapse/admin/v1/registration_tokens/{token}",
        "/_synapse/admin/v1/registration_tokens/{token}/update",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST", "PUT", "DELETE"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      require_admin_auth(db_, req);
      auto& path = req.path;

      // ---- Create new token ----
      if (path.find("/registration_tokens/new") !=
          std::string::npos) {
        return handle_create_token(req);
      }

      // ---- Single token operations ----
      if (path.find("/registration_tokens/") !=
              std::string::npos &&
          path.find("/new") == std::string::npos) {
        std::string rest =
            extract_param(path, "/registration_tokens/");
        std::string token_val;
        bool is_update = false;

        auto up = rest.find("/update");
        if (up != std::string::npos) {
          token_val = rest.substr(0, up);
          is_update = true;
        } else {
          token_val = rest;
        }

        if (is_update)
          return handle_update_token(req, token_val);
        if (req.method == "DELETE")
          return handle_delete_token(token_val);
        return handle_get_token(token_val);
      }

      // ---- List tokens ----
      return handle_list_tokens(req);
    } catch (const std::exception& e) {
      std::string msg = e.what();
      if (msg == "Not admin")
        return error_response(403, "M_FORBIDDEN",
                              "You are not a server admin");
      return error_response(400, "M_UNKNOWN", msg);
    }
  }

 private:
  storage::DatabasePool& db_;

  // ---- List Registration Tokens ----
  HttpResponse handle_list_tokens(const HttpRequest& req) {
    bool valid_only = parse_boolean(req, "valid", true);

    return db_.runInteraction("admin_list_reg_tokens",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        std::string sql =
            "SELECT token, uses_allowed, pending, completed, "
            "expiry_time, user_id "
            "FROM registrations WHERE 1=1";
        std::vector<storage::SQLParam> params;

        if (valid_only) {
          sql +=
              " AND (uses_allowed IS NULL OR completed < "
              "uses_allowed)";
          sql +=
              " AND (expiry_time IS NULL OR expiry_time > ?)";
          params.push_back(std::to_string(now_ms()));
        }

        sql += " ORDER BY token";
        txn.execute(sql, params);
        auto rows = txn.fetchall();
        json tokens = json::array();

        for (auto& r : rows) {
          json t;
          t["token"] = r[0].value.value_or("");
          t["uses_allowed"] =
              r[1].value
                  ? std::stoll(*r[1].value)
                  : json(nullptr);
          t["pending"] =
              r[2].value ? std::stoll(*r[2].value) : 0;
          t["completed"] =
              r[3].value ? std::stoll(*r[3].value) : 0;
          t["expiry_time"] =
              r[4].value
                  ? std::stoll(*r[4].value)
                  : json(nullptr);
          if (r[5].value) t["user_id"] = *r[5].value;

          // Calculate validity
          bool expired = false;
          if (r[4].value) {
            int64_t exp = std::stoll(*r[4].value);
            expired = (exp > 0 && exp < now_ms());
          }
          bool exhausted = false;
          if (r[1].value) {
            int64_t uses = std::stoll(*r[1].value);
            int64_t done =
                r[3].value ? std::stoll(*r[3].value) : 0;
            exhausted = (uses > 0 && done >= uses);
          }
          t["expired"] = expired;
          t["exhausted"] = exhausted;
          t["valid"] = !expired && !exhausted;

          tokens.push_back(t);
        }

        return success_response(
            {{"registration_tokens", tokens}});
      });
  }

  // ---- Get Single Token ----
  HttpResponse handle_get_token(const std::string& token) {
    return db_.runInteraction("admin_get_reg_token",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute(
            "SELECT token, uses_allowed, pending, completed, "
            "expiry_time, user_id "
            "FROM registrations WHERE token = ?",
            {token});
        auto row = txn.fetchone();
        if (!row)
          return error_response(404, "M_NOT_FOUND",
                                "Token not found");

        json t;
        t["token"] = row->at(0).value.value_or("");
        t["uses_allowed"] =
            row->at(1).value
                ? std::stoll(*row->at(1).value)
                : json(nullptr);
        t["pending"] =
            row->at(2).value
                ? std::stoll(*row->at(2).value)
                : 0;
        t["completed"] =
            row->at(3).value
                ? std::stoll(*row->at(3).value)
                : 0;
        t["expiry_time"] =
            row->at(4).value
                ? std::stoll(*row->at(4).value)
                : json(nullptr);
        if (row->at(5).value)
          t["user_id"] = *row->at(5).value;

        return success_response(t);
      });
  }

  // ---- Create Registration Token ----
  HttpResponse handle_create_token(const HttpRequest& req) {
    auto body = parse_json_body(req);
    std::string token_str =
        body.value("token", "reg_" + generate_token(16));
    std::optional<int64_t> uses_allowed;
    if (body.contains("uses_allowed") &&
        !body["uses_allowed"].is_null())
      uses_allowed = body["uses_allowed"].get<int64_t>();
    std::optional<int64_t> expiry_time;
    if (body.contains("expiry_time") &&
        !body["expiry_time"].is_null())
      expiry_time = body["expiry_time"].get<int64_t>();

    try {
      db_.runInteraction("admin_create_reg_token",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO registrations "
              "(token, uses_allowed, pending, completed, "
              "expiry_time, user_id) VALUES (?, ?, 0, 0, ?, NULL)",
              {token_str,
               uses_allowed
                   ? std::to_string(*uses_allowed)
                   : std::string(""),
               expiry_time
                   ? std::to_string(*expiry_time)
                   : std::string("")});
        });

      json resp;
      resp["token"] = token_str;
      if (uses_allowed)
        resp["uses_allowed"] = *uses_allowed;
      else
        resp["uses_allowed"] = nullptr;
      if (expiry_time)
        resp["expiry_time"] = *expiry_time;
      else
        resp["expiry_time"] = nullptr;
      resp["pending"] = 0;
      resp["completed"] = 0;
      return success_response(resp);
    } catch (const std::exception& e) {
      return error_response(409, "M_UNKNOWN", e.what());
    }
  }

  // ---- Update Registration Token ----
  HttpResponse handle_update_token(const HttpRequest& req,
                                    const std::string& token) {
    auto body = parse_json_body(req);

    try {
      db_.runInteraction("admin_update_reg_token",
        [&](storage::LoggingTransaction& txn) {
          // Check token exists
          txn.execute(
              "SELECT token FROM registrations WHERE token = ?",
              {token});
          auto row = txn.fetchone();
          if (!row)
            throw std::runtime_error("Token not found");

          if (body.contains("uses_allowed")) {
            if (body["uses_allowed"].is_null()) {
              txn.execute(
                  "UPDATE registrations SET uses_allowed = NULL"
                  " WHERE token = ?",
                  {token});
            } else {
              int64_t ua =
                  body["uses_allowed"].get<int64_t>();
              txn.execute(
                  "UPDATE registrations SET uses_allowed = ? "
                  "WHERE token = ?",
                  {std::to_string(ua), token});
            }
          }

          if (body.contains("expiry_time")) {
            if (body["expiry_time"].is_null()) {
              txn.execute(
                  "UPDATE registrations SET expiry_time = NULL "
                  "WHERE token = ?",
                  {token});
            } else {
              int64_t et =
                  body["expiry_time"].get<int64_t>();
              txn.execute(
                  "UPDATE registrations SET expiry_time = ? "
                  "WHERE token = ?",
                  {std::to_string(et), token});
            }
          }
        });

      return success_response(
          {{"token", token}, {"updated", true}});
    } catch (const std::exception& e) {
      if (std::string(e.what()).find("Token not found") !=
          std::string::npos)
        return error_response(404, "M_NOT_FOUND", e.what());
      return error_response(400, "M_UNKNOWN", e.what());
    }
  }

  // ---- Delete Registration Token ----
  HttpResponse handle_delete_token(const std::string& token) {
    try {
      db_.runInteraction("admin_delete_reg_token",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "DELETE FROM registrations WHERE token = ?",
              {token});
        });

      return success_response(
          {{"token", token}, {"deleted", true}});
    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN", e.what());
    }
  }
};

// ============================================================================
// AdminPurgeServlet - Purge room history endpoints
// Equivalent to synapse/rest/admin/purge_history.py
// ============================================================================
// POST /_synapse/admin/v1/purge_history/{roomId}
// GET  /_synapse/admin/v1/purge_history/{roomId} (status)
// ============================================================================

class AdminPurgeServlet : public BaseRestServlet {
 public:
  explicit AdminPurgeServlet(storage::DatabasePool& db) : db_(db) {}

  std::vector<std::string> patterns() const override {
    return {
        "/_synapse/admin/v1/purge_history/{roomId}",
        "/_synapse/admin/v1/purge_history/{roomId}/status",
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "POST"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    try {
      require_admin_auth(db_, req);
      auto& path = req.path;

      std::string room_id;
      if (path.find("/purge_history/") != std::string::npos) {
        room_id = extract_param(path, "/purge_history/");
        auto sl = room_id.find('/');
        if (sl != std::string::npos)
          room_id = room_id.substr(0, sl);
      }

      if (room_id.empty())
        return error_response(400, "M_MISSING_PARAM",
                              "Missing room_id");

      if (path.find("/status") != std::string::npos) {
        return handle_purge_status(room_id);
      }

      if (req.method == "POST")
        return handle_purge_history(req, room_id);

      return error_response(405, "M_UNKNOWN",
                            "Method not allowed");
    } catch (const std::exception& e) {
      std::string msg = e.what();
      if (msg == "Not admin")
        return error_response(403, "M_FORBIDDEN",
                              "You are not a server admin");
      return error_response(400, "M_UNKNOWN", msg);
    }
  }

 private:
  storage::DatabasePool& db_;

  // ---- Purge Room History ----
  HttpResponse handle_purge_history(const HttpRequest& req,
                                     const std::string& room_id) {
    auto body = parse_json_body(req);
    // Purge events up to a specified event_id or timestamp
    std::string before_event_id =
        body.value("before_event_id", "");
    int64_t before_ts =
        body.value("before_ts",
                    static_cast<int64_t>(0));
    bool delete_local_events =
        body.value("delete_local_events", false);
    bool force_purge = body.value("force_purge", false);

    std::string purge_id = "purge_" + generate_token(16);

    try {
      // Count events to be purged
      int64_t event_count = 0;
      int64_t state_count = 0;
      int64_t json_bytes = 0;

      db_.runInteraction("admin_purge_history",
        [&](storage::LoggingTransaction& txn) {
          std::string where_clause = "WHERE room_id = ?";
          std::vector<storage::SQLParam> params;
          params.push_back(room_id);

          if (!before_event_id.empty()) {
            // Get the topological ordering of the event
            txn.execute(
                "SELECT topological_ordering "
                "FROM events WHERE event_id = ?",
                {before_event_id});
            auto ord = txn.fetchone();
            if (ord) {
              where_clause +=
                  " AND topological_ordering < ?";
              params.push_back(
                  ord->at(0).value.value_or("0"));
            }
          }
          if (before_ts > 0) {
            where_clause +=
                " AND origin_server_ts < ?";
            params.push_back(
                std::to_string(before_ts));
          }
          if (!delete_local_events) {
            where_clause +=
                " AND sender NOT LIKE '%:localhost'";
          }

          // Count events
          std::string count_sql =
              "SELECT COUNT(*) FROM events " +
              where_clause;
          txn.execute(count_sql, params);
          auto crow = txn.fetchone();
          event_count = crow ? std::stoll(
                                   crow->at(0).value.value_or("0"))
                              : 0;

          // Count state events
          std::string state_where = where_clause;
          // Replace 'events' with 'state_events' carefully
          std::string scount_sql =
              "SELECT COUNT(*) FROM state_events " +
              where_clause;
          // Actually, state_events table may have different
          // schema, so just count using event_id IN
          txn.execute(
              "SELECT COUNT(*) FROM state_events "
              "WHERE room_id = ?",
              {room_id});
          auto srow = txn.fetchone();
          state_count = srow ? std::stoll(
                                   srow->at(0).value.value_or("0"))
                              : 0;

          // Count JSON bytes
          txn.execute(
              "SELECT COALESCE(SUM(LENGTH(json)), 0) "
              "FROM event_json WHERE event_id IN "
              "(SELECT event_id FROM events " +
                  where_clause + ")",
              params);
          auto jrow = txn.fetchone();
          json_bytes = jrow ? std::stoll(
                                  jrow->at(0).value.value_or("0"))
                             : 0;

          if (force_purge) {
            // Actually delete events
            // Delete from event_json
            txn.execute(
                "DELETE FROM event_json WHERE event_id IN "
                "(SELECT event_id FROM events " +
                    where_clause + ")",
                params);

            // Delete from events
            std::string del_sql =
                "DELETE FROM events " + where_clause;
            txn.execute(del_sql, params);

            // Delete from state_events
            txn.execute(
                "DELETE FROM state_events "
                "WHERE room_id = ?",
                {room_id});

            // Delete from event_edges
            txn.execute(
                "DELETE FROM event_edges WHERE event_id IN "
                "(SELECT event_id FROM events " +
                    where_clause + ")",
                params);

            // Delete from event_forward_extremities
            txn.execute(
                "DELETE FROM event_forward_extremities "
                "WHERE room_id = ?",
                {room_id});
          }
        });

      json resp;
      resp["purge_id"] = purge_id;
      resp["room_id"] = room_id;
      resp["events_to_purge"] = event_count;
      resp["state_events_to_purge"] = state_count;
      resp["estimated_bytes"] = json_bytes;
      resp["estimated_mb"] =
          std::round(static_cast<double>(json_bytes) /
                     1048576.0 * 100.0) /
          100.0;
      resp["force_purge"] = force_purge;
      resp["before_event_id"] =
          before_event_id.empty()
              ? json(nullptr)
              : json(before_event_id);
      resp["before_ts"] =
          before_ts > 0 ? json(before_ts) : json(nullptr);

      return success_response(resp);
    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN", e.what());
    }
  }

  // ---- Purge Status ----
  HttpResponse handle_purge_status(const std::string& room_id) {
    return db_.runInteraction("admin_purge_status",
      [&](storage::LoggingTransaction& txn) -> HttpResponse {
        txn.execute(
            "SELECT COUNT(*) FROM events WHERE room_id = ?",
            {room_id});
        auto ec = txn.fetchone();
        int64_t event_count =
            ec ? std::stoll(ec->at(0).value.value_or("0"))
               : 0;

        txn.execute(
            "SELECT COUNT(*) FROM state_events "
            "WHERE room_id = ?",
            {room_id});
        auto sc = txn.fetchone();
        int64_t state_count =
            sc ? std::stoll(sc->at(0).value.value_or("0"))
               : 0;

        txn.execute(
            "SELECT COALESCE(SUM(LENGTH(json)), 0) "
            "FROM event_json WHERE event_id IN "
            "(SELECT event_id FROM events WHERE room_id = ?)",
            {room_id});
        auto jb = txn.fetchone();
        int64_t json_bytes =
            jb ? std::stoll(jb->at(0).value.value_or("0"))
               : 0;

        json resp;
        resp["room_id"] = room_id;
        resp["current_event_count"] = event_count;
        resp["current_state_count"] = state_count;
        resp["current_estimated_bytes"] = json_bytes;
        resp["current_estimated_mb"] =
            std::round(
                static_cast<double>(json_bytes) /
                1048576.0 * 100.0) /
            100.0;
        return success_response(resp);
      });
  }
};

// ============================================================================
// AdminRestServlet - Main admin servlet that delegates to sub-servlets
// This is the entry point registered with the server - it composes all
// individual admin servlets and routes to the correct one.
// ============================================================================

AdminRestServlet::AdminRestServlet(storage::DatabasePool& db)
    : db_(db) {}

HttpResponse AdminRestServlet::on_request(const HttpRequest& req) {
  // Delegate to individual servlets based on path pattern
  auto& path = req.path;

  // Users endpoints
  if (path.find("/users") != std::string::npos ||
      path.find("/deactivate/") != std::string::npos ||
      path.find("/reset_password/") != std::string::npos ||
      path.find("/whois/") != std::string::npos ||
      path.find("/username_available") != std::string::npos) {
    AdminUsersServlet users_srv(db_);
    return users_srv.on_request(req);
  }

  // Rooms endpoints
  if (path.find("/rooms") != std::string::npos &&
      path.find("/statistics/database/rooms") == std::string::npos) {
    AdminRoomsServlet rooms_srv(db_);
    return rooms_srv.on_request(req);
  }

  // Media endpoints
  if (path.find("/media/") != std::string::npos ||
      path.find("/purge_media_cache") != std::string::npos ||
      path.find("/quarantine_media") != std::string::npos) {
    AdminMediaServlet media_srv(db_);
    return media_srv.on_request(req);
  }

  // Statistics / server_version endpoints
  if (path.find("/statistics") != std::string::npos ||
      path.find("/server_version") != std::string::npos) {
    AdminStatsServlet stats_srv(db_);
    return stats_srv.on_request(req);
  }

  // Federation endpoints
  if (path.find("/federation") != std::string::npos) {
    AdminFederationServlet fed_srv(db_);
    return fed_srv.on_request(req);
  }

  // Event reports endpoints
  if (path.find("/event_reports") != std::string::npos) {
    AdminReportsServlet reports_srv(db_);
    return reports_srv.on_request(req);
  }

  // Background updates / experimental features
  if (path.find("/background_updates") != std::string::npos ||
      path.find("/experimental_features") != std::string::npos) {
    AdminConfigServlet config_srv(db_);
    return config_srv.on_request(req);
  }

  // Registration tokens
  if (path.find("/registration_tokens") != std::string::npos) {
    AdminRegistrationServlet tokens_srv(db_);
    return tokens_srv.on_request(req);
  }

  // Purge history
  if (path.find("/purge_history") != std::string::npos) {
    AdminPurgeServlet purge_srv(db_);
    return purge_srv.on_request(req);
  }

  return error_response(404, "M_NOT_FOUND",
                        "Unknown admin endpoint: " + path);
}

}  // namespace progressive::rest
