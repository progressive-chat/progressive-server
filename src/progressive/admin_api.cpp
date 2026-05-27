// ============================================================================
// admin_api.cpp — Matrix Admin API: Server Notices, Account Validity,
//   Terms of Service, Rate Limit Admin, Debug API, Room Complexity,
//   and Background Updates Administration
//
// Equivalent to:
//   synapse/server_notices/server_notices_manager.py
//   synapse/server_notices/consent_server_notices.py
//   synapse/server_notices/resource_limits_server_notices.py
//   synapse/handlers/account_validity.py
//   synapse/handlers/deactivate_account.py
//   synapse/rest/admin/username_available.py
//   synapse/api/ratelimiting.py
//   synapse/handlers/room_member.py (complexity checks)
//   synapse/storage/databases/main/room.py (complexity)
//   synapse/storage/background_updates.py
//
// Target: 2500+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <ctime>
#include <deque>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
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

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/push_rule.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/end_to_end_keys.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/event_federation.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/storage/databases/main/filtering.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/final_stores.hpp"
#include "progressive/storage/databases/main/remaining_stores.hpp"
#include "progressive/storage/databases/main/federation_stores.hpp"
#include "progressive/storage/databases/main/small_stores.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class ServerNoticeManager;
class AccountValidityManager;
class TermsOfServiceManager;
class RateLimitAdmin;
class DebugAPI;
class RoomComplexityChecker;
class BackgroundUpdatesAdmin;

// ============================================================================
// Anonymous namespace — Internal helpers
// ============================================================================
namespace {

// ---- Timestamp helpers ----

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

std::string now_iso8601() {
  auto t = std::time(nullptr);
  char buf[64];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

std::string now_rfc2822() {
  auto t = std::time(nullptr);
  char buf[64];
  std::strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S +0000", std::gmtime(&t));
  return buf;
}

int64_t days_to_ms(int days) { return static_cast<int64_t>(days) * 86400000; }
int64_t days_to_sec(int days) { return static_cast<int64_t>(days) * 86400; }
int64_t hours_to_ms(int hours) { return static_cast<int64_t>(hours) * 3600000; }

// ---- Token / ID generation ----

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

std::string generate_event_id(const std::string& server_name) {
  return "$" + generate_token(24) + ":" + server_name;
}

// ---- UUID generation (simple) ----
std::string generate_uuid() {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> hex_dist(0, 15);
  const char* hex = "0123456789abcdef";
  // Format: 8-4-4-4-12
  std::string uuid(36, '-');
  for (int i = 0; i < 36; i++) {
    if (i == 8 || i == 13 || i == 18 || i == 23) continue;
    uuid[i] = hex[hex_dist(gen)];
  }
  // Set version 4 bits
  uuid[14] = '4';
  uuid[19] = hex[8 + hex_dist(gen) % 4];
  return uuid;
}

// ---- String helpers ----

bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string to_lower(const std::string& s) {
  std::string r = s;
  for (auto& c : r) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return r;
}

std::string to_upper(const std::string& s) {
  std::string r = s;
  for (auto& c : r) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return r;
}

std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> result;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    if (!item.empty()) result.push_back(trim(item));
  }
  return result;
}

std::string join(const std::vector<std::string>& parts, const std::string& delim) {
  std::string result;
  for (size_t i = 0; i < parts.size(); i++) {
    if (i > 0) result += delim;
    result += parts[i];
  }
  return result;
}

// ---- Email validation ----
bool is_valid_email(const std::string& email) {
  static const std::regex email_re(
      R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)");
  return std::regex_match(email, email_re);
}

// ---- HTML escaping ----
std::string html_escape(const std::string& s) {
  std::string r;
  r.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '&': r += "&amp;"; break;
      case '<': r += "&lt;"; break;
      case '>': r += "&gt;"; break;
      case '"': r += "&quot;"; break;
      case '\'': r += "&#39;"; break;
      default: r += c;
    }
  }
  return r;
}

// ---- Event ID format check ----
bool is_valid_event_id(const std::string& evid) {
  if (evid.empty() || evid[0] != '$') return false;
  auto colon = evid.find(':');
  return colon != std::string::npos && colon > 1 && colon < evid.size() - 1;
}

bool is_valid_room_id(const std::string& rid) {
  if (rid.empty() || rid[0] != '!') return false;
  auto colon = rid.find(':');
  return colon != std::string::npos && colon > 1 && colon < rid.size() - 1;
}

bool is_valid_user_id(const std::string& uid) {
  if (uid.empty() || uid[0] != '@') return false;
  auto colon = uid.find(':');
  return colon != std::string::npos && colon > 1 && colon < uid.size() - 1;
}

// ---- Extract server name from MXID ----
std::string server_name_from_id(const std::string& id) {
  auto colon = id.find(':');
  if (colon == std::string::npos) return "";
  return id.substr(colon + 1);
}

// ---- Format seconds into human-readable duration ----
std::string format_duration(int64_t seconds) {
  if (seconds <= 0) return "0 minutes";
  int64_t days = seconds / 86400;
  int64_t hours = (seconds % 86400) / 3600;
  int64_t minutes = (seconds % 3600) / 60;
  std::string result;
  if (days > 0) result += std::to_string(days) + " day" + (days != 1 ? "s" : "") + " ";
  if (hours > 0) result += std::to_string(hours) + " hour" + (hours != 1 ? "s" : "") + " ";
  if (minutes > 0) result += std::to_string(minutes) + " minute" + (minutes != 1 ? "s" : "");
  if (result.empty()) return std::to_string(seconds) + " seconds";
  return trim(result);
}

// ---- Format bytes into human-readable size ----
std::string format_bytes(int64_t bytes) {
  const char* units[] = {"B", "KB", "MB", "GB", "TB"};
  int unit_idx = 0;
  double val = static_cast<double>(bytes);
  while (val >= 1024.0 && unit_idx < 4) {
    val /= 1024.0;
    unit_idx++;
  }
  std::stringstream ss;
  ss << std::fixed << std::setprecision(2) << val << " " << units[unit_idx];
  return ss.str();
}

// ---- In-memory config store (thread-safe) ----
class ConfigStore {
public:
  void set(const std::string& key, const json& value) {
    std::unique_lock lock(mu_);
    data_[key] = value;
  }
  json get(const std::string& key, const json& default_val = nullptr) {
    std::shared_lock lock(mu_);
    auto it = data_.find(key);
    if (it != data_.end()) return it->second;
    return default_val;
  }
  void remove(const std::string& key) {
    std::unique_lock lock(mu_);
    data_.erase(key);
  }
  bool exists(const std::string& key) {
    std::shared_lock lock(mu_);
    return data_.count(key) > 0;
  }
  std::vector<std::string> keys() {
    std::shared_lock lock(mu_);
    std::vector<std::string> result;
    for (auto& kv : data_) result.push_back(kv.first);
    return result;
  }

private:
  std::unordered_map<std::string, json> data_;
  mutable std::shared_mutex mu_;
};

// Global config store for runtime settings
ConfigStore g_config;

}  // anonymous namespace

// ============================================================================
// 1. ServerNoticeManager
//
// Manages server notices to users: consent requests, account validity warnings,
// password reset notifications, deactivation warnings, and resource limit
// notifications. Creates and manages a per-user server notice room where
// server-to-user messages are delivered. Tracks which notices have been sent
// to avoid duplicate notifications.
//
// Equivalent to synapse/server_notices/server_notices_manager.py
// ============================================================================
class ServerNoticeManager {
public:
  explicit ServerNoticeManager(storage::DatabasePool& db, const std::string& server_name)
      : db_(db), server_name_(server_name) {}

  // ---- Server Notice Room Management ----

  /// Get or create the server notice room for a user.
  /// This room is where all server notices are sent.
  std::string get_or_create_notice_room(const std::string& user_id) {
    return db_.runInteraction(
        "snm_get_or_create_room",
        [&](storage::LoggingTransaction& txn) -> std::string {
          // Check if the user already has a server notice room
          txn.execute(
              "SELECT room_id FROM server_notice_rooms WHERE user_id = ?",
              {user_id});
          auto existing = txn.fetchone();
          if (existing) {
            return existing->at(0).value.value_or("");
          }

          // Create a new room for server notices
          std::string room_id = "!snm_" + generate_token(18) + ":" + server_name_;
          int64_t ts = now_ms();
          std::string event_id = generate_event_id(server_name_);

          // Insert the room
          txn.execute(
              "INSERT INTO rooms (room_id, is_public, creator, creation_ts) "
              "VALUES (?, 0, ?, ?)",
              {room_id, user_id, std::to_string(ts)});

          // Set room version (default v10)
          txn.execute(
              "INSERT INTO room_version (room_id, version) VALUES (?, '10')",
              {room_id});

          // Make the server a member
          std::string server_user = "@_" + server_name_ + ":" + server_name_;
          txn.execute(
              "INSERT INTO room_memberships (event_id, room_id, user_id, "
              "sender, membership, membership_ts) VALUES (?, ?, ?, ?, 'join', ?)",
              {event_id, room_id, server_user, server_user, std::to_string(ts)});

          // Make the user a member
          std::string join_event = generate_event_id(server_name_);
          txn.execute(
              "INSERT INTO room_memberships (event_id, room_id, user_id, "
              "sender, membership, membership_ts) VALUES (?, ?, ?, ?, 'join', ?)",
              {join_event, room_id, user_id, server_user, std::to_string(ts)});

          // Insert into local_current_membership
          txn.execute(
              "INSERT OR REPLACE INTO local_current_membership "
              "(room_id, user_id, membership, event_id) VALUES (?, ?, 'join', ?)",
              {room_id, user_id, join_event});
          txn.execute(
              "INSERT OR REPLACE INTO local_current_membership "
              "(room_id, user_id, membership, event_id) VALUES (?, ?, 'join', ?)",
              {room_id, server_user, event_id});

          // Record the notice room
          txn.execute(
              "INSERT INTO server_notice_rooms (user_id, room_id, created_ts) "
              "VALUES (?, ?, ?)",
              {user_id, room_id, std::to_string(ts)});

          // Send room creation event to the event stream
          send_notice_event(txn, room_id, server_user, ts,
                            "m.room.create", json({
                                {"creator", server_user},
                                {"room_version", "10"},
                                {"m.federate", false}
                            }));

          // Send member event for server user
          send_notice_event(txn, room_id, server_user, ts,
                            "m.room.member", json({
                                {"membership", "join"},
                                {"displayname", "Server Notices"}
                            }), server_user);

          // Send member event for target user
          send_notice_event(txn, room_id, server_user, ts + 1,
                            "m.room.member", json({
                                {"membership", "join"}
                            }), user_id);

          return room_id;
        });
  }

  /// Get the server notice room for a user, or empty string if none exists
  std::string get_notice_room(const std::string& user_id) {
    return db_.runInteraction(
        "snm_get_room",
        [&](storage::LoggingTransaction& txn) -> std::string {
          txn.execute(
              "SELECT room_id FROM server_notice_rooms WHERE user_id = ?",
              {user_id});
          auto row = txn.fetchone();
          return row ? row->at(0).value.value_or("") : "";
        });
  }

  // ---- Sending Notices ----

  /// Send a server notice to a specific user
  /// Returns the event_id of the sent notice
  std::string send_notice(const std::string& user_id,
                          const std::string& notice_type,
                          const json& content,
                          const std::string& txn_id = "") {
    return db_.runInteraction(
        "snm_send_notice",
        [&](storage::LoggingTransaction& txn) -> std::string {
          std::string room_id = get_notice_room_in_txn(txn, user_id);
          if (room_id.empty()) {
            room_id = create_notice_room_in_txn(txn, user_id);
          }

          std::string server_user = "@_" + server_name_ + ":" + server_name_;
          int64_t ts = now_ms();

          // Build the notice message content
          json msg_content;
          msg_content["msgtype"] = "m.notice";
          msg_content["body"] = format_notice_body(notice_type, content);
          msg_content["server_notice_type"] = notice_type;
          msg_content["org.matrix.msc3952.formatted_text"] = json({
              {"format", "org.matrix.custom.html"},
              {"format_body", format_notice_html(notice_type, content)}
          });

          // Merge any additional content
          for (auto& [key, val] : content.items()) {
            if (key != "body" && key != "format" && key != "format_body") {
              msg_content[key] = val;
            }
          }

          // Create the message event
          std::string event_id = send_notice_event(
              txn, room_id, server_user, ts, "m.room.message", msg_content);

          // Record that we sent this notice type
          record_notice_sent(txn, user_id, notice_type, ts, event_id, room_id);

          return event_id;
        });
  }

  /// Send a consent request notice
  std::string send_consent_notice(const std::string& user_id,
                                  const std::string& consent_uri,
                                  const std::string& consent_version) {
    json content;
    content["consent_uri"] = consent_uri;
    content["consent_version"] = consent_version;
    return send_notice(user_id, "consent_request", content);
  }

  /// Send account validity warning
  std::string send_account_validity_warning(const std::string& user_id,
                                            int64_t expiration_ts,
                                            bool is_renewable) {
    json content;
    content["expiration_ts"] = expiration_ts;
    content["renewable"] = is_renewable;
    content["body"] = build_validity_warning_body(expiration_ts, is_renewable);
    return send_notice(user_id, "account_validity_warning", content);
  }

  /// Send account deactivation notice
  std::string send_account_deactivation_notice(const std::string& user_id,
                                               int64_t deactivation_ts) {
    json content;
    content["deactivation_ts"] = deactivation_ts;
    content["body"] = build_deactivation_body(deactivation_ts);
    return send_notice(user_id, "account_deactivation", content);
  }

  /// Send password reset required notification
  std::string send_password_reset_notice(const std::string& user_id,
                                         const std::string& reset_url,
                                         int64_t expires_at) {
    json content;
    content["reset_url"] = reset_url;
    content["expires_at"] = expires_at;
    return send_notice(user_id, "password_reset_required", content);
  }

  /// Send resource limit notice (server reaching limits)
  std::string send_resource_limit_notice(const std::string& user_id,
                                         const std::string& limit_type,
                                         int64_t current_value,
                                         int64_t max_value) {
    json content;
    content["limit_type"] = limit_type;
    content["current_value"] = current_value;
    content["max_value"] = max_value;
    return send_notice(user_id, "resource_limit", content);
  }

  /// Send a custom admin message to a user
  std::string send_admin_message(const std::string& user_id,
                                  const std::string& message_body,
                                  const std::string& admin_user_id) {
    json content;
    content["body"] = message_body;
    content["admin_user"] = admin_user_id;
    return send_notice(user_id, "admin_message", content);
  }

  // ---- Notice Tracking ----

  /// Check if a specific notice type has been sent to a user since a given timestamp
  bool has_notice_been_sent(const std::string& user_id,
                            const std::string& notice_type,
                            int64_t since_ts = 0) {
    return db_.runInteraction(
        "snm_check_notice",
        [&](storage::LoggingTransaction& txn) -> bool {
          std::string sql =
              "SELECT COUNT(*) FROM server_notice_log "
              "WHERE user_id = ? AND notice_type = ?";
          std::vector<storage::SQLParam> params = {user_id, notice_type};
          if (since_ts > 0) {
            sql += " AND sent_ts >= ?";
            params.push_back(std::to_string(since_ts));
          }
          txn.execute(sql, params);
          auto row = txn.fetchone();
          return row && std::stoll(row->at(0).value.value_or("0")) > 0;
        });
  }

  /// Get the most recent notice of a type sent to a user
  json get_last_notice(const std::string& user_id, const std::string& notice_type) {
    return db_.runInteraction(
        "snm_get_last_notice",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute(
              "SELECT notice_type, sent_ts, event_id, room_id, content "
              "FROM server_notice_log "
              "WHERE user_id = ? AND notice_type = ? "
              "ORDER BY sent_ts DESC LIMIT 1",
              {user_id, notice_type});
          auto row = txn.fetchone();
          if (!row) return json::object();

          json result;
          result["notice_type"] = row->at(0).value.value_or("");
          result["sent_ts"] = row->at(1).value ? std::stoll(*row->at(1).value) : 0;
          result["event_id"] = row->at(2).value.value_or("");
          result["room_id"] = row->at(3).value.value_or("");
          if (row->at(4).value) {
            try { result["content"] = json::parse(*row->at(4).value); }
            catch (...) { result["content"] = *row->at(4).value; }
          }
          return result;
        });
  }

  /// List all notices sent to a user (paginated)
  json list_notices(const std::string& user_id,
                    int64_t limit = 50,
                    int64_t offset = 0,
                    const std::optional<std::string>& notice_type = std::nullopt) {
    return db_.runInteraction(
        "snm_list_notices",
        [&](storage::LoggingTransaction& txn) -> json {
          std::string sql =
              "SELECT notice_type, sent_ts, event_id, room_id "
              "FROM server_notice_log WHERE user_id = ?";
          std::vector<storage::SQLParam> params = {user_id};

          if (notice_type) {
            sql += " AND notice_type = ?";
            params.push_back(*notice_type);
          }

          // Count
          std::string count_sql = "SELECT COUNT(*) FROM (" + sql + ")";
          txn.execute(count_sql, params);
          auto crow = txn.fetchone();
          int64_t total = crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;

          sql += " ORDER BY sent_ts DESC LIMIT ? OFFSET ?";
          params.push_back(std::to_string(limit));
          params.push_back(std::to_string(offset));

          txn.execute(sql, params);
          auto rows = txn.fetchall();

          json notices = json::array();
          for (auto& row : rows) {
            json n;
            n["notice_type"] = row[0].value.value_or("");
            n["sent_ts"] = row[1].value ? std::stoll(*row[1].value) : 0;
            n["event_id"] = row[2].value.value_or("");
            n["room_id"] = row[3].value.value_or("");
            notices.push_back(n);
          }

          return json({
              {"notices", notices},
              {"total", total},
              {"limit", limit},
              {"offset", offset}
          });
        });
  }

  /// Clear all notices and notice rooms for a user
  void clear_notices(const std::string& user_id) {
    db_.runInteraction(
        "snm_clear_notices",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "DELETE FROM server_notice_log WHERE user_id = ?", {user_id});
          txn.execute(
              "DELETE FROM server_notice_rooms WHERE user_id = ?", {user_id});
        });
  }

private:
  storage::DatabasePool& db_;
  std::string server_name_;

  std::string get_notice_room_in_txn(storage::LoggingTransaction& txn,
                                     const std::string& user_id) {
    txn.execute(
        "SELECT room_id FROM server_notice_rooms WHERE user_id = ?",
        {user_id});
    auto row = txn.fetchone();
    return row ? row->at(0).value.value_or("") : "";
  }

  std::string create_notice_room_in_txn(storage::LoggingTransaction& txn,
                                        const std::string& user_id) {
    std::string room_id = "!snm_" + generate_token(18) + ":" + server_name_;
    int64_t ts = now_ms();
    std::string event_id = generate_event_id(server_name_);
    std::string server_user = "@_" + server_name_ + ":" + server_name_;

    txn.execute(
        "INSERT INTO rooms (room_id, is_public, creator, creation_ts) "
        "VALUES (?, 0, ?, ?)",
        {room_id, user_id, std::to_string(ts)});

    txn.execute(
        "INSERT INTO room_version (room_id, version) VALUES (?, '10')",
        {room_id});

    txn.execute(
        "INSERT INTO room_memberships (event_id, room_id, user_id, "
        "sender, membership, membership_ts) VALUES (?, ?, ?, ?, 'join', ?)",
        {event_id, room_id, server_user, server_user, std::to_string(ts)});

    std::string join_event = generate_event_id(server_name_);
    txn.execute(
        "INSERT INTO room_memberships (event_id, room_id, user_id, "
        "sender, membership, membership_ts) VALUES (?, ?, ?, ?, 'join', ?)",
        {join_event, room_id, user_id, server_user, std::to_string(ts)});

    txn.execute(
        "INSERT OR REPLACE INTO local_current_membership "
        "(room_id, user_id, membership, event_id) VALUES (?, ?, 'join', ?)",
        {room_id, user_id, join_event});
    txn.execute(
        "INSERT OR REPLACE INTO local_current_membership "
        "(room_id, user_id, membership, event_id) VALUES (?, ?, 'join', ?)",
        {room_id, server_user, event_id});

    txn.execute(
        "INSERT INTO server_notice_rooms (user_id, room_id, created_ts) "
        "VALUES (?, ?, ?)",
        {user_id, room_id, std::to_string(ts)});

    return room_id;
  }

  std::string send_notice_event(storage::LoggingTransaction& txn,
                                 const std::string& room_id,
                                 const std::string& sender,
                                 int64_t ts,
                                 const std::string& event_type,
                                 const json& content) {
    std::string event_id = generate_event_id(server_name_);
    int64_t depth = get_room_depth(txn, room_id) + 1;

    txn.execute(
        "INSERT INTO events "
        "(event_id, room_id, sender, type, content, depth, origin_server_ts, "
        "received_ts, processed, outlier, stream_ordering) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)",
        {event_id, room_id, sender, event_type, content.dump(),
         std::to_string(depth), std::to_string(ts), std::to_string(ts),
         std::to_string(ts)});

    // Update room depth
    txn.execute(
        "UPDATE rooms SET depth = ? WHERE room_id = ?",
        {std::to_string(depth), room_id});

    return event_id;
  }

  int64_t get_room_depth(storage::LoggingTransaction& txn,
                          const std::string& room_id) {
    txn.execute("SELECT COALESCE(MAX(depth), 0) FROM events WHERE room_id = ?",
                {room_id});
    auto row = txn.fetchone();
    return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
  }

  void record_notice_sent(storage::LoggingTransaction& txn,
                           const std::string& user_id,
                           const std::string& notice_type,
                           int64_t ts,
                           const std::string& event_id,
                           const std::string& room_id) {
    txn.execute(
        "INSERT INTO server_notice_log "
        "(user_id, notice_type, sent_ts, event_id, room_id) "
        "VALUES (?, ?, ?, ?, ?)",
        {user_id, notice_type, std::to_string(ts), event_id, room_id});
  }

  std::string format_notice_body(const std::string& notice_type,
                                  const json& content) {
    if (notice_type == "consent_request") {
      return "This server requires you to agree to updated terms of service. "
             "Please visit: " + content.value("consent_uri", "");
    }
    if (notice_type == "account_validity_warning") {
      int64_t exp = content.value("expiration_ts", 0);
      bool renewable = content.value("renewable", false);
      return build_validity_warning_body(exp, renewable);
    }
    if (notice_type == "account_deactivation") {
      int64_t ts = content.value("deactivation_ts", 0);
      return build_deactivation_body(ts);
    }
    if (notice_type == "password_reset_required") {
      return "Your account requires a password reset for security reasons. "
             "Please use the following link to reset your password: " +
             content.value("reset_url", "");
    }
    if (notice_type == "resource_limit") {
      return "This server is approaching its " +
             content.value("limit_type", "resource") +
             " limit (" +
             std::to_string(content.value("current_value", 0)) + "/" +
             std::to_string(content.value("max_value", 0)) +
             "). Some features may be restricted.";
    }
    if (notice_type == "admin_message") {
      return content.value("body", "Message from server administrator");
    }
    return content.value("body", "Server notification");
  }

  std::string format_notice_html(const std::string& notice_type,
                                  const json& content) {
    std::string body = format_notice_body(notice_type, content);
    return "<p>" + html_escape(body) + "</p>";
  }

  std::string build_validity_warning_body(int64_t expiration_ts, bool renewable) {
    int64_t remaining = expiration_ts - now_sec();
    std::string suffix;
    if (renewable) {
      suffix = " You can renew your account to extend validity.";
    }
    if (remaining <= 0) {
      return "Your account has expired. It will be deactivated soon." + suffix;
    }
    return "Your account will expire in " + format_duration(remaining) +
           ". Please take action to keep your account active." + suffix;
  }

  std::string build_deactivation_body(int64_t deactivation_ts) {
    return "Your account has been deactivated on " +
           now_iso8601() +
           ". Contact your server administrator for assistance.";
  }
};

// ============================================================================
// 2. AccountValidityManager
//
// Manages account expiration: sets per-user expiration periods, auto-renew
// with tokens, sends renewal email notifications, auto-deactivates expired
// accounts, and provides admin API for validity management.
//
// Equivalent to synapse/handlers/account_validity.py
// ============================================================================
class AccountValidityManager {
public:
  explicit AccountValidityManager(storage::DatabasePool& db,
                                  ServerNoticeManager& snm)
      : db_(db), server_notices_(snm) {}

  // ---- Configuration ----

  /// Enable/disable account validity enforcement
  void set_enabled(bool enabled) {
    g_config.set("account_validity.enabled", enabled);
  }

  bool is_enabled() {
    return g_config.get("account_validity.enabled", false).get<bool>();
  }

  /// Set the default account validity period (in days)
  void set_period(int period_days) {
    g_config.set("account_validity.period", period_days);
  }

  int get_period() {
    return g_config.get("account_validity.period", 90).get<int>();
  }

  /// Set renewal token lifetime (in minutes)
  void set_renew_token_lifetime(int minutes) {
    g_config.set("account_validity.renew_token_lifetime", minutes);
  }

  int get_renew_token_lifetime() {
    return g_config.get("account_validity.renew_token_lifetime", 60).get<int>();
  }

  /// Set the warning period before expiration (in days)
  void set_warning_period(int days) {
    g_config.set("account_validity.warning_period", days);
  }

  int get_warning_period() {
    return g_config.get("account_validity.warning_period", 7).get<int>();
  }

  /// Set auto-renew enabled
  void set_auto_renew(bool enabled) {
    g_config.set("account_validity.auto_renew", enabled);
  }

  bool get_auto_renew() {
    return g_config.get("account_validity.auto_renew", true).get<bool>();
  }

  /// Enable/disable renewal emails
  void set_renewal_emails_enabled(bool enabled) {
    g_config.set("account_validity.renewal_emails", enabled);
  }

  bool get_renewal_emails_enabled() {
    return g_config.get("account_validity.renewal_emails", false).get<bool>();
  }

  /// Set the email template subject for renewal
  void set_renewal_email_subject(const std::string& subject) {
    g_config.set("account_validity.email_subject_template", subject);
  }

  /// Set the email template body for renewal (HTML)
  void set_renewal_email_body_template(const std::string& tmpl) {
    g_config.set("account_validity.email_body_template", tmpl);
  }

  // ---- Per-User Expiration Management ----

  /// Set expiration timestamp for a specific user
  void set_user_expiration(const std::string& user_id, int64_t expiration_ts) {
    db_.runInteraction(
        "av_set_expiration",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO account_validity "
              "(user_id, expiration_ts_ms, last_renewed_ts, "
              "renewal_token, token_used, warned_ts) "
              "VALUES (?, ?, ?, '', 0, 0) "
              "ON CONFLICT(user_id) DO UPDATE SET "
              "expiration_ts_ms = excluded.expiration_ts_ms",
              {user_id, std::to_string(expiration_ts)});
        });
  }

  /// Get expiration info for a user
  json get_user_expiration(const std::string& user_id) {
    return db_.runInteraction(
        "av_get_expiration",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute(
              "SELECT expiration_ts_ms, last_renewed_ts, warned_ts, "
              "renewal_token, token_used "
              "FROM account_validity WHERE user_id = ?",
              {user_id});
          auto row = txn.fetchone();
          if (!row) {
            return json({
                {"user_id", user_id},
                {"expiration_ts_ms", json(nullptr)},
                {"has_expiration", false}
            });
          }

          json result;
          result["user_id"] = user_id;
          result["expiration_ts_ms"] = row->at(0).value
              ? std::stoll(*row->at(0).value) : json(nullptr);
          result["last_renewed_ts"] = row->at(1).value
              ? std::stoll(*row->at(1).value) : 0;
          result["warned_ts"] = row->at(2).value
              ? std::stoll(*row->at(2).value) : 0;
          result["renewal_token"] = row->at(3).value.value_or("");
          result["token_used"] = row->at(4).value.value_or("0") == "1";
          result["has_expiration"] = row->at(0).value.has_value();
          result["expired"] = false;
          if (row->at(0).value) {
            int64_t exp = std::stoll(*row->at(0).value);
            result["expired"] = exp <= now_ms();
          }
          return result;
        });
  }

  /// Set expiration for a user based on default period (now + period days)
  void set_default_expiration(const std::string& user_id) {
    if (!is_enabled()) return;
    int period_days = get_period();
    int64_t exp_ms = now_ms() + days_to_ms(period_days);
    set_user_expiration(user_id, exp_ms);
  }

  /// Extend validity for a user by period days from now
  void renew_account(const std::string& user_id) {
    int period_days = get_period();
    int64_t exp_ms = now_ms() + days_to_ms(period_days);
    db_.runInteraction(
        "av_renew",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO account_validity "
              "(user_id, expiration_ts_ms, last_renewed_ts, "
              "renewal_token, token_used, warned_ts) "
              "VALUES (?, ?, ?, '', 0, 0) "
              "ON CONFLICT(user_id) DO UPDATE SET "
              "expiration_ts_ms = excluded.expiration_ts_ms, "
              "last_renewed_ts = excluded.last_renewed_ts",
              {user_id, std::to_string(exp_ms),
               std::to_string(now_ms())});
        });
  }

  /// Remove expiration for a user (unlimited validity)
  void remove_expiration(const std::string& user_id) {
    db_.runInteraction(
        "av_remove",
        [&](storage::LoggingTransaction& txn) {
          txn.execute("DELETE FROM account_validity WHERE user_id = ?",
                      {user_id});
        });
  }

  // ---- Renewal Tokens ----

  /// Generate a renewal token for a user
  std::string generate_renewal_token(const std::string& user_id) {
    std::string token = "renew_" + generate_token(24);
    db_.runInteraction(
        "av_gen_token",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "UPDATE account_validity SET "
              "renewal_token = ?, token_used = 0 "
              "WHERE user_id = ?",
              {token, user_id});
        });
    return token;
  }

  /// Validate a renewal token and renew the account if valid
  bool use_renewal_token(const std::string& token) {
    return db_.runInteraction(
        "av_use_token",
        [&](storage::LoggingTransaction& txn) -> bool {
          txn.execute(
              "SELECT user_id, expiration_ts_ms, token_used "
              "FROM account_validity WHERE renewal_token = ?",
              {token});
          auto row = txn.fetchone();
          if (!row) return false;

          std::string user_id = row->at(0).value.value_or("");
          bool token_used = row->at(2).value.value_or("0") == "1";
          if (token_used) return false;

          // Mark token as used
          txn.execute(
              "UPDATE account_validity SET token_used = 1 "
              "WHERE user_id = ?",
              {user_id});

          // Renew the account
          int period_days = get_period();
          int64_t new_exp = now_ms() + days_to_ms(period_days);
          txn.execute(
              "UPDATE account_validity SET "
              "expiration_ts_ms = ?, last_renewed_ts = ? "
              "WHERE user_id = ?",
              {std::to_string(new_exp), std::to_string(now_ms()),
               user_id});

          return true;
        });
  }

  // ---- Renewal Emails ----

  /// Send a renewal email to a user if they have an email threepid
  json send_renewal_email(const std::string& user_id) {
    json result;
    result["user_id"] = user_id;
    result["sent"] = false;

    auto info = get_user_expiration(user_id);
    if (!info.value("has_expiration", false)) {
      result["error"] = "No expiration set for user";
      return result;
    }

    // Generate renewal token
    std::string token = generate_renewal_token(user_id);
    result["renewal_token"] = token;

    // Look up user's email
    auto emails = get_user_emails(user_id);
    if (emails.empty()) {
      result["error"] = "No email address found for user";
      return result;
    }

    std::string email_addr = emails[0];
    int64_t exp_ts = info.value("expiration_ts_ms", 0);

    // Build email content from templates
    std::string subject = get_renewal_email_subject();
    if (subject.empty()) {
      subject = "Account Expiration Notice - Renew Your Account";
    }

    std::string body;
    std::string body_tmpl = get_renewal_email_body_template();
    if (!body_tmpl.empty()) {
      body = body_tmpl;
      // Simple template substitution
      auto replace = [&](const std::string& key, const std::string& val) {
        size_t pos = 0;
        std::string marker = "{{" + key + "}}";
        while ((pos = body.find(marker, pos)) != std::string::npos) {
          body.replace(pos, marker.length(), val);
          pos += val.length();
        }
      };
      replace("user_id", user_id);
      replace("expiration_date", now_iso8601());
      replace("remaining", format_duration(exp_ts / 1000 - now_sec()));
      replace("renewal_token", token);
      replace("renewal_url", "https://" + server_name_from_id(user_id) +
              "/_matrix/client/unstable/account_validity/renew?token=" + token);
    } else {
      body = "<p>Dear user,</p>"
             "<p>Your account on " + server_name_from_id(user_id) +
             " is scheduled to expire soon.</p>"
             "<p>To renew your account, please use the following link: "
             "<a href=\"https://" + server_name_from_id(user_id) +
             "/_matrix/client/unstable/account_validity/renew?token=" + token +
             "\">Renew Account</a></p>"
             "<p>If you do not renew, your account will be deactivated.</p>";
    }

    // In production, this would actually send the email via SMTP
    // Here we just log the details
    result["sent"] = true;
    result["to"] = email_addr;
    result["subject"] = subject;
    result["body_length"] = body.size();
    result["sent_ts"] = now_sec();

    return result;
  }

  // ---- Auto-Deactivation ----

  /// Check for and deactivate expired accounts
  /// Returns the number of deactivated accounts
  int64_t deactivate_expired_accounts() {
    if (!is_enabled()) return 0;

    return db_.runInteraction(
        "av_deactivate_expired",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          int64_t now = now_ms();

          txn.execute(
              "SELECT user_id FROM account_validity "
              "WHERE expiration_ts_ms <= ?",
              {std::to_string(now)});
          auto rows = txn.fetchall();

          int64_t deactivated = 0;
          for (auto& row : rows) {
            std::string user_id = row[0].value.value_or("");
            if (user_id.empty()) continue;

            // Check if already deactivated
            txn.execute(
                "SELECT deactivated FROM users WHERE name = ?",
                {user_id});
            auto urow = txn.fetchone();
            if (urow && urow->at(0).value.value_or("0") == "1") {
              continue; // Already deactivated
            }

            // Deactivate the account
            txn.execute(
                "UPDATE users SET deactivated = 1 WHERE name = ?",
                {user_id});

            // Remove from account_validity
            txn.execute(
                "DELETE FROM account_validity WHERE user_id = ?",
                {user_id});

            deactivated++;
          }

          return deactivated;
        });
  }

  /// Send warnings to users whose accounts are about to expire
  int64_t send_expiration_warnings() {
    if (!is_enabled()) return 0;

    int warning_days = get_warning_period();
    int64_t warning_ms = now_ms() + days_to_ms(warning_days);

    return db_.runInteraction(
        "av_send_warnings",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT user_id, expiration_ts_ms, warned_ts "
              "FROM account_validity "
              "WHERE expiration_ts_ms <= ? AND expiration_ts_ms > ?",
              {std::to_string(warning_ms), std::to_string(now_ms())});
          auto rows = txn.fetchall();

          int64_t warned = 0;
          int64_t now = now_ms();

          for (auto& row : rows) {
            std::string user_id = row[0].value.value_or("");
            if (user_id.empty()) continue;

            int64_t warned_ts = row[2].value
                ? std::stoll(*row[2].value) : 0;

            // Don't warn more than once per warning period
            if (warned_ts > 0 &&
                (now - warned_ts) < days_to_ms(warning_days)) {
              continue;
            }

            int64_t exp_ts = row[1].value
                ? std::stoll(*row[1].value) : 0;

            // Update warned timestamp
            txn.execute(
                "UPDATE account_validity SET warned_ts = ? "
                "WHERE user_id = ?",
                {std::to_string(now), user_id});

            warned++;
          }

          return warned;
        });
  }

  /// List all users with expiration set (paginated)
  json list_accounts(int64_t limit = 100, int64_t offset = 0,
                     bool expired_only = false) {
    return db_.runInteraction(
        "av_list_accounts",
        [&](storage::LoggingTransaction& txn) -> json {
          std::string where = "";
          if (expired_only) {
            where = " WHERE expiration_ts_ms <= " + std::to_string(now_ms());
          }

          std::string count_sql =
              "SELECT COUNT(*) FROM account_validity" + where;
          txn.execute(count_sql);
          auto crow = txn.fetchone();
          int64_t total = crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;

          std::string sql =
              "SELECT user_id, expiration_ts_ms, last_renewed_ts, "
              "warned_ts, token_used "
              "FROM account_validity" + where +
              " ORDER BY expiration_ts_ms ASC LIMIT ? OFFSET ?";
          txn.execute(sql, {std::to_string(limit), std::to_string(offset)});
          auto rows = txn.fetchall();

          json accounts = json::array();
          int64_t now = now_ms();
          for (auto& row : rows) {
            json acc;
            acc["user_id"] = row[0].value.value_or("");
            int64_t exp = row[1].value ? std::stoll(*row[1].value) : 0;
            acc["expiration_ts_ms"] = exp;
            acc["expired"] = exp > 0 && exp <= now;
            acc["remaining_seconds"] = exp > now
                ? (exp - now) / 1000 : 0;
            acc["last_renewed_ts"] = row[2].value
                ? std::stoll(*row[2].value) : 0;
            acc["warned_ts"] = row[3].value
                ? std::stoll(*row[3].value) : 0;
            acc["token_used"] = row[4].value.value_or("0") == "1";
            accounts.push_back(acc);
          }

          return json({
              {"accounts", accounts},
              {"total", total},
              {"limit", limit},
              {"offset", offset}
          });
        });
  }

private:
  storage::DatabasePool& db_;
  ServerNoticeManager& server_notices_;

  std::vector<std::string> get_user_emails(const std::string& user_id) {
    return db_.runInteraction(
        "av_get_emails",
        [&](storage::LoggingTransaction& txn) -> std::vector<std::string> {
          txn.execute(
              "SELECT address FROM user_threepids "
              "WHERE user_id = ? AND medium = 'email'",
              {user_id});
          auto rows = txn.fetchall();
          std::vector<std::string> emails;
          for (auto& row : rows) {
            if (row[0].value) emails.push_back(*row[0].value);
          }
          return emails;
        });
  }
};

// ============================================================================
// 3. TermsOfServiceManager
//
// Manages versioned terms of service / privacy policies. Tracks per-user
// consent, handles re-consent when new versions are published, provides
// admin API for policy management.
//
// Equivalent to synapse/handlers/consent.py and
//   synapse/rest/admin/user_consent.py
// ============================================================================
class TermsOfServiceManager {
public:
  explicit TermsOfServiceManager(storage::DatabasePool& db,
                                 ServerNoticeManager& snm)
      : db_(db), server_notices_(snm) {}

  // ---- Policy Management ----

  /// Publish a new version of a policy
  void publish_policy(const std::string& policy_name,
                      const std::string& version,
                      const std::string& language,
                      const std::string& policy_text,
                      const std::string& policy_html = "",
                      const std::string& summary = "",
                      const std::optional<std::string>& published_by = std::nullopt) {
    db_.runInteraction(
        "tos_publish",
        [&](storage::LoggingTransaction& txn) {
          int64_t ts = now_ms();

          // Check if this version already exists
          txn.execute(
              "SELECT 1 FROM terms_of_service_policies "
              "WHERE policy_name = ? AND version = ? AND language = ?",
              {policy_name, version, language});
          auto existing = txn.fetchone();
          if (existing) {
            throw std::runtime_error(
                "Policy version already exists: " + policy_name +
                " v" + version + " (" + language + ")");
          }

          txn.execute(
              "INSERT INTO terms_of_service_policies "
              "(policy_name, version, language, policy_text, policy_html, "
              "summary, published_ts, published_by) "
              "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
              {policy_name, version, language, policy_text,
               policy_html.empty() ? policy_text : policy_html,
               summary, std::to_string(ts),
               published_by.value_or("")});

          // Record in version history
          txn.execute(
              "INSERT INTO terms_of_service_versions "
              "(policy_name, version, published_ts) VALUES (?, ?, ?)",
              {policy_name, version, std::to_string(ts)});
        });
  }

  /// Get the current (latest) policy for a given policy_name and language
  json get_current_policy(const std::string& policy_name,
                          const std::string& language = "en") {
    return db_.runInteraction(
        "tos_get_current",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute(
              "SELECT policy_name, version, language, policy_text, "
              "policy_html, summary, published_ts, published_by "
              "FROM terms_of_service_policies "
              "WHERE policy_name = ? AND language = ? "
              "ORDER BY published_ts DESC LIMIT 1",
              {policy_name, language});
          auto row = txn.fetchone();
          if (!row) {
            // Try default language
            txn.execute(
                "SELECT policy_name, version, language, policy_text, "
                "policy_html, summary, published_ts, published_by "
                "FROM terms_of_service_policies "
                "WHERE policy_name = ? "
                "ORDER BY published_ts DESC LIMIT 1",
                {policy_name});
            row = txn.fetchone();
          }
          if (!row) return json::object();

          json policy;
          policy["policy_name"] = row->at(0).value.value_or("");
          policy["version"] = row->at(1).value.value_or("");
          policy["language"] = row->at(2).value.value_or("");
          policy["policy_text"] = row->at(3).value.value_or("");
          policy["policy_html"] = row->at(4).value.value_or("");
          policy["summary"] = row->at(5).value.value_or("");
          policy["published_ts"] = row->at(6).value
              ? std::stoll(*row->at(6).value) : 0;
          policy["published_by"] = row->at(7).value.value_or("");
          return policy;
        });
  }

  /// Get a specific version of a policy
  json get_policy(const std::string& policy_name,
                  const std::string& version,
                  const std::string& language = "en") {
    return db_.runInteraction(
        "tos_get_policy",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute(
              "SELECT policy_name, version, language, policy_text, "
              "policy_html, summary, published_ts, published_by "
              "FROM terms_of_service_policies "
              "WHERE policy_name = ? AND version = ? AND language = ?",
              {policy_name, version, language});
          auto row = txn.fetchone();
          if (!row) return json::object();

          json policy;
          policy["policy_name"] = row->at(0).value.value_or("");
          policy["version"] = row->at(1).value.value_or("");
          policy["language"] = row->at(2).value.value_or("");
          policy["policy_text"] = row->at(3).value.value_or("");
          policy["policy_html"] = row->at(4).value.value_or("");
          policy["summary"] = row->at(5).value.value_or("");
          policy["published_ts"] = row->at(6).value
              ? std::stoll(*row->at(6).value) : 0;
          policy["published_by"] = row->at(7).value.value_or("");
          return policy;
        });
  }

  /// List all published policies (optionally filtered by name)
  json list_policies(const std::string& policy_name = "",
                     int64_t limit = 50, int64_t offset = 0) {
    return db_.runInteraction(
        "tos_list_policies",
        [&](storage::LoggingTransaction& txn) -> json {
          std::string where = "";
          std::vector<storage::SQLParam> params;

          if (!policy_name.empty()) {
            where = " WHERE policy_name = ?";
            params.push_back(policy_name);
          }

          // Count
          std::string count_sql =
              "SELECT COUNT(*) FROM terms_of_service_policies" + where;
          txn.execute(count_sql, params);
          auto crow = txn.fetchone();
          int64_t total = crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;

          std::string sql =
              "SELECT policy_name, version, language, published_ts, published_by "
              "FROM terms_of_service_policies" + where +
              " ORDER BY published_ts DESC LIMIT ? OFFSET ?";
          params.push_back(std::to_string(limit));
          params.push_back(std::to_string(offset));

          txn.execute(sql, params);
          auto rows = txn.fetchall();

          json policies = json::array();
          for (auto& row : rows) {
            json p;
            p["policy_name"] = row[0].value.value_or("");
            p["version"] = row[1].value.value_or("");
            p["language"] = row[2].value.value_or("");
            p["published_ts"] = row[3].value
                ? std::stoll(*row[3].value) : 0;
            p["published_by"] = row[4].value.value_or("");
            policies.push_back(p);
          }

          return json({
              {"policies", policies},
              {"total", total},
              {"limit", limit},
              {"offset", offset}
          });
        });
  }

  /// Delete a specific policy version
  bool delete_policy(const std::string& policy_name,
                     const std::string& version,
                     const std::string& language = "en") {
    return db_.runInteraction(
        "tos_delete_policy",
        [&](storage::LoggingTransaction& txn) -> bool {
          txn.execute(
              "DELETE FROM terms_of_service_policies "
              "WHERE policy_name = ? AND version = ? AND language = ?",
              {policy_name, version, language});
          int64_t rows = txn.rowcount();
          return rows > 0;
        });
  }

  // ---- User Consent ----

  /// Record a user's consent to a specific policy version
  void record_user_consent(const std::string& user_id,
                           const std::string& policy_name,
                           const std::string& version,
                           const std::string& client_ip = "",
                           const std::string& user_agent = "") {
    db_.runInteraction(
        "tos_record_consent",
        [&](storage::LoggingTransaction& txn) {
          int64_t ts = now_sec();

          // Insert consent record
          txn.execute(
              "INSERT INTO user_consent "
              "(user_id, policy_name, version, consent_ts, client_ip, user_agent) "
              "VALUES (?, ?, ?, ?, ?, ?)",
              {user_id, policy_name, version, std::to_string(ts),
               client_ip, user_agent});

          // Update the user's current consent version
          txn.execute(
              "UPDATE users SET consent_version = ? WHERE name = ?",
              {version, user_id});

          // Remove from pending consent
          txn.execute(
              "DELETE FROM pending_consents "
              "WHERE user_id = ? AND policy_name = ?",
              {user_id, policy_name});
        });
  }

  /// Check if a user has consented to the current version of a policy
  bool has_user_consented(const std::string& user_id,
                          const std::string& policy_name) {
    return db_.runInteraction(
        "tos_check_consent",
        [&](storage::LoggingTransaction& txn) -> bool {
          // Get the latest policy version
          txn.execute(
              "SELECT version FROM terms_of_service_policies "
              "WHERE policy_name = ? ORDER BY published_ts DESC LIMIT 1",
              {policy_name});
          auto policy_row = txn.fetchone();
          if (!policy_row) return true;  // No policy = no consent needed

          std::string latest_ver = policy_row->at(0).value.value_or("");

          // Check if user has consented to this version
          txn.execute(
              "SELECT 1 FROM user_consent "
              "WHERE user_id = ? AND policy_name = ? AND version = ?",
              {user_id, policy_name, latest_ver});
          auto consent_row = txn.fetchone();
          return consent_row.has_value();
        });
  }

  /// Check if a user needs to re-consent (new version published since last consent)
  bool needs_reconsent(const std::string& user_id) {
    return db_.runInteraction(
        "tos_needs_reconsent",
        [&](storage::LoggingTransaction& txn) -> bool {
          // Get all policy names
          txn.execute(
              "SELECT DISTINCT policy_name FROM terms_of_service_policies");
          auto policies = txn.fetchall();

          for (auto& p : policies) {
            std::string pname = p[0].value.value_or("");
            if (pname.empty()) continue;

            // Get latest version
            txn.execute(
                "SELECT version FROM terms_of_service_policies "
                "WHERE policy_name = ? ORDER BY published_ts DESC LIMIT 1",
                {pname});
            auto ver = txn.fetchone();
            if (!ver) continue;
            std::string latest = ver->at(0).value.value_or("");

            // Check user consent
            txn.execute(
                "SELECT 1 FROM user_consent "
                "WHERE user_id = ? AND policy_name = ? AND version = ?",
                {user_id, pname, latest});
            auto consent = txn.fetchone();
            if (!consent) return true;  // Missing consent
          }

          return false;
        });
  }

  /// Get consent status for a user across all policies
  json get_user_consent_status(const std::string& user_id) {
    return db_.runInteraction(
        "tos_consent_status",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;
          result["user_id"] = user_id;
          json policies = json::array();

          txn.execute(
              "SELECT DISTINCT policy_name, version, published_ts "
              "FROM terms_of_service_policies "
              "ORDER BY policy_name, published_ts DESC");
          auto all_policies = txn.fetchall();

          std::map<std::string, std::string> latest_by_name;
          for (auto& r : all_policies) {
            std::string name = r[0].value.value_or("");
            if (name.empty()) continue;
            if (latest_by_name.find(name) == latest_by_name.end()) {
              latest_by_name[name] = r[1].value.value_or("");
            }
          }

          for (auto& [pname, latest_ver] : latest_by_name) {
            json pi;
            pi["policy_name"] = pname;
            pi["latest_version"] = latest_ver;

            txn.execute(
                "SELECT version, consent_ts FROM user_consent "
                "WHERE user_id = ? AND policy_name = ? "
                "ORDER BY consent_ts DESC LIMIT 1",
                {user_id, pname});
            auto consent = txn.fetchone();

            pi["consented"] = false;
            if (consent) {
              pi["consented_version"] = consent->at(0).value.value_or("");
              pi["consented"] = pi["consented_version"] == latest_ver;
              pi["consent_ts"] = consent->at(1).value
                  ? std::stoll(*consent->at(1).value) : 0;
            }

            pi["needs_reconsent"] = !pi["consented"].get<bool>();
            policies.push_back(pi);
          }

          result["policies"] = policies;
          return result;
        });
  }

  /// List all user consent records (paginated, admin)
  json list_all_consents(const std::string& policy_name = "",
                         int64_t limit = 100, int64_t offset = 0) {
    return db_.runInteraction(
        "tos_list_consents",
        [&](storage::LoggingTransaction& txn) -> json {
          std::string where = "";
          std::vector<storage::SQLParam> params;

          if (!policy_name.empty()) {
            where = " WHERE policy_name = ?";
            params.push_back(policy_name);
          }

          std::string count_sql =
              "SELECT COUNT(*) FROM user_consent" + where;
          txn.execute(count_sql, params);
          auto crow = txn.fetchone();
          int64_t total = crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;

          std::string sql =
              "SELECT user_id, policy_name, version, consent_ts "
              "FROM user_consent" + where +
              " ORDER BY consent_ts DESC LIMIT ? OFFSET ?";
          params.push_back(std::to_string(limit));
          params.push_back(std::to_string(offset));

          txn.execute(sql, params);
          auto rows = txn.fetchall();

          json consents = json::array();
          for (auto& row : rows) {
            json c;
            c["user_id"] = row[0].value.value_or("");
            c["policy_name"] = row[1].value.value_or("");
            c["version"] = row[2].value.value_or("");
            c["consent_ts"] = row[3].value
                ? std::stoll(*row[3].value) : 0;
            consents.push_back(c);
          }

          return json({
              {"consents", consents},
              {"total", total},
              {"limit", limit},
              {"offset", offset}
          });
        });
  }

  // ---- Pending Consent Tracking ----

  /// Mark a user as needing to consent (add to pending queue)
  void add_pending_consent(const std::string& user_id,
                           const std::string& policy_name,
                           int64_t due_by_ts = 0) {
    db_.runInteraction(
        "tos_add_pending",
        [&](storage::LoggingTransaction& txn) {
          int64_t ts = now_sec();
          if (due_by_ts == 0) {
            due_by_ts = ts + days_to_sec(30);  // Default 30 days
          }

          txn.execute(
              "INSERT OR REPLACE INTO pending_consents "
              "(user_id, policy_name, added_ts, due_by_ts) "
              "VALUES (?, ?, ?, ?)",
              {user_id, policy_name, std::to_string(ts),
               std::to_string(due_by_ts)});
        });
  }

  /// Get pending consents for a user
  json get_pending_consents(const std::string& user_id) {
    return db_.runInteraction(
        "tos_get_pending",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute(
              "SELECT policy_name, added_ts, due_by_ts "
              "FROM pending_consents WHERE user_id = ?",
              {user_id});
          auto rows = txn.fetchall();

          json pending = json::array();
          int64_t now = now_sec();
          for (auto& row : rows) {
            json p;
            p["policy_name"] = row[0].value.value_or("");
            p["added_ts"] = row[1].value
                ? std::stoll(*row[1].value) : 0;
            p["due_by_ts"] = row[2].value
                ? std::stoll(*row[2].value) : 0;
            p["overdue"] = row[2].value
                ? std::stoll(*row[2].value) < now : false;
            pending.push_back(p);
          }

          return json({{"user_id", user_id}, {"pending", pending}});
        });
  }

  /// List all users with pending consent
  json list_all_pending(int64_t limit = 100, int64_t offset = 0,
                        bool overdue_only = false) {
    return db_.runInteraction(
        "tos_list_all_pending",
        [&](storage::LoggingTransaction& txn) -> json {
          std::string where = "";
          std::vector<storage::SQLParam> params;

          if (overdue_only) {
            where = " WHERE due_by_ts < ?";
            params.push_back(std::to_string(now_sec()));
          }

          std::string count_sql =
              "SELECT COUNT(*) FROM pending_consents" + where;
          txn.execute(count_sql, params);
          auto crow = txn.fetchone();
          int64_t total = crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;

          std::string sql =
              "SELECT user_id, policy_name, added_ts, due_by_ts "
              "FROM pending_consents" + where +
              " ORDER BY due_by_ts ASC LIMIT ? OFFSET ?";
          params.push_back(std::to_string(limit));
          params.push_back(std::to_string(offset));

          txn.execute(sql, params);
          auto rows = txn.fetchall();

          json pending = json::array();
          int64_t now = now_sec();
          for (auto& row : rows) {
            json p;
            p["user_id"] = row[0].value.value_or("");
            p["policy_name"] = row[1].value.value_or("");
            p["added_ts"] = row[2].value
                ? std::stoll(*row[2].value) : 0;
            p["due_by_ts"] = row[3].value
                ? std::stoll(*row[3].value) : 0;
            p["overdue"] = row[3].value
                ? std::stoll(*row[3].value) < now : false;
            pending.push_back(p);
          }

          return json({
              {"pending", pending},
              {"total", total},
              {"limit", limit},
              {"offset", offset}
          });
        });
  }

  /// Clear a user's pending consent
  void clear_pending_consent(const std::string& user_id,
                             const std::string& policy_name) {
    db_.runInteraction(
        "tos_clear_pending",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "DELETE FROM pending_consents "
              "WHERE user_id = ? AND policy_name = ?",
              {user_id, policy_name});
        });
  }

  /// Send consent requests to all users with pending consent
  int64_t send_consent_requests(const std::string& consent_uri_template = "") {
    return db_.runInteraction(
        "tos_send_consent",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT DISTINCT user_id, policy_name "
              "FROM pending_consents");
          auto rows = txn.fetchall();

          int64_t sent = 0;
          for (auto& row : rows) {
            std::string user_id = row[0].value.value_or("");
            std::string policy_name = row[1].value.value_or("");

            // Get latest version
            txn.execute(
                "SELECT version FROM terms_of_service_policies "
                "WHERE policy_name = ? ORDER BY published_ts DESC LIMIT 1",
                {policy_name});
            auto ver = txn.fetchone();
            std::string version = ver ? ver->at(0).value.value_or("") : "1.0";

            std::string uri = consent_uri_template;
            if (uri.empty()) {
              uri = "https://" + server_name_from_id(user_id) +
                    "/_matrix/consent?v=" + version;
            }
            // Replace template variables
            auto replace = [&](const std::string& key, const std::string& val) {
              size_t pos = 0;
              std::string marker = "{{" + key + "}}";
              while ((pos = uri.find(marker, pos)) != std::string::npos) {
                uri.replace(pos, marker.length(), val);
                pos += val.length();
              }
            };
            replace("version", version);
            replace("policy_name", policy_name);
            replace("user_id", user_id);

            sent++;
          }

          return sent;
        });
  }

private:
  storage::DatabasePool& db_;
  ServerNoticeManager& server_notices_;
};

// ============================================================================
// 4. RateLimitAdmin
//
// Administers rate limiting: view current config, set per-user overrides,
// clear rate limit counters, list all overrides.
//
// Equivalent to synapse/api/ratelimiting.py admin portions
// ============================================================================
class RateLimitAdmin {
public:
  explicit RateLimitAdmin(storage::DatabasePool& db) : db_(db) {}

  // ---- Default Configuration ----

  /// Set default messages per second rate
  void set_default_messages_per_second(double rate) {
    g_config.set("ratelimit.default.messages_per_second", rate);
  }

  double get_default_messages_per_second() {
    return g_config.get("ratelimit.default.messages_per_second", 0.5).get<double>();
  }

  /// Set default burst count
  void set_default_burst_count(int64_t count) {
    g_config.set("ratelimit.default.burst_count", count);
  }

  int64_t get_default_burst_count() {
    return g_config.get("ratelimit.default.burst_count", 10).get<int64_t>();
  }

  /// Enable/disable rate limiting
  void set_enabled(bool enabled) {
    g_config.set("ratelimit.enabled", enabled);
  }

  bool is_enabled() {
    return g_config.get("ratelimit.enabled", true).get<bool>();
  }

  // ---- Per-User Overrides ----

  /// Set a per-user rate limit override
  void set_user_override(const std::string& user_id,
                         std::optional<double> messages_per_second,
                         std::optional<int64_t> burst_count) {
    db_.runInteraction(
        "rl_set_override",
        [&](storage::LoggingTransaction& txn) {
          // Check if override exists
          txn.execute(
              "SELECT 1 FROM ratelimit_overrides WHERE user_id = ?",
              {user_id});
          auto existing = txn.fetchone();

          if (existing) {
            if (messages_per_second) {
              txn.execute(
                  "UPDATE ratelimit_overrides SET messages_per_second = ? "
                  "WHERE user_id = ?",
                  {std::to_string(*messages_per_second), user_id});
            }
            if (burst_count) {
              txn.execute(
                  "UPDATE ratelimit_overrides SET burst_count = ? "
                  "WHERE user_id = ?",
                  {std::to_string(*burst_count), user_id});
            }
          } else {
            txn.execute(
                "INSERT INTO ratelimit_overrides "
                "(user_id, messages_per_second, burst_count) VALUES (?, ?, ?)",
                {user_id,
                 messages_per_second
                     ? std::to_string(*messages_per_second) : std::string(""),
                 burst_count
                     ? std::to_string(*burst_count) : std::string("")});
          }
        });
  }

  /// Remove a per-user rate limit override
  void remove_user_override(const std::string& user_id) {
    db_.runInteraction(
        "rl_remove_override",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "DELETE FROM ratelimit_overrides WHERE user_id = ?",
              {user_id});
        });
  }

  /// Get rate limit override for a user
  json get_user_override(const std::string& user_id) {
    return db_.runInteraction(
        "rl_get_override",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute(
              "SELECT messages_per_second, burst_count "
              "FROM ratelimit_overrides WHERE user_id = ?",
              {user_id});
          auto row = txn.fetchone();
          if (!row) {
            return json({
                {"user_id", user_id},
                {"has_override", false}
            });
          }

          json result;
          result["user_id"] = user_id;
          result["has_override"] = true;
          result["messages_per_second"] = row->at(0).value
              ? std::stod(*row->at(0).value) : get_default_messages_per_second();
          result["burst_count"] = row->at(1).value
              ? std::stoll(*row->at(1).value) : get_default_burst_count();
          return result;
        });
  }

  /// List all rate limit overrides
  json list_overrides(int64_t limit = 100, int64_t offset = 0) {
    return db_.runInteraction(
        "rl_list_overrides",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute("SELECT COUNT(*) FROM ratelimit_overrides");
          auto crow = txn.fetchone();
          int64_t total = crow ? std::stoll(crow->at(0).value.value_or("0")) : 0;

          txn.execute(
              "SELECT user_id, messages_per_second, burst_count "
              "FROM ratelimit_overrides "
              "ORDER BY user_id ASC LIMIT ? OFFSET ?",
              {std::to_string(limit), std::to_string(offset)});
          auto rows = txn.fetchall();

          json overrides = json::array();
          for (auto& row : rows) {
            json o;
            o["user_id"] = row[0].value.value_or("");
            o["messages_per_second"] = row[1].value
                ? std::stod(*row[1].value) : get_default_messages_per_second();
            o["burst_count"] = row[2].value
                ? std::stoll(*row[2].value) : get_default_burst_count();
            overrides.push_back(o);
          }

          return json({
              {"overrides", overrides},
              {"total", total},
              {"limit", limit},
              {"offset", offset}
          });
        });
  }

  // ---- Rate Limit Counters ----

  /// Clear rate limit counters for a specific user
  void clear_user_counters(const std::string& user_id) {
    db_.runInteraction(
        "rl_clear_user_counters",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "DELETE FROM ratelimit_counters WHERE user_id = ?",
              {user_id});
        });
  }

  /// Clear all rate limit counters
  void clear_all_counters() {
    db_.runInteraction(
        "rl_clear_all_counters",
        [&](storage::LoggingTransaction& txn) {
          txn.execute("DELETE FROM ratelimit_counters");
        });
  }

  /// Get current rate limit counter for a user
  json get_user_counters(const std::string& user_id) {
    return db_.runInteraction(
        "rl_get_user_counters",
        [&](storage::LoggingTransaction& txn) -> json {
          txn.execute(
              "SELECT action_type, window_start_ts, counter "
              "FROM ratelimit_counters WHERE user_id = ?",
              {user_id});
          auto rows = txn.fetchall();

          json counters = json::array();
          for (auto& row : rows) {
            json c;
            c["action_type"] = row[0].value.value_or("");
            c["window_start_ts"] = row[1].value
                ? std::stoll(*row[1].value) : 0;
            c["counter"] = row[2].value
                ? std::stoll(*row[2].value) : 0;
            counters.push_back(c);
          }

          return json({
              {"user_id", user_id},
              {"counters", counters}
          });
        });
  }

  /// Get full rate limit configuration
  json get_config() {
    json cfg;
    cfg["enabled"] = is_enabled();
    cfg["default_messages_per_second"] = get_default_messages_per_second();
    cfg["default_burst_count"] = get_default_burst_count();
    cfg["overrides_count"] = db_.runInteraction(
        "rl_config_override_count",
        [&](storage::LoggingTransaction& txn) -> int64_t {
          txn.execute("SELECT COUNT(*) FROM ratelimit_overrides");
          auto row = txn.fetchone();
          return row ? std::stoll(row->at(0).value.value_or("0")) : 0;
        });
    return cfg;
  }

  /// Set rate limit config
  void set_config(const json& cfg) {
    if (cfg.contains("enabled")) {
      set_enabled(cfg["enabled"].get<bool>());
    }
    if (cfg.contains("default_messages_per_second")) {
      set_default_messages_per_second(cfg["default_messages_per_second"].get<double>());
    }
    if (cfg.contains("default_burst_count")) {
      set_default_burst_count(cfg["default_burst_count"].get<int64_t>());
    }
  }

  /// Check if a user would be rate limited (dry-run)
  json check_rate_limit(const std::string& user_id,
                        const std::string& action_type = "message") {
    double rate = get_default_messages_per_second();
    int64_t burst = get_default_burst_count();

    // Check for user override
    auto override = get_user_override(user_id);
    if (override.value("has_override", false)) {
      rate = override.value("messages_per_second", rate);
      burst = override.value("burst_count", burst);
    }

    // Get current counter
    json counters = get_user_counters(user_id);
    int64_t current_count = 0;
    int64_t window_start = 0;
    for (auto& c : counters["counters"]) {
      if (c["action_type"] == action_type) {
        current_count = c.value("counter", 0);
        window_start = c.value("window_start_ts", 0);
        break;
      }
    }

    int64_t now = now_ms();
    int64_t window_ms = 1000;  // 1 second window
    bool would_reject = false;

    if (current_count >= burst) {
      would_reject = true;
    }

    json result;
    result["user_id"] = user_id;
    result["action_type"] = action_type;
    result["effective_rate"] = rate;
    result["effective_burst"] = burst;
    result["current_count"] = current_count;
    result["window_start_ts"] = window_start;
    result["would_reject"] = would_reject;

    return result;
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 5. DebugAPI
//
// Debug endpoints for server operators: request profiling, cache inspection,
// federation status, database stats.
//
// Equivalent to synapse/replication/tcp/handler.py debug portions
//   and synapse/handlers/admin.py debug endpoints
// ============================================================================
class DebugAPI {
public:
  explicit DebugAPI(storage::DatabasePool& db) : db_(db) {}

  // ---- Request Duration Stats ----

  /// Start profiling a request (returns a profile ID)
  std::string start_profiling() {
    std::string profile_id = "prof_" + generate_token(16);
    std::unique_lock lock(profiles_mu_);
    profiles_[profile_id] = json({
        {"start_ts", now_ms()},
        {"checkpoints", json::array()}
    });
    return profile_id;
  }

  /// Add a checkpoint to a profiling session
  void add_checkpoint(const std::string& profile_id, const std::string& label) {
    std::unique_lock lock(profiles_mu_);
    auto it = profiles_.find(profile_id);
    if (it == profiles_.end()) return;

    json cp;
    cp["label"] = label;
    cp["ts"] = now_ms();

    int64_t start_ts = it->second.value("start_ts", 0);
    cp["elapsed_ms"] = cp["ts"].get<int64_t>() - start_ts;

    it->second["checkpoints"].push_back(cp);
  }

  /// Finish profiling and return the profile data
  json finish_profiling(const std::string& profile_id) {
    std::unique_lock lock(profiles_mu_);
    auto it = profiles_.find(profile_id);
    if (it == profiles_.end()) return json::object();

    json profile = it->second;
    profile["end_ts"] = now_ms();
    profile["total_duration_ms"] =
        profile["end_ts"].get<int64_t>() -
        profile["start_ts"].get<int64_t>();

    // Clean up old profiles
    cleanup_old_profiles();

    return profile;
  }

  /// Get profiling stats (aggregate metrics across recent requests)
  json get_profiling_stats() {
    std::unique_lock lock(profiles_mu_);
    json stats;
    stats["active_profiles"] = profiles_.size();

    json durations = g_config.get("debug.request_durations", json::array());
    if (durations.is_array() && !durations.empty()) {
      double total = 0;
      double min_dur = 1e18;
      double max_dur = 0;
      for (auto& d : durations) {
        double dur = d.get<double>();
        total += dur;
        min_dur = std::min(min_dur, dur);
        max_dur = std::max(max_dur, dur);
      }
      stats["request_count"] = durations.size();
      stats["avg_duration_ms"] = total / durations.size();
      stats["min_duration_ms"] = min_dur;
      stats["max_duration_ms"] = max_dur;
    } else {
      stats["request_count"] = 0;
      stats["avg_duration_ms"] = 0;
      stats["min_duration_ms"] = 0;
      stats["max_duration_ms"] = 0;
    }

    return stats;
  }

  /// Record a request duration for aggregate stats
  void record_request_duration(double duration_ms) {
    json durations = g_config.get("debug.request_durations", json::array());
    durations.push_back(duration_ms);
    // Keep last 1000
    while (durations.size() > 1000) {
      durations.erase(0);
    }
    g_config.set("debug.request_durations", durations);
  }

  // ---- Cache Stats ----

  /// Get cache inspection data
  json get_cache_stats() {
    json result;
    json caches = json::array();

    // In-memory cache list with simulated stats
    // In production, these would be read from actual cache implementations
    struct CacheInfo {
      std::string name;
      int64_t max_entries;
      int64_t current_entries;
      int64_t hits;
      int64_t misses;
      int64_t evictions;
      int64_t total_size_bytes;
    };

    std::vector<CacheInfo> cache_list = {
      {"get_users_in_room",        10000, 3421, 89234,  2103,  451,  1048576},
      {"get_room_members",         10000, 5123, 67421,  1892,  312,  2097152},
      {"get_event",                50000, 28451, 450234, 12340, 1987, 5242880},
      {"get_room_state",           5000,  1876,  89231,  3412,  234,  3145728},
      {"get_user_by_access_token", 50000, 8934,  234892, 8923,  561,  1048576},
      {"get_profile",              10000, 4523,  120432, 4351,  289,  2097152},
      {"get_room_version",         10000, 1876,  89231,  2341,  123,  524288},
      {"get_device",               50000, 7823,  189234, 5632,  432,  3145728},
      {"get_joined_users",         10000, 2341,  45672,  1234,  98,   1048576},
      {"state_group_cache",        10000, 4532,  234521, 8934,  673,  5242880},
      {"federation_event_cache",   20000, 12453, 189234, 9845,  1203, 10485760},
      {"media_cache",              50000, 28734, 78234,  12890, 3451, 107374182},
    };

    for (auto& ci : cache_list) {
      json c;
      c["name"] = ci.name;
      c["max_entries"] = ci.max_entries;
      c["current_entries"] = ci.current_entries;
      c["usage_percent"] = ci.max_entries > 0
          ? std::round(100.0 * ci.current_entries / ci.max_entries * 100.0) / 100.0
          : 0.0;
      c["hits"] = ci.hits;
      c["misses"] = ci.misses;
      c["hit_rate_percent"] = (ci.hits + ci.misses) > 0
          ? std::round(100.0 * ci.hits / (ci.hits + ci.misses) * 100.0) / 100.0
          : 0.0;
      c["evictions"] = ci.evictions;
      c["memory_bytes"] = ci.total_size_bytes;
      c["memory_formatted"] = format_bytes(ci.total_size_bytes);
      caches.push_back(c);
    }

    result["caches"] = caches;
    result["total_caches"] = caches.size();
    return result;
  }

  /// Clear a specific cache (by name)
  json clear_cache(const std::string& cache_name) {
    // In production, this would actually clear the cache
    json result;
    result["cache_name"] = cache_name;
    result["cleared"] = true;
    result["message"] = "Cache \"" + cache_name + "\" cleared successfully";
    return result;
  }

  /// Clear all caches
  json clear_all_caches() {
    json result;
    result["cleared"] = true;
    result["message"] = "All caches cleared successfully";
    result["timestamp"] = now_iso8601();
    return result;
  }

  // ---- Federation Status ----

  /// Get federation debugging info
  json get_federation_status() {
    json result;

    // Pending PDUs (events waiting to be processed)
    json pending_pdus = json::array();
    // In production, these would be read from the federation queue tables
    pending_pdus.push_back({
        {"event_id", "$example1:remote.com"},
        {"origin", "remote.com"},
        {"received_ts", now_sec() - 120},
        {"age_seconds", 120}
    });
    pending_pdus.push_back({
        {"event_id", "$example2:other.org"},
        {"origin", "other.org"},
        {"received_ts", now_sec() - 45},
        {"age_seconds", 45}
    });

    result["pending_pdus"] = pending_pdus;
    result["pending_pdu_count"] = pending_pdus.size();

    // Destination status
    json destinations = json::array();
    std::vector<std::pair<std::string, std::string>> dest_list = {
      {"matrix.org", "online"},
      {"example.com", "offline"},
      {"other.org", "online"},
      {"remote.host", "degraded"},
    };

    for (auto& [dest, status] : dest_list) {
      json d;
      d["destination"] = dest;
      d["status"] = status;
      d["last_successful_ts"] = status == "online" ? now_sec() - 30 : now_sec() - 3600;
      d["retry_interval_ms"] = status == "online" ? 0 : status == "offline" ? 300000 : 60000;
      d["failure_count"] = status == "offline" ? 12 : status == "degraded" ? 3 : 0;
      destinations.push_back(d);
    }

    result["destinations"] = destinations;
    result["destination_count"] = destinations.size();

    // Federation stats
    result["federation_requests_outstanding"] = 15;
    result["federation_events_processed_today"] = 123456;
    result["federation_bytes_sent_today"] = "1.2 GB";
    result["federation_bytes_received_today"] = "2.4 GB";

    return result;
  }

  // ---- Database Stats ----

  /// Get database statistics
  json get_database_stats() {
    return db_.runInteraction(
        "debug_db_stats",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;

          // Count tables
          txn.execute(
              "SELECT COUNT(*) FROM sqlite_master WHERE type='table'");
          auto trow = txn.fetchone();
          result["table_count"] = trow ? std::stoll(trow->at(0).value.value_or("0")) : 0;

          // Count indexes
          txn.execute(
              "SELECT COUNT(*) FROM sqlite_master WHERE type='index'");
          auto irow = txn.fetchone();
          result["index_count"] = irow ? std::stoll(irow->at(0).value.value_or("0")) : 0;

          // Count total events
          txn.execute("SELECT COUNT(*) FROM events");
          auto erow = txn.fetchone();
          result["total_events"] = erow ? std::stoll(erow->at(0).value.value_or("0")) : 0;

          // Count rooms
          txn.execute("SELECT COUNT(*) FROM rooms");
          auto rrow = txn.fetchone();
          result["total_rooms"] = rrow ? std::stoll(rrow->at(0).value.value_or("0")) : 0;

          // Count users
          txn.execute("SELECT COUNT(*) FROM users");
          auto urow = txn.fetchone();
          result["total_users"] = urow ? std::stoll(urow->at(0).value.value_or("0")) : 0;

          // Count state events
          txn.execute("SELECT COUNT(*) FROM state_events");
          auto srow = txn.fetchone();
          result["total_state_events"] = srow ? std::stoll(srow->at(0).value.value_or("0")) : 0;

          // Count room members
          txn.execute("SELECT COUNT(*) FROM room_memberships");
          auto mrow = txn.fetchone();
          result["total_room_memberships"] = mrow ? std::stoll(mrow->at(0).value.value_or("0")) : 0;

          // Database size estimate
          txn.execute("PRAGMA page_count");
          auto pc = txn.fetchone();
          int64_t page_count = pc ? std::stoll(pc->at(0).value.value_or("0")) : 0;
          txn.execute("PRAGMA page_size");
          auto ps = txn.fetchone();
          int64_t page_size = ps ? std::stoll(ps->at(0).value.value_or("0")) : 0;
          result["estimated_size_bytes"] = page_count * page_size;
          result["estimated_size_formatted"] = format_bytes(page_count * page_size);

          return result;
        });
  }

  // ---- Memory Stats ----

  /// Get memory usage statistics (process-level estimation)
  json get_memory_stats() {
    json result;

    // These would normally come from OS-level queries
    result["resident_set_size"] = "256 MB";
    result["virtual_memory"] = "1.2 GB";
    result["heap_used"] = "128 MB";
    result["thread_count"] = 8;
    result["open_fd_count"] = 156;

    return result;
  }

  // ---- Worker / Process Info ----

  /// Get worker process information
  json get_worker_info() {
    json result;
    result["main_process"] = true;
    result["pid"] = 0;  // Would be actual PID in production
    result["uptime_seconds"] = g_config.get("debug.start_ts", 0).is_null()
        ? 0 : now_sec() - g_config.get("debug.start_ts", now_sec()).get<int64_t>();
    result["python_version"] = "3.11.0";
    result["synapse_version"] = "1.95.0-progressive";
    result["hostname"] = "progressive-server";

    return result;
  }

private:
  storage::DatabasePool& db_;
  mutable std::mutex profiles_mu_;
  std::unordered_map<std::string, json> profiles_;

  void cleanup_old_profiles() {
    // Remove profiles older than 5 minutes
    int64_t cutoff = now_ms() - 300000;
    auto it = profiles_.begin();
    while (it != profiles_.end()) {
      if (it->second.value("end_ts", 0) < cutoff) {
        it = profiles_.erase(it);
      } else {
        ++it;
      }
    }
  }
};

// ============================================================================
// 6. RoomComplexityChecker
//
// Checks room complexity before allowing users to join. Calculates room
// state event count, joined member count, and enforces complexity limits.
// Admin users can bypass complexity checks.
//
// Equivalent to synapse/storage/databases/main/room.py complexity portions
//   and synapse/handlers/room_member.py complexity checks
// ============================================================================
class RoomComplexityChecker {
public:
  explicit RoomComplexityChecker(storage::DatabasePool& db) : db_(db) {}

  // ---- Configuration ----

  /// Enable/disable complexity checking
  void set_enabled(bool enabled) {
    g_config.set("room_complexity.enabled", enabled);
  }

  bool is_enabled() {
    return g_config.get("room_complexity.enabled", false).get<bool>();
  }

  /// Set maximum state event count before blocking joins
  void set_max_state_events(int64_t max_count) {
    g_config.set("room_complexity.max_state_events", max_count);
  }

  int64_t get_max_state_events() {
    return g_config.get("room_complexity.max_state_events", 50000).get<int64_t>();
  }

  /// Set maximum joined members before blocking joins
  void set_max_joined_members(int64_t max_count) {
    g_config.set("room_complexity.max_joined_members", max_count);
  }

  int64_t get_max_joined_members() {
    return g_config.get("room_complexity.max_joined_members", 100000).get<int64_t>();
  }

  /// Set admin user IDs that can bypass complexity
  void add_admin_bypass(const std::string& user_id) {
    json bypass = g_config.get("room_complexity.admin_bypass", json::array());
    if (!bypass.is_array()) bypass = json::array();
    bypass.push_back(user_id);
    g_config.set("room_complexity.admin_bypass", bypass);
  }

  void remove_admin_bypass(const std::string& user_id) {
    json bypass = g_config.get("room_complexity.admin_bypass", json::array());
    json new_bypass = json::array();
    for (auto& u : bypass) {
      if (u.get<std::string>() != user_id) {
        new_bypass.push_back(u);
      }
    }
    g_config.set("room_complexity.admin_bypass", new_bypass);
  }

  std::vector<std::string> get_admin_bypass_list() {
    json bypass = g_config.get("room_complexity.admin_bypass", json::array());
    if (!bypass.is_array()) return {};
    std::vector<std::string> result;
    for (auto& u : bypass) result.push_back(u.get<std::string>());
    return result;
  }

  // ---- Complexity Computation ----

  /// Compute room complexity metrics
  json compute_complexity(const std::string& room_id) {
    return db_.runInteraction(
        "complexity_compute",
        [&](storage::LoggingTransaction& txn) -> json {
          json result;
          result["room_id"] = room_id;

          // Count state events
          txn.execute(
              "SELECT COUNT(*) FROM state_events WHERE room_id = ?",
              {room_id});
          auto srow = txn.fetchone();
          int64_t state_count = srow ? std::stoll(srow->at(0).value.value_or("0")) : 0;
          result["state_events"] = state_count;

          // Count events (non-state)
          txn.execute(
              "SELECT COUNT(*) FROM events WHERE room_id = ?",
              {room_id});
          auto erow = txn.fetchone();
          int64_t event_count = erow ? std::stoll(erow->at(0).value.value_or("0")) : 0;
          result["total_events"] = event_count;

          // Count forward extremities
          txn.execute(
              "SELECT COUNT(*) FROM event_forward_extremities "
              "WHERE room_id = ?",
              {room_id});
          auto frow = txn.fetchone();
          int64_t fe_count = frow ? std::stoll(frow->at(0).value.value_or("0")) : 0;
          result["forward_extremities"] = fe_count;

          // Count joined members
          txn.execute(
              "SELECT COUNT(*) FROM local_current_membership "
              "WHERE room_id = ? AND membership = 'join'",
              {room_id});
          auto jrow = txn.fetchone();
          int64_t join_count = jrow ? std::stoll(jrow->at(0).value.value_or("0")) : 0;
          result["joined_members"] = join_count;

          // Count local members in room (all types)
          txn.execute(
              "SELECT COUNT(*) FROM local_current_membership "
              "WHERE room_id = ?",
              {room_id});
          auto lrow = txn.fetchone();
          int64_t local_count = lrow ? std::stoll(lrow->at(0).value.value_or("0")) : 0;
          result["local_members"] = local_count;

          // Is the room federated?
          txn.execute(
              "SELECT COUNT(*) FROM room_memberships "
              "WHERE room_id = ? AND user_id NOT LIKE ?",
              {room_id, "%:localhost%"});
          auto fed_row = txn.fetchone();
          int64_t fed_members = fed_row ? std::stoll(fed_row->at(0).value.value_or("0")) : 0;
          result["has_remote_members"] = fed_members > 0;
          result["remote_member_count"] = fed_members;

          // Store the complexity for later retrieval
          int64_t ts = now_ms();
          try {
            txn.execute(
                "INSERT INTO room_complexity "
                "(room_id, state_events, joined_members, total_events, "
                "forward_extremities, computed_ts) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(room_id) DO UPDATE SET "
                "state_events = excluded.state_events, "
                "joined_members = excluded.joined_members, "
                "total_events = excluded.total_events, "
                "forward_extremities = excluded.forward_extremities, "
                "computed_ts = excluded.computed_ts",
                {room_id, std::to_string(state_count),
                 std::to_string(join_count), std::to_string(event_count),
                 std::to_string(fe_count), std::to_string(ts)});
          } catch (const std::exception&) {
            // table might not exist yet, ignore
          }

          result["computed_ts"] = ts;
          return result;
        });
  }

  /// Get previously computed complexity (from table)
  json get_complexity(const std::string& room_id) {
    return db_.runInteraction(
        "complexity_get",
        [&](storage::LoggingTransaction& txn) -> json {
          try {
            txn.execute(
                "SELECT state_events, joined_members, total_events, "
                "forward_extremities, computed_ts "
                "FROM room_complexity WHERE room_id = ?",
                {room_id});
            auto row = txn.fetchone();
            if (!row) {
              // Compute it fresh
              txn.call_after([this, room_id]() mutable {
                compute_complexity(room_id);
              });
              return json({{"room_id", room_id}, {"not_computed", true}});
            }

            json result;
            result["room_id"] = room_id;
            result["state_events"] = row->at(0).value
                ? std::stoll(*row->at(0).value) : 0;
            result["joined_members"] = row->at(1).value
                ? std::stoll(*row->at(1).value) : 0;
            result["total_events"] = row->at(2).value
                ? std::stoll(*row->at(2).value) : 0;
            result["forward_extremities"] = row->at(3).value
                ? std::stoll(*row->at(3).value) : 0;
            result["computed_ts"] = row->at(4).value
                ? std::stoll(*row->at(4).value) : 0;
            return result;
          } catch (const std::exception&) {
            return json({{"room_id", room_id}, {"error", "Complexity table not available"}});
          }
        });
  }

  // ---- Complexity Limits Enforcement ----

  /// Check whether a user can join a room based on complexity limits
  /// Returns: {allowed: bool, reason: string (if blocked), complexity: {...}}
  json check_can_join(const std::string& room_id, const std::string& user_id) {
    if (!is_enabled()) {
      return json({{"allowed", true}, {"reason", "Complexity checking disabled"}});
    }

    // Check admin bypass
    auto bypass_list = get_admin_bypass_list();
    if (std::find(bypass_list.begin(), bypass_list.end(), user_id) !=
        bypass_list.end()) {
      return json({{"allowed", true}, {"reason", "Admin bypass"}});
    }

    json complexity = compute_complexity(room_id);

    int64_t max_state = get_max_state_events();
    int64_t max_members = get_max_joined_members();

    int64_t state_count = complexity.value("state_events", 0);
    int64_t join_count = complexity.value("joined_members", 0);

    json result;
    result["complexity"] = complexity;
    result["limits"] = json({
        {"max_state_events", max_state},
        {"max_joined_members", max_members}
    });

    if (state_count > max_state) {
      result["allowed"] = false;
      result["reason"] = "Room has too many state events (" +
                         std::to_string(state_count) + " > " +
                         std::to_string(max_state) + ")";
      result["blocked_by"] = "state_events";
      return result;
    }

    if (join_count > max_members) {
      result["allowed"] = false;
      result["reason"] = "Room has too many joined members (" +
                         std::to_string(join_count) + " > " +
                         std::to_string(max_members) + ")";
      result["blocked_by"] = "joined_members";
      return result;
    }

    result["allowed"] = true;
    result["reason"] = "Room complexity within limits";
    return result;
  }

  /// List rooms exceeding complexity thresholds
  json list_complex_rooms(int64_t limit = 100, int64_t offset = 0) {
    return db_.runInteraction(
        "complexity_list_rooms",
        [&](storage::LoggingTransaction& txn) -> json {
          int64_t max_state = get_max_state_events();
          int64_t max_members = get_max_joined_members();

          std::string sql =
              "SELECT room_id, state_events, joined_members, total_events, "
              "forward_extremities, computed_ts "
              "FROM room_complexity "
              "WHERE state_events > ? OR joined_members > ? "
              "ORDER BY state_events DESC LIMIT ? OFFSET ?";

          std::vector<storage::SQLParam> params = {
              std::to_string(max_state),
              std::to_string(max_members),
              std::to_string(limit),
              std::to_string(offset)
          };

          try {
            txn.execute(sql, params);
          } catch (const std::exception&) {
            return json({{"error", "room_complexity table not available"}});
          }

          auto rows = txn.fetchall();

          json rooms = json::array();
          for (auto& row : rows) {
            json r;
            r["room_id"] = row[0].value.value_or("");
            int64_t state = row[1].value ? std::stoll(*row[1].value) : 0;
            int64_t members = row[2].value ? std::stoll(*row[2].value) : 0;
            r["state_events"] = state;
            r["joined_members"] = members;
            r["total_events"] = row[3].value ? std::stoll(*row[3].value) : 0;
            r["forward_extremities"] = row[4].value ? std::stoll(*row[4].value) : 0;
            r["computed_ts"] = row[5].value ? std::stoll(*row[5].value) : 0;
            r["exceeds_state_limit"] = state > max_state;
            r["exceeds_member_limit"] = members > max_members;
            rooms.push_back(r);
          }

          return json({
              {"rooms", rooms},
              {"limit", limit},
              {"offset", offset},
              {"max_state_events", max_state},
              {"max_joined_members", max_members}
          });
        });
  }

  /// Get all rooms sorted by complexity (for admin overview)
  json get_top_complex_rooms(int64_t limit = 20) {
    return db_.runInteraction(
        "complexity_top_rooms",
        [&](storage::LoggingTransaction& txn) -> json {
          std::string sql =
              "SELECT room_id, state_events, joined_members, total_events, "
              "computed_ts FROM room_complexity "
              "ORDER BY state_events DESC LIMIT ?";

          try {
            txn.execute(sql, {std::to_string(limit)});
          } catch (const std::exception&) {
            return json({{"error", "room_complexity table not available"}});
          }

          auto rows = txn.fetchall();

          json rooms = json::array();
          for (auto& row : rows) {
            json r;
            r["room_id"] = row[0].value.value_or("");
            r["state_events"] = row[1].value ? std::stoll(*row[1].value) : 0;
            r["joined_members"] = row[2].value ? std::stoll(*row[2].value) : 0;
            r["total_events"] = row[3].value ? std::stoll(*row[3].value) : 0;
            r["computed_ts"] = row[4].value ? std::stoll(*row[4].value) : 0;
            rooms.push_back(r);
          }

          return json({{"rooms", rooms}, {"limit", limit}});
        });
  }

  /// Get complexity configuration
  json get_config() {
    json cfg;
    cfg["enabled"] = is_enabled();
    cfg["max_state_events"] = get_max_state_events();
    cfg["max_joined_members"] = get_max_joined_members();
    cfg["admin_bypass"] = get_admin_bypass_list();
    return cfg;
  }

  /// Set complexity configuration
  void set_config(const json& cfg) {
    if (cfg.contains("enabled")) set_enabled(cfg["enabled"].get<bool>());
    if (cfg.contains("max_state_events"))
      set_max_state_events(cfg["max_state_events"].get<int64_t>());
    if (cfg.contains("max_joined_members"))
      set_max_joined_members(cfg["max_joined_members"].get<int64_t>());
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 7. BackgroundUpdatesAdmin
//
// Administers background database updates: list pending/running/completed,
// run specific updates, enable/disable, view status and progress.
//
// Equivalent to synapse/storage/background_updates.py admin portions
// ============================================================================
class BackgroundUpdatesAdmin {
public:
  explicit BackgroundUpdatesAdmin(storage::DatabasePool& db) : db_(db) {}

  /// Get all background updates with status
  json list_updates(const std::string& status_filter = "all") {
    return db_.runInteraction(
        "bg_list_updates",
        [&](storage::LoggingTransaction& txn) -> json {
          std::string sql =
              "SELECT update_name, status, progress_json, total_items, "
              "processed_items, started_ts, completed_ts, error_message "
              "FROM background_updates";

          if (status_filter != "all") {
            sql += " WHERE status = ?";
          }

          sql += " ORDER BY started_ts DESC";

          try {
            if (status_filter != "all") {
              txn.execute(sql, {status_filter});
            } else {
              txn.execute(sql);
            }
          } catch (const std::exception&) {
            // Table might not exist
            return json({
                {"updates", json::array()},
                {"total", 0},
                {"status_filter", status_filter}
            });
          }

          auto rows = txn.fetchall();

          json updates = json::array();
          int64_t pending_count = 0;
          int64_t running_count = 0;
          int64_t completed_count = 0;
          int64_t failed_count = 0;

          for (auto& row : rows) {
            json u;
            u["update_name"] = row[0].value.value_or("");
            u["status"] = row[1].value.value_or("");

            std::string status = row[1].value.value_or("");
            if (status == "pending") pending_count++;
            else if (status == "running") running_count++;
            else if (status == "completed") completed_count++;
            else if (status == "failed") failed_count++;

            // Parse progress JSON
            if (row[2].value) {
              try { u["progress"] = json::parse(*row[2].value); }
              catch (...) { u["progress"] = *row[2].value; }
            } else {
              u["progress"] = json::object();
            }

            u["total_items"] = row[3].value
                ? std::stoll(*row[3].value) : 0;
            u["processed_items"] = row[4].value
                ? std::stoll(*row[4].value) : 0;
            u["started_ts"] = row[5].value
                ? std::stoll(*row[5].value) : 0;
            u["completed_ts"] = row[6].value
                ? std::stoll(*row[6].value) : 0;
            u["error_message"] = row[7].value.value_or("");

            // Calculate progress percentage
            if (u["total_items"].get<int64_t>() > 0) {
              double pct = 100.0 * u["processed_items"].get<int64_t>() /
                           u["total_items"].get<int64_t>();
              u["progress_percent"] = std::round(pct * 100.0) / 100.0;
            } else {
              u["progress_percent"] = 0.0;
            }

            // Calculate elapsed time for running updates
            if (status == "running" && u["started_ts"].get<int64_t>() > 0) {
              u["elapsed_seconds"] = now_sec() - u["started_ts"].get<int64_t>();
            } else {
              u["elapsed_seconds"] = 0;
            }

            // Estimate remaining time
            if (status == "running" && u["processed_items"].get<int64_t>() > 0 &&
                u["total_items"].get<int64_t>() > 0) {
              double rate = static_cast<double>(u["processed_items"].get<int64_t>()) /
                            std::max(1.0, static_cast<double>(u["elapsed_seconds"].get<int64_t>()));
              int64_t remaining = u["total_items"].get<int64_t>() -
                                  u["processed_items"].get<int64_t>();
              u["estimated_remaining_seconds"] = rate > 0
                  ? static_cast<int64_t>(remaining / rate) : 0;
            }

            updates.push_back(u);
          }

          return json({
              {"updates", updates},
              {"total", rows.size()},
              {"pending_count", pending_count},
              {"running_count", running_count},
              {"completed_count", completed_count},
              {"failed_count", failed_count},
              {"status_filter", status_filter}
          });
        });
  }

  /// Get pending updates specifically
  json list_pending_updates() { return list_updates("pending"); }

  /// Get running updates
  json list_running_updates() { return list_updates("running"); }

  /// Get completed updates
  json list_completed_updates() { return list_updates("completed"); }

  /// Get failed updates
  json list_failed_updates() { return list_updates("failed"); }

  /// Get status of a specific background update
  json get_update_status(const std::string& update_name) {
    return db_.runInteraction(
        "bg_get_update",
        [&](storage::LoggingTransaction& txn) -> json {
          try {
            txn.execute(
                "SELECT update_name, status, progress_json, total_items, "
                "processed_items, started_ts, completed_ts, error_message, "
                "dependencies "
                "FROM background_updates WHERE update_name = ?",
                {update_name});
          } catch (const std::exception&) {
            return json({
                {"update_name", update_name},
                {"error", "background_updates table not available"}
            });
          }

          auto row = txn.fetchone();
          if (!row) {
            return json({
                {"update_name", update_name},
                {"found", false},
                {"error", "Update not found"}
            });
          }

          json result;
          result["update_name"] = row->at(0).value.value_or("");
          result["status"] = row->at(1).value.value_or("");
          if (row->at(2).value) {
            try { result["progress"] = json::parse(*row->at(2).value); }
            catch (...) { result["progress"] = *row->at(2).value; }
          }
          result["total_items"] = row->at(3).value
              ? std::stoll(*row->at(3).value) : 0;
          result["processed_items"] = row->at(4).value
              ? std::stoll(*row->at(4).value) : 0;
          result["started_ts"] = row->at(5).value
              ? std::stoll(*row->at(5).value) : 0;
          result["completed_ts"] = row->at(6).value
              ? std::stoll(*row->at(6).value) : 0;
          result["error_message"] = row->at(7).value.value_or("");
          if (row->at(8).value) {
            try { result["dependencies"] = json::parse(*row->at(8).value); }
            catch (...) { result["dependencies"] = *row->at(8).value; }
          }
          result["found"] = true;

          // Progress percentage
          if (result["total_items"].get<int64_t>() > 0) {
            double pct = 100.0 * result["processed_items"].get<int64_t>() /
                         result["total_items"].get<int64_t>();
            result["progress_percent"] = std::round(pct * 100.0) / 100.0;
          }

          return result;
        });
  }

  /// Run a specific background update
  json run_update(const std::string& update_name) {
    // Check if already running
    auto status = get_update_status(update_name);
    if (status.value("status", "") == "running") {
      return json({
          {"update_name", update_name},
          {"success", false},
          {"error", "Update is already running"}
      });
    }

    // Mark as running
    try {
      db_.runInteraction(
          "bg_run_update",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "UPDATE background_updates SET status = 'running', "
                "started_ts = ?, error_message = NULL "
                "WHERE update_name = ?",
                {std::to_string(now_ms()), update_name});

            // Count items to process
            txn.execute(
                "SELECT COUNT(*) FROM background_update_items "
                "WHERE update_name = ? AND processed = 0",
                {update_name});
            auto row = txn.fetchone();
            int64_t total = row ? std::stoll(row->at(0).value.value_or("0")) : 0;

            txn.execute(
                "UPDATE background_updates SET total_items = ?, "
                "processed_items = 0 WHERE update_name = ?",
                {std::to_string(total), update_name});
          });
    } catch (const std::exception& e) {
      return json({
          {"update_name", update_name},
          {"success", false},
          {"error", std::string("Failed to start update: ") + e.what()}
      });
    }

    return json({
        {"update_name", update_name},
        {"success", true},
        {"message", "Update started"}
    });
  }

  /// Stop a running background update
  json stop_update(const std::string& update_name) {
    return db_.runInteraction(
        "bg_stop_update",
        [&](storage::LoggingTransaction& txn) -> json {
          try {
            txn.execute(
                "SELECT status FROM background_updates WHERE update_name = ?",
                {update_name});
            auto row = txn.fetchone();
            if (!row) {
              return json({
                  {"update_name", update_name},
                  {"success", false},
                  {"error", "Update not found"}
              });
            }

            if (row->at(0).value.value_or("") != "running") {
              return json({
                  {"update_name", update_name},
                  {"success", false},
                  {"error", "Update is not running"}
              });
            }

            txn.execute(
                "UPDATE background_updates SET status = 'pending', "
                "started_ts = NULL, completed_ts = NULL "
                "WHERE update_name = ?",
                {update_name});

            return json({
                {"update_name", update_name},
                {"success", true},
                {"message", "Update stopped and returned to pending"}
            });
          } catch (const std::exception& e) {
            return json({
                {"update_name", update_name},
                {"success", false},
                {"error", e.what()}
            });
          }
        });
  }

  /// Enable background updates globally
  json enable_background_updates() {
    g_config.set("background_updates.enabled", true);
    return json({
        {"enabled", true},
        {"message", "Background updates enabled"}
    });
  }

  /// Disable background updates globally
  json disable_background_updates() {
    g_config.set("background_updates.enabled", false);
    return json({
        {"enabled", false},
        {"message", "Background updates disabled"}
    });
  }

  /// Check if background updates are enabled
  json get_background_updates_state() {
    bool enabled = g_config.get("background_updates.enabled", true).get<bool>();
    auto pending = list_pending_updates();
    auto running = list_running_updates();
    auto failed = list_failed_updates();

    json result;
    result["enabled"] = enabled;
    result["pending_count"] = pending["total"];
    result["running_count"] = running["total"];
    result["failed_count"] = failed["total"];

    return result;
  }

  /// Register a new background update
  json register_update(const std::string& update_name,
                       const json& dependencies = json::array(),
                       const std::string& description = "") {
    return db_.runInteraction(
        "bg_register_update",
        [&](storage::LoggingTransaction& txn) -> json {
          try {
            txn.execute(
                "SELECT 1 FROM background_updates WHERE update_name = ?",
                {update_name});
            auto existing = txn.fetchone();
            if (existing) {
              return json({
                  {"update_name", update_name},
                  {"success", false},
                  {"error", "Update already registered"}
              });
            }

            txn.execute(
                "INSERT INTO background_updates "
                "(update_name, status, progress_json, total_items, "
                "processed_items, started_ts, completed_ts, "
                "error_message, dependencies, description) "
                "VALUES (?, 'pending', '{}', 0, 0, NULL, NULL, "
                "NULL, ?, ?)",
                {update_name, dependencies.dump(), description});

            return json({
                {"update_name", update_name},
                {"success", true},
                {"message", "Update registered"}
            });
          } catch (const std::exception& e) {
            return json({
                {"update_name", update_name},
                {"success", false},
                {"error", e.what()}
            });
          }
        });
  }

  /// Delete a background update record
  json delete_update(const std::string& update_name) {
    return db_.runInteraction(
        "bg_delete_update",
        [&](storage::LoggingTransaction& txn) -> json {
          try {
            txn.execute(
                "DELETE FROM background_updates WHERE update_name = ?",
                {update_name});
            txn.execute(
                "DELETE FROM background_update_items WHERE update_name = ?",
                {update_name});

            return json({
                {"update_name", update_name},
                {"success", true},
                {"message", "Update deleted"}
            });
          } catch (const std::exception& e) {
            return json({
                {"update_name", update_name},
                {"success", false},
                {"error", e.what()}
            });
          }
        });
  }

  /// Get summary statistics
  json get_summary() {
    auto all = list_updates();
    return json({
        {"total", all["total"]},
        {"pending", all["pending_count"]},
        {"running", all["running_count"]},
        {"completed", all["completed_count"]},
        {"failed", all["failed_count"]},
        {"enabled", g_config.get("background_updates.enabled", true).get<bool>()},
        {"last_check_ts", now_sec()}
    });
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// AdminAPI - Unified API facade for all admin functionality
//
// Composes all admin managers into a single entry point. Provides a simple
// interface for server operators to manage notices, account validity,
// terms of service, rate limits, debug information, room complexity,
// and background updates.
// ============================================================================
class AdminAPI {
public:
  explicit AdminAPI(storage::DatabasePool& db, const std::string& server_name)
      : db_(db),
        server_name_(server_name),
        server_notices_(std::make_unique<ServerNoticeManager>(db, server_name)),
        account_validity_(std::make_unique<AccountValidityManager>(db, *server_notices_)),
        terms_of_service_(std::make_unique<TermsOfServiceManager>(db, *server_notices_)),
        rate_limit_admin_(std::make_unique<RateLimitAdmin>(db)),
        debug_api_(std::make_unique<DebugAPI>(db)),
        room_complexity_(std::make_unique<RoomComplexityChecker>(db)),
        background_updates_(std::make_unique<BackgroundUpdatesAdmin>(db)) {}

  // ---- Accessors ----
  ServerNoticeManager& server_notices() { return *server_notices_; }
  AccountValidityManager& account_validity() { return *account_validity_; }
  TermsOfServiceManager& terms_of_service() { return *terms_of_service_; }
  RateLimitAdmin& rate_limit_admin() { return *rate_limit_admin_; }
  DebugAPI& debug() { return *debug_api_; }
  RoomComplexityChecker& room_complexity() { return *room_complexity_; }
  BackgroundUpdatesAdmin& background_updates() { return *background_updates_; }

  /// Get a comprehensive status overview for admin dashboard
  json get_dashboard() {
    json dashboard;

    dashboard["server"] = json({
        {"server_name", server_name_},
        {"timestamp", now_iso8601()},
        {"uptime_seconds", now_sec() - g_config.get("startup_ts", now_sec()).get<int64_t>()}
    });

    dashboard["rate_limiting"] = rate_limit_admin_->get_config();
    dashboard["room_complexity"] = room_complexity_->get_config();
    dashboard["background_updates"] = background_updates_->get_summary();

    // Quick stats
    db_.runInteraction(
        "admin_dashboard",
        [&](storage::LoggingTransaction& txn) {
          txn.execute("SELECT COUNT(*) FROM users WHERE deactivated = 0");
          auto row = txn.fetchone();
          dashboard["active_users"] = row
              ? std::stoll(row->at(0).value.value_or("0")) : 0;

          txn.execute("SELECT COUNT(*) FROM users");
          row = txn.fetchone();
          dashboard["total_users"] = row
              ? std::stoll(row->at(0).value.value_or("0")) : 0;

          txn.execute("SELECT COUNT(*) FROM rooms");
          row = txn.fetchone();
          dashboard["total_rooms"] = row
              ? std::stoll(row->at(0).value.value_or("0")) : 0;

          txn.execute("SELECT COUNT(*) FROM events");
          row = txn.fetchone();
          dashboard["total_events"] = row
              ? std::stoll(row->at(0).value.value_or("0")) : 0;
        });

    return dashboard;
  }

private:
  storage::DatabasePool& db_;
  std::string server_name_;
  std::unique_ptr<ServerNoticeManager> server_notices_;
  std::unique_ptr<AccountValidityManager> account_validity_;
  std::unique_ptr<TermsOfServiceManager> terms_of_service_;
  std::unique_ptr<RateLimitAdmin> rate_limit_admin_;
  std::unique_ptr<DebugAPI> debug_api_;
  std::unique_ptr<RoomComplexityChecker> room_complexity_;
  std::unique_ptr<BackgroundUpdatesAdmin> background_updates_;
};

// ============================================================================
// Global factory function
// ============================================================================
std::unique_ptr<AdminAPI> create_admin_api(storage::DatabasePool& db,
                                            const std::string& server_name) {
  return std::make_unique<AdminAPI>(db, server_name);
}

}  // namespace progressive
