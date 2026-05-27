// ============================================================================
// admin_users.cpp — Matrix Admin User Management
//
// Implements the full Synapse-compatible Admin User API:
//   - GET  /_synapse/admin/v2/users                  (list users)
//   - POST /_synapse/admin/v2/users                  (create user)
//   - GET  /_synapse/admin/v2/users/<user_id>        (user info)
//   - PUT  /_synapse/admin/v2/users/<user_id>        (update user)
//   - POST /_synapse/admin/v1/reset_password/<user_id>
//   - POST /_synapse/admin/v1/deactivate/<user_id>
//   - POST /_synapse/admin/v1/reactivate/<user_id>
//   - GET  /_synapse/admin/v2/users/<user_id>/devices
//   - GET  /_synapse/admin/v2/users/<user_id>/devices/<device_id>
//   - DEL  /_synapse/admin/v2/users/<user_id>/devices
//   - DEL  /_synapse/admin/v2/users/<user_id>/devices/<device_id>
//   - PUT  /_synapse/admin/v2/users/<user_id>/devices/<device_id>
//   - GET  /_synapse/admin/v2/users/<user_id>/rooms
//   - GET  /_synapse/admin/v2/users/<user_id>/media
//   - DEL  /_synapse/admin/v2/users/<user_id>/media
//   - DEL  /_synapse/admin/v2/users/<user_id>/media/<media_id>
//   - GET  /_synapse/admin/v2/users/<user_id>/pushers
//   - POST /_synapse/admin/v2/users/<user_id>/pushers
//   - DEL  /_synapse/admin/v2/users/<user_id>/pushers/<pusher_id>
//   - GET  /_synapse/admin/v2/users/<user_id>/connections
//   - GET  /_synapse/admin/v1/search/users             (admin search)
//   - POST /_synapse/admin/v1/export/<user_id>          (GDPR export)
//   - POST /_synapse/admin/v1/account_validity/<user_id>
//   - POST /_synapse/admin/v1/shadow_ban/<user_id>
//   - POST /_synapse/admin/v1/lock/<user_id>
//   - GET  /_synapse/admin/v2/users/<user_id>/pushers/<pusher_id>
//   - POST /_synapse/admin/v2/users/<user_id>/connections/revoke
//   - POST /_synapse/admin/v2/users/<user_id>/threepids
//   - DEL  /_synapse/admin/v2/users/<user_id>/threepids/<medium>/<address>
//
// Equivalent to:
//   synapse/rest/admin/users.py
//   synapse/handlers/admin.py
//   synapse/storage/databases/main/registration.py
//   synapse/handlers/device.py
//   synapse/handlers/push_rules.py
//   synapse/handlers/admin_media.py
//
// Target: 3000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
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

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/end_to_end_keys.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/push_rule.hpp"
#include "progressive/storage/databases/main/filtering.hpp"
#include "progressive/storage/databases/main/account_data.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class AdminUserDatabase;
class AdminUserQueryBuilder;
class AdminUserManager;
class AdminUserDeviceHandler;
class AdminUserRoomHandler;
class AdminUserMediaHandler;
class AdminUserPusherHandler;
class AdminUserConnectionHandler;
class AdminUserSearchEngine;
class AdminUserExporter;
class AdminUserAccountValidity;
class AdminUserSecurityManager;
class AdminUsersAPI;

// ============================================================================
// Enums and Constants
// ============================================================================

enum class AdminUserSortField : uint8_t {
  NAME          = 0,
  CREATION_TS   = 1,
  LAST_SEEN_TS  = 2,
  USER_TYPE     = 3,
  ADMIN         = 4,
  DEACTIVATED   = 5,
  LOCKED        = 6,
  SHADOW_BANNED = 7,
  DISPLAY_NAME  = 8,
  MEDIA_COUNT   = 9,
  ROOM_COUNT    = 10,
  DEVICE_COUNT  = 11
};

enum class AdminUserFilterOp : uint8_t {
  EQUALS        = 0,
  NOT_EQUALS    = 1,
  CONTAINS      = 2,
  STARTS_WITH   = 3,
  ENDS_WITH     = 4,
  GREATER_THAN  = 5,
  LESS_THAN     = 6,
  IN            = 7,
  BETWEEN       = 8
};

enum class UserConnectionType : uint8_t {
  LOGIN         = 0,
  LOGOUT        = 1,
  REFRESH       = 2,
  SSO           = 3,
  OAUTH2        = 4,
  TOKEN_EXPIRED = 5,
  REVOKED       = 6,
  PASSWORD_CHANGE = 7,
  DEACTIVATION  = 8,
  REACTIVATION  = 9,
  LOCK          = 10,
  UNLOCK        = 11,
  SUSPENSION    = 12,
  UNSUSPENSION  = 13
};

enum class PusherKind : uint8_t {
  HTTP    = 0,
  EMAIL   = 1,
  SMS     = 2,
  WEBHOOK = 3,
  APNS    = 4,
  FCM     = 5
};

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// ---- Server identification constants ----
constexpr const char* kServerName    = "Progressive";
constexpr const char* kServerVersion = "0.11.0";
constexpr const char* kAdminAPIVer   = "2.0";

// ---- Pagination constants ----
constexpr int64_t kDefaultLimit  = 100;
constexpr int64_t kMaxLimit      = 1000;
constexpr int64_t kMaxSearchResults = 500;

// ---- Timing constants (milliseconds) ----
constexpr int64_t kOneSecondMs = 1000;
constexpr int64_t kOneMinuteMs = 60000;
constexpr int64_t kOneHourMs   = 3600000;
constexpr int64_t kOneDayMs    = 86400000;
constexpr int64_t kOneWeekMs   = 604800000;

// ---- Password constants ----
constexpr int    kMinPasswordLength = 8;
constexpr int    kMaxPasswordLength = 512;
constexpr int    kPasswordHashRounds = 12;

// ---- User constraints ----
constexpr int    kMaxUsernameLength    = 255;
constexpr int    kMaxDisplayNameLength = 256;
constexpr int    kMaxDevicesPerUser    = 500;
constexpr int    kMaxSessionsPerUser   = 100;
constexpr int    kMaxThreepidsPerUser  = 50;
constexpr int    kMaxPushersPerUser    = 100;
constexpr int    kMaxMediaPerQuery     = 500;
constexpr int    kMaxConnectionsPerQuery = 500;
constexpr int    kMaxExportBatchSize   = 1000;

// ---- Guest / default user type ----
constexpr const char* kDefaultUserType = "user";
constexpr const char* kGuestUserType   = "guest";
constexpr const char* kBotUserType     = "bot";
constexpr const char* kSupportUserType = "support";

// ---- SQL-safe characters for LIKE patterns ----
const std::string kLikeEscapeChars = "%_\\";

// ---- Allowed username characters (ASCII subset) ----
const std::string kAllowedUsernameChars =
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "._=-/";

// ==========================================================================
// Timestamp helpers
// ==========================================================================

inline int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

inline int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
      chr::system_clock::now().time_since_epoch())
      .count();
}

inline std::string now_iso8601() {
  char buf[32];
  auto t = std::time(nullptr);
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

inline std::string ts_to_iso8601(int64_t ms) {
  char buf[32];
  auto t = static_cast<std::time_t>(ms / 1000);
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

inline std::string ts_sec_to_iso8601(int64_t sec) {
  char buf[32];
  auto t = static_cast<std::time_t>(sec);
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return buf;
}

inline int64_t ms_to_days(int64_t ms) {
  return ms / kOneDayMs;
}

inline int64_t sec_to_days(int64_t sec) {
  return sec / 86400;
}

// ==========================================================================
// String helpers
// ==========================================================================

inline bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

inline bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

inline bool contains(const std::string& s, const std::string& substr) {
  return s.find(substr) != std::string::npos;
}

inline std::string to_lower(const std::string& s) {
  std::string r = s;
  for (auto& c : r)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return r;
}

inline std::string to_upper(const std::string& s) {
  std::string r = s;
  for (auto& c : r)
    c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  return r;
}

inline std::string trim(const std::string& s) {
  auto start = s.find_first_not_of(" \t\r\n");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\r\n");
  return s.substr(start, end - start + 1);
}

inline std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> result;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    if (!item.empty()) result.push_back(trim(item));
  }
  return result;
}

inline std::string join(const std::vector<std::string>& parts,
                         const std::string& delim) {
  std::string result;
  for (size_t i = 0; i < parts.size(); i++) {
    if (i > 0) result += delim;
    result += parts[i];
  }
  return result;
}

// ==========================================================================
// Token / ID generation
// ==========================================================================

inline std::string generate_token(int length = 64) {
  static const char cs[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(0, 63);
  std::string tok(length, 'A');
  for (auto& c : tok) c = cs[dist(gen)];
  return tok;
}

inline std::string generate_uuid_v4() {
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(0, 15);
  const char* hex = "0123456789abcdef";
  std::string uuid(36, '-');
  for (int i = 0; i < 36; ++i) {
    if (i == 8 || i == 13 || i == 18 || i == 23) continue;
    if (i == 14) {
      uuid[i] = '4';
    } else if (i == 19) {
      uuid[i] = hex[(dist(gen) & 0x3) | 0x8];
    } else {
      uuid[i] = hex[dist(gen)];
    }
  }
  return uuid;
}

inline std::string generate_device_id() {
  static const char cs[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dist(0, 61);
  std::string id(10, 'A');
  for (auto& c : id) c = cs[dist(gen)];
  return id;
}

// ==========================================================================
// Validation helpers
// ==========================================================================

inline bool is_valid_user_id(const std::string& uid) {
  if (uid.empty() || uid[0] != '@') return false;
  auto colon = uid.find(':');
  return colon != std::string::npos && colon > 1 && colon < uid.size() - 1;
}

inline bool is_valid_room_id(const std::string& rid) {
  if (rid.empty() || rid[0] != '!') return false;
  auto colon = rid.find(':');
  return colon != std::string::npos && colon > 1 && colon < rid.size() - 1;
}

inline bool is_valid_event_id(const std::string& evid) {
  if (evid.empty() || evid[0] != '$') return false;
  auto colon = evid.find(':');
  return colon != std::string::npos && colon > 1 && colon < evid.size() - 1;
}

inline std::string server_name_from_id(const std::string& id) {
  auto colon = id.find(':');
  if (colon == std::string::npos) return "";
  return id.substr(colon + 1);
}

inline std::string localpart_from_user_id(const std::string& uid) {
  if (!is_valid_user_id(uid)) return uid;
  return uid.substr(1, uid.find(':') - 1);
}

inline bool is_valid_localpart(const std::string& lp) {
  if (lp.empty() || lp.size() > kMaxUsernameLength) return false;
  for (char c : lp) {
    if (kAllowedUsernameChars.find(c) == std::string::npos) return false;
  }
  // Cannot start with underscore (used for special users)
  if (lp[0] == '_') return false;
  return true;
}

inline bool is_valid_display_name(const std::string& dn) {
  return dn.size() <= kMaxDisplayNameLength;
}

inline bool is_valid_password(const std::string& pwd) {
  if (pwd.size() < kMinPasswordLength) return false;
  if (pwd.size() > kMaxPasswordLength) return false;
  // Must have at least one of each: lowercase, uppercase, digit, special
  bool has_lower = false, has_upper = false, has_digit = false, has_special = false;
  for (char c : pwd) {
    if (std::islower(static_cast<unsigned char>(c))) has_lower = true;
    else if (std::isupper(static_cast<unsigned char>(c))) has_upper = true;
    else if (std::isdigit(static_cast<unsigned char>(c))) has_digit = true;
    else has_special = true;
  }
  // At least 3 out of 4 character classes
  int classes = (has_lower ? 1 : 0) + (has_upper ? 1 : 0) +
                (has_digit ? 1 : 0) + (has_special ? 1 : 0);
  return classes >= 3;
}

inline bool is_valid_email(const std::string& email) {
  if (email.size() > 320) return false;
  auto at = email.find('@');
  if (at == std::string::npos || at == 0 || at == email.size() - 1) return false;
  auto dot = email.find('.', at);
  return dot != std::string::npos && dot > at + 1 && dot < email.size() - 1;
}

inline bool is_valid_phone(const std::string& phone) {
  if (phone.size() > 32) return false;
  for (char c : phone) {
    if (!std::isdigit(static_cast<unsigned char>(c)) && c != '+' && c != '-' &&
        c != ' ' && c != '(' && c != ')')
      return false;
  }
  return phone.size() >= 7;
}

inline bool is_valid_url(const std::string& url) {
  return starts_with(to_lower(url), "http://") ||
         starts_with(to_lower(url), "https://") ||
         starts_with(to_lower(url), "mxc://");
}

// ==========================================================================
// Password hashing (bcrypt/scrypt placeholder)
// ==========================================================================

inline std::string hash_password(const std::string& password) {
  std::hash<std::string> hasher;
  size_t h = hasher(password + "progressive_admin_salt_v2");
  std::stringstream ss;
  ss << std::hex << std::setfill('0') << std::setw(16) << h;
  std::string result = ss.str();
  while (result.size() < 64) result = "0" + result;
  return "$2b$12$" + result;
}

inline bool verify_password(const std::string& password,
                             const std::string& hash) {
  return hash_password(password) == hash;
}

// ==========================================================================
// Human-readable formatting
// ==========================================================================

inline std::string format_bytes(int64_t bytes) {
  const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB"};
  int unit_idx = 0;
  double val = static_cast<double>(bytes);
  while (val >= 1024.0 && unit_idx < 5) {
    val /= 1024.0;
    unit_idx++;
  }
  std::stringstream ss;
  ss << std::fixed << std::setprecision(2) << val << " " << units[unit_idx];
  return ss.str();
}

inline std::string format_duration_sec(int64_t seconds) {
  if (seconds <= 0) return "0s";
  int64_t days    = seconds / 86400;
  int64_t hours   = (seconds % 86400) / 3600;
  int64_t minutes = (seconds % 3600) / 60;
  int64_t secs    = seconds % 60;
  std::stringstream ss;
  if (days > 0)    ss << days << "d ";
  if (hours > 0)   ss << hours << "h ";
  if (minutes > 0) ss << minutes << "m ";
  ss << secs << "s";
  return ss.str();
}

inline std::string format_number(int64_t n) {
  if (n < 1000) return std::to_string(n);
  std::stringstream ss;
  ss << std::fixed << std::setprecision(1);
  if (n < 1000000) ss << (n / 1000.0) << "K";
  else if (n < 1000000000) ss << (n / 1000000.0) << "M";
  else ss << (n / 1000000000.0) << "B";
  return ss.str();
}

// ==========================================================================
// SQL sanitization
// ==========================================================================

inline std::string sanitize_sql_like(const std::string& input) {
  std::string result;
  result.reserve(input.size() * 2);
  for (char c : input) {
    if (c == '%' || c == '_' || c == '\\') {
      result += '\\';
      result += c;
    } else if (c == '\'') {
      result += "''";
    } else {
      result += c;
    }
  }
  return result;
}

inline std::string sanitize_sql_ident(const std::string& input) {
  std::string result;
  result.reserve(input.size());
  for (char c : input) {
    if (std::isalnum(static_cast<unsigned char>(c)) || c == '_') {
      result += c;
    }
  }
  return result;
}

inline std::string sql_quote(const std::string& s) {
  std::string result = "'";
  for (char c : s) {
    if (c == '\'') result += "''";
    else if (c == '\\') result += "\\\\";
    else result += c;
  }
  result += "'";
  return result;
}

// ==========================================================================
// JSON response helpers
// ==========================================================================

inline json build_error(int code, const std::string& errcode,
                         const std::string& error) {
  return json{{"errcode", errcode}, {"error", error}};
}

inline json build_success(const std::string& message) {
  return json{{"success", true}, {"message", message}};
}

inline json build_paginated_response(const json& data, int64_t total,
                                      const std::string& next_token,
                                      int64_t offset, int64_t limit) {
  json r;
  r["results"]    = data;
  r["total"]      = total;
  r["next_token"] = next_token;
  r["offset"]     = offset;
  r["limit"]      = limit;
  return r;
}

// ==========================================================================
// SQL row parsing helpers
// ==========================================================================

inline std::string row_get_str(const Row& row, size_t idx,
                                const std::string& default_val = "") {
  if (idx < row.size()) {
    return row[idx].value.value_or(default_val);
  }
  return default_val;
}

inline int64_t row_get_int(const Row& row, size_t idx, int64_t default_val = 0) {
  if (idx < row.size() && row[idx].value.has_value()) {
    try { return std::stoll(row[idx].value.value()); }
    catch (...) { return default_val; }
  }
  return default_val;
}

inline double row_get_double(const Row& row, size_t idx, double default_val = 0.0) {
  if (idx < row.size() && row[idx].value.has_value()) {
    try { return std::stod(row[idx].value.value()); }
    catch (...) { return default_val; }
  }
  return default_val;
}

inline bool row_get_bool(const Row& row, size_t idx, bool default_val = false) {
  std::string s = row_get_str(row, idx, default_val ? "1" : "0");
  return s == "1" || s == "true" || s == "yes";
}

// ==========================================================================
// JSON field getters with type-safe defaults
// ==========================================================================

inline std::string json_get_str(const json& obj, const std::string& key,
                                 const std::string& default_val = "") {
  if (obj.contains(key) && obj[key].is_string()) {
    return obj[key].get<std::string>();
  }
  return default_val;
}

inline int64_t json_get_int(const json& obj, const std::string& key,
                             int64_t default_val = 0) {
  if (obj.contains(key) && obj[key].is_number()) {
    return obj[key].get<int64_t>();
  }
  return default_val;
}

inline bool json_get_bool(const json& obj, const std::string& key,
                           bool default_val = false) {
  if (obj.contains(key) && obj[key].is_boolean()) {
    return obj[key].get<bool>();
  }
  return default_val;
}

inline json json_get_array(const json& obj, const std::string& key) {
  if (obj.contains(key) && obj[key].is_array()) {
    return obj[key];
  }
  return json::array();
}

}  // anonymous namespace

// ============================================================================
// Internal Data Structures
// ============================================================================

// Comprehensive user record from database
struct AdminUserRecord {
  std::string user_id;
  std::string display_name;
  std::string avatar_url;
  std::string password_hash;
  std::string user_type;      // "user", "guest", "bot", "support"
  std::string appservice_id;
  std::string consent_version;
  std::string external_auth_provider;
  bool is_guest            = false;
  bool is_admin            = false;
  bool deactivated         = false;
  bool locked              = false;
  bool suspended           = false;
  bool shadow_banned       = false;
  bool consent_given       = false;
  bool consent_notice_sent = false;
  bool is_erased           = false;
  int64_t creation_ts      = 0;
  int64_t last_seen_ts     = 0;
  int64_t consent_ts       = 0;
  int64_t deactivation_ts  = 0;
  int64_t lock_ts          = 0;
  int64_t suspension_ts    = 0;
  int64_t suspension_end_ts = 0;
  int  failed_login_attempts = 0;
  std::string deactivation_reason;
  std::string suspension_reason;
  std::string lock_reason;
};

// Device information
struct AdminDeviceInfo {
  std::string device_id;
  std::string display_name;
  std::string device_type;
  std::string last_seen_ip;
  std::string user_agent;
  std::string access_token_hash;
  int64_t last_seen_ts       = 0;
  int64_t creation_ts        = 0;
  int64_t last_token_refresh = 0;
  bool hidden                = false;
  bool verified              = false;
  bool dehydrated             = false;
  int  session_count         = 0;
};

// Room membership information per user
struct AdminUserRoomInfo {
  std::string room_id;
  std::string room_name;
  std::string room_alias;
  std::string membership;    // "join", "invite", "leave", "ban", "knock"
  std::string room_type;     // "room", "space"
  std::string sender;        // Who set this membership
  std::string join_rules;
  std::string guest_access;
  std::string history_visibility;
  int64_t membership_ts        = 0;
  int64_t creation_ts          = 0;
  int64_t last_activity_ts     = 0;
  int64_t joined_members       = 0;
  int64_t invited_members      = 0;
  int64_t total_events         = 0;
  bool is_encrypted            = false;
  bool is_public               = false;
  bool is_federatable          = true;
  bool is_direct               = false;
  std::string room_version;
};

// Media information per user
struct AdminUserMediaInfo {
  std::string media_id;
  std::string media_type;    // MIME type
  std::string upload_name;
  std::string origin_server;
  int64_t media_length       = 0;
  int64_t created_ts         = 0;
  int64_t last_access_ts     = 0;
  int64_t access_count       = 0;
  bool quarantined            = false;
  bool safe_from_quarantine   = false;
  std::string thumbnail_url;
  std::string mxc_uri;
  int thumbnail_width         = 0;
  int thumbnail_height        = 0;
};

// Pusher information
struct AdminUserPusherInfo {
  int64_t pusher_id           = 0;
  std::string pushkey;
  std::string kind;           // "http", "email", "sms", "webhook", "apns", "fcm"
  std::string app_id;
  std::string app_display_name;
  std::string device_display_name;
  std::string profile_tag;
  std::string lang;
  std::string data_url;
  std::string data_format;
  int64_t created_ts          = 0;
  int64_t updated_ts          = 0;
  int64_t last_success_ts     = 0;
  int64_t last_failure_ts     = 0;
  int  consecutive_failures    = 0;
  bool enabled                 = true;
  bool append_content          = false;
  int  rate_limit_count        = 0;
  int  rate_limit_period_ms    = 0;
};

// Connection / session information
struct AdminUserConnectionInfo {
  std::string connection_id;
  std::string device_id;
  std::string ip_address;
  std::string user_agent;
  std::string connection_type; // login, logout, refresh, sso, oauth2, etc.
  std::string access_token_hash;
  std::string refresh_token_hash;
  int64_t connected_at        = 0;
  int64_t disconnected_at     = 0;
  int64_t last_activity_ts    = 0;
  int64_t token_expires_at    = 0;
  bool is_active              = true;
  std::string country_code;
  std::string region;
  std::string city;
};

// User statistics summary
struct AdminUserStats {
  int64_t total_rooms          = 0;
  int64_t joined_rooms         = 0;
  int64_t invited_rooms        = 0;
  int64_t left_rooms           = 0;
  int64_t banned_rooms         = 0;
  int64_t direct_rooms         = 0;
  int64_t total_events_sent    = 0;
  int64_t total_media          = 0;
  int64_t total_media_bytes    = 0;
  int64_t total_devices        = 0;
  int64_t active_devices       = 0;
  int64_t total_sessions       = 0;
  int64_t active_sessions      = 0;
  int64_t total_pushers        = 0;
  int64_t total_threepids      = 0;
  int64_t total_connections    = 0;
  int64_t total_push_rules     = 0;
  int64_t total_account_data   = 0;
  int64_t last_active_ts       = 0;
};

// User query filter
struct AdminUserFilter {
  std::optional<std::string> name_contains;
  std::optional<std::string> name_starts_with;
  std::optional<std::string> display_name_contains;
  std::optional<std::string> user_type;
  std::optional<bool> is_guest;
  std::optional<bool> is_admin;
  std::optional<bool> deactivated;
  std::optional<bool> locked;
  std::optional<bool> suspended;
  std::optional<bool> shadow_banned;
  std::optional<bool> consent_given;
  std::optional<std::string> appservice_id;
  std::optional<int64_t> created_after;
  std::optional<int64_t> created_before;
  std::optional<int64_t> last_seen_after;
  std::optional<int64_t> last_seen_before;
  std::optional<std::string> threepid_medium;
  std::optional<std::string> threepid_address_contains;
  std::optional<std::string> ip_address;
  std::optional<std::string> device_id;
  std::optional<int64_t> min_room_count;
  std::optional<int64_t> max_room_count;
  std::optional<int64_t> min_media_count;
  std::optional<bool> not_user_id_in;
  std::vector<std::string> exclude_user_ids;
};

// Account validity record
struct AdminAccountValidity {
  bool has_expiration       = false;
  int64_t expiration_ts_ms  = 0;
  int64_t renewal_ts_ms     = 0;
  bool expired              = false;
  bool renewal_allowed      = true;
  int64_t period_ms         = 0;
  std::string period_display;
};

// ============================================================================
// 1. AdminUserDatabase — Raw SQL operations for admin user management
// ============================================================================

class AdminUserDatabase {
public:
  AdminUserDatabase(storage::DatabasePool& db, const std::string& server_name)
      : db_(db), server_name_(server_name) {}

  // ---- User existence and basic lookups ----

  std::optional<AdminUserRecord> get_user_record(const std::string& user_id) {
    try {
      auto row = db_.simple_select_one(
          "users",
          {{"name", user_id}},
          {"name", "password_hash", "is_guest", "admin", "deactivated",
           "creation_ts", "consent_version", "consent_server_notice_sent",
           "consent_ts", "appservice_id", "shadow_banned",
           "user_type", "locked", "last_seen_ts", "deactivation_ts",
           "suspended", "suspension_ts", "suspension_end_ts",
           "failed_login_attempts", "deactivation_reason",
           "suspension_reason", "lock_reason", "external_auth_provider"});

      if (!row.has_value()) return std::nullopt;

      return parse_user_record(row.value());
    } catch (...) {
      return std::nullopt;
    }
  }

  bool user_exists(const std::string& user_id) {
    try {
      auto row = db_.simple_select_one(
          "users", {{"name", user_id}}, {"name"});
      return row.has_value();
    } catch (...) {
      return false;
    }
  }

  // ---- User creation ----

  bool create_user(const AdminUserRecord& record) {
    try {
      db_.simple_insert("users", {
          {"name", record.user_id},
          {"password_hash", record.password_hash},
          {"is_guest", record.is_guest ? "1" : "0"},
          {"admin", record.is_admin ? "1" : "0"},
          {"deactivated", record.deactivated ? "1" : "0"},
          {"creation_ts", std::to_string(record.creation_ts)},
          {"user_type", record.user_type},
          {"appservice_id", record.appservice_id},
          {"shadow_banned", record.shadow_banned ? "1" : "0"},
          {"locked", record.locked ? "1" : "0"},
          {"last_seen_ts", std::to_string(record.last_seen_ts)},
          {"deactivation_ts", std::to_string(record.deactivation_ts)},
          {"suspended", record.suspended ? "1" : "0"},
          {"external_auth_provider", record.external_auth_provider}
      });
      return true;
    } catch (...) {
      return false;
    }
  }

  // ---- User updates ----

  bool update_user(const std::string& user_id,
                    const std::map<std::string, std::string>& fields) {
    try {
      db_.simple_update_one("users", {{"name", user_id}}, fields);
      return true;
    } catch (...) {
      return false;
    }
  }

  bool set_user_password(const std::string& user_id,
                          const std::string& password_hash) {
    return update_user(user_id, {{"password_hash", password_hash}});
  }

  bool set_user_admin(const std::string& user_id, bool admin) {
    return update_user(user_id, {{"admin", admin ? "1" : "0"}});
  }

  bool set_user_deactivated(const std::string& user_id, bool deactivated,
                             const std::string& reason = "") {
    std::map<std::string, std::string> fields{
        {"deactivated", deactivated ? "1" : "0"}};
    if (deactivated) {
      fields["deactivation_ts"] = std::to_string(now_ms());
      if (!reason.empty()) {
        fields["deactivation_reason"] = reason;
      }
    } else {
      fields["deactivation_ts"] = "0";
    }
    return update_user(user_id, fields);
  }

  bool set_user_locked(const std::string& user_id, bool locked,
                        const std::string& reason = "") {
    std::map<std::string, std::string> fields{
        {"locked", locked ? "1" : "0"}};
    if (locked) {
      fields["lock_ts"] = std::to_string(now_ms());
      if (!reason.empty()) fields["lock_reason"] = reason;
    }
    return update_user(user_id, fields);
  }

  bool set_user_suspended(const std::string& user_id, bool suspended,
                           int64_t duration_ms = 0,
                           const std::string& reason = "") {
    std::map<std::string, std::string> fields{
        {"suspended", suspended ? "1" : "0"}};
    if (suspended) {
      fields["suspension_ts"] = std::to_string(now_ms());
      fields["suspension_end_ts"] =
          std::to_string(duration_ms > 0 ? now_ms() + duration_ms : 0);
      if (!reason.empty()) fields["suspension_reason"] = reason;
    } else {
      fields["suspension_ts"] = "0";
      fields["suspension_end_ts"] = "0";
    }
    return update_user(user_id, fields);
  }

  bool set_user_shadow_banned(const std::string& user_id, bool banned) {
    return update_user(user_id, {{"shadow_banned", banned ? "1" : "0"}});
  }

  bool set_user_consent(const std::string& user_id,
                         const std::string& version) {
    return update_user(user_id, {
        {"consent_version", version},
        {"consent_ts", std::to_string(now_ms())},
        {"consent_server_notice_sent", "1"}
    });
  }

  bool set_user_type(const std::string& user_id, const std::string& utype) {
    return update_user(user_id, {{"user_type", utype}});
  }

  // ---- Profile operations ----

  bool upsert_profile(const std::string& user_id,
                       const std::string& display_name,
                       const std::string& avatar_url) {
    try {
      auto existing = db_.simple_select_one(
          "profiles", {{"user_id", user_id}}, {"user_id"});
      if (existing.has_value()) {
        db_.simple_update_one("profiles", {{"user_id", user_id}}, {
            {"displayname", display_name},
            {"avatar_url", avatar_url}
        });
      } else {
        db_.simple_insert("profiles", {
            {"user_id", user_id},
            {"displayname", display_name},
            {"avatar_url", avatar_url}
        });
      }
      return true;
    } catch (...) {
      return false;
    }
  }

  std::string get_display_name(const std::string& user_id) {
    try {
      auto row = db_.simple_select_one(
          "profiles", {{"user_id", user_id}}, {"displayname"});
      if (row.has_value()) return row_get_str(row.value(), 0);
    } catch (...) {}
    if (is_valid_user_id(user_id)) {
      return user_id.substr(1, user_id.find(':') - 1);
    }
    return user_id;
  }

  std::string get_avatar_url(const std::string& user_id) {
    try {
      auto row = db_.simple_select_one(
          "profiles", {{"user_id", user_id}}, {"avatar_url"});
      if (row.has_value()) return row_get_str(row.value(), 0);
    } catch (...) {}
    return "";
  }

  // ---- Threepid operations ----

  json get_user_threepids(const std::string& user_id) {
    json threepids = json::array();
    try {
      auto rows = db_.execute(
          "admin_threepids",
          "SELECT medium, address, validated_at, added_at "
          "FROM user_threepids WHERE user_id = ? ORDER BY added_at DESC",
          {user_id});
      for (auto& row : rows) {
        json entry;
        entry["medium"] = row_get_str(row, 0);
        entry["address"] = row_get_str(row, 1);
        int64_t validated = row_get_int(row, 2);
        int64_t added = row_get_int(row, 3);
        entry["validated"] = validated > 0;
        entry["validated_at"] = validated > 0 ? ts_to_iso8601(validated) : 0;
        entry["added_at"] = added > 0 ? ts_to_iso8601(added) : 0;
        threepids.push_back(entry);
      }
    } catch (...) {}
    return threepids;
  }

  bool add_threepid(const std::string& user_id,
                     const std::string& medium,
                     const std::string& address,
                     bool validated = false) {
    try {
      int64_t now = now_ms();
      db_.simple_insert("user_threepids", {
          {"user_id", user_id},
          {"medium", medium},
          {"address", address},
          {"validated_at", validated ? std::to_string(now) : "0"},
          {"added_at", std::to_string(now)}
      });
      return true;
    } catch (...) {
      return false;
    }
  }

  bool remove_threepid(const std::string& user_id,
                        const std::string& medium,
                        const std::string& address) {
    try {
      db_.execute("delete_threepid_admin",
                  "DELETE FROM user_threepids "
                  "WHERE user_id = ? AND medium = ? AND address = ?",
                  {user_id, medium, address});
      return true;
    } catch (...) {
      return false;
    }
  }

  bool validate_threepid(const std::string& user_id,
                          const std::string& medium,
                          const std::string& address) {
    try {
      db_.execute("validate_threepid_admin",
                  "UPDATE user_threepids SET validated_at = ? "
                  "WHERE user_id = ? AND medium = ? AND address = ?",
                  {std::to_string(now_ms()), user_id, medium, address});
      return true;
    } catch (...) {
      return false;
    }
  }

  // ---- External IDs ----

  json get_user_external_ids(const std::string& user_id) {
    json external = json::array();
    try {
      auto rows = db_.execute(
          "admin_external_ids",
          "SELECT auth_provider, external_id "
          "FROM user_external_ids WHERE user_id = ?",
          {user_id});
      for (auto& row : rows) {
        json entry;
        entry["auth_provider"] = row_get_str(row, 0);
        entry["external_id"] = row_get_str(row, 1);
        external.push_back(entry);
      }
    } catch (...) {}
    return external;
  }

  // ---- Device operations ----

  std::vector<AdminDeviceInfo> get_user_devices(const std::string& user_id) {
    std::vector<AdminDeviceInfo> devices;
    try {
      auto rows = db_.execute(
          "admin_devices",
          "SELECT device_id, display_name, last_seen, ip, user_agent, "
          "hidden, device_type, creation_ts, last_token_refresh "
          "FROM devices WHERE user_id = ? ORDER BY last_seen DESC",
          {user_id});
      for (auto& row : rows) {
        AdminDeviceInfo d;
        d.device_id          = row_get_str(row, 0);
        d.display_name       = row_get_str(row, 1);
        d.last_seen_ts       = row_get_int(row, 2);
        d.last_seen_ip       = row_get_str(row, 3);
        d.user_agent         = row_get_str(row, 4);
        d.hidden             = row_get_bool(row, 5);
        d.device_type        = row_get_str(row, 6, "unknown");
        d.creation_ts        = row_get_int(row, 7);
        d.last_token_refresh = row_get_int(row, 8);
        d.verified           = false; // placeholder
        d.dehydrated          = false; // placeholder
        devices.push_back(d);
      }
    } catch (...) {}
    return devices;
  }

  std::optional<AdminDeviceInfo> get_device(const std::string& user_id,
                                             const std::string& device_id) {
    try {
      auto rows = db_.execute(
          "admin_get_device",
          "SELECT device_id, display_name, last_seen, ip, user_agent, "
          "hidden, device_type, creation_ts, last_token_refresh "
          "FROM devices WHERE user_id = ? AND device_id = ?",
          {user_id, device_id});
      if (rows.empty()) return std::nullopt;
      auto& row = rows[0];
      AdminDeviceInfo d;
      d.device_id          = row_get_str(row, 0);
      d.display_name       = row_get_str(row, 1);
      d.last_seen_ts       = row_get_int(row, 2);
      d.last_seen_ip       = row_get_str(row, 3);
      d.user_agent         = row_get_str(row, 4);
      d.hidden             = row_get_bool(row, 5);
      d.device_type        = row_get_str(row, 6, "unknown");
      d.creation_ts        = row_get_int(row, 7);
      d.last_token_refresh = row_get_int(row, 8);
      return d;
    } catch (...) {
      return std::nullopt;
    }
  }

  bool update_device_display_name(const std::string& user_id,
                                   const std::string& device_id,
                                   const std::string& display_name) {
    try {
      db_.execute("admin_update_device_name",
                  "UPDATE devices SET display_name = ? "
                  "WHERE user_id = ? AND device_id = ?",
                  {display_name, user_id, device_id});
      return true;
    } catch (...) {
      return false;
    }
  }

  bool delete_device(const std::string& user_id,
                      const std::string& device_id) {
    try {
      db_.execute("admin_del_device_tokens",
                  "DELETE FROM access_tokens "
                  "WHERE user_id = ? AND device_id = ?",
                  {user_id, device_id});
      db_.execute("admin_del_device",
                  "DELETE FROM devices "
                  "WHERE user_id = ? AND device_id = ?",
                  {user_id, device_id});
      // Also remove E2E keys for this device
      db_.execute("admin_del_e2e_keys",
                  "DELETE FROM e2e_device_keys_json "
                  "WHERE user_id = ? AND device_id = ?",
                  {user_id, device_id});
      return true;
    } catch (...) {
      return false;
    }
  }

  bool delete_all_devices(const std::string& user_id) {
    try {
      db_.execute("admin_del_all_tokens",
                  "DELETE FROM access_tokens WHERE user_id = ?",
                  {user_id});
      db_.execute("admin_del_all_devices",
                  "DELETE FROM devices WHERE user_id = ?",
                  {user_id});
      db_.execute("admin_del_all_e2e",
                  "DELETE FROM e2e_device_keys_json WHERE user_id = ?",
                  {user_id});
      return true;
    } catch (...) {
      return false;
    }
  }

  int64_t get_device_count(const std::string& user_id) {
    try {
      auto rows = db_.execute(
          "admin_device_count",
          "SELECT COUNT(*) FROM devices WHERE user_id = ?",
          {user_id});
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  // ---- Room membership queries ----

  std::vector<AdminUserRoomInfo> get_user_rooms(
      const std::string& user_id,
      const std::string& membership_filter = "",
      int64_t limit = 100, int64_t offset = 0) {
    std::vector<AdminUserRoomInfo> rooms;
    try {
      std::string query =
          "SELECT r.room_id, rs.name, rs.canonical_alias, rm.membership, "
          "rm.sender, rm.membership_ts, r.creation_ts, rs.last_activity_ts, "
          "rs.joined_members, rs.invited_members, rs.total_events, "
          "rs.is_encrypted, rs.join_rules, rs.guest_access, "
          "rs.history_visibility, rs.room_type, r.is_public, r.room_version "
          "FROM local_current_membership rm "
          "JOIN rooms r ON rm.room_id = r.room_id "
          "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id "
          "WHERE rm.user_id = ?";

      std::vector<std::string> params = {user_id};

      if (!membership_filter.empty()) {
        query += " AND rm.membership = ?";
        params.push_back(membership_filter);
      }

      query += " ORDER BY r.creation_ts DESC "
               "LIMIT ? OFFSET ?";
      params.push_back(std::to_string(limit));
      params.push_back(std::to_string(offset));

      auto rows = db_.execute("admin_user_rooms", query, params);
      for (auto& row : rows) {
        AdminUserRoomInfo info;
        info.room_id            = row_get_str(row, 0);
        info.room_name          = row_get_str(row, 1);
        info.room_alias         = row_get_str(row, 2);
        info.membership         = row_get_str(row, 3, "leave");
        info.sender             = row_get_str(row, 4);
        info.membership_ts      = row_get_int(row, 5);
        info.creation_ts        = row_get_int(row, 6);
        info.last_activity_ts   = row_get_int(row, 7);
        info.joined_members     = row_get_int(row, 8);
        info.invited_members    = row_get_int(row, 9);
        info.total_events       = row_get_int(row, 10);
        info.is_encrypted       = row_get_bool(row, 11);
        info.join_rules         = row_get_str(row, 12, "invite");
        info.guest_access       = row_get_str(row, 13, "forbidden");
        info.history_visibility = row_get_str(row, 14, "shared");
        info.room_type          = row_get_str(row, 15, "room");
        info.is_public          = row_get_bool(row, 16);
        info.room_version       = row_get_str(row, 17, "1");
        rooms.push_back(info);
      }
    } catch (...) {}
    return rooms;
  }

  int64_t get_user_room_count(const std::string& user_id,
                               const std::string& membership_filter = "") {
    try {
      std::string query =
          "SELECT COUNT(*) FROM local_current_membership WHERE user_id = ?";
      std::vector<std::string> params = {user_id};
      if (!membership_filter.empty()) {
        query += " AND membership = ?";
        params.push_back(membership_filter);
      }
      auto rows = db_.execute("admin_user_room_count", query, params);
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  // ---- Media queries ----

  std::vector<AdminUserMediaInfo> get_user_media(
      const std::string& user_id,
      int64_t limit = 100, int64_t offset = 0,
      const std::string& sort_by = "created_ts",
      const std::string& sort_dir = "desc") {
    std::vector<AdminUserMediaInfo> media;
    try {
      std::string order_col = "created_ts";
      if (sort_by == "media_length") order_col = "media_length";
      else if (sort_by == "last_access_ts") order_col = "last_access_ts";
      else if (sort_by == "access_count") order_col = "access_count";

      std::string dir = (sort_dir == "asc") ? "ASC" : "DESC";

      std::string query =
          "SELECT media_id, media_type, upload_name, media_length, "
          "created_ts, last_access_ts, access_count, quarantined, "
          "safe_from_quarantine, origin_server "
          "FROM local_media_repository "
          "WHERE user_id = ? "
          "ORDER BY " + order_col + " " + dir + " "
          "LIMIT ? OFFSET ?";

      auto rows = db_.execute("admin_user_media", query, {
          user_id,
          std::to_string(limit),
          std::to_string(offset)
      });

      for (auto& row : rows) {
        AdminUserMediaInfo m;
        m.media_id            = row_get_str(row, 0);
        m.media_type          = row_get_str(row, 1, "application/octet-stream");
        m.upload_name         = row_get_str(row, 2);
        m.media_length        = row_get_int(row, 3);
        m.created_ts          = row_get_int(row, 4);
        m.last_access_ts      = row_get_int(row, 5);
        m.access_count        = row_get_int(row, 6);
        m.quarantined         = row_get_bool(row, 7);
        m.safe_from_quarantine = row_get_bool(row, 8);
        m.origin_server       = row_get_str(row, 9, server_name_);
        m.mxc_uri             = "mxc://" + server_name_ + "/" + m.media_id;
        media.push_back(m);
      }
    } catch (...) {}
    return media;
  }

  int64_t get_user_media_count(const std::string& user_id) {
    try {
      auto rows = db_.execute(
          "admin_user_media_count",
          "SELECT COUNT(*) FROM local_media_repository WHERE user_id = ?",
          {user_id});
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  int64_t get_user_media_total_bytes(const std::string& user_id) {
    try {
      auto rows = db_.execute(
          "admin_user_media_bytes",
          "SELECT COALESCE(SUM(media_length), 0) "
          "FROM local_media_repository WHERE user_id = ?",
          {user_id});
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  bool delete_user_media(const std::string& user_id,
                          const std::string& media_id) {
    try {
      db_.execute("admin_del_media",
                  "DELETE FROM local_media_repository "
                  "WHERE user_id = ? AND media_id = ?",
                  {user_id, media_id});
      return true;
    } catch (...) {
      return false;
    }
  }

  int64_t delete_all_user_media(const std::string& user_id) {
    try {
      auto count = get_user_media_count(user_id);
      db_.execute("admin_del_all_media",
                  "DELETE FROM local_media_repository WHERE user_id = ?",
                  {user_id});
      return count;
    } catch (...) {
      return 0;
    }
  }

  bool quarantine_media(const std::string& media_id, bool quarantine) {
    try {
      db_.execute("admin_quarantine_media",
                  "UPDATE local_media_repository SET quarantined = ? "
                  "WHERE media_id = ?",
                  {quarantine ? "1" : "0", media_id});
      return true;
    } catch (...) {
      return false;
    }
  }

  // ---- Pusher queries ----

  std::vector<AdminUserPusherInfo> get_user_pushers(
      const std::string& user_id) {
    std::vector<AdminUserPusherInfo> pushers;
    try {
      auto rows = db_.execute(
          "admin_user_pushers",
          "SELECT id, pushkey, kind, app_id, app_display_name, "
          "device_display_name, profile_tag, lang, data_url, "
          "data_format, created_ts, updated_ts, last_success_ts, "
          "last_failure_ts, consecutive_failures, enabled, "
          "append_content, rate_limit_count, rate_limit_period_ms "
          "FROM pushers WHERE user_name = ? ORDER BY created_ts DESC",
          {user_id});
      for (auto& row : rows) {
        AdminUserPusherInfo p;
        p.pusher_id            = row_get_int(row, 0);
        p.pushkey              = row_get_str(row, 1);
        p.kind                 = row_get_str(row, 2, "http");
        p.app_id               = row_get_str(row, 3);
        p.app_display_name     = row_get_str(row, 4);
        p.device_display_name  = row_get_str(row, 5);
        p.profile_tag          = row_get_str(row, 6);
        p.lang                 = row_get_str(row, 7, "en");
        p.data_url             = row_get_str(row, 8);
        p.data_format          = row_get_str(row, 9);
        p.created_ts           = row_get_int(row, 10);
        p.updated_ts           = row_get_int(row, 11);
        p.last_success_ts      = row_get_int(row, 12);
        p.last_failure_ts      = row_get_int(row, 13);
        p.consecutive_failures = static_cast<int>(row_get_int(row, 14));
        p.enabled              = row_get_bool(row, 15, true);
        p.append_content       = row_get_bool(row, 16);
        p.rate_limit_count     = static_cast<int>(row_get_int(row, 17));
        p.rate_limit_period_ms = static_cast<int>(row_get_int(row, 18));
        pushers.push_back(p);
      }
    } catch (...) {}
    return pushers;
  }

  std::optional<AdminUserPusherInfo> get_pusher(const std::string& user_id,
                                                  int64_t pusher_id) {
    try {
      auto rows = db_.execute(
          "admin_get_pusher",
          "SELECT id, pushkey, kind, app_id, app_display_name, "
          "device_display_name, profile_tag, lang, data_url, "
          "data_format, created_ts, updated_ts, last_success_ts, "
          "last_failure_ts, consecutive_failures, enabled, "
          "append_content "
          "FROM pushers WHERE user_name = ? AND id = ?",
          {user_id, std::to_string(pusher_id)});
      if (rows.empty()) return std::nullopt;
      auto& row = rows[0];
      AdminUserPusherInfo p;
      p.pusher_id            = row_get_int(row, 0);
      p.pushkey              = row_get_str(row, 1);
      p.kind                 = row_get_str(row, 2, "http");
      p.app_id               = row_get_str(row, 3);
      p.app_display_name     = row_get_str(row, 4);
      p.device_display_name  = row_get_str(row, 5);
      p.profile_tag          = row_get_str(row, 6);
      p.lang                 = row_get_str(row, 7, "en");
      p.data_url             = row_get_str(row, 8);
      p.data_format          = row_get_str(row, 9);
      p.created_ts           = row_get_int(row, 10);
      p.updated_ts           = row_get_int(row, 11);
      p.last_success_ts      = row_get_int(row, 12);
      p.last_failure_ts      = row_get_int(row, 13);
      p.consecutive_failures = static_cast<int>(row_get_int(row, 14));
      p.enabled              = row_get_bool(row, 15, true);
      p.append_content       = row_get_bool(row, 16);
      return p;
    } catch (...) {
      return std::nullopt;
    }
  }

  bool delete_pusher(const std::string& user_id, int64_t pusher_id) {
    try {
      db_.execute("admin_del_pusher",
                  "DELETE FROM pushers WHERE user_name = ? AND id = ?",
                  {user_id, std::to_string(pusher_id)});
      return true;
    } catch (...) {
      return false;
    }
  }

  int64_t delete_all_pushers(const std::string& user_id) {
    try {
      auto rows = db_.execute(
          "admin_count_pushers",
          "SELECT COUNT(*) FROM pushers WHERE user_name = ?",
          {user_id});
      int64_t count = rows.empty() ? 0 : row_get_int(rows[0], 0);
      db_.execute("admin_del_all_pushers",
                  "DELETE FROM pushers WHERE user_name = ?",
                  {user_id});
      return count;
    } catch (...) {
      return 0;
    }
  }

  // ---- Connection / session history queries ----

  std::vector<AdminUserConnectionInfo> get_user_connections(
      const std::string& user_id,
      int64_t limit = 100, int64_t offset = 0,
      bool active_only = false) {
    std::vector<AdminUserConnectionInfo> conns;
    try {
      std::string query =
          "SELECT id, device_id, ip_address, user_agent, "
          "connection_type, connected_at, disconnected_at, "
          "last_activity_ts, token_expires_at, is_active, "
          "access_token_hash, refresh_token_hash "
          "FROM user_connections "
          "WHERE user_id = ?";

      if (active_only) {
        query += " AND is_active = 1";
      }

      query += " ORDER BY connected_at DESC LIMIT ? OFFSET ?";

      auto rows = db_.execute("admin_user_connections", query, {
          user_id,
          std::to_string(limit),
          std::to_string(offset)
      });

      for (auto& row : rows) {
        AdminUserConnectionInfo c;
        c.connection_id     = std::to_string(row_get_int(row, 0));
        c.device_id         = row_get_str(row, 1);
        c.ip_address        = row_get_str(row, 2);
        c.user_agent        = row_get_str(row, 3);
        c.connection_type   = row_get_str(row, 4, "login");
        c.connected_at      = row_get_int(row, 5);
        c.disconnected_at   = row_get_int(row, 6);
        c.last_activity_ts  = row_get_int(row, 7);
        c.token_expires_at  = row_get_int(row, 8);
        c.is_active         = row_get_bool(row, 9);
        c.access_token_hash = row_get_str(row, 10);
        c.refresh_token_hash = row_get_str(row, 11);
        conns.push_back(c);
      }
    } catch (...) {}
    return conns;
  }

  int64_t get_user_connection_count(const std::string& user_id,
                                     bool active_only = false) {
    try {
      std::string query =
          "SELECT COUNT(*) FROM user_connections WHERE user_id = ?";
      std::vector<std::string> params = {user_id};
      if (active_only) {
        query += " AND is_active = 1";
      }
      auto rows = db_.execute("admin_connection_count", query, params);
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  bool revoke_user_connections(const std::string& user_id) {
    try {
      db_.execute("admin_revoke_connections",
                  "UPDATE user_connections "
                  "SET is_active = 0, disconnected_at = ? "
                  "WHERE user_id = ? AND is_active = 1",
                  {std::to_string(now_ms()), user_id});
      return true;
    } catch (...) {
      return false;
    }
  }

  bool revoke_connection(const std::string& user_id,
                          int64_t connection_id) {
    try {
      db_.execute("admin_revoke_connection",
                  "UPDATE user_connections "
                  "SET is_active = 0, disconnected_at = ? "
                  "WHERE user_id = ? AND id = ?",
                  {std::to_string(now_ms()), user_id,
                   std::to_string(connection_id)});
      return true;
    } catch (...) {
      return false;
    }
  }

  // ---- User listing and search ----

  std::vector<AdminUserRecord> query_users(
      const std::string& where_clause,
      const std::vector<std::string>& params,
      const std::string& order_clause,
      int64_t limit, int64_t offset) {
    std::vector<AdminUserRecord> users;
    try {
      std::string query =
          "SELECT name, password_hash, is_guest, admin, deactivated, "
          "creation_ts, consent_version, consent_server_notice_sent, "
          "consent_ts, appservice_id, shadow_banned, user_type, locked, "
          "last_seen_ts, deactivation_ts, suspended, suspension_ts, "
          "suspension_end_ts, failed_login_attempts, deactivation_reason, "
          "suspension_reason, lock_reason, external_auth_provider "
          "FROM users";

      if (!where_clause.empty()) {
        query += " WHERE " + where_clause;
      }
      if (!order_clause.empty()) {
        query += " ORDER BY " + order_clause;
      }
      query += " LIMIT ? OFFSET ?";

      std::vector<std::string> all_params = params;
      all_params.push_back(std::to_string(limit));
      all_params.push_back(std::to_string(offset));

      auto rows = db_.execute("admin_query_users", query, all_params);
      for (auto& row : rows) {
        users.push_back(parse_user_record(row));
      }
    } catch (...) {}
    return users;
  }

  int64_t count_query_users(const std::string& where_clause,
                              const std::vector<std::string>& params) {
    try {
      std::string query = "SELECT COUNT(*) FROM users";
      if (!where_clause.empty()) {
        query += " WHERE " + where_clause;
      }
      auto rows = db_.execute("admin_count_users", query, params);
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  int64_t get_total_user_count() {
    return count_query_users("", {});
  }

  // ---- Account validity ----

  std::optional<AdminAccountValidity> get_account_validity(
      const std::string& user_id) {
    try {
      auto row = db_.simple_select_one(
          "account_validity", {{"user_id", user_id}},
          {"expiration_ts_ms", "renewal_ts_ms",
           "period_ms"});
      if (row.has_value()) {
        AdminAccountValidity av;
        av.expiration_ts_ms = row_get_int(row.value(), 0);
        av.renewal_ts_ms    = row_get_int(row.value(), 1);
        av.period_ms        = row_get_int(row.value(), 2);
        av.has_expiration   = av.expiration_ts_ms > 0;
        av.expired          = av.expiration_ts_ms > 0 &&
                               av.expiration_ts_ms < now_ms();
        av.renewal_allowed  = av.expiration_ts_ms == 0 ||
                               av.expiration_ts_ms > now_ms();
        if (av.period_ms > 0) {
          std::stringstream ss;
          int64_t days = av.period_ms / kOneDayMs;
          ss << days << " days";
          av.period_display = ss.str();
        }
        return av;
      }
    } catch (...) {}
    return std::nullopt;
  }

  bool set_account_validity(const std::string& user_id,
                             int64_t period_ms) {
    try {
      int64_t expiration = period_ms > 0 ? now_ms() + period_ms : 0;
      auto existing = db_.simple_select_one(
          "account_validity", {{"user_id", user_id}}, {"user_id"});
      if (existing.has_value()) {
        db_.simple_update_one("account_validity", {{"user_id", user_id}}, {
            {"expiration_ts_ms", std::to_string(expiration)},
            {"period_ms", std::to_string(period_ms)}
        });
      } else {
        db_.simple_insert("account_validity", {
            {"user_id", user_id},
            {"expiration_ts_ms", std::to_string(expiration)},
            {"period_ms", std::to_string(period_ms)},
            {"renewal_ts_ms", "0"}
        });
      }
      return true;
    } catch (...) {
      return false;
    }
  }

  bool renew_account_validity(const std::string& user_id,
                               int64_t period_ms) {
    try {
      int64_t expiration = now_ms() + period_ms;
      db_.simple_update_one("account_validity", {{"user_id", user_id}}, {
          {"expiration_ts_ms", std::to_string(expiration)},
          {"renewal_ts_ms", std::to_string(now_ms())},
          {"period_ms", std::to_string(period_ms)}
      });
      return true;
    } catch (...) {
      return false;
    }
  }

  // ---- Push rules count (for stats) ----

  int64_t get_push_rules_count(const std::string& user_id) {
    try {
      auto rows = db_.execute(
          "admin_push_rules_count",
          "SELECT COUNT(*) FROM push_rules WHERE user_name = ?",
          {user_id});
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  // ---- Account data count ----

  int64_t get_account_data_count(const std::string& user_id) {
    try {
      auto rows = db_.execute(
          "admin_account_data_count",
          "SELECT COUNT(*) FROM account_data WHERE user_id = ?",
          {user_id});
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  // ---- Events sent count ----

  int64_t get_events_sent_count(const std::string& user_id) {
    try {
      auto rows = db_.execute(
          "admin_events_sent_count",
          "SELECT COUNT(*) FROM events WHERE sender = ?",
          {user_id});
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  // ---- Pseudonymize user data (GDPR erasure) ----

  void pseudonymize_user_data(const std::string& user_id) {
    try {
      std::string anon_hash = generate_token(32);
      std::string erased_name = "Erased User (" + anon_hash.substr(0,8) + ")";

      db_.simple_update_one("profiles", {{"user_id", user_id}}, {
          {"displayname", erased_name},
          {"avatar_url", ""}
      });

      db_.execute("admin_erase_threepids",
                  "DELETE FROM user_threepids WHERE user_id = ?",
                  {user_id});

      db_.execute("admin_erase_external_ids",
                  "DELETE FROM user_external_ids WHERE user_id = ?",
                  {user_id});

      db_.execute("admin_erase_pushers",
                  "DELETE FROM pushers WHERE user_name = ?",
                  {user_id});

      // Don't erase messages/media, but mark the account as erased
      db_.simple_update_one("users", {{"name", user_id}}, {
          {"deactivated", "1"},
          {"deactivation_ts", std::to_string(now_ms())},
          {"deactivation_reason", "GDPR erasure"}
      });
    } catch (...) {}
  }

private:
  AdminUserRecord parse_user_record(const Row& r) {
    AdminUserRecord rec;
    rec.user_id              = row_get_str(r, 0);
    rec.password_hash        = row_get_str(r, 1);
    rec.is_guest             = row_get_bool(r, 2);
    rec.is_admin             = row_get_bool(r, 3);
    rec.deactivated          = row_get_bool(r, 4);
    rec.creation_ts          = row_get_int(r, 5);
    rec.consent_version      = row_get_str(r, 6, "");
    rec.consent_notice_sent  = row_get_bool(r, 7);
    rec.consent_ts           = row_get_int(r, 8);
    rec.appservice_id        = row_get_str(r, 9, "");
    rec.shadow_banned        = row_get_bool(r, 10);
    rec.user_type            = row_get_str(r, 11, "user");
    rec.locked               = row_get_bool(r, 12);
    rec.last_seen_ts         = row_get_int(r, 13);
    rec.deactivation_ts      = row_get_int(r, 14);
    rec.suspended            = row_get_bool(r, 15);
    rec.suspension_ts        = row_get_int(r, 16);
    rec.suspension_end_ts    = row_get_int(r, 17);
    rec.failed_login_attempts = static_cast<int>(row_get_int(r, 18));
    rec.deactivation_reason  = row_get_str(r, 19, "");
    rec.suspension_reason    = row_get_str(r, 20, "");
    rec.lock_reason          = row_get_str(r, 21, "");
    rec.external_auth_provider = row_get_str(r, 22, "");
    return rec;
  }

  storage::DatabasePool& db_;
  std::string server_name_;
};

// ============================================================================
// 2. AdminUserQueryBuilder — Builds SQL WHERE/ORDER clauses from filters
// ============================================================================

class AdminUserQueryBuilder {
public:
  struct QueryParts {
    std::string where_clause;
    std::vector<std::string> params;
    std::string order_clause;
  };

  static QueryParts build(const AdminUserFilter& filter,
                           AdminUserSortField sort_field = AdminUserSortField::NAME,
                           bool sort_asc = true) {
    QueryParts parts;
    std::vector<std::string> conditions;

    // Name filters
    if (filter.name_contains.has_value() && !filter.name_contains->empty()) {
      conditions.push_back(
          "name LIKE '%' || ? || '%' ESCAPE '\\'");
      parts.params.push_back(
          sanitize_sql_like(filter.name_contains.value()));
    }
    if (filter.name_starts_with.has_value() &&
        !filter.name_starts_with->empty()) {
      conditions.push_back(
          "name LIKE ? || '%' ESCAPE '\\'");
      parts.params.push_back(
          sanitize_sql_like(filter.name_starts_with.value()));
    }

    // Display name filter (requires subquery or join)
    if (filter.display_name_contains.has_value() &&
        !filter.display_name_contains->empty()) {
      conditions.push_back(
          "name IN (SELECT user_id FROM profiles "
          "WHERE displayname LIKE '%' || ? || '%' ESCAPE '\\')");
      parts.params.push_back(
          sanitize_sql_like(filter.display_name_contains.value()));
    }

    // Boolean filters
    if (filter.is_guest.has_value()) {
      conditions.push_back("is_guest = ?");
      parts.params.push_back(filter.is_guest.value() ? "1" : "0");
    }
    if (filter.is_admin.has_value()) {
      conditions.push_back("admin = ?");
      parts.params.push_back(filter.is_admin.value() ? "1" : "0");
    }
    if (filter.deactivated.has_value()) {
      conditions.push_back("deactivated = ?");
      parts.params.push_back(filter.deactivated.value() ? "1" : "0");
    }
    if (filter.locked.has_value()) {
      conditions.push_back("locked = ?");
      parts.params.push_back(filter.locked.value() ? "1" : "0");
    }
    if (filter.suspended.has_value()) {
      conditions.push_back("suspended = ?");
      parts.params.push_back(filter.suspended.value() ? "1" : "0");
    }
    if (filter.shadow_banned.has_value()) {
      conditions.push_back("shadow_banned = ?");
      parts.params.push_back(filter.shadow_banned.value() ? "1" : "0");
    }
    if (filter.consent_given.has_value()) {
      if (filter.consent_given.value()) {
        conditions.push_back("consent_version IS NOT NULL AND consent_version != ''");
      } else {
        conditions.push_back("(consent_version IS NULL OR consent_version = '')");
      }
    }

    // String equality filters
    if (filter.user_type.has_value() && !filter.user_type->empty()) {
      conditions.push_back("user_type = ?");
      parts.params.push_back(filter.user_type.value());
    }
    if (filter.appservice_id.has_value() && !filter.appservice_id->empty()) {
      conditions.push_back("appservice_id = ?");
      parts.params.push_back(filter.appservice_id.value());
    }

    // Timestamp range filters
    if (filter.created_after.has_value()) {
      conditions.push_back("creation_ts >= ?");
      parts.params.push_back(std::to_string(filter.created_after.value()));
    }
    if (filter.created_before.has_value()) {
      conditions.push_back("creation_ts <= ?");
      parts.params.push_back(std::to_string(filter.created_before.value()));
    }
    if (filter.last_seen_after.has_value()) {
      conditions.push_back("last_seen_ts >= ?");
      parts.params.push_back(std::to_string(filter.last_seen_after.value()));
    }
    if (filter.last_seen_before.has_value()) {
      conditions.push_back("last_seen_ts <= ?");
      parts.params.push_back(std::to_string(filter.last_seen_before.value()));
    }

    // Threepid subquery
    if (filter.threepid_medium.has_value() &&
        filter.threepid_address_contains.has_value()) {
      conditions.push_back(
          "name IN (SELECT user_id FROM user_threepids "
          "WHERE medium = ? AND address LIKE '%' || ? || '%' ESCAPE '\\')");
      parts.params.push_back(filter.threepid_medium.value());
      parts.params.push_back(
          sanitize_sql_like(filter.threepid_address_contains.value()));
    } else if (filter.threepid_address_contains.has_value() &&
               !filter.threepid_address_contains->empty()) {
      conditions.push_back(
          "name IN (SELECT user_id FROM user_threepids "
          "WHERE address LIKE '%' || ? || '%' ESCAPE '\\')");
      parts.params.push_back(
          sanitize_sql_like(filter.threepid_address_contains.value()));
    }

    // IP address filter (via devices)
    if (filter.ip_address.has_value() && !filter.ip_address->empty()) {
      conditions.push_back(
          "name IN (SELECT user_id FROM devices "
          "WHERE ip LIKE '%' || ? || '%' ESCAPE '\\')");
      parts.params.push_back(
          sanitize_sql_like(filter.ip_address.value()));
    }

    // Device ID filter
    if (filter.device_id.has_value() && !filter.device_id->empty()) {
      conditions.push_back(
          "name IN (SELECT user_id FROM devices WHERE device_id = ?)");
      parts.params.push_back(filter.device_id.value());
    }

    // Room count subquery filters
    if (filter.min_room_count.has_value()) {
      conditions.push_back(
          "name IN (SELECT user_id FROM local_current_membership "
          "WHERE membership = 'join' "
          "GROUP BY user_id HAVING COUNT(*) >= ?)");
      parts.params.push_back(std::to_string(filter.min_room_count.value()));
    }
    if (filter.max_room_count.has_value()) {
      conditions.push_back(
          "(SELECT COUNT(*) FROM local_current_membership "
          "WHERE user_id = name AND membership = 'join') <= ?");
      parts.params.push_back(std::to_string(filter.max_room_count.value()));
    }

    // Media count subquery filter
    if (filter.min_media_count.has_value()) {
      conditions.push_back(
          "(SELECT COUNT(*) FROM local_media_repository "
          "WHERE user_id = name) >= ?");
      parts.params.push_back(std::to_string(filter.min_media_count.value()));
    }

    // Exclude user IDs
    if (!filter.exclude_user_ids.empty()) {
      std::vector<std::string> placeholders;
      for (auto& uid : filter.exclude_user_ids) {
        placeholders.push_back("?");
        parts.params.push_back(uid);
      }
      conditions.push_back(
          "name NOT IN (" + join(placeholders, ", ") + ")");
    }

    // Build WHERE clause
    if (!conditions.empty()) {
      parts.where_clause = join(conditions, " AND ");
    }

    // Build ORDER clause
    parts.order_clause = sort_field_to_sql(sort_field, sort_asc);

    return parts;
  }

private:
  static std::string sort_field_to_sql(AdminUserSortField field, bool asc) {
    std::string dir = asc ? "ASC" : "DESC";
    switch (field) {
      case AdminUserSortField::NAME:          return "name " + dir;
      case AdminUserSortField::CREATION_TS:   return "creation_ts " + dir;
      case AdminUserSortField::LAST_SEEN_TS:  return "last_seen_ts " + dir;
      case AdminUserSortField::USER_TYPE:     return "user_type " + dir;
      case AdminUserSortField::ADMIN:         return "admin " + dir;
      case AdminUserSortField::DEACTIVATED:   return "deactivated " + dir;
      case AdminUserSortField::LOCKED:        return "locked " + dir;
      case AdminUserSortField::SHADOW_BANNED: return "shadow_banned " + dir;
      case AdminUserSortField::DISPLAY_NAME:
        return "(SELECT displayname FROM profiles "
               "WHERE user_id = name) " + dir;
      case AdminUserSortField::MEDIA_COUNT:
        return "(SELECT COUNT(*) FROM local_media_repository "
               "WHERE user_id = name) " + dir;
      case AdminUserSortField::ROOM_COUNT:
        return "(SELECT COUNT(*) FROM local_current_membership "
               "WHERE user_id = name AND membership = 'join') " + dir;
      case AdminUserSortField::DEVICE_COUNT:
        return "(SELECT COUNT(*) FROM devices "
               "WHERE user_id = name) " + dir;
      default: return "name " + dir;
    }
  }
};

// ============================================================================
// 3. AdminUserManager — Core business logic for admin user management
// ============================================================================

class AdminUserManager {
public:
  AdminUserManager(storage::DatabasePool& db, const std::string& server_name)
      : db_(std::make_shared<AdminUserDatabase>(db, server_name)),
        server_name_(server_name) {}

  // ========================================================================
  // User Listing
  // ========================================================================

  json list_users(const AdminUserFilter& filter = {},
                  AdminUserSortField sort = AdminUserSortField::NAME,
                  bool sort_asc = true,
                  int64_t from = 0, int64_t limit = kDefaultLimit) {
    try {
      if (limit < 1) limit = kDefaultLimit;
      if (limit > kMaxLimit) limit = kMaxLimit;

      auto qp = AdminUserQueryBuilder::build(filter, sort, sort_asc);
      auto users = db_->query_users(
          qp.where_clause, qp.params,
          qp.order_clause, limit + 1, from);

      json users_array = json::array();
      bool has_more = false;
      size_t count = 0;

      for (auto& rec : users) {
        if (count >= static_cast<size_t>(limit)) {
          has_more = true;
          break;
        }
        users_array.push_back(format_user_summary(rec));
        count++;
      }

      int64_t total = db_->count_query_users(
          qp.where_clause, qp.params);

      json result;
      result["users"]       = users_array;
      result["total"]       = total;
      result["next_token"]  = has_more ? std::to_string(from + limit) : "";
      result["offset"]      = from;
      result["limit"]       = limit;
      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing users: ") + e.what());
    }
  }

  // ========================================================================
  // User Creation
  // ========================================================================

  json create_user(const json& body) {
    // Validate required fields
    if (!body.contains("name") || !body["name"].is_string()) {
      return build_error(400, "M_MISSING_PARAM",
                         "Missing required field: name (localpart)");
    }

    std::string localpart = trim(body["name"].get<std::string>());
    std::string full_uid = "@" + localpart + ":" + server_name_;

    // Validate localpart
    if (!is_valid_localpart(localpart)) {
      return build_error(400, "M_INVALID_USERNAME",
                         "Invalid username: " + localpart +
                         ". Must be 1-255 alphanumeric characters, "
                         "dots, hyphens, underscores, equals, or forward slashes.");
    }

    // Check if user already exists
    if (db_->user_exists(full_uid)) {
      return build_error(409, "M_USER_IN_USE",
                         "User ID already taken: " + full_uid);
    }

    // Validate password
    std::string password = json_get_str(body, "password", "");
    if (password.empty()) {
      password = generate_token(24); // auto-generate if not provided
    } else if (!is_valid_password(password)) {
      return build_error(400, "M_WEAK_PASSWORD",
                         "Password must be at least 8 characters and include "
                         "characters from at least 3 of: lowercase, uppercase, "
                         "digits, special characters.");
    }

    // Build user record
    AdminUserRecord rec;
    rec.user_id       = full_uid;
    rec.password_hash = hash_password(password);
    rec.is_admin      = json_get_bool(body, "admin", false);
    rec.is_guest      = json_get_bool(body, "is_guest", false);
    rec.user_type     = json_get_str(body, "user_type",
                                     rec.is_guest ? kGuestUserType :
                                                    kDefaultUserType);
    rec.appservice_id = json_get_str(body, "appservice_id", "");
    rec.creation_ts   = now_ms();
    rec.last_seen_ts  = rec.creation_ts;
    rec.shadow_banned = json_get_bool(body, "shadow_banned", false);
    rec.locked        = json_get_bool(body, "locked", false);
    rec.deactivated   = json_get_bool(body, "deactivated", false);
    rec.suspended     = json_get_bool(body, "suspended", false);
    rec.external_auth_provider = json_get_str(body, "auth_provider", "");

    // Create the user
    if (!db_->create_user(rec)) {
      return build_error(500, "M_UNKNOWN",
                         "Failed to create user in database.");
    }

    // Set display name if provided
    std::string display_name = json_get_str(
        body, "displayname",
        json_get_str(body, "display_name", localpart));
    if (!display_name.empty() && is_valid_display_name(display_name)) {
      std::string avatar_url = json_get_str(body, "avatar_url", "");
      db_->upsert_profile(full_uid, display_name, avatar_url);
    }

    // Add threepids if provided
    if (body.contains("threepids") && body["threepids"].is_array()) {
      for (auto& tp : body["threepids"]) {
        std::string medium = json_get_str(tp, "medium");
        std::string address = json_get_str(tp, "address");
        bool validated = json_get_bool(tp, "validated", false);
        if (!medium.empty() && !address.empty()) {
          db_->add_threepid(full_uid, medium, address, validated);
        }
      }
    }

    // Build response
    json response;
    response["name"]            = full_uid;
    response["displayname"]     = display_name;
    response["admin"]           = rec.is_admin;
    response["is_guest"]        = rec.is_guest;
    response["deactivated"]     = rec.deactivated;
    response["user_type"]       = rec.user_type;
    response["creation_ts"]     = rec.creation_ts;
    response["creation_ts_display"] = ts_to_iso8601(rec.creation_ts);
    response["password_set"]    = true;

    // Return the auto-generated password if one was created
    if (!body.contains("password") || body["password"].is_null()) {
      response["password"]      = password;
      response["password_generated"] = true;
    }

    return response;
  }

  // ========================================================================
  // User Update
  // ========================================================================

  json update_user(const std::string& user_id, const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    auto existing = db_->get_user_record(user_id);
    if (!existing.has_value()) {
      return build_error(404, "M_NOT_FOUND",
                         "User not found: " + user_id);
    }

    std::map<std::string, std::string> updates;
    json changes = json::object();

    // Update admin status
    if (body.contains("admin") && body["admin"].is_boolean()) {
      bool admin = body["admin"].get<bool>();
      updates["admin"] = admin ? "1" : "0";
      changes["admin"] = admin;
    }

    // Update user type
    if (body.contains("user_type") && body["user_type"].is_string()) {
      std::string utype = body["user_type"].get<std::string>();
      updates["user_type"] = utype;
      changes["user_type"] = utype;
    }

    // Update display name
    if (body.contains("displayname") || body.contains("display_name")) {
      std::string dn = json_get_str(body, "displayname",
                       json_get_str(body, "display_name",
                                     existing->display_name));
      if (is_valid_display_name(dn)) {
        std::string av = json_get_str(body, "avatar_url",
                         existing->avatar_url);
        db_->upsert_profile(user_id, dn, av);
        changes["displayname"] = dn;
      }
    }

    // Update avatar
    if (body.contains("avatar_url") && body["avatar_url"].is_string()) {
      std::string av = body["avatar_url"].get<std::string>();
      if (is_valid_url(av) || av.empty()) {
        std::string dn = json_get_str(body, "displayname",
                         db_->get_display_name(user_id));
        db_->upsert_profile(user_id, dn, av);
        changes["avatar_url"] = av;
      }
    }

    // Update locked status
    if (body.contains("locked") && body["locked"].is_boolean()) {
      bool locked = body["locked"].get<bool>();
      std::string reason = json_get_str(body, "lock_reason", "");
      db_->set_user_locked(user_id, locked, reason);
      changes["locked"] = locked;
      if (!reason.empty()) changes["lock_reason"] = reason;
    }

    // Update shadow ban
    if (body.contains("shadow_banned") && body["shadow_banned"].is_boolean()) {
      bool sb = body["shadow_banned"].get<bool>();
      db_->set_user_shadow_banned(user_id, sb);
      changes["shadow_banned"] = sb;
    }

    // Update consent
    if (body.contains("consent_version") && body["consent_version"].is_string()) {
      std::string ver = body["consent_version"].get<std::string>();
      db_->set_user_consent(user_id, ver);
      changes["consent_version"] = ver;
    }

    // Apply remaining updates
    if (!updates.empty()) {
      db_->update_user(user_id, updates);
    }

    json response;
    response["user_id"] = user_id;
    response["updated"] = true;
    response["changes"] = changes;
    return response;
  }

  // ========================================================================
  // User Info (Full Detail)
  // ========================================================================

  json get_user_info(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    auto rec = db_->get_user_record(user_id);
    if (!rec.has_value()) {
      return build_error(404, "M_NOT_FOUND",
                         "User not found: " + user_id);
    }

    try {
      json info = format_user_detail(rec.value());

      // Threepids
      info["threepids"] = db_->get_user_threepids(user_id);

      // External IDs
      info["external_ids"] = db_->get_user_external_ids(user_id);

      // Account validity
      auto validity = db_->get_account_validity(user_id);
      if (validity.has_value()) {
        info["account_valid"] = !validity->expired;
        info["account_valid_until_ts"] = validity->expiration_ts_ms;
        if (validity->expiration_ts_ms > 0) {
          info["account_valid_until"] =
              ts_to_iso8601(validity->expiration_ts_ms);
          info["account_valid_days_remaining"] =
              ms_to_days(validity->expiration_ts_ms - now_ms());
        }
        info["account_renewal_allowed"] = validity->renewal_allowed;
        if (validity->period_ms > 0) {
          info["account_validity_period"] = validity->period_display;
        }
      }

      // Device summary
      auto devices = db_->get_user_devices(user_id);
      info["devices"] = json::object();
      info["devices"]["total"] = devices.size();
      int active_count = 0;
      int64_t now = now_ms();
      for (auto& dev : devices) {
        if (dev.last_seen_ts > 0 &&
            (now - dev.last_seen_ts) < kOneWeekMs) {
          active_count++;
        }
      }
      info["devices"]["active"] = active_count;
      info["devices"]["inactive"] = devices.size() - active_count;

      json sessions_arr = json::array();
      for (auto& dev : devices) {
        json sess;
        sess["device_id"]    = dev.device_id;
        sess["display_name"] = dev.display_name;
        sess["device_type"]  = dev.device_type;
        sess["last_seen_ts"] = dev.last_seen_ts;
        if (dev.last_seen_ts > 0) {
          sess["last_seen_ip"]  = dev.last_seen_ip;
          sess["last_seen_ua"]  = dev.user_agent;
          sess["last_seen_display"] = ts_to_iso8601(dev.last_seen_ts);
          sess["last_seen_days_ago"] = ms_to_days(now - dev.last_seen_ts);
        }
        sess["hidden"] = dev.hidden;
        sessions_arr.push_back(sess);
      }
      info["devices"]["sessions"] = sessions_arr;

      // Room summary
      info["joined_rooms"]   = db_->get_user_room_count(user_id, "join");
      info["invited_rooms"]  = db_->get_user_room_count(user_id, "invite");
      info["left_rooms"]     = db_->get_user_room_count(user_id, "leave");
      info["banned_rooms"]   = db_->get_user_room_count(user_id, "ban");
      info["total_rooms"]    = info["joined_rooms"].get<int64_t>() +
                               info["invited_rooms"].get<int64_t>() +
                               info["left_rooms"].get<int64_t>() +
                               info["banned_rooms"].get<int64_t>();

      // Media summary
      int64_t media_count = db_->get_user_media_count(user_id);
      int64_t media_bytes = db_->get_user_media_total_bytes(user_id);
      info["media_count"] = media_count;
      info["media_length"] = media_bytes;
      info["media_length_display"] = format_bytes(media_bytes);

      // Pusher count
      auto pushers = db_->get_user_pushers(user_id);
      info["pushers"] = json::object();
      info["pushers"]["total"] = pushers.size();
      int enabled_pushers = 0;
      for (auto& p : pushers) { if (p.enabled) enabled_pushers++; }
      info["pushers"]["enabled"] = enabled_pushers;

      // Connection count
      info["active_connections"] = db_->get_user_connection_count(user_id, true);
      info["total_connections"]  = db_->get_user_connection_count(user_id, false);

      // Other stats
      info["push_rules_count"]   = db_->get_push_rules_count(user_id);
      info["account_data_count"] = db_->get_account_data_count(user_id);
      info["events_sent"]        = db_->get_events_sent_count(user_id);

      return info;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error fetching user info: ") + e.what());
    }
  }

  // ========================================================================
  // Password Reset
  // ========================================================================

  json reset_password(const std::string& user_id, const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    if (!db_->user_exists(user_id)) {
      return build_error(404, "M_NOT_FOUND",
                         "User not found: " + user_id);
    }

    // Get password from body
    std::string new_password;
    if (body.contains("new_password") && body["new_password"].is_string()) {
      new_password = body["new_password"].get<std::string>();
    } else if (body.contains("password") && body["password"].is_string()) {
      new_password = body["password"].get<std::string>();
    } else {
      return build_error(400, "M_MISSING_PARAM",
                         "Missing required field: new_password");
    }

    if (!is_valid_password(new_password)) {
      return build_error(400, "M_WEAK_PASSWORD",
                         "Password must be at least 8 characters and include "
                         "characters from at least 3 of: lowercase, uppercase, "
                         "digits, special characters.");
    }

    bool logout_devices = json_get_bool(body, "logout_devices", true);

    try {
      // Hash and store
      std::string password_hash = hash_password(new_password);
      db_->set_user_password(user_id, password_hash);

      int invalidated = 0;
      if (logout_devices) {
        // Log out all devices
        db_->delete_all_devices(user_id);
        db_->revoke_user_connections(user_id);
        invalidated = static_cast<int>(db_->get_device_count(user_id));
      }

      json response;
      response["success"] = true;
      response["user_id"] = user_id;
      response["logout_devices"] = logout_devices;
      response["invalidated_sessions"] = invalidated;
      response["message"] = "Password reset successfully";

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Password reset failed: ") + e.what());
    }
  }

  // ========================================================================
  // Deactivation
  // ========================================================================

  json deactivate_user(const std::string& user_id, const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    auto rec = db_->get_user_record(user_id);
    if (!rec.has_value()) {
      return build_error(404, "M_NOT_FOUND",
                         "User not found: " + user_id);
    }

    if (rec->deactivated) {
      return build_error(400, "M_USER_DEACTIVATED",
                         "User is already deactivated");
    }

    bool erase = json_get_bool(body, "erase", false);
    std::string reason = json_get_str(body, "reason", "Admin deactivation");

    try {
      db_->set_user_deactivated(user_id, true, reason);

      // Log out all sessions
      db_->delete_all_devices(user_id);
      db_->revoke_user_connections(user_id);

      int device_count = static_cast<int>(db_->get_device_count(user_id));

      // GDPR erasure if requested
      if (erase) {
        db_->pseudonymize_user_data(user_id);
      }

      json response;
      response["success"]        = true;
      response["user_id"]        = user_id;
      response["deactivated"]    = true;
      response["erased"]         = erase;
      response["reason"]         = reason;
      response["deactivated_at"] = now_iso8601();
      response["devices_logged_out"] = device_count;

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Deactivation failed: ") + e.what());
    }
  }

  // ========================================================================
  // Reactivation
  // ========================================================================

  json reactivate_user(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    auto rec = db_->get_user_record(user_id);
    if (!rec.has_value()) {
      return build_error(404, "M_NOT_FOUND",
                         "User not found: " + user_id);
    }

    if (!rec->deactivated) {
      return build_error(400, "M_USER_NOT_DEACTIVATED",
                         "User is not deactivated");
    }

    try {
      db_->set_user_deactivated(user_id, false);

      json response;
      response["success"]       = true;
      response["user_id"]       = user_id;
      response["reactivated"]   = true;
      response["reactivated_at"] = now_iso8601();

      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Reactivation failed: ") + e.what());
    }
  }

  // ========================================================================
  // Account Locking / Suspension
  // ========================================================================

  json lock_user(const std::string& user_id, const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    if (!db_->user_exists(user_id)) {
      return build_error(404, "M_NOT_FOUND", "User not found: " + user_id);
    }

    bool lock = json_get_bool(body, "lock", true);
    std::string reason = json_get_str(body, "reason",
                         lock ? "Admin lock" : "Admin unlock");

    db_->set_user_locked(user_id, lock, reason);

    // If locking, also revoke connections
    if (lock) {
      db_->revoke_user_connections(user_id);
    }

    json response;
    response["success"] = true;
    response["user_id"] = user_id;
    response["locked"]  = lock;
    response["reason"]  = reason;
    return response;
  }

  json suspend_user(const std::string& user_id, const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    if (!db_->user_exists(user_id)) {
      return build_error(404, "M_NOT_FOUND", "User not found: " + user_id);
    }

    bool suspend = json_get_bool(body, "suspend", true);
    int64_t duration_ms = json_get_int(body, "duration_ms",
                          json_get_int(body, "duration_seconds", 0) * 1000);
    if (duration_ms == 0) duration_ms = kOneWeekMs * 7; // 7 days default
    std::string reason = json_get_str(body, "reason",
                         suspend ? "Admin suspension" : "Admin unsuspension");

    db_->set_user_suspended(user_id, suspend, duration_ms, reason);

    if (suspend) {
      db_->revoke_user_connections(user_id);
    }

    json response;
    response["success"]       = true;
    response["user_id"]       = user_id;
    response["suspended"]     = suspend;
    response["reason"]        = reason;
    if (suspend && duration_ms > 0) {
      response["duration_ms"] = duration_ms;
      response["duration_display"] = format_duration_sec(duration_ms / 1000);
      response["suspension_end_ts"] = ts_to_iso8601(now_ms() + duration_ms);
    }
    return response;
  }

  json set_shadow_ban(const std::string& user_id, const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    bool ban = json_get_bool(body, "shadow_ban", true);
    std::string reason = json_get_str(body, "reason",
                         ban ? "Admin shadow ban" : "Admin shadow unban");

    db_->set_user_shadow_banned(user_id, ban);

    json response;
    response["success"]       = true;
    response["user_id"]       = user_id;
    response["shadow_banned"] = ban;
    response["reason"]        = reason;
    return response;
  }

  // ========================================================================
  // Account Validity
  // ========================================================================

  json set_account_validity(const std::string& user_id, const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    if (!body.contains("period_ms") && !body.contains("period_days")) {
      return build_error(400, "M_MISSING_PARAM",
                         "Missing required field: period_ms or period_days");
    }

    int64_t period_ms = json_get_int(body, "period_ms", 0);
    if (period_ms == 0 && body.contains("period_days")) {
      period_ms = json_get_int(body, "period_days", 0) * kOneDayMs;
    }

    if (period_ms < 0) {
      return build_error(400, "M_INVALID_PARAM",
                         "period_ms must be non-negative");
    }

    bool success = db_->set_account_validity(user_id, period_ms);

    json response;
    response["success"]   = success;
    response["user_id"]   = user_id;
    response["period_ms"] = period_ms;
    if (period_ms > 0) {
      response["period_days"] = period_ms / kOneDayMs;
      response["expiration_ts"] = ts_to_iso8601(now_ms() + period_ms);
    }
    return response;
  }

  json renew_account_validity(const std::string& user_id, const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    int64_t period_ms = json_get_int(body, "period_ms", 0);
    if (period_ms == 0 && body.contains("period_days")) {
      period_ms = json_get_int(body, "period_days", 0) * kOneDayMs;
    }
    if (period_ms <= 0) period_ms = kOneDayMs * 365; // 1 year default

    bool success = db_->renew_account_validity(user_id, period_ms);

    json response;
    response["success"]       = success;
    response["user_id"]       = user_id;
    response["period_ms"]     = period_ms;
    response["expiration_ts"] = ts_to_iso8601(now_ms() + period_ms);
    return response;
  }

  // ========================================================================
  // User Devices
  // ========================================================================

  json list_user_devices(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    auto devices = db_->get_user_devices(user_id);

    json result;
    result["user_id"] = user_id;
    result["total"]   = devices.size();

    json devs = json::array();
    int64_t now = now_ms();
    for (auto& dev : devices) {
      json d;
      d["device_id"]      = dev.device_id;
      d["display_name"]   = dev.display_name;
      d["device_type"]    = dev.device_type;
      d["last_seen_ts"]   = dev.last_seen_ts;
      d["last_seen_ip"]   = dev.last_seen_ip;
      d["last_seen_ua"]   = dev.user_agent;
      d["creation_ts"]    = dev.creation_ts;
      d["hidden"]         = dev.hidden;
      if (dev.last_seen_ts > 0) {
        d["last_seen_display"]    = ts_to_iso8601(dev.last_seen_ts);
        d["last_seen_days_ago"]   = ms_to_days(now - dev.last_seen_ts);
        d["last_seen_seconds_ago"] = (now - dev.last_seen_ts) / 1000;
      }
      if (dev.creation_ts > 0) {
        d["creation_ts_display"] = ts_to_iso8601(dev.creation_ts);
      }
      devs.push_back(d);
    }
    result["devices"] = devs;

    return result;
  }

  json get_device_info(const std::string& user_id,
                        const std::string& device_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    auto dev = db_->get_device(user_id, device_id);
    if (!dev.has_value()) {
      return build_error(404, "M_NOT_FOUND",
                         "Device not found: " + device_id);
    }

    json d;
    d["user_id"]        = user_id;
    d["device_id"]      = dev->device_id;
    d["display_name"]   = dev->display_name;
    d["device_type"]    = dev->device_type;
    d["last_seen_ts"]   = dev->last_seen_ts;
    d["last_seen_ip"]   = dev->last_seen_ip;
    d["last_seen_ua"]   = dev->user_agent;
    d["creation_ts"]    = dev->creation_ts;
    d["hidden"]         = dev->hidden;
    d["verified"]       = dev->verified;

    int64_t now = now_ms();
    if (dev->last_seen_ts > 0) {
      d["last_seen_display"]    = ts_to_iso8601(dev->last_seen_ts);
      d["last_seen_days_ago"]   = ms_to_days(now - dev->last_seen_ts);
      d["last_seen_seconds_ago"] = (now - dev->last_seen_ts) / 1000;
    }
    if (dev->creation_ts > 0) {
      d["creation_ts_display"] = ts_to_iso8601(dev->creation_ts);
      d["device_age_days"]     = ms_to_days(now - dev->creation_ts);
    }

    // Activity classification
    if (dev->last_seen_ts > 0) {
      int64_t idle_ms = now - dev->last_seen_ts;
      if (idle_ms < kOneHourMs) d["activity_status"] = "active";
      else if (idle_ms < kOneDayMs) d["activity_status"] = "recent";
      else if (idle_ms < kOneWeekMs) d["activity_status"] = "idle";
      else d["activity_status"] = "stale";
    } else {
      d["activity_status"] = "unknown";
    }

    return d;
  }

  json update_device(const std::string& user_id,
                      const std::string& device_id,
                      const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    std::string display_name = json_get_str(body, "display_name",
                               json_get_str(body, "displayname", ""));
    if (display_name.empty()) {
      return build_error(400, "M_MISSING_PARAM",
                         "Missing required field: display_name");
    }

    bool ok = db_->update_device_display_name(
        user_id, device_id, display_name);

    if (!ok) {
      return build_error(404, "M_NOT_FOUND",
                         "Device not found or update failed");
    }

    return build_success("Device display name updated");
  }

  json delete_user_device(const std::string& user_id,
                           const std::string& device_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    bool ok = db_->delete_device(user_id, device_id);

    json response;
    response["success"]   = ok;
    response["user_id"]   = user_id;
    response["device_id"] = device_id;
    response["deleted"]   = ok;
    response["message"]   = ok ? "Device deleted successfully"
                               : "Device not found";
    return response;
  }

  json delete_all_user_devices(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    int64_t before_count = db_->get_device_count(user_id);
    bool ok = db_->delete_all_devices(user_id);

    json response;
    response["success"]          = ok;
    response["user_id"]          = user_id;
    response["devices_deleted"]  = before_count;
    response["message"]          = "All devices deleted and sessions invalidated";
    return response;
  }

  // ========================================================================
  // User Rooms
  // ========================================================================

  json list_user_rooms(const std::string& user_id,
                        const std::string& membership_filter = "",
                        int64_t from = 0, int64_t limit = kDefaultLimit) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    if (limit < 1) limit = kDefaultLimit;
    if (limit > kMaxLimit) limit = kMaxLimit;

    auto rooms = db_->get_user_rooms(
        user_id, membership_filter, limit + 1, from);

    json rooms_arr = json::array();
    bool has_more = false;
    size_t count = 0;

    for (auto& r : rooms) {
      if (count >= static_cast<size_t>(limit)) {
        has_more = true;
        break;
      }
      json room;
      room["room_id"]            = r.room_id;
      room["room_name"]          = r.room_name;
      room["canonical_alias"]    = r.room_alias;
      room["membership"]         = r.membership;
      room["sender"]             = r.sender;
      room["membership_ts"]      = r.membership_ts;
      room["creation_ts"]        = r.creation_ts;
      room["last_activity_ts"]   = r.last_activity_ts;
      room["joined_members"]     = r.joined_members;
      room["invited_members"]    = r.invited_members;
      room["total_events"]       = r.total_events;
      room["encrypted"]          = r.is_encrypted;
      room["join_rules"]         = r.join_rules;
      room["guest_access"]       = r.guest_access;
      room["history_visibility"] = r.history_visibility;
      room["room_type"]          = r.room_type;
      room["public"]             = r.is_public;
      room["room_version"]       = r.room_version;

      if (r.membership_ts > 0) {
        room["membership_ts_display"] = ts_to_iso8601(r.membership_ts);
      }
      if (r.creation_ts > 0) {
        room["creation_ts_display"] = ts_to_iso8601(r.creation_ts);
      }
      if (r.last_activity_ts > 0) {
        room["last_activity_display"] = ts_to_iso8601(r.last_activity_ts);
        room["last_activity_days_ago"] = ms_to_days(now_ms() - r.last_activity_ts);
      }

      rooms_arr.push_back(room);
      count++;
    }

    int64_t total = db_->get_user_room_count(user_id, membership_filter);

    json result;
    result["rooms"]      = rooms_arr;
    result["total"]      = total;
    result["next_token"] = has_more ? std::to_string(from + limit) : "";
    result["offset"]     = from;
    result["limit"]      = limit;
    result["user_id"]    = user_id;

    return result;
  }

  // ========================================================================
  // User Media
  // ========================================================================

  json list_user_media(const std::string& user_id,
                        int64_t from = 0, int64_t limit = kDefaultLimit,
                        const std::string& sort_by = "created_ts",
                        const std::string& sort_dir = "desc") {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    if (limit < 1) limit = kDefaultLimit;
    if (limit > kMaxLimit) limit = kMaxLimit;
    if (limit > kMaxMediaPerQuery) limit = kMaxMediaPerQuery;

    auto media = db_->get_user_media(
        user_id, limit + 1, from, sort_by, sort_dir);

    json media_arr = json::array();
    bool has_more = false;
    size_t count = 0;

    for (auto& m : media) {
      if (count >= static_cast<size_t>(limit)) {
        has_more = true;
        break;
      }
      json entry;
      entry["media_id"]         = m.media_id;
      entry["media_type"]       = m.media_type;
      entry["upload_name"]      = m.upload_name;
      entry["media_length"]     = m.media_length;
      entry["media_length_display"] = format_bytes(m.media_length);
      entry["created_ts"]       = m.created_ts;
      entry["last_access_ts"]   = m.last_access_ts;
      entry["access_count"]     = m.access_count;
      entry["quarantined"]      = m.quarantined;
      entry["safe_from_quarantine"] = m.safe_from_quarantine;
      entry["origin_server"]    = m.origin_server;
      entry["mxc_uri"]          = m.mxc_uri;

      if (m.created_ts > 0) {
        entry["created_ts_display"] = ts_to_iso8601(m.created_ts);
        entry["media_age_days"]     = ms_to_days(now_ms() - m.created_ts);
      }
      if (m.last_access_ts > 0) {
        entry["last_access_display"] = ts_to_iso8601(m.last_access_ts);
        entry["last_access_days_ago"] = ms_to_days(now_ms() - m.last_access_ts);
      }

      media_arr.push_back(entry);
      count++;
    }

    int64_t total = db_->get_user_media_count(user_id);
    int64_t total_bytes = db_->get_user_media_total_bytes(user_id);

    json result;
    result["media"]               = media_arr;
    result["total"]               = total;
    result["total_bytes"]         = total_bytes;
    result["total_bytes_display"] = format_bytes(total_bytes);
    result["next_token"]          = has_more ? std::to_string(from + limit) : "";
    result["offset"]              = from;
    result["limit"]               = limit;
    result["user_id"]             = user_id;

    return result;
  }

  json delete_user_media(const std::string& user_id,
                          const std::string& media_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    bool ok = db_->delete_user_media(user_id, media_id);

    json response;
    response["success"]  = ok;
    response["user_id"]  = user_id;
    response["media_id"] = media_id;
    response["deleted"]  = ok;
    response["message"]  = ok ? "Media deleted successfully"
                              : "Media not found";
    return response;
  }

  json delete_all_user_media(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    int64_t count = db_->delete_all_user_media(user_id);

    json response;
    response["success"]       = true;
    response["user_id"]       = user_id;
    response["media_deleted"] = count;
    response["message"]       = "All user media deleted";
    return response;
  }

  json quarantine_user_media(const std::string& user_id,
                              const std::string& media_id,
                              bool quarantine) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    bool ok = db_->quarantine_media(media_id, quarantine);

    json response;
    response["success"]      = ok;
    response["user_id"]      = user_id;
    response["media_id"]     = media_id;
    response["quarantined"]  = quarantine;
    response["message"]      = quarantine
        ? "Media quarantined successfully"
        : "Media unquarantined successfully";
    return response;
  }

  // ========================================================================
  // User Pushers
  // ========================================================================

  json list_user_pushers(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    auto pushers = db_->get_user_pushers(user_id);

    json result;
    result["user_id"] = user_id;
    result["total"]   = pushers.size();

    json pushers_arr = json::array();
    for (auto& p : pushers) {
      json entry;
      entry["pusher_id"]          = p.pusher_id;
      entry["pushkey"]            = p.pushkey;
      entry["kind"]               = p.kind;
      entry["app_id"]             = p.app_id;
      entry["app_display_name"]   = p.app_display_name;
      entry["device_display_name"] = p.device_display_name;
      entry["profile_tag"]        = p.profile_tag;
      entry["lang"]               = p.lang;
      entry["data_url"]           = p.data_url;
      entry["data_format"]        = p.data_format;
      entry["enabled"]            = p.enabled;
      entry["append_content"]     = p.append_content;
      entry["consecutive_failures"] = p.consecutive_failures;

      if (p.created_ts > 0) {
        entry["created_ts"]         = p.created_ts;
        entry["created_ts_display"] = ts_to_iso8601(p.created_ts);
      }
      if (p.last_success_ts > 0) {
        entry["last_success_ts"]         = p.last_success_ts;
        entry["last_success_display"]    = ts_to_iso8601(p.last_success_ts);
        entry["last_success_days_ago"]   = ms_to_days(now_ms() - p.last_success_ts);
      }
      if (p.last_failure_ts > 0) {
        entry["last_failure_ts"]         = p.last_failure_ts;
        entry["last_failure_display"]    = ts_to_iso8601(p.last_failure_ts);
      }

      // Status
      if (p.consecutive_failures > 10) {
        entry["status"] = "failing";
      } else if (!p.enabled) {
        entry["status"] = "disabled";
      } else if (p.last_success_ts > 0) {
        entry["status"] = "active";
      } else {
        entry["status"] = "pending";
      }

      pushers_arr.push_back(entry);
    }
    result["pushers"] = pushers_arr;

    return result;
  }

  json get_pusher_info(const std::string& user_id, int64_t pusher_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    auto p = db_->get_pusher(user_id, pusher_id);
    if (!p.has_value()) {
      return build_error(404, "M_NOT_FOUND",
                         "Pusher not found: " + std::to_string(pusher_id));
    }

    json entry;
    entry["pusher_id"]          = p->pusher_id;
    entry["user_id"]            = user_id;
    entry["pushkey"]            = p->pushkey;
    entry["kind"]               = p->kind;
    entry["app_id"]             = p->app_id;
    entry["app_display_name"]   = p->app_display_name;
    entry["device_display_name"] = p->device_display_name;
    entry["profile_tag"]        = p->profile_tag;
    entry["lang"]               = p->lang;
    entry["data_url"]           = p->data_url;
    entry["data_format"]        = p->data_format;
    entry["enabled"]            = p->enabled;
    entry["append_content"]     = p->append_content;
    entry["consecutive_failures"] = p->consecutive_failures;
    entry["rate_limit_count"]   = p->rate_limit_count;
    entry["rate_limit_period_ms"] = p->rate_limit_period_ms;

    if (p->created_ts > 0) {
      entry["created_ts"]         = p->created_ts;
      entry["created_ts_display"] = ts_to_iso8601(p->created_ts);
    }

    return entry;
  }

  json delete_user_pusher(const std::string& user_id, int64_t pusher_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    bool ok = db_->delete_pusher(user_id, pusher_id);

    json response;
    response["success"]   = ok;
    response["user_id"]   = user_id;
    response["pusher_id"] = pusher_id;
    response["deleted"]   = ok;
    return response;
  }

  json delete_all_user_pushers(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    int64_t count = db_->delete_all_pushers(user_id);

    json response;
    response["success"]         = true;
    response["user_id"]         = user_id;
    response["pushers_deleted"] = count;
    return response;
  }

  // ========================================================================
  // User Connections
  // ========================================================================

  json list_user_connections(const std::string& user_id,
                              bool active_only = false,
                              int64_t from = 0,
                              int64_t limit = kDefaultLimit) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    if (limit < 1) limit = kDefaultLimit;
    if (limit > kMaxLimit) limit = kMaxLimit;
    if (limit > kMaxConnectionsPerQuery) limit = kMaxConnectionsPerQuery;

    auto conns = db_->get_user_connections(
        user_id, limit + 1, from, active_only);

    json conns_arr = json::array();
    bool has_more = false;
    size_t count = 0;
    int64_t now = now_ms();

    for (auto& c : conns) {
      if (count >= static_cast<size_t>(limit)) {
        has_more = true;
        break;
      }
      json entry;
      entry["connection_id"]    = c.connection_id;
      entry["device_id"]        = c.device_id;
      entry["ip_address"]       = c.ip_address;
      entry["user_agent"]       = c.user_agent;
      entry["connection_type"]  = c.connection_type;
      entry["is_active"]        = c.is_active;
      entry["connected_at"]     = c.connected_at;
      entry["disconnected_at"]  = c.disconnected_at;
      entry["last_activity_ts"] = c.last_activity_ts;

      if (c.connected_at > 0) {
        entry["connected_at_display"] = ts_to_iso8601(c.connected_at);
        entry["connection_age_days"]  = ms_to_days(now - c.connected_at);
      }
      if (c.last_activity_ts > 0) {
        entry["last_activity_display"] = ts_to_iso8601(c.last_activity_ts);
        entry["last_activity_seconds_ago"] = (now - c.last_activity_ts) / 1000;
      }
      if (c.token_expires_at > 0) {
        entry["token_expires_at"] = ts_to_iso8601(c.token_expires_at);
        if (c.token_expires_at > now) {
          entry["token_expires_in_seconds"] =
              (c.token_expires_at - now) / 1000;
        } else {
          entry["token_expired"] = true;
        }
      }

      // Connection duration
      if (c.connected_at > 0 && c.disconnected_at > 0) {
        entry["connection_duration_seconds"] =
            (c.disconnected_at - c.connected_at) / 1000;
      } else if (c.is_active && c.connected_at > 0) {
        entry["connection_duration_seconds"] =
            (now - c.connected_at) / 1000;
      }

      conns_arr.push_back(entry);
      count++;
    }

    int64_t total = db_->get_user_connection_count(user_id, active_only);

    json result;
    result["connections"] = conns_arr;
    result["total"]       = total;
    result["active_only"] = active_only;
    result["next_token"]  = has_more ? std::to_string(from + limit) : "";
    result["offset"]      = from;
    result["limit"]       = limit;
    result["user_id"]     = user_id;

    return result;
  }

  json revoke_user_connections(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    bool ok = db_->revoke_user_connections(user_id);

    json response;
    response["success"]      = ok;
    response["user_id"]      = user_id;
    response["revoked"]      = ok;
    response["message"]      = "All active connections revoked";
    return response;
  }

  json revoke_specific_connection(const std::string& user_id,
                                   int64_t connection_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    bool ok = db_->revoke_connection(user_id, connection_id);

    json response;
    response["success"]       = ok;
    response["user_id"]       = user_id;
    response["connection_id"] = connection_id;
    response["revoked"]       = ok;
    return response;
  }

  // ========================================================================
  // User Threepid Management
  // ========================================================================

  json add_user_threepid(const std::string& user_id, const json& body) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    std::string medium = json_get_str(body, "medium", "");
    std::string address = json_get_str(body, "address", "");
    bool validated = json_get_bool(body, "validated", true);

    if (medium.empty() || address.empty()) {
      return build_error(400, "M_MISSING_PARAM",
                         "Missing required fields: medium, address");
    }

    if (medium == "email" && !is_valid_email(address)) {
      return build_error(400, "M_INVALID_EMAIL",
                         "Invalid email address: " + address);
    }

    if (medium == "msisdn" && !is_valid_phone(address)) {
      return build_error(400, "M_INVALID_PHONE",
                         "Invalid phone number: " + address);
    }

    bool ok = db_->add_threepid(user_id, medium, address, validated);

    json response;
    response["success"]   = ok;
    response["user_id"]   = user_id;
    response["medium"]    = medium;
    response["address"]   = address;
    response["validated"] = validated;
    return response;
  }

  json remove_user_threepid(const std::string& user_id,
                             const std::string& medium,
                             const std::string& address) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    bool ok = db_->remove_threepid(user_id, medium, address);

    json response;
    response["success"] = ok;
    response["user_id"] = user_id;
    response["medium"]  = medium;
    response["address"] = address;
    response["removed"] = ok;
    return response;
  }

  json validate_user_threepid(const std::string& user_id,
                               const std::string& medium,
                               const std::string& address) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    bool ok = db_->validate_threepid(user_id, medium, address);

    json response;
    response["success"]   = ok;
    response["user_id"]   = user_id;
    response["medium"]    = medium;
    response["address"]   = address;
    response["validated"] = ok;
    return response;
  }

  // ========================================================================
  // User Search
  // ========================================================================

  json search_users(const std::string& search_term,
                     const std::string& search_field = "all",
                     int64_t limit = 50) {
    if (search_term.empty()) {
      return build_error(400, "M_MISSING_PARAM",
                         "Missing required parameter: search_term");
    }

    if (limit < 1) limit = 50;
    if (limit > kMaxSearchResults) limit = kMaxSearchResults;

    try {
      std::string sanitized = sanitize_sql_like(search_term);
      std::vector<std::string> conditions;
      std::vector<std::string> params;

      if (search_field == "name" || search_field == "all") {
        conditions.push_back(
            "name LIKE '%' || ? || '%' ESCAPE '\\'");
        params.push_back(sanitized);
      }
      if (search_field == "display_name" || search_field == "all") {
        conditions.push_back(
            "name IN (SELECT user_id FROM profiles "
            "WHERE displayname LIKE '%' || ? || '%' ESCAPE '\\')");
        params.push_back(sanitized);
      }
      if (search_field == "email" || search_field == "all") {
        conditions.push_back(
            "name IN (SELECT user_id FROM user_threepids "
            "WHERE medium = 'email' AND address LIKE '%' || ? || '%' ESCAPE '\\')");
        params.push_back(sanitized);
      }
      if (search_field == "ip" || search_field == "all") {
        conditions.push_back(
            "name IN (SELECT user_id FROM devices "
            "WHERE ip LIKE '%' || ? || '%' ESCAPE '\\')");
        params.push_back(sanitized);
      }
      if (search_field == "device_id" || search_field == "all") {
        conditions.push_back(
            "name IN (SELECT user_id FROM devices "
            "WHERE device_id LIKE '%' || ? || '%' ESCAPE '\\')");
        params.push_back(sanitized);
      }

      std::string where_clause = join(conditions, " OR ");
      auto users = db_->query_users(
          where_clause, params, "creation_ts DESC", limit, 0);

      json users_arr = json::array();
      for (auto& rec : users) {
        json u;
        u["name"]          = rec.user_id;
        u["displayname"]   = db_->get_display_name(rec.user_id);
        u["avatar_url"]    = db_->get_avatar_url(rec.user_id);
        u["is_guest"]      = rec.is_guest;
        u["admin"]         = rec.is_admin;
        u["deactivated"]   = rec.deactivated;
        u["user_type"]     = rec.user_type;
        u["locked"]        = rec.locked;
        u["shadow_banned"] = rec.shadow_banned;
        u["creation_ts"]   = rec.creation_ts;
        if (rec.creation_ts > 0) {
          u["creation_ts_display"] = ts_to_iso8601(rec.creation_ts);
        }
        u["last_seen_ts"]  = rec.last_seen_ts;
        if (rec.last_seen_ts > 0) {
          u["last_seen_display"] = ts_to_iso8601(rec.last_seen_ts);
        }

        // Quick stats
        u["device_count"]  = db_->get_device_count(rec.user_id);
        u["room_count"]    = db_->get_user_room_count(rec.user_id, "join");

        users_arr.push_back(u);
      }

      json result;
      result["users"]       = users_arr;
      result["total"]       = users_arr.size();
      result["search_term"] = search_term;
      result["search_field"] = search_field;
      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error searching users: ") + e.what());
    }
  }

  // ========================================================================
  // User Statistics
  // ========================================================================

  json get_user_stats(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    AdminUserStats stats;
    stats.joined_rooms      = db_->get_user_room_count(user_id, "join");
    stats.invited_rooms     = db_->get_user_room_count(user_id, "invite");
    stats.left_rooms        = db_->get_user_room_count(user_id, "leave");
    stats.banned_rooms      = db_->get_user_room_count(user_id, "ban");
    stats.total_rooms       = stats.joined_rooms + stats.invited_rooms +
                              stats.left_rooms + stats.banned_rooms;
    stats.total_media       = db_->get_user_media_count(user_id);
    stats.total_media_bytes = db_->get_user_media_total_bytes(user_id);
    stats.total_devices     = db_->get_device_count(user_id);
    stats.total_pushers     = static_cast<int64_t>(
        db_->get_user_pushers(user_id).size());
    stats.total_threepids   = static_cast<int64_t>(
        db_->get_user_threepids(user_id).size());
    stats.total_connections = db_->get_user_connection_count(user_id);
    stats.active_sessions   = db_->get_user_connection_count(user_id, true);
    stats.total_push_rules  = db_->get_push_rules_count(user_id);
    stats.total_account_data = db_->get_account_data_count(user_id);
    stats.total_events_sent = db_->get_events_sent_count(user_id);

    auto devices = db_->get_user_devices(user_id);
    int64_t now = now_ms();
    for (auto& dev : devices) {
      if (dev.last_seen_ts > 0 && (now - dev.last_seen_ts) < kOneWeekMs) {
        stats.active_devices++;
      }
      if (dev.last_seen_ts > stats.last_active_ts) {
        stats.last_active_ts = dev.last_seen_ts;
      }
    }

    json result;
    result["user_id"]            = user_id;
    result["joined_rooms"]       = stats.joined_rooms;
    result["invited_rooms"]      = stats.invited_rooms;
    result["left_rooms"]         = stats.left_rooms;
    result["banned_rooms"]       = stats.banned_rooms;
    result["total_rooms"]        = stats.total_rooms;
    result["direct_rooms"]       = stats.direct_rooms;
    result["total_media"]        = stats.total_media;
    result["total_media_bytes"]  = stats.total_media_bytes;
    result["total_media_display"] = format_bytes(stats.total_media_bytes);
    result["total_devices"]      = stats.total_devices;
    result["active_devices"]     = stats.active_devices;
    result["total_sessions"]     = stats.total_connections;
    result["active_sessions"]    = stats.active_sessions;
    result["total_pushers"]      = stats.total_pushers;
    result["total_threepids"]    = stats.total_threepids;
    result["total_push_rules"]   = stats.total_push_rules;
    result["total_account_data"] = stats.total_account_data;
    result["events_sent"]        = stats.total_events_sent;

    if (stats.last_active_ts > 0) {
      result["last_active_ts"]     = stats.last_active_ts;
      result["last_active_display"] = ts_to_iso8601(stats.last_active_ts);
      result["last_active_days_ago"] =
          ms_to_days(now - stats.last_active_ts);
    }

    return result;
  }

  // ========================================================================
  // GDPR Data Export (for a single user)
  // ========================================================================

  json export_user_data(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid user_id: " + user_id);
    }

    auto rec = db_->get_user_record(user_id);
    if (!rec.has_value()) {
      return build_error(404, "M_NOT_FOUND",
                         "User not found: " + user_id);
    }

    json export_data;

    // Metadata
    export_data["export_metadata"] = {
        {"exported_at", now_iso8601()},
        {"exported_at_ts", now_ms()},
        {"server_name", server_name_},
        {"server_version", kServerVersion},
        {"export_format_version", "1.0"},
        {"user_id", user_id}
    };

    // Profile
    export_data["profile"] = {
        {"display_name", db_->get_display_name(user_id)},
        {"avatar_url", db_->get_avatar_url(user_id)}
    };

    // Account info
    export_data["account"] = format_user_detail(rec.value());

    // Devices
    auto devices = db_->get_user_devices(user_id);
    json devs = json::array();
    for (auto& dev : devices) {
      json d;
      d["device_id"]    = dev.device_id;
      d["display_name"] = dev.display_name;
      d["device_type"]  = dev.device_type;
      d["last_seen_ip"] = dev.last_seen_ip;
      d["last_seen_ua"] = dev.user_agent;
      d["last_seen_ts"] = dev.last_seen_ts;
      devs.push_back(d);
    }
    export_data["devices"] = devs;

    // Threepids
    export_data["threepids"] = db_->get_user_threepids(user_id);

    // External IDs
    export_data["external_ids"] = db_->get_user_external_ids(user_id);

    // Room memberships (summary)
    export_data["rooms"] = json::object();
    export_data["rooms"]["joined_count"]  = db_->get_user_room_count(user_id, "join");
    export_data["rooms"]["invited_count"] = db_->get_user_room_count(user_id, "invite");
    export_data["rooms"]["left_count"]    = db_->get_user_room_count(user_id, "leave");
    export_data["rooms"]["banned_count"]  = db_->get_user_room_count(user_id, "ban");

    // Media count
    export_data["media_count"] = db_->get_user_media_count(user_id);

    // Connections count
    export_data["connections_count"] = db_->get_user_connection_count(user_id);

    // Pushers
    auto pushers = db_->get_user_pushers(user_id);
    json ps = json::array();
    for (auto& p : pushers) {
      json jp;
      jp["kind"] = p.kind;
      jp["app_id"] = p.app_id;
      jp["enabled"] = p.enabled;
      ps.push_back(jp);
    }
    export_data["pushers"] = ps;

    return export_data;
  }

private:
  // ====================================================================
  // Formatting helpers
  // ====================================================================

  json format_user_summary(const AdminUserRecord& rec) {
    json u;
    u["name"]          = rec.user_id;
    u["displayname"]   = db_->get_display_name(rec.user_id);
    u["avatar_url"]    = db_->get_avatar_url(rec.user_id);
    u["is_guest"]      = rec.is_guest;
    u["admin"]         = rec.is_admin;
    u["deactivated"]   = rec.deactivated;
    u["user_type"]     = rec.user_type;
    u["shadow_banned"] = rec.shadow_banned;
    u["locked"]        = rec.locked;
    u["suspended"]     = rec.suspended;
    u["creation_ts"]   = rec.creation_ts;
    u["last_seen_ts"]  = rec.last_seen_ts;

    if (rec.creation_ts > 0) {
      u["creation_ts_display"] = ts_to_iso8601(rec.creation_ts);
      u["account_age_days"]    = ms_to_days(now_ms() - rec.creation_ts);
    }
    if (rec.last_seen_ts > 0) {
      u["last_seen_display"]   = ts_to_iso8601(rec.last_seen_ts);
      u["last_seen_days_ago"]  = ms_to_days(now_ms() - rec.last_seen_ts);
    }
    if (rec.deactivation_ts > 0) {
      u["deactivation_ts_display"] = ts_to_iso8601(rec.deactivation_ts);
    }
    if (!rec.deactivation_reason.empty()) {
      u["deactivation_reason"] = rec.deactivation_reason;
    }
    if (!rec.suspension_reason.empty()) {
      u["suspension_reason"] = rec.suspension_reason;
    }
    if (rec.suspended && rec.suspension_end_ts > 0) {
      u["suspension_end_ts"] = rec.suspension_end_ts;
      u["suspension_end_display"] = ts_to_iso8601(rec.suspension_end_ts);
    }
    if (!rec.appservice_id.empty()) {
      u["appservice_id"] = rec.appservice_id;
    }

    return u;
  }

  json format_user_detail(const AdminUserRecord& rec) {
    json u = format_user_summary(rec);

    // Additional detailed fields
    u["password_hash"]          = rec.password_hash;
    u["consent_version"]        = rec.consent_version;
    u["consent_given"]          = !rec.consent_version.empty();
    u["consent_server_notice_sent"] = rec.consent_notice_sent;
    u["external_auth_provider"] = rec.external_auth_provider;
    u["failed_login_attempts"]  = rec.failed_login_attempts;

    if (rec.consent_ts > 0) {
      u["consent_ts"]         = rec.consent_ts;
      u["consent_ts_display"] = ts_to_iso8601(rec.consent_ts);
    }

    if (rec.locked) {
      u["lock_ts"] = rec.lock_ts;
      if (rec.lock_ts > 0) {
        u["lock_ts_display"] = ts_to_iso8601(rec.lock_ts);
      }
      if (!rec.lock_reason.empty()) {
        u["lock_reason"] = rec.lock_reason;
      }
    }

    if (rec.suspended) {
      u["suspension_ts"] = rec.suspension_ts;
      if (rec.suspension_ts > 0) {
        u["suspension_ts_display"] = ts_to_iso8601(rec.suspension_ts);
      }
    }

    u["is_support"] = (rec.user_type == kSupportUserType);
    u["is_bot"]     = (rec.user_type == kBotUserType);

    return u;
  }

  std::shared_ptr<AdminUserDatabase> db_;
  std::string server_name_;
};

// ============================================================================
// 4. AdminUsersAPI — Top-level API facade
// ============================================================================

class AdminUsersAPI {
public:
  AdminUsersAPI(storage::DatabasePool& db, const std::string& server_name)
      : user_manager_(std::make_unique<AdminUserManager>(db, server_name)),
        db_ref_(db),
        server_name_(server_name) {}

  // ---- User Listing ----
  json handle_list_users(const json& query_params) {
    AdminUserFilter filter;
    AdminUserSortField sort = AdminUserSortField::NAME;
    bool sort_asc = true;
    int64_t from = 0;
    int64_t limit = kDefaultLimit;

    // Parse query parameters
    if (query_params.contains("from") || query_params.contains("offset")) {
      from = json_get_int(query_params, "from",
             json_get_int(query_params, "offset", 0));
    }
    if (query_params.contains("limit")) {
      limit = json_get_int(query_params, "limit", kDefaultLimit);
    }

    // Sort
    std::string order_by = json_get_str(query_params, "order_by", "name");
    if (order_by == "creation_ts") sort = AdminUserSortField::CREATION_TS;
    else if (order_by == "last_seen_ts") sort = AdminUserSortField::LAST_SEEN_TS;
    else if (order_by == "user_type") sort = AdminUserSortField::USER_TYPE;
    else if (order_by == "admin") sort = AdminUserSortField::ADMIN;
    else if (order_by == "deactivated") sort = AdminUserSortField::DEACTIVATED;
    else if (order_by == "locked") sort = AdminUserSortField::LOCKED;
    else if (order_by == "shadow_banned") sort = AdminUserSortField::SHADOW_BANNED;
    else if (order_by == "displayname") sort = AdminUserSortField::DISPLAY_NAME;
    else if (order_by == "media_count") sort = AdminUserSortField::MEDIA_COUNT;
    else if (order_by == "room_count") sort = AdminUserSortField::ROOM_COUNT;
    else if (order_by == "device_count") sort = AdminUserSortField::DEVICE_COUNT;

    std::string dir = json_get_str(query_params, "dir", "asc");
    sort_asc = (dir != "desc");

    // Filters
    filter.name_contains = query_params.contains("name")
        ? std::optional<std::string>(json_get_str(query_params, "name"))
        : std::nullopt;

    filter.name_starts_with = query_params.contains("name_startswith")
        ? std::optional<std::string>(json_get_str(query_params, "name_startswith"))
        : std::nullopt;

    filter.display_name_contains = query_params.contains("display_name")
        ? std::optional<std::string>(json_get_str(query_params, "display_name"))
        : std::nullopt;

    filter.user_type = query_params.contains("user_type")
        ? std::optional<std::string>(json_get_str(query_params, "user_type"))
        : std::nullopt;

    if (query_params.contains("guests")) {
      filter.is_guest = json_get_bool(query_params, "guests");
    }
    if (query_params.contains("admins")) {
      filter.is_admin = json_get_bool(query_params, "admins");
    }
    if (query_params.contains("deactivated")) {
      filter.deactivated = json_get_bool(query_params, "deactivated");
    }
    if (query_params.contains("locked")) {
      filter.locked = json_get_bool(query_params, "locked");
    }
    if (query_params.contains("suspended")) {
      filter.suspended = json_get_bool(query_params, "suspended");
    }
    if (query_params.contains("shadow_banned")) {
      filter.shadow_banned = json_get_bool(query_params, "shadow_banned");
    }

    return user_manager_->list_users(filter, sort, sort_asc, from, limit);
  }

  // ---- User Creation ----
  json handle_create_user(const json& body) {
    return user_manager_->create_user(body);
  }

  // ---- User Update ----
  json handle_update_user(const std::string& user_id, const json& body) {
    return user_manager_->update_user(user_id, body);
  }

  // ---- User Info ----
  json handle_get_user_info(const std::string& user_id) {
    return user_manager_->get_user_info(user_id);
  }

  // ---- Password Reset ----
  json handle_reset_password(const std::string& user_id, const json& body) {
    return user_manager_->reset_password(user_id, body);
  }

  // ---- Deactivate / Reactivate ----
  json handle_deactivate_user(const std::string& user_id, const json& body) {
    return user_manager_->deactivate_user(user_id, body);
  }

  json handle_reactivate_user(const std::string& user_id) {
    return user_manager_->reactivate_user(user_id);
  }

  // ---- Lock / Suspend / Shadow Ban ----
  json handle_lock_user(const std::string& user_id, const json& body) {
    return user_manager_->lock_user(user_id, body);
  }

  json handle_suspend_user(const std::string& user_id, const json& body) {
    return user_manager_->suspend_user(user_id, body);
  }

  json handle_shadow_ban(const std::string& user_id, const json& body) {
    return user_manager_->set_shadow_ban(user_id, body);
  }

  // ---- Account Validity ----
  json handle_set_account_validity(const std::string& user_id,
                                     const json& body) {
    return user_manager_->set_account_validity(user_id, body);
  }

  json handle_renew_account_validity(const std::string& user_id,
                                       const json& body) {
    return user_manager_->renew_account_validity(user_id, body);
  }

  // ---- Devices ----
  json handle_list_user_devices(const std::string& user_id) {
    return user_manager_->list_user_devices(user_id);
  }

  json handle_get_device(const std::string& user_id,
                           const std::string& device_id) {
    return user_manager_->get_device_info(user_id, device_id);
  }

  json handle_update_device(const std::string& user_id,
                              const std::string& device_id,
                              const json& body) {
    return user_manager_->update_device(user_id, device_id, body);
  }

  json handle_delete_device(const std::string& user_id,
                              const std::string& device_id) {
    return user_manager_->delete_user_device(user_id, device_id);
  }

  json handle_delete_all_devices(const std::string& user_id) {
    return user_manager_->delete_all_user_devices(user_id);
  }

  // ---- Rooms ----
  json handle_list_user_rooms(const std::string& user_id,
                                const json& query_params) {
    std::string membership = json_get_str(query_params, "membership", "");
    int64_t from = json_get_int(query_params, "from", 0);
    int64_t limit = json_get_int(query_params, "limit", kDefaultLimit);
    return user_manager_->list_user_rooms(user_id, membership, from, limit);
  }

  // ---- Media ----
  json handle_list_user_media(const std::string& user_id,
                                const json& query_params) {
    int64_t from = json_get_int(query_params, "from", 0);
    int64_t limit = json_get_int(query_params, "limit", kDefaultLimit);
    std::string sort_by = json_get_str(query_params, "sort_by", "created_ts");
    std::string sort_dir = json_get_str(query_params, "sort_dir", "desc");
    return user_manager_->list_user_media(user_id, from, limit, sort_by, sort_dir);
  }

  json handle_delete_user_media(const std::string& user_id,
                                  const std::string& media_id) {
    return user_manager_->delete_user_media(user_id, media_id);
  }

  json handle_delete_all_user_media(const std::string& user_id) {
    return user_manager_->delete_all_user_media(user_id);
  }

  json handle_quarantine_media(const std::string& user_id,
                                 const std::string& media_id,
                                 bool quarantine) {
    return user_manager_->quarantine_user_media(user_id, media_id, quarantine);
  }

  // ---- Pushers ----
  json handle_list_user_pushers(const std::string& user_id) {
    return user_manager_->list_user_pushers(user_id);
  }

  json handle_get_pusher(const std::string& user_id, int64_t pusher_id) {
    return user_manager_->get_pusher_info(user_id, pusher_id);
  }

  json handle_delete_pusher(const std::string& user_id, int64_t pusher_id) {
    return user_manager_->delete_user_pusher(user_id, pusher_id);
  }

  json handle_delete_all_pushers(const std::string& user_id) {
    return user_manager_->delete_all_user_pushers(user_id);
  }

  // ---- Connections ----
  json handle_list_user_connections(const std::string& user_id,
                                      const json& query_params) {
    bool active_only = json_get_bool(query_params, "active_only", false);
    int64_t from = json_get_int(query_params, "from", 0);
    int64_t limit = json_get_int(query_params, "limit", kDefaultLimit);
    return user_manager_->list_user_connections(
        user_id, active_only, from, limit);
  }

  json handle_revoke_connections(const std::string& user_id) {
    return user_manager_->revoke_user_connections(user_id);
  }

  json handle_revoke_connection(const std::string& user_id,
                                  int64_t connection_id) {
    return user_manager_->revoke_specific_connection(user_id, connection_id);
  }

  // ---- Threepids ----
  json handle_add_threepid(const std::string& user_id, const json& body) {
    return user_manager_->add_user_threepid(user_id, body);
  }

  json handle_remove_threepid(const std::string& user_id,
                               const std::string& medium,
                               const std::string& address) {
    return user_manager_->remove_user_threepid(user_id, medium, address);
  }

  json handle_validate_threepid(const std::string& user_id,
                                  const std::string& medium,
                                  const std::string& address) {
    return user_manager_->validate_user_threepid(user_id, medium, address);
  }

  // ---- Search ----
  json handle_search_users(const json& query_params) {
    std::string search_term = json_get_str(query_params, "search_term",
                              json_get_str(query_params, "q", ""));
    std::string search_field = json_get_str(query_params, "search_field", "all");
    int64_t limit = json_get_int(query_params, "limit", 50);
    return user_manager_->search_users(search_term, search_field, limit);
  }

  // ---- Stats ----
  json handle_get_user_stats(const std::string& user_id) {
    return user_manager_->get_user_stats(user_id);
  }

  // ---- Export ----
  json handle_export_user_data(const std::string& user_id) {
    return user_manager_->export_user_data(user_id);
  }

private:
  std::unique_ptr<AdminUserManager> user_manager_;
  storage::DatabasePool& db_ref_;
  std::string server_name_;
};

}  // namespace progressive
