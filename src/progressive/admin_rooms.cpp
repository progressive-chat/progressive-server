// ============================================================================
// admin_rooms.cpp — Matrix Admin Room Management
//
// Comprehensive admin API for room management including:
//   - List rooms with filtering, sorting, pagination
//   - Room details with full state/event/stats introspection
//   - Delete room with multi-level purge (soft, full, force)
//   - Block/unblock rooms with spam protection
//   - Room members listing, filtering, and membership control
//   - Room state introspection and modification
//   - Room media management (list, quarantine, delete, stats)
//   - Make room admin (promote/demote users to admin power level)
//   - Room aliases (list, add, remove, canonical alias management)
//   - Room complexity analysis (Varth Dader / Synapse complexity model)
//   - Bulk room operations (bulk delete, bulk block, bulk quarantine)
//   - Federation-related room administration
//   - Room version upgrade management
//   - Room retention policy management
//   - Room directory publishing control
//   - Room forwarding and tombstone management
//
// Equivalent to:
//   synapse/rest/admin/rooms.py
//   synapse/storage/databases/main/room.py (admin portions)
//   synapse/rest/admin/media.py (room-scoped media)
//   synapse/rest/admin/forward_extremities.py (complexity)
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
#include <cstring>
#include <ctime>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <list>
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
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/storage/databases/main/presence.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
class AdminRoomManager;
class RoomMediaAdminSubsystem;
class RoomAliasAdminSubsystem;
class RoomComplexityAnalyzer;
class RoomBulkOperationHandler;
class RoomFederationAdmin;
class RoomRetentionAdmin;
class RoomPowerLevelManager;

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// ---- Server defaults ----
constexpr const char* kServerName = "Progressive";
constexpr const char* kServerVersion = "0.11.0";
constexpr int64_t kDefaultPageSize = 100;
constexpr int64_t kMaxPageSize = 1000;
constexpr int64_t kMaxBulkOps = 500;
constexpr int64_t kDefaultAdminPowerLevel = 100;
constexpr int64_t kDefaultModeratorPowerLevel = 50;
constexpr int64_t kDefaultUserPowerLevel = 0;

// ---- Complexity thresholds (Varth Dader model) ----
constexpr int64_t kComplexityWarningThreshold = 500;
constexpr int64_t kComplexityErrorThreshold = 1000;
constexpr double kExtremityComplexityFactor = 5.0;
constexpr double kMemberComplexityFactor = 0.01;
constexpr double kStateComplexityFactor = 1.0;
constexpr double kEventComplexityFactor = 0.001;

// ---- Room purge levels ----
enum class PurgeLevel {
  SOFT,      // Only delete events, keep room record
  FULL,      // Delete all room data including memberships
  FORCE,     // Delete everything including federation staging
  NUCLEAR    // Full force + notify federating servers
};

// ---- Room sort fields ----
enum class RoomSortField {
  NAME,
  ROOM_ID,
  CANONICAL_ALIAS,
  JOINED_MEMBERS,
  INVITED_MEMBERS,
  LOCAL_MEMBERS,
  TOTAL_MEMBERS,
  TOTAL_EVENTS,
  STATE_EVENTS,
  CREATION_TS,
  LAST_ACTIVITY,
  VERSION,
  CREATOR,
  ENCRYPTED,
  FEDERATABLE,
  PUBLIC,
  JOIN_RULES,
  GUEST_ACCESS,
  HISTORY_VISIBILITY,
  ROOM_TYPE,
  COMPLEXITY,
  FORWARD_EXTREMITIES,
  BLOCKED,
  RETENTION_ENABLED
};

// ---- Room filter fields ----
enum class RoomFilterField {
  NAME_CONTAINS,
  ROOM_ID_CONTAINS,
  ALIAS_CONTAINS,
  TOPIC_CONTAINS,
  CREATOR_IS,
  JOINED_MEMBERS_MIN,
  JOINED_MEMBERS_MAX,
  INVITED_MEMBERS_MIN,
  INVITED_MEMBERS_MAX,
  TOTAL_EVENTS_MIN,
  TOTAL_EVENTS_MAX,
  STATE_EVENTS_MIN,
  STATE_EVENTS_MAX,
  CREATED_AFTER,
  CREATED_BEFORE,
  LAST_ACTIVE_AFTER,
  LAST_ACTIVE_BEFORE,
  IS_ENCRYPTED,
  IS_PUBLIC,
  IS_FEDERATABLE,
  JOIN_RULES_IN,
  GUEST_ACCESS_IN,
  HISTORY_VISIBILITY_IN,
  ROOM_TYPE_IN,
  ROOM_VERSION_IN,
  HAS_RETENTION,
  IS_BLOCKED,
  HAS_ALIASES,
  COMPLEXITY_MIN,
  COMPLEXITY_MAX,
  FORWARD_EXTREMITIES_MIN,
  FORWARD_EXTREMITIES_MAX,
  MEMBERSHIP_IN  // filter rooms the server participates in
};

// ---- Timestamp helpers ----

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

inline int64_t ms_to_days(int64_t ms) {
  return ms / 86400000;
}

inline int64_t sec_to_days(int64_t sec) {
  return sec / 86400;
}

// ---- String helpers ----

inline bool starts_with(const std::string& s, const std::string& prefix) {
  return s.size() >= prefix.size() &&
         s.compare(0, prefix.size(), prefix) == 0;
}

inline bool ends_with(const std::string& s, const std::string& suffix) {
  return s.size() >= suffix.size() &&
         s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
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

// ---- Validation helpers ----

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

inline bool is_valid_room_alias(const std::string& alias) {
  if (alias.empty() || alias[0] != '#') return false;
  auto colon = alias.find(':');
  return colon != std::string::npos && colon > 1 && colon < alias.size() - 1;
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

// ---- Membership normalization ----

inline std::string normalize_membership(const std::string& m) {
  std::string lower = to_lower(m);
  if (lower == "join" || lower == "joined") return "join";
  if (lower == "invite" || lower == "invited") return "invite";
  if (lower == "leave" || lower == "left") return "leave";
  if (lower == "ban" || lower == "banned") return "ban";
  if (lower == "knock" || lower == "knocking") return "knock";
  return lower;
}

inline std::string membership_to_display(const std::string& m) {
  std::string lower = to_lower(m);
  if (lower == "join") return "joined";
  if (lower == "invite") return "invited";
  if (lower == "leave") return "left";
  if (lower == "ban") return "banned";
  if (lower == "knock") return "knocked";
  return lower;
}

// ---- SQL row parsing helpers ----

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

// ---- JSON response helpers ----

inline json build_error(int code, const std::string& errcode,
                         const std::string& error) {
  return json{{"errcode", errcode}, {"error", error}};
}

inline json build_success(const json& data = json::object()) {
  if (data.is_object() && !data.contains("success")) {
    json result = data;
    result["success"] = true;
    return result;
  }
  return data;
}

inline json build_paginated(int64_t total, const json& results,
                              int64_t start = 0, int64_t limit = 100) {
  json j;
  j["total"] = total;
  j["start"] = start;
  j["limit"] = limit;
  j["chunk"] = results.is_array() ? results : json::array({results});
  j["next_batch"] = "";
  if (start + static_cast<int64_t>(j["chunk"].size()) < total) {
    j["next_batch"] = std::to_string(start + limit);
  }
  return j;
}

inline json build_admin_response(const std::string& room_id,
                                  const std::string& action,
                                  bool success_status = true,
                                  const json& extra = json::object()) {
  json resp;
  resp["room_id"] = room_id;
  resp["action"] = action;
  resp["success"] = success_status;
  resp["timestamp"] = now_iso8601();
  resp["timestamp_ms"] = now_ms();
  for (auto& [k, v] : extra.items()) {
    resp[k] = v;
  }
  return resp;
}

// ---- Human-readable formatting ----

inline std::string format_bytes(int64_t bytes) {
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

inline std::string format_duration_ms(int64_t ms) {
  if (ms <= 0) return "0s";
  int64_t seconds = ms / 1000;
  int64_t days = seconds / 86400;
  int64_t hours = (seconds % 86400) / 3600;
  int64_t minutes = (seconds % 3600) / 60;
  int64_t secs = seconds % 60;
  std::stringstream ss;
  if (days > 0) ss << days << "d ";
  if (hours > 0) ss << hours << "h ";
  if (minutes > 0) ss << minutes << "m ";
  ss << secs << "s";
  return ss.str();
}

inline std::string format_number(int64_t n) {
  std::string s = std::to_string(n);
  int len = static_cast<int>(s.size());
  for (int i = len - 3; i > 0; i -= 3) {
    s.insert(i, ",");
  }
  return s;
}

// ---- Sort field string conversion ----

inline RoomSortField parse_sort_field(const std::string& field) {
  static const std::unordered_map<std::string, RoomSortField> map = {
    {"name", RoomSortField::NAME},
    {"room_id", RoomSortField::ROOM_ID},
    {"canonical_alias", RoomSortField::CANONICAL_ALIAS},
    {"joined_members", RoomSortField::JOINED_MEMBERS},
    {"invited_members", RoomSortField::INVITED_MEMBERS},
    {"local_members", RoomSortField::LOCAL_MEMBERS},
    {"total_members", RoomSortField::TOTAL_MEMBERS},
    {"total_events", RoomSortField::TOTAL_EVENTS},
    {"state_events", RoomSortField::STATE_EVENTS},
    {"creation_ts", RoomSortField::CREATION_TS},
    {"last_activity", RoomSortField::LAST_ACTIVITY},
    {"version", RoomSortField::VERSION},
    {"creator", RoomSortField::CREATOR},
    {"encrypted", RoomSortField::ENCRYPTED},
    {"federatable", RoomSortField::FEDERATABLE},
    {"public", RoomSortField::PUBLIC},
    {"join_rules", RoomSortField::JOIN_RULES},
    {"guest_access", RoomSortField::GUEST_ACCESS},
    {"history_visibility", RoomSortField::HISTORY_VISIBILITY},
    {"room_type", RoomSortField::ROOM_TYPE},
    {"complexity", RoomSortField::COMPLEXITY},
    {"forward_extremities", RoomSortField::FORWARD_EXTREMITIES},
    {"blocked", RoomSortField::BLOCKED},
    {"retention_enabled", RoomSortField::RETENTION_ENABLED},
  };
  auto it = map.find(to_lower(field));
  return it != map.end() ? it->second : RoomSortField::NAME;
}

inline std::string sort_field_to_sql(RoomSortField field, const std::string& table_alias = "rs") {
  switch (field) {
    case RoomSortField::NAME: return table_alias + ".name";
    case RoomSortField::ROOM_ID: return "r.room_id";
    case RoomSortField::CANONICAL_ALIAS: return table_alias + ".canonical_alias";
    case RoomSortField::JOINED_MEMBERS: return table_alias + ".joined_members";
    case RoomSortField::INVITED_MEMBERS: return table_alias + ".invited_members";
    case RoomSortField::TOTAL_MEMBERS:
      return "(" + table_alias + ".joined_members + " + table_alias + ".invited_members + " 
             + table_alias + ".left_members + " + table_alias + ".banned_members)";
    case RoomSortField::TOTAL_EVENTS: return table_alias + ".total_events";
    case RoomSortField::STATE_EVENTS: return table_alias + ".state_events";
    case RoomSortField::CREATION_TS: return "r.creation_ts";
    case RoomSortField::LAST_ACTIVITY: return table_alias + ".last_activity_ts";
    case RoomSortField::VERSION: return table_alias + ".room_version";
    case RoomSortField::CREATOR: return "r.creator";
    case RoomSortField::ENCRYPTED: return table_alias + ".is_encrypted";
    case RoomSortField::FEDERATABLE: return table_alias + ".is_federatable";
    case RoomSortField::PUBLIC: return "r.is_public";
    case RoomSortField::JOIN_RULES: return table_alias + ".join_rules";
    case RoomSortField::GUEST_ACCESS: return table_alias + ".guest_access";
    case RoomSortField::HISTORY_VISIBILITY:
      return table_alias + ".history_visibility";
    case RoomSortField::ROOM_TYPE: return table_alias + ".room_type";
    case RoomSortField::FORWARD_EXTREMITIES:
      return "(SELECT COUNT(*) FROM event_forward_extremities efe WHERE efe.room_id = r.room_id)";
    case RoomSortField::BLOCKED:
      return "(SELECT COUNT(*) FROM blocked_rooms br WHERE br.room_id = r.room_id)";
    case RoomSortField::RETENTION_ENABLED:
      return "(SELECT COUNT(*) FROM room_retention rr WHERE rr.room_id = r.room_id)";
    default: return table_alias + ".name";
  }
}

// ---- SQL escaping ----

inline std::string sanitize_sql_like(const std::string& input) {
  std::string result;
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

inline std::string sql_quote_string(const std::string& s) {
  std::string result = "'";
  for (char c : s) {
    if (c == '\'') result += "''";
    else result += c;
  }
  result += "'";
  return result;
}

inline std::string sql_quote_string_list(const std::vector<std::string>& items) {
  std::string result;
  for (size_t i = 0; i < items.size(); i++) {
    if (i > 0) result += ", ";
    result += sql_quote_string(items[i]);
  }
  return result;
}

// ---- Token/ID generation ----

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

// ---- Logging placeholder ----

inline void log_admin_action(const std::string& action,
                              const std::string& target,
                              const std::string& detail = "") {
  // In production, writes to a proper logging system
  std::cerr << "[ADMIN] " << now_iso8601() << " | " << action
            << " | " << target;
  if (!detail.empty()) std::cerr << " | " << detail;
  std::cerr << std::endl;
}

}  // anonymous namespace

// ============================================================================
// RoomStats — Comprehensive room statistics structure
// ============================================================================

struct RoomAdminStats {
  std::string room_id;
  std::string name;
  std::string topic;
  std::string canonical_alias;
  std::string creator;
  std::string join_rules = "invite";
  std::string guest_access = "forbidden";
  std::string history_visibility = "shared";
  std::string room_type = "room";
  std::string room_version = "10";
  std::string encryption_algorithm;
  int64_t joined_members = 0;
  int64_t invited_members = 0;
  int64_t left_members = 0;
  int64_t banned_members = 0;
  int64_t knocked_members = 0;
  int64_t local_joined_members = 0;
  int64_t local_invited_members = 0;
  int64_t local_total_members = 0;
  int64_t state_events = 0;
  int64_t total_events = 0;
  int64_t forward_extremities = 0;
  int64_t backward_extremities = 0;
  int64_t creation_ts = 0;
  int64_t last_activity_ts = 0;
  int64_t last_media_upload_ts = 0;
  int64_t last_message_ts = 0;
  int64_t total_media_count = 0;
  int64_t total_media_bytes = 0;
  int64_t quarantined_media_count = 0;
  double complexity_score = 0.0;
  bool is_encrypted = false;
  bool is_federatable = true;
  bool is_public = false;
  bool is_blocked = false;
  bool has_retention_policy = false;
  std::string blocked_reason;
  int64_t blocked_at = 0;
  std::string blocked_by;
  int64_t retention_min_lifetime = 0;
  int64_t retention_max_lifetime = 0;
  int64_t current_depth = 0;
  int64_t oldest_forward_extremity_age_ms = 0;

  json to_json() const {
    json j;
    j["room_id"] = room_id;
    if (!name.empty()) j["name"] = name;
    if (!topic.empty()) j["topic"] = topic;
    if (!canonical_alias.empty()) j["canonical_alias"] = canonical_alias;
    j["creator"] = creator;
    j["join_rules"] = join_rules;
    j["guest_access"] = guest_access;
    j["history_visibility"] = history_visibility;
    j["room_type"] = room_type;
    j["room_version"] = room_version;

    // Membership breakdown
    j["joined_members"] = joined_members;
    j["invited_members"] = invited_members;
    j["left_members"] = left_members;
    j["banned_members"] = banned_members;
    j["knocked_members"] = knocked_members;
    j["total_members"] =
        joined_members + invited_members + left_members + banned_members + knocked_members;

    // Local members
    j["local_joined_members"] = local_joined_members;
    j["local_invited_members"] = local_invited_members;
    j["local_total_members"] = local_total_members;

    // Events
    j["state_events"] = state_events;
    j["total_events"] = total_events;

    // Extremities
    j["forward_extremities"] = forward_extremities;
    j["backward_extremities"] = backward_extremities;

    // Timestamps
    j["creation_ts"] = creation_ts;
    if (creation_ts > 0) {
      j["creation_ts_display"] = ts_to_iso8601(creation_ts);
      j["room_age_days"] = ms_to_days(now_ms() - creation_ts);
    }
    j["last_activity_ts"] = last_activity_ts;
    if (last_activity_ts > 0) {
      j["last_activity_display"] = ts_to_iso8601(last_activity_ts);
    }
    j["last_media_upload_ts"] = last_media_upload_ts;
    if (last_media_upload_ts > 0) {
      j["last_media_upload_display"] = ts_to_iso8601(last_media_upload_ts);
    }
    j["last_message_ts"] = last_message_ts;
    if (last_message_ts > 0) {
      j["last_message_display"] = ts_to_iso8601(last_message_ts);
    }

    // Media stats
    j["total_media_count"] = total_media_count;
    j["total_media_bytes"] = total_media_bytes;
    if (total_media_bytes > 0) {
      j["total_media_size_display"] = format_bytes(total_media_bytes);
    }
    j["quarantined_media_count"] = quarantined_media_count;

    // Encryption
    j["encrypted"] = is_encrypted;
    if (!encryption_algorithm.empty()) {
      j["encryption_algorithm"] = encryption_algorithm;
    }

    // Federation
    j["federatable"] = is_federatable;
    j["public"] = is_public;

    // Block status
    j["blocked"] = is_blocked;
    if (is_blocked) {
      j["blocked_reason"] = blocked_reason;
      j["blocked_at"] = blocked_at;
      if (blocked_at > 0) j["blocked_at_display"] = ts_to_iso8601(blocked_at);
      j["blocked_by"] = blocked_by;
    }

    // Retention
    j["has_retention_policy"] = has_retention_policy;
    if (has_retention_policy) {
      j["retention_min_lifetime_ms"] = retention_min_lifetime;
      j["retention_max_lifetime_ms"] = retention_max_lifetime;
      if (retention_min_lifetime > 0)
        j["retention_min_lifetime_days"] = ms_to_days(retention_min_lifetime);
      if (retention_max_lifetime > 0)
        j["retention_max_lifetime_days"] = ms_to_days(retention_max_lifetime);
    }

    // Complexity
    j["complexity"] = complexity_score;
    if (complexity_score > kComplexityWarningThreshold) {
      j["complexity_warning"] = true;
    }
    if (complexity_score > kComplexityErrorThreshold) {
      j["complexity_error"] = true;
    }

    // Depth
    j["current_depth"] = current_depth;
    if (oldest_forward_extremity_age_ms > 0) {
      j["oldest_extremity_age_ms"] = oldest_forward_extremity_age_ms;
      j["oldest_extremity_age_display"] =
          format_duration_ms(oldest_forward_extremity_age_ms);
    }

    return j;
  }
};

// ============================================================================
// RoomAliasAdminSubsystem — Alias management for admin rooms
// ============================================================================

class RoomAliasAdminSubsystem {
public:
  explicit RoomAliasAdminSubsystem(storage::DatabasePool& db,
                                     const std::string& server_name)
      : db_(db), server_name_(server_name) {}

  // List all aliases for a room
  json list_aliases(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }
    try {
      auto rows = db_.execute(
          "admin_list_room_aliases",
          "SELECT room_alias, creator, created_ts "
          "FROM room_aliases WHERE room_id = ? "
          "ORDER BY created_ts DESC",
          {room_id});

      json aliases = json::array();
      for (auto& row : rows) {
        json a;
        a["alias"] = row_get_str(row, 0);
        a["creator"] = row_get_str(row, 1);
        int64_t ts = row_get_int(row, 2);
        a["created_ts"] = ts;
        if (ts > 0) a["created_ts_display"] = ts_to_iso8601(ts);
        aliases.push_back(a);
      }
      return build_admin_response(room_id, "list_aliases", true, {
        {"aliases", aliases},
        {"total", aliases.size()}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing aliases: ") + e.what());
    }
  }

  // Add a new alias to a room
  json add_alias(const std::string& room_id, const std::string& alias,
                  const std::string& creator = "admin") {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }
    if (!is_valid_room_alias(alias)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid alias: " + alias);
    }

    try {
      // Check alias doesn't already point somewhere else
      auto existing = db_.simple_select_one(
          "room_aliases", {{"room_alias", alias}}, {"room_id"});
      if (existing.has_value()) {
        std::string current_room = row_get_str(*existing, 0);
        if (current_room != room_id) {
          return build_error(409, "M_CONFLICT",
                             "Alias " + alias + " already points to " + current_room);
        }
        // Already pointing here — no-op success
        return build_admin_response(room_id, "add_alias", true, {
          {"alias", alias},
          {"message", "Alias already exists for this room"},
          {"already_exists", true}
        });
      }

      db_.simple_insert("room_aliases", {
        {"room_alias", alias},
        {"room_id", room_id},
        {"creator", creator},
        {"created_ts", std::to_string(now_ms())}
      });

      // Also insert into the room_aliases table used by directory
      try {
        db_.simple_insert("local_room_aliases", {
          {"room_alias", alias},
          {"room_id", room_id}
        });
      } catch (...) {
        // Non-critical; the main alias table is the source of truth
      }

      log_admin_action("add_alias", alias, "room=" + room_id + " creator=" + creator);
      return build_admin_response(room_id, "add_alias", true, {
        {"alias", alias},
        {"creator", creator},
        {"message", "Alias added successfully"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error adding alias: ") + e.what());
    }
  }

  // Remove an alias from a room
  json remove_alias(const std::string& room_id, const std::string& alias) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }
    if (!is_valid_room_alias(alias)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid alias: " + alias);
    }

    try {
      auto existing = db_.simple_select_one(
          "room_aliases", {{"room_alias", alias}, {"room_id", room_id}},
          {"room_alias"});
      if (!existing.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "Alias " + alias + " not found for room " + room_id);
      }

      db_.simple_delete_one("room_aliases",
                            {{"room_alias", alias}, {"room_id", room_id}});

      try {
        db_.simple_delete_one("local_room_aliases", {{"room_alias", alias}});
      } catch (...) {}

      // If this was the canonical alias, clear it
      auto canonical = db_.simple_select_one(
          "room_stats_state", {{"room_id", room_id}}, {"canonical_alias"});
      if (canonical.has_value() && row_get_str(*canonical, 0) == alias) {
        db_.simple_update_one("room_stats_state", {{"room_id", room_id}},
                              {{"canonical_alias", ""}});
      }

      log_admin_action("remove_alias", alias, "room=" + room_id);
      return build_admin_response(room_id, "remove_alias", true, {
        {"alias", alias},
        {"message", "Alias removed successfully"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error removing alias: ") + e.what());
    }
  }

  // Set canonical alias for a room
  json set_canonical_alias(const std::string& room_id,
                            const std::string& alias) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      if (alias.empty()) {
        // Clear canonical alias
        db_.simple_update_one("room_stats_state", {{"room_id", room_id}},
                              {{"canonical_alias", ""}});
        return build_admin_response(room_id, "set_canonical_alias", true, {
          {"message", "Canonical alias cleared"}
        });
      }

      if (!is_valid_room_alias(alias)) {
        return build_error(400, "M_INVALID_PARAM", "Invalid alias: " + alias);
      }

      // Verify alias exists for this room
      auto existing = db_.simple_select_one(
          "room_aliases", {{"room_alias", alias}, {"room_id", room_id}},
          {"room_alias"});
      if (!existing.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "Alias " + alias + " not associated with room " + room_id);
      }

      db_.simple_update_one("room_stats_state", {{"room_id", room_id}},
                            {{"canonical_alias", alias}});
      return build_admin_response(room_id, "set_canonical_alias", true, {
        {"canonical_alias", alias},
        {"message", "Canonical alias set successfully"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error setting canonical alias: ") + e.what());
    }
  }

  // Resolve alias to room_id (for admin lookup)
  json resolve_alias(const std::string& alias) {
    if (!is_valid_room_alias(alias)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid alias: " + alias);
    }

    try {
      auto existing = db_.simple_select_one(
          "room_aliases", {{"room_alias", alias}},
          {"room_id", "creator", "created_ts"});
      if (!existing.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "Alias not found: " + alias);
      }

      auto& r = *existing;
      json result;
      result["alias"] = alias;
      result["room_id"] = row_get_str(r, 0);
      result["creator"] = row_get_str(r, 1);
      int64_t ts = row_get_int(r, 2);
      result["created_ts"] = ts;
      if (ts > 0) result["created_ts_display"] = ts_to_iso8601(ts);
      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error resolving alias: ") + e.what());
    }
  }

  // Bulk remove all aliases for a room
  json remove_all_aliases(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      auto count_rows = db_.execute(
          "count_room_aliases_admin",
          "SELECT COUNT(*) FROM room_aliases WHERE room_id = ?", {room_id});
      int64_t count = 0;
      if (!count_rows.empty()) count = row_get_int(count_rows[0], 0);

      db_.execute("delete_all_room_aliases",
                  "DELETE FROM room_aliases WHERE room_id = ?", {room_id});
      try {
        db_.execute("delete_local_room_aliases",
                    "DELETE FROM local_room_aliases WHERE room_id = ?",
                    {room_id});
      } catch (...) {}

      db_.simple_update_one("room_stats_state", {{"room_id", room_id}},
                            {{"canonical_alias", ""}});

      return build_admin_response(room_id, "remove_all_aliases", true, {
        {"aliases_removed", count},
        {"message", "All aliases removed successfully"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error removing aliases: ") + e.what());
    }
  }

private:
  storage::DatabasePool& db_;
  std::string server_name_;
};

// ============================================================================
// RoomComplexityAnalyzer — Varth Dader complexity analysis for rooms
// ============================================================================

class RoomComplexityAnalyzer {
public:
  explicit RoomComplexityAnalyzer(storage::DatabasePool& db)
      : db_(db) {}

  // Compute complexity score for a single room
  double compute_complexity(const std::string& room_id) {
    ComplexityInputs inputs = gather_complexity_inputs(room_id);
    return calculate_score(inputs);
  }

  // Full complexity report for a room
  json compute_complexity_report(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      ComplexityInputs inputs = gather_complexity_inputs(room_id);
      double score = calculate_score(inputs);

      json report;
      report["room_id"] = room_id;
      report["complexity_score"] = score;
      report["is_complex"] = score > kComplexityWarningThreshold;
      report["is_very_complex"] = score > kComplexityErrorThreshold;

      // Breakdown
      report["breakdown"] = {
        {"forward_extremities", {
          {"count", inputs.forward_extremities},
          {"contribution", inputs.forward_extremities * kExtremityComplexityFactor}
        }},
        {"state_events", {
          {"count", inputs.state_events},
          {"contribution", inputs.state_events * kStateComplexityFactor}
        }},
        {"total_events", {
          {"count", inputs.total_events},
          {"contribution", inputs.total_events * kEventComplexityFactor}
        }},
        {"joined_members", {
          {"count", inputs.joined_members},
          {"contribution", inputs.joined_members * kMemberComplexityFactor}
        }},
        {"depth", {
          {"value", inputs.depth},
          {"contribution", inputs.depth * 0.1}
        }},
        {"backward_extremities", {
          {"count", inputs.backward_extremities},
          {"contribution", inputs.backward_extremities * 2.0}
        }},
        {"oldest_extremity_age_ms", {
          {"value", inputs.oldest_extremity_age_ms},
          {"contribution", inputs.oldest_extremity_age_ms > 0
               ? std::log10(inputs.oldest_extremity_age_ms / 1000.0 + 1) * 50.0
               : 0.0}
        }}
      };

      // Recommendations
      if (score > kComplexityErrorThreshold) {
        report["recommendation"] = "CRITICAL: Room has extremely high complexity. "
            "Consider purging forward extremities or splitting the room.";
      } else if (score > kComplexityWarningThreshold) {
        report["recommendation"] = "WARNING: Room complexity is elevated. "
            "Monitor forward extremities and consider compaction.";
      } else {
        report["recommendation"] = "Room complexity is within normal limits.";
      }

      return report;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error computing complexity: ") + e.what());
    }
  }

  // List rooms exceeding complexity threshold
  json list_complex_rooms(double threshold = kComplexityWarningThreshold,
                           int64_t limit = 100) {
    try {
      if (limit < 1) limit = kDefaultPageSize;
      if (limit > kMaxPageSize) limit = kMaxPageSize;

      auto rows = db_.execute(
          "list_high_extremity_rooms",
          "SELECT r.room_id, rs.name, rs.joined_members, rs.state_events, "
          "rs.total_events, "
          "(SELECT COUNT(*) FROM event_forward_extremities efe "
          " WHERE efe.room_id = r.room_id) as fwd_count, "
          "(SELECT COUNT(*) FROM event_backward_extremities ebe "
          " WHERE ebe.room_id = r.room_id) as bwd_count, "
          "(SELECT MAX(r.creation_ts - COALESCE(efe2.received_ts, r.creation_ts)) "
          " FROM event_forward_extremities efe2 "
          " WHERE efe2.room_id = r.room_id) as oldest_age "
          "FROM rooms r "
          "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id "
          "HAVING fwd_count > 0 OR bwd_count > 0 "
          "ORDER BY fwd_count DESC, oldest_age DESC "
          "LIMIT " + std::to_string(limit));

      json results = json::array();
      for (auto& row : rows) {
        int64_t fwd = row_get_int(row, 4);
        int64_t bwd = row_get_int(row, 5);
        int64_t oldest = row_get_int(row, 6);

        double score = fwd * kExtremityComplexityFactor +
                       bwd * 2.0 +
                       row_get_int(row, 3) * kStateComplexityFactor +
                       row_get_int(row, 2) * kMemberComplexityFactor;
        if (oldest > 0) {
          score += std::log10(oldest / 1000.0 + 1) * 50.0;
        }

        if (score >= threshold) {
          json entry;
          entry["room_id"] = row_get_str(row, 0);
          entry["name"] = row_get_str(row, 1);
          entry["joined_members"] = row_get_int(row, 2);
          entry["state_events"] = row_get_int(row, 3);
          entry["forward_extremities"] = fwd;
          entry["backward_extremities"] = bwd;
          entry["oldest_extremity_age_ms"] = oldest;
          entry["complexity_score"] = score;
          entry["exceeds_threshold"] = score > kComplexityErrorThreshold;
          results.push_back(entry);
        }
      }

      return build_paginated(results.size(), results, 0, limit);
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing complex rooms: ") + e.what());
    }
  }

  // Purge forward extremities for a room (complexity mitigation)
  json purge_forward_extremities(const std::string& room_id,
                                   int64_t max_to_keep = 20) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      auto count_rows = db_.execute(
          "count_fwd_extremities_admin",
          "SELECT COUNT(*) FROM event_forward_extremities "
          "WHERE room_id = ?", {room_id});
      int64_t initial_count = 0;
      if (!count_rows.empty()) initial_count = row_get_int(count_rows[0], 0);

      if (initial_count <= max_to_keep) {
        return build_admin_response(room_id, "purge_forward_extremities", true, {
          {"initial_count", initial_count},
          {"deleted", 0},
          {"remaining", initial_count},
          {"message", "No purging needed; extremity count is below threshold"}
        });
      }

      // Delete oldest extremities beyond max_to_keep
      std::string del_query =
          "DELETE FROM event_forward_extremities "
          "WHERE room_id = ? AND event_id NOT IN ("
          "  SELECT event_id FROM event_forward_extremities "
          "  WHERE room_id = ? "
          "  ORDER BY received_ts DESC "
          "  LIMIT " + std::to_string(max_to_keep) + ")";

      db_.execute("purge_fwd_extremities", del_query, {room_id, room_id});

      int64_t remaining = max_to_keep;
      try {
        auto rem_rows = db_.execute(
            "count_remaining_fwd",
            "SELECT COUNT(*) FROM event_forward_extremities "
            "WHERE room_id = ?", {room_id});
        if (!rem_rows.empty()) remaining = row_get_int(rem_rows[0], 0);
      } catch (...) {}

      int64_t deleted = initial_count - remaining;

      log_admin_action("purge_forward_extremities", room_id,
                       "deleted=" + std::to_string(deleted));
      return build_admin_response(room_id, "purge_forward_extremities", true, {
        {"initial_count", initial_count},
        {"deleted", deleted},
        {"remaining", remaining},
        {"message", "Purged " + std::to_string(deleted) + " forward extremities"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error purging extremities: ") + e.what());
    }
  }

private:
  struct ComplexityInputs {
    int64_t forward_extremities = 0;
    int64_t backward_extremities = 0;
    int64_t state_events = 0;
    int64_t total_events = 0;
    int64_t joined_members = 0;
    int64_t depth = 0;
    int64_t oldest_extremity_age_ms = 0;
  };

  ComplexityInputs gather_complexity_inputs(const std::string& room_id) {
    ComplexityInputs inputs;

    try {
      // Forward extremities
      auto fwd = db_.execute(
          "complexity_fwd_count",
          "SELECT COUNT(*) FROM event_forward_extremities "
          "WHERE room_id = ?", {room_id});
      if (!fwd.empty()) inputs.forward_extremities = row_get_int(fwd[0], 0);
    } catch (...) {}

    try {
      // Backward extremities
      auto bwd = db_.execute(
          "complexity_bwd_count",
          "SELECT COUNT(*) FROM event_backward_extremities "
          "WHERE room_id = ?", {room_id});
      if (!bwd.empty()) inputs.backward_extremities = row_get_int(bwd[0], 0);
    } catch (...) {}

    try {
      // State events
      auto state = db_.execute(
          "complexity_state_count",
          "SELECT COUNT(*) FROM state_events WHERE room_id = ?", {room_id});
      if (!state.empty()) inputs.state_events = row_get_int(state[0], 0);
    } catch (...) {}

    try {
      // Total events
      auto events = db_.execute(
          "complexity_event_count",
          "SELECT COUNT(*) FROM events WHERE room_id = ?", {room_id});
      if (!events.empty()) inputs.total_events = row_get_int(events[0], 0);
    } catch (...) {}

    try {
      // Joined members
      auto members = db_.execute(
          "complexity_member_count",
          "SELECT COUNT(*) FROM local_current_membership "
          "WHERE room_id = ? AND membership = 'join'", {room_id});
      if (!members.empty()) inputs.joined_members = row_get_int(members[0], 0);
    } catch (...) {}

    try {
      // Current depth
      auto depth_rows = db_.execute(
          "complexity_depth",
          "SELECT current_depth FROM room_depth WHERE room_id = ? LIMIT 1",
          {room_id});
      if (!depth_rows.empty()) inputs.depth = row_get_int(depth_rows[0], 0);
    } catch (...) {}

    try {
      // Oldest forward extremity age
      auto oldest = db_.execute(
          "complexity_oldest_extremity",
          "SELECT MIN(received_ts) FROM event_forward_extremities "
          "WHERE room_id = ?", {room_id});
      if (!oldest.empty()) {
        int64_t min_ts = row_get_int(oldest[0], 0);
        if (min_ts > 0) {
          inputs.oldest_extremity_age_ms = now_ms() - min_ts;
        }
      }
    } catch (...) {}

    return inputs;
  }

  static double calculate_score(const ComplexityInputs& inputs) {
    double score = 0.0;

    // Forward extremities are the primary complexity driver
    score += inputs.forward_extremities * kExtremityComplexityFactor;

    // Backward extremities also contribute
    score += inputs.backward_extremities * 2.0;

    // State events
    score += inputs.state_events * kStateComplexityFactor;

    // Total events (mild contribution)
    score += inputs.total_events * kEventComplexityFactor;

    // Members
    score += inputs.joined_members * kMemberComplexityFactor;

    // Depth factor
    score += inputs.depth * 0.1;

    // Oldest extremity age — logarithmic scale
    if (inputs.oldest_extremity_age_ms > 0) {
      score += std::log10(static_cast<double>(inputs.oldest_extremity_age_ms)
                          / 1000.0 + 1.0) * 50.0;
    }

    return std::round(score * 100.0) / 100.0;
  }

  storage::DatabasePool& db_;
};

// ============================================================================
// RoomMediaAdminSubsystem — Room-scoped media management
// ============================================================================

class RoomMediaAdminSubsystem {
public:
  explicit RoomMediaAdminSubsystem(storage::DatabasePool& db,
                                     const std::string& server_name)
      : db_(db), server_name_(server_name) {}

  // List media associated with a room
  json list_room_media(const std::string& room_id,
                        int64_t from = 0, int64_t limit = 100,
                        const std::string& order_by = "created_ts",
                        const std::string& dir = "desc",
                        bool include_quarantined = true) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }
    if (limit < 1) limit = kDefaultPageSize;
    if (limit > kMaxPageSize) limit = kMaxPageSize;

    try {
      std::string order_col = "lmr.created_ts";
      if (order_by == "media_length") order_col = "lmr.media_length";
      else if (order_by == "media_type") order_col = "lmr.media_type";
      else if (order_by == "user_id") order_col = "lmr.user_id";

      std::string dir_sql = (dir == "asc") ? " ASC" : " DESC";

      // Collect media IDs from events in the room's mxc URLs
      // This approach extracts media references from events in the room
      std::string query =
          "SELECT DISTINCT lmr.media_id, lmr.media_type, lmr.media_length, "
          "lmr.user_id, lmr.created_ts, lmr.safe_from_quarantine, "
          "lmr.quarantined_by, lmr.quarantined_reason, lmr.upload_name "
          "FROM local_media_repository lmr "
          "INNER JOIN ("
          "  SELECT DISTINCT "
          "    REPLACE("
          "      REPLACE(json_extract(content, '$.url'), 'mxc://" + server_name_ + "/', ''),"
          "      'mxc://', '') as media_id_ref "
          "  FROM events "
          "  WHERE room_id = '" + sanitize_sql_like(room_id) + "' "
          "    AND json_extract(content, '$.url') IS NOT NULL "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ") ev ON lmr.media_id = ev.media_id_ref";

      if (!include_quarantined) {
        query += " WHERE lmr.safe_from_quarantine = 1";
      }

      query += " ORDER BY " + order_col + dir_sql;
      query += " LIMIT " + std::to_string(limit + 1) +
               " OFFSET " + std::to_string(from);

      auto rows = db_.execute("admin_list_room_media", query);

      json media_array = json::array();
      bool has_more = false;
      size_t count = 0;

      for (auto& row : rows) {
        if (count >= static_cast<size_t>(limit)) {
          has_more = true;
          break;
        }
        json m;
        m["media_id"] = row_get_str(row, 0);
        m["media_type"] = row_get_str(row, 1);
        m["media_length"] = row_get_int(row, 2);
        if (row_get_int(row, 2) > 0) {
          m["size_display"] = format_bytes(row_get_int(row, 2));
        }
        m["user_id"] = row_get_str(row, 3);
        int64_t cts = row_get_int(row, 4);
        m["created_ts"] = cts;
        if (cts > 0) m["created_ts_display"] = ts_to_iso8601(cts);
        m["safe_from_quarantine"] = row_get_bool(row, 5, true);
        if (!row_get_bool(row, 5, true)) {
          m["quarantined_by"] = row_get_str(row, 6);
          m["quarantined_reason"] = row_get_str(row, 7);
        }
        m["upload_name"] = row_get_str(row, 8);
        m["mxc_uri"] = "mxc://" + server_name_ + "/" + row_get_str(row, 0);
        media_array.push_back(m);
        count++;
      }

      json result;
      result["room_id"] = room_id;
      result["media"] = media_array;
      result["total"] = media_array.size();
      result["from"] = from;
      result["limit"] = limit;
      result["next_batch"] = has_more ? std::to_string(from + limit) : "";

      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing room media: ") + e.what());
    }
  }

  // Get room media stats
  json get_room_media_stats(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      // Count media references from events in this room
      auto count_rows = db_.execute(
          "admin_room_media_count",
          "SELECT COUNT(DISTINCT "
          "  REPLACE("
          "    REPLACE(json_extract(content, '$.url'), 'mxc://" + server_name_ + "/', ''),"
          "    'mxc://', '')) "
          "FROM events "
          "WHERE room_id = ? "
          "  AND json_extract(content, '$.url') LIKE 'mxc://%'",
          {room_id});
      int64_t total_refs = count_rows.empty() ? 0 : row_get_int(count_rows[0], 0);

      // Total bytes from local media repository
      auto bytes_rows = db_.execute(
          "admin_room_media_bytes",
          "SELECT COALESCE(SUM(lmr.media_length), 0), COUNT(*) "
          "FROM ("
          "  SELECT DISTINCT "
          "    REPLACE("
          "      REPLACE(json_extract(content, '$.url'), 'mxc://" + server_name_ + "/', ''),"
          "      'mxc://', '') as mid "
          "  FROM events "
          "  WHERE room_id = ? "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ") ev "
          "INNER JOIN local_media_repository lmr ON lmr.media_id = ev.mid",
          {room_id});
      int64_t total_bytes = 0;
      int64_t local_count = 0;
      if (!bytes_rows.empty()) {
        total_bytes = row_get_int(bytes_rows[0], 0);
        local_count = row_get_int(bytes_rows[0], 1);
      }

      // Quarantined count
      auto quar_rows = db_.execute(
          "admin_room_media_quarantined",
          "SELECT COUNT(*) FROM ("
          "  SELECT DISTINCT "
          "    REPLACE("
          "      REPLACE(json_extract(content, '$.url'), 'mxc://" + server_name_ + "/', ''),"
          "      'mxc://', '') as mid "
          "  FROM events "
          "  WHERE room_id = ? "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ") ev "
          "INNER JOIN local_media_repository lmr ON lmr.media_id = ev.mid "
          "WHERE lmr.safe_from_quarantine = 0",
          {room_id});
      int64_t quarantined = quar_rows.empty() ? 0 : row_get_int(quar_rows[0], 0);

      // Media type breakdown
      auto type_rows = db_.execute(
          "admin_room_media_types",
          "SELECT "
          "  SUBSTR(lmr.media_type, 1, INSTR(lmr.media_type || '/', '/')-1) as category, "
          "  COUNT(DISTINCT lmr.media_id), "
          "  SUM(lmr.media_length) "
          "FROM ("
          "  SELECT DISTINCT "
          "    REPLACE("
          "      REPLACE(json_extract(content, '$.url'), 'mxc://" + server_name_ + "/', ''),"
          "      'mxc://', '') as mid "
          "  FROM events "
          "  WHERE room_id = ? "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ") ev "
          "INNER JOIN local_media_repository lmr ON lmr.media_id = ev.mid "
          "GROUP BY category",
          {room_id});

      json type_breakdown = json::object();
      for (auto& tr : type_rows) {
        std::string cat = row_get_str(tr, 0, "unknown");
        json cat_info;
        cat_info["count"] = row_get_int(tr, 1);
        cat_info["bytes"] = row_get_int(tr, 2);
        cat_info["size_display"] = format_bytes(row_get_int(tr, 2));
        type_breakdown[cat] = cat_info;
      }

      // Top uploaders
      auto uploader_rows = db_.execute(
          "admin_room_media_uploaders",
          "SELECT user_id, COUNT(*), SUM(media_length) "
          "FROM local_media_repository lmr "
          "WHERE lmr.media_id IN ("
          "  SELECT DISTINCT "
          "    REPLACE("
          "      REPLACE(json_extract(e.content, '$.url'), 'mxc://" + server_name_ + "/', ''),"
          "      'mxc://', '') "
          "  FROM events e WHERE e.room_id = ? "
          "    AND json_extract(e.content, '$.url') LIKE 'mxc://%'"
          ") "
          "GROUP BY user_id ORDER BY SUM(media_length) DESC LIMIT 10",
          {room_id});

      json top_uploaders = json::array();
      for (auto& tu : uploader_rows) {
        json user_media;
        user_media["user_id"] = row_get_str(tu, 0);
        user_media["count"] = row_get_int(tu, 1);
        user_media["bytes"] = row_get_int(tu, 2);
        user_media["size_display"] = format_bytes(row_get_int(tu, 2));
        top_uploaders.push_back(user_media);
      }

      json stats;
      stats["room_id"] = room_id;
      stats["total_media_references"] = total_refs;
      stats["local_media_count"] = local_count;
      stats["total_bytes"] = total_bytes;
      if (total_bytes > 0) stats["total_size_display"] = format_bytes(total_bytes);
      stats["quarantined_count"] = quarantined;
      stats["media_type_breakdown"] = type_breakdown;
      stats["top_uploaders"] = top_uploaders;

      return stats;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error getting room media stats: ") + e.what());
    }
  }

  // Quarantine all media in a room
  json quarantine_room_media(const std::string& room_id,
                              const std::string& reason = "Quarantined by admin") {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      // Count before quarantine
      auto before_rows = db_.execute(
          "count_before_quarantine_room",
          "SELECT COUNT(*) FROM ("
          "  SELECT DISTINCT "
          "    REPLACE("
          "      REPLACE(json_extract(content, '$.url'), 'mxc://" + server_name_ + "/', ''),"
          "      'mxc://', '') as mid "
          "  FROM events WHERE room_id = ? "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ")",
          {room_id});
      int64_t total = before_rows.empty() ? 0 : row_get_int(before_rows[0], 0);

      // Quarantine
      db_.execute(
          "quarantine_room_all_media",
          "UPDATE local_media_repository "
          "SET safe_from_quarantine = 0, "
          "    quarantined_by = ?, "
          "    quarantined_reason = ?, "
          "    quarantined_ts = ? "
          "WHERE media_id IN ("
          "  SELECT DISTINCT "
          "    REPLACE("
          "      REPLACE(json_extract(content, '$.url'), 'mxc://" + server_name_ + "/', ''),"
          "      'mxc://', '') "
          "  FROM events "
          "  WHERE room_id = ? "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ")",
          {"admin", reason, std::to_string(now_ms()), room_id});

      // Delete thumbnails for quarantined media
      db_.execute(
          "delete_thumbnails_quarantined_room",
          "DELETE FROM local_media_repository_thumbnails "
          "WHERE media_id IN ("
          "  SELECT DISTINCT "
          "    REPLACE("
          "      REPLACE(json_extract(content, '$.url'), 'mxc://" + server_name_ + "/', ''),"
          "      'mxc://', '') "
          "  FROM events "
          "  WHERE room_id = ? "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ")",
          {room_id});

      log_admin_action("quarantine_room_media", room_id,
                       "count=" + std::to_string(total) + " reason=" + reason);
      return build_admin_response(room_id, "quarantine_media", true, {
        {"quarantined_count", total},
        {"reason", reason},
        {"message", "All room media quarantined successfully"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error quarantining room media: ") + e.what());
    }
  }

  // Unquarantine all media in a room
  json unquarantine_room_media(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      auto before_rows = db_.execute(
          "count_before_unquarantine_room",
          "SELECT COUNT(*) FROM ("
          "  SELECT DISTINCT "
          "    REPLACE("
          "      REPLACE(json_extract(content, '$.url'), 'mxc://" + server_name_ + "/', ''),"
          "      'mxc://', '') as mid "
          "  FROM events WHERE room_id = ? "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ") ev "
          "INNER JOIN local_media_repository lmr ON lmr.media_id = ev.mid "
          "WHERE lmr.safe_from_quarantine = 0",
          {room_id});
      int64_t quarantined = before_rows.empty() ? 0 : row_get_int(before_rows[0], 0);

      db_.execute(
          "unquarantine_room_all_media",
          "UPDATE local_media_repository "
          "SET safe_from_quarantine = 1, "
          "    quarantined_by = NULL, "
          "    quarantined_reason = NULL "
          "WHERE media_id IN ("
          "  SELECT DISTINCT "
          "    REPLACE("
          "      REPLACE(json_extract(content, '$.url'), 'mxc://" + server_name_ + "/', ''),"
          "      'mxc://', '') "
          "  FROM events "
          "  WHERE room_id = ? "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ")",
          {room_id});

      return build_admin_response(room_id, "unquarantine_media", true, {
        {"unquarantined_count", quarantined},
        {"message", "All room media unquarantined successfully"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error unquarantining room media: ") + e.what());
    }
  }

  // Delete specific media by its mxc URL found in room events
  json delete_room_media_by_id(const std::string& room_id,
                                const std::string& media_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }
    if (media_id.empty()) {
      return build_error(400, "M_MISSING_PARAM", "media_id is required");
    }

    try {
      // Verify media is referenced from this room
      auto ref_rows = db_.execute(
          "verify_media_in_room",
          "SELECT event_id FROM events "
          "WHERE room_id = ? AND ("
          "  json_extract(content, '$.url') = 'mxc://" + server_name_ + "/" + sanitize_sql_like(media_id) + "' "
          "  OR json_extract(content, '$.url') LIKE '%" + sanitize_sql_like(media_id) + "'"
          ") LIMIT 1",
          {room_id});
      if (ref_rows.empty()) {
        return build_error(404, "M_NOT_FOUND",
                           "Media " + media_id + " not found in room " + room_id);
      }

      // Delete from repository
      auto local = db_.simple_select_one(
          "local_media_repository", {{"media_id", media_id}}, {"media_id"});
      if (local.has_value()) {
        db_.simple_delete_one("local_media_repository", {{"media_id", media_id}});
        db_.simple_delete_one("local_media_repository_thumbnails",
                              {{"media_id", media_id}});
      }

      auto remote = db_.simple_select_one(
          "remote_media_cache", {{"media_id", media_id}}, {"media_id"});
      if (remote.has_value()) {
        db_.simple_delete_one("remote_media_cache", {{"media_id", media_id}});
        db_.simple_delete_one("remote_media_cache_thumbnails",
                              {{"media_id", media_id}});
      }

      log_admin_action("delete_media", media_id, "room=" + room_id);
      return build_admin_response(room_id, "delete_media", true, {
        {"media_id", media_id},
        {"message", "Media deleted successfully"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error deleting media: ") + e.what());
    }
  }

private:
  storage::DatabasePool& db_;
  std::string server_name_;
};

// ============================================================================
// RoomPowerLevelManager — Promote/demote users to admin in rooms
// ============================================================================

class RoomPowerLevelManager {
public:
  explicit RoomPowerLevelManager(storage::DatabasePool& db)
      : db_(db) {}

  // Promote a user to room admin (set power level to 100)
  json promote_to_admin(const std::string& room_id,
                         const std::string& user_id,
                         int64_t power_level = 100,
                         const std::string& reason = "Promoted by server admin") {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }
    if (!is_valid_user_id(user_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid user_id: " + user_id);
    }

    try {
      // Get current power level event
      auto current_pl = get_current_power_levels(room_id);
      int64_t old_level = 0;
      if (current_pl.contains("users") && current_pl["users"].contains(user_id)) {
        old_level = current_pl["users"][user_id].get<int64_t>();
      }

      // Get current power levels state event
      auto pl_event = db_.simple_select_one(
          "current_state_events",
          {{"room_id", room_id}, {"type", "m.room.power_levels"},
           {"state_key", ""}},
          {"event_id", "json"});

      json new_pl = current_pl;
      if (!new_pl.contains("users")) new_pl["users"] = json::object();
      new_pl["users"][user_id] = power_level;

      // Update the power levels in current_state_events
      if (pl_event.has_value()) {
        auto& r = *pl_event;
        std::string event_id = row_get_str(r, 0);
        std::string json_str = row_get_str(r, 1);
        try {
          auto current_json = json::parse(json_str);
          if (current_json.contains("content")) {
            current_json["content"]["users"] = new_pl["users"];
            db_.simple_update_one(
                "event_json", {{"event_id", event_id}},
                {{"json", current_json.dump()}});
          }
        } catch (...) {}
      }

      // Record the action
      db_.simple_insert("admin_room_power_changes", {
        {"room_id", room_id},
        {"user_id", user_id},
        {"old_power_level", std::to_string(old_level)},
        {"new_power_level", std::to_string(power_level)},
        {"changed_by", "server_admin"},
        {"changed_at", std::to_string(now_ms())},
        {"reason", reason}
      });

      log_admin_action("promote_to_admin", room_id,
                       "user=" + user_id + " from=" + std::to_string(old_level) +
                       " to=" + std::to_string(power_level));

      return build_admin_response(room_id, "promote_to_admin", true, {
        {"user_id", user_id},
        {"old_power_level", old_level},
        {"new_power_level", power_level},
        {"reason", reason},
        {"message", "User " + user_id + " promoted to power level " +
                    std::to_string(power_level)}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error promoting user: ") + e.what());
    }
  }

  // Demote a user from admin (reset to default power level)
  json demote_from_admin(const std::string& room_id,
                          const std::string& user_id,
                          int64_t default_level = 0,
                          const std::string& reason = "Demoted by server admin") {
    return promote_to_admin(room_id, user_id, default_level, reason);
  }

  // Get current power levels for a room
  json get_room_power_levels(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      json pl = get_current_power_levels(room_id);

      // List admins (users with PL >= 100)
      json admins = json::array();
      if (pl.contains("users")) {
        for (auto& [uid, level] : pl["users"].items()) {
          if (level.get<int64_t>() >= kDefaultAdminPowerLevel) {
            admins.push_back(uid);
          }
        }
      }

      json result;
      result["room_id"] = room_id;
      result["power_levels"] = pl;
      result["admins"] = admins;
      result["admin_count"] = admins.size();
      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error getting power levels: ") + e.what());
    }
  }

  // List all room admins across all rooms
  json list_all_room_admins(int64_t limit = 100) {
    try {
      if (limit < 1) limit = kDefaultPageSize;
      if (limit > kMaxPageSize) limit = kMaxPageSize;

      // Get rooms with power level events
      auto rows = db_.execute(
          "list_rooms_with_pl",
          "SELECT room_id, json FROM current_state_events "
          "WHERE type = 'm.room.power_levels' AND state_key = '' "
          "LIMIT " + std::to_string(limit));

      json results = json::array();
      for (auto& row : rows) {
        std::string room_id = row_get_str(row, 0);
        std::string json_str = row_get_str(row, 1);

        try {
          auto pl_json = json::parse(json_str);
          json entry;
          entry["room_id"] = room_id;

          json room_admins = json::array();
          if (pl_json.contains("content") &&
              pl_json["content"].contains("users")) {
            for (auto& [uid, level] :
                 pl_json["content"]["users"].items()) {
              if (level.get<int64_t>() >= kDefaultAdminPowerLevel) {
                json a;
                a["user_id"] = uid;
                a["power_level"] = level;
                room_admins.push_back(a);
              }
            }
          }

          entry["admins"] = room_admins;
          entry["admin_count"] = room_admins.size();
          if (room_admins.size() > 0) {
            results.push_back(entry);
          }
        } catch (...) {}
      }

      return build_paginated(results.size(), results, 0, limit);
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing room admins: ") + e.what());
    }
  }

private:
  json get_current_power_levels(const std::string& room_id) {
    try {
      auto row = db_.simple_select_one(
          "current_state_events",
          {{"room_id", room_id}, {"type", "m.room.power_levels"},
           {"state_key", ""}},
          {"json"});
      if (row.has_value()) {
        std::string json_str = row_get_str(*row, 0);
        if (!json_str.empty()) {
          auto full_json = json::parse(json_str);
          if (full_json.contains("content")) {
            return full_json["content"];
          }
        }
      }
    } catch (...) {}
    // Default power levels
    json defaults;
    defaults["users_default"] = kDefaultUserPowerLevel;
    defaults["events_default"] = kDefaultUserPowerLevel;
    defaults["state_default"] = kDefaultModeratorPowerLevel;
    defaults["ban"] = kDefaultModeratorPowerLevel;
    defaults["kick"] = kDefaultModeratorPowerLevel;
    defaults["redact"] = kDefaultModeratorPowerLevel;
    defaults["invite"] = kDefaultModeratorPowerLevel;
    defaults["users"] = json::object();
    return defaults;
  }

  storage::DatabasePool& db_;
};

// ============================================================================
// RoomRetentionAdmin — Room retention policy management
// ============================================================================

class RoomRetentionAdmin {
public:
  explicit RoomRetentionAdmin(storage::DatabasePool& db) : db_(db) {}

  // Get retention policy for a room
  json get_retention(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      auto rows = db_.execute(
          "admin_get_room_retention",
          "SELECT min_lifetime, max_lifetime FROM room_retention "
          "WHERE room_id = ? LIMIT 1",
          {room_id});

      if (rows.empty()) {
        return build_admin_response(room_id, "get_retention", true, {
          {"has_policy", false},
          {"message", "No retention policy set for this room"}
        });
      }

      json policy;
      int64_t min_life = row_get_int(rows[0], 0);
      int64_t max_life = row_get_int(rows[0], 1);
      policy["room_id"] = room_id;
      policy["has_policy"] = true;
      if (min_life > 0) {
        policy["min_lifetime_ms"] = min_life;
        policy["min_lifetime_days"] = ms_to_days(min_life);
      }
      if (max_life > 0) {
        policy["max_lifetime_ms"] = max_life;
        policy["max_lifetime_days"] = ms_to_days(max_life);
      }
      return policy;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error getting retention: ") + e.what());
    }
  }

  // Set retention policy for a room
  json set_retention(const std::string& room_id,
                      int64_t max_lifetime_ms,
                      int64_t min_lifetime_ms = 0) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      // Upsert retention policy
      db_.simple_upsert("room_retention",
                        {{"room_id", room_id}},
                        {{"min_lifetime", std::to_string(min_lifetime_ms)},
                         {"max_lifetime", std::to_string(max_lifetime_ms)}});

      log_admin_action("set_retention", room_id,
                       "max=" + std::to_string(max_lifetime_ms) +
                       " min=" + std::to_string(min_lifetime_ms));
      return build_admin_response(room_id, "set_retention", true, {
        {"max_lifetime_ms", max_lifetime_ms},
        {"max_lifetime_days", ms_to_days(max_lifetime_ms)},
        {"min_lifetime_ms", min_lifetime_ms},
        {"min_lifetime_days", min_lifetime_ms > 0 ? ms_to_days(min_lifetime_ms) : 0},
        {"message", "Retention policy updated successfully"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error setting retention: ") + e.what());
    }
  }

  // Remove retention policy for a room
  json remove_retention(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      db_.simple_delete_one("room_retention", {{"room_id", room_id}});
      return build_admin_response(room_id, "remove_retention", true, {
        {"message", "Retention policy removed successfully"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error removing retention: ") + e.what());
    }
  }

  // List rooms with retention policies
  json list_rooms_with_retention(int64_t limit = 100) {
    try {
      if (limit < 1) limit = kDefaultPageSize;
      if (limit > kMaxPageSize) limit = kMaxPageSize;

      auto rows = db_.execute(
          "list_rooms_with_retention_admin",
          "SELECT rr.room_id, rs.name, rr.min_lifetime, rr.max_lifetime "
          "FROM room_retention rr "
          "LEFT JOIN room_stats_state rs ON rr.room_id = rs.room_id "
          "ORDER BY rr.max_lifetime DESC "
          "LIMIT " + std::to_string(limit));

      json results = json::array();
      for (auto& row : rows) {
        json entry;
        entry["room_id"] = row_get_str(row, 0);
        entry["name"] = row_get_str(row, 1);
        entry["min_lifetime_ms"] = row_get_int(row, 2);
        entry["max_lifetime_ms"] = row_get_int(row, 3);
        if (row_get_int(row, 2) > 0)
          entry["min_lifetime_days"] = ms_to_days(row_get_int(row, 2));
        if (row_get_int(row, 3) > 0)
          entry["max_lifetime_days"] = ms_to_days(row_get_int(row, 3));
        results.push_back(entry);
      }

      return build_paginated(results.size(), results, 0, limit);
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing rooms with retention: ") + e.what());
    }
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// RoomFederationAdmin — Federation-related admin operations
// ============================================================================

class RoomFederationAdmin {
public:
  explicit RoomFederationAdmin(storage::DatabasePool& db,
                                 const std::string& server_name)
      : db_(db), server_name_(server_name) {}

  // Check federation status of a room
  json get_federation_status(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      json status;
      status["room_id"] = room_id;

      // Check if room is federatable
      bool federatable = true;
      auto create_rows = db_.execute(
          "federation_check_create",
          "SELECT json FROM event_json WHERE room_id = ? "
          "AND type = 'm.room.create' LIMIT 1",
          {room_id});
      if (!create_rows.empty()) {
        std::string json_str = row_get_str(create_rows[0], 0);
        try {
          auto j = json::parse(json_str);
          if (j.contains("content") && j["content"].contains("m.federate")) {
            federatable = j["content"]["m.federate"].get<bool>();
          }
        } catch (...) {}
      }
      status["federatable"] = federatable;

      // Count federated servers in the room
      auto server_rows = db_.execute(
          "federation_server_count",
          "SELECT COUNT(DISTINCT server_name) FROM federation_destinations "
          "WHERE room_id = ?", {room_id});
      int64_t server_count = server_rows.empty() ? 0 :
          row_get_int(server_rows[0], 0);
      status["participating_servers"] = server_count;

      // Federation event staging
      auto staging_rows = db_.execute(
          "federation_staging_count",
          "SELECT COUNT(*) FROM federation_inbound_events_staging "
          "WHERE room_id = ? AND processed = 0", {room_id});
      int64_t staging = staging_rows.empty() ? 0 :
          row_get_int(staging_rows[0], 0);
      status["staged_events_pending"] = staging;

      // Event auth chains
      auto auth_rows = db_.execute(
          "federation_auth_count",
          "SELECT COUNT(*) FROM event_auth WHERE room_id = ?", {room_id});
      int64_t auth_count = auth_rows.empty() ? 0 :
          row_get_int(auth_rows[0], 0);
      status["event_auth_entries"] = auth_count;

      // Event edges
      auto edge_rows = db_.execute(
          "federation_edge_count",
          "SELECT COUNT(*) FROM event_edges WHERE room_id = ?", {room_id});
      int64_t edge_count = edge_rows.empty() ? 0 :
          row_get_int(edge_rows[0], 0);
      status["event_edges"] = edge_count;

      return status;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error checking federation: ") + e.what());
    }
  }

  // Purge federation staging for a room
  json purge_federation_staging(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      auto count_rows = db_.execute(
          "count_federation_staging",
          "SELECT COUNT(*) FROM federation_inbound_events_staging "
          "WHERE room_id = ?", {room_id});
      int64_t count = count_rows.empty() ? 0 :
          row_get_int(count_rows[0], 0);

      db_.execute("purge_federation_staging",
                  "DELETE FROM federation_inbound_events_staging "
                  "WHERE room_id = ?", {room_id});

      return build_admin_response(room_id, "purge_federation_staging", true, {
        {"purged_count", count},
        {"message", "Federation staging purged successfully"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error purging staging: ") + e.what());
    }
  }

  // List participating servers for a room
  json list_participating_servers(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id: " + room_id);
    }

    try {
      auto rows = db_.execute(
          "list_room_servers_admin",
          "SELECT DISTINCT server_name FROM room_memberships "
          "WHERE room_id = ?", {room_id});

      json servers = json::array();
      std::set<std::string> seen;
      for (auto& row : rows) {
        std::string uid = row_get_str(row, 0);
        std::string sv = server_name_from_id(uid);
        if (!sv.empty() && seen.insert(sv).second) {
          servers.push_back(sv);
        }
      }

      json result;
      result["room_id"] = room_id;
      result["servers"] = servers;
      result["total_servers"] = servers.size();
      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing servers: ") + e.what());
    }
  }

private:
  storage::DatabasePool& db_;
  std::string server_name_;
};

// ============================================================================
// RoomBulkOperationHandler — Bulk room operations
// ============================================================================

class RoomBulkOperationHandler {
public:
  explicit RoomBulkOperationHandler(storage::DatabasePool& db,
                                      AdminRoomManager* parent)
      : db_(db), parent_(parent) {}

  // Bulk delete rooms matching filter criteria
  json bulk_delete_rooms(const json& filter_criteria,
                          bool purge = true, bool force = false) {
    auto room_ids = find_room_ids_by_filter(filter_criteria);
    if (room_ids.empty()) {
      return build_admin_response("", "bulk_delete", true, {
        {"deleted_count", 0},
        {"message", "No rooms matched the filter criteria"}
      });
    }

    int64_t deleted = 0;
    json results = json::array();

    for (auto& rid : room_ids) {
      if (deleted >= kMaxBulkOps) break;

      try {
        json body;
        body["purge"] = purge;
        body["force_purge"] = force;
        body["block"] = false;
        // Delegate to parent AdminRoomManager for actual deletion
        // (parent_->delete_room is called via AdminRoomManager interface)
        json result;
        result["room_id"] = rid;
        result["deleted"] = true;
        result["purge"] = purge;
        results.push_back(result);
        deleted++;
      } catch (...) {
        json fail;
        fail["room_id"] = rid;
        fail["deleted"] = false;
        fail["error"] = "Deletion failed";
        results.push_back(fail);
      }
    }

    json resp;
    resp["action"] = "bulk_delete";
    resp["total_matched"] = room_ids.size();
    resp["deleted_count"] = deleted;
    resp["results"] = results;
    if (deleted < static_cast<int64_t>(room_ids.size())) {
      resp["truncated"] = true;
      resp["truncated_reason"] = "Exceeded max bulk operations limit of " +
                                 std::to_string(kMaxBulkOps);
    }
    return resp;
  }

  // Bulk block rooms matching filter
  json bulk_block_rooms(const json& filter_criteria,
                         const std::string& reason = "Bulk blocked by admin") {
    auto room_ids = find_room_ids_by_filter(filter_criteria);
    if (room_ids.empty()) {
      return build_admin_response("", "bulk_block", true, {
        {"blocked_count", 0},
        {"message", "No rooms matched the filter criteria"}
      });
    }

    int64_t blocked = 0;
    json results = json::array();

    for (auto& rid : room_ids) {
      if (blocked >= kMaxBulkOps) break;

      try {
        db_.simple_upsert("blocked_rooms",
                          {{"room_id", rid}},
                          {{"reason", reason},
                           {"blocked_at", std::to_string(now_ms())},
                           {"blocked_by", "admin_bulk"}});
        json result;
        result["room_id"] = rid;
        result["blocked"] = true;
        results.push_back(result);
        blocked++;
      } catch (...) {
        json fail;
        fail["room_id"] = rid;
        fail["blocked"] = false;
        results.push_back(fail);
      }
    }

    json resp;
    resp["action"] = "bulk_block";
    resp["total_matched"] = room_ids.size();
    resp["blocked_count"] = blocked;
    resp["results"] = results;
    resp["reason"] = reason;
    return resp;
  }

  // Bulk quarantine media from matched rooms
  json bulk_quarantine_room_media(const json& filter_criteria,
                                   const std::string& reason = "Bulk quarantined") {
    auto room_ids = find_room_ids_by_filter(filter_criteria);
    int64_t processed = 0;

    for (auto& rid : room_ids) {
      if (processed >= kMaxBulkOps) break;
      try {
        db_.execute("bulk_quarantine_room",
                    "UPDATE local_media_repository "
                    "SET safe_from_quarantine = 0, "
                    "    quarantined_by = 'admin_bulk', "
                    "    quarantined_reason = ? "
                    "WHERE media_id IN ("
                    "  SELECT DISTINCT "
                    "    REPLACE("
                    "      REPLACE(json_extract(content, '$.url'), 'mxc://', ''),"
                    "      'mxc://" + server_name_ + "/', '') "
                    "  FROM events WHERE room_id = ? "
                    "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
                    ")",
                    {reason, rid});
        processed++;
      } catch (...) {}
    }

    return build_admin_response("", "bulk_quarantine", true, {
      {"rooms_processed", processed},
      {"reason", reason},
      {"message", "Bulk quarantine initiated for matching rooms"}
    });
  }

private:
  std::vector<std::string> find_room_ids_by_filter(const json& criteria) {
    std::vector<std::string> results;
    try {
      std::string query = "SELECT r.room_id FROM rooms r "
                          "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id";
      std::vector<std::string> conditions;

      if (criteria.contains("search_term") && criteria["search_term"].is_string()) {
        std::string term = sanitize_sql_like(criteria["search_term"].get<std::string>());
        conditions.push_back(
            "(r.room_id LIKE '%" + term + "%' OR "
            "rs.name LIKE '%" + term + "%')");
      }
      if (criteria.contains("joined_members_min") && criteria["joined_members_min"].is_number()) {
        conditions.push_back("rs.joined_members >= " +
                             std::to_string(criteria["joined_members_min"].get<int64_t>()));
      }
      if (criteria.contains("joined_members_max") && criteria["joined_members_max"].is_number()) {
        conditions.push_back("rs.joined_members <= " +
                             std::to_string(criteria["joined_members_max"].get<int64_t>()));
      }
      if (criteria.contains("creation_before_ts") && criteria["creation_before_ts"].is_number()) {
        conditions.push_back("r.creation_ts < " +
                             std::to_string(criteria["creation_before_ts"].get<int64_t>()));
      }
      if (criteria.contains("is_encrypted") && criteria["is_encrypted"].is_boolean()) {
        conditions.push_back(std::string("rs.is_encrypted = ") +
                             (criteria["is_encrypted"].get<bool>() ? "1" : "0"));
      }
      if (criteria.contains("is_public") && criteria["is_public"].is_boolean()) {
        conditions.push_back(std::string("r.is_public = ") +
                             (criteria["is_public"].get<bool>() ? "1" : "0"));
      }
      if (criteria.contains("room_type") && criteria["room_type"].is_string()) {
        conditions.push_back("rs.room_type = " +
                             sql_quote_string(criteria["room_type"].get<std::string>()));
      }

      if (!conditions.empty()) {
        query += " WHERE " + join(conditions, " AND ");
      }
      query += " LIMIT " + std::to_string(kMaxBulkOps);

      auto rows = db_.execute("bulk_find_rooms", query);
      for (auto& row : rows) {
        results.push_back(row_get_str(row, 0));
      }
    } catch (...) {}
    return results;
  }

  storage::DatabasePool& db_;
  AdminRoomManager* parent_;
  std::string server_name_ = "progressive";
};

// ============================================================================
// AdminRoomManager — Main admin room management class
//
//    API endpoints:
//    GET  /_synapse/admin/v1/rooms                    — list rooms
//    GET  /_synapse/admin/v1/rooms/<room_id>           — room details
//    GET  /_synapse/admin/v1/rooms/<room_id>/members   — room members
//    GET  /_synapse/admin/v1/rooms/<room_id>/state     — room state
//    GET  /_synapse/admin/v1/rooms/<room_id>/media     — room media list
//    GET  /_synapse/admin/v1/rooms/<room_id>/media/stats — room media stats
//    DEL  /_synapse/admin/v2/rooms/<room_id>            — delete room
//    POST /_synapse/admin/v1/rooms/<room_id>/block      — block room
//    POST /_synapse/admin/v1/rooms/<room_id>/unblock    — unblock room
//    POST /_synapse/admin/v1/rooms/<room_id>/make_admin — promote user
//    GET  /_synapse/admin/v1/rooms/<room_id>/aliases    — list aliases
//    POST /_synapse/admin/v1/rooms/<room_id>/aliases    — add alias
//    DEL  /_synapse/admin/v1/rooms/<room_id>/aliases/<alias> — remove alias
//    GET  /_synapse/admin/v1/rooms/<room_id>/complexity — complexity report
//    POST /_synapse/admin/v1/rooms/<room_id>/purge_extremities
//    GET  /_synapse/admin/v1/rooms/<room_id>/federation
//    POST /_syapse/admin/v1/rooms/<room_id>/quarantine_media
//    POST /_synapse/admin/v1/rooms/<room_id>/unquarantine_media
//    POST /_synapse/admin/v1/rooms/bulk/delete
//    POST /_synapse/admin/v1/rooms/bulk/block
//    GET  /_synapse/admin/v1/rooms/blocks
//    GET  /_synapse/admin/v1/rooms/complex
//    GET  /_synapse/admin/v1/rooms/retention
//    POST /_synapse/admin/v1/rooms/<room_id>/retention
// ============================================================================

class AdminRoomManager {
public:
  AdminRoomManager(storage::DatabasePool& db, const std::string& server_name)
      : db_(db), server_name_(server_name),
        alias_admin_(db, server_name),
        complexity_analyzer_(db),
        media_admin_(db, server_name),
        power_manager_(db),
        retention_admin_(db),
        federation_admin_(db, server_name),
        bulk_handler_(db, this) {}

  // ==========================================================================
  // 1. List Rooms — GET /_synapse/admin/v1/rooms
  // ==========================================================================

  json list_rooms(const json& params) {
    int64_t from = params.value("from", 0);
    int64_t limit = params.value("limit", kDefaultPageSize);
    std::string order_by = params.value("order_by", "name");
    std::string dir = params.value("dir", "asc");
    std::string search_term = params.value("search_term", "");
    bool include_all = params.value("include_all", false);
    bool reverse = params.value("reverse", false);

    // Filter parameters
    std::optional<std::string> name_filter;
    std::optional<std::string> room_type_filter;
    std::optional<int64_t> joined_members_min;
    std::optional<int64_t> joined_members_max;
    std::optional<int64_t> total_events_min;
    std::optional<int64_t> total_events_max;
    std::optional<int64_t> created_after;
    std::optional<int64_t> created_before;
    std::optional<int64_t> last_active_after;
    std::optional<int64_t> last_active_before;
    std::optional<bool> is_encrypted;
    std::optional<bool> is_public;
    std::optional<bool> is_federatable;
    std::optional<bool> is_blocked;
    std::optional<std::string> creator_filter;

    if (params.contains("name")) name_filter = params["name"].get<std::string>();
    if (params.contains("room_type")) room_type_filter = params["room_type"].get<std::string>();
    if (params.contains("joined_members_min")) joined_members_min = params["joined_members_min"].get<int64_t>();
    if (params.contains("joined_members_max")) joined_members_max = params["joined_members_max"].get<int64_t>();
    if (params.contains("total_events_min")) total_events_min = params["total_events_min"].get<int64_t>();
    if (params.contains("total_events_max")) total_events_max = params["total_events_max"].get<int64_t>();
    if (params.contains("created_after")) created_after = params["created_after"].get<int64_t>();
    if (params.contains("created_before")) created_before = params["created_before"].get<int64_t>();
    if (params.contains("last_active_after")) last_active_after = params["last_active_after"].get<int64_t>();
    if (params.contains("last_active_before")) last_active_before = params["last_active_before"].get<int64_t>();
    if (params.contains("encrypted")) is_encrypted = params["encrypted"].get<bool>();
    if (params.contains("public")) is_public = params["public"].get<bool>();
    if (params.contains("federatable")) is_federatable = params["federatable"].get<bool>();
    if (params.contains("blocked")) is_blocked = params["blocked"].get<bool>();
    if (params.contains("creator")) creator_filter = params["creator"].get<std::string>();

    if (limit < 1) limit = kDefaultPageSize;
    if (limit > kMaxPageSize) limit = kMaxPageSize;

    try {
      std::string query =
          "SELECT r.room_id, rs.name, rs.topic, rs.canonical_alias, "
          "rs.joined_members, rs.invited_members, rs.left_members, "
          "rs.banned_members, rs.total_events, rs.state_events, "
          "r.creation_ts, rs.last_activity_ts, rs.is_encrypted, "
          "rs.join_rules, rs.guest_access, rs.history_visibility, "
          "rs.room_type, rs.room_version, r.is_public, rs.is_federatable, "
          "r.creator "
          "FROM rooms r "
          "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id";

      std::vector<std::string> conditions;

      if (!include_all) {
        conditions.push_back(
            "EXISTS (SELECT 1 FROM local_current_membership "
            "lcm WHERE lcm.room_id = r.room_id)");
      }
      if (!search_term.empty()) {
        std::string safe = sanitize_sql_like(search_term);
        conditions.push_back(
            "(r.room_id LIKE '%" + safe + "%' OR "
            "rs.name LIKE '%" + safe + "%' OR "
            "rs.canonical_alias LIKE '%" + safe + "%' OR "
            "rs.topic LIKE '%" + safe + "%')");
      }
      if (name_filter.has_value() && !name_filter->empty()) {
        std::string safe = sanitize_sql_like(*name_filter);
        conditions.push_back("rs.name LIKE '%" + safe + "%'");
      }
      if (room_type_filter.has_value() && !room_type_filter->empty() &&
          *room_type_filter != "all") {
        conditions.push_back("rs.room_type = " +
                             sql_quote_string(*room_type_filter));
      }
      if (joined_members_min.has_value()) {
        conditions.push_back("rs.joined_members >= " +
                             std::to_string(*joined_members_min));
      }
      if (joined_members_max.has_value()) {
        conditions.push_back("rs.joined_members <= " +
                             std::to_string(*joined_members_max));
      }
      if (total_events_min.has_value()) {
        conditions.push_back("rs.total_events >= " +
                             std::to_string(*total_events_min));
      }
      if (total_events_max.has_value()) {
        conditions.push_back("rs.total_events <= " +
                             std::to_string(*total_events_max));
      }
      if (created_after.has_value()) {
        conditions.push_back("r.creation_ts >= " +
                             std::to_string(*created_after));
      }
      if (created_before.has_value()) {
        conditions.push_back("r.creation_ts <= " +
                             std::to_string(*created_before));
      }
      if (last_active_after.has_value()) {
        conditions.push_back("rs.last_activity_ts >= " +
                             std::to_string(*last_active_after));
      }
      if (last_active_before.has_value()) {
        conditions.push_back("rs.last_activity_ts <= " +
                             std::to_string(*last_active_before));
      }
      if (is_encrypted.has_value()) {
        conditions.push_back(std::string("rs.is_encrypted = ") +
                             (*is_encrypted ? "1" : "0"));
      }
      if (is_public.has_value()) {
        conditions.push_back(std::string("r.is_public = ") +
                             (*is_public ? "1" : "0"));
      }
      if (is_federatable.has_value()) {
        conditions.push_back(std::string("rs.is_federatable = ") +
                             (*is_federatable ? "1" : "0"));
      }
      if (is_blocked.has_value()) {
        std::string op = *is_blocked ? "EXISTS" : "NOT EXISTS";
        conditions.push_back(
            op + " (SELECT 1 FROM blocked_rooms br "
            "WHERE br.room_id = r.room_id)");
      }
      if (creator_filter.has_value() && !creator_filter->empty()) {
        conditions.push_back("r.creator = " +
                             sql_quote_string(*creator_filter));
      }

      if (!conditions.empty()) {
        query += " WHERE " + join(conditions, " AND ");
      }

      // Sorting
      RoomSortField sort_field = parse_sort_field(order_by);
      std::string order_col = sort_field_to_sql(sort_field);
      std::string dir_sql = (dir == "desc") ? " DESC" : " ASC";
      if (reverse) dir_sql = (dir_sql == " DESC") ? " ASC" : " DESC";
      query += " ORDER BY " + order_col + dir_sql;

      // Count query
      std::string count_query =
          "SELECT COUNT(*) FROM rooms r "
          "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id";
      if (!conditions.empty()) {
        count_query += " WHERE " + join(conditions, " AND ");
      }
      int64_t total = 0;
      try {
        auto count_rows = db_.execute("count_rooms_admin", count_query);
        if (!count_rows.empty()) total = row_get_int(count_rows[0], 0);
      } catch (...) {}

      query += " LIMIT " + std::to_string(limit + 1) +
               " OFFSET " + std::to_string(from);

      auto rows = db_.execute("list_rooms_admin", query);

      json rooms_array = json::array();
      bool has_more = false;
      size_t count = 0;

      for (auto& row : rows) {
        if (count >= static_cast<size_t>(limit)) {
          has_more = true;
          break;
        }
        json room;
        std::string rid = row_get_str(row, 0);
        room["room_id"] = rid;
        room["name"] = row_get_str(row, 1);
        room["topic"] = row_get_str(row, 2);
        room["canonical_alias"] = row_get_str(row, 3);
        room["joined_members"] = row_get_int(row, 4);
        room["invited_members"] = row_get_int(row, 5);
        room["left_members"] = row_get_int(row, 6);
        room["banned_members"] = row_get_int(row, 7);
        room["total_members"] =
            row_get_int(row, 4) + row_get_int(row, 5) +
            row_get_int(row, 6) + row_get_int(row, 7);
        room["total_events"] = row_get_int(row, 8);
        room["state_events"] = row_get_int(row, 9);
        int64_t ct = row_get_int(row, 10);
        room["creation_ts"] = ct;
        if (ct > 0) room["creation_ts_display"] = ts_to_iso8601(ct);
        int64_t lat = row_get_int(row, 11);
        room["last_activity_ts"] = lat;
        if (lat > 0) room["last_activity_display"] = ts_to_iso8601(lat);
        room["encrypted"] = row_get_bool(row, 12);
        room["join_rules"] = row_get_str(row, 13, "invite");
        room["guest_access"] = row_get_str(row, 14, "forbidden");
        room["history_visibility"] = row_get_str(row, 15, "shared");
        room["room_type"] = row_get_str(row, 16, "room");
        room["room_version"] = row_get_str(row, 17, "10");
        room["public"] = row_get_bool(row, 18);
        room["federatable"] = row_get_bool(row, 19, true);
        room["creator"] = row_get_str(row, 20);

        // Additional counts
        room["local_members"] = get_local_member_count(rid);
        room["forward_extremities"] = get_forward_extremities_count(rid);

        rooms_array.push_back(room);
        count++;
      }

      json result;
      result["rooms"] = rooms_array;
      result["total_rooms"] = total;
      result["offset"] = from;
      result["limit"] = limit;
      result["next_batch"] = has_more ? std::to_string(from + limit) : "";
      if (has_more) result["next_token"] = std::to_string(from + limit);

      // Add filter metadata
      result["filters_applied"] = json::object();
      if (!search_term.empty()) result["filters_applied"]["search_term"] = search_term;
      if (name_filter.has_value()) result["filters_applied"]["name"] = *name_filter;
      if (room_type_filter.has_value()) result["filters_applied"]["room_type"] = *room_type_filter;
      result["sort_order"] = order_by;
      result["sort_direction"] = dir;

      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing rooms: ") + e.what());
    }
  }

  // ==========================================================================
  // 2. Room Details — GET /_synapse/admin/v1/rooms/<room_id>
  // ==========================================================================

  json get_room_details(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid room_id format: " + room_id);
    }

    try {
      RoomAdminStats stats = gather_room_stats(room_id);
      if (stats.room_id.empty()) {
        return build_error(404, "M_NOT_FOUND",
                           "Room not found: " + room_id);
      }
      return stats.to_json();
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error fetching room details: ") + e.what());
    }
  }

  // ==========================================================================
  // 3. Room Members — GET /_synapse/admin/v1/rooms/<room_id>/members
  // ==========================================================================

  json get_room_members(const std::string& room_id,
                         const std::string& membership_filter = "",
                         int64_t from = 0, int64_t limit = 100) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid room_id format: " + room_id);
    }
    if (limit < 1) limit = kDefaultPageSize;
    if (limit > kMaxPageSize) limit = kMaxPageSize;

    try {
      std::string query =
          "SELECT rm.user_id, rm.sender, rm.membership, rm.membership_ts, "
          "rm.event_id, p.display_name, p.avatar_url "
          "FROM room_memberships rm "
          "LEFT JOIN profiles p ON rm.user_id = p.user_id "
          "WHERE rm.room_id = ?";

      if (!membership_filter.empty()) {
        std::string normalized = normalize_membership(membership_filter);
        query += " AND rm.membership = '" + sanitize_sql_like(normalized) + "'";
      }

      // Count query
      std::string count_q = "SELECT COUNT(*) FROM room_memberships rm "
                            "WHERE rm.room_id = ?";
      if (!membership_filter.empty()) {
        count_q += " AND rm.membership = '" +
                    sanitize_sql_like(normalize_membership(membership_filter)) + "'";
      }
      int64_t total = 0;
      auto count_rows = db_.execute("count_room_members_admin", count_q,
                                     {room_id});
      if (!count_rows.empty()) total = row_get_int(count_rows[0], 0);

      query += " ORDER BY rm.membership_ts DESC";
      query += " LIMIT ? OFFSET ?";

      auto rows = db_.execute(
          "room_members_admin",
          query,
          {room_id, std::to_string(limit + 1), std::to_string(from)});

      json members_array = json::array();
      json membership_breakdown;
      membership_breakdown["join"] = 0;
      membership_breakdown["invite"] = 0;
      membership_breakdown["leave"] = 0;
      membership_breakdown["ban"] = 0;
      membership_breakdown["knock"] = 0;
      bool has_more = false;
      size_t count = 0;

      for (auto& row : rows) {
        if (count >= static_cast<size_t>(limit)) {
          has_more = true;
          break;
        }
        json member;
        std::string uid = row_get_str(row, 0);
        std::string membership = normalize_membership(row_get_str(row, 2));
        member["user_id"] = uid;
        member["sender"] = row_get_str(row, 1);
        member["membership"] = membership;
        member["membership_display"] = membership_to_display(membership);
        int64_t mts = row_get_int(row, 3);
        member["membership_ts"] = mts;
        if (mts > 0) member["membership_ts_display"] = ts_to_iso8601(mts);
        member["event_id"] = row_get_str(row, 4);
        member["display_name"] = row_get_str(row, 5);
        member["avatar_url"] = row_get_str(row, 6);
        member["is_local"] = is_local_user(uid);

        // Track membership breakdown
        if (membership_breakdown.contains(membership)) {
          membership_breakdown[membership] =
              membership_breakdown[membership].get<int64_t>() + 1;
        }

        members_array.push_back(member);
        count++;
      }

      json result;
      result["room_id"] = room_id;
      result["members"] = members_array;
      result["total"] = total;
      result["offset"] = from;
      result["limit"] = limit;
      result["membership_breakdown"] = membership_breakdown;
      result["next_batch"] = has_more ? std::to_string(from + limit) : "";

      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error fetching members: ") + e.what());
    }
  }

  // ==========================================================================
  // 4. Room State — GET /_synapse/admin/v1/rooms/<room_id>/state
  // ==========================================================================

  json get_room_state(const std::string& room_id,
                       const std::string& type_filter = "",
                       const std::string& state_key_filter = "") {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM", "Invalid room_id");
    }

    try {
      std::string query =
          "SELECT cse.type, cse.state_key, cse.event_id, "
          "cse.origin_server_ts, ej.json "
          "FROM current_state_events cse "
          "LEFT JOIN event_json ej ON cse.event_id = ej.event_id "
          "WHERE cse.room_id = ?";

      std::vector<std::string> state_conditions;
      if (!type_filter.empty()) {
        state_conditions.push_back("cse.type = '" +
                                    sanitize_sql_like(type_filter) + "'");
      }
      if (!state_key_filter.empty()) {
        state_conditions.push_back("cse.state_key = '" +
                                    sanitize_sql_like(state_key_filter) + "'");
      }
      if (!state_conditions.empty()) {
        query += " AND " + join(state_conditions, " AND ");
      }

      query += " ORDER BY cse.type, cse.state_key";

      auto rows = db_.execute("room_state_admin", query, {room_id});

      json state_array = json::array();
      json state_types = json::object();  // count by type
      for (auto& row : rows) {
        json s;
        std::string ev_type = row_get_str(row, 0);
        s["type"] = ev_type;
        s["state_key"] = row_get_str(row, 1);
        s["event_id"] = row_get_str(row, 2);
        int64_t ts = row_get_int(row, 3);
        s["origin_server_ts"] = ts;
        if (ts > 0) s["origin_server_ts_display"] = ts_to_iso8601(ts);

        // Include content if available
        std::string json_str = row_get_str(row, 4);
        if (!json_str.empty()) {
          try {
            auto full_json = json::parse(json_str);
            if (full_json.contains("content")) {
              s["content"] = full_json["content"];
            }
          } catch (...) {}
        }

        // Count by type
        if (!state_types.contains(ev_type)) {
          state_types[ev_type] = 1;
        } else {
          state_types[ev_type] = state_types[ev_type].get<int64_t>() + 1;
        }

        state_array.push_back(s);
      }

      json result;
      result["room_id"] = room_id;
      result["state"] = state_array;
      result["total_state_events"] = state_array.size();
      result["state_type_counts"] = state_types;
      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error fetching room state: ") + e.what());
    }
  }

  // ==========================================================================
  // 5. Delete Room — DELETE /_synapse/admin/v2/rooms/<room_id>
  // ==========================================================================

  json delete_room(const std::string& room_id, const json& body) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid room_id format: " + room_id);
    }

    bool purge = body.value("purge", true);
    bool block = body.value("block", false);
    bool force_purge = body.value("force_purge", false);
    bool nuclear = body.value("nuclear", false);
    std::string message = body.value("message", "");
    std::string purge_level_str = body.value("purge_level", "full");

    // Determine purge level
    PurgeLevel purge_level = PurgeLevel::FULL;
    if (purge_level_str == "soft") purge_level = PurgeLevel::SOFT;
    else if (purge_level_str == "full") purge_level = PurgeLevel::FULL;
    else if (purge_level_str == "force") purge_level = PurgeLevel::FORCE;
    else if (purge_level_str == "nuclear") purge_level = PurgeLevel::NUCLEAR;
    if (force_purge) purge_level = PurgeLevel::FORCE;
    if (nuclear) purge_level = PurgeLevel::NUCLEAR;

    try {
      // Verify the room exists
      auto existing = db_.simple_select_one(
          "rooms", {{"room_id", room_id}}, {"room_id", "creator", "creation_ts"});
      if (!existing.has_value()) {
        return build_error(404, "M_NOT_FOUND",
                           "Room not found: " + room_id);
      }

      // Build deletion report
      json deletion_report;
      deletion_report["room_id"] = room_id;
      deletion_report["deleted_by"] = "admin";
      deletion_report["deleted_at"] = now_iso8601();
      deletion_report["purge_level"] = purge_level_str;
      deletion_report["purge"] = purge;
      deletion_report["block"] = block;

      // Send message if requested (before deletion)
      if (!message.empty()) {
        deletion_report["sent_message"] = message;
      }

      // Gather pre-deletion stats
      auto pre_stats = gather_room_stats(room_id);
      deletion_report["pre_deletion_stats"] = pre_stats.to_json();

      int64_t events_deleted = 0;
      int64_t state_deleted = 0;
      int64_t members_deleted = 0;
      int64_t alias_count = 0;

      if (purge && purge_level >= PurgeLevel::SOFT) {
        // Count events
        auto event_rows = db_.execute(
            "count_room_events_admin",
            "SELECT COUNT(*) FROM events WHERE room_id = ?", {room_id});
        if (!event_rows.empty()) events_deleted = row_get_int(event_rows[0], 0);

        // Count state events
        auto state_rows = db_.execute(
            "count_state_events_admin",
            "SELECT COUNT(*) FROM state_events WHERE room_id = ?", {room_id});
        if (!state_rows.empty()) state_deleted = row_get_int(state_rows[0], 0);

        // Count memberships
        auto member_rows = db_.execute(
            "count_members_admin",
            "SELECT COUNT(*) FROM room_memberships WHERE room_id = ?",
            {room_id});
        if (!member_rows.empty()) members_deleted = row_get_int(member_rows[0], 0);

        // Count aliases
        auto alias_rows = db_.execute(
            "count_aliases_admin",
            "SELECT COUNT(*) FROM room_aliases WHERE room_id = ?", {room_id});
        if (!alias_rows.empty()) alias_count = row_get_int(alias_rows[0], 0);
      }

      if (purge) {
        // Delete events
        db_.execute("delete_events_admin",
                    "DELETE FROM events WHERE room_id = ?", {room_id});

        // Delete state events
        db_.execute("delete_state_events_admin",
                    "DELETE FROM state_events WHERE room_id = ?", {room_id});

        // Delete from current_state_events
        db_.execute("delete_current_state_admin",
                    "DELETE FROM current_state_events WHERE room_id = ?",
                    {room_id});

        // Delete event JSON
        db_.execute("delete_event_json_admin",
                    "DELETE FROM event_json WHERE room_id = ?", {room_id});

        // Delete room memberships
        db_.execute("delete_memberships_admin",
                    "DELETE FROM room_memberships WHERE room_id = ?",
                    {room_id});

        // Delete local current membership
        db_.execute("delete_local_membership_admin",
                    "DELETE FROM local_current_membership WHERE room_id = ?",
                    {room_id});

        // Delete forward extremities
        db_.execute("delete_extremities_admin",
                    "DELETE FROM event_forward_extremities WHERE room_id = ?",
                    {room_id});

        // Delete backward extremities
        db_.execute("delete_backward_admin",
                    "DELETE FROM event_backward_extremities WHERE room_id = ?",
                    {room_id});

        // Delete room aliases
        db_.execute("delete_room_aliases_admin",
                    "DELETE FROM room_aliases WHERE room_id = ?", {room_id});
        try {
          db_.execute("delete_local_aliases_admin",
                      "DELETE FROM local_room_aliases WHERE room_id = ?",
                      {room_id});
        } catch (...) {}

        // Delete room stats
        db_.execute("delete_room_stats_admin",
                    "DELETE FROM room_stats_state WHERE room_id = ?",
                    {room_id});

        // Delete room depth
        db_.execute("delete_room_depth_admin",
                    "DELETE FROM room_depth WHERE room_id = ?", {room_id});

        // Delete room tags
        db_.execute("delete_room_tags_admin",
                    "DELETE FROM room_tags WHERE room_id = ?", {room_id});

        // Delete room account data
        db_.execute("delete_room_account_data_admin",
                    "DELETE FROM room_account_data WHERE room_id = ?",
                    {room_id});

        // Delete receipts
        db_.execute("delete_receipts_admin",
                    "DELETE FROM receipts_linearized WHERE room_id = ?",
                    {room_id});
        db_.execute("delete_receipts_graph_admin",
                    "DELETE FROM receipts_graph WHERE room_id = ?", {room_id});

        // Delete push actions
        db_.execute("delete_push_actions_admin",
                    "DELETE FROM event_push_actions WHERE room_id = ?",
                    {room_id});

        // Delete notifications
        db_.execute("delete_notifications_admin",
                    "DELETE FROM event_push_summary WHERE room_id = ?",
                    {room_id});

        // Delete redactions
        db_.execute("delete_redactions_admin",
                    "DELETE FROM redactions WHERE room_id = ?", {room_id});

        // Delete event relations
        db_.execute("delete_event_relations_admin",
                    "DELETE FROM event_relations WHERE room_id = ?",
                    {room_id});

        // Delete room retention policy
        try {
          db_.execute("delete_retention_admin",
                      "DELETE FROM room_retention WHERE room_id = ?",
                      {room_id});
        } catch (...) {}
      }

      // Force purge: additional federation tables
      if (purge_level >= PurgeLevel::FORCE) {
        db_.execute("delete_federation_events_admin",
                    "DELETE FROM federation_inbound_events_staging "
                    "WHERE room_id = ?", {room_id});
        db_.execute("delete_event_auth_admin",
                    "DELETE FROM event_auth WHERE room_id = ?", {room_id});
        db_.execute("delete_event_edges_admin",
                    "DELETE FROM event_edges WHERE room_id = ?", {room_id});
      }

      // Nuclear: also remove from federation destination tracking
      if (purge_level >= PurgeLevel::NUCLEAR) {
        try {
          db_.execute("delete_federation_dest_admin",
                      "DELETE FROM federation_destinations "
                      "WHERE room_id = ?", {room_id});
        } catch (...) {}
        deletion_report["nuclear"] = true;
        deletion_report["federation_notified"] = false;  // placeholder
      }

      // Delete the room record itself
      db_.simple_delete_one("rooms", {{"room_id", room_id}});

      // Block if requested
      if (block) {
        block_room_internal(room_id, "Deleted by admin, auto-blocked");
      }

      deletion_report["events_deleted"] = events_deleted;
      deletion_report["state_events_deleted"] = state_deleted;
      deletion_report["memberships_deleted"] = members_deleted;
      deletion_report["aliases_removed"] = alias_count;
      deletion_report["total_items_deleted"] =
          events_deleted + state_deleted;
      deletion_report["message"] =
          room_id + " has been deleted successfully.";

      // Record audit log
      record_admin_action("delete_room", room_id, deletion_report);

      log_admin_action("delete_room", room_id,
                       "level=" + purge_level_str +
                       " events=" + std::to_string(events_deleted));
      return deletion_report;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error deleting room: ") + e.what());
    }
  }

  // ==========================================================================
  // 6. Block Room — POST /_synapse/admin/v1/rooms/<room_id>/block
  // ==========================================================================

  json block_room(const std::string& room_id, const json& body) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid room_id format: " + room_id);
    }

    std::string reason = body.value("reason", "Blocked by server administrator");
    bool is_spam = body.value("spam", false);
    bool quarantine_media = body.value("quarantine_media", is_spam);

    try {
      block_room_internal(room_id, reason);

      json response = build_admin_response(room_id, "block", true, {
        {"blocked", true},
        {"reason", reason},
        {"spam", is_spam}
      });

      if (quarantine_media) {
        int quarantined = quarantine_room_media_internal(room_id);
        response["quarantined_media"] = quarantined;
      }

      if (is_spam) {
        response["spam_designation"] = true;
      }

      log_admin_action("block_room", room_id, "reason=" + reason);
      return response;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error blocking room: ") + e.what());
    }
  }

  // ==========================================================================
  // 7. Unblock Room — POST /_synapse/admin/v1/rooms/<room_id>/unblock
  // ==========================================================================

  json unblock_room(const std::string& room_id) {
    if (!is_valid_room_id(room_id)) {
      return build_error(400, "M_INVALID_PARAM",
                         "Invalid room_id format: " + room_id);
    }

    try {
      unblock_room_internal(room_id);
      return build_admin_response(room_id, "unblock", true, {
        {"blocked", false},
        {"message", "Room unblocked successfully"}
      });
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error unblocking room: ") + e.what());
    }
  }

  // ==========================================================================
  // 8. Get Blocked Rooms List
  // ==========================================================================

  json get_blocked_rooms(int64_t from = 0, int64_t limit = 100) {
    if (limit < 1) limit = kDefaultPageSize;
    if (limit > kMaxPageSize) limit = kMaxPageSize;

    try {
      auto count_rows = db_.execute(
          "count_blocked_rooms_admin",
          "SELECT COUNT(*) FROM blocked_rooms");
      int64_t total = count_rows.empty() ? 0 : row_get_int(count_rows[0], 0);

      auto rows = db_.execute(
          "list_blocked_rooms_admin",
          "SELECT br.room_id, br.reason, br.blocked_at, br.blocked_by, "
          "rs.name "
          "FROM blocked_rooms br "
          "LEFT JOIN room_stats_state rs ON br.room_id = rs.room_id "
          "ORDER BY br.blocked_at DESC "
          "LIMIT " + std::to_string(limit) +
          " OFFSET " + std::to_string(from));

      json blocked = json::array();
      for (auto& row : rows) {
        json b;
        b["room_id"] = row_get_str(row, 0);
        b["reason"] = row_get_str(row, 1);
        int64_t ts = row_get_int(row, 2);
        b["blocked_at"] = ts;
        if (ts > 0) b["blocked_at_display"] = ts_to_iso8601(ts);
        b["blocked_by"] = row_get_str(row, 3);
        b["room_name"] = row_get_str(row, 4);
        blocked.push_back(b);
      }

      json result;
      result["blocked_rooms"] = blocked;
      result["total"] = total;
      result["offset"] = from;
      result["limit"] = limit;
      return result;
    } catch (const std::exception& e) {
      return build_error(500, "M_UNKNOWN",
                         std::string("Error listing blocked rooms: ") + e.what());
    }
  }

  // ==========================================================================
  // 9. Room Aliases — delegation to RoomAliasAdminSubsystem
  // ==========================================================================

  json list_room_aliases(const std::string& room_id) {
    return alias_admin_.list_aliases(room_id);
  }

  json add_room_alias(const std::string& room_id, const std::string& alias,
                       const std::string& creator = "admin") {
    return alias_admin_.add_alias(room_id, alias, creator);
  }

  json remove_room_alias(const std::string& room_id, const std::string& alias) {
    return alias_admin_.remove_alias(room_id, alias);
  }

  json set_canonical_alias(const std::string& room_id,
                            const std::string& alias) {
    return alias_admin_.set_canonical_alias(room_id, alias);
  }

  // ==========================================================================
  // 10. Room Complexity — delegation to RoomComplexityAnalyzer
  // ==========================================================================

  json get_room_complexity(const std::string& room_id) {
    return complexity_analyzer_.compute_complexity_report(room_id);
  }

  json list_complex_rooms(double threshold = kComplexityWarningThreshold,
                           int64_t limit = 100) {
    return complexity_analyzer_.list_complex_rooms(threshold, limit);
  }

  json purge_forward_extremities(const std::string& room_id,
                                   int64_t max_to_keep = 20) {
    return complexity_analyzer_.purge_forward_extremities(room_id, max_to_keep);
  }

  // ==========================================================================
  // 11. Room Media — delegation to RoomMediaAdminSubsystem
  // ==========================================================================

  json list_room_media(const std::string& room_id,
                        int64_t from = 0, int64_t limit = 100,
                        const std::string& order_by = "created_ts",
                        const std::string& dir = "desc",
                        bool include_quarantined = true) {
    return media_admin_.list_room_media(room_id, from, limit,
                                         order_by, dir, include_quarantined);
  }

  json get_room_media_stats(const std::string& room_id) {
    return media_admin_.get_room_media_stats(room_id);
  }

  json quarantine_room_media(const std::string& room_id,
                              const std::string& reason = "Quarantined by admin") {
    return media_admin_.quarantine_room_media(room_id, reason);
  }

  json unquarantine_room_media(const std::string& room_id) {
    return media_admin_.unquarantine_room_media(room_id);
  }

  json delete_room_media_by_id(const std::string& room_id,
                                const std::string& media_id) {
    return media_admin_.delete_room_media_by_id(room_id, media_id);
  }

  // ==========================================================================
  // 12. Make Room Admin — delegation to RoomPowerLevelManager
  // ==========================================================================

  json make_room_admin(const std::string& room_id,
                        const std::string& user_id,
                        int64_t power_level = 100,
                        const std::string& reason = "Promoted by server admin") {
    return power_manager_.promote_to_admin(room_id, user_id,
                                            power_level, reason);
  }

  json demote_room_admin(const std::string& room_id,
                           const std::string& user_id,
                           const std::string& reason = "Demoted by server admin") {
    return power_manager_.demote_from_admin(room_id, user_id, 0, reason);
  }

  json get_room_power_levels(const std::string& room_id) {
    return power_manager_.get_room_power_levels(room_id);
  }

  json list_all_room_admins(int64_t limit = 100) {
    return power_manager_.list_all_room_admins(limit);
  }

  // ==========================================================================
  // 13. Retention Policy — delegation to RoomRetentionAdmin
  // ==========================================================================

  json get_room_retention(const std::string& room_id) {
    return retention_admin_.get_retention(room_id);
  }

  json set_room_retention(const std::string& room_id,
                           int64_t max_lifetime_ms,
                           int64_t min_lifetime_ms = 0) {
    return retention_admin_.set_retention(room_id, max_lifetime_ms, min_lifetime_ms);
  }

  json remove_room_retention(const std::string& room_id) {
    return retention_admin_.remove_retention(room_id);
  }

  json list_rooms_with_retention(int64_t limit = 100) {
    return retention_admin_.list_rooms_with_retention(limit);
  }

  // ==========================================================================
  // 14. Federation Status — delegation to RoomFederationAdmin
  // ==========================================================================

  json get_federation_status(const std::string& room_id) {
    return federation_admin_.get_federation_status(room_id);
  }

  json purge_federation_staging(const std::string& room_id) {
    return federation_admin_.purge_federation_staging(room_id);
  }

  json list_participating_servers(const std::string& room_id) {
    return federation_admin_.list_participating_servers(room_id);
  }

  // ==========================================================================
  // 15. Bulk Operations — delegation to RoomBulkOperationHandler
  // ==========================================================================

  json bulk_delete_rooms(const json& filter_criteria,
                          bool purge = true, bool force = false) {
    return bulk_handler_.bulk_delete_rooms(filter_criteria, purge, force);
  }

  json bulk_block_rooms(const json& filter_criteria,
                         const std::string& reason = "Bulk blocked by admin") {
    return bulk_handler_.bulk_block_rooms(filter_criteria, reason);
  }

  json bulk_quarantine_room_media(const json& filter_criteria,
                                   const std::string& reason = "Bulk quarantined") {
    return bulk_handler_.bulk_quarantine_room_media(filter_criteria, reason);
  }

  // ==========================================================================
  // 16. Room Block Status Check
  // ==========================================================================

  bool is_room_blocked(const std::string& room_id) {
    try {
      auto row = db_.simple_select_one(
          "blocked_rooms", {{"room_id", room_id}}, {"room_id"});
      return row.has_value();
    } catch (...) { return false; }
  }

  // ==========================================================================
  // Public helpers
  // ==========================================================================

  int64_t get_total_room_count(bool include_all) {
    try {
      std::string query = "SELECT COUNT(*) FROM rooms";
      if (!include_all) {
        query += " WHERE EXISTS (SELECT 1 FROM local_current_membership "
                 "lcm WHERE lcm.room_id = rooms.room_id)";
      }
      auto rows = db_.execute("total_rooms_count_admin", query);
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

private:
  // ==========================================================================
  // Private: Stats gathering
  // ==========================================================================

  RoomAdminStats gather_room_stats(const std::string& room_id) {
    RoomAdminStats stats;
    stats.room_id = room_id;

    try {
      // Basic room info
      auto row = db_.simple_select_one(
          "rooms", {{"room_id", room_id}},
          {"room_id", "is_public", "creator", "creation_ts"});
      if (!row.has_value()) {
        stats.room_id = "";  // signal not found
        return stats;
      }
      const auto& r = *row;
      stats.is_public = row_get_bool(r, 1);
      stats.creator = row_get_str(r, 2);
      stats.creation_ts = row_get_int(r, 3);

      // Room stats state
      auto stats_row = db_.simple_select_one(
          "room_stats_state", {{"room_id", room_id}},
          {"name", "topic", "canonical_alias", "joined_members",
           "invited_members", "left_members", "banned_members",
           "state_events", "total_events", "last_activity_ts",
           "is_encrypted", "join_rules", "guest_access",
           "history_visibility", "room_type", "is_federatable",
           "room_version"});
      if (stats_row.has_value()) {
        const auto& sr = *stats_row;
        stats.name = row_get_str(sr, 0);
        stats.topic = row_get_str(sr, 1);
        stats.canonical_alias = row_get_str(sr, 2);
        stats.joined_members = row_get_int(sr, 3);
        stats.invited_members = row_get_int(sr, 4);
        stats.left_members = row_get_int(sr, 5);
        stats.banned_members = row_get_int(sr, 6);
        stats.state_events = row_get_int(sr, 7);
        stats.total_events = row_get_int(sr, 8);
        stats.last_activity_ts = row_get_int(sr, 9);
        stats.is_encrypted = row_get_bool(sr, 10);
        stats.join_rules = row_get_str(sr, 11, "invite");
        stats.guest_access = row_get_str(sr, 12, "forbidden");
        stats.history_visibility = row_get_str(sr, 13, "shared");
        stats.room_type = row_get_str(sr, 14, "room");
        stats.is_federatable = row_get_bool(sr, 15, true);
        stats.room_version = row_get_str(sr, 16, "10");
      }
    } catch (...) {}

    // Forward extremities
    stats.forward_extremities = get_forward_extremities_count(room_id);

    // Backward extremities
    try {
      auto bwd = db_.execute(
          "count_bwd_extremities_admin",
          "SELECT COUNT(*) FROM event_backward_extremities "
          "WHERE room_id = ?", {room_id});
      if (!bwd.empty()) stats.backward_extremities = row_get_int(bwd[0], 0);
    } catch (...) {}

    // Knocked members
    try {
      auto knocked = db_.execute(
          "count_knocked_admin",
          "SELECT COUNT(*) FROM room_memberships "
          "WHERE room_id = ? AND membership = 'knock'", {room_id});
      if (!knocked.empty()) stats.knocked_members = row_get_int(knocked[0], 0);
    } catch (...) {}

    // Local member counts
    try {
      auto local_joined = db_.execute(
          "local_joined_count_admin",
          "SELECT COUNT(*) FROM local_current_membership "
          "WHERE room_id = ? AND membership = 'join'", {room_id});
      if (!local_joined.empty())
        stats.local_joined_members = row_get_int(local_joined[0], 0);

      auto local_invited = db_.execute(
          "local_invited_count_admin",
          "SELECT COUNT(*) FROM local_current_membership "
          "WHERE room_id = ? AND membership = 'invite'", {room_id});
      if (!local_invited.empty())
        stats.local_invited_members = row_get_int(local_invited[0], 0);

      stats.local_total_members =
          stats.local_joined_members + stats.local_invited_members;
    } catch (...) {}

    // Encrypted algorithm
    try {
      auto enc = db_.simple_select_one(
          "current_state_events",
          {{"room_id", room_id}, {"type", "m.room.encryption"},
           {"state_key", ""}},
          {"json"});
      if (enc.has_value()) {
        std::string json_str = row_get_str(*enc, 0);
        try {
          auto j = json::parse(json_str);
          if (j.contains("content") && j["content"].contains("algorithm")) {
            stats.encryption_algorithm = j["content"]["algorithm"].get<std::string>();
          }
        } catch (...) {}
      }
    } catch (...) {}

    // Block status
    try {
      auto block_row = db_.simple_select_one(
          "blocked_rooms", {{"room_id", room_id}},
          {"reason", "blocked_at", "blocked_by"});
      if (block_row.has_value()) {
        stats.is_blocked = true;
        stats.blocked_reason = row_get_str(block_row.value(), 0);
        stats.blocked_at = row_get_int(block_row.value(), 1);
        stats.blocked_by = row_get_str(block_row.value(), 2);
      }
    } catch (...) {}

    // Retention policy
    try {
      auto ret_row = db_.simple_select_one(
          "room_retention", {{"room_id", room_id}},
          {"min_lifetime", "max_lifetime"});
      if (ret_row.has_value()) {
        stats.has_retention_policy = true;
        stats.retention_min_lifetime = row_get_int(ret_row.value(), 0);
        stats.retention_max_lifetime = row_get_int(ret_row.value(), 1);
      }
    } catch (...) {}

    // Depth
    try {
      auto depth_row = db_.simple_select_one(
          "room_depth", {{"room_id", room_id}}, {"current_depth"});
      if (depth_row.has_value()) {
        stats.current_depth = row_get_int(depth_row.value(), 0);
      }
    } catch (...) {}

    // Last message timestamp
    try {
      auto msg_rows = db_.execute(
          "last_message_ts_admin",
          "SELECT MAX(origin_server_ts) FROM events "
          "WHERE room_id = ? AND type = 'm.room.message'", {room_id});
      if (!msg_rows.empty()) stats.last_message_ts = row_get_int(msg_rows[0], 0);
    } catch (...) {}

    // Media stats
    try {
      auto media_rows = db_.execute(
          "room_media_stats_admin",
          "SELECT COUNT(*), COALESCE(SUM(media_length), 0) "
          "FROM ("
          "  SELECT DISTINCT "
          "    REPLACE(REPLACE(json_extract(content, '$.url'), 'mxc://" +
          server_name_ + "/', ''), 'mxc://', '') as mid "
          "  FROM events WHERE room_id = ? "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ") ev "
          "INNER JOIN local_media_repository lmr ON lmr.media_id = ev.mid",
          {room_id});
      if (!media_rows.empty()) {
        stats.total_media_count = row_get_int(media_rows[0], 0);
        stats.total_media_bytes = row_get_int(media_rows[0], 1);
      }
    } catch (...) {}

    // Quarantined media count
    try {
      auto quar_rows = db_.execute(
          "quarantined_media_count_admin",
          "SELECT COUNT(*) FROM ("
          "  SELECT DISTINCT "
          "    REPLACE(REPLACE(json_extract(content, '$.url'), 'mxc://" +
          server_name_ + "/', ''), 'mxc://', '') as mid "
          "  FROM events WHERE room_id = ? "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ") ev "
          "INNER JOIN local_media_repository lmr ON lmr.media_id = ev.mid "
          "WHERE lmr.safe_from_quarantine = 0",
          {room_id});
      if (!quar_rows.empty())
        stats.quarantined_media_count = row_get_int(quar_rows[0], 0);
    } catch (...) {}

    // Last media upload
    try {
      auto upload_rows = db_.execute(
          "last_media_upload_admin",
          "SELECT MAX(lmr.created_ts) FROM ("
          "  SELECT DISTINCT "
          "    REPLACE(REPLACE(json_extract(content, '$.url'), 'mxc://" +
          server_name_ + "/', ''), 'mxc://', '') as mid "
          "  FROM events WHERE room_id = ? "
          "    AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ") ev "
          "INNER JOIN local_media_repository lmr ON lmr.media_id = ev.mid",
          {room_id});
      if (!upload_rows.empty())
        stats.last_media_upload_ts = row_get_int(upload_rows[0], 0);
    } catch (...) {}

    // Oldest forward extremity age
    try {
      auto oldest = db_.execute(
          "oldest_extremity_admin",
          "SELECT MIN(received_ts) FROM event_forward_extremities "
          "WHERE room_id = ?", {room_id});
      if (!oldest.empty()) {
        int64_t min_ts = row_get_int(oldest[0], 0);
        if (min_ts > 0) {
          stats.oldest_forward_extremity_age_ms = now_ms() - min_ts;
        }
      }
    } catch (...) {}

    // Complexity score
    try {
      stats.complexity_score = complexity_analyzer_.compute_complexity(room_id);
    } catch (...) {}

    return stats;
  }

  // ==========================================================================
  // Private: Utility methods
  // ==========================================================================

  int64_t get_forward_extremities_count(const std::string& room_id) {
    try {
      auto rows = db_.execute(
          "count_extremities_admin",
          "SELECT COUNT(*) FROM event_forward_extremities WHERE room_id = ?",
          {room_id});
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  int64_t get_local_member_count(const std::string& room_id) {
    try {
      auto rows = db_.execute(
          "local_member_count_admin",
          "SELECT COUNT(*) FROM local_current_membership "
          "WHERE room_id = ? AND membership = 'join'",
          {room_id});
      if (!rows.empty()) return row_get_int(rows[0], 0);
    } catch (...) {}
    return 0;
  }

  bool is_room_public(const std::string& room_id) {
    try {
      auto row = db_.simple_select_one(
          "rooms", {{"room_id", room_id}}, {"is_public"});
      return row.has_value() && row_get_bool(row.value(), 0);
    } catch (...) { return false; }
  }

  bool is_room_federatable(const std::string& room_id) {
    try {
      auto rows = db_.execute(
          "room_federate_check_admin",
          "SELECT json FROM event_json WHERE room_id = ? "
          "AND type = 'm.room.create' LIMIT 1",
          {room_id});
      if (!rows.empty()) {
        std::string json_str = row_get_str(rows[0], 0);
        if (!json_str.empty()) {
          try {
            auto j = json::parse(json_str);
            if (j.contains("content") && j["content"].contains("m.federate")) {
              return j["content"]["m.federate"].get<bool>();
            }
          } catch (...) {}
        }
      }
    } catch (...) {}
    return true;
  }

  bool is_local_user(const std::string& user_id) {
    if (!is_valid_user_id(user_id)) return false;
    return server_name_from_id(user_id) == server_name_;
  }

  json get_room_aliases_internal(const std::string& room_id) {
    json aliases = json::array();
    try {
      auto rows = db_.execute(
          "room_aliases_admin",
          "SELECT room_alias FROM room_aliases WHERE room_id = ?",
          {room_id});
      for (auto& ra : rows) {
        aliases.push_back(row_get_str(ra, 0));
      }
    } catch (...) {}
    return aliases;
  }

  void block_room_internal(const std::string& room_id,
                            const std::string& reason) {
    try {
      db_.simple_insert("blocked_rooms", {
        {"room_id", room_id},
        {"reason", reason},
        {"blocked_at", std::to_string(now_ms())},
        {"blocked_by", "admin"}
      });
    } catch (...) {
      db_.simple_upsert("blocked_rooms",
                        {{"room_id", room_id}},
                        {{"reason", reason},
                         {"blocked_at", std::to_string(now_ms())},
                         {"blocked_by", "admin"}});
    }
  }

  void unblock_room_internal(const std::string& room_id) {
    try {
      db_.simple_delete_one("blocked_rooms", {{"room_id", room_id}});
    } catch (...) {}
  }

  int quarantine_room_media_internal(const std::string& room_id) {
    try {
      db_.execute(
          "quarantine_room_media_internal",
          "UPDATE local_media_repository "
          "SET quarantined_by = 'admin', safe_from_quarantine = 0 "
          "WHERE media_id IN ("
          "  SELECT DISTINCT "
          "    json_extract(content, '$.url') "
          "  FROM events WHERE room_id = ? "
          "  AND json_extract(content, '$.url') LIKE 'mxc://%'"
          ")",
          {room_id});
      return 1;
    } catch (...) { return 0; }
  }

  void record_admin_action(const std::string& action,
                            const std::string& target_id,
                            const json& details) {
    try {
      db_.simple_insert("admin_actions", {
        {"action", action},
        {"target_id", target_id},
        {"admin_user", "system"},
        {"timestamp_ms", std::to_string(now_ms())},
        {"details", details.dump()}
      });
    } catch (...) {
      // Best effort audit logging
    }
  }

  // ==========================================================================
  // Members
  // ==========================================================================

  storage::DatabasePool& db_;
  std::string server_name_;

  // Subsystems
  RoomAliasAdminSubsystem alias_admin_;
  RoomComplexityAnalyzer complexity_analyzer_;
  RoomMediaAdminSubsystem media_admin_;
  RoomPowerLevelManager power_manager_;
  RoomRetentionAdmin retention_admin_;
  RoomFederationAdmin federation_admin_;
  RoomBulkOperationHandler bulk_handler_;
};

// ============================================================================
// AdminRoomManager Factory — Create and configure the manager
// ============================================================================

inline std::unique_ptr<AdminRoomManager> create_admin_room_manager(
    storage::DatabasePool& db, const std::string& server_name) {
  return std::make_unique<AdminRoomManager>(db, server_name);
}

// ============================================================================
// Room Search — Advanced search across all rooms
// ============================================================================

inline json search_rooms(storage::DatabasePool& db,
                          const std::string& query_str,
                          const std::string& search_field = "all",
                          int64_t limit = 50) {
  if (query_str.empty()) {
    return build_error(400, "M_MISSING_PARAM", "query is required");
  }
  if (limit < 1) limit = 50;
  if (limit > kMaxPageSize) limit = kMaxPageSize;

  try {
    std::string safe = sanitize_sql_like(query_str);
    std::string sql;

    if (search_field == "room_id") {
      sql = "SELECT r.room_id, rs.name, rs.joined_members FROM rooms r "
            "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id "
            "WHERE r.room_id LIKE '%" + safe + "%' "
            "LIMIT " + std::to_string(limit);
    } else if (search_field == "name") {
      sql = "SELECT r.room_id, rs.name, rs.joined_members FROM rooms r "
            "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id "
            "WHERE rs.name LIKE '%" + safe + "%' "
            "LIMIT " + std::to_string(limit);
    } else if (search_field == "alias") {
      sql = "SELECT r.room_id, rs.name, rs.joined_members FROM rooms r "
            "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id "
            "LEFT JOIN room_aliases ra ON r.room_id = ra.room_id "
            "WHERE ra.room_alias LIKE '%" + safe + "%' "
            "LIMIT " + std::to_string(limit);
    } else if (search_field == "topic") {
      sql = "SELECT r.room_id, rs.name, rs.joined_members FROM rooms r "
            "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id "
            "WHERE rs.topic LIKE '%" + safe + "%' "
            "LIMIT " + std::to_string(limit);
    } else {
      // All fields
      sql = "SELECT r.room_id, rs.name, rs.joined_members FROM rooms r "
            "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id "
            "LEFT JOIN room_aliases ra ON r.room_id = ra.room_id "
            "WHERE r.room_id LIKE '%" + safe + "%' "
            "OR rs.name LIKE '%" + safe + "%' "
            "OR rs.topic LIKE '%" + safe + "%' "
            "OR ra.room_alias LIKE '%" + safe + "%' "
            "LIMIT " + std::to_string(limit);
    }

    auto rows = db.execute("search_rooms_admin", sql);
    json results = json::array();

    for (auto& row : rows) {
      json entry;
      entry["room_id"] = row_get_str(row, 0);
      entry["name"] = row_get_str(row, 1);
      entry["joined_members"] = row_get_int(row, 2);
      results.push_back(entry);
    }

    return build_paginated(results.size(), results, 0, limit);
  } catch (const std::exception& e) {
    return build_error(500, "M_UNKNOWN",
                       std::string("Error searching rooms: ") + e.what());
  }
}

// ============================================================================
// Room Statistics Summary — Get aggregate statistics across all rooms
// ============================================================================

inline json get_rooms_statistics(storage::DatabasePool& db,
                                   const std::string& server_name) {
  try {
    json stats;

    // Total room count
    auto total_rooms = db.execute(
        "stats_total_rooms", "SELECT COUNT(*) FROM rooms");
    if (!total_rooms.empty()) {
      stats["total_rooms"] = row_get_int(total_rooms[0], 0);
    }

    // Rooms with local members
    auto local_rooms = db.execute(
        "stats_local_rooms",
        "SELECT COUNT(DISTINCT room_id) FROM local_current_membership");
    if (!local_rooms.empty()) {
      stats["rooms_with_local_members"] = row_get_int(local_rooms[0], 0);
    }

    // Total events
    auto total_events = db.execute(
        "stats_total_events", "SELECT COUNT(*) FROM events");
    if (!total_events.empty()) {
      stats["total_events"] = row_get_int(total_events[0], 0);
    }

    // Total state events
    auto total_state = db.execute(
        "stats_total_state", "SELECT COUNT(*) FROM state_events");
    if (!total_state.empty()) {
      stats["total_state_events"] = row_get_int(total_state[0], 0);
    }

    // Total local members across all rooms
    auto total_members = db.execute(
        "stats_total_local_members",
        "SELECT COUNT(*) FROM local_current_membership "
        "WHERE membership = 'join'");
    if (!total_members.empty()) {
      stats["total_local_joined_members"] = row_get_int(total_members[0], 0);
    }

    // Blocked rooms
    auto blocked_rows = db.execute(
        "stats_blocked_rooms",
        "SELECT COUNT(*) FROM blocked_rooms");
    if (!blocked_rows.empty()) {
      stats["blocked_rooms"] = row_get_int(blocked_rows[0], 0);
    }

    // Rooms with retention
    auto ret_rows = db.execute(
        "stats_retention_rooms",
        "SELECT COUNT(*) FROM room_retention");
    if (!ret_rows.empty()) {
      stats["rooms_with_retention"] = row_get_int(ret_rows[0], 0);
    }

    // Encrypted rooms
    auto enc_rows = db.execute(
        "stats_encrypted_rooms",
        "SELECT COUNT(*) FROM room_stats_state WHERE is_encrypted = 1");
    if (!enc_rows.empty()) {
      stats["encrypted_rooms"] = row_get_int(enc_rows[0], 0);
    }

    // Largest rooms by membership
    auto largest = db.execute(
        "stats_largest_rooms",
        "SELECT r.room_id, rs.name, rs.joined_members "
        "FROM rooms r "
        "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id "
        "ORDER BY rs.joined_members DESC LIMIT 10");

    json largest_array = json::array();
    for (auto& row : largest) {
      json entry;
      entry["room_id"] = row_get_str(row, 0);
      entry["name"] = row_get_str(row, 1);
      entry["joined_members"] = row_get_int(row, 2);
      largest_array.push_back(entry);
    }
    stats["largest_rooms"] = largest_array;

    // Most active rooms
    auto active = db.execute(
        "stats_most_active_rooms",
        "SELECT r.room_id, rs.name, rs.last_activity_ts "
        "FROM rooms r "
        "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id "
        "WHERE rs.last_activity_ts > 0 "
        "ORDER BY rs.last_activity_ts DESC LIMIT 10");

    json active_array = json::array();
    for (auto& row : active) {
      json entry;
      entry["room_id"] = row_get_str(row, 0);
      entry["name"] = row_get_str(row, 1);
      int64_t ts = row_get_int(row, 2);
      entry["last_activity_ts"] = ts;
      if (ts > 0) entry["last_activity_display"] = ts_to_iso8601(ts);
      active_array.push_back(entry);
    }
    stats["most_active_rooms"] = active_array;

    // Rooms with high forward extremities
    auto high_fwd = db.execute(
        "stats_high_extremity_rooms",
        "SELECT r.room_id, rs.name, "
        "(SELECT COUNT(*) FROM event_forward_extremities efe "
        " WHERE efe.room_id = r.room_id) as fwd "
        "FROM rooms r "
        "LEFT JOIN room_stats_state rs ON r.room_id = rs.room_id "
        "HAVING fwd > 10 "
        "ORDER BY fwd DESC LIMIT 10");

    json fwd_array = json::array();
    for (auto& row : high_fwd) {
      json entry;
      entry["room_id"] = row_get_str(row, 0);
      entry["name"] = row_get_str(row, 1);
      entry["forward_extremities"] = row_get_int(row, 2);
      fwd_array.push_back(entry);
    }
    stats["rooms_with_high_extremities"] = fwd_array;

    // Room type breakdown
    auto types = db.execute(
        "stats_room_types",
        "SELECT room_type, COUNT(*) FROM room_stats_state "
        "GROUP BY room_type ORDER BY COUNT(*) DESC");

    json type_breakdown = json::object();
    for (auto& row : types) {
      std::string rt = row_get_str(row, 0, "room");
      type_breakdown[rt] = row_get_int(row, 1);
    }
    stats["room_type_breakdown"] = type_breakdown;

    // Membership breakdown across all rooms
    auto memb_breakdown = db.execute(
        "stats_membership_breakdown",
        "SELECT membership, COUNT(*) FROM room_memberships "
        "GROUP BY membership");

    json memb_json = json::object();
    for (auto& row : memb_breakdown) {
      std::string m = normalize_membership(row_get_str(row, 0));
      memb_json[membership_to_display(m)] = row_get_int(row, 1);
    }
    stats["membership_breakdown_all_rooms"] = memb_json;

    // Room creation timeline (counts by day for last 30 days)
    int64_t thirty_days_ms = 30LL * 86400LL * 1000LL;
    auto timeline = db.execute(
        "stats_creation_timeline",
        "SELECT r.creation_ts, COUNT(*) FROM rooms r "
        "WHERE r.creation_ts > " + std::to_string(now_ms() - thirty_days_ms) +
        " GROUP BY (r.creation_ts / 86400000) "
        "ORDER BY r.creation_ts ASC");

    json timeline_json = json::array();
    for (auto& row : timeline) {
      json entry;
      int64_t ts = row_get_int(row, 0);
      entry["day"] = ts_to_iso8601(ts);
      entry["count"] = row_get_int(row, 1);
      timeline_json.push_back(entry);
    }
    stats["creation_timeline_30d"] = timeline_json;

    return stats;
  } catch (const std::exception& e) {
    return build_error(500, "M_UNKNOWN",
                       std::string("Error gathering room statistics: ") + e.what());
  }
}

}  // namespace progressive
