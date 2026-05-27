// ============================================================================
// event_filter_engine.cpp — Matrix Event Filter Engine
//
// Implements a comprehensive Matrix event filtering system according to the
// Matrix Client-Server API specification (r0.6.1 / v1.1+ filter sections):
//
//   - Room Event Filters: filters timeline events by types, not_types,
//     senders, not_senders, rooms, not_rooms, contains_url, and limit.
//     Applied during /sync and /messages pagination to reduce bandwidth
//     and provide clients with only the events they want.
//
//   - State Event Filters: filters state events by types, not_types,
//     senders, not_senders, and limit. Additionally implements Matrix's
//     lazy-loading members feature (lazy_load_members) which only sends
//     membership events for members who have sent events in the timeline,
//     dramatically reducing initial sync payload for large rooms. The
//     include_redundant_members option allows clients to request all
//     members when they need the full member list.
//
//   - Filter JSON Validation: comprehensive validation of filter JSON
//     passed by clients in POST /_matrix/client/v3/user/{userId}/filter.
//     Validates field types (e.g., limit must be integer, types must be
//     string arrays), value ranges (limit must be positive), and unknown
//     fields. Returns detailed error messages with field paths to help
//     client developers debug filter issues. Supports strict mode for
//     rejecting unknown fields and lenient mode for forward compatibility.
//
//   - Filter ID Storage: persistent storage of named filters per user
//     using a SQL-backed store. Each filter gets a unique filter_id
//     (auto-incrementing per user), the full filter JSON blob, and
//     metadata (created timestamp, last_used timestamp). Supports CRUD
//     operations: create, read, update (by re-creating), delete, and
//     list all filters for a user. Implements filter ID uniqueness per
//     user as required by the spec.
//
//   - Server Filters: supports server-default filters for federation
//     and admin-defined filters. Server filters are identified by a
//     namespace prefix and are available to all users. Supports
//     read-only server filters and user-overridable server filters.
//
//   - Filter Application Pipeline: modular pipeline that can compose
//     multiple filter stages (type filtering, sender filtering, room
//     filtering, URL filtering, limit truncation) into a single
//     efficient pass over events. Each stage implements a common
//     FilterStage interface, allowing custom stages to be added.
//
//   - Caching: in-memory LRU cache of parsed filter objects to avoid
//     repeated JSON parsing and validation on every sync request.
//     TTL-based cache invalidation with configurable max size.
//
//   - Event field filtering: supports the event_fields and
//     event_format parameters of Matrix filters to select only a
//     subset of event fields in the response, reducing payload size.
//
//   - SQL Schema: provides the complete DDL for filter storage tables
//     with proper indexes for efficient lookup by user_id + filter_id,
//     and by filter_id alone for admin operations.
//
// Namespace: progressive::
//
// Equivalent to:
//   synapse/api/filtering.py          (~450 lines, filter parsing/validation)
//   synapse/storage/databases/main/filtering.py  (~120 lines, filter storage)
//   synapse/handlers/filter.py        (~230 lines, filter API handler)
//   synapse/events/utils.py           (filtering utilities)
//
// Target: 3000+ lines of production-grade C++ with full SQL.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
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
#include "progressive/storage/databases/main/filtering.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/util/log.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
namespace storage {
class DatabasePool;
class LoggingTransaction;
class LoggingDatabaseConnection;
class FilteringStore;
}  // namespace storage

// ============================================================================
// Type aliases
// ============================================================================
using storage::DatabasePool;
using storage::LoggingTransaction;
using storage::LoggingDatabaseConnection;
using storage::FilteringStore;
using storage::Row;
using storage::RowList;
using storage::ColumnValue;
using storage::SQLParam;
using storage::SQLQueryParameters;

// ============================================================================
// Internal logger helper
// ============================================================================
namespace util {
struct LoggerImpl {
  std::string name_;
  void debug(const std::string& msg) { log::info(name_, "[DEBUG] " + msg); }
  void info(const std::string& msg)  { log::info(name_, msg); }
  void warn(const std::string& msg)  { log::warn(name_, msg); }
  void error(const std::string& msg) { log::error(name_, msg); }
};

inline LoggerImpl& get_logger(const std::string& name) {
  static thread_local std::map<std::string, LoggerImpl> loggers;
  return loggers[name];
}
}  // namespace util

// ---------------------------------------------------------------------------
// Logger references
// ---------------------------------------------------------------------------
auto& filter_logger   = util::get_logger("progressive.event_filter_engine");
auto& validation_log  = util::get_logger("progressive.event_filter.validation");
auto& storage_log     = util::get_logger("progressive.event_filter.storage");
auto& cache_log       = util::get_logger("progressive.event_filter.cache");

// ============================================================================
// Internal constants
// ============================================================================
namespace {

// --- Filter field names (as per Matrix spec) ---
constexpr const char* FILTER_FIELD_EVENT_FIELDS      = "event_fields";
constexpr const char* FILTER_FIELD_EVENT_FORMAT      = "event_format";
constexpr const char* FILTER_FIELD_ROOM              = "room";
constexpr const char* FILTER_FIELD_ROOM_TIMELINE     = "timeline";
constexpr const char* FILTER_FIELD_ROOM_STATE        = "state";
constexpr const char* FILTER_FIELD_ROOM_EPHEMERAL    = "ephemeral";
constexpr const char* FILTER_FIELD_ROOM_ACCOUNT_DATA  = "account_data";
constexpr const char* FILTER_FIELD_TYPES              = "types";
constexpr const char* FILTER_FIELD_NOT_TYPES          = "not_types";
constexpr const char* FILTER_FIELD_SENDERS             = "senders";
constexpr const char* FILTER_FIELD_NOT_SENDERS         = "not_senders";
constexpr const char* FILTER_FIELD_ROOMS               = "rooms";
constexpr const char* FILTER_FIELD_NOT_ROOMS           = "not_rooms";
constexpr const char* FILTER_FIELD_CONTAINS_URL        = "contains_url";
constexpr const char* FILTER_FIELD_LIMIT               = "limit";
constexpr const char* FILTER_FIELD_LAZY_LOAD_MEMBERS   = "lazy_load_members";
constexpr const char* FILTER_FIELD_INCLUDE_REDUNDANT_MEMBERS = "include_redundant_members";
constexpr const char* FILTER_FIELD_NOT_ROOMS_FIELD     = "not_rooms";
constexpr const char* FILTER_FIELD_UNREAD_THREAD_NOTIFICATIONS = "unread_thread_notifications";

// --- Event format constants ---
constexpr const char* EVENT_FORMAT_CLIENT  = "client";
constexpr const char* EVENT_FORMAT_FEDERATION = "federation";

// --- Default limit values ---
constexpr int DEFAULT_ROOM_TIMELINE_LIMIT = 20;
constexpr int DEFAULT_ROOM_STATE_LIMIT    = 128;
constexpr int DEFAULT_FILTER_LIMIT        = 20;
constexpr int MAX_FILTER_LIMIT            = 1000;

// --- Cache configuration ---
constexpr size_t FILTER_CACHE_MAX_SIZE     = 500;
constexpr int64_t FILTER_CACHE_TTL_SECONDS = 300;   // 5 minutes
constexpr int64_t FILTER_CACHE_CLEANUP_INTERVAL_SEC = 60;  // 1 minute

// --- SQL DDL for filter storage tables ---
constexpr const char* FILTER_TABLES_DDL = R"SQL(
-- ============================================================================
-- User filters table: stores named filters created by users via the
-- POST /_matrix/client/v3/user/{userId}/filter endpoint.
-- Each user can have multiple filters, each identified by a filter_id
-- that is auto-incremented per user (so filter_id=1 is the first filter
-- for that user, regardless of other users' filters).
-- ============================================================================
CREATE TABLE IF NOT EXISTS user_filters (
    user_id         TEXT        NOT NULL,
    filter_id       BIGINT      NOT NULL,
    filter_json     TEXT        NOT NULL,
    created_ts      BIGINT      NOT NULL DEFAULT 0,
    last_used_ts    BIGINT      NOT NULL DEFAULT 0,
    CONSTRAINT user_filters_pk PRIMARY KEY (user_id, filter_id)
);

-- Index for listing all filters for a user (ordered by most recent)
CREATE INDEX IF NOT EXISTS user_filters_user_idx
    ON user_filters (user_id, last_used_ts DESC);

-- Index for looking up a filter by its global ID (admin use)
CREATE INDEX IF NOT EXISTS user_filters_created_idx
    ON user_filters (created_ts);

-- ============================================================================
-- Server filters table: stores server-default filters that can be applied
-- to federation requests or used as admin-enforced defaults. Server filters
-- are identified by a namespace-prefixed filter_id (e.g., "server.default_sync").
-- ============================================================================
CREATE TABLE IF NOT EXISTS server_filters (
    filter_id       TEXT        NOT NULL PRIMARY KEY,
    filter_json     TEXT        NOT NULL,
    description     TEXT        NOT NULL DEFAULT '',
    created_ts      BIGINT      NOT NULL DEFAULT 0,
    updated_ts      BIGINT      NOT NULL DEFAULT 0
);

-- ============================================================================
-- Filter usage tracking table: records when a filter is applied to a request,
-- for analytics and cache warming. Tracks the request type (sync, messages,
-- context, search) and the user who made the request.
-- ============================================================================
CREATE TABLE IF NOT EXISTS filter_usage_log (
    id              BIGINT      PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT        NOT NULL,
    filter_id       TEXT        NOT NULL,
    request_type    TEXT        NOT NULL,  -- 'sync', 'messages', 'context', 'search'
    used_ts         BIGINT      NOT NULL DEFAULT 0,
    room_count      INTEGER     NOT NULL DEFAULT 0,
    event_count     INTEGER     NOT NULL DEFAULT 0,
    duration_us     BIGINT      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS filter_usage_user_idx
    ON filter_usage_log (user_id, used_ts DESC);

CREATE INDEX IF NOT EXISTS filter_usage_filter_idx
    ON filter_usage_log (filter_id, used_ts DESC);
)SQL";

// ============================================================================
// Known valid top-level filter fields (for strict validation)
// ============================================================================
const std::set<std::string> KNOWN_FILTER_FIELDS = {
    FILTER_FIELD_EVENT_FIELDS,
    FILTER_FIELD_EVENT_FORMAT,
    FILTER_FIELD_ROOM,
};

// ============================================================================
// Known valid room-level filter fields
// ============================================================================
const std::set<std::string> KNOWN_ROOM_FILTER_FIELDS = {
    FILTER_FIELD_ROOM_TIMELINE,
    FILTER_FIELD_ROOM_STATE,
    FILTER_FIELD_ROOM_EPHEMERAL,
    FILTER_FIELD_ROOM_ACCOUNT_DATA,
    FILTER_FIELD_ROOMS,
    FILTER_FIELD_NOT_ROOMS,
};

// ============================================================================
// Known valid timeline/state filter fields (RoomEventFilter and StateFilter)
// ============================================================================
const std::set<std::string> KNOWN_EVENT_FILTER_FIELDS = {
    FILTER_FIELD_TYPES,
    FILTER_FIELD_NOT_TYPES,
    FILTER_FIELD_SENDERS,
    FILTER_FIELD_NOT_SENDERS,
    FILTER_FIELD_LIMIT,
};

const std::set<std::string> KNOWN_ROOM_EVENT_FILTER_FIELDS = {
    FILTER_FIELD_TYPES,
    FILTER_FIELD_NOT_TYPES,
    FILTER_FIELD_SENDERS,
    FILTER_FIELD_NOT_SENDERS,
    FILTER_FIELD_ROOMS,
    FILTER_FIELD_NOT_ROOMS,
    FILTER_FIELD_CONTAINS_URL,
    FILTER_FIELD_LIMIT,
};

const std::set<std::string> KNOWN_STATE_FILTER_FIELDS = {
    FILTER_FIELD_TYPES,
    FILTER_FIELD_NOT_TYPES,
    FILTER_FIELD_SENDERS,
    FILTER_FIELD_NOT_SENDERS,
    FILTER_FIELD_LIMIT,
    FILTER_FIELD_LAZY_LOAD_MEMBERS,
    FILTER_FIELD_INCLUDE_REDUNDANT_MEMBERS,
    FILTER_FIELD_NOT_ROOMS_FIELD,
    FILTER_FIELD_UNREAD_THREAD_NOTIFICATIONS,
};

// ============================================================================
// URL-matching pattern used by contains_url filter:
// matches Matrix mxc:// URIs and standard http(s) URLs in event content.
// ============================================================================
const std::regex URL_PATTERN(
    R"((?:https?://|mxc://)[^\s<>"']+)",
    std::regex::optimize | std::regex::ECMAScript);

}  // anonymous namespace

// ============================================================================
// Utility: current wall-clock time in milliseconds since Unix epoch.
// ============================================================================
static int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// ============================================================================
// Utility: current wall-clock time in seconds since Unix epoch.
// ============================================================================
static int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// ============================================================================
// Utility: convert a JSON value to a string representation for error messages.
// Truncates long strings to avoid bloated error output.
// ============================================================================
static std::string json_value_repr(const json& j, size_t max_len = 80) {
  if (j.is_string()) {
    std::string s = j.get<std::string>();
    if (s.size() > max_len) s = s.substr(0, max_len - 3) + "...";
    return "\"" + s + "\"";
  }
  if (j.is_null()) return "null";
  std::string dumped = j.dump();
  if (dumped.size() > max_len) dumped = dumped.substr(0, max_len - 3) + "...";
  return dumped;
}

// ============================================================================
// Utility: check if a string is a valid Matrix user ID.
// Pattern: @localpart:domain
// ============================================================================
static bool is_valid_user_id(const std::string& s) {
  if (s.empty() || s[0] != '@') return false;
  auto colon_pos = s.find(':');
  if (colon_pos == std::string::npos || colon_pos < 2) return false;
  return colon_pos < s.size() - 1;  // domain must be non-empty
}

// ============================================================================
// Utility: check if a string is a valid Matrix room ID.
// Pattern: !opaque_id:domain
// ============================================================================
static bool is_valid_room_id(const std::string& s) {
  if (s.empty() || s[0] != '!') return false;
  auto colon_pos = s.find(':');
  if (colon_pos == std::string::npos || colon_pos < 2) return false;
  return colon_pos < s.size() - 1;
}

// ============================================================================
// Utility: check if a string is a valid Matrix event ID.
// Pattern: $opaque_id
// ============================================================================
static bool is_valid_event_id(const std::string& s) {
  return !s.empty() && s[0] == '$' && s.size() > 1;
}

// ============================================================================
// Utility: escape single-quote for SQL string literals (doubles quotes).
// ============================================================================
static std::string sql_escape(std::string_view sv) {
  std::string out;
  out.reserve(sv.size() + 8);
  for (char c : sv) {
    if (c == '\'') out += "''";
    else out += c;
  }
  return out;
}

// ============================================================================
// Utility: generate a random alphanumeric string for trace IDs, etc.
// ============================================================================
static std::string generate_random_id(int len = 16) {
  static const char charset[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  std::string result(len, '\0');
  thread_local std::mt19937 rng(
      static_cast<unsigned>(now_ms() ^
          std::hash<std::thread::id>{}(std::this_thread::get_id())));
  std::uniform_int_distribution<int> dist(0, sizeof(charset) - 2);
  for (int i = 0; i < len; ++i) result[i] = charset[dist(rng)];
  return result;
}

// ============================================================================
// Utility: simple SHA-256-ish hash of a string for cache keys.
// Uses std::hash for speed; sufficient for filter dedup, not for crypto.
// ============================================================================
static std::string hash_string(const std::string& s) {
  std::hash<std::string> hasher;
  std::stringstream ss;
  ss << std::hex << std::setw(16) << std::setfill('0') << hasher(s);
  return ss.str();
}

// ============================================================================
// Utility: starts_with — string prefix check.
// ============================================================================
static bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

// ============================================================================
// Utility: split a string by delimiter into a vector.
// ============================================================================
static std::vector<std::string> split_string(const std::string& s, char delim) {
  std::vector<std::string> result;
  std::stringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    if (!item.empty()) result.push_back(item);
  }
  return result;
}

// ============================================================================
// Utility: join a vector of strings with a delimiter.
// ============================================================================
static std::string join_strings(const std::vector<std::string>& parts,
                                 const std::string& delim) {
  std::string result;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) result += delim;
    result += parts[i];
  }
  return result;
}

// ============================================================================
// Utility: trim whitespace from both ends of a string.
// ============================================================================
static std::string trim_string(const std::string& s) {
  auto start = s.find_first_not_of(" \t\n\r\f\v");
  if (start == std::string::npos) return "";
  auto end = s.find_last_not_of(" \t\n\r\f\v");
  return s.substr(start, end - start + 1);
}

// ============================================================================
// Utility: convert a string to lowercase.
// ============================================================================
static std::string to_lower(const std::string& s) {
  std::string result = s;
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return result;
}

// ============================================================================
// Utility: check if a JSON array contains only strings.
// ============================================================================
static bool is_string_array(const json& j) {
  if (!j.is_array()) return false;
  for (const auto& item : j) {
    if (!item.is_string()) return false;
  }
  return true;
}

// ============================================================================
// FilterError — structured error for filter validation failures.
// Carries a path (e.g., "room.timeline.limit") and a human-readable message.
// ============================================================================
struct FilterError {
  std::string path;     // dotted path to the invalid field
  std::string message;  // human-readable error description
  std::string code;     // optional error code (e.g., "INVALID_TYPE")

  FilterError() = default;
  FilterError(std::string p, std::string m, std::string c = "")
      : path(std::move(p)), message(std::move(m)), code(std::move(c)) {}

  json to_json() const {
    json j;
    j["path"] = path;
    j["message"] = message;
    if (!code.empty()) j["code"] = code;
    return j;
  }
};

// ============================================================================
// FilterValidationResult — outcome of validating a filter JSON document.
// ============================================================================
struct FilterValidationResult {
  bool valid = true;
  std::vector<FilterError> errors;
  std::vector<std::string> warnings;

  void add_error(const std::string& path, const std::string& msg,
                 const std::string& code = "") {
    valid = false;
    errors.emplace_back(path, msg, code);
  }

  void add_warning(const std::string& path, const std::string& msg) {
    warnings.push_back("[" + path + "] " + msg);
  }

  json to_json() const {
    json j;
    j["valid"] = valid;
    if (!errors.empty()) {
      json errs = json::array();
      for (const auto& e : errors) errs.push_back(e.to_json());
      j["errors"] = errs;
    }
    if (!warnings.empty()) {
      j["warnings"] = warnings;
    }
    return j;
  }
};

// ============================================================================
// EventFieldFilter — configuration for event field filtering.
//
// Clients can request only a subset of event fields (e.g., ["type", "content"])
// to reduce the payload size. The spec also supports an "event_format"
// parameter: "client" (default) or "federation".
//
// Fields:
//   - enabled: whether field filtering is active
//   - fields: set of field names to include in output events
//   - format: "client" (default) or "federation"
// ============================================================================
struct EventFieldFilter {
  bool enabled = false;
  std::set<std::string> fields;  // empty = include all
  std::string format = EVENT_FORMAT_CLIENT;

  // ------------------------------------------------------------------------
  // Check if a given field should be included.
  // Returns true if the field passes the filter (should be kept).
  // If no fields are specified, all fields pass.
  // ------------------------------------------------------------------------
  bool include_field(const std::string& field_name) const {
    if (!enabled || fields.empty()) return true;
    return fields.count(field_name) > 0;
  }

  // ------------------------------------------------------------------------
  // Parse from a JSON filter object. Validates field types.
  // ------------------------------------------------------------------------
  static std::optional<EventFieldFilter> from_json(const json& j,
                                                    FilterValidationResult& vr,
                                                    const std::string& path);

  // ------------------------------------------------------------------------
  // Apply field filtering to a single event JSON, keeping only the
  // specified fields. Always keeps "event_id" and "type" regardless of
  // the field list, since those are required for event identification.
  // ------------------------------------------------------------------------
  json apply_to_event(const json& event) const {
    if (!enabled || fields.empty()) return event;

    json filtered;
    // Always include these critical fields
    const std::set<std::string> always_include = {
        "event_id", "type", "sender", "room_id", "origin_server_ts"
    };

    for (auto it = event.begin(); it != event.end(); ++it) {
      if (always_include.count(it.key()) > 0 ||
          fields.count(it.key()) > 0) {
        filtered[it.key()] = it.value();
      }
    }
    return filtered;
  }
};

// ============================================================================
// RoomEventFilter — filter for room timeline events (messages, etc.).
//
// Implements the Matrix RoomEventFilter as defined in the spec:
//   - types:        whitelist of event types to include
//   - not_types:    blacklist of event types to exclude
//   - senders:      whitelist of sender user IDs to include
//   - not_senders:  blacklist of sender user IDs to exclude
//   - rooms:        whitelist of room IDs to include
//   - not_rooms:    blacklist of room IDs to exclude
//   - contains_url: if true, only include events whose content has a URL
//   - limit:        maximum number of events to return
//
// Filtering logic:
//   1. If types is specified and non-empty: event.type must be in types
//   2. If not_types is specified: event.type must NOT be in not_types
//   3. If senders is specified and non-empty: event.sender must be in senders
//   4. If not_senders is specified: event.sender must NOT be in not_senders
//   5. If rooms is specified: event.room_id must be in rooms
//   6. If not_rooms is specified: event.room_id must NOT be in not_rooms
//   7. If contains_url is true: event.content must contain a URL
//   8. After all filters, apply limit to truncate result set
//
// All checks are applied as AND conditions. If a filter is not specified
// (empty/null), it is treated as a pass-through.
// ============================================================================
struct RoomEventFilter {
  bool         has_types        = false;   // types is specified (even if empty)
  bool         has_not_types    = false;   // not_types is specified
  bool         has_senders      = false;   // senders is specified
  bool         has_not_senders  = false;   // not_senders is specified
  bool         has_rooms        = false;   // rooms is specified
  bool         has_not_rooms    = false;   // not_rooms is specified
  bool         has_contains_url = false;   // contains_url is specified
  bool         has_limit        = false;   // limit is specified

  std::set<std::string> types;
  std::set<std::string> not_types;
  std::set<std::string> senders;
  std::set<std::string> not_senders;
  std::set<std::string> rooms;
  std::set<std::string> not_rooms;
  bool         contains_url = false;
  int          limit        = DEFAULT_ROOM_TIMELINE_LIMIT;

  // ------------------------------------------------------------------------
  // Default constructor — creates a pass-through filter (allows everything).
  // ------------------------------------------------------------------------
  RoomEventFilter() = default;

  // ------------------------------------------------------------------------
  // is_empty — returns true if no filtering is active (passthrough).
  // A filter is empty if no filtering fields are specified.
  // ------------------------------------------------------------------------
  bool is_empty() const {
    return !has_types && !has_not_types && !has_senders && !has_not_senders &&
           !has_rooms && !has_not_rooms && !has_contains_url;
  }

  // ------------------------------------------------------------------------
  // is_limited_only — returns true if the filter has only a limit and no
  // other constraining fields. Used to optimize by only applying SQL LIMIT
  // without post-filtering.
  // ------------------------------------------------------------------------
  bool is_limited_only() const {
    return is_empty() && has_limit;
  }

  // ------------------------------------------------------------------------
  // matches_event — checks whether a single event passes this filter.
  //
  // Parameters:
  //   - event_type:   the event type string (e.g., "m.room.message")
  //   - sender:       the sender's user ID (e.g., "@alice:example.com")
  //   - room_id:      the room ID (e.g., "!abc123:example.com")
  //   - event_json:   the full event JSON (needed for contains_url check)
  //
  // Returns true if the event should be included.
  // ------------------------------------------------------------------------
  bool matches_event(const std::string& event_type,
                     const std::string& sender,
                     const std::string& room_id,
                     const json& event_json) const {
    // Check types whitelist: if specified, type MUST be in the set
    if (has_types && !types.empty()) {
      if (types.find(event_type) == types.end()) return false;
    }

    // Check not_types blacklist: if specified, type must NOT be in the set
    if (has_not_types && !not_types.empty()) {
      if (not_types.find(event_type) != not_types.end()) return false;
    }

    // Check senders whitelist: if specified, sender MUST be in the set
    if (has_senders && !senders.empty()) {
      if (senders.find(sender) == senders.end()) return false;
    }

    // Check not_senders blacklist
    if (has_not_senders && !not_senders.empty()) {
      if (not_senders.find(sender) != not_senders.end()) return false;
    }

    // Check rooms whitelist
    if (has_rooms && !rooms.empty()) {
      if (rooms.find(room_id) == rooms.end()) return false;
    }

    // Check not_rooms blacklist
    if (has_not_rooms && !not_rooms.empty()) {
      if (not_rooms.find(room_id) != not_rooms.end()) return false;
    }

    // Check contains_url: scan event content for URLs
    if (has_contains_url && contains_url) {
      if (!event_contains_url(event_json)) return false;
    }

    return true;
  }

  // ------------------------------------------------------------------------
  // matches_event_light — lightweight check without the JSON parameter.
  // Used when contains_url is not needed (common for state events).
  // ------------------------------------------------------------------------
  bool matches_event_light(const std::string& event_type,
                           const std::string& sender,
                           const std::string& room_id) const {
    // Same as matches_event but skips contains_url check
    if (has_types && !types.empty()) {
      if (types.find(event_type) == types.end()) return false;
    }
    if (has_not_types && !not_types.empty()) {
      if (not_types.find(event_type) != not_types.end()) return false;
    }
    if (has_senders && !senders.empty()) {
      if (senders.find(sender) == senders.end()) return false;
    }
    if (has_not_senders && !not_senders.empty()) {
      if (not_senders.find(sender) != not_senders.end()) return false;
    }
    if (has_rooms && !rooms.empty()) {
      if (rooms.find(room_id) == rooms.end()) return false;
    }
    if (has_not_rooms && !not_rooms.empty()) {
      if (not_rooms.find(room_id) != not_rooms.end()) return false;
    }
    return true;
  }

  // ------------------------------------------------------------------------
  // apply_limit — truncate a vector of events to at most `limit` entries.
  // Returns a new vector (or the original if no truncation needed).
  // ------------------------------------------------------------------------
  template<typename T>
  std::vector<T> apply_limit(const std::vector<T>& events) const {
    if (!has_limit) return events;
    if (static_cast<int>(events.size()) <= limit) return events;
    return std::vector<T>(events.begin(), events.begin() + limit);
  }

  // ------------------------------------------------------------------------
  // build_sql_where — construct a SQL WHERE clause fragment for this filter.
  //
  // This builds parameterized SQL conditions that can be appended to a
  // query that fetches events. Uses positional parameters ($1, $2, ...).
  // Returns a pair of (sql_clause, params_vector).
  //
  // SQL fragment example:
  //   WHERE event_type IN ($1, $2) AND sender NOT IN ($3, $4) ...
  // ------------------------------------------------------------------------
  std::pair<std::string, SQLQueryParameters> build_sql_where() const {
    std::vector<std::string> clauses;
    SQLQueryParameters params;
    int param_idx = 0;

    // types IN (...)
    if (has_types && !types.empty()) {
      std::vector<std::string> placeholders;
      for (const auto& t : types) {
        ++param_idx;
        placeholders.push_back("$" + std::to_string(param_idx));
        params.emplace_back(t);
      }
      clauses.push_back("event_type IN (" +
                        join_strings(placeholders, ", ") + ")");
    }

    // not_types NOT IN (...)
    if (has_not_types && !not_types.empty()) {
      std::vector<std::string> placeholders;
      for (const auto& t : not_types) {
        ++param_idx;
        placeholders.push_back("$" + std::to_string(param_idx));
        params.emplace_back(t);
      }
      clauses.push_back("event_type NOT IN (" +
                        join_strings(placeholders, ", ") + ")");
    }

    // senders IN (...)
    if (has_senders && !senders.empty()) {
      std::vector<std::string> placeholders;
      for (const auto& s : senders) {
        ++param_idx;
        placeholders.push_back("$" + std::to_string(param_idx));
        params.emplace_back(s);
      }
      clauses.push_back("sender IN (" +
                        join_strings(placeholders, ", ") + ")");
    }

    // not_senders NOT IN (...)
    if (has_not_senders && !not_senders.empty()) {
      std::vector<std::string> placeholders;
      for (const auto& s : not_senders) {
        ++param_idx;
        placeholders.push_back("$" + std::to_string(param_idx));
        params.emplace_back(s);
      }
      clauses.push_back("sender NOT IN (" +
                        join_strings(placeholders, ", ") + ")");
    }

    // rooms IN (...)
    if (has_rooms && !rooms.empty()) {
      std::vector<std::string> placeholders;
      for (const auto& r : rooms) {
        ++param_idx;
        placeholders.push_back("$" + std::to_string(param_idx));
        params.emplace_back(r);
      }
      clauses.push_back("room_id IN (" +
                        join_strings(placeholders, ", ") + ")");
    }

    // not_rooms NOT IN (...)
    if (has_not_rooms && !not_rooms.empty()) {
      std::vector<std::string> placeholders;
      for (const auto& r : not_rooms) {
        ++param_idx;
        placeholders.push_back("$" + std::to_string(param_idx));
        params.emplace_back(r);
      }
      clauses.push_back("room_id NOT IN (" +
                        join_strings(placeholders, ", ") + ")");
    }

    std::string where;
    if (!clauses.empty()) {
      where = "WHERE " + join_strings(clauses, " AND ");
    }
    return {where, params};
  }

  // ------------------------------------------------------------------------
  // to_json — serialize this filter to a JSON object.
  // Output conforms to the Matrix spec filter API response format.
  // ------------------------------------------------------------------------
  json to_json() const {
    json j;
    if (has_types) {
      j[FILTER_FIELD_TYPES] = json::array();
      for (const auto& t : types) j[FILTER_FIELD_TYPES].push_back(t);
    }
    if (has_not_types) {
      j[FILTER_FIELD_NOT_TYPES] = json::array();
      for (const auto& t : not_types) j[FILTER_FIELD_NOT_TYPES].push_back(t);
    }
    if (has_senders) {
      j[FILTER_FIELD_SENDERS] = json::array();
      for (const auto& s : senders) j[FILTER_FIELD_SENDERS].push_back(s);
    }
    if (has_not_senders) {
      j[FILTER_FIELD_NOT_SENDERS] = json::array();
      for (const auto& s : not_senders) j[FILTER_FIELD_NOT_SENDERS].push_back(s);
    }
    if (has_rooms) {
      j[FILTER_FIELD_ROOMS] = json::array();
      for (const auto& r : rooms) j[FILTER_FIELD_ROOMS].push_back(r);
    }
    if (has_not_rooms) {
      j[FILTER_FIELD_NOT_ROOMS] = json::array();
      for (const auto& r : not_rooms) j[FILTER_FIELD_NOT_ROOMS].push_back(r);
    }
    if (has_contains_url) j[FILTER_FIELD_CONTAINS_URL] = contains_url;
    if (has_limit) j[FILTER_FIELD_LIMIT] = limit;
    return j;
  }

  // ------------------------------------------------------------------------
  // from_json — parse a RoomEventFilter from a JSON object.
  // Validates all fields and populates FilterValidationResult with any
  // errors found. Returns std::nullopt if JSON is not an object.
  // ------------------------------------------------------------------------
  static std::optional<RoomEventFilter> from_json(
      const json& j,
      FilterValidationResult& vr,
      const std::string& path);

private:
  // ------------------------------------------------------------------------
  // event_contains_url — scan event content recursively for URLs.
  // Checks the "content" object and also "content.url" specifically.
  // Uses regex matching on string values.
  // ------------------------------------------------------------------------
  static bool event_contains_url(const json& event) {
    // Check content.url directly (common pattern for m.room.message with url)
    if (event.contains("content")) {
      const auto& content = event["content"];
      if (content.contains("url") && content["url"].is_string()) {
        std::string url_str = content["url"].get<std::string>();
        if (!url_str.empty()) return true;
      }

      // Check content.body for URLs (plain text body)
      if (content.contains("body") && content["body"].is_string()) {
        std::string body = content["body"].get<std::string>();
        if (std::regex_search(body, URL_PATTERN)) return true;
      }

      // Check content.formatted_body for URLs (HTML body)
      if (content.contains("formatted_body") &&
          content["formatted_body"].is_string()) {
        std::string fb = content["formatted_body"].get<std::string>();
        if (std::regex_search(fb, URL_PATTERN)) return true;
      }

      // Recursively scan all string values in content
      for (auto it = content.begin(); it != content.end(); ++it) {
        if (it.value().is_string()) {
          std::string val = it.value().get<std::string>();
          if (std::regex_search(val, URL_PATTERN)) return true;
        }
      }
    }
    return false;
  }
};

// ============================================================================
// StateFilter — filter for room state events.
//
// Implements the Matrix StateFilter as defined in the spec:
//   - types:       whitelist of state event types to include
//   - not_types:   blacklist of state event types to exclude
//   - senders:     whitelist of sender user IDs to include
//   - not_senders: blacklist of sender user IDs to exclude
//   - limit:       maximum number of state events to return
//   - lazy_load_members: if true, only include m.room.member events for
//                        members who have sent events in the timeline,
//                        dramatically reducing payload for large rooms.
//   - include_redundant_members: if true, include ALL member events
//                        regardless of lazy_load_members. False by default.
//                        When set to true with lazy_load_members=true,
//                        the server may still lazy-load but clients indicate
//                        they want the full list if possible.
//
// Lazy-loading logic:
//   When lazy_load_members is true, membership events ("m.room.member")
//   are only included if the member's user_id appears in the sender field
//   of any event in the timeline being returned. This means the client
//   only gets member state for users who are "active" in the visible
//   portion of the timeline. The client can later request the full member
//   list via /members if needed.
//
//   include_redundant_members overrides this: when true, all member events
//   are included regardless of the sender set. This is used by clients
//   that have already paginated and want to refresh the member list.
// ============================================================================
struct StateFilter {
  bool         has_types                    = false;
  bool         has_not_types                = false;
  bool         has_senders                  = false;
  bool         has_not_senders              = false;
  bool         has_limit                    = false;
  bool         has_lazy_load_members        = false;
  bool         has_include_redundant_members = false;

  std::set<std::string> types;
  std::set<std::string> not_types;
  std::set<std::string> senders;
  std::set<std::string> not_senders;
  int          limit                    = DEFAULT_ROOM_STATE_LIMIT;
  bool         lazy_load_members        = false;
  bool         include_redundant_members = false;

  // ------------------------------------------------------------------------
  // Default constructor — creates a pass-through filter.
  // ------------------------------------------------------------------------
  StateFilter() = default;

  // ------------------------------------------------------------------------
  // is_empty — returns true if no filtering is active.
  // ------------------------------------------------------------------------
  bool is_empty() const {
    return !has_types && !has_not_types && !has_senders && !has_not_senders &&
           !has_lazy_load_members;
  }

  // ------------------------------------------------------------------------
  // is_limited_only — only limit is specified.
  // ------------------------------------------------------------------------
  bool is_limited_only() const {
    return is_empty() && has_limit;
  }

  // ------------------------------------------------------------------------
  // should_lazy_load_members — returns true if lazy-loading is active.
  // Lazy-loading is active when lazy_load_members is true AND
  // include_redundant_members is NOT true (or not specified).
  // ------------------------------------------------------------------------
  bool should_lazy_load_members() const {
    return lazy_load_members && !include_redundant_members;
  }

  // ------------------------------------------------------------------------
  // matches_state_event — checks whether a state event passes this filter.
  //
  // Parameters:
  //   - event_type:  state event type (e.g., "m.room.member")
  //   - sender:      sender's user ID
  //   - state_key:   state key (e.g., user ID for member events)
  //
  // Returns true if the event should be included.
  // ------------------------------------------------------------------------
  bool matches_state_event(const std::string& event_type,
                           const std::string& sender,
                           const std::string& state_key) const {
    if (has_types && !types.empty()) {
      if (types.find(event_type) == types.end()) return false;
    }
    if (has_not_types && !not_types.empty()) {
      if (not_types.find(event_type) != not_types.end()) return false;
    }
    if (has_senders && !senders.empty()) {
      if (senders.find(sender) == senders.end()) return false;
    }
    if (has_not_senders && !not_senders.empty()) {
      if (not_senders.find(sender) != not_senders.end()) return false;
    }
    return true;
  }

  // ------------------------------------------------------------------------
  // is_member_event_filtered_out_by_lazy_loading — checks whether a
  // membership event should be excluded due to lazy-loading.
  //
  // A membership event is excluded if:
  //   - lazy_load_members is true
  //   - include_redundant_members is false
  //   - The member's user_id is NOT in the sender_set
  //
  // The sender_set is the set of all sender user_ids from events in the
  // timeline that have been or will be returned to the client.
  // ------------------------------------------------------------------------
  bool is_member_event_filtered_out_by_lazy_loading(
      const std::string& state_key,
      const std::unordered_set<std::string>& active_senders) const {
    if (!should_lazy_load_members()) return false;
    return active_senders.find(state_key) == active_senders.end();
  }

  // ------------------------------------------------------------------------
  // apply_limit — truncate a vector to at most `limit` entries.
  // ------------------------------------------------------------------------
  template<typename T>
  std::vector<T> apply_limit(const std::vector<T>& items) const {
    if (!has_limit) return items;
    if (static_cast<int>(items.size()) <= limit) return items;
    return std::vector<T>(items.begin(), items.begin() + limit);
  }

  // ------------------------------------------------------------------------
  // build_sql_where — construct a SQL WHERE clause for this state filter.
  // ------------------------------------------------------------------------
  std::pair<std::string, SQLQueryParameters> build_sql_where() const {
    std::vector<std::string> clauses;
    SQLQueryParameters params;
    int param_idx = 0;

    if (has_types && !types.empty()) {
      std::vector<std::string> placeholders;
      for (const auto& t : types) {
        ++param_idx;
        placeholders.push_back("$" + std::to_string(param_idx));
        params.emplace_back(t);
      }
      clauses.push_back("event_type IN (" +
                        join_strings(placeholders, ", ") + ")");
    }

    if (has_not_types && !not_types.empty()) {
      std::vector<std::string> placeholders;
      for (const auto& t : not_types) {
        ++param_idx;
        placeholders.push_back("$" + std::to_string(param_idx));
        params.emplace_back(t);
      }
      clauses.push_back("event_type NOT IN (" +
                        join_strings(placeholders, ", ") + ")");
    }

    if (has_senders && !senders.empty()) {
      std::vector<std::string> placeholders;
      for (const auto& s : senders) {
        ++param_idx;
        placeholders.push_back("$" + std::to_string(param_idx));
        params.emplace_back(s);
      }
      clauses.push_back("sender IN (" +
                        join_strings(placeholders, ", ") + ")");
    }

    if (has_not_senders && !not_senders.empty()) {
      std::vector<std::string> placeholders;
      for (const auto& s : not_senders) {
        ++param_idx;
        placeholders.push_back("$" + std::to_string(param_idx));
        params.emplace_back(s);
      }
      clauses.push_back("sender NOT IN (" +
                        join_strings(placeholders, ", ") + ")");
    }

    std::string where;
    if (!clauses.empty()) {
      where = "WHERE " + join_strings(clauses, " AND ");
    }
    return {where, params};
  }

  // ------------------------------------------------------------------------
  // to_json — serialize this filter to a JSON object.
  // ------------------------------------------------------------------------
  json to_json() const {
    json j;
    if (has_types) {
      j[FILTER_FIELD_TYPES] = json::array();
      for (const auto& t : types) j[FILTER_FIELD_TYPES].push_back(t);
    }
    if (has_not_types) {
      j[FILTER_FIELD_NOT_TYPES] = json::array();
      for (const auto& t : not_types) j[FILTER_FIELD_NOT_TYPES].push_back(t);
    }
    if (has_senders) {
      j[FILTER_FIELD_SENDERS] = json::array();
      for (const auto& s : senders) j[FILTER_FIELD_SENDERS].push_back(s);
    }
    if (has_not_senders) {
      j[FILTER_FIELD_NOT_SENDERS] = json::array();
      for (const auto& s : not_senders) j[FILTER_FIELD_NOT_SENDERS].push_back(s);
    }
    if (has_limit) j[FILTER_FIELD_LIMIT] = limit;
    if (has_lazy_load_members) {
      j[FILTER_FIELD_LAZY_LOAD_MEMBERS] = lazy_load_members;
    }
    if (has_include_redundant_members) {
      j[FILTER_FIELD_INCLUDE_REDUNDANT_MEMBERS] = include_redundant_members;
    }
    return j;
  }

  // ------------------------------------------------------------------------
  // from_json — parse a StateFilter from a JSON object.
  // ------------------------------------------------------------------------
  static std::optional<StateFilter> from_json(
      const json& j,
      FilterValidationResult& vr,
      const std::string& path);
};

// ============================================================================
// RoomFilter — filter for a single room's data in /sync responses.
//
// Contains separate filters for:
//   - timeline:     RoomEventFilter for timeline events
//   - state:        StateFilter for state events
//   - ephemeral:    RoomEventFilter for ephemeral events (typing, receipts)
//   - account_data: RoomEventFilter for account-data events
//   - rooms:        whitelist of room IDs
//   - not_rooms:    blacklist of room IDs
// ============================================================================
struct RoomFilter {
  bool has_rooms = false;
  bool has_not_rooms = false;

  std::set<std::string> rooms;
  std::set<std::string> not_rooms;

  RoomEventFilter timeline;
  StateFilter      state;
  RoomEventFilter  ephemeral;
  RoomEventFilter  account_data;

  // ------------------------------------------------------------------------
  // Default constructor.
  // ------------------------------------------------------------------------
  RoomFilter() = default;

  // ------------------------------------------------------------------------
  // is_empty — no filtering at all.
  // ------------------------------------------------------------------------
  bool is_empty() const {
    return !has_rooms && !has_not_rooms &&
           timeline.is_empty() && state.is_empty() &&
           ephemeral.is_empty() && account_data.is_empty();
  }

  // ------------------------------------------------------------------------
  // room_included — check if a room_id passes the room whitelist/blacklist.
  // ------------------------------------------------------------------------
  bool room_included(const std::string& room_id) const {
    if (has_not_rooms && !not_rooms.empty()) {
      if (not_rooms.find(room_id) != not_rooms.end()) return false;
    }
    if (has_rooms && !rooms.empty()) {
      if (rooms.find(room_id) == rooms.end()) return false;
    }
    return true;
  }

  // ------------------------------------------------------------------------
  // to_json — serialize to JSON.
  // ------------------------------------------------------------------------
  json to_json() const {
    json j;
    if (!timeline.is_empty() || timeline.has_limit) {
      j[FILTER_FIELD_ROOM_TIMELINE] = timeline.to_json();
    }
    if (!state.is_empty() || state.has_limit) {
      j[FILTER_FIELD_ROOM_STATE] = state.to_json();
    }
    if (!ephemeral.is_empty() || ephemeral.has_limit) {
      j[FILTER_FIELD_ROOM_EPHEMERAL] = ephemeral.to_json();
    }
    if (!account_data.is_empty() || account_data.has_limit) {
      j[FILTER_FIELD_ROOM_ACCOUNT_DATA] = account_data.to_json();
    }
    if (has_rooms) {
      j[FILTER_FIELD_ROOMS] = json::array();
      for (const auto& r : rooms) j[FILTER_FIELD_ROOMS].push_back(r);
    }
    if (has_not_rooms) {
      j[FILTER_FIELD_NOT_ROOMS] = json::array();
      for (const auto& r : not_rooms) j[FILTER_FIELD_NOT_ROOMS].push_back(r);
    }
    return j;
  }

  // ------------------------------------------------------------------------
  // from_json — parse from JSON with validation.
  // ------------------------------------------------------------------------
  static std::optional<RoomFilter> from_json(
      const json& j,
      FilterValidationResult& vr,
      const std::string& path);
};

// ============================================================================
// MatrixFilter — the top-level filter object for the /sync endpoint.
//
// Fields:
//   - event_fields:  list of event fields to include (strip others)
//   - event_format:  "client" or "federation"
//   - presence:      EventFilter for presence events
//   - account_data:  EventFilter for account-data events
//   - room:          RoomFilter for room-level filtering
// ============================================================================
struct MatrixFilter {
  EventFieldFilter event_fields;
  RoomEventFilter  presence;
  RoomEventFilter  account_data;
  RoomFilter       room;

  // ------------------------------------------------------------------------
  // Default constructor.
  // ------------------------------------------------------------------------
  MatrixFilter() = default;

  // ------------------------------------------------------------------------
  // is_empty — returns true if no filtering is configured.
  // ------------------------------------------------------------------------
  bool is_empty() const {
    return !event_fields.enabled &&
           presence.is_empty() &&
           account_data.is_empty() &&
           room.is_empty();
  }

  // ------------------------------------------------------------------------
  // to_json — serialize to JSON.
  // ------------------------------------------------------------------------
  json to_json() const {
    json j;
    if (event_fields.enabled) {
      if (!event_fields.fields.empty()) {
        j[FILTER_FIELD_EVENT_FIELDS] = json::array();
        for (const auto& f : event_fields.fields) {
          j[FILTER_FIELD_EVENT_FIELDS].push_back(f);
        }
      }
      if (event_fields.format != EVENT_FORMAT_CLIENT) {
        j[FILTER_FIELD_EVENT_FORMAT] = event_fields.format;
      }
    }
    if (!presence.is_empty() || presence.has_limit) {
      j["presence"] = presence.to_json();
    }
    if (!account_data.is_empty() || account_data.has_limit) {
      j["account_data"] = account_data.to_json();
    }
    if (!room.is_empty()) {
      j[FILTER_FIELD_ROOM] = room.to_json();
    }
    return j;
  }

  // ------------------------------------------------------------------------
  // from_json — parse a full MatrixFilter from a JSON object.
  // Validates the top-level structure and delegates to sub-filter parsers.
  // ------------------------------------------------------------------------
  static std::optional<MatrixFilter> from_json(
      const json& j,
      FilterValidationResult& vr,
      const std::string& path = "",
      bool strict = false);
};

// ============================================================================
// Static from_json implementations
// ============================================================================

// ----------------------------------------------------------------------------
// EventFieldFilter::from_json
// ----------------------------------------------------------------------------
/* static */ std::optional<EventFieldFilter> EventFieldFilter::from_json(
    const json& j,
    FilterValidationResult& vr,
    const std::string& path) {

  if (!j.is_object()) {
    vr.add_error(path, "event_fields must be an object");
    return std::nullopt;
  }

  EventFieldFilter eff;
  eff.enabled = true;

  // Parse fields array
  if (j.contains(FILTER_FIELD_EVENT_FIELDS)) {
    const auto& fields_val = j[FILTER_FIELD_EVENT_FIELDS];
    if (!fields_val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_EVENT_FIELDS,
                   "event_fields must be an array of strings");
    } else {
      for (const auto& f : fields_val) {
        if (f.is_string()) {
          eff.fields.insert(f.get<std::string>());
        } else {
          vr.add_error(path + "." + FILTER_FIELD_EVENT_FIELDS,
                       "each event_field must be a string, got " +
                       json_value_repr(f));
        }
      }
    }
  }

  // Parse event_format
  if (j.contains(FILTER_FIELD_EVENT_FORMAT)) {
    const auto& fmt = j[FILTER_FIELD_EVENT_FORMAT];
    if (!fmt.is_string()) {
      vr.add_error(path + "." + FILTER_FIELD_EVENT_FORMAT,
                   "event_format must be a string (\"client\" or \"federation\")");
    } else {
      std::string fmt_str = fmt.get<std::string>();
      if (fmt_str == EVENT_FORMAT_CLIENT || fmt_str == EVENT_FORMAT_FEDERATION) {
        eff.format = fmt_str;
      } else {
        vr.add_error(path + "." + FILTER_FIELD_EVENT_FORMAT,
                     "event_format must be \"client\" or \"federation\", got \"" +
                     fmt_str + "\"");
      }
    }
  }

  return eff;
}

// ----------------------------------------------------------------------------
// RoomEventFilter::from_json
// ----------------------------------------------------------------------------
/* static */ std::optional<RoomEventFilter> RoomEventFilter::from_json(
    const json& j,
    FilterValidationResult& vr,
    const std::string& path) {

  if (!j.is_object()) {
    vr.add_error(path, "RoomEventFilter must be a JSON object");
    return std::nullopt;
  }

  RoomEventFilter ref;

  // --- Parse `types` array ---
  if (j.contains(FILTER_FIELD_TYPES)) {
    ref.has_types = true;
    const auto& val = j[FILTER_FIELD_TYPES];
    if (val.is_null()) {
      // null means "unbounded" — include all types
      ref.has_types = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_TYPES,
                   "types must be an array of strings or null, got " +
                   json_value_repr(val));
    } else {
      for (const auto& item : val) {
        if (item.is_string()) {
          ref.types.insert(item.get<std::string>());
        } else {
          vr.add_error(path + "." + FILTER_FIELD_TYPES,
                       "each type must be a string, got " + json_value_repr(item));
        }
      }
    }
  }

  // --- Parse `not_types` array ---
  if (j.contains(FILTER_FIELD_NOT_TYPES)) {
    ref.has_not_types = true;
    const auto& val = j[FILTER_FIELD_NOT_TYPES];
    if (val.is_null()) {
      ref.has_not_types = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_NOT_TYPES,
                   "not_types must be an array of strings or null, got " +
                   json_value_repr(val));
    } else {
      for (const auto& item : val) {
        if (item.is_string()) {
          ref.not_types.insert(item.get<std::string>());
        } else {
          vr.add_error(path + "." + FILTER_FIELD_NOT_TYPES,
                       "each not_type must be a string, got " +
                       json_value_repr(item));
        }
      }
    }
  }

  // --- Parse `senders` array ---
  if (j.contains(FILTER_FIELD_SENDERS)) {
    ref.has_senders = true;
    const auto& val = j[FILTER_FIELD_SENDERS];
    if (val.is_null()) {
      ref.has_senders = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_SENDERS,
                   "senders must be an array of strings or null, got " +
                   json_value_repr(val));
    } else {
      for (const auto& item : val) {
        if (item.is_string()) {
          std::string sender = item.get<std::string>();
          if (is_valid_user_id(sender)) {
            ref.senders.insert(sender);
          } else {
            vr.add_warning(path + "." + FILTER_FIELD_SENDERS,
                           "sender \"" + sender +
                           "\" does not look like a valid Matrix user ID");
            ref.senders.insert(sender);  // still include it
          }
        } else {
          vr.add_error(path + "." + FILTER_FIELD_SENDERS,
                       "each sender must be a string, got " +
                       json_value_repr(item));
        }
      }
    }
  }

  // --- Parse `not_senders` array ---
  if (j.contains(FILTER_FIELD_NOT_SENDERS)) {
    ref.has_not_senders = true;
    const auto& val = j[FILTER_FIELD_NOT_SENDERS];
    if (val.is_null()) {
      ref.has_not_senders = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_NOT_SENDERS,
                   "not_senders must be an array of strings or null, got " +
                   json_value_repr(val));
    } else {
      for (const auto& item : val) {
        if (item.is_string()) {
          std::string sender = item.get<std::string>();
          if (is_valid_user_id(sender)) {
            ref.not_senders.insert(sender);
          } else {
            vr.add_warning(path + "." + FILTER_FIELD_NOT_SENDERS,
                           "not_sender \"" + sender +
                           "\" does not look like a valid Matrix user ID");
            ref.not_senders.insert(sender);
          }
        } else {
          vr.add_error(path + "." + FILTER_FIELD_NOT_SENDERS,
                       "each not_sender must be a string, got " +
                       json_value_repr(item));
        }
      }
    }
  }

  // --- Parse `rooms` array ---
  if (j.contains(FILTER_FIELD_ROOMS)) {
    ref.has_rooms = true;
    const auto& val = j[FILTER_FIELD_ROOMS];
    if (val.is_null()) {
      ref.has_rooms = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_ROOMS,
                   "rooms must be an array of strings or null, got " +
                   json_value_repr(val));
    } else {
      for (const auto& item : val) {
        if (item.is_string()) {
          std::string rid = item.get<std::string>();
          if (is_valid_room_id(rid)) {
            ref.rooms.insert(rid);
          } else {
            vr.add_warning(path + "." + FILTER_FIELD_ROOMS,
                           "room_id \"" + rid +
                           "\" does not look like a valid Matrix room ID");
            ref.rooms.insert(rid);
          }
        } else {
          vr.add_error(path + "." + FILTER_FIELD_ROOMS,
                       "each room must be a string, got " +
                       json_value_repr(item));
        }
      }
    }
  }

  // --- Parse `not_rooms` array ---
  if (j.contains(FILTER_FIELD_NOT_ROOMS)) {
    ref.has_not_rooms = true;
    const auto& val = j[FILTER_FIELD_NOT_ROOMS];
    if (val.is_null()) {
      ref.has_not_rooms = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_NOT_ROOMS,
                   "not_rooms must be an array of strings or null, got " +
                   json_value_repr(val));
    } else {
      for (const auto& item : val) {
        if (item.is_string()) {
          std::string rid = item.get<std::string>();
          if (is_valid_room_id(rid)) {
            ref.not_rooms.insert(rid);
          } else {
            vr.add_warning(path + "." + FILTER_FIELD_NOT_ROOMS,
                           "room_id \"" + rid +
                           "\" does not look like a valid Matrix room ID");
            ref.not_rooms.insert(rid);
          }
        } else {
          vr.add_error(path + "." + FILTER_FIELD_NOT_ROOMS,
                       "each not_room must be a string, got " +
                       json_value_repr(item));
        }
      }
    }
  }

  // --- Parse `contains_url` boolean ---
  if (j.contains(FILTER_FIELD_CONTAINS_URL)) {
    ref.has_contains_url = true;
    const auto& val = j[FILTER_FIELD_CONTAINS_URL];
    if (val.is_boolean()) {
      ref.contains_url = val.get<bool>();
    } else if (val.is_null()) {
      ref.contains_url = false;
    } else {
      vr.add_error(path + "." + FILTER_FIELD_CONTAINS_URL,
                   "contains_url must be a boolean, got " +
                   json_value_repr(val));
    }
  }

  // --- Parse `limit` integer ---
  if (j.contains(FILTER_FIELD_LIMIT)) {
    ref.has_limit = true;
    const auto& val = j[FILTER_FIELD_LIMIT];
    if (val.is_number_integer()) {
      int lim = val.get<int>();
      if (lim < 0) {
        vr.add_error(path + "." + FILTER_FIELD_LIMIT,
                     "limit must be non-negative, got " + std::to_string(lim));
      } else if (lim > MAX_FILTER_LIMIT) {
        vr.add_warning(path + "." + FILTER_FIELD_LIMIT,
                       "limit " + std::to_string(lim) +
                       " exceeds maximum of " + std::to_string(MAX_FILTER_LIMIT) +
                       ", capping");
        ref.limit = MAX_FILTER_LIMIT;
      } else {
        ref.limit = lim;
      }
    } else if (val.is_null()) {
      ref.has_limit = false;
    } else {
      vr.add_error(path + "." + FILTER_FIELD_LIMIT,
                   "limit must be an integer, got " + json_value_repr(val));
    }
  }

  return ref;
}

// ----------------------------------------------------------------------------
// StateFilter::from_json
// ----------------------------------------------------------------------------
/* static */ std::optional<StateFilter> StateFilter::from_json(
    const json& j,
    FilterValidationResult& vr,
    const std::string& path) {

  if (!j.is_object()) {
    vr.add_error(path, "StateFilter must be a JSON object");
    return std::nullopt;
  }

  StateFilter sf;

  // --- Parse `types` array ---
  if (j.contains(FILTER_FIELD_TYPES)) {
    sf.has_types = true;
    const auto& val = j[FILTER_FIELD_TYPES];
    if (val.is_null()) {
      sf.has_types = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_TYPES,
                   "types must be an array of strings or null");
    } else {
      for (const auto& item : val) {
        if (item.is_string()) {
          sf.types.insert(item.get<std::string>());
        } else {
          vr.add_error(path + "." + FILTER_FIELD_TYPES,
                       "each type must be a string");
        }
      }
    }
  }

  // --- Parse `not_types` array ---
  if (j.contains(FILTER_FIELD_NOT_TYPES)) {
    sf.has_not_types = true;
    const auto& val = j[FILTER_FIELD_NOT_TYPES];
    if (val.is_null()) {
      sf.has_not_types = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_NOT_TYPES,
                   "not_types must be an array of strings or null");
    } else {
      for (const auto& item : val) {
        if (item.is_string()) {
          sf.not_types.insert(item.get<std::string>());
        } else {
          vr.add_error(path + "." + FILTER_FIELD_NOT_TYPES,
                       "each not_type must be a string");
        }
      }
    }
  }

  // --- Parse `senders` array ---
  if (j.contains(FILTER_FIELD_SENDERS)) {
    sf.has_senders = true;
    const auto& val = j[FILTER_FIELD_SENDERS];
    if (val.is_null()) {
      sf.has_senders = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_SENDERS,
                   "senders must be an array of strings or null");
    } else {
      for (const auto& item : val) {
        if (item.is_string()) {
          sf.senders.insert(item.get<std::string>());
        } else {
          vr.add_error(path + "." + FILTER_FIELD_SENDERS,
                       "each sender must be a string");
        }
      }
    }
  }

  // --- Parse `not_senders` array ---
  if (j.contains(FILTER_FIELD_NOT_SENDERS)) {
    sf.has_not_senders = true;
    const auto& val = j[FILTER_FIELD_NOT_SENDERS];
    if (val.is_null()) {
      sf.has_not_senders = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_NOT_SENDERS,
                   "not_senders must be an array of strings or null");
    } else {
      for (const auto& item : val) {
        if (item.is_string()) {
          sf.not_senders.insert(item.get<std::string>());
        } else {
          vr.add_error(path + "." + FILTER_FIELD_NOT_SENDERS,
                       "each not_sender must be a string");
        }
      }
    }
  }

  // --- Parse `limit` integer ---
  if (j.contains(FILTER_FIELD_LIMIT)) {
    sf.has_limit = true;
    const auto& val = j[FILTER_FIELD_LIMIT];
    if (val.is_number_integer()) {
      int lim = val.get<int>();
      if (lim < 0) {
        vr.add_error(path + "." + FILTER_FIELD_LIMIT,
                     "limit must be non-negative, got " + std::to_string(lim));
      } else if (lim > MAX_FILTER_LIMIT) {
        vr.add_warning(path + "." + FILTER_FIELD_LIMIT,
                       "limit " + std::to_string(lim) +
                       " exceeds maximum, capping");
        sf.limit = MAX_FILTER_LIMIT;
      } else {
        sf.limit = lim;
      }
    } else if (val.is_null()) {
      sf.has_limit = false;
    } else {
      vr.add_error(path + "." + FILTER_FIELD_LIMIT,
                   "limit must be an integer");
    }
  }

  // --- Parse `lazy_load_members` boolean ---
  if (j.contains(FILTER_FIELD_LAZY_LOAD_MEMBERS)) {
    sf.has_lazy_load_members = true;
    const auto& val = j[FILTER_FIELD_LAZY_LOAD_MEMBERS];
    if (val.is_boolean()) {
      sf.lazy_load_members = val.get<bool>();
    } else {
      vr.add_error(path + "." + FILTER_FIELD_LAZY_LOAD_MEMBERS,
                   "lazy_load_members must be a boolean, got " +
                   json_value_repr(val));
    }
  }

  // --- Parse `include_redundant_members` boolean ---
  if (j.contains(FILTER_FIELD_INCLUDE_REDUNDANT_MEMBERS)) {
    sf.has_include_redundant_members = true;
    const auto& val = j[FILTER_FIELD_INCLUDE_REDUNDANT_MEMBERS];
    if (val.is_boolean()) {
      sf.include_redundant_members = val.get<bool>();
    } else {
      vr.add_error(path + "." + FILTER_FIELD_INCLUDE_REDUNDANT_MEMBERS,
                   "include_redundant_members must be a boolean, got " +
                   json_value_repr(val));
    }
  }

  return sf;
}

// ----------------------------------------------------------------------------
// RoomFilter::from_json
// ----------------------------------------------------------------------------
/* static */ std::optional<RoomFilter> RoomFilter::from_json(
    const json& j,
    FilterValidationResult& vr,
    const std::string& path) {

  if (!j.is_object()) {
    vr.add_error(path, "Room filter must be a JSON object");
    return std::nullopt;
  }

  RoomFilter rf;

  // --- Parse `rooms` array ---
  if (j.contains(FILTER_FIELD_ROOMS)) {
    rf.has_rooms = true;
    const auto& val = j[FILTER_FIELD_ROOMS];
    if (val.is_null()) {
      rf.has_rooms = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_ROOMS,
                   "rooms must be an array of strings or null");
    } else {
      for (const auto& item : val) {
        if (item.is_string()) rf.rooms.insert(item.get<std::string>());
      }
    }
  }

  // --- Parse `not_rooms` array ---
  if (j.contains(FILTER_FIELD_NOT_ROOMS)) {
    rf.has_not_rooms = true;
    const auto& val = j[FILTER_FIELD_NOT_ROOMS];
    if (val.is_null()) {
      rf.has_not_rooms = true;
    } else if (!val.is_array()) {
      vr.add_error(path + "." + FILTER_FIELD_NOT_ROOMS,
                   "not_rooms must be an array of strings or null");
    } else {
      for (const auto& item : val) {
        if (item.is_string()) rf.not_rooms.insert(item.get<std::string>());
      }
    }
  }

  // --- Parse `timeline` sub-filter ---
  if (j.contains(FILTER_FIELD_ROOM_TIMELINE)) {
    auto sub = RoomEventFilter::from_json(
        j[FILTER_FIELD_ROOM_TIMELINE], vr,
        path + "." + FILTER_FIELD_ROOM_TIMELINE);
    if (sub.has_value()) rf.timeline = sub.value();
  }

  // --- Parse `state` sub-filter ---
  if (j.contains(FILTER_FIELD_ROOM_STATE)) {
    auto sub = StateFilter::from_json(
        j[FILTER_FIELD_ROOM_STATE], vr,
        path + "." + FILTER_FIELD_ROOM_STATE);
    if (sub.has_value()) rf.state = sub.value();
  }

  // --- Parse `ephemeral` sub-filter ---
  if (j.contains(FILTER_FIELD_ROOM_EPHEMERAL)) {
    auto sub = RoomEventFilter::from_json(
        j[FILTER_FIELD_ROOM_EPHEMERAL], vr,
        path + "." + FILTER_FIELD_ROOM_EPHEMERAL);
    if (sub.has_value()) rf.ephemeral = sub.value();
  }

  // --- Parse `account_data` sub-filter ---
  if (j.contains(FILTER_FIELD_ROOM_ACCOUNT_DATA)) {
    auto sub = RoomEventFilter::from_json(
        j[FILTER_FIELD_ROOM_ACCOUNT_DATA], vr,
        path + "." + FILTER_FIELD_ROOM_ACCOUNT_DATA);
    if (sub.has_value()) rf.account_data = sub.value();
  }

  return rf;
}

// ----------------------------------------------------------------------------
// MatrixFilter::from_json
// ----------------------------------------------------------------------------
/* static */ std::optional<MatrixFilter> MatrixFilter::from_json(
    const json& j,
    FilterValidationResult& vr,
    const std::string& path,
    bool strict) {

  if (!j.is_object()) {
    vr.add_error(path, "Filter must be a JSON object");
    return std::nullopt;
  }

  MatrixFilter mf;

  // --- Check for unknown fields (strict mode) ---
  if (strict) {
    for (auto it = j.begin(); it != j.end(); ++it) {
      if (KNOWN_FILTER_FIELDS.find(it.key()) == KNOWN_FILTER_FIELDS.end()) {
        vr.add_warning(path, "Unknown filter field: \"" + it.key() + "\"");
      }
    }
  }

  // --- Parse `event_fields` ---
  if (j.contains(FILTER_FIELD_EVENT_FIELDS) ||
      j.contains(FILTER_FIELD_EVENT_FORMAT)) {
    // EventFieldFilter expects the filter-level JSON (which may contain
    // both event_fields and event_format at the top level)
    auto eff = EventFieldFilter::from_json(j, vr, path);
    if (eff.has_value()) mf.event_fields = eff.value();
  }

  // --- Parse `presence` sub-filter ---
  if (j.contains("presence")) {
    auto sub = RoomEventFilter::from_json(
        j["presence"], vr, path + ".presence");
    if (sub.has_value()) mf.presence = sub.value();
  }

  // --- Parse `account_data` sub-filter ---
  if (j.contains("account_data")) {
    auto sub = RoomEventFilter::from_json(
        j["account_data"], vr, path + ".account_data");
    if (sub.has_value()) mf.account_data = sub.value();
  }

  // --- Parse `room` sub-filter ---
  if (j.contains(FILTER_FIELD_ROOM)) {
    auto sub = RoomFilter::from_json(
        j[FILTER_FIELD_ROOM], vr, path + ".room");
    if (sub.has_value()) mf.room = sub.value();
  }

  return mf;
}

// ============================================================================
// FilterCache — thread-safe LRU cache for parsed filter objects.
//
// Caches parsed MatrixFilter objects keyed by (user_id, filter_id) to avoid
// repeated JSON parsing and validation on every sync request. Uses a simple
// LRU eviction policy with a configurable max size and TTL-based expiry.
//
// Thread safety: uses a shared_mutex (read-write lock) so multiple readers
// can access the cache concurrently while writes are exclusive.
// ============================================================================
class FilterCache {
public:
  // ------------------------------------------------------------------------
  // Constructor — creates a cache with the given maximum size and TTL.
  // ------------------------------------------------------------------------
  explicit FilterCache(size_t max_size = FILTER_CACHE_MAX_SIZE,
                       int64_t ttl_seconds = FILTER_CACHE_TTL_SECONDS)
      : max_size_(max_size), ttl_seconds_(ttl_seconds) {
    last_cleanup_ = now_sec();
  }

  // ------------------------------------------------------------------------
  // get — retrieve a cached filter if it exists and hasn't expired.
  // Returns std::nullopt if the filter is not in the cache or has expired.
  // ------------------------------------------------------------------------
  std::optional<MatrixFilter> get(const std::string& user_id,
                                   const std::string& filter_id) {
    std::shared_lock lock(mutex_);

    std::string key = make_key(user_id, filter_id);
    auto it = cache_map_.find(key);
    if (it == cache_map_.end()) {
      cache_misses_++;
      return std::nullopt;
    }

    // Check TTL expiry
    int64_t now = now_sec();
    if (now - it->second.cached_at > ttl_seconds_) {
      // Expired — don't remove here (would need exclusive lock),
      // just report miss; it'll be cleaned up on next put or cleanup.
      cache_misses_++;
      return std::nullopt;
    }

    // Move to front of LRU list (can't do under shared_lock, but we
    // approximate by not touching the list on reads — only on writes).
    // This is an acceptable trade-off: LRU is approximate for reads.
    cache_hits_++;
    return it->second.filter;
  }

  // ------------------------------------------------------------------------
  // put — store a filter in the cache. If the cache is full, evicts the
  // least recently used entry. If the key already exists, updates it.
  // ------------------------------------------------------------------------
  void put(const std::string& user_id, const std::string& filter_id,
           const MatrixFilter& filter) {
    std::unique_lock lock(mutex_);

    // Periodic cleanup
    maybe_cleanup();

    std::string key = make_key(user_id, filter_id);

    // If already exists, remove from LRU list to re-add at front
    auto it = cache_map_.find(key);
    if (it != cache_map_.end()) {
      lru_list_.erase(it->second.lru_pos);
    }

    // Evict if at capacity
    while (cache_map_.size() >= max_size_) {
      evict_lru();
    }

    // Add to front of LRU list
    lru_list_.push_front(key);
    CacheEntry entry;
    entry.filter = filter;
    entry.cached_at = now_sec();
    entry.lru_pos = lru_list_.begin();
    cache_map_[key] = entry;
  }

  // ------------------------------------------------------------------------
  // invalidate — remove a specific filter from the cache.
  // ------------------------------------------------------------------------
  void invalidate(const std::string& user_id, const std::string& filter_id) {
    std::unique_lock lock(mutex_);
    std::string key = make_key(user_id, filter_id);
    auto it = cache_map_.find(key);
    if (it != cache_map_.end()) {
      lru_list_.erase(it->second.lru_pos);
      cache_map_.erase(it);
    }
  }

  // ------------------------------------------------------------------------
  // invalidate_user — remove all filters for a user from the cache.
  // ------------------------------------------------------------------------
  void invalidate_user(const std::string& user_id) {
    std::unique_lock lock(mutex_);
    std::string prefix = user_id + ":";
    for (auto it = cache_map_.begin(); it != cache_map_.end(); ) {
      if (starts_with(it->first, prefix)) {
        lru_list_.erase(it->second.lru_pos);
        it = cache_map_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // ------------------------------------------------------------------------
  // clear — remove all entries from the cache.
  // ------------------------------------------------------------------------
  void clear() {
    std::unique_lock lock(mutex_);
    cache_map_.clear();
    lru_list_.clear();
    cache_hits_ = 0;
    cache_misses_ = 0;
  }

  // ------------------------------------------------------------------------
  // stats — return cache statistics as a JSON object.
  // ------------------------------------------------------------------------
  json stats() const {
    std::shared_lock lock(mutex_);
    json j;
    j["size"] = cache_map_.size();
    j["max_size"] = max_size_;
    j["hits"] = cache_hits_;
    j["misses"] = cache_misses_;
    j["hit_ratio"] = (cache_hits_ + cache_misses_ > 0)
        ? static_cast<double>(cache_hits_) /
          static_cast<double>(cache_hits_ + cache_misses_)
        : 0.0;
    return j;
  }

private:
  struct CacheEntry {
    MatrixFilter filter;
    int64_t cached_at = 0;
    std::list<std::string>::iterator lru_pos;
  };

  std::string make_key(const std::string& user_id,
                        const std::string& filter_id) const {
    return user_id + ":" + filter_id;
  }

  void maybe_cleanup() {
    int64_t now = now_sec();
    if (now - last_cleanup_ < FILTER_CACHE_CLEANUP_INTERVAL_SEC) return;
    last_cleanup_ = now;

    // Remove expired entries
    for (auto it = cache_map_.begin(); it != cache_map_.end(); ) {
      if (now - it->second.cached_at > ttl_seconds_) {
        lru_list_.erase(it->second.lru_pos);
        it = cache_map_.erase(it);
      } else {
        ++it;
      }
    }
  }

  void evict_lru() {
    if (lru_list_.empty()) return;
    const auto& key = lru_list_.back();
    cache_map_.erase(key);
    lru_list_.pop_back();
  }

  size_t max_size_;
  int64_t ttl_seconds_;
  int64_t last_cleanup_ = 0;
  std::unordered_map<std::string, CacheEntry> cache_map_;
  std::list<std::string> lru_list_;  // front = most recent, back = LRU

  mutable std::shared_mutex mutex_;
  mutable int64_t cache_hits_ = 0;
  mutable int64_t cache_misses_ = 0;
};

// ============================================================================
// FilterStore — persistent storage and retrieval of filters via SQL.
//
// Provides CRUD operations for user-defined filters stored in the
// user_filters table. Each filter is associated with a user_id and has
// a unique filter_id (auto-incremented per user). The filter_json is
// stored as a text blob.
//
// Also manages server filters in the server_filters table, which are
// globally available named filters.
//
// All database operations use parameterized queries via the storage
// layer for SQL injection safety.
// ============================================================================
class FilterStore {
public:
  // ------------------------------------------------------------------------
  // Constructor — takes a reference to the DatabasePool.
  // ------------------------------------------------------------------------
  explicit FilterStore(DatabasePool& db)
      : db_(db) {
    storage_log.info("FilterStore initialized");
  }

  // ------------------------------------------------------------------------
  // ensure_tables — create the filter tables if they don't exist.
  // Should be called during server startup or migration.
  // ------------------------------------------------------------------------
  void ensure_tables() {
    storage_log.info("Ensuring filter tables exist...");

    db_.runInteraction("event_filter_engine.ensure_tables",
        [](LoggingTransaction& txn) {
          txn.execute(
              "CREATE TABLE IF NOT EXISTS user_filters ("
              "  user_id         TEXT        NOT NULL,"
              "  filter_id       BIGINT      NOT NULL,"
              "  filter_json     TEXT        NOT NULL,"
              "  created_ts      BIGINT      NOT NULL DEFAULT 0,"
              "  last_used_ts    BIGINT      NOT NULL DEFAULT 0,"
              "  CONSTRAINT user_filters_pk PRIMARY KEY (user_id, filter_id)"
              ")");

          txn.execute(
              "CREATE INDEX IF NOT EXISTS user_filters_user_idx "
              "ON user_filters (user_id, last_used_ts DESC)");

          txn.execute(
              "CREATE INDEX IF NOT EXISTS user_filters_created_idx "
              "ON user_filters (created_ts)");

          txn.execute(
              "CREATE TABLE IF NOT EXISTS server_filters ("
              "  filter_id       TEXT        NOT NULL PRIMARY KEY,"
              "  filter_json     TEXT        NOT NULL,"
              "  description     TEXT        NOT NULL DEFAULT '',"
              "  created_ts      BIGINT      NOT NULL DEFAULT 0,"
              "  updated_ts      BIGINT      NOT NULL DEFAULT 0"
              ")");

          txn.execute(
              "CREATE TABLE IF NOT EXISTS filter_usage_log ("
              "  id              BIGINT      PRIMARY KEY AUTOINCREMENT,"
              "  user_id         TEXT        NOT NULL,"
              "  filter_id       TEXT        NOT NULL,"
              "  request_type    TEXT        NOT NULL,"
              "  used_ts         BIGINT      NOT NULL DEFAULT 0,"
              "  room_count      INTEGER     NOT NULL DEFAULT 0,"
              "  event_count     INTEGER     NOT NULL DEFAULT 0,"
              "  duration_us     BIGINT      NOT NULL DEFAULT 0"
              ")");

          txn.execute(
              "CREATE INDEX IF NOT EXISTS filter_usage_user_idx "
              "ON filter_usage_log (user_id, used_ts DESC)");

          txn.execute(
              "CREATE INDEX IF NOT EXISTS filter_usage_filter_idx "
              "ON filter_usage_log (filter_id, used_ts DESC)");
        });

    storage_log.info("Filter tables ensured.");
  }

  // ------------------------------------------------------------------------
  // create_filter — store a new filter for a user.
  //
  // Generates the next filter_id for this user (auto-increment per user).
  // Inserts the filter_json into user_filters.
  //
  // Returns the assigned filter_id.
  //
  // This method runs inside its own transaction for atomicity: the filter
  // ID assignment and insert happen together.
  // ------------------------------------------------------------------------
  int64_t create_filter(const std::string& user_id, const json& filter_json) {
    return db_.runInteraction("event_filter_engine.create_filter",
        [&](LoggingTransaction& txn) -> int64_t {
          return create_filter_txn(txn, user_id, filter_json);
        });
  }

  // ------------------------------------------------------------------------
  // create_filter_txn — same as create_filter but within an existing
  // transaction. Useful for batch operations.
  // ------------------------------------------------------------------------
  static int64_t create_filter_txn(LoggingTransaction& txn,
                                    const std::string& user_id,
                                    const json& filter_json) {
    std::string json_str = filter_json.dump();
    int64_t now = now_sec();

    // Get next filter_id for this user
    txn.execute(
        "SELECT COALESCE(MAX(filter_id), 0) + 1 AS next_id "
        "FROM user_filters WHERE user_id = $1",
        {SQLParam{user_id}});

    int64_t next_id = 1;
    auto row = txn.fetchone();
    if (row.has_value() && !row->empty()) {
      const auto& col = (*row)[0];
      if (col.value.has_value()) {
        next_id = std::stoll(col.value.value());
      }
    }

    txn.execute(
        "INSERT INTO user_filters "
        "(user_id, filter_id, filter_json, created_ts, last_used_ts) "
        "VALUES ($1, $2, $3, $4, $5)",
        {SQLParam{user_id}, SQLParam{next_id},
         SQLParam{json_str}, SQLParam{now}, SQLParam{now}});

    storage_log.info("Created filter " + std::to_string(next_id) +
                     " for user " + user_id);
    return next_id;
  }

  // ------------------------------------------------------------------------
  // get_filter — retrieve a filter by user_id and filter_id.
  //
  // Returns the filter JSON if found, or std::nullopt if not found.
  // Also updates the last_used_ts to track filter usage.
  // ------------------------------------------------------------------------
  std::optional<json> get_filter(const std::string& user_id,
                                  int64_t filter_id) {
    return db_.runInteraction("event_filter_engine.get_filter",
        [&](LoggingTransaction& txn) -> std::optional<json> {
          return get_filter_txn(txn, user_id, filter_id, true);
        });
  }

  // ------------------------------------------------------------------------
  // get_filter_txn — transaction-bound version of get_filter.
  // ------------------------------------------------------------------------
  static std::optional<json> get_filter_txn(LoggingTransaction& txn,
                                             const std::string& user_id,
                                             int64_t filter_id,
                                             bool update_last_used = true) {
    txn.execute(
        "SELECT filter_json FROM user_filters "
        "WHERE user_id = $1 AND filter_id = $2",
        {SQLParam{user_id}, SQLParam{filter_id}});

    auto row = txn.fetchone();
    if (!row.has_value() || row->empty()) {
      return std::nullopt;
    }

    const auto& col = (*row)[0];
    if (!col.value.has_value()) {
      return std::nullopt;
    }

    if (update_last_used) {
      int64_t now = now_sec();
      txn.execute(
          "UPDATE user_filters SET last_used_ts = $1 "
          "WHERE user_id = $2 AND filter_id = $3",
          {SQLParam{now}, SQLParam{user_id}, SQLParam{filter_id}});
    }

    try {
      return json::parse(col.value.value());
    } catch (const json::parse_error& e) {
      storage_log.error("Failed to parse filter JSON for user " + user_id +
                        " filter " + std::to_string(filter_id) + ": " +
                        e.what());
      return std::nullopt;
    }
  }

  // ------------------------------------------------------------------------
  // get_all_filters — retrieve all filters for a user.
  //
  // Returns a vector of (filter_id, filter_json, created_ts, last_used_ts)
  // tuples, ordered by last_used_ts descending.
  // ------------------------------------------------------------------------
  struct FilterInfo {
    int64_t filter_id;
    json filter_json;
    int64_t created_ts;
    int64_t last_used_ts;
  };

  std::vector<FilterInfo> get_all_filters(const std::string& user_id) {
    return db_.runInteraction("event_filter_engine.get_all_filters",
        [&](LoggingTransaction& txn) -> std::vector<FilterInfo> {
          txn.execute(
              "SELECT filter_id, filter_json, created_ts, last_used_ts "
              "FROM user_filters WHERE user_id = $1 "
              "ORDER BY last_used_ts DESC",
              {SQLParam{user_id}});

          std::vector<FilterInfo> result;
          Row row;
          while (txn.iter_next(row)) {
            FilterInfo info;
            if (row.size() >= 4) {
              if (row[0].value.has_value())
                info.filter_id = std::stoll(row[0].value.value());
              if (row[1].value.has_value()) {
                try {
                  info.filter_json = json::parse(row[1].value.value());
                } catch (...) {
                  info.filter_json = json::object();
                }
              }
              if (row[2].value.has_value())
                info.created_ts = std::stoll(row[2].value.value());
              if (row[3].value.has_value())
                info.last_used_ts = std::stoll(row[3].value.value());
            }
            result.push_back(info);
          }
          return result;
        });
  }

  // ------------------------------------------------------------------------
  // update_filter — update an existing filter by storing a new JSON blob
  // under the same (user_id, filter_id) key. This effectively replaces
  // the old filter definition.
  //
  // Returns true if the filter existed and was updated, false if not found.
  // ------------------------------------------------------------------------
  bool update_filter(const std::string& user_id, int64_t filter_id,
                     const json& filter_json) {
    return db_.runInteraction("event_filter_engine.update_filter",
        [&](LoggingTransaction& txn) -> bool {
          return update_filter_txn(txn, user_id, filter_id, filter_json);
        });
  }

  // ------------------------------------------------------------------------
  // update_filter_txn — transaction-bound version of update_filter.
  // ------------------------------------------------------------------------
  static bool update_filter_txn(LoggingTransaction& txn,
                                 const std::string& user_id,
                                 int64_t filter_id,
                                 const json& filter_json) {
    std::string json_str = filter_json.dump();
    int64_t now = now_sec();

    txn.execute(
        "UPDATE user_filters "
        "SET filter_json = $1, last_used_ts = $2 "
        "WHERE user_id = $3 AND filter_id = $4",
        {SQLParam{json_str}, SQLParam{now},
         SQLParam{user_id}, SQLParam{filter_id}});

    int64_t count = txn.rowcount();
    return count > 0;
  }

  // ------------------------------------------------------------------------
  // delete_filter — remove a filter for a user.
  //
  // Returns true if the filter was found and deleted, false if not found.
  // ------------------------------------------------------------------------
  bool delete_filter(const std::string& user_id, int64_t filter_id) {
    return db_.runInteraction("event_filter_engine.delete_filter",
        [&](LoggingTransaction& txn) -> bool {
          return delete_filter_txn(txn, user_id, filter_id);
        });
  }

  // ------------------------------------------------------------------------
  // delete_filter_txn — transaction-bound version of delete_filter.
  // ------------------------------------------------------------------------
  static bool delete_filter_txn(LoggingTransaction& txn,
                                 const std::string& user_id,
                                 int64_t filter_id) {
    txn.execute(
        "DELETE FROM user_filters WHERE user_id = $1 AND filter_id = $2",
        {SQLParam{user_id}, SQLParam{filter_id}});

    int64_t count = txn.rowcount();
    return count > 0;
  }

  // ------------------------------------------------------------------------
  // delete_all_user_filters — remove all filters for a user.
  // Used during account deactivation/deletion.
  // ------------------------------------------------------------------------
  int64_t delete_all_user_filters(const std::string& user_id) {
    return db_.runInteraction("event_filter_engine.delete_all_user_filters",
        [&](LoggingTransaction& txn) -> int64_t {
          txn.execute("DELETE FROM user_filters WHERE user_id = $1",
                       {SQLParam{user_id}});
          return txn.rowcount();
        });
  }

  // ------------------------------------------------------------------------
  // count_user_filters — return the number of filters a user has.
  // ------------------------------------------------------------------------
  int64_t count_user_filters(const std::string& user_id) {
    return db_.runInteraction("event_filter_engine.count_filters",
        [&](LoggingTransaction& txn) -> int64_t {
          txn.execute(
              "SELECT COUNT(*) AS cnt FROM user_filters WHERE user_id = $1",
              {SQLParam{user_id}});
          auto row = txn.fetchone();
          if (row.has_value() && !row->empty() && (*row)[0].value.has_value()) {
            return std::stoll((*row)[0].value.value());
          }
          return 0;
        });
  }

  // ------------------------------------------------------------------------
  // Server filter operations
  // ------------------------------------------------------------------------

  void create_server_filter(const std::string& filter_id,
                            const json& filter_json,
                            const std::string& description = "") {
    db_.runInteraction("event_filter_engine.create_server_filter",
        [&](LoggingTransaction& txn) {
          std::string json_str = filter_json.dump();
          int64_t now = now_sec();

          txn.execute(
              "INSERT OR REPLACE INTO server_filters "
              "(filter_id, filter_json, description, created_ts, updated_ts) "
              "VALUES ($1, $2, $3, "
              "  COALESCE((SELECT created_ts FROM server_filters "
              "            WHERE filter_id = $1), $4),"
              "  $5)",
              {SQLParam{filter_id}, SQLParam{json_str},
               SQLParam{description}, SQLParam{now}, SQLParam{now}});

          storage_log.info("Created/updated server filter: " + filter_id);
        });
  }

  std::optional<json> get_server_filter(const std::string& filter_id) {
    return db_.runInteraction("event_filter_engine.get_server_filter",
        [&](LoggingTransaction& txn) -> std::optional<json> {
          txn.execute(
              "SELECT filter_json FROM server_filters WHERE filter_id = $1",
              {SQLParam{filter_id}});
          auto row = txn.fetchone();
          if (!row.has_value() || row->empty()) return std::nullopt;
          const auto& col = (*row)[0];
          if (!col.value.has_value()) return std::nullopt;
          try {
            return json::parse(col.value.value());
          } catch (...) {
            return std::nullopt;
          }
        });
  }

  std::vector<std::pair<std::string, json>> get_all_server_filters() {
    return db_.runInteraction("event_filter_engine.get_all_server_filters",
        [&](LoggingTransaction& txn)
            -> std::vector<std::pair<std::string, json>> {
          txn.execute(
              "SELECT filter_id, filter_json FROM server_filters "
              "ORDER BY filter_id");
          std::vector<std::pair<std::string, json>> result;
          Row row;
          while (txn.iter_next(row)) {
            if (row.size() >= 2 &&
                row[0].value.has_value() && row[1].value.has_value()) {
              try {
                result.emplace_back(row[0].value.value(),
                                    json::parse(row[1].value.value()));
              } catch (...) {}
            }
          }
          return result;
        });
  }

  bool delete_server_filter(const std::string& filter_id) {
    return db_.runInteraction("event_filter_engine.delete_server_filter",
        [&](LoggingTransaction& txn) -> bool {
          txn.execute("DELETE FROM server_filters WHERE filter_id = $1",
                       {SQLParam{filter_id}});
          return txn.rowcount() > 0;
        });
  }

  // ------------------------------------------------------------------------
  // filter_usage_log — record that a filter was used.
  // ------------------------------------------------------------------------
  void log_filter_usage(const std::string& user_id,
                        const std::string& filter_id_str,
                        const std::string& request_type,
                        int room_count, int event_count,
                        int64_t duration_us) {
    db_.runInteraction("event_filter_engine.log_usage",
        [&](LoggingTransaction& txn) {
          int64_t now = now_sec();
          txn.execute(
              "INSERT INTO filter_usage_log "
              "(user_id, filter_id, request_type, used_ts, "
              " room_count, event_count, duration_us) "
              "VALUES ($1, $2, $3, $4, $5, $6, $7)",
              {SQLParam{user_id}, SQLParam{filter_id_str},
               SQLParam{request_type}, SQLParam{now},
               SQLParam{static_cast<int64_t>(room_count)},
               SQLParam{static_cast<int64_t>(event_count)},
               SQLParam{duration_us}});
        });
  }

  // ------------------------------------------------------------------------
  // get_filter_usage_stats — return aggregate usage statistics.
  // ------------------------------------------------------------------------
  json get_filter_usage_stats(const std::string& user_id,
                               int64_t since_ts = 0) {
    return db_.runInteraction("event_filter_engine.usage_stats",
        [&](LoggingTransaction& txn) -> json {
          SQLQueryParameters params = {SQLParam{user_id}};
          std::string sql =
              "SELECT request_type, COUNT(*) AS cnt, "
              "SUM(event_count) AS total_events "
              "FROM filter_usage_log WHERE user_id = $1";
          if (since_ts > 0) {
            sql += " AND used_ts >= $2";
            params.push_back(SQLParam{since_ts});
          }
          sql += " GROUP BY request_type ORDER BY cnt DESC";

          txn.execute(sql, params);

          json result = json::array();
          Row row;
          while (txn.iter_next(row)) {
            json entry;
            if (row.size() >= 3) {
              if (row[0].value.has_value())
                entry["request_type"] = row[0].value.value();
              if (row[1].value.has_value())
                entry["count"] = std::stoll(row[1].value.value());
              if (row[2].value.has_value())
                entry["total_events"] = std::stoll(row[2].value.value());
            }
            result.push_back(entry);
          }
          return result;
        });
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// FilterValidator — standalone filter JSON validator.
//
// Provides methods to validate filter JSON against the Matrix spec without
// requiring a database connection. Can be used for client-side pre-validation
// or server-side validation before storing.
//
// Supports:
//   - validate_full: validate a complete MatrixFilter
//   - validate_room_event_filter: validate just a RoomEventFilter
//   - validate_state_filter: validate just a StateFilter
//   - strict mode: reject unknown fields
// ============================================================================
class FilterValidator {
public:
  // ------------------------------------------------------------------------
  // validate_full — validate a complete filter JSON document.
  //
  // Parameters:
  //   - filter_json:  the JSON object to validate
  //   - strict:       if true, unknown fields produce warnings
  //
  // Returns a FilterValidationResult with all errors and warnings.
  // ------------------------------------------------------------------------
  static FilterValidationResult validate_full(const json& filter_json,
                                                bool strict = false) {
    FilterValidationResult vr;

    if (!filter_json.is_object()) {
      vr.add_error("", "Filter must be a JSON object");
      return vr;
    }

    // Check for unknown top-level fields
    if (strict) {
      for (auto it = filter_json.begin(); it != filter_json.end(); ++it) {
        if (KNOWN_FILTER_FIELDS.find(it.key()) == KNOWN_FILTER_FIELDS.end()) {
          vr.add_warning("", "Unknown field: \"" + it.key() + "\"");
        }
      }
    }

    // Validate event_fields / event_format
    if (filter_json.contains(FILTER_FIELD_EVENT_FIELDS)) {
      const auto& val = filter_json[FILTER_FIELD_EVENT_FIELDS];
      if (!val.is_array()) {
        vr.add_error(FILTER_FIELD_EVENT_FIELDS,
                     "event_fields must be an array of strings");
      } else {
        for (size_t i = 0; i < val.size(); ++i) {
          if (!val[i].is_string()) {
            vr.add_error(FILTER_FIELD_EVENT_FIELDS + "[" + std::to_string(i) + "]",
                         "must be a string, got " + json_value_repr(val[i]));
          }
        }
      }
    }

    if (filter_json.contains(FILTER_FIELD_EVENT_FORMAT)) {
      const auto& val = filter_json[FILTER_FIELD_EVENT_FORMAT];
      if (!val.is_string()) {
        vr.add_error(FILTER_FIELD_EVENT_FORMAT, "must be a string");
      } else {
        std::string fmt = val.get<std::string>();
        if (fmt != EVENT_FORMAT_CLIENT && fmt != EVENT_FORMAT_FEDERATION) {
          vr.add_error(FILTER_FIELD_EVENT_FORMAT,
                       "must be \"client\" or \"federation\", got \"" + fmt + "\"");
        }
      }
    }

    // Validate presence
    if (filter_json.contains("presence")) {
      validate_room_event_filter_internal(
          filter_json["presence"], vr, "presence", strict, true);
    }

    // Validate account_data
    if (filter_json.contains("account_data")) {
      validate_room_event_filter_internal(
          filter_json["account_data"], vr, "account_data", strict, true);
    }

    // Validate room
    if (filter_json.contains(FILTER_FIELD_ROOM)) {
      validate_room_filter_internal(
          filter_json[FILTER_FIELD_ROOM], vr, "room", strict);
    }

    return vr;
  }

  // ------------------------------------------------------------------------
  // validate_room_event_filter — validate a RoomEventFilter JSON.
  // ------------------------------------------------------------------------
  static FilterValidationResult validate_room_event_filter(
      const json& filter_json, bool strict = false) {
    FilterValidationResult vr;
    validate_room_event_filter_internal(filter_json, vr, "", strict, false);
    return vr;
  }

  // ------------------------------------------------------------------------
  // validate_state_filter — validate a StateFilter JSON.
  // ------------------------------------------------------------------------
  static FilterValidationResult validate_state_filter(
      const json& filter_json, bool strict = false) {
    FilterValidationResult vr;
    if (!filter_json.is_object()) {
      vr.add_error("", "State filter must be a JSON object");
      return vr;
    }

    // Check for unknown fields
    if (strict) {
      for (auto it = filter_json.begin(); it != filter_json.end(); ++it) {
        if (KNOWN_STATE_FILTER_FIELDS.find(it.key()) ==
            KNOWN_STATE_FILTER_FIELDS.end()) {
          vr.add_warning("", "Unknown field: \"" + it.key() + "\"");
        }
      }
    }

    validate_string_array(filter_json, FILTER_FIELD_TYPES, vr, "");
    validate_string_array(filter_json, FILTER_FIELD_NOT_TYPES, vr, "");
    validate_string_array(filter_json, FILTER_FIELD_SENDERS, vr, "");
    validate_string_array(filter_json, FILTER_FIELD_NOT_SENDERS, vr, "");
    validate_integer(filter_json, FILTER_FIELD_LIMIT, vr, "", 0, MAX_FILTER_LIMIT);

    if (filter_json.contains(FILTER_FIELD_LAZY_LOAD_MEMBERS) &&
        !filter_json[FILTER_FIELD_LAZY_LOAD_MEMBERS].is_boolean() &&
        !filter_json[FILTER_FIELD_LAZY_LOAD_MEMBERS].is_null()) {
      vr.add_error(FILTER_FIELD_LAZY_LOAD_MEMBERS,
                   "lazy_load_members must be a boolean");
    }

    if (filter_json.contains(FILTER_FIELD_INCLUDE_REDUNDANT_MEMBERS) &&
        !filter_json[FILTER_FIELD_INCLUDE_REDUNDANT_MEMBERS].is_boolean() &&
        !filter_json[FILTER_FIELD_INCLUDE_REDUNDANT_MEMBERS].is_null()) {
      vr.add_error(FILTER_FIELD_INCLUDE_REDUNDANT_MEMBERS,
                   "include_redundant_members must be a boolean");
    }

    return vr;
  }

private:
  // ------------------------------------------------------------------------
  // Internal: validate a RoomEventFilter at a given path.
  // ------------------------------------------------------------------------
  static void validate_room_event_filter_internal(
      const json& j, FilterValidationResult& vr,
      const std::string& path, bool strict, bool compact) {

    if (!j.is_object()) {
      vr.add_error(path, "RoomEventFilter must be a JSON object");
      return;
    }

    const auto& allowed_fields = compact
        ? KNOWN_EVENT_FILTER_FIELDS
        : KNOWN_ROOM_EVENT_FILTER_FIELDS;

    if (strict) {
      for (auto it = j.begin(); it != j.end(); ++it) {
        if (allowed_fields.find(it.key()) == allowed_fields.end()) {
          vr.add_warning(path, "Unknown field: \"" + it.key() + "\"");
        }
      }
    }

    validate_string_array(j, FILTER_FIELD_TYPES, vr, path);
    validate_string_array(j, FILTER_FIELD_NOT_TYPES, vr, path);
    validate_string_array(j, FILTER_FIELD_SENDERS, vr, path);
    validate_string_array(j, FILTER_FIELD_NOT_SENDERS, vr, path);

    if (!compact) {
      validate_string_array(j, FILTER_FIELD_ROOMS, vr, path);
      validate_string_array(j, FILTER_FIELD_NOT_ROOMS, vr, path);

      if (j.contains(FILTER_FIELD_CONTAINS_URL) &&
          !j[FILTER_FIELD_CONTAINS_URL].is_boolean() &&
          !j[FILTER_FIELD_CONTAINS_URL].is_null()) {
        vr.add_error(join_path(path, FILTER_FIELD_CONTAINS_URL),
                     "contains_url must be a boolean");
      }
    }

    validate_integer(j, FILTER_FIELD_LIMIT, vr, path, 0, MAX_FILTER_LIMIT);
  }

  // ------------------------------------------------------------------------
  // Internal: validate a RoomFilter at a given path.
  // ------------------------------------------------------------------------
  static void validate_room_filter_internal(
      const json& j, FilterValidationResult& vr,
      const std::string& path, bool strict) {

    if (!j.is_object()) {
      vr.add_error(path, "Room filter must be a JSON object");
      return;
    }

    if (strict) {
      for (auto it = j.begin(); it != j.end(); ++it) {
        if (KNOWN_ROOM_FILTER_FIELDS.find(it.key()) ==
            KNOWN_ROOM_FILTER_FIELDS.end()) {
          vr.add_warning(path, "Unknown field: \"" + it.key() + "\"");
        }
      }
    }

    validate_string_array(j, FILTER_FIELD_ROOMS, vr, path);
    validate_string_array(j, FILTER_FIELD_NOT_ROOMS, vr, path);

    if (j.contains(FILTER_FIELD_ROOM_TIMELINE)) {
      validate_room_event_filter_internal(
          j[FILTER_FIELD_ROOM_TIMELINE], vr,
          join_path(path, FILTER_FIELD_ROOM_TIMELINE), strict, false);
    }

    if (j.contains(FILTER_FIELD_ROOM_STATE)) {
      auto state_result = validate_state_filter(
          j[FILTER_FIELD_ROOM_STATE], strict);
      for (auto& err : state_result.errors) {
        vr.add_error(join_path(path, err.path), err.message, err.code);
      }
      for (auto& w : state_result.warnings) {
        vr.add_warning(
            join_path(path, FILTER_FIELD_ROOM_STATE), w);
      }
    }

    if (j.contains(FILTER_FIELD_ROOM_EPHEMERAL)) {
      validate_room_event_filter_internal(
          j[FILTER_FIELD_ROOM_EPHEMERAL], vr,
          join_path(path, FILTER_FIELD_ROOM_EPHEMERAL), strict, true);
    }

    if (j.contains(FILTER_FIELD_ROOM_ACCOUNT_DATA)) {
      validate_room_event_filter_internal(
          j[FILTER_FIELD_ROOM_ACCOUNT_DATA], vr,
          join_path(path, FILTER_FIELD_ROOM_ACCOUNT_DATA), strict, true);
    }
  }

  // ------------------------------------------------------------------------
  // Helper: validate a string array field at a path.
  // ------------------------------------------------------------------------
  static void validate_string_array(const json& j, const std::string& field,
                                     FilterValidationResult& vr,
                                     const std::string& path) {
    if (!j.contains(field)) return;
    const auto& val = j[field];
    std::string full_path = join_path(path, field);

    if (val.is_null()) return;  // null is allowed (unbounded)

    if (!val.is_array()) {
      vr.add_error(full_path, "must be an array of strings or null, got " +
                   json_value_repr(val));
      return;
    }

    for (size_t i = 0; i < val.size(); ++i) {
      if (!val[i].is_string()) {
        vr.add_error(full_path + "[" + std::to_string(i) + "]",
                     "must be a string, got " + json_value_repr(val[i]));
      }
    }
  }

  // ------------------------------------------------------------------------
  // Helper: validate an integer field at a path, with optional min/max.
  // ------------------------------------------------------------------------
  static void validate_integer(const json& j, const std::string& field,
                                FilterValidationResult& vr,
                                const std::string& path,
                                int min_val = 0,
                                int max_val = MAX_FILTER_LIMIT) {
    if (!j.contains(field)) return;
    const auto& val = j[field];
    std::string full_path = join_path(path, field);

    if (val.is_null()) return;

    if (!val.is_number_integer()) {
      vr.add_error(full_path, "must be an integer, got " +
                   json_value_repr(val));
      return;
    }

    int int_val = val.get<int>();
    if (int_val < min_val) {
      vr.add_error(full_path, "must be >= " + std::to_string(min_val) +
                   ", got " + std::to_string(int_val));
    }
    if (int_val > max_val && max_val > 0) {
      vr.add_warning(full_path, "value " + std::to_string(int_val) +
                     " exceeds maximum " + std::to_string(max_val) +
                     ", will be capped");
    }
  }

  // ------------------------------------------------------------------------
  // Helper: join a base path and a field name with a dot separator.
  // ------------------------------------------------------------------------
  static std::string join_path(const std::string& base,
                                const std::string& field) {
    if (base.empty()) return field;
    return base + "." + field;
  }
};

// ============================================================================
// EventFilterEngine — the main engine that ties everything together.
//
// This is the primary entry point that exposes the full filtering pipeline:
//   1. JSON validation (via FilterValidator)
//   2. Parsing (via MatrixFilter::from_json, etc.)
//   3. Storage (via FilterStore)
//   4. Retrieval with caching (via FilterCache)
//   5. Application to events (via filter struct methods)
//
// All operations are thread-safe: the cache uses a shared_mutex and
// the store delegates to the database layer which is connection-safe.
// ============================================================================
class EventFilterEngine {
public:
  // ------------------------------------------------------------------------
  // Constructor — requires a database pool and initializes the store
  // and cache.
  // ------------------------------------------------------------------------
  explicit EventFilterEngine(DatabasePool& db)
      : store_(db), cache_() {
    filter_logger.info("EventFilterEngine initialized");
  }

  // ------------------------------------------------------------------------
  // ensure_tables — create filter tables on startup.
  // ------------------------------------------------------------------------
  void ensure_tables() {
    store_.ensure_tables();
  }

  // ------------------------------------------------------------------------
  // validate_filter_json — validate a filter JSON document against the
  // Matrix spec. Returns a structured result with errors and warnings.
  //
  // This is a pure validation pass — no parsing, no storage.
  // ------------------------------------------------------------------------
  FilterValidationResult validate_filter_json(const json& filter_json,
                                                bool strict = false) {
    return FilterValidator::validate_full(filter_json, strict);
  }

  // ------------------------------------------------------------------------
  // parse_filter_json — parse a filter JSON document into a MatrixFilter
  // struct. Validates along the way and returns any errors.
  //
  // Returns the parsed filter on success (even if warnings exist), or
  // std::nullopt on critical validation failure.
  // ------------------------------------------------------------------------
  std::optional<MatrixFilter> parse_filter_json(
      const json& filter_json,
      FilterValidationResult& vr,
      bool strict = false) {
    return MatrixFilter::from_json(filter_json, vr, "", strict);
  }

  // ------------------------------------------------------------------------
  // create_filter — validate, parse, and store a new filter for a user.
  //
  // Returns a JSON response suitable for the /filter API:
  //   - On success: {"filter_id": <id>}
  //   - On validation failure: {"errcode": "M_INVALID_PARAM", "error": "..."}
  // ------------------------------------------------------------------------
  json create_filter(const std::string& user_id, const json& filter_json) {
    // Step 1: Validate
    auto vr = validate_filter_json(filter_json, false);
    if (!vr.valid) {
      json error;
      error["errcode"] = "M_INVALID_PARAM";
      error["error"] = "Invalid filter JSON";
      json err_details = json::array();
      for (const auto& e : vr.errors) {
        err_details.push_back(e.to_json());
      }
      error["details"] = err_details;
      return error;
    }

    // Step 2: Parse
    FilterValidationResult parse_vr;
    auto parsed = parse_filter_json(filter_json, parse_vr, false);
    if (!parsed.has_value()) {
      json error;
      error["errcode"] = "M_INVALID_PARAM";
      error["error"] = "Failed to parse filter";
      return error;
    }

    // Step 3: Store
    int64_t filter_id = store_.create_filter(user_id, filter_json);

    // Step 4: Cache the parsed filter
    std::string fid_str = std::to_string(filter_id);
    cache_.put(user_id, fid_str, parsed.value());

    json response;
    response["filter_id"] = std::to_string(filter_id);
    return response;
  }

  // ------------------------------------------------------------------------
  // get_filter — retrieve a stored filter by user_id and filter_id.
  //
  // First checks the cache, then falls back to the database store.
  // Returns a pair of (parsed_filter, raw_json), or std::nullopt.
  // ------------------------------------------------------------------------
  struct FilterResult {
    MatrixFilter parsed;
    json raw_json;
  };

  std::optional<FilterResult> get_filter(const std::string& user_id,
                                           const std::string& filter_id) {
    // Try cache first
    auto cached = cache_.get(user_id, filter_id);
    if (cached.has_value()) {
      filter_logger.debug("Cache hit for filter " + filter_id +
                          " of user " + user_id);
      FilterResult result;
      result.parsed = cached.value();
      // We don't have raw_json in cache — caller may not need it
      return result;
    }

    // Fall back to DB
    filter_logger.debug("Cache miss for filter " + filter_id +
                        " of user " + user_id);

    int64_t fid = 0;
    try {
      fid = std::stoll(filter_id);
    } catch (...) {
      filter_logger.error("Invalid filter_id: " + filter_id);
      return std::nullopt;
    }

    auto raw = store_.get_filter(user_id, fid);
    if (!raw.has_value()) {
      filter_logger.warn("Filter " + filter_id + " not found for user " +
                         user_id);
      return std::nullopt;
    }

    // Parse the raw JSON
    FilterValidationResult vr;
    auto parsed = MatrixFilter::from_json(raw.value(), vr, "", false);
    if (!parsed.has_value()) {
      filter_logger.error("Failed to parse stored filter " + filter_id);
      return std::nullopt;
    }

    // Populate cache
    cache_.put(user_id, filter_id, parsed.value());

    FilterResult result;
    result.parsed = parsed.value();
    result.raw_json = raw.value();
    return result;
  }

  // ------------------------------------------------------------------------
  // get_filter_raw — retrieve only the raw JSON for a filter.
  // ------------------------------------------------------------------------
  std::optional<json> get_filter_raw(const std::string& user_id,
                                       const std::string& filter_id) {
    int64_t fid = 0;
    try {
      fid = std::stoll(filter_id);
    } catch (...) {
      return std::nullopt;
    }
    return store_.get_filter(user_id, fid);
  }

  // ------------------------------------------------------------------------
  // list_filters — get all filters for a user (with metadata).
  // ------------------------------------------------------------------------
  json list_filters(const std::string& user_id) {
    auto filters = store_.get_all_filters(user_id);
    json result = json::array();
    for (const auto& f : filters) {
      json entry;
      entry["filter_id"] = std::to_string(f.filter_id);
      entry["filter_json"] = f.filter_json;
      entry["created_ts"] = f.created_ts;
      entry["last_used_ts"] = f.last_used_ts;
      result.push_back(entry);
    }
    return result;
  }

  // ------------------------------------------------------------------------
  // delete_filter — delete a filter by user_id and filter_id.
  // Returns true if deleted, false if not found.
  // ------------------------------------------------------------------------
  bool delete_filter(const std::string& user_id,
                      const std::string& filter_id) {
    int64_t fid = 0;
    try {
      fid = std::stoll(filter_id);
    } catch (...) {
      return false;
    }
    bool deleted = store_.delete_filter(user_id, fid);
    if (deleted) {
      cache_.invalidate(user_id, filter_id);
    }
    return deleted;
  }

  // ------------------------------------------------------------------------
  // apply_filter_to_events — apply a full room event filter to a vector
  // of event JSON objects and return only the matching events.
  //
  // This is a post-query filter that applies all the filter criteria
  // (types, not_types, senders, not_senders, rooms, not_rooms,
  //  contains_url, limit) to an already-fetched event list.
  //
  // Parameters:
  //   - events:      vector of event JSON objects to filter
  //   - filter:      the RoomEventFilter to apply
  //   - room_id:     optional room_id override (if events lack room_id)
  //
  // Returns the filtered (and possibly truncated) event vector.
  // ------------------------------------------------------------------------
  std::vector<json> apply_room_event_filter(
      const std::vector<json>& events,
      const RoomEventFilter& filter,
      const std::string& room_id = "") {

    if (filter.is_empty()) {
      return filter.apply_limit(events);
    }

    std::vector<json> result;
    result.reserve(events.size());

    for (const auto& event : events) {
      std::string event_type;
      std::string sender;
      std::string rid = room_id;

      if (event.contains("type") && event["type"].is_string())
        event_type = event["type"].get<std::string>();
      if (event.contains("sender") && event["sender"].is_string())
        sender = event["sender"].get<std::string>();
      if (rid.empty() && event.contains("room_id") && event["room_id"].is_string())
        rid = event["room_id"].get<std::string>();

      if (filter.matches_event(event_type, sender, rid, event)) {
        result.push_back(event);
      }

      // Early exit if we've hit the limit
      if (filter.has_limit && static_cast<int>(result.size()) >= filter.limit) {
        break;
      }
    }

    return result;
  }

  // ------------------------------------------------------------------------
  // apply_state_filter — apply a state filter to a vector of state events.
  //
  // Additionally applies lazy-loading if enabled: only includes member
  // events for members who appear in the active_senders set.
  // ------------------------------------------------------------------------
  std::vector<json> apply_state_filter(
      const std::vector<json>& state_events,
      const StateFilter& filter,
      const std::unordered_set<std::string>& active_senders = {}) {

    if (filter.is_empty() && !filter.should_lazy_load_members()) {
      return filter.apply_limit(state_events);
    }

    std::vector<json> result;
    result.reserve(state_events.size());

    for (const auto& event : state_events) {
      std::string event_type;
      std::string sender;
      std::string state_key;

      if (event.contains("type") && event["type"].is_string())
        event_type = event["type"].get<std::string>();
      if (event.contains("sender") && event["sender"].is_string())
        sender = event["sender"].get<std::string>();
      if (event.contains("state_key") && event["state_key"].is_string())
        state_key = event["state_key"].get<std::string>();

      // Apply lazy-loading for member events
      if (filter.should_lazy_load_members() &&
          event_type == "m.room.member") {
        if (filter.is_member_event_filtered_out_by_lazy_loading(
                state_key, active_senders)) {
          continue;  // skip this member event
        }
      }

      if (filter.matches_state_event(event_type, sender, state_key)) {
        result.push_back(event);
      }

      // Check limit
      if (filter.has_limit && static_cast<int>(result.size()) >= filter.limit) {
        break;
      }
    }

    return result;
  }

  // ------------------------------------------------------------------------
  // apply_event_field_filter — strip event objects down to the requested
  // fields, reducing payload size.
  // ------------------------------------------------------------------------
  std::vector<json> apply_event_field_filter(
      const std::vector<json>& events,
      const EventFieldFilter& field_filter) {

    if (!field_filter.enabled) return events;

    std::vector<json> result;
    result.reserve(events.size());
    for (const auto& event : events) {
      result.push_back(field_filter.apply_to_event(event));
    }
    return result;
  }

  // ------------------------------------------------------------------------
  // collect_active_senders_from_timeline — extract the set of unique
  // sender user_ids from a vector of timeline events.
  //
  // Used by lazy-loading to determine which members to include.
  // ------------------------------------------------------------------------
  static std::unordered_set<std::string> collect_active_senders(
      const std::vector<json>& timeline_events) {
    std::unordered_set<std::string> senders;
    for (const auto& event : timeline_events) {
      if (event.contains("sender") && event["sender"].is_string()) {
        senders.insert(event["sender"].get<std::string>());
      }
    }
    return senders;
  }

  // ------------------------------------------------------------------------
  // build_sync_state_sql — generates SQL to fetch state events for a room
  // with filtering applied at the query level where possible.
  //
  // This optimizes by pushing filter predicates into the SQL query rather
  // than fetching all state events and filtering in memory. Returns the
  // SQL string (with $N placeholders) and the corresponding parameters.
  //
  // Only type/sender/not_type/not_sender filters can be pushed to SQL;
  // lazy-loading and redundant members are applied post-query.
  // ------------------------------------------------------------------------
  std::pair<std::string, SQLQueryParameters> build_state_query_sql(
      const std::string& room_id,
      const StateFilter& filter,
      const std::string& state_table = "current_state_events",
      const std::string& events_table = "events") {

    auto [where_clause, params] = filter.build_sql_where();

    std::string sql =
        "SELECT e.event_id, e.type AS event_type, e.sender, "
        "e.state_key, e.origin_server_ts, "
        "c.event_id AS curr_event_id, c.content "
        "FROM " + state_table + " AS c "
        "JOIN " + events_table + " AS e "
        "ON c.event_id = e.event_id "
        "WHERE c.room_id = $" + std::to_string(params.size() + 1);

    params.push_back(SQLParam{room_id});

    if (!where_clause.empty()) {
      sql += " AND " + where_clause.substr(6);  // strip leading "WHERE "
    }

    if (filter.has_limit) {
      sql += " LIMIT $" + std::to_string(params.size() + 1);
      params.push_back(SQLParam{static_cast<int64_t>(filter.limit)});
    }

    return {sql, params};
  }

  // ------------------------------------------------------------------------
  // build_timeline_query_sql — generates SQL to fetch timeline events
  // for a room with room event filtering pushed to the query level.
  //
  // Note: contains_url filtering cannot be pushed to SQL easily, so it
  // must be applied post-query. Similarly, the room/not_room filters are
  // applied at the room level, not per-event.
  // ------------------------------------------------------------------------
  std::pair<std::string, SQLQueryParameters> build_timeline_query_sql(
      const std::string& room_id,
      const RoomEventFilter& filter,
      int64_t from_token = 0,
      const std::string& events_table = "events") {

    auto [where_clause, params] = filter.build_sql_where();

    int next_param = static_cast<int>(params.size()) + 1;

    std::string sql =
        "SELECT event_id, type AS event_type, sender,"
        "room_id, origin_server_ts, content "
        "FROM " + events_table + " "
        "WHERE room_id = $" + std::to_string(next_param) + " "
        "AND stream_ordering > $" + std::to_string(next_param + 1);

    params.push_back(SQLParam{room_id});
    params.push_back(SQLParam{from_token});
    next_param += 2;

    if (!where_clause.empty()) {
      sql += " AND " + where_clause.substr(6);  // strip leading "WHERE "
    }

    sql += " ORDER BY stream_ordering ASC";

    if (filter.has_limit) {
      sql += " LIMIT $" + std::to_string(params.size() + 1);
      params.push_back(SQLParam{static_cast<int64_t>(filter.limit)});
    } else {
      sql += " LIMIT $" + std::to_string(params.size() + 1);
      params.push_back(SQLParam{static_cast<int64_t>(DEFAULT_ROOM_TIMELINE_LIMIT)});
    }

    return {sql, params};
  }

  // ------------------------------------------------------------------------
  // cache_stats — return cache statistics as JSON.
  // ------------------------------------------------------------------------
  json cache_stats() const {
    return cache_.stats();
  }

  // ------------------------------------------------------------------------
  // invalidate_cache — clear the filter cache for a specific filter
  // or all filters for a user.
  // ------------------------------------------------------------------------
  void invalidate_cache(const std::string& user_id,
                         const std::string& filter_id = "") {
    if (filter_id.empty()) {
      cache_.invalidate_user(user_id);
    } else {
      cache_.invalidate(user_id, filter_id);
    }
  }

  // ------------------------------------------------------------------------
  // get_store — access the underlying FilterStore for direct operations.
  // ------------------------------------------------------------------------
  FilterStore& get_store() { return store_; }

  // ------------------------------------------------------------------------
  // create_server_filter — create or update a server-default filter.
  // ------------------------------------------------------------------------
  void create_server_filter(const std::string& filter_id,
                            const json& filter_json,
                            const std::string& description = "") {
    store_.create_server_filter(filter_id, filter_json, description);
  }

  // ------------------------------------------------------------------------
  // get_server_filter — retrieve a server filter by ID.
  // ------------------------------------------------------------------------
  std::optional<json> get_server_filter(const std::string& filter_id) {
    return store_.get_server_filter(filter_id);
  }

  // ------------------------------------------------------------------------
  // log_filter_usage — record filter usage for analytics.
  // ------------------------------------------------------------------------
  void log_filter_usage(const std::string& user_id,
                         const std::string& filter_id,
                         const std::string& request_type,
                         int room_count, int event_count,
                         int64_t duration_us) {
    store_.log_filter_usage(user_id, filter_id, request_type,
                            room_count, event_count, duration_us);
  }

private:
  FilterStore store_;
  FilterCache cache_;
};

// ============================================================================
// Global engine instance (thread-safe singleton with lazy initialization)
//
// In a production server, this would typically be managed by the server's
// dependency injection/handler registry. For convenience, we provide a
// global accessor that creates the engine on first use.
// ============================================================================
namespace {

std::unique_ptr<EventFilterEngine> g_filter_engine;
std::once_flag g_filter_engine_init_flag;

}  // anonymous namespace

// ----------------------------------------------------------------------------
// get_filter_engine — returns the global EventFilterEngine instance.
// Must be called after the database pool is available.
// ----------------------------------------------------------------------------
EventFilterEngine& get_filter_engine(DatabasePool& db) {
  std::call_once(g_filter_engine_init_flag, [&db]() {
    g_filter_engine = std::make_unique<EventFilterEngine>(db);
    g_filter_engine->ensure_tables();
    filter_logger.info("Global EventFilterEngine initialized");
  });
  return *g_filter_engine;
}

// ----------------------------------------------------------------------------
// Convenience: validate a complete filter JSON (no database needed).
// ----------------------------------------------------------------------------
json validate_filter_json_api(const json& filter_json, bool strict = false) {
  auto vr = FilterValidator::validate_full(filter_json, strict);
  return vr.to_json();
}

// ----------------------------------------------------------------------------
// Convenience: create a filter for a user and return the API response.
// ----------------------------------------------------------------------------
json create_user_filter(DatabasePool& db,
                         const std::string& user_id,
                         const json& filter_json) {
  auto& engine = get_filter_engine(db);
  return engine.create_filter(user_id, filter_json);
}

// ----------------------------------------------------------------------------
// Convenience: get a user's filter by ID, returning parsed+raw.
// ----------------------------------------------------------------------------
std::optional<EventFilterEngine::FilterResult> get_user_filter(
    DatabasePool& db,
    const std::string& user_id,
    const std::string& filter_id) {
  auto& engine = get_filter_engine(db);
  return engine.get_filter(user_id, filter_id);
}

// ----------------------------------------------------------------------------
// Convenience: delete a user's filter by ID.
// ----------------------------------------------------------------------------
bool delete_user_filter(DatabasePool& db,
                         const std::string& user_id,
                         const std::string& filter_id) {
  auto& engine = get_filter_engine(db);
  return engine.delete_filter(user_id, filter_id);
}

// ----------------------------------------------------------------------------
// Convenience: list all filters for a user.
// ----------------------------------------------------------------------------
json list_user_filters(DatabasePool& db, const std::string& user_id) {
  auto& engine = get_filter_engine(db);
  return engine.list_filters(user_id);
}

// ----------------------------------------------------------------------------
// Convenience: apply room event filter to a batch of events.
// ----------------------------------------------------------------------------
std::vector<json> filter_events_with_room_filter(
    DatabasePool& db,
    const std::vector<json>& events,
    const RoomEventFilter& filter,
    const std::string& room_id = "") {
  auto& engine = get_filter_engine(db);

  int64_t start_us = now_ms() * 1000;  // ms -> us

  auto filtered = engine.apply_room_event_filter(events, filter, room_id);

  int64_t duration_us = (now_ms() * 1000) - start_us;

  // Could log usage here if we had user context
  (void)duration_us;

  return filtered;
}

// ----------------------------------------------------------------------------
// Convenience: apply state filter to a batch of state events with lazy loading.
// ----------------------------------------------------------------------------
std::vector<json> filter_state_events_with_filter(
    DatabasePool& db,
    const std::vector<json>& state_events,
    const StateFilter& filter,
    const std::unordered_set<std::string>& active_senders = {}) {
  auto& engine = get_filter_engine(db);
  return engine.apply_state_filter(state_events, filter, active_senders);
}

// ============================================================================
// Batch filter application — apply multiple filters at once for a sync
// response, processing timeline, state, and ephemeral events for many rooms
// in a single pass.
// ============================================================================
namespace batch_filter {

// ----------------------------------------------------------------------------
// RoomFilterBatchResult — the result of applying filters to one room's
// sync data.
// ----------------------------------------------------------------------------
struct RoomFilterBatchResult {
  std::string room_id;
  std::vector<json> timeline_events;
  std::vector<json> state_events;
  std::vector<json> ephemeral_events;
  std::vector<json> account_data_events;
  bool truncated_timeline = false;
  bool truncated_state = false;
};

// ----------------------------------------------------------------------------
// apply_room_filters_batch — apply filters to multiple rooms at once.
//
// For each room in the input, applies the corresponding room filter
// (from the MatrixFilter) to the room's timeline, state, ephemeral,
// and account_data events.
//
// This is the main filtering pass used during /sync response construction.
// ============================================================================
std::vector<RoomFilterBatchResult> apply_room_filters_batch(
    DatabasePool& db,
    const std::vector<std::tuple<std::string,
                                   std::vector<json>,
                                   std::vector<json>,
                                   std::vector<json>,
                                   std::vector<json>>>& room_data,
    const MatrixFilter& mfilter) {

  auto& engine = get_filter_engine(db);
  std::vector<RoomFilterBatchResult> results;
  results.reserve(room_data.size());

  for (const auto& [room_id, timeline, state, ephemeral, account_data] :
       room_data) {

    // Check if this room passes the room whitelist/blacklist
    if (!mfilter.room.room_included(room_id)) {
      continue;
    }

    RoomFilterBatchResult room_result;
    room_result.room_id = room_id;

    // Collect active senders from timeline for lazy-loading
    std::unordered_set<std::string> active_senders;
    if (mfilter.room.state.should_lazy_load_members()) {
      active_senders = EventFilterEngine::collect_active_senders(timeline);
    }

    // Apply timeline filter
    const auto& tl_filter = mfilter.room.timeline;
    room_result.timeline_events = engine.apply_room_event_filter(
        timeline, tl_filter, room_id);
    room_result.truncated_timeline =
        tl_filter.has_limit &&
        static_cast<int>(timeline.size()) > tl_filter.limit;

    // Apply state filter (with lazy-loading support)
    room_result.state_events = engine.apply_state_filter(
        state, mfilter.room.state, active_senders);
    room_result.truncated_state =
        mfilter.room.state.has_limit &&
        static_cast<int>(state.size()) > mfilter.room.state.limit;

    // Apply ephemeral filter
    room_result.ephemeral_events = engine.apply_room_event_filter(
        ephemeral, mfilter.room.ephemeral, room_id);

    // Apply account_data filter
    room_result.account_data_events = engine.apply_room_event_filter(
        account_data, mfilter.room.account_data, room_id);

    // Apply event field filtering to all event arrays
    if (mfilter.event_fields.enabled) {
      room_result.timeline_events = engine.apply_event_field_filter(
          room_result.timeline_events, mfilter.event_fields);
      room_result.state_events = engine.apply_event_field_filter(
          room_result.state_events, mfilter.event_fields);
      room_result.ephemeral_events = engine.apply_event_field_filter(
          room_result.ephemeral_events, mfilter.event_fields);
      room_result.account_data_events = engine.apply_event_field_filter(
          room_result.account_data_events, mfilter.event_fields);
    }

    results.push_back(room_result);
  }

  return results;
}

}  // namespace batch_filter

// ============================================================================
// Schema migration helper: applies DDL for filter tables.
// ============================================================================
void migrate_filter_tables(DatabasePool& db) {
  db.runInteraction("event_filter_engine.migrate",
      [](LoggingTransaction& txn) {
        storage_log.info("Running filter table migrations...");

        // Create user_filters table
        txn.execute(
            "CREATE TABLE IF NOT EXISTS user_filters ("
            "  user_id         TEXT        NOT NULL,"
            "  filter_id       BIGINT      NOT NULL,"
            "  filter_json     TEXT        NOT NULL,"
            "  created_ts      BIGINT      NOT NULL DEFAULT 0,"
            "  last_used_ts    BIGINT      NOT NULL DEFAULT 0,"
            "  CONSTRAINT user_filters_pk PRIMARY KEY (user_id, filter_id)"
            ")");

        // Add index for user filter listing
        txn.execute(
            "CREATE INDEX IF NOT EXISTS user_filters_user_idx "
            "ON user_filters (user_id, last_used_ts DESC)");

        // Add index for created timestamp
        txn.execute(
            "CREATE INDEX IF NOT EXISTS user_filters_created_idx "
            "ON user_filters (created_ts)");

        // Create server_filters table
        txn.execute(
            "CREATE TABLE IF NOT EXISTS server_filters ("
            "  filter_id       TEXT        NOT NULL PRIMARY KEY,"
            "  filter_json     TEXT        NOT NULL,"
            "  description     TEXT        NOT NULL DEFAULT '',"
            "  created_ts      BIGINT      NOT NULL DEFAULT 0,"
            "  updated_ts      BIGINT      NOT NULL DEFAULT 0"
            ")");

        // Create filter_usage_log table
        txn.execute(
            "CREATE TABLE IF NOT EXISTS filter_usage_log ("
            "  id              BIGINT      PRIMARY KEY AUTOINCREMENT,"
            "  user_id         TEXT        NOT NULL,"
            "  filter_id       TEXT        NOT NULL,"
            "  request_type    TEXT        NOT NULL,"
            "  used_ts         BIGINT      NOT NULL DEFAULT 0,"
            "  room_count      INTEGER     NOT NULL DEFAULT 0,"
            "  event_count     INTEGER     NOT NULL DEFAULT 0,"
            "  duration_us     BIGINT      NOT NULL DEFAULT 0"
            ")");

        txn.execute(
            "CREATE INDEX IF NOT EXISTS filter_usage_user_idx "
            "ON filter_usage_log (user_id, used_ts DESC)");

        txn.execute(
            "CREATE INDEX IF NOT EXISTS filter_usage_filter_idx "
            "ON filter_usage_log (filter_id, used_ts DESC)");

        // Insert default server filter for federation
        txn.execute(
            "INSERT OR IGNORE INTO server_filters "
            "(filter_id, filter_json, description, created_ts, updated_ts) "
            "VALUES ('server.default_federation', '{}', "
            "'Default federation filter (passthrough)', "
            "CAST(strftime('%s','now') AS INTEGER), "
            "CAST(strftime('%s','now') AS INTEGER))");

        storage_log.info("Filter table migrations completed.");
      });
}

// ============================================================================
// Admin API: get comprehensive filter statistics.
// ============================================================================
json get_filter_admin_stats(DatabasePool& db) {
  return db.runInteraction("event_filter_engine.admin_stats",
      [](LoggingTransaction& txn) -> json {
        json stats;

        // Count user filters
        txn.execute("SELECT COUNT(*) AS cnt FROM user_filters");
        auto row = txn.fetchone();
        if (row.has_value() && !row->empty() && (*row)[0].value.has_value()) {
          stats["total_user_filters"] =
              std::stoll((*row)[0].value.value());
        }

        // Count distinct users with filters
        txn.execute("SELECT COUNT(DISTINCT user_id) AS cnt FROM user_filters");
        row = txn.fetchone();
        if (row.has_value() && !row->empty() && (*row)[0].value.has_value()) {
          stats["users_with_filters"] =
              std::stoll((*row)[0].value.value());
        }

        // Count server filters
        txn.execute("SELECT COUNT(*) AS cnt FROM server_filters");
        row = txn.fetchone();
        if (row.has_value() && !row->empty() && (*row)[0].value.has_value()) {
          stats["total_server_filters"] =
              std::stoll((*row)[0].value.value());
        }

        // Count usage log entries
        txn.execute("SELECT COUNT(*) AS cnt FROM filter_usage_log");
        row = txn.fetchone();
        if (row.has_value() && !row->empty() && (*row)[0].value.has_value()) {
          stats["total_usage_log_entries"] =
              std::stoll((*row)[0].value.value());
        }

        // Average filter JSON size
        txn.execute(
            "SELECT AVG(LENGTH(filter_json)) AS avg_size FROM user_filters");
        row = txn.fetchone();
        if (row.has_value() && !row->empty() && (*row)[0].value.has_value()) {
          stats["avg_filter_json_bytes"] =
              static_cast<int>(std::stod((*row)[0].value.value()));
        }

        return stats;
      });
}

// ============================================================================
// Admin API: purge old filter usage log entries.
// ============================================================================
int64_t purge_filter_usage_log(DatabasePool& db, int64_t older_than_seconds) {
  return db.runInteraction("event_filter_engine.purge_usage",
      [&](LoggingTransaction& txn) -> int64_t {
        int64_t cutoff = now_sec() - older_than_seconds;
        txn.execute(
            "DELETE FROM filter_usage_log WHERE used_ts < $1",
            {SQLParam{cutoff}});
        return txn.rowcount();
      });
}

// ============================================================================
// Admin API: delete all filters for inactive users.
// ============================================================================
json cleanup_inactive_user_filters(DatabasePool& db,
                                     int64_t inactive_days = 90) {
  return db.runInteraction("event_filter_engine.cleanup_filters",
      [&](LoggingTransaction& txn) -> json {
        int64_t cutoff = now_sec() - (inactive_days * 86400);

        // Find users whose filters haven't been used recently
        txn.execute(
            "SELECT user_id, COUNT(*) AS filter_count "
            "FROM user_filters "
            "WHERE last_used_ts < $1 "
            "GROUP BY user_id",
            {SQLParam{cutoff}});

        json result;
        result["cutoff_timestamp"] = cutoff;
        result["cutoff_days"] = inactive_days;
        result["users_cleaned"] = json::array();

        Row row;
        while (txn.iter_next(row)) {
          if (row.size() >= 2 &&
              row[0].value.has_value() && row[1].value.has_value()) {
            std::string uid = row[0].value.value();
            int64_t count = std::stoll(row[1].value.value());

            txn.execute(
                "DELETE FROM user_filters WHERE user_id = $1",
                {SQLParam{uid}});

            json user_entry;
            user_entry["user_id"] = uid;
            user_entry["filters_deleted"] = count;
            result["users_cleaned"].push_back(user_entry);
          }
        }

        return result;
      });
}

}  // namespace progressive
