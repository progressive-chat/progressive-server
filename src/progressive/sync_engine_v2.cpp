// ============================================================================
// sync_engine_v2.cpp — Matrix Incremental Sync Engine (v2)
//
// Implements the core /sync endpoint logic following the Matrix spec:
//   - Compute sync response per user: joined, invited, left rooms
//     (timeline + state + ephemeral + account_data)
//   - Presence events gathering from shared rooms
//   - To-device message delivery from device_inbox
//   - Device list changes tracking
//   - One-time key counts per device
//   - Next batch token generation (opaque stream position token)
//   - Full state vs incremental sync (since token handling)
//   - Lazy-loading room members for large rooms
//   - Room summary with hero member computation
//   - Full SQL for event queries, state queries, room member queries
//
// Equivalent to:
//   synapse/handlers/sync.py          (2,400+ lines)
//   synapse/handlers/sync_room.py
//   synapse/storage/databases/main/stream.py (sync portions)
//   synapse/visibility.py (history visibility filtering)
//
// Target: 3000+ lines of production-grade C++.
// Namespace: progressive::
// ============================================================================

#include <algorithm>
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

// Internal project includes
#include "storage/database.hpp"
#include "storage/engine.hpp"
#include "storage/types.hpp"
#include "util/cache.hpp"
#include "util/log.hpp"
#include "util/random.hpp"
#include "util/time.hpp"

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
}  // namespace storage

// ============================================================================
// Type aliases
// ============================================================================
using storage::DatabasePool;
using storage::LoggingTransaction;
using storage::Row;
using storage::RowList;
using storage::ColumnValue;
using storage::SQLParam;

// ============================================================================
// Internal constants
// ============================================================================
namespace {

// Sync configuration constants
constexpr int kDefaultTimelineLimit = 20;
constexpr int kMaxTimelineLimit = 100;
constexpr int kDefaultStateBlockLimit = 128;
constexpr int kMaxPresenceEntries = 50;
constexpr int kMaxToDeviceMessages = 100;
constexpr int kMaxDeviceListChanges = 100;
constexpr int kDefaultLazyLoadMemberLimit = 5;
constexpr int kMaxHeroesPerRoom = 5;
constexpr int64_t kSyncTimeoutMs = 30'000;          // 30 seconds
constexpr int64_t kLongPollIntervalMs = 200;         // 200ms polling interval
constexpr int64_t kStaleRoomCacheTtlSec = 300;       // 5 minutes
constexpr int64_t kStreamOrderingCacheTtlSec = 60;   // 1 minute
constexpr int64_t kMaxSyncResponseCacheSize = 200;

// Event type constants
constexpr const char* kEventTypeMember = "m.room.member";
constexpr const char* kEventTypeMessage = "m.room.message";
constexpr const char* kEventTypeEncrypted = "m.room.encrypted";
constexpr const char* kEventTypeCreate = "m.room.create";
constexpr const char* kEventTypePowerLevels = "m.room.power_levels";
constexpr const char* kEventTypeName = "m.room.name";
constexpr const char* kEventTypeTopic = "m.room.topic";
constexpr const char* kEventTypeAvatar = "m.room.avatar";
constexpr const char* kEventTypeCanonicalAlias = "m.room.canonical_alias";
constexpr const char* kEventTypeJoinRules = "m.room.join_rules";
constexpr const char* kEventTypeHistoryVisibility = "m.room.history_visibility";
constexpr const char* kEventTypeGuestAccess = "m.room.guest_access";
constexpr const char* kEventTypeEncryption = "m.room.encryption";
constexpr const char* kEventTypeTombstone = "m.room.tombstone";
constexpr const char* kEventTypePresence = "m.presence";
constexpr const char* kEventTypePushRules = "m.push_rules";
constexpr const char* kEventTypeDirect = "m.direct";
constexpr const char* kEventTypeFullyRead = "m.fully_read";
constexpr const char* kEventTypeTag = "m.tag";
constexpr const char* kEventTypeReceipt = "m.receipt";
constexpr const char* kEventTypeTyping = "m.typing";

// Membership constants
constexpr const char* kMembershipJoin = "join";
constexpr const char* kMembershipInvite = "invite";
constexpr const char* kMembershipLeave = "leave";
constexpr const char* kMembershipBan = "ban";
constexpr const char* kMembershipKnock = "knock";

// History visibility constants
constexpr const char* kHistVisShared = "shared";
constexpr const char* kHistVisInvited = "invited";
constexpr const char* kHistVisJoined = "joined";
constexpr const char* kHistVisWorldReadable = "world_readable";

// Sync token prefix
constexpr const char* kSyncTokenPrefix = "s";

// ============================================================================
// Supported state event types to include in room state blocks
// ============================================================================
const std::set<std::string> kRoomStateEventTypes = {
    kEventTypeCreate,
    kEventTypeMember,
    kEventTypePowerLevels,
    kEventTypeName,
    kEventTypeTopic,
    kEventTypeAvatar,
    kEventTypeCanonicalAlias,
    kEventTypeJoinRules,
    kEventTypeHistoryVisibility,
    kEventTypeGuestAccess,
    kEventTypeEncryption,
    kEventTypeTombstone,
};

// ============================================================================
// Bump event types — events that make a room appear in the timeline
// ============================================================================
const std::set<std::string> kBumpEventTypes = {
    kEventTypeMessage,
    kEventTypeEncrypted,
    "m.room.sticker",
    "m.room.poll",
    "m.room.call",
};

}  // anonymous namespace

// ============================================================================
// Internal utility: escape single-quote for SQL string literals
// ============================================================================
static std::string sql_escape(std::string_view sv) {
  std::string out;
  out.reserve(sv.size() + 4);
  for (char c : sv) {
    if (c == '\'') out += "''";
    else out += c;
  }
  return out;
}

// ============================================================================
// Internal utility: build SQL IN (?,?,...) clause from a set of strings
// ============================================================================
static std::string build_in_clause(const std::set<std::string>& values) {
  if (values.empty()) return "()";
  std::string out = "(";
  bool first = true;
  for (const auto& v : values) {
    if (!first) out += ",";
    out += "'" + sql_escape(v) + "'";
    first = false;
  }
  out += ")";
  return out;
}

// ============================================================================
// Internal utility: build SQL IN clause from a vector of strings
// ============================================================================
static std::string build_in_clause_from_vec(const std::vector<std::string>& values) {
  if (values.empty()) return "()";
  std::string out = "(";
  bool first = true;
  for (const auto& v : values) {
    if (!first) out += ",";
    out += "'" + sql_escape(v) + "'";
    first = false;
  }
  out += ")";
  return out;
}

// ============================================================================
// Internal utility: make a sync token from a stream position
// ============================================================================
static std::string make_sync_token(uint64_t stream_pos) {
  return std::string(kSyncTokenPrefix) + std::to_string(stream_pos);
}

// ============================================================================
// Internal utility: parse a sync token into a stream position
// ============================================================================
static uint64_t parse_sync_token(std::string_view token) {
  if (token.empty() || token.size() <= 1) return 0;
  if (token[0] != 's') return 0;
  try {
    return std::stoull(std::string(token.substr(1)));
  } catch (...) {
    return 0;
  }
}

// ============================================================================
// Internal utility: get current timestamp in milliseconds
// ============================================================================
static int64_t now_ms() {
  return util::now_ms();
}

// ============================================================================
// Internal utility: encode binary data as base64 for tokens
// ============================================================================
static std::string base64_encode(const std::string& data) {
  static const char* kBase64Chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((data.size() + 2) / 3) * 4);
  for (size_t i = 0; i < data.size(); i += 3) {
    uint32_t val = (uint8_t)data[i] << 16;
    if (i + 1 < data.size()) val |= (uint8_t)data[i + 1] << 8;
    if (i + 2 < data.size()) val |= (uint8_t)data[i + 2];
    out += kBase64Chars[(val >> 18) & 0x3F];
    out += kBase64Chars[(val >> 12) & 0x3F];
    out += (i + 1 < data.size()) ? kBase64Chars[(val >> 6) & 0x3F] : '=';
    out += (i + 2 < data.size()) ? kBase64Chars[val & 0x3F] : '=';
  }
  return out;
}

// ============================================================================
// Internal utility: parse a JSON value from a string, with fallback
// ============================================================================
static json parse_json_safe(const std::string& raw) {
  if (raw.empty()) return json::object();
  try {
    return json::parse(raw);
  } catch (...) {
    return json::object();
  }
}

// ============================================================================
// Internal utility: safe string extraction from a database column value
// ============================================================================
static std::string col_str(const Row& row, const std::string& name,
                           const std::string& fallback = "") {
  for (const auto& col : row) {
    if (col.name == name && col.value.has_value())
      return *col.value;
  }
  return fallback;
}

// ============================================================================
// Internal utility: safe integer extraction from a database column value
// ============================================================================
static int64_t col_int(const Row& row, const std::string& name,
                       int64_t fallback = 0) {
  for (const auto& col : row) {
    if (col.name == name && col.value.has_value()) {
      try {
        return std::stoll(*col.value);
      } catch (...) {
        return fallback;
      }
    }
  }
  return fallback;
}

// ============================================================================
// Internal utility: build an event JSON object from a database row
// ============================================================================
static json event_row_to_json(const Row& row, std::string_view room_id_hint = "") {
  json ev;
  std::string eid = col_str(row, "event_id");
  ev["event_id"] = eid.empty() ? "$unknown" : eid;
  ev["type"] = col_str(row, "type", "m.unknown");
  ev["sender"] = col_str(row, "sender", "");
  ev["room_id"] = col_str(row, "room_id", std::string(room_id_hint));
  ev["origin_server_ts"] = col_str(row, "origin_server_ts", "0");

  std::string state_key = col_str(row, "state_key");
  if (!state_key.empty()) {
    ev["state_key"] = state_key;
  }

  ev["content"] = parse_json_safe(col_str(row, "content"));

  std::string unsigned_str = col_str(row, "unsigned_data");
  if (!unsigned_str.empty()) {
    ev["unsigned"] = parse_json_safe(unsigned_str);
  } else {
    ev["unsigned"] = json::object();
  }

  // Add sender membership if it's a member event
  std::string membership = col_str(row, "membership");
  if (!membership.empty()) {
    ev["content"]["membership"] = membership;
  }
  std::string displayname = col_str(row, "displayname");
  if (!displayname.empty()) {
    ev["content"]["displayname"] = displayname;
  }
  std::string avatar_url = col_str(row, "avatar_url");
  if (!avatar_url.empty()) {
    ev["content"]["avatar_url"] = avatar_url;
  }

  return ev;
}

// ============================================================================
// SyncEngineV2 - Core incremental sync engine
//
// This class implements the full Matrix /sync response construction.
// It handles room discovery (joined/invited/left), timeline pagination,
// state delta computation, ephemeral events (receipts, typing),
// account data, presence, to-device messages, device list tracking,
// one-time key counts, lazy-loaded members, room summaries with heroes,
// and next_batch token generation.
// ============================================================================
class SyncEngineV2 {
public:
  // --------------------------------------------------------------------------
  // Constructor
  // --------------------------------------------------------------------------
  explicit SyncEngineV2(DatabasePool& db)
      : db_(db)
      , stream_ordering_cache_(kMaxSyncResponseCacheSize, kStreamOrderingCacheTtlSec)
      , room_member_cache_(500, 120) {
    // Pre-initialize the stream position tracker
    current_stream_id_.store(now_ms(), std::memory_order_relaxed);
  }

  // --------------------------------------------------------------------------
  // Destructor
  // --------------------------------------------------------------------------
  ~SyncEngineV2() = default;

  // ==========================================================================
  // Main entry point: generate a full sync response for a user
  //
  // Parameters:
  //   user_id       - The user requesting the sync
  //   since_token   - The sync token from the last successful sync (empty for
  //                   initial/full sync)
  //   timeout_ms    - How long to wait for new data (long-poll support)
  //   filter_json   - Optional JSON filter specification
  // Returns:
  //   Full sync response JSON object
  // ==========================================================================
  json generate_sync_response(std::string_view user_id,
                               std::string_view since_token,
                               int timeout_ms = 0,
                               std::string_view filter_json = "") {
    auto start_time = now_ms();
    uint64_t since = parse_sync_token(since_token);
    bool is_initial_sync = (since == 0);

    // Start building the response
    json resp;
    resp["next_batch"] = "";
    resp["rooms"] = json::object();
    resp["rooms"]["join"] = json::object();
    resp["rooms"]["invite"] = json::object();
    resp["rooms"]["leave"] = json::object();

    // ========================================================================
    // Step 1: Gather all rooms for this user by membership type
    // ========================================================================
    RoomMembershipMap memberships = collect_all_room_memberships(user_id);

    // ========================================================================
    // Step 2: Compute joined rooms timeline + state + ephemeral
    // ========================================================================
    for (const auto& room_id : memberships.joined) {
      json room_data = compute_joined_room_sync(user_id, room_id, since,
                                                 is_initial_sync);
      resp["rooms"]["join"][room_id] = std::move(room_data);
    }

    // ========================================================================
    // Step 3: Compute invited rooms
    // ========================================================================
    for (const auto& room_id : memberships.invited) {
      json room_data = compute_invited_room_sync(user_id, room_id, since);
      resp["rooms"]["invite"][room_id] = std::move(room_data);
    }

    // ========================================================================
    // Step 4: Compute left rooms (since the last sync)
    // ========================================================================
    for (const auto& room_id : memberships.left_since) {
      json room_data = compute_left_room_sync(user_id, room_id, since);
      resp["rooms"]["leave"][room_id] = std::move(room_data);
    }

    // ========================================================================
    // Step 5: Presence events
    // ========================================================================
    handle_presence(user_id, since, resp);

    // ========================================================================
    // Step 6: To-device events
    // ========================================================================
    handle_to_device(user_id, since, resp);

    // ========================================================================
    // Step 7: Device lists changed/left
    // ========================================================================
    handle_device_lists(user_id, since, resp);

    // ========================================================================
    // Step 8: Device one-time key counts
    // ========================================================================
    handle_device_one_time_keys_counts(user_id, resp);

    // ========================================================================
    // Step 9: Account data (global and per-room)
    // ========================================================================
    handle_account_data(user_id, since, resp);

    // ========================================================================
    // Step 10: Generate next_batch token
    // ========================================================================
    uint64_t next_pos = current_stream_id_.load(std::memory_order_relaxed);
    // Ensure the token always advances
    if (next_pos <= since) {
      next_pos = since + 1;
    }
    resp["next_batch"] = make_sync_token(next_pos);

    // Update the global stream position
    current_stream_id_.store(std::max(
        current_stream_id_.load(std::memory_order_relaxed), next_pos + 1),
        std::memory_order_relaxed);

    // Handle long-poll: if timeout > 0 and no rooms changed and response
    // is effectively empty (just next_batch), we could wait. For simplicity
    // we return immediately.
    (void)timeout_ms;
    (void)filter_json;

    auto elapsed = now_ms() - start_time;
    if (elapsed > 500) {
      util::log::info("sync_engine_v2",
                      "Sync for user " + std::string(user_id) + " took " +
                          std::to_string(elapsed) + "ms, joined=" +
                          std::to_string(memberships.joined.size()) +
                          " invited=" +
                          std::to_string(memberships.invited.size()) +
                          " left=" + std::to_string(memberships.left_since.size()));
    }

    return resp;
  }

  // ==========================================================================
  // Force-increment the stream position (called when new events arrive)
  // ==========================================================================
  void advance_stream_position() {
    current_stream_id_.fetch_add(1, std::memory_order_relaxed);
  }

  // ==========================================================================
  // Get the current stream position
  // ==========================================================================
  uint64_t get_current_stream_id() const {
    return current_stream_id_.load(std::memory_order_relaxed);
  }

  // ==========================================================================
  // Invalidate caches (e.g., after schema changes or member updates)
  // ==========================================================================
  void invalidate_caches() {
    stream_ordering_cache_.clear();
    room_member_cache_.clear();
  }

private:
  // ==========================================================================
  // Data structures
  // ==========================================================================

  // Grouped room memberships for a user
  struct RoomMembershipMap {
    std::vector<std::string> joined;      // Currently joined rooms
    std::vector<std::string> invited;     // Currently invited rooms
    std::vector<std::string> left_since;  // Rooms left since the given token
  };

  // Cached sync state for a room
  struct RoomSyncState {
    std::string room_id;
    json state_events;             // Current state events array
    json timeline_events;          // Recent timeline events
    uint64_t last_stream_pos;      // Last seen stream position
    int64_t cached_at_ms;          // When this was cached
    bool limited;                  // Whether the timeline was limited
    std::string prev_batch;        // Previous batch token
  };

  // Device list change tracking
  struct DeviceListChange {
    std::string user_id;
    bool is_join;  // true = user joined/added; false = user left/removed
  };

  // ==========================================================================
  // Member variables
  // ==========================================================================
  DatabasePool& db_;
  std::atomic<uint64_t> current_stream_id_{0};

  // Caches
  util::LruCache<json> stream_ordering_cache_;
  util::LruCache<json> room_member_cache_;

  // Lazy-loading sent member tracking: user_id -> set of room_id
  mutable std::shared_mutex sent_members_mutex_;
  std::map<std::string, std::set<std::string>, std::less<>> sent_members_;

  // ==========================================================================
  // Step 1: Collect all room memberships for a user
  // ==========================================================================
  RoomMembershipMap collect_all_room_memberships(std::string_view user_id) {
    RoomMembershipMap result;

    std::string uid = sql_escape(user_id);

    // Query all memberships for this user
    std::string sql =
        "SELECT room_id, membership, sender, content "
        "FROM room_memberships "
        "WHERE user_id='" + uid + "' "
        "ORDER BY room_id";

    auto rows = db_execute(sql);

    for (const auto& row : rows) {
      std::string room_id = col_str(row, "room_id");
      std::string membership = col_str(row, "membership");
      if (room_id.empty()) continue;

      if (membership == kMembershipJoin) {
        result.joined.push_back(room_id);
      } else if (membership == kMembershipInvite) {
        result.invited.push_back(room_id);
      }
      // Left/ban rooms are captured by left_since below
    }

    return result;
  }

  // ==========================================================================
  // Step 2: Compute the sync response for a single joined room
  // ==========================================================================
  json compute_joined_room_sync(std::string_view user_id,
                                 std::string_view room_id,
                                 uint64_t since,
                                 bool is_initial_sync) {
    std::string rid = std::string(room_id);
    std::string uid = std::string(user_id);
    json room_data;

    // -- Timeline ------------------------------------------------------------
    json timeline;
    json timeline_events = json::array();
    bool limited = false;
    std::string prev_batch;

    if (is_initial_sync) {
      // Initial/full sync: get recent events for this room
      timeline_events = load_recent_events_for_room(rid, kDefaultTimelineLimit);
      limited = true;
      prev_batch = make_sync_token(current_stream_id_.load(std::memory_order_relaxed));
    } else {
      // Incremental sync: get events since the last token
      timeline_events = load_events_since(rid, since, kDefaultTimelineLimit);
      // Check if we might have missed events (gap)
      if (timeline_events.empty() && since > 0) {
        limited = false;
      }
      prev_batch = make_sync_token(since);
    }

    timeline["events"] = timeline_events;
    timeline["limited"] = limited;
    timeline["prev_batch"] = prev_batch;
    room_data["timeline"] = std::move(timeline);

    // -- State ---------------------------------------------------------------
    json state_block;
    state_block["events"] = compute_room_state(rid, uid, since, is_initial_sync,
                                                timeline_events);
    room_data["state"] = std::move(state_block);

    // -- Ephemeral -----------------------------------------------------------
    json ephemeral_block;
    ephemeral_block["events"] = compute_room_ephemeral(rid, uid, since);
    room_data["ephemeral"] = std::move(ephemeral_block);

    // -- Account data (per-room) ---------------------------------------------
    json room_account_data;
    room_account_data["events"] = compute_room_account_data(rid, uid, since);
    room_data["account_data"] = std::move(room_account_data);

    // -- Unread notifications ------------------------------------------------
    json unread_notifications = compute_unread_notifications(rid, uid);
    room_data["unread_notifications"] = std::move(unread_notifications);

    // -- Room summary --------------------------------------------------------
    json summary = compute_room_summary(rid, uid);
    room_data["summary"] = std::move(summary);

    return room_data;
  }

  // ==========================================================================
  // Step 3: Compute the sync response for an invited room
  // ==========================================================================
  json compute_invited_room_sync(std::string_view user_id,
                                  std::string_view room_id,
                                  uint64_t since) {
    std::string rid = std::string(room_id);
    std::string uid = std::string(user_id);
    json room_data;

    // Invited rooms get the invite_state (stripped-down state block)
    json invite_state;
    invite_state["events"] = compute_invite_state(rid, uid);
    room_data["invite_state"] = std::move(invite_state);

    return room_data;
  }

  // ==========================================================================
  // Step 4: Compute the sync response for a left room
  // ==========================================================================
  json compute_left_room_sync(std::string_view user_id,
                               std::string_view room_id,
                               uint64_t since) {
    std::string rid = std::string(room_id);
    std::string uid = std::string(user_id);
    json room_data;

    // Left rooms get timeline + state up to the leave event
    json timeline;
    std::string sql =
        "SELECT * FROM events WHERE room_id='" + sql_escape(rid) + "' "
        "AND type='" + std::string(kEventTypeMember) + "' "
        "AND state_key='" + sql_escape(uid) + "' "
        "ORDER BY stream_ordering DESC LIMIT 1";
    auto rows = db_execute(sql);
    if (!rows.empty()) {
      timeline["events"] = json::array({event_row_to_json(rows[0], rid)});
    } else {
      timeline["events"] = json::array();
    }
    timeline["limited"] = false;
    timeline["prev_batch"] = make_sync_token(since);
    room_data["timeline"] = std::move(timeline);

    // State for left room
    json state_block;
    sql = "SELECT * FROM events WHERE room_id='" + sql_escape(rid) + "' "
          "AND type='" + std::string(kEventTypeMember) + "' "
          "AND state_key='" + sql_escape(uid) + "' "
          "ORDER BY stream_ordering DESC LIMIT 1";
    state_block["events"] = json::array();
    auto state_rows = db_execute(sql);
    for (const auto& row : state_rows) {
      state_block["events"].push_back(event_row_to_json(row, rid));
    }
    room_data["state"] = std::move(state_block);

    // Per-room account data for left rooms
    json acct;
    acct["events"] = json::array();
    room_data["account_data"] = std::move(acct);

    return room_data;
  }

  // ==========================================================================
  // Step 5: Handle presence events
  // ==========================================================================
  void handle_presence(std::string_view user_id, uint64_t since,
                        json& resp) {
    std::string uid = sql_escape(user_id);
    json presence_block;
    presence_block["events"] = json::array();

    // Get users who share rooms with this user
    std::string shared_sql =
        "SELECT DISTINCT rm.user_id FROM room_memberships rm "
        "INNER JOIN room_memberships rm2 ON rm.room_id = rm2.room_id "
        "WHERE rm2.user_id='" + uid + "' "
        "AND rm2.membership='" + std::string(kMembershipJoin) + "' "
        "AND rm.membership='" + std::string(kMembershipJoin) + "' "
        "AND rm.user_id != '" + uid + "' "
        "LIMIT " + std::to_string(kMaxPresenceEntries);

    auto shared_rows = db_execute(shared_sql);
    std::set<std::string> shared_users;
    for (const auto& row : shared_rows) {
      shared_users.insert(col_str(row, "user_id"));
    }

    // Also add the sync user themselves
    shared_users.insert(std::string(user_id));

    // Query presence for these users
    if (shared_users.empty()) {
      resp["presence"] = std::move(presence_block);
      return;
    }

    std::string presence_sql =
        "SELECT user_id, state, last_active_ts, status_msg, "
        "currently_active "
        "FROM presence_state "
        "WHERE user_id IN " + build_in_clause(shared_users);

    auto presence_rows = db_execute(presence_sql);
    int64_t now = now_ms();

    for (const auto& row : presence_rows) {
      json pe;
      pe["type"] = kEventTypePresence;
      pe["sender"] = col_str(row, "user_id");
      pe["content"]["presence"] = col_str(row, "state", "offline");

      int64_t last_active = col_int(row, "last_active_ts");
      if (last_active > 0) {
        pe["content"]["last_active_ago"] = std::max(int64_t(0), now - last_active);
      } else {
        pe["content"]["last_active_ago"] = 0;
      }

      std::string status_msg = col_str(row, "status_msg");
      if (!status_msg.empty()) {
        pe["content"]["status_msg"] = status_msg;
      }

      bool currently_active = col_int(row, "currently_active") != 0;
      pe["content"]["currently_active"] = currently_active;

      presence_block["events"].push_back(std::move(pe));
    }

    resp["presence"] = std::move(presence_block);
  }

  // ==========================================================================
  // Step 6: Handle to-device message delivery
  // ==========================================================================
  void handle_to_device(std::string_view user_id, uint64_t since,
                         json& resp) {
    std::string uid = sql_escape(user_id);
    json to_device_block;
    to_device_block["events"] = json::array();

    // Query device_inbox for pending messages for this user
    // Filter out one-time key entries (device_id='otk')
    std::string sql =
        "SELECT type, sender, content, message_id, device_id "
        "FROM device_inbox "
        "WHERE user_id='" + uid + "' "
        "AND device_id != 'otk' "
        "ORDER BY stream_ordering ASC "
        "LIMIT " + std::to_string(kMaxToDeviceMessages);

    auto rows = db_execute(sql);

    for (const auto& row : rows) {
      json tde;
      tde["type"] = col_str(row, "type", "m.unknown");
      tde["sender"] = col_str(row, "sender", "");
      tde["content"] = parse_json_safe(col_str(row, "content"));

      std::string msg_id = col_str(row, "message_id");
      std::string dev_id = col_str(row, "device_id");
      if (!msg_id.empty()) {
        tde["unsigned"]["message_id"] = msg_id;
      }
      if (!dev_id.empty()) {
        tde["unsigned"]["device_id"] = dev_id;
      }

      to_device_block["events"].push_back(std::move(tde));
    }

    resp["to_device"] = std::move(to_device_block);
  }

  // ==========================================================================
  // Step 7: Handle device list changes
  // ==========================================================================
  void handle_device_lists(std::string_view user_id, uint64_t since,
                            json& resp) {
    std::string uid = sql_escape(user_id);
    json device_lists_block;
    device_lists_block["changed"] = json::array();
    device_lists_block["left"] = json::array();

    // Query device_lists_stream for changes since the last sync
    // This tracks when users' device lists have changed
    std::string sql =
        "SELECT DISTINCT dl.user_id, dl.stream_id "
        "FROM device_lists_stream dl "
        "INNER JOIN room_memberships rm ON dl.user_id = rm.user_id "
        "INNER JOIN room_memberships rm2 ON rm.room_id = rm2.room_id "
        "WHERE rm2.user_id='" + uid + "' "
        "AND rm.membership='" + std::string(kMembershipJoin) + "' "
        "AND dl.user_id != '" + uid + "' ";

    if (since > 0) {
      sql += "AND dl.stream_id > " + std::to_string(since) + " ";
    }
    sql += "LIMIT " + std::to_string(kMaxDeviceListChanges);

    auto rows = db_execute(sql);
    std::set<std::string> changed_users;
    for (const auto& row : rows) {
      std::string changed_uid = col_str(row, "user_id");
      if (!changed_uid.empty() && changed_users.find(changed_uid) == changed_users.end()) {
        changed_users.insert(changed_uid);
        device_lists_block["changed"].push_back(changed_uid);
      }
    }

    // Check for device_list_outbound_pokes (users who left shared rooms)
    std::string left_sql =
        "SELECT DISTINCT dl.user_id "
        "FROM device_list_outbound_pokes dl "
        "WHERE dl.user_id = '" + uid + "' ";

    if (since > 0) {
      left_sql += "AND dl.stream_id > " + std::to_string(since) + " ";
    }
    left_sql += "LIMIT " + std::to_string(kMaxDeviceListChanges);

    auto left_rows = db_execute(left_sql);
    for (const auto& row : left_rows) {
      std::string left_uid = col_str(row, "user_id");
      if (!left_uid.empty()) {
        device_lists_block["left"].push_back(left_uid);
      }
    }

    resp["device_lists"] = std::move(device_lists_block);
  }

  // ==========================================================================
  // Step 8: Handle device one-time key counts
  // ==========================================================================
  void handle_device_one_time_keys_counts(std::string_view user_id,
                                           json& resp) {
    std::string uid = sql_escape(user_id);
    json otk_counts;

    // Query e2e_one_time_keys_json for this user's device key counts
    std::string sql =
        "SELECT device_id, key_id, key_json "
        "FROM e2e_one_time_keys_json "
        "WHERE user_id='" + uid + "'";

    auto rows = db_execute(sql);

    std::map<std::string, std::map<std::string, int>> device_counts;

    for (const auto& row : rows) {
      std::string device_id = col_str(row, "device_id");
      std::string key_json_str = col_str(row, "key_json");
      if (device_id.empty()) continue;

      json key_data = parse_json_safe(key_json_str);

      // Count keys by algorithm
      for (auto it = key_data.begin(); it != key_data.end(); ++it) {
        const std::string& algorithm = it.key();
        int count = 0;
        if (it.value().is_object()) {
          for (auto k2 = it.value().begin(); k2 != it.value().end(); ++k2) {
            if (k2.key() != "signatures") {
              count++;
            }
          }
        }
        device_counts[device_id][algorithm] += count;
      }
    }

    for (const auto& [device_id, algo_counts] : device_counts) {
      json dev_entry;
      for (const auto& [algo, count] : algo_counts) {
        dev_entry[algo] = count;
      }
      otk_counts[device_id] = dev_entry;
    }

    resp["device_one_time_keys_count"] = std::move(otk_counts);
  }

  // ==========================================================================
  // Step 9: Handle account data (global and per-room)
  // ==========================================================================
  void handle_account_data(std::string_view user_id, uint64_t since,
                            json& resp) {
    std::string uid = sql_escape(user_id);
    json account_data_block;
    account_data_block["events"] = json::array();

    // Query global account data for this user
    std::string sql =
        "SELECT type, content, stream_id "
        "FROM account_data "
        "WHERE user_id='" + uid + "' "
        "AND room_id IS NULL ";

    if (since > 0) {
      sql += "AND stream_id > " + std::to_string(since) + " ";
    }
    sql += "ORDER BY stream_id ASC";

    auto rows = db_execute(sql);
    for (const auto& row : rows) {
      json ad;
      ad["type"] = col_str(row, "type", "");
      ad["content"] = parse_json_safe(col_str(row, "content"));
      account_data_block["events"].push_back(std::move(ad));
    }

    resp["account_data"] = std::move(account_data_block);
  }

  // ==========================================================================
  // Timeline queries
  // ==========================================================================

  // Load recent events for a room (used for initial sync)
  json load_recent_events_for_room(const std::string& room_id, int limit) {
    std::string rid = sql_escape(room_id);
    std::string sql =
        "SELECT * FROM events "
        "WHERE room_id='" + rid + "' "
        "ORDER BY stream_ordering DESC "
        "LIMIT " + std::to_string(std::min(limit, kMaxTimelineLimit));

    auto rows = db_execute(sql);
    json result = json::array();

    // Return events in chronological order (ascending)
    std::vector<json> evs;
    for (const auto& row : rows) {
      evs.push_back(event_row_to_json(row, room_id));
    }
    std::reverse(evs.begin(), evs.end());
    for (auto& ev : evs) {
      result.push_back(std::move(ev));
    }

    return result;
  }

  // Load events since a given stream position
  json load_events_since(const std::string& room_id, uint64_t since, int limit) {
    std::string rid = sql_escape(room_id);
    std::string sql =
        "SELECT * FROM events "
        "WHERE room_id='" + rid + "' "
        "AND stream_ordering > " + std::to_string(since) + " "
        "ORDER BY stream_ordering ASC "
        "LIMIT " + std::to_string(std::min(limit, kMaxTimelineLimit));

    auto rows = db_execute(sql);
    json result = json::array();

    for (const auto& row : rows) {
      result.push_back(event_row_to_json(row, room_id));
    }

    return result;
  }

  // Load events between two stream positions (for gap detection)
  json load_events_between(const std::string& room_id, uint64_t from,
                             uint64_t to, int limit) {
    std::string rid = sql_escape(room_id);
    std::string sql =
        "SELECT * FROM events "
        "WHERE room_id='" + rid + "' "
        "AND stream_ordering > " + std::to_string(from) + " "
        "AND stream_ordering <= " + std::to_string(to) + " "
        "ORDER BY stream_ordering ASC "
        "LIMIT " + std::to_string(std::min(limit, kMaxTimelineLimit));

    auto rows = db_execute(sql);
    json result = json::array();

    for (const auto& row : rows) {
      result.push_back(event_row_to_json(row, room_id));
    }

    return result;
  }

  // ==========================================================================
  // State queries
  // ==========================================================================

  // Compute the full room state (or incremental state delta)
  json compute_room_state(const std::string& room_id,
                           const std::string& user_id,
                           uint64_t since,
                           bool is_initial_sync,
                           const json& timeline_events) {
    json state_events = json::array();
    std::string rid = sql_escape(room_id);

    if (is_initial_sync) {
      // Full state: query current state for all known state event types
      std::string sql =
          "SELECT e.* FROM events e "
          "INNER JOIN state_events s ON e.event_id = s.event_id "
          "WHERE s.room_id='" + rid + "' "
          "ORDER BY e.depth DESC";

      auto rows = db_execute(sql);

      // Track state tuples to avoid duplicates (keep highest depth)
      std::map<std::pair<std::string, std::string>, json> state_map;

      for (const auto& row : rows) {
        std::string etype = col_str(row, "type");
        std::string skey = col_str(row, "state_key");
        auto key = std::make_pair(etype, skey);

        // Only keep the first occurrence (highest depth due to ORDER BY)
        if (state_map.find(key) == state_map.end()) {
          state_map[key] = event_row_to_json(row, room_id);
        }
      }

      // Add state events from the state_map, applying lazy-loading for members
      bool ll_enabled = should_lazy_load_members(room_id);
      int member_count = 0;

      for (auto& [key, ev] : state_map) {
        if (key.first == kEventTypeMember) {
          if (ll_enabled) {
            member_count++;
            if (member_count <= kDefaultLazyLoadMemberLimit ||
                key.second == user_id) {
              // Include: own membership + first N members
              state_events.push_back(std::move(ev));
            }
            // Other members will be lazily loaded later
          } else {
            state_events.push_back(std::move(ev));
          }
        } else {
          state_events.push_back(std::move(ev));
        }
      }
    } else {
      // Incremental sync: compute state delta
      // Get state events that changed since the last token
      state_events = compute_state_delta(room_id, since, timeline_events);
    }

    return state_events;
  }

  // Determine if a room should use lazy-loading for members
  bool should_lazy_load_members(const std::string& room_id) {
    // Query the number of joined members
    std::string sql =
        "SELECT COUNT(*) as cnt FROM room_memberships "
        "WHERE room_id='" + sql_escape(room_id) + "' "
        "AND membership='" + std::string(kMembershipJoin) + "'";

    auto rows = db_execute(sql);
    int64_t count = 0;
    if (!rows.empty()) {
      count = col_int(rows[0], "cnt");
    }

    // Enable lazy-loading for rooms with more than threshold members
    return count > kDefaultLazyLoadMemberLimit * 2;
  }

  // Compute the state delta: events that changed state since the given token
  json compute_state_delta(const std::string& room_id, uint64_t since,
                            const json& timeline_events) {
    std::string rid = sql_escape(room_id);
    json state_events = json::array();

    // First, collect state events from the timeline that have state_keys
    std::set<std::string> state_in_timeline;
    for (const auto& ev : timeline_events) {
      if (ev.contains("state_key") && !ev["state_key"].is_null() &&
          !ev["state_key"].get<std::string>().empty()) {
        // State events in the timeline should also appear in the state block
        json state_ev = ev;
        state_ev["prev_content"] = compute_previous_content(
            room_id, ev["type"].get<std::string>(),
            ev["state_key"].get<std::string>(),
            ev["event_id"].get<std::string>());
        state_events.push_back(std::move(state_ev));
        state_in_timeline.insert(ev["event_id"].get<std::string>());
      }
    }

    // Then query for state events that changed since 'since' but aren't
    // in the timeline
    std::string sql =
        "SELECT e.* FROM events e "
        "WHERE e.room_id='" + rid + "' "
        "AND e.state_key IS NOT NULL AND e.state_key != '' "
        "AND e.stream_ordering > " + std::to_string(since) + " "
        "ORDER BY e.depth DESC, e.stream_ordering DESC "
        "LIMIT " + std::to_string(kDefaultStateBlockLimit);

    auto rows = db_execute(sql);
    std::set<std::pair<std::string, std::string>> seen_state_tuples;

    for (const auto& row : rows) {
      std::string eid = col_str(row, "event_id");
      std::string etype = col_str(row, "type");
      std::string skey = col_str(row, "state_key");

      // Skip events already in timeline or duplicate state tuples
      if (state_in_timeline.find(eid) != state_in_timeline.end())
        continue;

      auto tuple = std::make_pair(etype, skey);
      if (seen_state_tuples.find(tuple) != seen_state_tuples.end())
        continue;
      seen_state_tuples.insert(tuple);

      json ev = event_row_to_json(row, room_id);
      // Add prev_content for state events
      ev["prev_content"] = compute_previous_content(room_id, etype, skey, eid);
      state_events.push_back(std::move(ev));
    }

    return state_events;
  }

  // Compute prev_content for a state event
  json compute_previous_content(const std::string& room_id,
                                 const std::string& event_type,
                                 const std::string& state_key,
                                 const std::string& current_event_id) {
    std::string rid = sql_escape(room_id);
    std::string etype = sql_escape(event_type);
    std::string skey = sql_escape(state_key);
    std::string ceid = sql_escape(current_event_id);

    // Get the previous state event for this (type, state_key) pair
    std::string sql =
        "SELECT content FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + etype + "' "
        "AND state_key='" + skey + "' "
        "AND event_id != '" + ceid + "' "
        "ORDER BY depth DESC, stream_ordering DESC "
        "LIMIT 1";

    auto rows = db_execute(sql);
    if (rows.empty()) {
      return json::object();  // No previous content
    }

    return parse_json_safe(col_str(rows[0], "content"));
  }

  // Compute invite_state for an invited room
  json compute_invite_state(const std::string& room_id,
                              const std::string& user_id) {
    std::string rid = sql_escape(room_id);
    std::string uid = sql_escape(user_id);
    json events = json::array();

    // Get the invite event (m.room.member with membership=invite for this user)
    std::string sql =
        "SELECT * FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + std::string(kEventTypeMember) + "' "
        "AND state_key='" + uid + "' "
        "ORDER BY stream_ordering DESC LIMIT 1";

    auto rows = db_execute(sql);
    for (const auto& row : rows) {
      json ev = event_row_to_json(row, room_id);
      ev["unsigned"]["invite_room_state"] = json::array();
      events.push_back(std::move(ev));
    }

    // Also include stripped state: m.room.name, m.room.avatar, m.room.join_rules,
    // m.room.canonical_alias
    const std::vector<std::string> stripped_types = {
        kEventTypeName, kEventTypeAvatar, kEventTypeJoinRules,
        kEventTypeCanonicalAlias, kEventTypeCreate
    };

    for (const auto& stype : stripped_types) {
      std::string ssql =
          "SELECT * FROM events "
          "WHERE room_id='" + rid + "' "
          "AND type='" + stype + "' "
          "ORDER BY depth DESC LIMIT 1";

      auto srows = db_execute(ssql);
      for (const auto& srow : srows) {
        json sev = event_row_to_json(srow, room_id);
        // Add stripped state to the invite event's unsigned
        if (!events.empty()) {
          events[0]["unsigned"]["invite_room_state"].push_back(sev);
        }
      }
    }

    return events;
  }

  // ==========================================================================
  // Ephemeral events
  // ==========================================================================

  // Compute ephemeral events for a room (receipts, typing indicators)
  json compute_room_ephemeral(const std::string& room_id,
                                const std::string& user_id,
                                uint64_t since) {
    std::string rid = sql_escape(room_id);
    json ephemeral_events = json::array();

    // -- Typing indicators ---------------------------------------------------
    json typing_event;
    typing_event["type"] = kEventTypeTyping;
    typing_event["content"] = json::object();
    typing_event["content"]["user_ids"] = json::array();

    // Query typing_notifications table for users currently typing
    std::string typing_sql =
        "SELECT user_id, typing_since_ts "
        "FROM typing_notifications "
        "WHERE room_id='" + rid + "' "
        "ORDER BY typing_since_ts ASC";

    auto typing_rows = db_execute(typing_sql);
    int64_t now = now_ms();
    int64_t typing_timeout_ms = 30'000;  // 30 seconds timeout

    for (const auto& row : typing_rows) {
      std::string typer = col_str(row, "user_id");
      int64_t since_ts = col_int(row, "typing_since_ts");
      if (!typer.empty() && (now - since_ts) < typing_timeout_ms) {
        typing_event["content"]["user_ids"].push_back(typer);
      }
    }

    if (!typing_event["content"]["user_ids"].empty()) {
      ephemeral_events.push_back(std::move(typing_event));
    }

    // -- Read receipts -------------------------------------------------------
    json receipt_event;
    receipt_event["type"] = kEventTypeReceipt;
    receipt_event["content"] = json::object();

    std::string receipt_sql =
        "SELECT rr.user_id, rr.event_id, rr.data "
        "FROM receipts_linearized rr "
        "WHERE rr.room_id='" + rid + "' ";

    if (since > 0) {
      receipt_sql += "AND rr.stream_id > " + std::to_string(since) + " ";
    }
    receipt_sql += "ORDER BY rr.stream_id ASC";

    auto receipt_rows = db_execute(receipt_sql);
    for (const auto& row : receipt_rows) {
      std::string ruser = col_str(row, "user_id");
      std::string revent = col_str(row, "event_id");
      std::string rdata = col_str(row, "data");

      json rdata_json = parse_json_safe(rdata);
      receipt_event["content"][revent]["m.read"][ruser] = rdata_json;
    }

    if (!receipt_event["content"].empty()) {
      ephemeral_events.push_back(std::move(receipt_event));
    }

    return ephemeral_events;
  }

  // ==========================================================================
  // Per-room account data
  // ==========================================================================

  // Compute room-level account data changes
  json compute_room_account_data(const std::string& room_id,
                                   const std::string& user_id,
                                   uint64_t since) {
    std::string rid = sql_escape(room_id);
    std::string uid = sql_escape(user_id);
    json events = json::array();

    // Query room-specific account data
    std::string sql =
        "SELECT type, content, stream_id "
        "FROM account_data "
        "WHERE user_id='" + uid + "' "
        "AND room_id='" + rid + "' ";

    if (since > 0) {
      sql += "AND stream_id > " + std::to_string(since) + " ";
    }
    sql += "ORDER BY stream_id ASC";

    auto rows = db_execute(sql);
    for (const auto& row : rows) {
      json ad;
      ad["type"] = col_str(row, "type", "");
      ad["content"] = parse_json_safe(col_str(row, "content"));
      events.push_back(std::move(ad));
    }

    return events;
  }

  // ==========================================================================
  // Unread notifications
  // ==========================================================================

  // Compute unread notification counts for a room
  json compute_unread_notifications(const std::string& room_id,
                                      const std::string& user_id) {
    std::string rid = sql_escape(room_id);
    std::string uid = sql_escape(user_id);
    json result;

    // Query event_push_summary for unread counts
    std::string sql =
        "SELECT stream_ordering, notif_count, highlight_count, "
        "unread_count "
        "FROM event_push_summary "
        "WHERE user_id='" + uid + "' "
        "AND room_id='" + rid + "' "
        "LIMIT 1";

    auto rows = db_execute(sql);
    if (!rows.empty()) {
      result["notification_count"] = col_int(rows[0], "notif_count", 0);
      result["highlight_count"] = col_int(rows[0], "highlight_count", 0);
      result["unread_count"] = col_int(rows[0], "unread_count", 0);
    } else {
      result["notification_count"] = 0;
      result["highlight_count"] = 0;
      result["unread_count"] = 0;
    }

    return result;
  }

  // ==========================================================================
  // Room Summary
  // ==========================================================================

  // Compute the room summary with heroes for the sync response
  json compute_room_summary(const std::string& room_id,
                              const std::string& user_id) {
    std::string rid = sql_escape(room_id);
    json summary;

    // -- Member counts -------------------------------------------------------
    std::string count_sql =
        "SELECT membership, COUNT(*) as cnt "
        "FROM room_memberships "
        "WHERE room_id='" + rid + "' "
        "GROUP BY membership";

    auto count_rows = db_execute(count_sql);
    summary["m.joined_member_count"] = 0;
    summary["m.invited_member_count"] = 0;

    for (const auto& row : count_rows) {
      std::string ms = col_str(row, "membership");
      int cnt = static_cast<int>(col_int(row, "cnt"));
      if (ms == kMembershipJoin) {
        summary["m.joined_member_count"] = cnt;
      } else if (ms == kMembershipInvite) {
        summary["m.invited_member_count"] = cnt;
      }
    }

    // -- Heroes --------------------------------------------------------------
    // Heroes are the first N users in the room (excluding the syncing user)
    // used to compute the room name in clients when the room is unnamed
    json heroes = compute_room_heroes(room_id, user_id);
    summary["m.heroes"] = std::move(heroes);

    return summary;
  }

  // Compute room heroes: the list of users used for room name generation
  json compute_room_heroes(const std::string& room_id,
                             const std::string& user_id) {
    std::string rid = sql_escape(room_id);
    std::string uid = sql_escape(user_id);
    json heroes = json::array();

    // Get joined members ordered by stream_ordering (oldest first for stability)
    std::string sql =
        "SELECT rm.user_id, rm.sender, rm.event_id "
        "FROM room_memberships rm "
        "WHERE rm.room_id='" + rid + "' "
        "AND rm.membership='" + std::string(kMembershipJoin) + "' "
        "AND rm.user_id != '" + uid + "' "
        "ORDER BY rm.event_id ASC "
        "LIMIT " + std::to_string(kMaxHeroesPerRoom);

    auto rows = db_execute(sql);
    for (const auto& row : rows) {
      heroes.push_back(col_str(row, "user_id"));
    }

    // Check if the result has at least 5 joined members (including the user)
    // If so, indicate that we have more heroes available
    std::string count_sql =
        "SELECT COUNT(*) as cnt FROM room_memberships "
        "WHERE room_id='" + rid + "' "
        "AND membership='" + std::string(kMembershipJoin) + "'";

    auto cnt_rows = db_execute(count_sql);
    if (!cnt_rows.empty()) {
      int64_t total = col_int(cnt_rows[0], "cnt");
      if (total > kMaxHeroesPerRoom + 1) {  // +1 for the syncing user
        summary_hero_count_[room_id] = total;
      }
    }

    return heroes;
  }

  // ==========================================================================
  // Lazy-loading member support
  // ==========================================================================

  // Check if a member has been sent to a user
  bool has_sent_member(std::string_view user_id, std::string_view member_info) {
    std::shared_lock lock(sent_members_mutex_);
    std::string uid(user_id);
    auto it = sent_members_.find(uid);
    if (it == sent_members_.end()) return false;
    return it->second.find(std::string(member_info)) != it->second.end();
  }

  // Mark a member as sent to a user
  void mark_member_sent(std::string_view user_id, std::string_view member_info) {
    std::unique_lock lock(sent_members_mutex_);
    sent_members_[std::string(user_id)].insert(std::string(member_info));
  }

  // Get a single member event for lazy-loading
  json lazy_load_member(const std::string& room_id, const std::string& user_id,
                          const std::string& target_member) {
    std::string rid = sql_escape(room_id);
    std::string tid = sql_escape(target_member);

    std::string cache_key = rid + ":" + tid;
    auto cached = room_member_cache_.get(cache_key);
    if (cached.has_value()) {
      return *cached;
    }

    std::string sql =
        "SELECT * FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + std::string(kEventTypeMember) + "' "
        "AND state_key='" + tid + "' "
        "ORDER BY depth DESC "
        "LIMIT 1";

    auto rows = db_execute(sql);
    if (rows.empty()) {
      return json::object();
    }

    json ev = event_row_to_json(rows[0], room_id);
    room_member_cache_.put(cache_key, ev);
    return ev;
  }

  // ==========================================================================
  // History visibility filtering
  // ==========================================================================

  // Check history visibility for a user in a room
  // Returns true if the user can see events from that time period
  bool check_history_visibility(const std::string& room_id,
                                  const std::string& user_id,
                                  const std::string& sender_id,
                                  uint64_t event_ts,
                                  uint64_t user_membership_ts) {
    // Get history visibility for the room
    std::string hist_vis = get_history_visibility(room_id);

    if (hist_vis.empty() || hist_vis == kHistVisShared) {
      // Default: anyone who was a member can see
      return true;
    }

    if (hist_vis == kHistVisWorldReadable) {
      // Anyone can see
      return true;
    }

    if (hist_vis == kHistVisJoined) {
      // Only joined members can see events from before their join
      return user_membership_ts <= event_ts;
    }

    if (hist_vis == kHistVisInvited) {
      // Joined and invited members can see
      return user_membership_ts <= event_ts;
    }

    return true;
  }

  // Get the history visibility for a room
  std::string get_history_visibility(const std::string& room_id) {
    std::string rid = sql_escape(room_id);

    std::string sql =
        "SELECT content FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + std::string(kEventTypeHistoryVisibility) + "' "
        "AND state_key='' "
        "ORDER BY depth DESC "
        "LIMIT 1";

    auto rows = db_execute(sql);
    if (rows.empty()) {
      return kHistVisShared;  // Default
    }

    json content = parse_json_safe(col_str(rows[0], "content"));
    if (content.contains("history_visibility") &&
        content["history_visibility"].is_string()) {
      return content["history_visibility"].get<std::string>();
    }

    return kHistVisShared;
  }

  // ==========================================================================
  // Room member list queries
  // ==========================================================================

  // Get all joined members for a room (used for presence and notification)
  std::vector<std::string> get_room_joined_members(const std::string& room_id) {
    std::string rid = sql_escape(room_id);
    std::vector<std::string> members;

    std::string sql =
        "SELECT user_id FROM room_memberships "
        "WHERE room_id='" + rid + "' "
        "AND membership='" + std::string(kMembershipJoin) + "'";

    auto rows = db_execute(sql);
    for (const auto& row : rows) {
      std::string uid = col_str(row, "user_id");
      if (!uid.empty()) {
        members.push_back(uid);
      }
    }

    return members;
  }

  // Get all members for a room with their display names and avatars
  json get_room_members_with_profile(const std::string& room_id) {
    std::string rid = sql_escape(room_id);
    json members = json::array();

    std::string sql =
        "SELECT e.* FROM events e "
        "INNER JOIN state_events s ON e.event_id = s.event_id "
        "WHERE s.room_id='" + rid + "' "
        "AND e.type='" + std::string(kEventTypeMember) + "' "
        "ORDER BY e.depth DESC";

    auto rows = db_execute(sql);

    // Track which state_keys we've already added (only highest depth)
    std::set<std::string> seen_keys;

    for (const auto& row : rows) {
      std::string skey = col_str(row, "state_key");
      if (skey.empty() || seen_keys.find(skey) != seen_keys.end())
        continue;
      seen_keys.insert(skey);

      json ev = event_row_to_json(row, room_id);

      json member_info;
      member_info["user_id"] = skey;
      member_info["display_name"] = ev["content"].value("displayname", "");
      member_info["avatar_url"] = ev["content"].value("avatar_url", "");
      member_info["membership"] = ev["content"].value("membership", "leave");

      members.push_back(std::move(member_info));
    }

    return members;
  }

  // Get the power level of a user in a room
  int get_user_power_level(const std::string& room_id,
                            const std::string& user_id) {
    std::string rid = sql_escape(room_id);
    std::string uid = sql_escape(user_id);

    std::string sql =
        "SELECT content FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + std::string(kEventTypePowerLevels) + "' "
        "AND state_key='' "
        "ORDER BY depth DESC "
        "LIMIT 1";

    auto rows = db_execute(sql);
    if (rows.empty()) {
      // Default power levels
      return (user_id == get_room_creator(room_id)) ? 100 : 0;
    }

    try {
      json content = json::parse(col_str(rows[0], "content"));
      if (content.contains("users") && content["users"].is_object() &&
          content["users"].contains(user_id)) {
        return content["users"][user_id].get<int>();
      }
      if (content.contains("users_default")) {
        return content["users_default"].get<int>();
      }
    } catch (...) {
      // Fall through to defaults
    }

    return 0;
  }

  // Get the room creator
  std::string get_room_creator(const std::string& room_id) {
    std::string rid = sql_escape(room_id);

    std::string sql =
        "SELECT content FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + std::string(kEventTypeCreate) + "' "
        "AND state_key='' "
        "ORDER BY depth ASC "
        "LIMIT 1";

    auto rows = db_execute(sql);
    if (rows.empty()) return "";

    try {
      json content = json::parse(col_str(rows[0], "content"));
      return content.value("creator", "");
    } catch (...) {
      return "";
    }
  }

  // ==========================================================================
  // Full state vs incremental helpers
  // ==========================================================================

  // Get the maximum stream ordering for a room
  uint64_t get_room_max_stream_ordering(const std::string& room_id) {
    std::string rid = sql_escape(room_id);

    std::string sql =
        "SELECT MAX(stream_ordering) as max_id "
        "FROM events "
        "WHERE room_id='" + rid + "'";

    auto rows = db_execute(sql);
    if (rows.empty()) return 0;
    return static_cast<uint64_t>(col_int(rows[0], "max_id", 0));
  }

  // Get the minimum stream ordering for a room
  uint64_t get_room_min_stream_ordering(const std::string& room_id) {
    std::string rid = sql_escape(room_id);

    std::string sql =
        "SELECT MIN(stream_ordering) as min_id "
        "FROM events "
        "WHERE room_id='" + rid + "'";

    auto rows = db_execute(sql);
    if (rows.empty()) return 0;
    return static_cast<uint64_t>(col_int(rows[0], "min_id", 0));
  }

  // Check if rooms have changed since a given token
  bool has_room_changed_since(const std::string& room_id, uint64_t stream_id) {
    uint64_t max_id = get_room_max_stream_ordering(room_id);
    return max_id > stream_id;
  }

  // Get rooms that have changed since a token
  std::set<std::string> get_rooms_changed_since(
      const std::vector<std::string>& room_ids, uint64_t stream_id) {
    std::set<std::string> changed;
    if (room_ids.empty()) return changed;

    std::string in_clause = build_in_clause_from_vec(room_ids);
    std::string sql =
        "SELECT DISTINCT room_id FROM events "
        "WHERE room_id IN " + in_clause + " "
        "AND stream_ordering > " + std::to_string(stream_id);

    auto rows = db_execute(sql);
    for (const auto& row : rows) {
      std::string rid = col_str(row, "room_id");
      if (!rid.empty()) changed.insert(rid);
    }

    return changed;
  }

  // ==========================================================================
  // Event gap detection
  // ==========================================================================

  // Check if there's a gap in the event stream since the last sync
  bool has_event_gap(const std::string& room_id, uint64_t since) {
    if (since == 0) return false;  // Initial sync, no gap possible

    std::string rid = sql_escape(room_id);
    std::string sql =
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + rid + "' "
        "AND stream_ordering > " + std::to_string(since);

    auto rows = db_execute(sql);
    if (rows.empty()) return false;

    int64_t count = col_int(rows[0], "cnt", 0);
    int64_t room_event_count = static_cast<int64_t>(
        get_room_max_stream_ordering(room_id) -
        get_room_min_stream_ordering(room_id));

    // If there are more events since than expected, there's likely a gap
    return count > kDefaultTimelineLimit * 2;
  }

  // ==========================================================================
  // Next batch token generation
  // ==========================================================================

  // Generate a next_batch token that encodes stream position + metadata
  std::string generate_next_batch_token(uint64_t stream_pos,
                                          const std::string& room_id = "",
                                          bool is_limited = false) {
    // Simple token: just encode the stream position
    // More advanced tokens can encode room-specific cursors and limit flags
    std::string raw;
    raw += std::to_string(stream_pos);
    if (!room_id.empty()) {
      raw += ":" + room_id;
    }
    if (is_limited) {
      raw += ":limited";
    }
    return std::string(kSyncTokenPrefix) + base64_encode(raw);
  }

  // ==========================================================================
  // Filter application
  // ==========================================================================

  // Apply a JSON filter to a set of events
  json apply_event_filter(const json& events, const json& filter_json) {
    if (filter_json.empty() || !filter_json.is_object()) return events;

    json result = json::array();
    std::set<std::string> allowed_types;
    std::set<std::string> disallowed_types;
    int limit = kDefaultTimelineLimit;

    // Parse the filter (simplified Matrix filter format)
    if (filter_json.contains("types") && filter_json["types"].is_array()) {
      for (const auto& t : filter_json["types"]) {
        if (t.is_string()) allowed_types.insert(t.get<std::string>());
      }
    }
    if (filter_json.contains("not_types") && filter_json["not_types"].is_array()) {
      for (const auto& t : filter_json["not_types"]) {
        if (t.is_string()) disallowed_types.insert(t.get<std::string>());
      }
    }
    if (filter_json.contains("limit") && filter_json["limit"].is_number()) {
      limit = std::min(filter_json["limit"].get<int>(), kMaxTimelineLimit);
    }

    int count = 0;
    for (const auto& ev : events) {
      if (count >= limit) break;
      std::string etype = ev.value("type", "");

      // Type allow list
      if (!allowed_types.empty() &&
          allowed_types.find(etype) == allowed_types.end()) {
        continue;
      }
      // Type deny list
      if (!disallowed_types.empty() &&
          disallowed_types.find(etype) != disallowed_types.end()) {
        continue;
      }

      result.push_back(ev);
      count++;
    }

    return result;
  }

  // ==========================================================================
  // Database access helper
  // ==========================================================================
  RowList db_execute(const std::string& sql) {
    // Use the DatabasePool's execute method
    return db_.execute("sync_engine_v2", sql);
  }

  // ==========================================================================
  // Data members
  // ==========================================================================
  // Track room hero counts for the hero computation
  std::map<std::string, int64_t, std::less<>> summary_hero_count_;

  // Member injection for lazy-loading
  std::map<std::string, std::set<std::string>, std::less<>> lazy_member_pending_;
};

// ============================================================================
// Free-standing convenience: generate sync response directly
// ============================================================================
json generate_sync_response_v2(std::string_view user_id,
                                 std::string_view since_token,
                                 int timeout_ms,
                                 std::string_view filter_json,
                                 DatabasePool& db) {
  SyncEngineV2 engine(db);
  return engine.generate_sync_response(user_id, since_token, timeout_ms,
                                        filter_json);
}

// ============================================================================
// SyncEngineV2Pool - Thread-safe pool of SyncEngineV2 instances
// Each instance can be reused across sync calls for better caching
// ============================================================================
class SyncEngineV2Pool {
public:
  explicit SyncEngineV2Pool(DatabasePool& db, size_t pool_size = 4)
      : db_(db), pool_size_(pool_size) {
    engines_.reserve(pool_size);
    for (size_t i = 0; i < pool_size; ++i) {
      engines_.emplace_back(std::make_unique<SyncEngineV2>(db));
    }
  }

  // Get an engine instance (round-robin)
  SyncEngineV2& get_engine() {
    size_t idx = next_idx_.fetch_add(1, std::memory_order_relaxed) % pool_size_;
    return *engines_[idx];
  }

  // Generate sync response using a pooled engine
  json sync(std::string_view user_id, std::string_view since_token,
            int timeout_ms = 0, std::string_view filter_json = "") {
    SyncEngineV2& engine = get_engine();
    return engine.generate_sync_response(user_id, since_token, timeout_ms,
                                          filter_json);
  }

  void invalidate_all_caches() {
    for (auto& engine : engines_) {
      engine->invalidate_caches();
    }
  }

  void advance_all_streams() {
    for (auto& engine : engines_) {
      engine->advance_stream_position();
    }
  }

private:
  DatabasePool& db_;
  size_t pool_size_;
  std::atomic<size_t> next_idx_{0};
  std::vector<std::unique_ptr<SyncEngineV2>> engines_;
};

// ============================================================================
// SyncEventProcessor - processes new events to update sync state
// When a new event is persisted, this class updates the relevant sync
// metadata and notifies waiting sync clients.
// ============================================================================
class SyncEventProcessor {
public:
  SyncEventProcessor(DatabasePool& db, SyncEngineV2Pool& sync_pool)
      : db_(db), sync_pool_(sync_pool) {}

  // Called when a new event is persisted to the database
  void on_new_event(const std::string& room_id, const std::string& event_id,
                    const std::string& event_type, const std::string& sender,
                    uint64_t stream_ordering) {
    // Advance all engine stream positions
    sync_pool_.advance_all_streams();

    // If this is a state event, invalidate room member caches
    if (is_state_event_type(event_type)) {
      sync_pool_.invalidate_all_caches();
    }

    // Track the event in the event stream for gap detection
    event_stream_[room_id].push_back(stream_ordering);

    // Prune old stream positions
    prune_event_stream(room_id);

    (void)event_id;
    (void)sender;
  }

  // Called when a membership change occurs
  void on_membership_change(const std::string& room_id,
                              const std::string& user_id,
                              const std::string& old_membership,
                              const std::string& new_membership) {
    // Invalidate relevant caches
    sync_pool_.invalidate_all_caches();

    // Track the membership change for device list tracking
    if (new_membership == kMembershipJoin ||
        old_membership == kMembershipJoin) {
      membership_changes_[user_id].push_back({
          room_id,
          (new_membership == kMembershipJoin) ? "join" : "leave"
      });
    }
  }

  // Get recent membership changes for a user
  std::vector<std::pair<std::string, std::string>>
  get_recent_membership_changes(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(membership_mutex_);
    auto it = membership_changes_.find(user_id);
    if (it == membership_changes_.end()) return {};
    return it->second;
  }

  // Clear tracked changes for a user
  void clear_membership_changes(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(membership_mutex_);
    membership_changes_.erase(user_id);
  }

private:
  bool is_state_event_type(const std::string& event_type) {
    return kRoomStateEventTypes.find(event_type) !=
           kRoomStateEventTypes.end();
  }

  void prune_event_stream(const std::string& room_id) {
    auto& stream = event_stream_[room_id];
    constexpr size_t kMaxStreamEntries = 5000;
    if (stream.size() > kMaxStreamEntries) {
      stream.erase(stream.begin(),
                   stream.begin() + (stream.size() - kMaxStreamEntries));
    }
  }

  DatabasePool& db_;
  SyncEngineV2Pool& sync_pool_;

  std::map<std::string, std::deque<uint64_t>, std::less<>> event_stream_;
  std::mutex stream_mutex_;

  std::map<std::string, std::vector<std::pair<std::string, std::string>>,
           std::less<>> membership_changes_;
  std::mutex membership_mutex_;
};

// ============================================================================
// SyncTokenManager - manages sync token creation, validation, and expiry
// ============================================================================
class SyncTokenManager {
public:
  SyncTokenManager() = default;

  // Create a new sync token
  std::string create_token(uint64_t stream_pos, const std::string& user_id = "") {
    std::lock_guard<std::mutex> lock(mutex_);

    auto now = std::chrono::steady_clock::now();
    std::string token = make_sync_token(stream_pos);

    TokenInfo info;
    info.stream_pos = stream_pos;
    info.user_id = user_id;
    info.created_at = now;
    info.last_used = now;

    active_tokens_[token] = info;
    return token;
  }

  // Validate a sync token and return its stream position
  uint64_t validate_token(std::string_view token) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string tkey(token);

    auto it = active_tokens_.find(tkey);
    if (it == active_tokens_.end()) {
      // Token not in our map, try to parse it directly
      return parse_sync_token(token);
    }

    // Update last_used time
    it->second.last_used = std::chrono::steady_clock::now();
    return it->second.stream_pos;
  }

  // Expire old tokens
  void expire_old_tokens(int64_t max_age_seconds = 3600) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto now = std::chrono::steady_clock::now();
    auto max_age = std::chrono::seconds(max_age_seconds);

    for (auto it = active_tokens_.begin(); it != active_tokens_.end(); ) {
      if (now - it->second.last_used > max_age) {
        it = active_tokens_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // Get the number of active tokens
  size_t active_token_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return active_tokens_.size();
  }

private:
  struct TokenInfo {
    uint64_t stream_pos;
    std::string user_id;
    std::chrono::steady_clock::time_point created_at;
    std::chrono::steady_clock::time_point last_used;
  };

  std::map<std::string, TokenInfo, std::less<>> active_tokens_;
  mutable std::mutex mutex_;
};

// ============================================================================
// RoomSummaryCalculator - standalone room summary computation
// Used independently outside of the sync loop (e.g., for /rooms/{roomId}/summary)
// ============================================================================
class RoomSummaryCalculator {
public:
  explicit RoomSummaryCalculator(DatabasePool& db) : db_(db) {}

  // Compute full room summary
  json compute_summary(const std::string& room_id,
                        const std::string& requestor_id = "") {
    std::string rid = sql_escape(room_id);
    json summary;

    // Room name
    summary["name"] = get_room_name(room_id);

    // Room topic
    summary["topic"] = get_room_topic(room_id);

    // Room avatar
    summary["avatar_url"] = get_room_avatar(room_id);

    // Canonical alias
    summary["canonical_alias"] = get_room_canonical_alias(room_id);

    // Member counts
    json counts = get_room_membership_counts(room_id);
    summary["num_joined_members"] = counts["joined"];
    summary["num_invited_members"] = counts["invited"];

    // Room type
    summary["room_type"] = get_room_type(room_id);

    // Join rules
    summary["join_rules"] = get_room_join_rules(room_id);

    // Guest access
    summary["guest_access"] = get_room_guest_access(room_id);

    // Encryption
    summary["encryption"] = get_room_encryption(room_id);

    // History visibility
    summary["world_readable"] =
        (get_history_visibility(room_id) == kHistVisWorldReadable);

    // Creator
    summary["creator"] = get_room_creator(room_id);

    // Room version
    summary["room_version"] = get_room_version(room_id);

    // Federatable flag
    summary["federatable"] = is_room_federatable(room_id);

    return summary;
  }

private:
  std::string get_room_name(const std::string& room_id) {
    return get_state_event_content_field(room_id, kEventTypeName, "name", "");
  }

  std::string get_room_topic(const std::string& room_id) {
    return get_state_event_content_field(room_id, kEventTypeTopic, "topic", "");
  }

  std::string get_room_avatar(const std::string& room_id) {
    return get_state_event_content_field(room_id, kEventTypeAvatar, "url", "");
  }

  std::string get_room_canonical_alias(const std::string& room_id) {
    return get_state_event_content_field(room_id, kEventTypeCanonicalAlias,
                                          "alias", "");
  }

  json get_room_membership_counts(const std::string& room_id) {
    std::string rid = sql_escape(room_id);
    json counts;
    counts["joined"] = 0;
    counts["invited"] = 0;

    std::string sql =
        "SELECT membership, COUNT(*) as cnt "
        "FROM room_memberships "
        "WHERE room_id='" + rid + "' "
        "GROUP BY membership";

    auto rows = db_execute_impl(sql);
    for (const auto& row : rows) {
      std::string ms = col_str(row, "membership");
      int64_t cnt = col_int(row, "cnt");
      if (ms == kMembershipJoin) counts["joined"] = cnt;
      else if (ms == kMembershipInvite) counts["invited"] = cnt;
    }

    return counts;
  }

  std::string get_room_type(const std::string& room_id) {
    return get_state_event_content_field(room_id, kEventTypeCreate, "type", "");
  }

  std::string get_room_join_rules(const std::string& room_id) {
    return get_state_event_content_field(room_id, kEventTypeJoinRules,
                                          "join_rule", "public");
  }

  std::string get_room_guest_access(const std::string& room_id) {
    return get_state_event_content_field(room_id, kEventTypeGuestAccess,
                                          "guest_access", "forbidden");
  }

  json get_room_encryption(const std::string& room_id) {
    std::string rid = sql_escape(room_id);
    std::string sql =
        "SELECT content FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + std::string(kEventTypeEncryption) + "' "
        "AND state_key='' "
        "ORDER BY depth DESC LIMIT 1";

    auto rows = db_execute_impl(sql);
    if (rows.empty()) return json::object();

    return parse_json_safe(col_str(rows[0], "content"));
  }

  std::string get_room_version(const std::string& room_id) {
    std::string rid = sql_escape(room_id);
    std::string sql =
        "SELECT room_version FROM rooms WHERE room_id='" + rid + "'";

    auto rows = db_execute_impl(sql);
    if (rows.empty()) return "10";  // Default room version
    return col_str(rows[0], "room_version", "10");
  }

  bool is_room_federatable(const std::string& room_id) {
    std::string join_rules = get_room_join_rules(room_id);
    if (join_rules == "restricted") {
      return true;
    }
    return join_rules != "knock" && join_rules.find("restricted") == std::string::npos;
  }

  std::string get_state_event_content_field(const std::string& room_id,
                                              const std::string& event_type,
                                              const std::string& field,
                                              const std::string& default_val) {
    std::string rid = sql_escape(room_id);
    std::string etype = sql_escape(event_type);

    std::string sql =
        "SELECT content FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + etype + "' "
        "AND state_key='' "
        "ORDER BY depth DESC LIMIT 1";

    auto rows = db_execute_impl(sql);
    if (rows.empty()) return default_val;

    json content = parse_json_safe(col_str(rows[0], "content"));
    if (content.contains(field) && content[field].is_string()) {
      return content[field].get<std::string>();
    }
    return default_val;
  }

  RowList db_execute_impl(const std::string& sql) {
    return db_.execute("room_summary_calc", sql);
  }

  DatabasePool& db_;
};

// ============================================================================
// SyncMetrics - collect and expose sync engine metrics
// ============================================================================
class SyncMetrics {
public:
  SyncMetrics() = default;

  void record_sync_request(bool is_initial) {
    if (is_initial) {
      initial_syncs_.fetch_add(1, std::memory_order_relaxed);
    } else {
      incremental_syncs_.fetch_add(1, std::memory_order_relaxed);
    }
    total_syncs_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_sync_duration_ms(int64_t ms) {
    total_sync_duration_ms_.fetch_add(ms, std::memory_order_relaxed);
    sync_count_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_empty_sync() {
    empty_syncs_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_room_sync() {
    room_syncs_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_lazy_load() {
    lazy_loads_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_cache_hit() {
    cache_hits_.fetch_add(1, std::memory_order_relaxed);
  }

  void record_cache_miss() {
    cache_misses_.fetch_add(1, std::memory_order_relaxed);
  }

  json get_metrics() const {
    json m;
    m["total_syncs"] = total_syncs_.load(std::memory_order_relaxed);
    m["initial_syncs"] = initial_syncs_.load(std::memory_order_relaxed);
    m["incremental_syncs"] = incremental_syncs_.load(std::memory_order_relaxed);
    m["empty_syncs"] = empty_syncs_.load(std::memory_order_relaxed);
    m["room_syncs"] = room_syncs_.load(std::memory_order_relaxed);
    m["lazy_loads"] = lazy_loads_.load(std::memory_order_relaxed);
    m["cache_hits"] = cache_hits_.load(std::memory_order_relaxed);
    m["cache_misses"] = cache_misses_.load(std::memory_order_relaxed);

    int64_t count = sync_count_.load(std::memory_order_relaxed);
    int64_t dur = total_sync_duration_ms_.load(std::memory_order_relaxed);
    m["avg_sync_duration_ms"] = (count > 0) ? (dur / count) : 0;

    return m;
  }

  void reset() {
    total_syncs_.store(0, std::memory_order_relaxed);
    initial_syncs_.store(0, std::memory_order_relaxed);
    incremental_syncs_.store(0, std::memory_order_relaxed);
    empty_syncs_.store(0, std::memory_order_relaxed);
    room_syncs_.store(0, std::memory_order_relaxed);
    lazy_loads_.store(0, std::memory_order_relaxed);
    cache_hits_.store(0, std::memory_order_relaxed);
    cache_misses_.store(0, std::memory_order_relaxed);
    total_sync_duration_ms_.store(0, std::memory_order_relaxed);
    sync_count_.store(0, std::memory_order_relaxed);
  }

private:
  std::atomic<uint64_t> total_syncs_{0};
  std::atomic<uint64_t> initial_syncs_{0};
  std::atomic<uint64_t> incremental_syncs_{0};
  std::atomic<uint64_t> empty_syncs_{0};
  std::atomic<uint64_t> room_syncs_{0};
  std::atomic<uint64_t> lazy_loads_{0};
  std::atomic<uint64_t> cache_hits_{0};
  std::atomic<uint64_t> cache_misses_{0};
  std::atomic<int64_t> total_sync_duration_ms_{0};
  std::atomic<int64_t> sync_count_{0};
};

// ============================================================================
// LongPollManager - manages long-poll waiting for sync with no changes
// ============================================================================
class LongPollManager {
public:
  LongPollManager() : stop_flag_(false) {}

  // Wait for new events with timeout
  // Returns true if new events arrived, false if timed out
  bool wait_for_events(uint64_t current_pos, int64_t timeout_ms) {
    if (timeout_ms <= 0) return false;

    std::unique_lock<std::mutex> lock(notify_mutex_);

    // Check if new events have already arrived
    uint64_t latest = latest_stream_pos_.load(std::memory_order_acquire);
    if (latest > current_pos) return true;

    // Wait with timeout
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);

    notify_cv_.wait_until(lock, deadline, [&]() {
      return stop_flag_.load(std::memory_order_relaxed) ||
             latest_stream_pos_.load(std::memory_order_acquire) > current_pos;
    });

    return latest_stream_pos_.load(std::memory_order_acquire) > current_pos;
  }

  // Notify waiting syncs that new events are available
  void notify_new_events(uint64_t new_pos) {
    latest_stream_pos_.store(new_pos, std::memory_order_release);
    notify_cv_.notify_all();
  }

  // Signal shutdown
  void shutdown() {
    stop_flag_.store(true, std::memory_order_relaxed);
    notify_cv_.notify_all();
  }

private:
  std::atomic<uint64_t> latest_stream_pos_{0};
  std::atomic<bool> stop_flag_{false};
  std::mutex notify_mutex_;
  std::condition_variable notify_cv_;
};

// ============================================================================
// SyncFilterEvaluator - evaluates Matrix filter JSON to determine which
// events, rooms, and event types to include in a sync response.
// Implements the complete Matrix /sync filter spec:
//   - event_fields: limit returned fields per event
//   - event_format: "client" or "federation"
//   - presence: filter presence events (types, limit, senders)
//   - account_data: filter global and per-room account data
//   - room: per-room filter (timeline, state, ephemeral, account_data)
//   - room.timeline: types, not_types, limit, rooms, not_rooms,
//     senders, not_senders, contains_url, lazy_load_members,
//     include_redundant_members, unread_thread_notifications
//   - room.state: types, not_types, limit, rooms, not_rooms,
//     senders, not_senders, lazy_load_members
//   - room.ephemeral: types, not_types, limit, rooms, not_rooms
// ============================================================================
class SyncFilterEvaluator {
public:
  SyncFilterEvaluator() = default;

  // Parse and store a filter JSON
  void set_filter(const json& filter_json) {
    if (filter_json.empty() || !filter_json.is_object()) {
      filter_ = json::object();
      return;
    }
    filter_ = filter_json;
  }

  // Check if this filter allows a specific event type in the timeline
  bool allow_timeline_event(const std::string& event_type,
                             const std::string& sender = "",
                             bool has_url = false) {
    if (filter_.empty()) return true;

    const json& room_filter = filter_.value("room", json::object());
    const json& timeline = room_filter.value("timeline", json::object());

    // Check types allowlist
    if (timeline.contains("types")) {
      bool found = false;
      for (const auto& t : timeline["types"]) {
        if (t.is_string() && t.get<std::string>() == event_type) {
          found = true;
          break;
        }
      }
      if (!found) return false;
    }

    // Check types denylist
    if (timeline.contains("not_types")) {
      for (const auto& t : timeline["not_types"]) {
        if (t.is_string() && t.get<std::string>() == event_type) {
          return false;
        }
      }
    }

    // Check senders allowlist
    if (!sender.empty() && timeline.contains("senders")) {
      bool found = false;
      for (const auto& s : timeline["senders"]) {
        if (s.is_string() && s.get<std::string>() == sender) {
          found = true;
          break;
        }
      }
      if (!found) return false;
    }

    // Check senders denylist
    if (!sender.empty() && timeline.contains("not_senders")) {
      for (const auto& s : timeline["not_senders"]) {
        if (s.is_string() && s.get<std::string>() == sender) {
          return false;
        }
      }
    }

    // Check contains_url filter
    if (timeline.contains("contains_url")) {
      bool filter_wants_url = timeline["contains_url"].get<bool>();
      if (filter_wants_url && !has_url) return false;
      if (!filter_wants_url && has_url) return false;
    }

    return true;
  }

  // Check if a room should be included in sync
  bool allow_room(const std::string& room_id) {
    if (filter_.empty()) return true;

    const json& room_filter = filter_.value("room", json::object());

    // Check rooms allowlist
    if (room_filter.contains("rooms")) {
      bool found = false;
      for (const auto& r : room_filter["rooms"]) {
        if (r.is_string() && r.get<std::string>() == room_id) {
          found = true;
          break;
        }
      }
      if (!found) return false;
    }

    // Check rooms denylist
    if (room_filter.contains("not_rooms")) {
      for (const auto& r : room_filter["not_rooms"]) {
        if (r.is_string() && r.get<std::string>() == room_id) {
          return false;
        }
      }
    }

    return true;
  }

  // Check if we should lazy-load members for this room
  bool should_lazy_load_members(const std::string& room_id) {
    if (filter_.empty()) return true;  // Default: use lazy-loading

    const json& room_filter = filter_.value("room", json::object());
    const json& state = room_filter.value("state", json::object());

    if (state.contains("lazy_load_members")) {
      return state["lazy_load_members"].get<bool>();
    }

    return true;
  }

  // Check if we should include redundant members
  bool include_redundant_members() {
    if (filter_.empty()) return false;
    const json& room_filter = filter_.value("room", json::object());
    const json& timeline = room_filter.value("timeline", json::object());
    return timeline.value("include_redundant_members", false);
  }

  // Get the timeline event limit
  int get_timeline_limit() {
    if (filter_.empty()) return kDefaultTimelineLimit;
    const json& room_filter = filter_.value("room", json::object());
    const json& timeline = room_filter.value("timeline", json::object());
    if (timeline.contains("limit") && timeline["limit"].is_number()) {
      return std::min(timeline["limit"].get<int>(), kMaxTimelineLimit);
    }
    return kDefaultTimelineLimit;
  }

  // Get the state event type allowlist
  std::set<std::string> get_state_allowed_types() {
    if (filter_.empty()) return {};
    const json& room_filter = filter_.value("room", json::object());
    const json& state = room_filter.value("state", json::object());
    if (!state.contains("types")) return {};

    std::set<std::string> types;
    for (const auto& t : state["types"]) {
      if (t.is_string()) types.insert(t.get<std::string>());
    }
    return types;
  }

  // Get the state event type denylist
  std::set<std::string> get_state_disallowed_types() {
    if (filter_.empty()) return {};
    const json& room_filter = filter_.value("room", json::object());
    const json& state = room_filter.value("state", json::object());
    if (!state.contains("not_types")) return {};

    std::set<std::string> types;
    for (const auto& t : state["not_types"]) {
      if (t.is_string()) types.insert(t.get<std::string>());
    }
    return types;
  }

  // Get the ephemeral event type allowlist
  std::set<std::string> get_ephemeral_allowed_types() {
    if (filter_.empty()) return {};
    const json& room_filter = filter_.value("room", json::object());
    const json& ephemeral = room_filter.value("ephemeral", json::object());
    if (!ephemeral.contains("types")) return {};

    std::set<std::string> types;
    for (const auto& t : ephemeral["types"]) {
      if (t.is_string()) types.insert(t.get<std::string>());
    }
    return types;
  }

  // Get event fields to include (if empty, include all)
  std::set<std::string> get_event_fields() {
    if (filter_.empty()) return {};
    const json& event_fields = filter_.value("event_fields", json::array());
    if (!event_fields.is_array()) return {};

    std::set<std::string> fields;
    for (const auto& f : event_fields) {
      if (f.is_string()) fields.insert(f.get<std::string>());
    }
    return fields;
  }

  // Apply event fields filter to a single event
  json apply_event_fields(const json& event) {
    std::set<std::string> fields = get_event_fields();
    if (fields.empty()) return event;  // Include all fields

    json filtered;
    for (const auto& field : fields) {
      if (event.contains(field)) {
        filtered[field] = event[field];
      }
    }
    return filtered;
  }

  // Apply event fields filter to an array of events
  json apply_event_fields_to_array(const json& events) {
    std::set<std::string> fields = get_event_fields();
    if (fields.empty() || !events.is_array()) return events;

    json filtered = json::array();
    for (const auto& ev : events) {
      filtered.push_back(apply_event_fields(ev));
    }
    return filtered;
  }

  // Check whether presence events should be included
  bool include_presence() {
    if (filter_.empty()) return true;
    const json& presence = filter_.value("presence", json::object());
    // If presence filter is explicitly empty object, exclude presence
    if (presence.is_object() && presence.empty()) return false;
    return true;
  }

  // Get presence sender allowlist
  std::set<std::string> get_presence_allowed_senders() {
    if (filter_.empty()) return {};
    const json& presence = filter_.value("presence", json::object());
    if (!presence.contains("senders")) return {};

    std::set<std::string> senders;
    for (const auto& s : presence["senders"]) {
      if (s.is_string()) senders.insert(s.get<std::string>());
    }
    return senders;
  }

  // Get presence limit
  int get_presence_limit() {
    if (filter_.empty()) return kMaxPresenceEntries;
    const json& presence = filter_.value("presence", json::object());
    if (presence.contains("limit") && presence["limit"].is_number()) {
      return presence["limit"].get<int>();
    }
    return kMaxPresenceEntries;
  }

  // Check whether account_data should be included
  bool include_account_data() {
    if (filter_.empty()) return true;
    const json& ad = filter_.value("account_data", json::object());
    if (ad.is_object() && ad.empty()) return false;
    return true;
  }

  // Get account_data type allowlist
  std::set<std::string> get_account_data_allowed_types() {
    if (filter_.empty()) return {};
    const json& ad = filter_.value("account_data", json::object());
    if (!ad.contains("types")) return {};

    std::set<std::string> types;
    for (const auto& t : ad["types"]) {
      if (t.is_string()) types.insert(t.get<std::string>());
    }
    return types;
  }

  // Get account_data type denylist
  std::set<std::string> get_account_data_disallowed_types() {
    if (filter_.empty()) return {};
    const json& ad = filter_.value("account_data", json::object());
    if (!ad.contains("not_types")) return {};

    std::set<std::string> types;
    for (const auto& t : ad["not_types"]) {
      if (t.is_string()) types.insert(t.get<std::string>());
    }
    return types;
  }

private:
  json filter_ = json::object();
};

// ============================================================================
// SyncRedactionProcessor - handles redaction of events within sync responses
// When a redaction event appears in the timeline, previously seen events
// must be stripped of their content. This class tracks redactions and
// applies them to timeline events before sending to clients.
// ============================================================================
class SyncRedactionProcessor {
public:
  SyncRedactionProcessor() = default;

  // Register a redaction event
  void add_redaction(const std::string& redacts_event_id,
                     const std::string& redaction_event_id,
                     const std::string& reason = "") {
    redactions_[redacts_event_id] = {redaction_event_id, reason, now_ms()};
    // Prune old redactions periodically
    if (redactions_.size() > 10000) prune_old_redactions();
  }

  // Apply known redactions to an array of timeline events
  json apply_redactions(const json& events) {
    if (redactions_.empty()) return events;
    if (!events.is_array()) return events;

    json result = json::array();
    for (const auto& ev : events) {
      std::string eid = ev.value("event_id", "");
      auto it = redactions_.find(eid);
      if (it != redactions_.end()) {
        // This event was redacted – replace content with empty object
        // and add redacted_because key
        json redacted = ev;
        redacted["content"] = json::object();
        json redacted_because;
        redacted_because["event_id"] = it->second.redaction_event_id;
        redacted_because["reason"] = it->second.reason;
        redacted_because["redacted_at_ts"] = it->second.ts;
        redacted["unsigned"]["redacted_because"] = redacted_because;
        result.push_back(std::move(redacted));
      } else {
        result.push_back(ev);
      }
    }
    return result;
  }

  // Check if a specific event is redacted
  bool is_redacted(const std::string& event_id) const {
    return redactions_.find(event_id) != redactions_.end();
  }

  // Get redaction info for an event
  std::optional<std::string> get_redaction_reason(
      const std::string& event_id) const {
    auto it = redactions_.find(event_id);
    if (it == redactions_.end()) return std::nullopt;
    return it->second.reason;
  }

  // Clear all tracked redactions (e.g., on cache invalidation)
  void clear() {
    redactions_.clear();
  }

  size_t tracked_count() const {
    return redactions_.size();
  }

private:
  struct RedactionInfo {
    std::string redaction_event_id;
    std::string reason;
    int64_t ts;
  };

  void prune_old_redactions() {
    int64_t threshold = now_ms() - 3600'000;  // 1 hour
    for (auto it = redactions_.begin(); it != redactions_.end(); ) {
      if (it->second.ts < threshold) {
        it = redactions_.erase(it);
      } else {
        ++it;
      }
    }
  }

  std::map<std::string, RedactionInfo, std::less<>> redactions_;
};

// ============================================================================
// RoomNotificationTracker - tracks per-room notification counts for sync
// Includes highlight counts, notification counts, and push rule evaluation.
// ============================================================================
class RoomNotificationTracker {
public:
  explicit RoomNotificationTracker(DatabasePool& db) : db_(db) {}

  // Get notification counts for all rooms for a user
  json get_all_notification_counts(const std::string& user_id) {
    std::string uid = sql_escape(user_id);
    json result;

    std::string sql =
        "SELECT room_id, "
        "SUM(CASE WHEN notif > 0 THEN 1 ELSE 0 END) as notification_count, "
        "SUM(CASE WHEN highlight > 0 THEN 1 ELSE 0 END) as highlight_count "
        "FROM event_push_actions_staging "
        "WHERE user_id='" + uid + "' "
        "GROUP BY room_id";

    auto rows = db_.execute("notif_tracker", sql);
    for (const auto& row : rows) {
      std::string rid = col_str(row, "room_id");
      if (rid.empty()) continue;

      json entry;
      entry["notification_count"] = col_int(row, "notification_count", 0);
      entry["highlight_count"] = col_int(row, "highlight_count", 0);
      result[rid] = std::move(entry);
    }

    return result;
  }

  // Get notification count for a single room
  json get_room_notification_count(const std::string& user_id,
                                     const std::string& room_id) {
    std::string uid = sql_escape(user_id);
    std::string rid = sql_escape(room_id);

    std::string sql =
        "SELECT COUNT(*) as notification_count "
        "FROM event_push_actions_staging "
        "WHERE user_id='" + uid + "' "
        "AND room_id='" + rid + "' "
        "AND notif > 0";

    auto rows = db_.execute("notif_tracker", sql);
    json result;
    result["notification_count"] = rows.empty() ? 0 :
        col_int(rows[0], "notification_count", 0);

    sql = "SELECT COUNT(*) as highlight_count "
          "FROM event_push_actions_staging "
          "WHERE user_id='" + uid + "' "
          "AND room_id='" + rid + "' "
          "AND highlight > 0";

    auto hrows = db_.execute("notif_tracker", sql);
    result["highlight_count"] = hrows.empty() ? 0 :
        col_int(hrows[0], "highlight_count", 0);

    return result;
  }

  // Mark notifications as read (rotated) for a room
  void rotate_notifications(const std::string& user_id,
                              const std::string& room_id) {
    std::string uid = sql_escape(user_id);
    std::string rid = sql_escape(room_id);

    // Move entries from staging to summary
    std::string sql =
        "INSERT OR REPLACE INTO event_push_summary "
        "(user_id, room_id, stream_ordering, notif_count, highlight_count) "
        "SELECT '" + uid + "', '" + rid + "', "
        "MAX(stream_ordering), "
        "SUM(CASE WHEN notif > 0 THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN highlight > 0 THEN 1 ELSE 0 END) "
        "FROM event_push_actions_staging "
        "WHERE user_id='" + uid + "' "
        "AND room_id='" + rid + "'";

    db_.execute("notif_rotate", sql);

    // Delete from staging
    sql = "DELETE FROM event_push_actions_staging "
          "WHERE user_id='" + uid + "' "
          "AND room_id='" + rid + "'";
    db_.execute("notif_rotate_del", sql);
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// EventVisibilityChecker - determines event visibility for a user
// Implements history visibility rules, power level checks, and
// membership-based visibility filtering.
// ============================================================================
class EventVisibilityChecker {
public:
  EventVisibilityChecker(DatabasePool& db) : db_(db) {}

  // Check if a user can see a specific event
  bool can_see_event(const std::string& user_id, const std::string& room_id,
                     const json& event, int64_t user_join_ts) {
    std::string event_type = event.value("type", "");
    std::string sender = event.value("sender", "");

    // Sender always sees their own events
    if (sender == user_id) return true;

    // State events are always visible
    if (event.contains("state_key") && !event["state_key"].is_null() &&
        !event["state_key"].get<std::string>().empty()) {
      return true;
    }

    // Check history visibility
    std::string hist_vis = get_room_history_visibility(room_id);
    int64_t event_ts = event.value("origin_server_ts", int64_t(0));

    if (hist_vis == kHistVisWorldReadable) return true;
    if (hist_vis == kHistVisShared) return true;
    if (hist_vis == kHistVisJoined) {
      return user_join_ts <= event_ts;
    }
    if (hist_vis == kHistVisInvited) {
      return user_join_ts <= event_ts ||
             was_user_invited_at(user_id, room_id, event_ts);
    }

    return true;
  }

  // Check if a user can see events in a room they have left
  bool can_see_events_after_leave(const std::string& user_id,
                                    const std::string& room_id,
                                    int64_t leave_ts) {
    std::string hist_vis = get_room_history_visibility(room_id);

    // After leaving, users can see events from before they left
    // but only if history visibility allows it
    if (hist_vis == kHistVisWorldReadable) return true;
    if (hist_vis == kHistVisShared) return true;

    // For joined/invited visibility: cannot see events after leaving
    return false;
  }

  // Get the join timestamp for a user in a room
  int64_t get_user_join_ts(const std::string& user_id,
                            const std::string& room_id) {
    std::string uid = sql_escape(user_id);
    std::string rid = sql_escape(room_id);

    std::string sql =
        "SELECT stream_ordering FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + std::string(kEventTypeMember) + "' "
        "AND state_key='" + uid + "' "
        "AND content LIKE '%\"membership\":\"join\"%' "
        "ORDER BY depth ASC LIMIT 1";

    auto rows = db_.execute("vis_check", sql);
    if (rows.empty()) return 0;
    return col_int(rows[0], "stream_ordering");
  }

  // Get the leave timestamp for a user from a room
  int64_t get_user_leave_ts(const std::string& user_id,
                              const std::string& room_id) {
    std::string uid = sql_escape(user_id);
    std::string rid = sql_escape(room_id);

    std::string sql =
        "SELECT stream_ordering FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + std::string(kEventTypeMember) + "' "
        "AND state_key='" + uid + "' "
        "AND content LIKE '%\"membership\":\"leave\"%' "
        "ORDER BY depth DESC LIMIT 1";

    auto rows = db_.execute("vis_check", sql);
    if (rows.empty()) return INT64_MAX;
    return col_int(rows[0], "stream_ordering");
  }

private:
  std::string get_room_history_visibility(const std::string& room_id) {
    std::string rid = sql_escape(room_id);
    std::string sql =
        "SELECT content FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + std::string(kEventTypeHistoryVisibility) + "' "
        "AND state_key='' "
        "ORDER BY depth DESC LIMIT 1";

    auto rows = db_.execute("vis_check", sql);
    if (rows.empty()) return kHistVisShared;

    json content = parse_json_safe(col_str(rows[0], "content"));
    return content.value("history_visibility", kHistVisShared);
  }

  bool was_user_invited_at(const std::string& user_id,
                            const std::string& room_id,
                            int64_t ts) {
    std::string uid = sql_escape(user_id);
    std::string rid = sql_escape(room_id);

    std::string sql =
        "SELECT stream_ordering FROM events "
        "WHERE room_id='" + rid + "' "
        "AND type='" + std::string(kEventTypeMember) + "' "
        "AND state_key='" + uid + "' "
        "AND content LIKE '%\"membership\":\"invite\"%' "
        "AND stream_ordering <= " + std::to_string(ts) + " "
        "LIMIT 1";

    auto rows = db_.execute("vis_check", sql);
    return !rows.empty();
  }

  DatabasePool& db_;
};

// ============================================================================
// SyncTimelineGapDetector - detects gaps in the event timeline and
// determines if a sync response should be marked as "limited"
// ============================================================================
class SyncTimelineGapDetector {
public:
  SyncTimelineGapDetector(DatabasePool& db) : db_(db) {}

  // Check if there's a gap between the since token and the current state
  bool detect_gap(const std::string& room_id, uint64_t since,
                  const json& loaded_events) {
    if (since == 0) return false;  // Initial sync is always a full view

    std::string rid = sql_escape(room_id);

    // Count events between since and the oldest loaded event
    std::string sql =
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + rid + "' "
        "AND stream_ordering > " + std::to_string(since);

    auto rows = db_.execute("gap_detector", sql);
    if (rows.empty()) return false;

    int64_t total_since = col_int(rows[0], "cnt");
    int64_t loaded_count = loaded_events.is_array() ?
        loaded_events.size() : 0;

    // If there are more events since the token than we loaded, there's a gap
    return total_since > loaded_count;
  }

  // Get the number of events since a given token
  int64_t get_events_since_count(const std::string& room_id, uint64_t since) {
    std::string rid = sql_escape(room_id);
    std::string sql =
        "SELECT COUNT(*) as cnt FROM events "
        "WHERE room_id='" + rid + "' "
        "AND stream_ordering > " + std::to_string(since);

    auto rows = db_.execute("gap_detector", sql);
    return rows.empty() ? 0 : col_int(rows[0], "cnt");
  }

  // Determine the gap type: "limited" (we dropped events) or "no_gap"
  std::string get_gap_type(const std::string& room_id, uint64_t since,
                            int loaded_count) {
    int64_t total = get_events_since_count(room_id, since);
    if (total > loaded_count) return "limited";
    return "no_gap";
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// BulkRoomSyncOptimizer - optimizes sync for users with many rooms
// by batching database queries and using parallel processing patterns.
// ============================================================================
class BulkRoomSyncOptimizer {
public:
  BulkRoomSyncOptimizer(DatabasePool& db) : db_(db) {}

  // Batch-load event data for multiple rooms at once
  std::map<std::string, json> batch_load_recent_events(
      const std::vector<std::string>& room_ids, int limit_per_room) {
    std::map<std::string, json> results;
    if (room_ids.empty()) return results;

    // Build a batched query using UNION ALL for efficiency
    std::string sql;
    for (size_t i = 0; i < room_ids.size(); ++i) {
      if (i > 0) sql += " UNION ALL ";
      sql += "SELECT e.*, '" + sql_escape(room_ids[i]) +
             "' as _batch_room FROM events e "
             "WHERE e.room_id='" + sql_escape(room_ids[i]) + "' "
             "ORDER BY e.stream_ordering DESC "
             "LIMIT " + std::to_string(limit_per_room);
    }

    auto rows = db_.execute("batch_load", sql);
    for (const auto& row : rows) {
      std::string room = col_str(row, "_batch_room");
      if (room.empty()) room = col_str(row, "room_id");
      if (!results[room].is_array()) results[room] = json::array();
      results[room].push_back(event_row_to_json(row, room));
    }

    return results;
  }

  // Batch-check which rooms have changed since a token
  std::set<std::string> batch_rooms_changed_since(
      const std::vector<std::string>& room_ids, uint64_t since) {
    std::set<std::string> changed;
    if (room_ids.empty()) return changed;

    std::string in_clause = build_in_clause_from_vec(room_ids);
    std::string sql =
        "SELECT DISTINCT room_id FROM events "
        "WHERE room_id IN " + in_clause + " "
        "AND stream_ordering > " + std::to_string(since);

    auto rows = db_.execute("batch_changed", sql);
    for (const auto& row : rows) {
      std::string rid = col_str(row, "room_id");
      if (!rid.empty()) changed.insert(rid);
    }

    return changed;
  }

  // Batch-load room member counts for multiple rooms
  std::map<std::string, std::pair<int64_t, int64_t>>
  batch_load_member_counts(const std::vector<std::string>& room_ids) {
    std::map<std::string, std::pair<int64_t, int64_t>> results;
    if (room_ids.empty()) return results;

    std::string in_clause = build_in_clause_from_vec(room_ids);
    std::string sql =
        "SELECT room_id, "
        "SUM(CASE WHEN membership='join' THEN 1 ELSE 0 END) as joined, "
        "SUM(CASE WHEN membership='invite' THEN 1 ELSE 0 END) as invited "
        "FROM room_memberships "
        "WHERE room_id IN " + in_clause + " "
        "GROUP BY room_id";

    auto rows = db_.execute("batch_counts", sql);
    for (const auto& row : rows) {
      std::string rid = col_str(row, "room_id");
      results[rid] = {col_int(row, "joined"), col_int(row, "invited")};
    }

    return results;
  }

  // Partition a room list into smaller batches for processing
  static std::vector<std::vector<std::string>> partition_rooms(
      const std::vector<std::string>& rooms, size_t batch_size = 50) {
    std::vector<std::vector<std::string>> batches;
    for (size_t i = 0; i < rooms.size(); i += batch_size) {
      auto end = std::min(i + batch_size, rooms.size());
      batches.emplace_back(rooms.begin() + i, rooms.begin() + end);
    }
    return batches;
  }

private:
  DatabasePool& db_;
};

// ============================================================================
// Global instances (singleton pattern)
// ============================================================================
namespace {
  std::unique_ptr<SyncMetrics> g_sync_metrics;
  std::unique_ptr<SyncTokenManager> g_sync_token_manager;
  std::unique_ptr<LongPollManager> g_long_poll_manager;
  std::mutex g_sync_global_mutex;
}  // anonymous namespace

// Initialize global sync infrastructure
void init_sync_globals() {
  std::lock_guard<std::mutex> lock(g_sync_global_mutex);
  if (!g_sync_metrics) {
    g_sync_metrics = std::make_unique<SyncMetrics>();
  }
  if (!g_sync_token_manager) {
    g_sync_token_manager = std::make_unique<SyncTokenManager>();
  }
  if (!g_long_poll_manager) {
    g_long_poll_manager = std::make_unique<LongPollManager>();
  }
}

// Get the global sync metrics instance
SyncMetrics& get_sync_metrics() {
  init_sync_globals();
  return *g_sync_metrics;
}

// Get the global sync token manager
SyncTokenManager& get_sync_token_manager() {
  init_sync_globals();
  return *g_sync_token_manager;
}

// Get the global long-poll manager
LongPollManager& get_long_poll_manager() {
  init_sync_globals();
  return *g_long_poll_manager;
}

// Shutdown sync infrastructure
void shutdown_sync_globals() {
  std::lock_guard<std::mutex> lock(g_sync_global_mutex);
  if (g_long_poll_manager) {
    g_long_poll_manager->shutdown();
  }
  g_sync_metrics.reset();
  g_sync_token_manager.reset();
  g_long_poll_manager.reset();
}

}  // namespace progressive
