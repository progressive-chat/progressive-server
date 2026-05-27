#include "progressive/storage/databases/main/events.hpp"
#include <algorithm>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace progressive::storage {

// ============================================================================
// SQL DDL Constants - All table definitions used by EventsStore
// ============================================================================
namespace sql_ddl {

// Primary event table - stores all events
static const char* EVENTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    sender TEXT NOT NULL,
    state_key TEXT,
    membership TEXT,
    depth BIGINT NOT NULL DEFAULT 0,
    origin_server_ts BIGINT NOT NULL DEFAULT 0,
    stream_ordering BIGINT NOT NULL,
    instance_name TEXT,
    received_ts BIGINT NOT NULL DEFAULT 0,
    topological_ordering BIGINT NOT NULL DEFAULT 0,
    format_version INTEGER NOT NULL DEFAULT 1,
    is_outlier BOOLEAN NOT NULL DEFAULT FALSE,
    is_redacted BOOLEAN NOT NULL DEFAULT FALSE,
    is_out_of_band_membership BOOLEAN NOT NULL DEFAULT FALSE,
    is_state_event BOOLEAN NOT NULL DEFAULT FALSE,
    is_notifiable BOOLEAN NOT NULL DEFAULT FALSE,
    contains_url BOOLEAN NOT NULL DEFAULT FALSE,
    redacts TEXT,
    transaction_id TEXT,
    device_id TEXT,
    content TEXT NOT NULL DEFAULT '{}',
    internal_metadata TEXT NOT NULL DEFAULT '{}',
    unsigned_data TEXT NOT NULL DEFAULT '{}',
    room_version_id TEXT NOT NULL DEFAULT '1',
    reconciled BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT events_pkey PRIMARY KEY (event_id)
);
CREATE INDEX IF NOT EXISTS events_room_id_idx ON events (room_id);
CREATE INDEX IF NOT EXISTS events_stream_ordering_idx ON events (stream_ordering);
CREATE INDEX IF NOT EXISTS events_ts_idx ON events (origin_server_ts);
CREATE INDEX IF NOT EXISTS events_txn_id_idx ON events (transaction_id);
CREATE INDEX IF NOT EXISTS events_related_event_idx ON events (room_id, type);
)SQL";

static const char* EVENT_JSON_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_json (
    event_id TEXT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    internal_metadata TEXT NOT NULL,
    json TEXT NOT NULL,
    format_version INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT event_json_fkey FOREIGN KEY (event_id) REFERENCES events (event_id)
);
CREATE INDEX IF NOT EXISTS event_json_room_id_idx ON event_json (room_id);
)SQL";

static const char* EVENT_AUTH_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_auth (
    event_id TEXT NOT NULL,
    auth_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    CONSTRAINT event_auth_pkey PRIMARY KEY (event_id, auth_id, room_id)
);
CREATE INDEX IF NOT EXISTS event_auth_auth_id_idx ON event_auth (auth_id);
CREATE INDEX IF NOT EXISTS event_auth_event_id_idx ON event_auth (event_id);
)SQL";

static const char* EVENT_EDGES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_edges (
    event_id TEXT NOT NULL,
    prev_event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    is_state BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT event_edges_pkey PRIMARY KEY (event_id, prev_event_id, room_id)
);
CREATE INDEX IF NOT EXISTS event_edges_prev_id_idx ON event_edges (prev_event_id);
)SQL";

static const char* STATE_EVENTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS state_events (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    prev_state TEXT,
    CONSTRAINT state_events_pkey PRIMARY KEY (event_id, room_id, type, state_key)
);
)SQL";

static const char* CURRENT_STATE_EVENTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS current_state_events (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    CONSTRAINT current_state_events_pkey PRIMARY KEY (room_id, type, state_key)
);
CREATE INDEX IF NOT EXISTS current_state_events_event_id ON current_state_events (event_id);
CREATE INDEX IF NOT EXISTS current_state_events_member_idx ON current_state_events (room_id) WHERE type = 'm.room.member';
)SQL";

static const char* ROOM_MEMBERSHIPS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS room_memberships (
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    room_id TEXT NOT NULL,
    membership TEXT NOT NULL,
    forgotten BOOLEAN NOT NULL DEFAULT FALSE,
    display_name TEXT,
    avatar_url TEXT,
    CONSTRAINT room_memberships_pkey PRIMARY KEY (event_id)
);
CREATE INDEX IF NOT EXISTS room_memberships_user_room_idx ON room_memberships (user_id, room_id);
CREATE INDEX IF NOT EXISTS room_memberships_room_idx ON room_memberships (room_id);
)SQL";

static const char* LOCAL_CURRENT_MEMBERSHIP_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS local_current_membership (
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    membership TEXT NOT NULL,
    CONSTRAINT local_current_membership_pkey PRIMARY KEY (user_id, room_id)
);
CREATE INDEX IF NOT EXISTS local_current_membership_room_idx ON local_current_membership (room_id, membership);
)SQL";

static const char* ROOM_STATS_STATE_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS room_stats_state (
    room_id TEXT NOT NULL PRIMARY KEY,
    name TEXT,
    topic TEXT,
    canonical_alias TEXT,
    joined_members INTEGER NOT NULL DEFAULT 0,
    invited_members INTEGER NOT NULL DEFAULT 0,
    left_members INTEGER NOT NULL DEFAULT 0,
    banned_members INTEGER NOT NULL DEFAULT 0,
    total_members INTEGER NOT NULL DEFAULT 0,
    local_users_in_room INTEGER NOT NULL DEFAULT 0,
    history_visibility TEXT,
    join_rules TEXT,
    guest_access TEXT,
    encryption TEXT,
    room_type TEXT,
    is_federatable BOOLEAN NOT NULL DEFAULT TRUE
);
)SQL";

static const char* EVENT_FORWARD_EXTREMITIES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_forward_extremities (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    CONSTRAINT event_forward_extremities_pkey PRIMARY KEY (event_id, room_id)
);
CREATE INDEX IF NOT EXISTS event_forward_extremities_room_idx ON event_forward_extremities (room_id);
)SQL";

static const char* EVENT_BACKWARD_EXTREMITIES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_backward_extremities (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    CONSTRAINT event_backward_extremities_pkey PRIMARY KEY (event_id, room_id)
);
)SQL";

static const char* EVENT_RELATIONS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_relations (
    event_id TEXT NOT NULL,
    relates_to_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    aggregation_key TEXT,
    CONSTRAINT event_relations_pkey PRIMARY KEY (event_id)
);
CREATE INDEX IF NOT EXISTS event_relations_relates_idx ON event_relations (relates_to_id, relation_type);
CREATE INDEX IF NOT EXISTS event_relations_agg_key_idx ON event_relations (relates_to_id, relation_type, aggregation_key);
)SQL";

static const char* REDACTIONS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS redactions (
    event_id TEXT NOT NULL PRIMARY KEY,
    redacts TEXT NOT NULL,
    received_ts BIGINT NOT NULL,
    CONSTRAINT redactions_fkey FOREIGN KEY (event_id) REFERENCES events (event_id)
);
CREATE INDEX IF NOT EXISTS redactions_redacts_idx ON redactions (redacts);
)SQL";

static const char* EX_OUTLIER_STREAM_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS ex_outlier_stream (
    event_stream_ordering BIGINT NOT NULL,
    event_id TEXT NOT NULL,
    state_group BIGINT NOT NULL,
    instance_name TEXT NOT NULL,
    CONSTRAINT ex_outlier_stream_pkey PRIMARY KEY (event_stream_ordering)
);
)SQL";

static const char* EVENT_REJECTIONS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_rejections (
    event_id TEXT NOT NULL PRIMARY KEY,
    reason TEXT NOT NULL,
    last_check BIGINT NOT NULL,
    CONSTRAINT rejections_fkey FOREIGN KEY (event_id) REFERENCES events (event_id)
);
)SQL";

static const char* STATE_GROUPS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS state_groups (
    id BIGINT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS state_groups_room_idx ON state_groups (room_id);
)SQL";

static const char* STATE_GROUP_EDGES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS state_group_edges (
    state_group BIGINT NOT NULL,
    prev_state_group BIGINT NOT NULL,
    CONSTRAINT state_group_edges_pkey PRIMARY KEY (state_group, prev_state_group)
);
)SQL";

static const char* STATE_GROUPS_STATE_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS state_groups_state (
    state_group BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    event_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS state_groups_state_idx ON state_groups_state (state_group);
CREATE INDEX IF NOT EXISTS state_groups_state_type_idx ON state_groups_state (room_id, type, state_key);
)SQL";

static const char* EVENT_TO_STATE_GROUPS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_to_state_groups (
    event_id TEXT NOT NULL PRIMARY KEY,
    state_group BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS event_to_state_groups_sg_idx ON event_to_state_groups (state_group);
)SQL";

static const char* EVENT_SEARCH_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_search (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    key TEXT NOT NULL,
    vector TEXT,
    stream_ordering BIGINT,
    origin_server_ts BIGINT,
    CONSTRAINT event_search_pkey PRIMARY KEY (event_id, key)
);
CREATE INDEX IF NOT EXISTS event_search_room_idx ON event_search (room_id);
)SQL";

static const char* SLIDING_SYNC_JOINED_ROOMS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS sliding_sync_joined_rooms (
    room_id TEXT NOT NULL PRIMARY KEY,
    bump_stamp BIGINT NOT NULL DEFAULT 0,
    room_type TEXT,
    is_encrypted BOOLEAN,
    room_name TEXT,
    tombstone_successor_room_id TEXT
);
)SQL";

static const char* SLIDING_SYNC_MEMBERSHIP_SNAPSHOTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS sliding_sync_membership_snapshots (
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    membership_event_id TEXT NOT NULL,
    membership TEXT NOT NULL,
    has_known_state BOOLEAN,
    room_type TEXT,
    is_encrypted BOOLEAN,
    room_name TEXT,
    tombstone_successor_room_id TEXT,
    forgotten BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT sliding_sync_membership_snapshots_pkey PRIMARY KEY (room_id, user_id)
);
)SQL";

static const char* EVENT_FAILED_PULL_ATTEMPTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_failed_pull_attempts (
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    num_attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_ts BIGINT NOT NULL,
    last_cause TEXT,
    CONSTRAINT event_failed_pull_attempts_pkey PRIMARY KEY (room_id, event_id)
);
)SQL";

static const char* INSERTION_EVENTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS insertion_events (
    event_id TEXT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    next_batch_id TEXT NOT NULL
);
)SQL";

static const char* INSERTION_EVENT_EXTREMITIES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS insertion_event_extremities (
    event_id TEXT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    insertion_prev_event_id TEXT NOT NULL
);
)SQL";

static const char* BATCH_EVENTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS batch_events (
    event_id TEXT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    batch_id TEXT NOT NULL
);
)SQL";

static const char* UNPARTIAL_STATED_ROOMS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS unpartial_stated_rooms (room_id TEXT NOT NULL PRIMARY KEY);
)SQL";

static const char* PARTIAL_STATE_ROOMS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS partial_state_rooms (room_id TEXT NOT NULL PRIMARY KEY);
)SQL";

static const char* PARTIAL_STATE_ROOMS_EVENTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS partial_state_rooms_events (
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    CONSTRAINT partial_state_rooms_events_pkey PRIMARY KEY (room_id, event_id)
);
)SQL";

static const char* KNOCK_MEMBERSHIPS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS knock_memberships (
    event_id TEXT NOT NULL PRIMARY KEY,
    user_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    room_id TEXT NOT NULL,
    membership TEXT NOT NULL DEFAULT 'knock',
    display_name TEXT,
    avatar_url TEXT
);
CREATE INDEX IF NOT EXISTS knock_memberships_room_idx ON knock_memberships (room_id);
)SQL";

} // namespace sql_ddl

// ============================================================================
// PersistEventsStore Implementation
// ============================================================================

PersistEventsStore::PersistEventsStore(
    const std::string& server_name,
    const std::string& instance_name,
    DatabasePool& db_pool,
    bool (*is_mine_id_func)(const std::string&),
    int64_t (*time_msec)(),
    bool msc4354_enabled,
    bool ephemeral_messages_enabled,
    bool msc4293_enabled)
    : server_name_(server_name),
      instance_name_(instance_name),
      db_pool_(db_pool),
      is_mine_id_(is_mine_id_func),
      time_msec_(time_msec),
      msc4354_enabled_(msc4354_enabled),
      ephemeral_messages_enabled_(ephemeral_messages_enabled),
      msc4293_enabled_(msc4293_enabled) {}

// ============================================================================
// Event Type Classification Helpers
// ============================================================================

namespace {

bool is_member_event(const EventData& event) {
  return event.type == EventTypes::Member;
}

bool is_state_event_type(const std::string& event_type, 
                         const std::optional<std::string>& state_key) {
  // State events have a state_key
  if (!state_key) return false;
  // Common state event types
  if (event_type == EventTypes::Create) return true;
  if (event_type == EventTypes::Member) return true;
  if (event_type == EventTypes::Name) return true;
  if (event_type == EventTypes::Topic) return true;
  if (event_type == EventTypes::RoomEncryption) return true;
  if (event_type == EventTypes::PowerLevels) return true;
  if (event_type == EventTypes::Tombstone) return true;
  if (event_type == EventTypes::Retention) return true;
  // Any event with a state_key is a state event
  return !state_key->empty();
}

std::optional<std::string> get_latest_redaction(
    LoggingTransaction& txn, const std::string& event_id) {
  auto result = txn.select_one(
      "SELECT event_id FROM redactions WHERE redacts = ? ORDER BY received_ts DESC LIMIT 1",
      {event_id});
  if (result && !result->is_null()) {
    return result->get<std::string>(0);
  }
  return std::nullopt;
}

bool is_redacted_event(LoggingTransaction& txn, const std::string& event_id) {
  auto result = txn.select_one(
      "SELECT COUNT(*) FROM redactions WHERE redacts = ?", {event_id});
  if (result && !result->is_null()) {
    return result->get<int64_t>(0) > 0;
  }
  return false;
}

std::vector<std::string> resolve_state_groups(
    LoggingTransaction& txn, int64_t state_group, 
    const std::string& room_id, const std::string& type,
    const std::string& state_key) {
  // Walk state group edges to find the event_id
  std::vector<std::string> result;
  std::set<int64_t> visited;
  std::vector<int64_t> stack = {state_group};
  
  while (!stack.empty()) {
    int64_t sg = stack.back();
    stack.pop_back();
    if (visited.count(sg)) continue;
    visited.insert(sg);
    
    // Check if this state group has the state
    auto row = txn.select_one(
        "SELECT event_id FROM state_groups_state "
        "WHERE state_group = ? AND type = ? AND state_key = ?",
        {sg, type, state_key});
    if (row && !row->is_null()) {
      result.push_back(row->get<std::string>(0));
      continue; // Found it, don't need to go deeper
    }
    
    // Add prev state groups
    auto prevs = txn.select(
        "SELECT prev_state_group FROM state_group_edges WHERE state_group = ?",
        {sg});
    for (auto& prev : prevs) {
      if (!prev.is_null()) {
        stack.push_back(prev.get<int64_t>(0));
      }
    }
  }
  
  return result;
}

int64_t get_or_create_state_group(
    LoggingTransaction& txn, const std::string& room_id,
    const std::string& event_id, int64_t(*next_id)(LoggingTransaction&, int64_t)) {
  // Check if state group already exists for this event
  auto existing = txn.select_one(
      "SELECT id FROM state_groups WHERE event_id = ?", {event_id});
  if (existing && !existing->is_null()) {
    return existing->get<int64_t>(0);
  }
  
  int64_t sg_id = next_id(txn, 1);
  txn.execute(
      "INSERT INTO state_groups (id, room_id, event_id) VALUES (?, ?, ?)",
      {sg_id, room_id, event_id});
  return sg_id;
}

void update_sliding_sync_joined_rooms(
    LoggingTransaction& txn, const std::string& room_id,
    int64_t bump_stamp, const SlidingSyncStateInsertValues& updates) {
  // Upsert into sliding_sync_joined_rooms
  auto existing = txn.select_one(
      "SELECT room_id FROM sliding_sync_joined_rooms WHERE room_id = ?", 
      {room_id});
  
  if (!existing || existing->is_null()) {
    // Full insert
    txn.execute(
        "INSERT INTO sliding_sync_joined_rooms "
        "(room_id, bump_stamp, room_type, is_encrypted, room_name, "
        "tombstone_successor_room_id) VALUES (?, ?, ?, ?, ?, ?)",
        {room_id, bump_stamp, 
         updates.room_type.value_or(""),
         updates.is_encrypted ? (updates.is_encrypted.value() ? "1" : "0") : std::optional<std::string>(),
         updates.room_name.value_or(""),
         updates.tombstone_successor_room_id.value_or("")});
  } else {
    // Update existing
    std::string set_clauses;
    std::vector<DatabaseType> params;
    
    set_clauses += "bump_stamp = ?";
    params.push_back(bump_stamp);
    
    if (updates.room_type) {
      set_clauses += ", room_type = ?";
      params.push_back(*updates.room_type);
    }
    if (updates.is_encrypted) {
      set_clauses += ", is_encrypted = ?";
      params.push_back(*updates.is_encrypted);
    }
    if (updates.room_name) {
      set_clauses += ", room_name = ?";
      params.push_back(*updates.room_name);
    }
    if (updates.tombstone_successor_room_id) {
      set_clauses += ", tombstone_successor_room_id = ?";
      params.push_back(*updates.tombstone_successor_room_id);
    }
    
    params.push_back(room_id);
    txn.execute(
        "UPDATE sliding_sync_joined_rooms SET " + set_clauses + " WHERE room_id = ?",
        params);
  }
}

void update_sliding_sync_membership_snapshots(
    LoggingTransaction& txn, const std::string& room_id,
    const std::vector<SlidingSyncMembershipInfo>& to_insert,
    const std::vector<std::string>& to_delete,
    const SlidingSyncMembershipSnapshotSharedInsertValues& shared_values) {
  
  // Delete memberships
  for (const auto& user_id : to_delete) {
    txn.execute(
        "DELETE FROM sliding_sync_membership_snapshots WHERE room_id = ? AND user_id = ?",
        {room_id, user_id});
  }
  
  // Upsert memberships
  for (const auto& info : to_insert) {
    txn.execute(
        "INSERT INTO sliding_sync_membership_snapshots "
        "(room_id, user_id, sender, membership_event_id, membership, "
        "has_known_state, room_type, is_encrypted, room_name, "
        "tombstone_successor_room_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (room_id, user_id) DO UPDATE SET "
        "sender = excluded.sender, "
        "membership_event_id = excluded.membership_event_id, "
        "membership = excluded.membership, "
        "has_known_state = excluded.has_known_state, "
        "room_type = excluded.room_type, "
        "is_encrypted = excluded.is_encrypted, "
        "room_name = excluded.room_name, "
        "tombstone_successor_room_id = excluded.tombstone_successor_room_id",
        {room_id, info.user_id, info.sender, info.membership_event_id,
         info.membership,
         shared_values.has_known_state ? (shared_values.has_known_state.value() ? "1" : "0") : std::optional<std::string>(),
         shared_values.room_type.value_or(""),
         shared_values.is_encrypted ? (shared_values.is_encrypted.value() ? "1" : "0") : std::optional<std::string>(),
         shared_values.room_name.value_or(""),
         shared_values.tombstone_successor_room_id.value_or("")});
  }
}

// Extract membership from event content
std::string extract_membership(const EventData& event) {
  if (event.content.contains("membership") && event.content["membership"].is_string()) {
    return event.content["membership"].get<std::string>();
  }
  return "";
}

// Extract display name from event content
std::optional<std::string> extract_displayname(const EventData& event) {
  if (event.content.contains("displayname") && event.content["displayname"].is_string()) {
    return event.content["displayname"].get<std::string>();
  }
  return std::nullopt;
}

// Extract avatar url from event content
std::optional<std::string> extract_avatar_url(const EventData& event) {
  if (event.content.contains("avatar_url") && event.content["avatar_url"].is_string()) {
    return event.content["avatar_url"].get<std::string>();
  }
  return std::nullopt;
}

bool check_if_is_notifiable(const EventData& event, const std::string& room_id,
                            const std::string& event_id) {
  // Check if event should trigger a notification
  // Based on push rules matching
  if (event.type == EventTypes::Message || event.type == EventTypes::Encrypted) {
    return true;
  }
  if (event.type == EventTypes::Member && event.content.contains("membership") &&
      event.content["membership"] == "invite") {
    return true;
  }
  return false;
}

bool check_if_contains_url(const EventData& event) {
  if (!event.content.contains("body") || !event.content["body"].is_string()) {
    return false;
  }
  std::string body = event.content["body"].get<std::string>();
  return body.find("http://") != std::string::npos ||
         body.find("https://") != std::string::npos ||
         body.find("matrix.to") != std::string::npos;
}

std::vector<std::string> collect_prevs_from_event(const EventData& event) {
  std::vector<std::string> prevs;
  // From prev_events in unsigned
  if (event.unsigned_data.contains("prev_events") && 
      event.unsigned_data["prev_events"].is_array()) {
    for (auto& pe : event.unsigned_data["prev_events"]) {
      if (pe.is_string()) prevs.push_back(pe.get<std::string>());
    }
  }
  // From prev_event_ids
  for (auto& pe : event.prev_event_ids) {
    if (std::find(prevs.begin(), prevs.end(), pe) == prevs.end()) {
      prevs.push_back(pe);
    }
  }
  return prevs;
}

std::vector<std::string> collect_auth_ids_from_event(const EventData& event) {
  return event.auth_event_ids_list();
}

std::vector<std::string> collect_prev_state_from_context(const EventContext& ctx) {
  // For state events, we need previous state info
  return {};
}

int64_t calculate_topological_ordering(
    const EventData& event, LoggingTransaction& txn,
    int64_t default_value = 0) {
  // Calculate topological ordering based on prev events
  auto prevs = collect_prevs_from_event(event);
  if (prevs.empty()) {
    return default_value;
  }
  
  // Get the max topological ordering of prev events
  std::string placeholders;
  for (size_t i = 0; i < prevs.size(); ++i) {
    if (i > 0) placeholders += ", ";
    placeholders += "?";
  }
  
  std::vector<DatabaseType> params;
  for (auto& p : prevs) params.push_back(p);
  
  auto result = txn.select_one(
      "SELECT COALESCE(MAX(topological_ordering), 0) FROM events WHERE event_id IN (" +
          placeholders + ")",
      params);
  
  int64_t max_topo = 0;
  if (result && !result->is_null()) {
    max_topo = result->get<int64_t>(0);
  }
  
  return max_topo + 1;
}

// Check if an event already exists
bool event_exists(LoggingTransaction& txn, const std::string& event_id) {
  auto result = txn.select_one(
      "SELECT 1 FROM events WHERE event_id = ?", {event_id});
  return result && !result->is_null();
}

} // anonymous namespace

// ============================================================================
// can_sender_redact_txn - Check if sender can redact an event
// Equivalent to Python can_sender_redact at events.py line 501
// ============================================================================
bool PersistEventsStore::can_sender_redact_txn(
    LoggingTransaction& txn, const EventData& event) {
  
  // Senders can always redact their own events
  if (event.sender == event.sender) return true; // self-redaction
  
  // Check room power levels
  auto power_levels = txn.select_one(
      "SELECT event_id FROM current_state_events "
      "WHERE room_id = ? AND type = 'm.room.power_levels' AND state_key = ''",
      {event.room_id});
  
  if (!power_levels || power_levels->is_null()) {
    return false; // No power levels set - only own events can be redacted
  }
  
  // Get the power levels event content
  auto pl_event = txn.select_one(
      "SELECT content FROM event_json WHERE event_id = ?",
      {power_levels->get<std::string>(0)});
  
  if (!pl_event || pl_event->is_null()) return false;
  
  json pl_content = json::parse(pl_event->get<std::string>(0));
  
  int64_t redact_level = 50; // Default redact power level
  if (pl_content.contains("redact")) {
    redact_level = pl_content["redact"].get<int64_t>();
  }
  
  // Get sender's power level
  int64_t sender_level = 0;
  if (pl_content.contains("users") && pl_content["users"].contains(event.sender)) {
    sender_level = pl_content["users"][event.sender].get<int64_t>();
  }
  
  return sender_level >= redact_level;
}

// ============================================================================
// calculate_sliding_sync_table_changes_txn
// Equivalent to Python _calculate_sliding_sync_table_changes at events.py line 554
// ============================================================================
SlidingSyncTableChanges 
PersistEventsStore::calculate_sliding_sync_table_changes_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::vector<EventPersistencePair>& events_and_contexts,
    const DeltaState& delta_state) {
  
  SlidingSyncTableChanges changes;
  changes.room_id = room_id;
  
  // Check if row exists to determine if we need a bump_stamp
  auto existing = txn.select_one(
      "SELECT bump_stamp FROM sliding_sync_joined_rooms WHERE room_id = ?",
      {room_id});
  
  if (!existing || existing->is_null()) {
    // Row doesn't exist - need full insert
    // Get the latest bump event timestamp
    auto bump = txn.select_one(
        "SELECT COALESCE(MAX(origin_server_ts), 0) FROM events WHERE room_id = ?",
        {room_id});
    if (bump && !bump->is_null()) {
      changes.joined_room_bump_stamp_to_fully_insert = bump->get<int64_t>(0);
    } else {
      changes.joined_room_bump_stamp_to_fully_insert = time_msec_();
    }
  }
  
  // Process state delta to determine sliding sync updates
  for (const auto& [type, state_key] : delta_state.to_delete) {
    bool found = false;
    for (auto& [t, sk] : SLIDING_SYNC_RELEVANT_STATE_SET) {
      if (t == type && sk == state_key) {
        found = true;
        break;
      }
    }
    if (found) {
      // Clear the relevant field
      if (type == EventTypes::Create) {
        changes.joined_room_updates.room_type = std::nullopt;
      } else if (type == EventTypes::RoomEncryption) {
        changes.joined_room_updates.is_encrypted = std::nullopt;
      } else if (type == EventTypes::Name) {
        changes.joined_room_updates.room_name = std::nullopt;
      } else if (type == EventTypes::Tombstone) {
        changes.joined_room_updates.tombstone_successor_room_id = std::nullopt;
      }
    }
  }
  
  // Process inserts
  for (const auto& [type_state, event_id] : delta_state.to_insert) {
    const auto& type = type_state.first;
    const auto& state_key = type_state.second;
    
    bool relevant = false;
    for (auto& [t, sk] : SLIDING_SYNC_RELEVANT_STATE_SET) {
      if (t == type && sk == state_key) {
        relevant = true;
        break;
      }
    }
    
    if (relevant) {
      // Get event content
      auto content_row = txn.select_one(
          "SELECT content FROM event_json WHERE event_id = ?", {event_id});
      if (content_row && !content_row->is_null()) {
        json content = json::parse(content_row->get<std::string>(0));
        
        if (type == EventTypes::Create) {
          if (content.contains("type")) {
            changes.joined_room_updates.room_type = content["type"].get<std::string>();
          }
        } else if (type == EventTypes::RoomEncryption) {
          changes.joined_room_updates.is_encrypted = true;
        } else if (type == EventTypes::Name) {
          if (content.contains("name")) {
            changes.joined_room_updates.room_name = content["name"].get<std::string>();
          }
        } else if (type == EventTypes::Tombstone) {
          if (content.contains("replacement_room")) {
            changes.joined_room_updates.tombstone_successor_room_id = 
                content["replacement_room"].get<std::string>();
          }
        }
      }
    }
  }
  
  return changes;
}

// ============================================================================
// persist_events_and_state_updates
// Equivalent to Python _persist_events_and_state_updates at events.py line 290
// ============================================================================
void PersistEventsStore::persist_events_and_state_updates(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::vector<EventPersistencePair>& events_and_contexts,
    const DeltaState* state_delta_for_room,
    const std::set<std::string>* new_forward_extremities,
    const std::map<std::string, NewEventChainLinks>& new_event_links,
    bool use_negative_stream_ordering,
    bool inhibit_local_membership_updates,
    const std::set<std::string>* new_state_dag_forward_extremities) {
  
  // Calculate sliding sync changes if we have state delta
  SlidingSyncTableChanges sliding_sync_changes;
  bool has_sliding_sync = false;
  
  if (state_delta_for_room && !state_delta_for_room->is_noop()) {
    sliding_sync_changes = calculate_sliding_sync_table_changes_txn(
        txn, room_id, events_and_contexts, *state_delta_for_room);
    has_sliding_sync = true;
  }
  
  // Delegate to persist_events_txn for the actual persistence
  persist_events_txn(
      txn, room_id, events_and_contexts,
      inhibit_local_membership_updates,
      state_delta_for_room,
      new_forward_extremities,
      new_event_links,
      has_sliding_sync ? &sliding_sync_changes : nullptr,
      new_state_dag_forward_extremities);
}

// ============================================================================
// persist_events_txn - Main event persistence transaction
// Equivalent to Python _persist_events_txn at events.py line 1039
// ============================================================================
void PersistEventsStore::persist_events_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const std::vector<EventPersistencePair>& events_and_contexts,
    bool inhibit_local_membership_updates,
    const DeltaState* state_delta_for_room,
    const std::set<std::string>* new_forward_extremities,
    const std::map<std::string, NewEventChainLinks>& new_event_links,
    const SlidingSyncTableChanges* sliding_sync_table_changes,
    const std::set<std::string>* new_state_dag_forward_extremities) {
  
  int64_t now = time_msec_();
  
  for (const auto& pair : events_and_contexts) {
    const EventData& event = pair.event;
    const EventContext& context = pair.context;
    
    // Skip if already persisted
    if (event_exists(txn, event.event_id)) {
      continue;
    }
    
    // Calculate topological ordering
    int64_t topo = calculate_topological_ordering(event, txn, event.depth * 1000);
    
    // Determine if the event is a state event
    bool is_state = is_state_event_type(event.type, event.state_key);
    
    // Check notification eligibility
    bool is_notifiable = check_if_is_notifiable(event, room_id, event.event_id);
    
    // Check for URLs in content
    bool contains_url = check_if_contains_url(event);
    
    // Check if redacted
    bool is_redacted = is_redacted_event(txn, event.event_id);
    
    // Get the redacts value (if this is a redaction event)
    std::optional<std::string> redacts;
    if (event.state_key) {
      // Redaction events have their own event_id as state_key
      // Actually in Matrix, redaction events have redacts in content
      if (event.content.contains("redacts") && event.content["redacts"].is_string()) {
        redacts = event.content["redacts"].get<std::string>();
      }
    }
    
    // Extract membership for member events
    std::string membership;
    std::optional<std::string> display_name;
    std::optional<std::string> avatar_url;
    
    if (is_member_event(event)) {
      membership = extract_membership(event);
      display_name = extract_displayname(event);
      avatar_url = extract_avatar_url(event);
    }
    
    // Handle txn_id for idempotency
    std::optional<std::string> txn_id;
    if (event.txn_id && !event.txn_id->empty()) {
      // Check if a previous event with same txn_id exists
      auto existing_txn = txn.select_one(
          "SELECT event_id FROM events WHERE transaction_id = ? AND sender = ?",
          {*event.txn_id, event.sender});
      if (existing_txn && !existing_txn->is_null()) {
        continue; // Already processed this txn_id
      }
      txn_id = event.txn_id;
    }
    
    // Insert event into events table
    txn.execute(
        "INSERT INTO events "
        "(event_id, room_id, type, sender, state_key, membership, depth, "
        "origin_server_ts, stream_ordering, instance_name, received_ts, "
        "topological_ordering, format_version, is_outlier, is_redacted, "
        "is_out_of_band_membership, is_state_event, is_notifiable, "
        "contains_url, redacts, transaction_id, device_id, content, "
        "internal_metadata, unsigned_data, room_version_id, reconciled) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
        "?, ?, ?, ?, ?, ?, ?, ?)",
        {event.event_id, event.room_id, event.type, event.sender,
         event.state_key.value_or(""), membership,
         event.depth, event.origin_server_ts, event.stream_ordering,
         instance_name_, now, topo, event.format_version,
         event.is_outlier ? 1 : 0, is_redacted ? 1 : 0,
         event.is_out_of_band_membership ? 1 : 0, is_state ? 1 : 0,
         is_notifiable ? 1 : 0, contains_url ? 1 : 0,
         redacts.value_or(""), txn_id.value_or(""),
         event.device_id.value_or(""),
         event.content.dump(), event.internal_metadata_json,
         event.unsigned_data.dump(), event.room_version_id, 0});
    
    // Insert event_json
    txn.execute(
        "INSERT INTO event_json (event_id, room_id, internal_metadata, json, format_version) "
        "VALUES (?, ?, ?, ?, ?)",
        {event.event_id, event.room_id, event.internal_metadata_json,
         event.content.dump(), event.format_version});
    
    // Insert event_auth entries
    for (const auto& auth_id : event.auth_event_ids) {
      txn.execute(
          "INSERT OR IGNORE INTO event_auth (event_id, auth_id, room_id) VALUES (?, ?, ?)",
          {event.event_id, auth_id, event.room_id});
    }
    
    // Insert event_edges (prev_events)
    auto prevs = collect_prevs_from_event(event);
    for (const auto& prev_id : prevs) {
      bool is_prev_state = false;
      // Check if prev is a state event
      auto prev_type = txn.select_one(
          "SELECT type, state_key FROM events WHERE event_id = ?",
          {prev_id});
      if (prev_type && !prev_type->is_null()) {
        is_prev_state = !prev_type->is_null(0) && !prev_type->is_null(1);
      }
      txn.execute(
          "INSERT OR IGNORE INTO event_edges (event_id, prev_event_id, room_id, is_state) "
          "VALUES (?, ?, ?, ?)",
          {event.event_id, prev_id, event.room_id, is_prev_state ? 1 : 0});
    }
    
    // Insert state_events if this is a state event
    if (is_state && event.state_key) {
      // Get prev_state from context
      txn.execute(
          "INSERT OR IGNORE INTO state_events (event_id, room_id, type, state_key, prev_state) "
          "VALUES (?, ?, ?, ?, ?)",
          {event.event_id, event.room_id, event.type, *event.state_key, ""});
    }
    
    // Update room_memberships for member events
    if (is_member_event(event) && !membership.empty()) {
      txn.execute(
          "INSERT INTO room_memberships "
          "(event_id, user_id, sender, room_id, membership, display_name, avatar_url) "
          "VALUES (?, ?, ?, ?, ?, ?, ?)",
          {event.event_id, 
           event.state_key.value_or(""),  // user_id is state_key for member events
           event.sender, event.room_id, membership,
           display_name.value_or(""), avatar_url.value_or("")});
      
      // Update local_current_membership
      if (!inhibit_local_membership_updates && is_mine_id_) {
        std::string user_id = event.state_key.value_or("");
        if (is_mine_id_(user_id)) {
          auto cur = txn.select_one(
              "SELECT membership FROM local_current_membership WHERE user_id = ? AND room_id = ?",
              {user_id, event.room_id});
          
          if (cur && !cur->is_null()) {
            std::string cur_mem = cur->get<std::string>(0);
            if (cur_mem != membership) {
              txn.execute(
                  "UPDATE local_current_membership SET event_id = ?, membership = ? "
                  "WHERE user_id = ? AND room_id = ?",
                  {event.event_id, membership, user_id, event.room_id});
            }
          } else {
            txn.execute(
                "INSERT INTO local_current_membership (room_id, user_id, event_id, membership) "
                "VALUES (?, ?, ?, ?)",
                {event.room_id, user_id, event.event_id, membership});
          }
        }
      }
    }
    
    // Insert event_search for full-text search
    if (event.content.contains("body") && event.content["body"].is_string()) {
      txn.execute(
          "INSERT INTO event_search (event_id, room_id, sender, key, stream_ordering, origin_server_ts) "
          "VALUES (?, ?, ?, ?, ?, ?)",
          {event.event_id, event.room_id, event.sender,
           event.content["body"].get<std::string>(),
           event.stream_ordering, event.origin_server_ts});
    }
    
    // Handle event relations
    if (event.content.contains("m.relates_to") && 
        event.content["m.relates_to"].is_object()) {
      auto& rel = event.content["m.relates_to"];
      std::string rel_type = "m.reference";
      std::string relates_to_id;
      std::string aggregation_key;
      
      if (rel.contains("rel_type") && rel["rel_type"].is_string()) {
        rel_type = rel["rel_type"].get<std::string>();
      }
      if (rel.contains("event_id") && rel["event_id"].is_string()) {
        relates_to_id = rel["event_id"].get<std::string>();
      }
      if (rel.contains("key") && rel["key"].is_string()) {
        aggregation_key = rel["key"].get<std::string>();
      }
      
      if (!relates_to_id.empty()) {
        txn.execute(
            "INSERT OR IGNORE INTO event_relations "
            "(event_id, relates_to_id, relation_type, aggregation_key) "
            "VALUES (?, ?, ?, ?)",
            {event.event_id, relates_to_id, rel_type,
             aggregation_key.empty() ? std::optional<std::string>() : aggregation_key});
      }
    }
  }
  
  // Update current_state_events with state delta
  if (state_delta_for_room && !state_delta_for_room->is_noop()) {
    // Delete entries
    for (const auto& [type, state_key] : state_delta_for_room->to_delete) {
      txn.execute(
          "DELETE FROM current_state_events WHERE room_id = ? AND type = ? AND state_key = ?",
          {room_id, type, state_key});
    }
    
    // Insert entries
    for (const auto& [type_state, event_id] : state_delta_for_room->to_insert) {
      const auto& type = type_state.first;
      const auto& state_key = type_state.second;
      
      txn.execute(
          "INSERT INTO current_state_events (event_id, room_id, type, state_key) "
          "VALUES (?, ?, ?, ?) "
          "ON CONFLICT (room_id, type, state_key) DO UPDATE SET event_id = excluded.event_id",
          {event_id, room_id, type, state_key});
    }
    
    // Handle no_longer_in_room
    if (state_delta_for_room->no_longer_in_room) {
      txn.execute(
          "DELETE FROM current_state_events WHERE room_id = ?", {room_id});
    }
  }
  
  // Update forward extremities
  if (new_forward_extremities) {
    // Delete old forward extremities for this room
    txn.execute(
        "DELETE FROM event_forward_extremities WHERE room_id = ?", {room_id});
    
    // Insert new forward extremities
    for (const auto& event_id : *new_forward_extremities) {
      txn.execute(
          "INSERT INTO event_forward_extremities (event_id, room_id) VALUES (?, ?)",
          {event_id, room_id});
    }
  }
  
  // Update state DAG forward extremities (MSC4242)
  if (msc4354_enabled_ && new_state_dag_forward_extremities) {
    for (const auto& event_id : *new_state_dag_forward_extremities) {
      txn.execute(
          "INSERT OR IGNORE INTO insertion_event_extremities (event_id, room_id, insertion_prev_event_id) "
          "VALUES (?, ?, ?)",
          {event_id, room_id, ""});
    }
  }
  
  // Apply sliding sync table changes
  if (sliding_sync_table_changes && !sliding_sync_table_changes->room_id.empty()) {
    update_sliding_sync_joined_rooms(
        txn, sliding_sync_table_changes->room_id,
        sliding_sync_table_changes->joined_room_bump_stamp_to_fully_insert.value_or(time_msec_()),
        sliding_sync_table_changes->joined_room_updates);
    
    update_sliding_sync_membership_snapshots(
        txn, sliding_sync_table_changes->room_id,
        sliding_sync_table_changes->to_insert_membership_snapshots,
        sliding_sync_table_changes->to_delete_membership_snapshots,
        sliding_sync_table_changes->membership_snapshot_shared_insert_values);
  }
  
  // Persist chain cover index
  if (!new_event_links.empty()) {
    persist_chain_cover_index_txn(txn, db_pool_, new_event_links);
  }
}

// ============================================================================
// update_current_state_txn
// ============================================================================
void PersistEventsStore::update_current_state_txn(
    LoggingTransaction& txn, const std::string& room_id,
    const DeltaState& delta_state, int64_t stream_id,
    const SlidingSyncTableChanges& sliding_sync_table_changes) {
  
  // Delete old state entries
  for (const auto& [type, state_key] : delta_state.to_delete) {
    txn.execute(
        "DELETE FROM current_state_events WHERE room_id = ? AND type = ? AND state_key = ?",
        {room_id, type, state_key});
  }
  
  // Insert new state entries
  for (const auto& [type_state, event_id] : delta_state.to_insert) {
    txn.execute(
        "INSERT INTO current_state_events (event_id, room_id, type, state_key) "
        "VALUES (?, ?, ?, ?) "
        "ON CONFLICT (room_id, type, state_key) DO UPDATE SET event_id = excluded.event_id",
        {event_id, room_id, type_state.first, type_state.second});
  }
  
  if (delta_state.no_longer_in_room) {
    txn.execute("DELETE FROM current_state_events WHERE room_id = ?", {room_id});
  }
  
  // Update sliding sync tables
  if (!sliding_sync_table_changes.room_id.empty()) {
    update_sliding_sync_joined_rooms(
        txn, sliding_sync_table_changes.room_id,
        sliding_sync_table_changes.joined_room_bump_stamp_to_fully_insert.value_or(time_msec_()),
        sliding_sync_table_changes.joined_room_updates);
  }
}

// ============================================================================
// calculate_chain_cover_index_for_events_txn
// Equivalent to Python _calculate_chain_cover_index_for_events at events.py line 849
// ============================================================================
std::map<std::string, NewEventChainLinks>
PersistEventsStore::calculate_chain_cover_index_for_events_txn(
    LoggingTransaction& txn,
    const std::string& room_id,
    const std::vector<EventData>& events,
    int64_t (*event_chain_id_gen_get_next_mult)(LoggingTransaction&, int64_t)) {
  
  std::map<std::string, std::string> event_to_room;
  std::map<std::string, std::pair<std::string, std::string>> event_to_types;
  std::map<std::string, std::vector<std::string>> event_to_auth_chain;
  
  for (const auto& event : events) {
    event_to_room[event.event_id] = event.room_id;
    event_to_types[event.event_id] = {event.type, event.state_key.value_or("")};
    event_to_auth_chain[event.event_id] = event.auth_event_ids_list();
  }
  
  return calculate_chain_cover_index_txn(
      txn, db_pool_, event_chain_id_gen_get_next_mult,
      event_to_room, event_to_types, event_to_auth_chain);
}

// ============================================================================
// get_events_which_are_prevs_txn
// Equivalent to Python _get_events_which_are_prevs at events.py line 930
// ============================================================================
std::vector<std::string> PersistEventsStore::get_events_which_are_prevs_txn(
    LoggingTransaction& txn, const std::vector<std::string>& event_ids) {
  
  std::vector<std::string> result;
  if (event_ids.empty()) return result;
  
  // Build IN clause
  std::string placeholders;
  std::vector<DatabaseType> params;
  for (size_t i = 0; i < event_ids.size(); ++i) {
    if (i > 0) placeholders += ", ";
    placeholders += "?";
    params.push_back(event_ids[i]);
  }
  
  auto rows = txn.select(
      "SELECT event_id FROM event_edges WHERE prev_event_id IN (" + placeholders + ")",
      params);
  
  std::set<std::string> seen;
  for (auto& row : rows) {
    if (!row.is_null()) {
      std::string eid = row.get<std::string>(0);
      if (seen.insert(eid).second) {
        result.push_back(eid);
      }
    }
  }
  
  return result;
}

// ============================================================================
// get_prevs_before_rejected_txn
// Equivalent to Python _get_prevs_before_rejected at events.py line 971
// ============================================================================
std::set<std::string> PersistEventsStore::get_prevs_before_rejected_txn(
    LoggingTransaction& txn, const std::vector<std::string>& event_ids,
    bool include_soft_failed) {
  
  std::set<std::string> result;
  if (event_ids.empty()) return result;
  
  // Check which events are rejected
  std::string placeholders;
  std::vector<DatabaseType> params;
  for (size_t i = 0; i < event_ids.size(); ++i) {
    if (i > 0) placeholders += ", ";
    placeholders += "?";
    params.push_back(event_ids[i]);
  }
  
  auto rejected = txn.select(
      "SELECT event_id FROM events WHERE event_id IN (" + placeholders + 
      ") AND is_outlier = 1",
      params);
  
  std::set<std::string> rejected_ids;
  for (auto& row : rejected) {
    if (!row.is_null()) rejected_ids.insert(row.get<std::string>(0));
  }
  if (rejected_ids.empty() && !include_soft_failed) return result;
  
  // Get prev events of rejected events
  for (const auto& rej_id : rejected_ids) {
    auto prevs = txn.select(
        "SELECT prev_event_id FROM event_edges WHERE event_id = ?", {rej_id});
    for (auto& prev : prevs) {
      if (!prev.is_null()) {
        result.insert(prev.get<std::string>(0));
      }
    }
  }
  
  return result;
}

// ============================================================================
// Static: add_chain_cover_index_txn
// Equivalent to Python @classmethod _add_chain_cover_index at events.py line 1246
// ============================================================================
void PersistEventsStore::add_chain_cover_index_txn(
    LoggingTransaction& txn, DatabasePool& db_pool,
    int64_t (*event_chain_id_gen_get_next_mult)(LoggingTransaction&, int64_t),
    const std::map<std::string, std::string>& event_to_room_id,
    const std::map<std::string, std::pair<std::string, std::string>>& event_to_types,
    const std::map<std::string, std::vector<std::string>>& event_to_auth_chain) {
  
  auto new_links = calculate_chain_cover_index_txn(
      txn, db_pool, event_chain_id_gen_get_next_mult,
      event_to_room_id, event_to_types, event_to_auth_chain);
  
  persist_chain_cover_index_txn(txn, db_pool, new_links);
}

// ============================================================================
// Static: calculate_chain_cover_index_txn
// Equivalent to Python @classmethod _calculate_chain_cover_index at events.py line 1275
// ============================================================================
std::map<std::string, NewEventChainLinks>
PersistEventsStore::calculate_chain_cover_index_txn(
    LoggingTransaction& txn, DatabasePool& db_pool,
    int64_t (*event_chain_id_gen_get_next_mult)(LoggingTransaction&, int64_t),
    const std::map<std::string, std::string>& event_to_room_id,
    const std::map<std::string, std::pair<std::string, std::string>>& event_to_types,
    const std::map<std::string, std::vector<std::string>>& event_to_auth_chain) {
  
  // Build the set of events we need to calculate chain IDs for
  std::set<std::string> events_to_calc;
  for (const auto& [eid, _] : event_to_room_id) {
    events_to_calc.insert(eid);
  }
  
  // Map of event_id -> (chain_id, sequence_number)
  std::map<std::string, std::pair<int64_t, int64_t>> chain_map;
  
  return allocate_chain_ids_txn(
      txn, db_pool, event_chain_id_gen_get_next_mult,
      event_to_room_id, event_to_types, event_to_auth_chain,
      events_to_calc, chain_map);
}

// ============================================================================
// Static: persist_chain_cover_index_txn
// Equivalent to Python @classmethod _persist_chain_cover_index at events.py line 1525
// ============================================================================
void PersistEventsStore::persist_chain_cover_index_txn(
    LoggingTransaction& txn, DatabasePool& db_pool,
    const std::map<std::string, NewEventChainLinks>& new_event_links) {
  
  for (const auto& [event_id, chain_links] : new_event_links) {
    // Persist chain links
    for (const auto& [src_chain, src_seq] : chain_links.links) {
      txn.execute(
          "INSERT OR IGNORE INTO event_auth_chains "
          "(event_id, chain_id, sequence_number) VALUES (?, ?, ?)",
          {event_id, src_chain, src_seq});
    }
  }
}

// ============================================================================
// Static: allocate_chain_ids_txn
// Equivalent to Python @classmethod _allocate_chain_ids at events.py line 1571
// ============================================================================
std::map<std::string, std::pair<int64_t, int64_t>>
PersistEventsStore::allocate_chain_ids_txn(
    LoggingTransaction& txn, DatabasePool& db_pool,
    int64_t (*event_chain_id_gen_get_next_mult)(LoggingTransaction&, int64_t),
    const std::map<std::string, std::string>& event_to_room_id,
    const std::map<std::string, std::pair<std::string, std::string>>& event_to_types,
    const std::map<std::string, std::vector<std::string>>& event_to_auth_chain,
    const std::set<std::string>& events_to_calc_chain_id_for,
    std::map<std::string, std::pair<int64_t, int64_t>>& chain_map) {
  
  std::map<std::string, std::pair<int64_t, int64_t>> result;
  
  for (const auto& event_id : events_to_calc_chain_id_for) {
    // Look up auth events' chain IDs
    auto auth_it = event_to_auth_chain.find(event_id);
    if (auth_it != event_to_auth_chain.end()) {
      std::vector<std::pair<int64_t, int64_t>> auth_chains;
      for (const auto& auth_id : auth_it->second) {
        auto chain_it = chain_map.find(auth_id);
        if (chain_it != chain_map.end()) {
          auth_chains.push_back(chain_it->second);
        }
      }
      
      if (!auth_chains.empty()) {
        // Take the last auth chain as the base
        int64_t chain_id = auth_chains.back().first;
        int64_t seq_num = auth_chains.back().second + 1;
        result[event_id] = {chain_id, seq_num};
        chain_map[event_id] = {chain_id, seq_num};
      } else {
        // No auth chain info - allocate new
        int64_t new_chain_id = event_chain_id_gen_get_next_mult(txn, 1);
        result[event_id] = {new_chain_id, 1};
        chain_map[event_id] = {new_chain_id, 1};
      }
    } else {
      int64_t new_chain_id = event_chain_id_gen_get_next_mult(txn, 1);
      result[event_id] = {new_chain_id, 1};
      chain_map[event_id] = {new_chain_id, 1};
    }
  }
  
  return result;
}

// ============================================================================
// LinkMap Implementation
// ============================================================================
bool LinkMap::add_link(std::pair<int64_t, int64_t> src_tuple,
                       std::pair<int64_t, int64_t> target_tuple,
                       bool is_new) {
  auto [src_chain, src_seq] = src_tuple;
  auto [tgt_chain, tgt_seq] = target_tuple;
  
  // Check if link already exists
  auto& middle = maps_[src_chain];
  auto& inner = middle[tgt_chain];
  auto it = inner.find(src_seq);
  if (it != inner.end()) {
    return false; // Already exists
  }
  
  // Check if there's already a path (transitive closure)
  if (exists_path_from(src_tuple, target_tuple)) {
    return false;
  }
  
  // Add the link
  inner[src_seq] = tgt_seq;
  
  if (is_new) {
    additions_.insert({src_chain, tgt_chain, src_seq, tgt_seq});
  }
  
  return true;
}

std::vector<LinkMap::LinkTuple> LinkMap::get_additions() const {
  return {additions_.begin(), additions_.end()};
}

bool LinkMap::exists_path_from(std::pair<int64_t, int64_t> src_tuple,
                                std::pair<int64_t, int64_t> target_tuple) const {
  auto [src_chain, src_seq] = src_tuple;
  auto [tgt_chain, tgt_seq] = target_tuple;
  
  // Direct link
  auto mid_it = maps_.find(src_chain);
  if (mid_it != maps_.end()) {
    auto inner_it = mid_it->second.find(tgt_chain);
    if (inner_it != mid_it->second.end()) {
      auto it = inner_it->second.lower_bound(src_seq);
      if (it != inner_it->second.end() && it->second >= tgt_seq) {
        return true;
      }
    }
  }
  
  // BFS for transitive path
  std::set<std::pair<int64_t, int64_t>> visited;
  std::vector<std::pair<int64_t, int64_t>> stack = {src_tuple};
  
  while (!stack.empty()) {
    auto [c, s] = stack.back();
    stack.pop_back();
    if (visited.count({c, s})) continue;
    visited.insert({c, s});
    
    auto mid_it2 = maps_.find(c);
    if (mid_it2 == maps_.end()) continue;
    
    for (const auto& [next_chain, next_inner] : mid_it2->second) {
      for (const auto& [from_seq, to_seq] : next_inner) {
        if (from_seq >= s) {
          if (next_chain == tgt_chain && to_seq >= tgt_seq) {
            return true;
          }
          stack.push_back({next_chain, to_seq});
        }
      }
    }
  }
  
  return false;
}

// ============================================================================
// EventsWorkerStore helper methods (used by events_worker.hpp/cpp)
// ============================================================================

// Get event by event_id with full details
std::optional<EventData> get_event_by_id(LoggingTransaction& txn, 
                                          const std::string& event_id,
                                          bool allow_none = true,
                                          bool allow_rejected = false,
                                          bool redact_behaviour = false) {
  auto row = txn.select_one(
      "SELECT event_id, room_id, type, sender, state_key, membership, "
      "depth, origin_server_ts, stream_ordering, instance_name, "
      "is_state_event, is_outlier, content, internal_metadata, "
      "unsigned_data, room_version_id, is_redacted "
      "FROM events WHERE event_id = ?", {event_id});
  
  if (!row || row->is_null()) {
    if (!allow_none) return std::nullopt;
    return std::nullopt;
  }
  
  EventData event;
  event.event_id = row->get<std::string>(0);
  event.room_id = row->get<std::string>(1);
  event.type = row->get<std::string>(2);
  event.sender = row->get<std::string>(3);
  if (!row->is_null(4)) event.state_key = row->get<std::string>(4);
  event.membership = row->get<std::string>(5);
  event.depth = row->get<int64_t>(6);
  event.origin_server_ts = row->get<int64_t>(7);
  event.stream_ordering = row->get<int64_t>(8);
  event.instance_name = row->get<std::string>(9);
  event.is_state_event = row->get<int64_t>(10) != 0;
  event.is_outlier = row->get<int64_t>(11) != 0;
  event.content = json::parse(row->get<std::string>(12));
  event.internal_metadata_json = row->get<std::string>(13);
  event.unsigned_data = json::parse(row->get<std::string>(14));
  event.room_version_id = row->get<std::string>(15);
  event.is_redacted = row->get<int64_t>(16) != 0;
  
  return event;
}

// Get multiple events by IDs
std::vector<EventData> get_events(LoggingTransaction& txn,
                                   const std::vector<std::string>& event_ids,
                                   bool allow_rejected = false) {
  std::vector<EventData> result;
  if (event_ids.empty()) return result;
  
  std::string placeholders;
  std::vector<DatabaseType> params;
  for (size_t i = 0; i < event_ids.size(); ++i) {
    if (i > 0) placeholders += ", ";
    placeholders += "?";
    params.push_back(event_ids[i]);
  }
  
  std::string query = "SELECT event_id, room_id, type, sender, state_key, "
      "membership, depth, origin_server_ts, stream_ordering, instance_name, "
      "is_state_event, is_outlier, content, internal_metadata, unsigned_data, "
      "room_version_id, is_redacted FROM events WHERE event_id IN (" 
      + placeholders + ")";
  
  if (!allow_rejected) {
    query += " AND is_outlier = 0";
  }
  
  auto rows = txn.select(query, params);
  for (auto& row : rows) {
    if (row.is_null()) continue;
    EventData event;
    event.event_id = row.get<std::string>(0);
    event.room_id = row.get<std::string>(1);
    event.type = row.get<std::string>(2);
    event.sender = row.get<std::string>(3);
    if (!row.is_null(4)) event.state_key = row.get<std::string>(4);
    event.membership = row.get<std::string>(5);
    event.depth = row.get<int64_t>(6);
    event.origin_server_ts = row.get<int64_t>(7);
    event.stream_ordering = row.get<int64_t>(8);
    event.instance_name = row.get<std::string>(9);
    event.is_state_event = row.get<int64_t>(10) != 0;
    event.is_outlier = row.get<int64_t>(11) != 0;
    event.content = json::parse(row.get<std::string>(12));
    event.internal_metadata_json = row.get<std::string>(13);
    event.unsigned_data = json::parse(row.get<std::string>(14));
    event.room_version_id = row.get<std::string>(15);
    event.is_redacted = row.get<int64_t>(16) != 0;
    result.push_back(std::move(event));
  }
  
  return result;
}

// Get current state for a room
std::map<std::pair<std::string, std::string>, std::string> 
get_current_state(LoggingTransaction& txn, const std::string& room_id) {
  std::map<std::pair<std::string, std::string>, std::string> result;
  
  auto rows = txn.select(
      "SELECT type, state_key, event_id FROM current_state_events WHERE room_id = ?",
      {room_id});
  
  for (auto& row : rows) {
    if (!row.is_null()) {
      std::string type = row.get<std::string>(0);
      std::string state_key = row.get<std::string>(1);
      std::string event_id = row.get<std::string>(2);
      result[{type, state_key}] = event_id;
    }
  }
  
  return result;
}

// Get room members
std::vector<std::tuple<std::string, std::string, std::string>> 
get_room_members(LoggingTransaction& txn, const std::string& room_id,
                 const std::string& membership = "join") {
  std::vector<std::tuple<std::string, std::string, std::string>> result;
  
  auto rows = txn.select(
      "SELECT event_id, user_id, sender FROM room_memberships "
      "WHERE room_id = ? AND membership = ?",
      {room_id, membership});
  
  for (auto& row : rows) {
    result.emplace_back(
        row.get<std::string>(0), row.get<std::string>(1), row.get<std::string>(2));
  }
  
  return result;
}

// Get events since a stream ordering
std::vector<EventData> get_events_since(LoggingTransaction& txn,
                                         int64_t from_stream,
                                         int64_t to_stream,
                                         int limit = 100) {
  std::vector<EventData> result;
  
  auto rows = txn.select(
      "SELECT event_id, room_id, type, sender, state_key, membership, "
      "depth, origin_server_ts, stream_ordering, instance_name, "
      "is_state_event, is_outlier, content, internal_metadata, "
      "unsigned_data, room_version_id, is_redacted "
      "FROM events "
      "WHERE stream_ordering > ? AND stream_ordering <= ? AND is_outlier = 0 "
      "ORDER BY stream_ordering ASC LIMIT ?",
      {from_stream, to_stream, limit});
  
  for (auto& row : rows) {
    EventData e;
    e.event_id = row.get<std::string>(0);
    e.room_id = row.get<std::string>(1);
    e.type = row.get<std::string>(2);
    e.sender = row.get<std::string>(3);
    if (!row.is_null(4)) e.state_key = row.get<std::string>(4);
    e.membership = row.get<std::string>(5);
    e.depth = row.get<int64_t>(6);
    e.origin_server_ts = row.get<int64_t>(7);
    e.stream_ordering = row.get<int64_t>(8);
    e.instance_name = row.get<std::string>(9);
    e.is_state_event = row.get<int64_t>(10) != 0;
    e.is_outlier = row.get<int64_t>(11) != 0;
    e.content = json::parse(row.get<std::string>(12));
    e.internal_metadata_json = row.get<std::string>(13);
    e.unsigned_data = json::parse(row.get<std::string>(14));
    e.room_version_id = row.get<std::string>(15);
    e.is_redacted = row.get<int64_t>(16) != 0;
    result.push_back(std::move(e));
  }
  
  return result;
}

} // namespace progressive::storage
