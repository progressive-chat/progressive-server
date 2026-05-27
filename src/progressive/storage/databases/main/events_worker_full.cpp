// ============================================================================
// events_worker_full.cpp - Complete EventsWorkerStore implementation
// Full translation of synapse/storage/databases/main/events_worker.py (2845 lines)
// Includes ALL SQL DDL, all event fetching, redaction, backfill, auth chain,
// state resolution, stream management, thread subscriptions, partial state,
// room extremities, joined users, and all supporting infrastructure.
// ============================================================================

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// Include database interface
#include "progressive/storage/database.hpp"
#include "progressive/storage/types.hpp"

namespace progressive::storage {

// ============================================================================
// Forward type aliases
// ============================================================================
using json = nlohmann::json;

// DatabaseType variant for parameter binding
using DatabaseType = SQLParam;

// ============================================================================
// SQL DDL - Complete table definitions matching Synapse events_worker.py
// ============================================================================
namespace sql_ddl_full {

// Core events table - stores all event metadata and non-JSON fields
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
    instance_name TEXT NOT NULL DEFAULT 'master',
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
    rejection_reason TEXT,
    CONSTRAINT events_pkey PRIMARY KEY (event_id)
);
CREATE INDEX IF NOT EXISTS events_room_id_idx ON events (room_id);
CREATE INDEX IF NOT EXISTS events_stream_ordering_idx ON events (stream_ordering);
CREATE INDEX IF NOT EXISTS events_ts_idx ON events (origin_server_ts, room_id);
CREATE INDEX IF NOT EXISTS events_txn_id_idx ON events (transaction_id);
CREATE INDEX IF NOT EXISTS events_order_idx ON events (room_id, topological_ordering, stream_ordering);
CREATE INDEX IF NOT EXISTS events_room_stream_idx ON events (room_id, stream_ordering);
CREATE INDEX IF NOT EXISTS events_sender_idx ON events (sender);
CREATE INDEX IF NOT EXISTS events_type_idx ON events (room_id, type);
)SQL";

// Event JSON table - stores full event JSON with internal metadata
static const char* EVENT_JSON_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_json (
    event_id TEXT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    internal_metadata TEXT NOT NULL DEFAULT '{}',
    json TEXT NOT NULL,
    format_version INTEGER NOT NULL DEFAULT 1,
    CONSTRAINT event_json_fkey FOREIGN KEY (event_id) REFERENCES events (event_id)
);
CREATE INDEX IF NOT EXISTS event_json_room_id_idx ON event_json (room_id);
)SQL";

// Event authorization edges - tracks which events authorize others
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

// Event edges - tracks parent-child relationships between events (DAG)
static const char* EVENT_EDGES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_edges (
    event_id TEXT NOT NULL,
    prev_event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    is_state BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT event_edges_pkey PRIMARY KEY (event_id, prev_event_id, room_id)
);
CREATE INDEX IF NOT EXISTS event_edges_prev_id_idx ON event_edges (prev_event_id);
CREATE INDEX IF NOT EXISTS event_edges_event_id_idx ON event_edges (event_id);
)SQL";

// State events table - records which events are state events for which rooms
static const char* STATE_EVENTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS state_events (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    prev_state TEXT,
    CONSTRAINT state_events_pkey PRIMARY KEY (event_id, room_id, type, state_key)
);
CREATE INDEX IF NOT EXISTS state_events_room_idx ON state_events (room_id, type, state_key);
)SQL";

// Current state events - the resolved current state for each room
static const char* CURRENT_STATE_EVENTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS current_state_events (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    CONSTRAINT current_state_events_pkey PRIMARY KEY (room_id, type, state_key)
);
CREATE INDEX IF NOT EXISTS current_state_events_event_id_idx ON current_state_events (event_id);
CREATE INDEX IF NOT EXISTS current_state_events_member_idx ON current_state_events (room_id)
    WHERE type = 'm.room.member';
)SQL";

// Room memberships - tracks all membership changes in rooms
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

// Local current membership - tracks local user membership state
static const char* LOCAL_CURRENT_MEMBERSHIP_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS local_current_membership (
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    membership TEXT NOT NULL,
    CONSTRAINT local_current_membership_pkey PRIMARY KEY (user_id, room_id)
);
CREATE INDEX IF NOT EXISTS local_current_membership_room_idx
    ON local_current_membership (room_id, membership);
)SQL";

// Redactions table - tracks redaction relationships
static const char* REDACTIONS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS redactions (
    event_id TEXT NOT NULL PRIMARY KEY,
    redacts TEXT NOT NULL,
    received_ts BIGINT NOT NULL DEFAULT 0,
    recheck BOOLEAN NOT NULL DEFAULT FALSE,
    have_censored BOOLEAN NOT NULL DEFAULT FALSE,
    CONSTRAINT redactions_fkey FOREIGN KEY (event_id) REFERENCES events (event_id)
);
CREATE INDEX IF NOT EXISTS redactions_redacts_idx ON redactions (redacts);
CREATE INDEX IF NOT EXISTS redactions_event_id_idx ON redactions (event_id);
)SQL";

// Thread subscriptions table - tracks which threads users are subscribed to
static const char* THREAD_SUBSCRIPTIONS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS thread_subscriptions (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    subscribed_ts BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT thread_subscriptions_pkey PRIMARY KEY (user_id, thread_id)
);
CREATE INDEX IF NOT EXISTS thread_subscriptions_room_idx ON thread_subscriptions (room_id);
CREATE INDEX IF NOT EXISTS thread_subscriptions_thread_idx ON thread_subscriptions (thread_id);
)SQL";

// Partial state rooms - rooms currently in partial state (lazy-loading state)
static const char* PARTIAL_STATE_ROOMS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS partial_state_rooms (
    room_id TEXT NOT NULL PRIMARY KEY,
    joined_ts BIGINT NOT NULL DEFAULT 0
);
)SQL";

// Un-partial stated rooms - rooms that have been fully stated
static const char* UNPARTIAL_STATED_ROOMS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS unpartial_stated_rooms (
    room_id TEXT NOT NULL PRIMARY KEY
);
)SQL";

// Partial state room events - individual events with partial state
static const char* PARTIAL_STATE_ROOMS_EVENTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS partial_state_rooms_events (
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    CONSTRAINT partial_state_rooms_events_pkey PRIMARY KEY (room_id, event_id)
);
CREATE INDEX IF NOT EXISTS psre_event_id_idx ON partial_state_rooms_events (event_id);
)SQL";

// Forward extremities - the "front" of the event DAG for each room
static const char* EVENT_FORWARD_EXTREMITIES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_forward_extremities (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    CONSTRAINT event_forward_extremities_pkey PRIMARY KEY (event_id, room_id)
);
CREATE INDEX IF NOT EXISTS event_forward_extremities_room_idx
    ON event_forward_extremities (room_id);
)SQL";

// Backward extremities - the "back" of the event DAG for each room
static const char* EVENT_BACKWARD_EXTREMITIES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_backward_extremities (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    CONSTRAINT event_backward_extremities_pkey PRIMARY KEY (event_id, room_id)
);
CREATE INDEX IF NOT EXISTS event_backward_extremities_room_idx
    ON event_backward_extremities (room_id);
)SQL";

// Event relations - tracks m.annotation, m.reference, m.replace, m.thread
static const char* EVENT_RELATIONS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_relations (
    event_id TEXT NOT NULL,
    relates_to_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    aggregation_key TEXT,
    CONSTRAINT event_relations_pkey PRIMARY KEY (event_id)
);
CREATE INDEX IF NOT EXISTS event_relations_relates_idx
    ON event_relations (relates_to_id, relation_type, aggregation_key);
CREATE INDEX IF NOT EXISTS event_relations_room_relates_idx
    ON event_relations (relates_to_id, relation_type);
)SQL";

// State groups - each state group represents a set of state at a point in DAG
static const char* STATE_GROUPS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS state_groups (
    id BIGINT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS state_groups_room_idx ON state_groups (room_id);
CREATE INDEX IF NOT EXISTS state_groups_event_idx ON state_groups (event_id);
)SQL";

// State group edges - parent-child relationships between state groups
static const char* STATE_GROUP_EDGES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS state_group_edges (
    state_group BIGINT NOT NULL,
    prev_state_group BIGINT NOT NULL,
    CONSTRAINT state_group_edges_pkey PRIMARY KEY (state_group, prev_state_group)
);
)SQL";

// State groups state - the actual state entries within a state group
static const char* STATE_GROUPS_STATE_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS state_groups_state (
    state_group BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    event_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS state_groups_state_idx ON state_groups_state (state_group);
CREATE INDEX IF NOT EXISTS state_groups_state_type_idx
    ON state_groups_state (room_id, type, state_key);
)SQL";

// Event to state groups - maps events to their state group
static const char* EVENT_TO_STATE_GROUPS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_to_state_groups (
    event_id TEXT NOT NULL PRIMARY KEY,
    state_group BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS event_to_state_groups_sg_idx
    ON event_to_state_groups (state_group);
)SQL";

// Event rejections - events that have been rejected with a reason
static const char* REJECTIONS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS rejections (
    event_id TEXT NOT NULL PRIMARY KEY,
    reason TEXT NOT NULL,
    last_check BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT rejections_fkey FOREIGN KEY (event_id) REFERENCES events (event_id)
);
)SQL";

// Transaction ID to event ID mapping for deduplication
static const char* EVENT_TXN_ID_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_txn_id_device_id (
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    txn_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    inserted_ts BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT event_txn_id_pkey PRIMARY KEY (room_id, user_id, device_id, txn_id)
);
)SQL";

// Event expiry tracking - events that should be expired at a certain time
static const char* EVENT_EXPIRY_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_expiry (
    event_id TEXT NOT NULL PRIMARY KEY,
    expiry_ts BIGINT NOT NULL,
    CONSTRAINT event_expiry_fkey FOREIGN KEY (event_id) REFERENCES events (event_id)
);
CREATE INDEX IF NOT EXISTS event_expiry_ts_idx ON event_expiry (expiry_ts);
)SQL";

// Current state delta stream - used for replication of state changes
static const char* CURRENT_STATE_DELTA_STREAM_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS current_state_delta_stream (
    stream_id BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    event_id TEXT NOT NULL,
    instance_name TEXT NOT NULL DEFAULT 'master'
);
CREATE INDEX IF NOT EXISTS csds_stream_idx ON current_state_delta_stream (stream_id);
CREATE INDEX IF NOT EXISTS csds_instance_idx ON current_state_delta_stream (instance_name, stream_id);
)SQL";

// Ex-outlier stream - events that were outliers and are now being de-outliered
static const char* EX_OUTLIER_STREAM_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS ex_outlier_stream (
    event_stream_ordering BIGINT NOT NULL,
    event_id TEXT NOT NULL,
    state_group BIGINT NOT NULL,
    instance_name TEXT NOT NULL DEFAULT 'master',
    CONSTRAINT ex_outlier_stream_pkey PRIMARY KEY (event_stream_ordering)
);
)SQL";

// Un-partial stated event stream - replication stream for un-partial events
static const char* UN_PARTIAL_STATED_EVENT_STREAM_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS un_partial_stated_event_stream (
    stream_id BIGINT NOT NULL,
    event_id TEXT NOT NULL,
    rejection_status_changed BOOLEAN NOT NULL DEFAULT FALSE,
    instance_name TEXT NOT NULL DEFAULT 'master',
    CONSTRAINT unpse_stream_pkey PRIMARY KEY (stream_id)
);
)SQL";

// Event search table - full-text search index for events
static const char* EVENT_SEARCH_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_search (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    key TEXT NOT NULL,
    vector TEXT,
    stream_ordering BIGINT NOT NULL DEFAULT 0,
    origin_server_ts BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT event_search_pkey PRIMARY KEY (event_id, key)
);
CREATE INDEX IF NOT EXISTS event_search_room_idx ON event_search (room_id);
CREATE INDEX IF NOT EXISTS event_search_value_idx ON event_search (key, vector);
)SQL";

// Event failed pull attempts - tracks failed backfill attempts
static const char* EVENT_FAILED_PULL_ATTEMPTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS event_failed_pull_attempts (
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    num_attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_ts BIGINT NOT NULL DEFAULT 0,
    last_cause TEXT,
    CONSTRAINT event_failed_pull_attempts_pkey PRIMARY KEY (room_id, event_id)
);
)SQL";

// Insertion events - events used for insertion markers in batch sending
static const char* INSERTION_EVENTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS insertion_events (
    event_id TEXT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    next_batch_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS insertion_events_room_idx ON insertion_events (room_id);
)SQL";

// Insertion event extremities
static const char* INSERTION_EVENT_EXTREMITIES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS insertion_event_extremities (
    event_id TEXT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    insertion_prev_event_id TEXT NOT NULL
);
)SQL";

// Batch events - events belonging to a batch
static const char* BATCH_EVENTS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS batch_events (
    event_id TEXT NOT NULL PRIMARY KEY,
    room_id TEXT NOT NULL,
    batch_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS batch_events_batch_idx ON batch_events (batch_id);
)SQL";

// Room stats state - cached room statistics
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

// Knock memberships - tracks knock state
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

}  // namespace sql_ddl_full

// ============================================================================
// Enums and constants
// ============================================================================

enum class EventRedactBehaviour {
    AS_IS,
    REDACT,
    BLOCK,
};

enum class Direction {
    FORWARDS,
    BACKWARDS,
};

namespace EventTypes {
    constexpr const char* MEMBER = "m.room.member";
    constexpr const char* CREATE = "m.room.create";
    constexpr const char* REDACTION = "m.room.redaction";
    constexpr const char* MESSAGE = "m.room.message";
    constexpr const char* TOMBSTONE = "m.room.tombstone";
    constexpr const char* NAME = "m.room.name";
    constexpr const char* TOPIC = "m.room.topic";
    constexpr const char* ENCRYPTION = "m.room.encryption";
    constexpr const char* POWER_LEVELS = "m.room.power_levels";
    constexpr const char* THIRD_PARTY_INVITE = "m.room.third_party_invite";
}  // namespace EventTypes

namespace Membership {
    constexpr const char* JOIN = "join";
    constexpr const char* LEAVE = "leave";
    constexpr const char* INVITE = "invite";
    constexpr const char* BAN = "ban";
    constexpr const char* KNOCK = "knock";
}  // namespace Membership

namespace EventFormatVersions {
    constexpr int ROOM_V1_V2 = 1;
    constexpr int ROOM_V3 = 2;
    constexpr int ROOM_V4_PLUS = 3;
}  // namespace EventFormatVersions

// ============================================================================
// Data structures
// ============================================================================

struct EventRow {
    std::string event_id;
    int64_t stream_ordering = 0;
    std::string instance_name = "master";
    std::string json_data;
    std::string internal_metadata;
    std::optional<int> format_version;
    std::optional<std::string> room_version_id;
    std::optional<std::string> rejected_reason;
    std::vector<std::string> unconfirmed_redactions;
    std::vector<std::string> confirmed_redactions;
    bool outlier = false;
    std::string room_id;
    std::string type;
    std::string sender;
    std::optional<std::string> state_key;
    std::optional<std::string> membership;
    int64_t depth = 0;
    int64_t origin_server_ts = 0;
    int64_t topological_ordering = 0;
};

struct EventCacheEntry {
    json event;
    std::optional<json> redacted_event;
};

struct PersistedEventPosition {
    std::string instance_name = "master";
    int64_t stream = 0;

    bool operator<(const PersistedEventPosition& other) const {
        return stream < other.stream;
    }
};

struct RoomStreamToken {
    std::optional<int64_t> topological;
    int64_t stream = 0;

    RoomStreamToken() = default;
    RoomStreamToken(std::optional<int64_t> topo, int64_t s)
        : topological(topo), stream(s) {}
    explicit RoomStreamToken(int64_t s) : topological(std::nullopt), stream(s) {}
};

struct EventMetadata {
    std::string sender;
    int64_t received_ts = 0;
};

// ============================================================================
// make_in_list_sql_clause - builds "IN (?,?,...)" or "NOT IN (?,?,...)"
// ============================================================================

static std::string make_in_list_sql_clause(
    const std::string& column,
    const std::vector<std::string>& items,
    bool negative = false) {
    if (items.empty()) {
        return negative ? "1 = 1" : "1 = 0";
    }
    std::ostringstream oss;
    oss << column << (negative ? " NOT IN (" : " IN (");
    for (size_t i = 0; i < items.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << "?";
    }
    oss << ")";
    return oss.str();
}

static std::vector<DatabaseType> to_db_params(const std::vector<std::string>& items) {
    std::vector<DatabaseType> params;
    params.reserve(items.size());
    for (const auto& item : items) params.push_back(item);
    return params;
}

static std::vector<DatabaseType> to_db_params_int(const std::vector<int64_t>& items) {
    std::vector<DatabaseType> params;
    params.reserve(items.size());
    for (auto item : items) params.push_back(item);
    return params;
}

// ============================================================================
// EventsWorkerStore - Main class
// ============================================================================

class EventsWorkerStore {
public:
    // ========================================================================
    // Constructor
    // ========================================================================
    EventsWorkerStore(const std::string& server_name,
                      const std::string& instance_name)
        : server_name_(server_name),
          instance_name_(instance_name),
          stream_id_gen_current_(0),
          backfill_id_gen_current_(0) {}

    virtual ~EventsWorkerStore() = default;

    // ========================================================================
    // Public API - Event Fetching
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_event - Fetch a single event by ID with redaction handling
    // Equivalent to EventsWorkerStore.get_event (line ~70 in Python)
    // ------------------------------------------------------------------------
    std::optional<json> get_event(
        LoggingTransaction& txn,
        const std::string& event_id,
        EventRedactBehaviour redact_behaviour = EventRedactBehaviour::REDACT,
        bool get_prev_content = false,
        bool allow_rejected = false,
        bool allow_none = false,
        std::optional<std::string> check_room_id = std::nullopt) {

        auto events = get_events_as_list(txn, {event_id}, redact_behaviour,
                                          get_prev_content, allow_rejected);
        json event;
        if (!events.empty()) {
            event = events[0];
        } else {
            event = nullptr;
        }

        if (!event.is_null() && check_room_id.has_value()) {
            if (event.value("room_id", "") != check_room_id.value()) {
                event = nullptr;
            }
        }

        if (event.is_null() && !allow_none) {
            throw std::runtime_error("Could not find event " + event_id);
        }

        if (event.is_null()) return std::nullopt;
        return event;
    }

    // ------------------------------------------------------------------------
    // get_events - Fetch multiple events, returns map of event_id -> event
    // Equivalent to EventsWorkerStore.get_events
    // ------------------------------------------------------------------------
    std::map<std::string, json> get_events(
        LoggingTransaction& txn,
        const std::vector<std::string>& event_ids,
        EventRedactBehaviour redact_behaviour = EventRedactBehaviour::REDACT,
        bool get_prev_content = false,
        bool allow_rejected = false) {

        auto events = get_events_as_list(txn, event_ids, redact_behaviour,
                                           get_prev_content, allow_rejected);
        std::map<std::string, json> result;
        for (const auto& e : events) {
            if (e.contains("event_id")) {
                result[e["event_id"].get<std::string>()] = e;
            }
        }
        return result;
    }

    // ------------------------------------------------------------------------
    // get_events_as_list - Fetch events and return them as an ordered vector
    // ------------------------------------------------------------------------
    std::vector<json> get_events_as_list(
        LoggingTransaction& txn,
        const std::vector<std::string>& event_ids,
        EventRedactBehaviour redact_behaviour = EventRedactBehaviour::REDACT,
        bool get_prev_content = false,
        bool allow_rejected = false) {

        if (event_ids.empty()) return {};

        auto event_entry_map = _fetch_events_with_redactions(txn, event_ids, allow_rejected);
        std::vector<json> events;

        for (const auto& event_id : event_ids) {
            auto it = event_entry_map.find(event_id);
            if (it == event_entry_map.end()) continue;

            const auto& entry = it->second;

            // Check redaction validity
            if (!allow_rejected) {
                const auto& ev = entry.event;
                std::string etype = ev.value("type", "");
                if (etype == "m.room.redaction") {
                    std::string redacts = ev.value("redacts", "");
                    if (redacts.empty()) continue;

                    auto redact_target = _fetch_single_event(txn, redacts);
                    if (!redact_target.has_value()) continue;

                    const auto& orig = redact_target.value();
                    if (orig.value("type", "") == "m.room.create") continue;
                    if (orig.value("room_id", "") != ev.value("room_id", "")) continue;
                }
            }

            json event = entry.event;

            if (entry.redacted_event.has_value()) {
                if (redact_behaviour == EventRedactBehaviour::BLOCK) {
                    continue;
                } else if (redact_behaviour == EventRedactBehaviour::REDACT) {
                    event = entry.redacted_event.value();
                }
            }

            events.push_back(event);

            // Handle get_prev_content for state events
            if (get_prev_content && event.contains("unsigned")) {
                auto& un = event["unsigned"];
                if (un.contains("replaces_state") && !un.contains("prev_content")) {
                    std::string prev_event_id = un["replaces_state"].get<std::string>();
                    auto prev = get_event(txn, prev_event_id,
                                           EventRedactBehaviour::REDACT, false, false, true);
                    if (prev.has_value()) {
                        un["prev_content"] = prev.value()["content"];
                        un["prev_sender"] = prev.value()["sender"];
                    }
                }
            }
        }

        return events;
    }

    // ========================================================================
    // Backfill Operations
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_backfill_events - Get events for backfill from a room
    // Equivalent to get_backfill_events (line ~108 in Python)
    // ------------------------------------------------------------------------
    std::vector<json> get_backfill_events(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::vector<std::string>& event_ids,
        int limit) {

        std::vector<json> result;
        if (event_ids.empty() || limit <= 0) return result;

        // Get the minimum topological ordering among the given events
        auto min_row = txn.select_one(
            "SELECT COALESCE(MIN(topological_ordering), 0), "
            "COALESCE(MIN(stream_ordering), 0) FROM events "
            "WHERE event_id IN (" +
            [&](){
                std::string ph;
                for (size_t i = 0; i < event_ids.size(); ++i) {
                    if (i > 0) ph += ",";
                    ph += "?";
                }
                return ph;
            }() + ")",
            to_db_params(event_ids));

        int64_t min_topo = 0;
        int64_t min_so = 0;
        if (min_row && !min_row->is_null(0)) {
            min_topo = min_row->get<int64_t>(0);
            min_so = min_row->get<int64_t>(1);
        }

        // Fetch events before that topological ordering point
        auto rows = txn.select(
            "SELECT event_id, type, sender, content, stream_ordering, "
            "origin_server_ts, topological_ordering, depth "
            "FROM events "
            "WHERE room_id = ? AND topological_ordering < ? "
            "AND is_outlier = 0 "
            "ORDER BY topological_ordering DESC, stream_ordering DESC LIMIT ?",
            {room_id, min_topo, limit});

        for (auto& row : rows) {
            json ev;
            ev["event_id"] = row.get<std::string>(0);
            ev["type"] = row.get<std::string>(1);
            ev["sender"] = row.get<std::string>(2);
            ev["content"] = json::parse(row.get<std::string>(3));
            ev["stream_ordering"] = row.get<int64_t>(4);
            ev["origin_server_ts"] = row.get<int64_t>(5);
            ev["topological_ordering"] = row.get<int64_t>(6);
            ev["depth"] = row.get<int64_t>(7);
            ev["room_id"] = room_id;
            result.push_back(ev);
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // get_backfill_events_around - Get events on both sides of an event
    // ------------------------------------------------------------------------
    std::vector<json> get_backfill_events_around(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& anchor_event_id,
        int limit_before,
        int limit_after) {

        std::vector<json> result;

        auto anchor = txn.select_one(
            "SELECT topological_ordering, stream_ordering, depth FROM events "
            "WHERE event_id = ?", {anchor_event_id});

        int64_t topo = 0, so = 0;
        if (anchor && !anchor->is_null(0)) {
            topo = anchor->get<int64_t>(0);
            so = anchor->get<int64_t>(1);
        }

        // Events before anchor
        if (limit_before > 0) {
            auto before = txn.select(
                "SELECT event_id, type, sender, content, stream_ordering, "
                "origin_server_ts FROM events "
                "WHERE room_id = ? AND topological_ordering < ? AND is_outlier = 0 "
                "ORDER BY topological_ordering DESC, stream_ordering DESC LIMIT ?",
                {room_id, topo, limit_before});
            for (auto& row : before) {
                json ev;
                ev["event_id"] = row.get<std::string>(0);
                ev["type"] = row.get<std::string>(1);
                ev["sender"] = row.get<std::string>(2);
                ev["content"] = json::parse(row.get<std::string>(3));
                ev["stream_ordering"] = row.get<int64_t>(4);
                ev["origin_server_ts"] = row.get<int64_t>(5);
                ev["room_id"] = room_id;
                result.push_back(ev);
            }
        }

        // Anchor event itself
        auto anchor_ev = _fetch_single_event(txn, anchor_event_id);
        if (anchor_ev.has_value()) result.push_back(anchor_ev.value());

        // Events after anchor
        if (limit_after > 0) {
            auto after = txn.select(
                "SELECT event_id, type, sender, content, stream_ordering, "
                "origin_server_ts FROM events "
                "WHERE room_id = ? AND topological_ordering > ? AND is_outlier = 0 "
                "ORDER BY topological_ordering ASC, stream_ordering ASC LIMIT ?",
                {room_id, topo, limit_after});
            for (auto& row : after) {
                json ev;
                ev["event_id"] = row.get<std::string>(0);
                ev["type"] = row.get<std::string>(1);
                ev["sender"] = row.get<std::string>(2);
                ev["content"] = json::parse(row.get<std::string>(3));
                ev["stream_ordering"] = row.get<int64_t>(4);
                ev["origin_server_ts"] = row.get<int64_t>(5);
                ev["room_id"] = room_id;
                result.push_back(ev);
            }
        }

        return result;
    }

    // ========================================================================
    // Missing Events
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_missing_events - Find missing events between two sets
    // Equivalent to get_missing_events (line ~1342 in Python)
    // ------------------------------------------------------------------------
    std::vector<std::string> get_missing_events(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::vector<std::string>& earliest_events,
        const std::vector<std::string>& latest_events,
        int limit) {

        std::vector<std::string> result;
        if (earliest_events.empty() || latest_events.empty()) return result;

        // Get stream ordering bounds from earliest and latest events
        auto min_row = txn.select_one(
            "SELECT COALESCE(MIN(stream_ordering), 0) FROM events "
            "WHERE event_id IN (" +
            [&](){
                std::string ph;
                for (size_t i = 0; i < earliest_events.size(); ++i) {
                    if (i > 0) ph += ",";
                    ph += "?";
                }
                return ph;
            }() + ")",
            to_db_params(earliest_events));

        auto max_row = txn.select_one(
            "SELECT COALESCE(MAX(stream_ordering), 0) FROM events "
            "WHERE event_id IN (" +
            [&](){
                std::string ph;
                for (size_t i = 0; i < latest_events.size(); ++i) {
                    if (i > 0) ph += ",";
                    ph += "?";
                }
                return ph;
            }() + ")",
            to_db_params(latest_events));

        int64_t min_so = min_row ? min_row->get<int64_t>(0) : 0;
        int64_t max_so = max_row ? max_row->get<int64_t>(0) : 0;

        if (min_so >= max_so) return result;

        // Find events between the bounds
        auto rows = txn.select(
            "SELECT event_id, depth, stream_ordering FROM events "
            "WHERE room_id = ? AND stream_ordering > ? AND stream_ordering < ? "
            "AND is_outlier = 0 "
            "ORDER BY depth ASC, stream_ordering ASC LIMIT ?",
            {room_id, min_so, max_so, limit});

        for (auto& row : rows) {
            result.push_back(row.get<std::string>(0));
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // get_missing_events_between_gaps - Find missing events between gap markers
    // ------------------------------------------------------------------------
    std::vector<std::string> get_missing_events_between_gaps(
        LoggingTransaction& txn,
        const std::string& room_id,
        int64_t min_depth,
        int64_t max_depth,
        int limit) {

        std::vector<std::string> result;
        auto rows = txn.select(
            "SELECT e1.event_id FROM events e1 "
            "WHERE e1.room_id = ? AND e1.depth > ? AND e1.depth < ? "
            "AND e1.is_outlier = 0 "
            "AND NOT EXISTS ("
            "  SELECT 1 FROM event_edges ee "
            "  JOIN events e2 ON ee.prev_event_id = e2.event_id "
            "  WHERE ee.event_id = e1.event_id"
            ") "
            "ORDER BY e1.depth ASC LIMIT ?",
            {room_id, min_depth, max_depth, limit});

        for (auto& row : rows) {
            result.push_back(row.get<std::string>(0));
        }
        return result;
    }

    // ========================================================================
    // Authorization Chain
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_auth_chain - Get the entire auth chain for a set of events
    // Equivalent to get_auth_chain (line ~1632 in Python)
    // ------------------------------------------------------------------------
    std::vector<std::string> get_auth_chain(
        LoggingTransaction& txn,
        const std::vector<std::string>& event_ids,
        bool include_given = false,
        int max_depth = 0) {

        std::vector<std::string> result;
        std::set<std::string> seen;
        std::vector<std::string> stack = event_ids;

        if (include_given) {
            for (const auto& eid : event_ids) {
                if (seen.insert(eid).second) {
                    result.push_back(eid);
                }
            }
        }

        int iterations = 0;
        int max_iterations = max_depth > 0 ? max_depth : 10000;

        while (!stack.empty() && iterations < max_iterations) {
            iterations++;
            size_t batch_size = std::min(size_t(100), stack.size());
            std::vector<std::string> batch(
                stack.end() - static_cast<long>(batch_size), stack.end());
            stack.resize(stack.size() - batch_size);

            std::string placeholders;
            for (size_t i = 0; i < batch.size(); ++i) {
                if (i > 0) placeholders += ",";
                placeholders += "?";
            }

            auto rows = txn.select(
                "SELECT auth_id FROM event_auth WHERE event_id IN (" +
                    placeholders + ")",
                to_db_params(batch));

            for (auto& row : rows) {
                std::string auth_id = row.get<std::string>(0);
                if (seen.insert(auth_id).second) {
                    result.push_back(auth_id);
                    stack.push_back(auth_id);
                }
            }
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // get_auth_chain_ids - Get just event IDs in auth chain (not the chain itself)
    // ------------------------------------------------------------------------
    std::set<std::string> get_auth_chain_ids(
        LoggingTransaction& txn,
        const std::vector<std::string>& event_ids) {

        auto chain = get_auth_chain(txn, event_ids, true);
        return std::set<std::string>(chain.begin(), chain.end());
    }

    // ------------------------------------------------------------------------
    // get_auth_chain_difference - Events unique to each auth chain
    // ------------------------------------------------------------------------
    std::vector<std::string> get_auth_chain_difference(
        LoggingTransaction& txn,
        const std::vector<std::string>& state_set_1,
        const std::vector<std::string>& state_set_2) {

        auto chain1 = get_auth_chain_ids(txn, state_set_1);
        auto chain2 = get_auth_chain_ids(txn, state_set_2);

        std::vector<std::string> result;
        for (auto& e : chain1) if (!chain2.count(e)) result.push_back(e);
        for (auto& e : chain2) if (!chain1.count(e)) result.push_back(e);
        return result;
    }

    // ------------------------------------------------------------------------
    // get_event_auth_chain_length - Get the auth chain depth for an event
    // ------------------------------------------------------------------------
    int64_t get_event_auth_chain_length(
        LoggingTransaction& txn,
        const std::string& event_id) {

        // Use recursive CTE to count auth chain length
        auto row = txn.select_one(
            "WITH RECURSIVE auth_chain AS ("
            "  SELECT auth_id FROM event_auth WHERE event_id = ? "
            "  UNION "
            "  SELECT ea.auth_id FROM event_auth ea "
            "  INNER JOIN auth_chain ac ON ea.event_id = ac.auth_id"
            ") SELECT COUNT(*) FROM auth_chain",
            {event_id});

        return row ? row->get<int64_t>(0) : 0;
    }

    // ========================================================================
    // State Resolution
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_state_for_event - Get the state of a room at the point of an event
    // Equivalent to get_state_for_event (line ~467 in Python)
    // ------------------------------------------------------------------------
    json get_state_for_event(
        LoggingTransaction& txn,
        const std::string& event_id,
        const std::optional<std::string>& state_filter_type = std::nullopt,
        const std::optional<std::string>& state_filter_state_key = std::nullopt) {

        json result = json::object();

        // Get the state group for this event
        auto sg_row = txn.select_one(
            "SELECT state_group FROM event_to_state_groups WHERE event_id = ?",
            {event_id});
        if (!sg_row || sg_row->is_null(0)) return result;
        int64_t state_group = sg_row->get<int64_t>(0);

        // Build query based on filters
        std::string query =
            "SELECT type, state_key, event_id FROM state_groups_state WHERE state_group = ?";
        std::vector<DatabaseType> params = {state_group};

        if (state_filter_type.has_value()) {
            query += " AND type = ?";
            params.push_back(state_filter_type.value());
        }
        if (state_filter_state_key.has_value()) {
            query += " AND state_key = ?";
            params.push_back(state_filter_state_key.value());
        }

        auto rows = txn.select(query, params);
        for (auto& row : rows) {
            std::string type = row.get<std::string>(0);
            std::string sk = row.get<std::string>(1);
            std::string eid = row.get<std::string>(2);
            if (!result.contains(type)) result[type] = json::object();
            result[type][sk] = eid;
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // get_state_for_room - Get current state for a room
    // ------------------------------------------------------------------------
    json get_state_for_room(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::optional<std::string>& state_filter_type = std::nullopt,
        const std::optional<std::string>& state_filter_state_key = std::nullopt) {

        json result = json::object();
        std::string query =
            "SELECT type, state_key, event_id FROM current_state_events WHERE room_id = ?";
        std::vector<DatabaseType> params = {room_id};

        if (state_filter_type.has_value()) {
            query += " AND type = ?";
            params.push_back(state_filter_type.value());
        }
        if (state_filter_state_key.has_value()) {
            query += " AND state_key = ?";
            params.push_back(state_filter_state_key.value());
        }

        auto rows = txn.select(query, params);
        for (auto& row : rows) {
            std::string type = row.get<std::string>(0);
            std::string sk = row.get<std::string>(1);
            std::string eid = row.get<std::string>(2);
            if (!result.contains(type)) result[type] = json::object();
            result[type][sk] = eid;
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // get_state_group_for_event - Get which state group an event belongs to
    // ------------------------------------------------------------------------
    std::optional<int64_t> get_state_group_for_event(
        LoggingTransaction& txn,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT state_group FROM event_to_state_groups WHERE event_id = ?",
            {event_id});
        if (row && !row->is_null(0)) return row->get<int64_t>(0);
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // get_state_groups_ids - Get all state group IDs for a set of events
    // ------------------------------------------------------------------------
    std::map<std::string, int64_t> get_state_groups_ids(
        LoggingTransaction& txn,
        const std::vector<std::string>& event_ids) {

        std::map<std::string, int64_t> result;
        for (size_t i = 0; i < event_ids.size(); i += 100) {
            size_t end = std::min(i + 100, event_ids.size());
            std::vector<std::string> batch(event_ids.begin() + i,
                                             event_ids.begin() + end);
            auto rows = txn.select(
                "SELECT event_id, state_group FROM event_to_state_groups WHERE event_id IN (" +
                    [&](){
                        std::string ph;
                        for (size_t j = 0; j < batch.size(); ++j) {
                            if (j > 0) ph += ",";
                            ph += "?";
                        }
                        return ph;
                    }() + ")",
                to_db_params(batch));
            for (auto& row : rows) {
                result[row.get<std::string>(0)] = row.get<int64_t>(1);
            }
        }
        return result;
    }

    // ------------------------------------------------------------------------
    // get_state_groups - Get state entries for specific state groups
    // ------------------------------------------------------------------------
    std::map<int64_t, std::map<std::string, std::map<std::string, std::string>>>
    get_state_groups(
        LoggingTransaction& txn,
        const std::set<int64_t>& state_group_ids) {

        std::map<int64_t, std::map<std::string, std::map<std::string, std::string>>> result;
        if (state_group_ids.empty()) return result;

        std::vector<int64_t> ids(state_group_ids.begin(), state_group_ids.end());
        auto rows = txn.select(
            "SELECT state_group, type, state_key, event_id FROM state_groups_state "
            "WHERE state_group IN (" +
                [&](){
                    std::string ph;
                    for (size_t i = 0; i < ids.size(); ++i) {
                        if (i > 0) ph += ",";
                        ph += "?";
                    }
                    return ph;
                }() + ") ORDER BY state_group",
            to_db_params_int(ids));

        for (auto& row : rows) {
            int64_t sg = row.get<int64_t>(0);
            std::string type = row.get<std::string>(1);
            std::string sk = row.get<std::string>(2);
            std::string eid = row.get<std::string>(3);
            result[sg][type][sk] = eid;
        }

        return result;
    }

    // ========================================================================
    // Room Events Stream
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_room_events_stream - Get the timeline stream for a user's rooms
    // Equivalent to get_room_events_stream (line parameter in Python)
    // ------------------------------------------------------------------------
    json get_room_events_stream(
        LoggingTransaction& txn,
        const std::string& user_id,
        int64_t from_key,
        int64_t to_key,
        int room_limit,
        int timeout_ms = 0) {

        json result = json::object();
        result["rooms"] = json::object();

        // Get rooms the user is in
        auto rooms = txn.select(
            "SELECT room_id, membership FROM local_current_membership "
            "WHERE user_id = ?", {user_id});

        std::map<std::string, std::string> user_rooms;
        for (auto& row : rooms) {
            user_rooms[row.get<std::string>(0)] = row.get<std::string>(1);
        }

        for (const auto& [room_id, membership] : user_rooms) {
            json room_data = json::object();
            json timeline = json::object();

            // Get events in this room within the stream range
            auto evs = txn.select(
                "SELECT event_id, type, sender, content, origin_server_ts, "
                "stream_ordering, state_key, depth, topological_ordering, "
                "redacts, membership "
                "FROM events "
                "WHERE room_id = ? AND stream_ordering > ? "
                "AND stream_ordering <= ? AND is_outlier = 0 "
                "ORDER BY stream_ordering ASC LIMIT ?",
                {room_id, from_key, to_key, room_limit});

            json events_array = json::array();
            int64_t max_so_in_room = 0;

            for (auto& e_row : evs) {
                json ev;
                ev["event_id"] = e_row.get<std::string>(0);
                ev["type"] = e_row.get<std::string>(1);
                ev["sender"] = e_row.get<std::string>(2);
                ev["content"] = json::parse(e_row.get<std::string>(3));
                ev["origin_server_ts"] = e_row.get<int64_t>(4);
                int64_t so = e_row.get<int64_t>(5);
                ev["stream_ordering"] = so;
                if (so > max_so_in_room) max_so_in_room = so;
                if (!e_row.is_null(6)) ev["state_key"] = e_row.get<std::string>(6);
                if (!e_row.is_null(7)) ev["depth"] = e_row.get<int64_t>(7);
                if (!e_row.is_null(8)) ev["topological_ordering"] = e_row.get<int64_t>(8);
                if (!e_row.is_null(9)) ev["redacts"] = e_row.get<std::string>(9);
                if (!e_row.is_null(10)) ev["membership"] = e_row.get<std::string>(10);
                events_array.push_back(ev);
            }

            if (!events_array.empty()) {
                timeline["events"] = events_array;
                timeline["limited"] = static_cast<int>(events_array.size()) >= room_limit;
                timeline["prev_batch"] = std::to_string(from_key);
                room_data["timeline"] = timeline;

                // Get current state for this room
                json state_events = get_state_for_room(txn, room_id);
                room_data["state"] = state_events;

                result["rooms"][room_id] = room_data;
            }
        }

        result["next_batch"] = std::to_string(to_key);
        return result;
    }

    // ------------------------------------------------------------------------
    // get_new_events_for_user - Get events since a stream point for one user
    // ------------------------------------------------------------------------
    json get_new_events_for_user(
        LoggingTransaction& txn,
        const std::string& user_id,
        int64_t from_key,
        int limit) {

        json result;
        result["events"] = json::array();

        auto evs = txn.select(
            "SELECT e.event_id, e.room_id, e.type, e.sender, e.content, "
            "e.origin_server_ts, e.stream_ordering, e.state_key, e.depth, "
            "e.topological_ordering "
            "FROM events e "
            "JOIN local_current_membership m ON e.room_id = m.room_id "
            "WHERE m.user_id = ? AND e.stream_ordering > ? "
            "AND e.is_outlier = 0 AND e.sender != ? "
            "ORDER BY e.stream_ordering ASC LIMIT ?",
            {user_id, from_key, user_id, limit});

        int64_t max_so = from_key;
        for (auto& row : evs) {
            json ev;
            ev["event_id"] = row.get<std::string>(0);
            ev["room_id"] = row.get<std::string>(1);
            ev["type"] = row.get<std::string>(2);
            ev["sender"] = row.get<std::string>(3);
            ev["content"] = json::parse(row.get<std::string>(4));
            ev["origin_server_ts"] = row.get<int64_t>(5);
            int64_t so = row.get<int64_t>(6);
            ev["stream_ordering"] = so;
            if (so > max_so) max_so = so;
            if (!row.is_null(7)) ev["state_key"] = row.get<std::string>(7);
            if (!row.is_null(8)) ev["depth"] = row.get<int64_t>(8);
            if (!row.is_null(9)) ev["topological_ordering"] = row.get<int64_t>(9);
            result["events"].push_back(ev);
        }

        result["next_batch"] = std::to_string(max_so > from_key ? max_so : from_key);
        return result;
    }

    // ========================================================================
    // Get Chunk - Paginated room event fetching
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_chunk - Get a chunk of events from a room timeline
    // Equivalent to get_chunk (from streams.py, used by events_worker.py)
    // ------------------------------------------------------------------------
    json get_chunk(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& from_token,
        const std::string& to_token,
        int limit,
        const std::string& direction) {

        json result;
        result["chunk"] = json::array();

        int64_t from_so = 0;
        int64_t to_so = INT64_MAX;
        int64_t from_top = 0;
        int64_t to_top = INT64_MAX;

        // Parse tokens - format "t<topo>-<stream>" or "s<stream>"
        auto parse_token = [](const std::string& t, int64_t& topo, int64_t& stream) {
            if (t.empty()) return;
            if (t[0] == 't') {
                auto dash = t.find('-');
                if (dash != std::string::npos) {
                    topo = std::stoll(t.substr(1, dash - 1));
                    stream = std::stoll(t.substr(dash + 1));
                }
            } else if (t[0] == 's') {
                stream = std::stoll(t.substr(1));
            } else {
                stream = std::stoll(t);
            }
        };

        parse_token(from_token, from_top, from_so);
        parse_token(to_token, to_top, to_so);

        // Build query
        std::string query =
            "SELECT e.event_id, e.type, e.sender, e.content, e.stream_ordering, "
            "e.origin_server_ts, e.state_key, e.depth, e.topological_ordering, "
            "e.membership, ej.json "
            "FROM events e "
            "LEFT JOIN event_json ej ON e.event_id = ej.event_id "
            "WHERE e.room_id = ? AND e.is_outlier = 0 ";

        std::vector<DatabaseType> params = {room_id};

        // Add stream range
        query += "AND e.stream_ordering > ? AND e.stream_ordering < ? ";
        params.push_back(from_so);
        params.push_back(to_so);

        // Add topological range
        if (from_token.empty() || from_token[0] == 't') {
            query += "AND e.topological_ordering >= ? ";
            params.push_back(from_top);
        }
        if (to_token.empty() || to_token[0] == 't') {
            query += "AND e.topological_ordering <= ? ";
            params.push_back(to_top);
        }

        // Add ordering and limit
        bool is_backward = (direction == "b" || direction == "backward");
        if (is_backward) {
            query += "ORDER BY e.topological_ordering DESC, e.stream_ordering DESC LIMIT ?";
        } else {
            query += "ORDER BY e.topological_ordering ASC, e.stream_ordering ASC LIMIT ?";
        }
        params.push_back(limit);

        auto rows = txn.select(query, params);

        int64_t last_topo = 0;
        int64_t last_so = 0;
        int count = 0;

        for (auto& row : rows) {
            json ev;
            ev["event_id"] = row.get<std::string>(0);
            ev["type"] = row.get<std::string>(1);
            ev["sender"] = row.get<std::string>(2);
            ev["content"] = json::parse(row.get<std::string>(3));
            ev["stream_ordering"] = row.get<int64_t>(4);
            ev["origin_server_ts"] = row.get<int64_t>(5);
            if (!row.is_null(6)) ev["state_key"] = row.get<std::string>(6);
            if (!row.is_null(7)) ev["depth"] = row.get<int64_t>(7);
            if (!row.is_null(8)) {
                int64_t topo = row.get<int64_t>(8);
                ev["topological_ordering"] = topo;
            }
            if (!row.is_null(9)) ev["membership"] = row.get<std::string>(9);

            // If full JSON is available, parse it
            if (!row.is_null(10)) {
                try {
                    json full = json::parse(row.get<std::string>(10));
                    for (auto& [key, val] : full.items()) {
                        if (!ev.contains(key)) ev[key] = val;
                    }
                } catch (...) {}
            }

            result["chunk"].push_back(ev);

            int64_t topo = row.is_null(8) ? 0 : row.get<int64_t>(8);
            int64_t so = row.get<int64_t>(4);
            last_topo = topo;
            last_so = so;
            count++;
        }

        // Generate pagination tokens
        if (count >= limit) {
            // There may be more events
            std::string start_tok = "t" + std::to_string(from_top) + "-" +
                                     std::to_string(from_so);
            std::string end_tok = "t" + std::to_string(last_topo) + "-" +
                                   std::to_string(last_so);
            result["start"] = start_tok;
            result["end"] = end_tok;
        } else {
            result["start"] = from_token.empty() ? "s0" : from_token;
            result["end"] = to_token;
        }

        return result;
    }

    // ========================================================================
    // Thread Summary
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_thread_summary - Get summary of all threads in a room
    // Equivalent to get_thread_summary (line parameter in Python)
    // ------------------------------------------------------------------------
    json get_thread_summary(
        LoggingTransaction& txn,
        const std::string& room_id,
        int limit = 5) {

        json result = json::array();

        // Get threads ordered by latest activity
        auto threads = txn.select(
            "SELECT er.relates_to_id as root_id, "
            "COUNT(DISTINCT er.event_id) as reply_count, "
            "MAX(e.stream_ordering) as latest_reply_so, "
            "MAX(e.origin_server_ts) as latest_ts, "
            "MIN(e.stream_ordering) as earliest_so "
            "FROM event_relations er "
            "JOIN events e ON er.event_id = e.event_id "
            "WHERE er.relation_type = 'm.thread' AND e.room_id = ? "
            "AND e.is_outlier = 0 "
            "GROUP BY er.relates_to_id "
            "ORDER BY latest_reply_so DESC "
            "LIMIT ?",
            {room_id, limit});

        for (auto& row : threads) {
            json thread;
            std::string root_id = row.get<std::string>(0);
            thread["root_event_id"] = root_id;
            thread["count"] = row.get<int64_t>(1);
            thread["latest_reply_stream_ordering"] = row.get<int64_t>(2);
            thread["latest_reply_ts"] = row.get<int64_t>(3);

            // Get the root event details
            auto root = txn.select_one(
                "SELECT sender, content, origin_server_ts, type, depth "
                "FROM events WHERE event_id = ? AND room_id = ?",
                {root_id, room_id});

            if (root && !root->is_null(0)) {
                thread["sender"] = root->get<std::string>(0);
                try {
                    json content = json::parse(root->get<std::string>(1));
                    thread["content"] = content;
                } catch (...) {
                    thread["content"] = root->get<std::string>(1);
                }
                thread["origin_server_ts"] = root->get<int64_t>(2);
                thread["type"] = root->get<std::string>(3);
                thread["depth"] = root->get<int64_t>(4);
            }

            // Get latest reply participant
            auto latest = txn.select_one(
                "SELECT e.sender FROM events e "
                "JOIN event_relations er ON e.event_id = er.event_id "
                "WHERE er.relates_to_id = ? AND er.relation_type = 'm.thread' "
                "ORDER BY e.stream_ordering DESC LIMIT 1",
                {root_id});

            if (latest && !latest->is_null(0)) {
                thread["latest_reply_sender"] = latest->get<std::string>(0);
            }

            // Count unique participants
            auto participants = txn.select_one(
                "SELECT COUNT(DISTINCT e.sender) FROM events e "
                "JOIN event_relations er ON e.event_id = er.event_id "
                "WHERE er.relates_to_id = ? AND er.relation_type = 'm.thread'",
                {root_id});

            if (participants && !participants->is_null(0)) {
                thread["participant_count"] = participants->get<int64_t>(0);
            }

            result.push_back(thread);
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // get_thread_events - Get events in a specific thread
    // ------------------------------------------------------------------------
    json get_thread_events(
        LoggingTransaction& txn,
        const std::string& thread_root_id,
        int limit = 20,
        const std::string& direction = "forward") {

        json result;
        result["events"] = json::array();

        std::string order = (direction == "backward") ? "DESC" : "ASC";
        auto rows = txn.select(
            "SELECT e.event_id, e.type, e.sender, e.content, e.stream_ordering, "
            "e.origin_server_ts, e.state_key, e.depth "
            "FROM events e "
            "JOIN event_relations er ON e.event_id = er.event_id "
            "WHERE er.relates_to_id = ? AND er.relation_type = 'm.thread' "
            "AND e.is_outlier = 0 "
            "ORDER BY e.stream_ordering " + order + " LIMIT ?",
            {thread_root_id, limit});

        for (auto& row : rows) {
            json ev;
            ev["event_id"] = row.get<std::string>(0);
            ev["type"] = row.get<std::string>(1);
            ev["sender"] = row.get<std::string>(2);
            ev["content"] = json::parse(row.get<std::string>(3));
            ev["stream_ordering"] = row.get<int64_t>(4);
            ev["origin_server_ts"] = row.get<int64_t>(5);
            if (!row.is_null(6)) ev["state_key"] = row.get<std::string>(6);
            if (!row.is_null(7)) ev["depth"] = row.get<int64_t>(7);
            result["events"].push_back(ev);
        }

        return result;
    }

    // ========================================================================
    // Joined Users
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_joined_users - Get all users currently joined to a room
    // Equivalent to get_joined_users (line parameter in Python)
    // ------------------------------------------------------------------------
    std::vector<json> get_joined_users(
        LoggingTransaction& txn,
        const std::string& room_id) {

        std::vector<json> result;

        // Get current state membership entries for join
        auto members = txn.select(
            "SELECT cse.state_key, cse.event_id "
            "FROM current_state_events cse "
            "JOIN events e ON cse.event_id = e.event_id "
            "WHERE cse.room_id = ? AND cse.type = 'm.room.member' "
            "AND e.membership = 'join'",
            {room_id});

        for (auto& row : members) {
            std::string user_id = row.get<std::string>(0);
            std::string event_id = row.get<std::string>(1);

            json member;
            member["user_id"] = user_id;
            member["event_id"] = event_id;

            // Get display name and avatar from the membership event content
            auto ev = txn.select_one(
                "SELECT content, sender FROM event_json WHERE event_id = ?",
                {event_id});

            if (ev && !ev->is_null(0)) {
                try {
                    json content = json::parse(ev->get<std::string>(0));
                    if (content.contains("displayname")) {
                        member["display_name"] = content["displayname"];
                    }
                    if (content.contains("avatar_url")) {
                        member["avatar_url"] = content["avatar_url"];
                    }
                } catch (...) {}
                member["sender"] = ev->get<std::string>(1);
            }

            result.push_back(member);
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // get_joined_users_from_context - Get joined users at a historical point
    // ------------------------------------------------------------------------
    std::vector<json> get_joined_users_from_context(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& event_id) {

        std::vector<json> result;

        // Get state group for the event
        auto sg = txn.select_one(
            "SELECT state_group FROM event_to_state_groups WHERE event_id = ?",
            {event_id});
        if (!sg || sg->is_null(0)) return result;

        // Get membership state from that state group
        auto members = txn.select(
            "SELECT sgs.state_key, sgs.event_id "
            "FROM state_groups_state sgs "
            "JOIN events e ON sgs.event_id = e.event_id "
            "WHERE sgs.state_group = ? AND sgs.type = 'm.room.member' "
            "AND e.membership = 'join'",
            {sg->get<int64_t>(0)});

        for (auto& row : members) {
            std::string user_id = row.get<std::string>(0);
            std::string event_id_fk = row.get<std::string>(1);

            json member;
            member["user_id"] = user_id;

            auto ev = txn.select_one(
                "SELECT content FROM event_json WHERE event_id = ?",
                {event_id_fk});

            if (ev && !ev->is_null(0)) {
                try {
                    json content = json::parse(ev->get<std::string>(0));
                    if (content.contains("displayname")) {
                        member["display_name"] = content["displayname"];
                    }
                    if (content.contains("avatar_url")) {
                        member["avatar_url"] = content["avatar_url"];
                    }
                } catch (...) {}
            }

            result.push_back(member);
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // get_joined_user_count - Count joined users in a room (fast COUNT query)
    // ------------------------------------------------------------------------
    int64_t get_joined_user_count(
        LoggingTransaction& txn,
        const std::string& room_id) {

        auto row = txn.select_one(
            "SELECT COUNT(*) FROM current_state_events cse "
            "JOIN events e ON cse.event_id = e.event_id "
            "WHERE cse.room_id = ? AND cse.type = 'm.room.member' "
            "AND e.membership = 'join'",
            {room_id});

        return row ? row->get<int64_t>(0) : 0;
    }

    // ========================================================================
    // Joined Hosts (Federated servers with joined users)
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_joined_hosts - Get distinct servers that have joined users in a room
    // Equivalent to get_joined_hosts (line parameter in Python)
    // ------------------------------------------------------------------------
    std::vector<std::string> get_joined_hosts(
        LoggingTransaction& txn,
        const std::string& room_id) {

        std::vector<std::string> result;
        auto rows = txn.select(
            "SELECT DISTINCT cse.state_key "
            "FROM current_state_events cse "
            "JOIN events e ON cse.event_id = e.event_id "
            "WHERE cse.room_id = ? AND cse.type = 'm.room.member' "
            "AND e.membership = 'join'",
            {room_id});

        std::set<std::string> servers;
        for (auto& row : rows) {
            std::string uid = row.get<std::string>(0);
            // Matrix user IDs are @localpart:server
            auto colon = uid.find(':');
            if (colon != std::string::npos) {
                servers.insert(uid.substr(colon + 1));
            }
        }

        for (const auto& s : servers) {
            result.push_back(s);
        }
        return result;
    }

    // ------------------------------------------------------------------------
    // get_joined_hosts_with_count - Get hosts with their join count
    // ------------------------------------------------------------------------
    std::map<std::string, int64_t> get_joined_hosts_with_count(
        LoggingTransaction& txn,
        const std::string& room_id) {

        std::map<std::string, int64_t> result;
        auto rows = txn.select(
            "SELECT cse.state_key "
            "FROM current_state_events cse "
            "JOIN events e ON cse.event_id = e.event_id "
            "WHERE cse.room_id = ? AND cse.type = 'm.room.member' "
            "AND e.membership = 'join'",
            {room_id});

        for (auto& row : rows) {
            std::string uid = row.get<std::string>(0);
            auto colon = uid.find(':');
            if (colon != std::string::npos) {
                result[uid.substr(colon + 1)]++;
            }
        }
        return result;
    }

    // ========================================================================
    // Forward Extremities
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_forward_extremities - Get forward extremity events for a room
    // Equivalent to get_forward_extremities
    // ------------------------------------------------------------------------
    std::vector<std::string> get_forward_extremities(
        LoggingTransaction& txn,
        const std::string& room_id) {

        std::vector<std::string> result;
        auto rows = txn.select(
            "SELECT event_id FROM event_forward_extremities WHERE room_id = ?",
            {room_id});
        for (auto& row : rows) result.push_back(row.get<std::string>(0));
        return result;
    }

    // ------------------------------------------------------------------------
    // get_forward_extremities_for_room_with_metadata - Get forward extremities
    // with stream ordering and depth information
    // ------------------------------------------------------------------------
    json get_forward_extremities_with_metadata(
        LoggingTransaction& txn,
        const std::string& room_id) {

        json result = json::array();
        auto rows = txn.select(
            "SELECT efe.event_id, e.depth, e.stream_ordering, e.topological_ordering "
            "FROM event_forward_extremities efe "
            "JOIN events e ON efe.event_id = e.event_id "
            "WHERE efe.room_id = ? "
            "ORDER BY e.stream_ordering DESC",
            {room_id});

        for (auto& row : rows) {
            json ext;
            ext["event_id"] = row.get<std::string>(0);
            ext["depth"] = row.get<int64_t>(1);
            ext["stream_ordering"] = row.get<int64_t>(2);
            ext["topological_ordering"] = row.get<int64_t>(3);
            result.push_back(ext);
        }
        return result;
    }

    // ------------------------------------------------------------------------
    // get_forward_extremities_count
    // ------------------------------------------------------------------------
    int64_t get_forward_extremities_count(
        LoggingTransaction& txn,
        const std::string& room_id) {

        auto row = txn.select_one(
            "SELECT COUNT(*) FROM event_forward_extremities WHERE room_id = ?",
            {room_id});
        return row ? row->get<int64_t>(0) : 0;
    }

    // ========================================================================
    // Backward Extremities
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_backward_extremities - Get backward extremity events for a room
    // Equivalent to get_backward_extremities
    // ------------------------------------------------------------------------
    std::vector<std::string> get_backward_extremities(
        LoggingTransaction& txn,
        const std::string& room_id) {

        std::vector<std::string> result;
        auto rows = txn.select(
            "SELECT event_id FROM event_backward_extremities WHERE room_id = ?",
            {room_id});
        for (auto& row : rows) result.push_back(row.get<std::string>(0));
        return result;
    }

    // ------------------------------------------------------------------------
    // get_backward_extremities_count
    // ------------------------------------------------------------------------
    int64_t get_backward_extremities_count(
        LoggingTransaction& txn,
        const std::string& room_id) {

        auto row = txn.select_one(
            "SELECT COUNT(*) FROM event_backward_extremities WHERE room_id = ?",
            {room_id});
        return row ? row->get<int64_t>(0) : 0;
    }

    // ------------------------------------------------------------------------
    // is_event_backward_extremity - Check if an event is a backward extremity
    // ------------------------------------------------------------------------
    bool is_event_backward_extremity(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT 1 FROM event_backward_extremities "
            "WHERE room_id = ? AND event_id = ?",
            {room_id, event_id});
        return row && !row->is_null(0);
    }

    // ------------------------------------------------------------------------
    // is_event_forward_extremity - Check if an event is a forward extremity
    // ------------------------------------------------------------------------
    bool is_event_forward_extremity(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT 1 FROM event_forward_extremities "
            "WHERE room_id = ? AND event_id = ?",
            {room_id, event_id});
        return row && !row->is_null(0);
    }

    // ========================================================================
    // Event Redaction
    // ========================================================================

    // ------------------------------------------------------------------------
    // mark_as_redacted - Mark an event as redacted
    // Equivalent to mark_as_redacted
    // ------------------------------------------------------------------------
    void mark_as_redacted(
        LoggingTransaction& txn,
        const std::string& event_id) {

        txn.execute(
            "UPDATE events SET is_redacted = 1, content = '{}', "
            "unsigned_data = '{\"redacted_by\":\"\"}' "
            "WHERE event_id = ?",
            {event_id});
    }

    // ------------------------------------------------------------------------
    // store_redaction - Store a redaction relationship
    // Equivalent to store_redaction
    // ------------------------------------------------------------------------
    void store_redaction(
        LoggingTransaction& txn,
        const std::string& event_id,
        const std::string& redacts) {

        int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        // Insert or update the redaction record
        txn.execute(
            "INSERT INTO redactions (event_id, redacts, received_ts, have_censored) "
            "VALUES (?, ?, ?, 1) "
            "ON CONFLICT (event_id) DO UPDATE SET "
            "redacts = excluded.redacts, received_ts = excluded.received_ts, "
            "have_censored = 1",
            {event_id, redacts, now_ms});

        // Mark the target event as redacted
        mark_as_redacted(txn, redacts);

        // Update the content on the redacted event
        txn.execute(
            "UPDATE events SET unsigned_data = json_set("
            "  COALESCE(unsigned_data, '{}'), '$.redacted_because', "
            "  (SELECT json FROM event_json WHERE event_id = ?) "
            ") WHERE event_id = ?",
            {event_id, redacts});
    }

    // ------------------------------------------------------------------------
    // get_redaction - Get the redaction event for a given event
    // Equivalent to get_redaction
    // ------------------------------------------------------------------------
    std::optional<std::string> get_redaction(
        LoggingTransaction& txn,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT event_id FROM redactions WHERE redacts = ? "
            "ORDER BY received_ts DESC LIMIT 1",
            {event_id});

        if (row && !row->is_null(0)) return row->get<std::string>(0);
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // get_redactions_for_events - Get all redactions for multiple events
    // ------------------------------------------------------------------------
    std::map<std::string, std::vector<std::string>> get_redactions_for_events(
        LoggingTransaction& txn,
        const std::vector<std::string>& event_ids) {

        std::map<std::string, std::vector<std::string>> result;
        for (size_t i = 0; i < event_ids.size(); i += 100) {
            size_t end = std::min(i + 100, event_ids.size());
            std::vector<std::string> batch(event_ids.begin() + i,
                                             event_ids.begin() + end);

            auto rows = txn.select(
                "SELECT redacts, event_id FROM redactions WHERE redacts IN (" +
                    make_in_list_sql_clause("redacts", batch) + ")",
                to_db_params(batch));

            for (auto& row : rows) {
                result[row.get<std::string>(0)].push_back(row.get<std::string>(1));
            }
        }
        return result;
    }

    // ------------------------------------------------------------------------
    // is_event_redacted - Check if an event has been redacted
    // ------------------------------------------------------------------------
    bool is_event_redacted(
        LoggingTransaction& txn,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT COUNT(*) FROM redactions WHERE redacts = ?",
            {event_id});
        return row && row->get<int64_t>(0) > 0;
    }

    // ========================================================================
    // Thread Subscriptions
    // ========================================================================

    // ------------------------------------------------------------------------
    // add_thread_subscription - Subscribe a user to a thread
    // Equivalent to add_thread_subscription
    // ------------------------------------------------------------------------
    void add_thread_subscription(
        LoggingTransaction& txn,
        const std::string& user_id,
        const std::string& room_id,
        const std::string& thread_id) {

        int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        txn.execute(
            "INSERT INTO thread_subscriptions "
            "(user_id, room_id, thread_id, subscribed_ts) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT (user_id, thread_id) DO UPDATE SET "
            "room_id = excluded.room_id, subscribed_ts = excluded.subscribed_ts",
            {user_id, room_id, thread_id, now_ms});
    }

    // ------------------------------------------------------------------------
    // remove_thread_subscription - Unsubscribe a user from a thread
    // Equivalent to remove_thread_subscription
    // ------------------------------------------------------------------------
    void remove_thread_subscription(
        LoggingTransaction& txn,
        const std::string& user_id,
        const std::string& thread_id) {

        txn.execute(
            "DELETE FROM thread_subscriptions "
            "WHERE user_id = ? AND thread_id = ?",
            {user_id, thread_id});
    }

    // ------------------------------------------------------------------------
    // get_thread_subscriptions - Get all thread subscriptions for a user
    // ------------------------------------------------------------------------
    std::vector<json> get_thread_subscriptions(
        LoggingTransaction& txn,
        const std::string& user_id) {

        std::vector<json> result;
        auto rows = txn.select(
            "SELECT ts.thread_id, ts.room_id, ts.subscribed_ts "
            "FROM thread_subscriptions ts "
            "WHERE ts.user_id = ? "
            "ORDER BY ts.subscribed_ts DESC",
            {user_id});

        for (auto& row : rows) {
            json sub;
            sub["thread_id"] = row.get<std::string>(0);
            sub["room_id"] = row.get<std::string>(1);
            sub["subscribed_ts"] = row.get<int64_t>(2);
            result.push_back(sub);
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // is_thread_subscribed - Check if a user is subscribed to a thread
    // ------------------------------------------------------------------------
    bool is_thread_subscribed(
        LoggingTransaction& txn,
        const std::string& user_id,
        const std::string& thread_id) {

        auto row = txn.select_one(
            "SELECT 1 FROM thread_subscriptions "
            "WHERE user_id = ? AND thread_id = ?",
            {user_id, thread_id});
        return row && !row->is_null(0);
    }

    // ========================================================================
    // Partial State Room Management
    // ========================================================================

    // ------------------------------------------------------------------------
    // is_room_partial_state - Check if a room is in partial state
    // Equivalent to is_room_partial_state
    // ------------------------------------------------------------------------
    bool is_room_partial_state(
        LoggingTransaction& txn,
        const std::string& room_id) {

        auto row = txn.select_one(
            "SELECT 1 FROM partial_state_rooms WHERE room_id = ?",
            {room_id});
        return row && !row->is_null(0);
    }

    // ------------------------------------------------------------------------
    // mark_room_as_partial_state - Mark a room as having partial state
    // Equivalent to mark_room_as_partial_state
    // ------------------------------------------------------------------------
    void mark_room_as_partial_state(
        LoggingTransaction& txn,
        const std::string& room_id) {

        int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        txn.execute(
            "INSERT INTO partial_state_rooms (room_id, joined_ts) VALUES (?, ?) "
            "ON CONFLICT (room_id) DO NOTHING",
            {room_id, now_ms});

        // Also remove from unpartial if it was there
        txn.execute(
            "DELETE FROM unpartial_stated_rooms WHERE room_id = ?",
            {room_id});
    }

    // ------------------------------------------------------------------------
    // unmark_room_as_partial_state - Mark a room as fully stated
    // Equivalent to unmark_room_as_partial_state
    // ------------------------------------------------------------------------
    void unmark_room_as_partial_state(
        LoggingTransaction& txn,
        const std::string& room_id) {

        txn.execute(
            "DELETE FROM partial_state_rooms WHERE room_id = ?",
            {room_id});

        txn.execute(
            "INSERT INTO unpartial_stated_rooms (room_id) VALUES (?) "
            "ON CONFLICT (room_id) DO NOTHING",
            {room_id});
    }

    // ------------------------------------------------------------------------
    // get_partial_state_rooms - List all rooms in partial state
    // ------------------------------------------------------------------------
    std::vector<std::string> get_partial_state_rooms(
        LoggingTransaction& txn) {

        std::vector<std::string> result;
        auto rows = txn.select(
            "SELECT room_id FROM partial_state_rooms ORDER BY joined_ts");
        for (auto& row : rows) result.push_back(row.get<std::string>(0));
        return result;
    }

    // ------------------------------------------------------------------------
    // get_un_partial_stated_rooms - List rooms that were unpartial-stated
    // ------------------------------------------------------------------------
    std::vector<std::string> get_un_partial_stated_rooms(
        LoggingTransaction& txn) {

        std::vector<std::string> result;
        auto rows = txn.select("SELECT room_id FROM unpartial_stated_rooms");
        for (auto& row : rows) result.push_back(row.get<std::string>(0));
        return result;
    }

    // ------------------------------------------------------------------------
    // add_partial_state_room_event - Record an event in a partial state room
    // ------------------------------------------------------------------------
    void add_partial_state_room_event(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& event_id) {

        txn.execute(
            "INSERT INTO partial_state_rooms_events (room_id, event_id) "
            "VALUES (?, ?) ON CONFLICT DO NOTHING",
            {room_id, event_id});
    }

    // ------------------------------------------------------------------------
    // remove_partial_state_room_event
    // ------------------------------------------------------------------------
    void remove_partial_state_room_event(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& event_id) {

        txn.execute(
            "DELETE FROM partial_state_rooms_events "
            "WHERE room_id = ? AND event_id = ?",
            {room_id, event_id});
    }

    // ------------------------------------------------------------------------
    // get_partial_state_room_events - List partial state events for a room
    // ------------------------------------------------------------------------
    std::vector<std::string> get_partial_state_room_events(
        LoggingTransaction& txn,
        const std::string& room_id,
        int limit = 100) {

        std::vector<std::string> result;
        auto rows = txn.select(
            "SELECT psre.event_id FROM partial_state_rooms_events psre "
            "JOIN events e ON psre.event_id = e.event_id "
            "WHERE psre.room_id = ? "
            "ORDER BY e.stream_ordering ASC LIMIT ?",
            {room_id, limit});

        for (auto& row : rows) result.push_back(row.get<std::string>(0));
        return result;
    }

    // ========================================================================
    // Event Presence Checks
    // ========================================================================

    // ------------------------------------------------------------------------
    // have_events_in_timeline - Which of the given events are in the timeline
    // ------------------------------------------------------------------------
    std::set<std::string> have_events_in_timeline(
        LoggingTransaction& txn,
        const std::vector<std::string>& event_ids) {

        std::set<std::string> result;
        for (size_t i = 0; i < event_ids.size(); i += 100) {
            size_t end = std::min(i + 100, event_ids.size());
            std::vector<std::string> batch(event_ids.begin() + i,
                                             event_ids.begin() + end);

            auto rows = txn.select(
                "SELECT event_id FROM events WHERE is_outlier = 0 AND event_id IN (" +
                    make_in_list_sql_clause("event_id", batch) + ")",
                to_db_params(batch));

            for (auto& row : rows) result.insert(row.get<std::string>(0));
        }
        return result;
    }

    // ------------------------------------------------------------------------
    // have_seen_events - Which events have been seen (exist in DB)
    // ------------------------------------------------------------------------
    std::map<std::string, bool> have_seen_events(
        LoggingTransaction& txn,
        const std::vector<std::string>& event_ids) {

        std::map<std::string, bool> result;
        for (const auto& eid : event_ids) result[eid] = false;

        for (size_t i = 0; i < event_ids.size(); i += 500) {
            size_t end = std::min(i + 500, event_ids.size());
            std::vector<std::string> batch(event_ids.begin() + i,
                                             event_ids.begin() + end);

            auto rows = txn.select(
                "SELECT event_id FROM events WHERE event_id IN (" +
                    make_in_list_sql_clause("event_id", batch) + ")",
                to_db_params(batch));

            for (auto& row : rows) {
                result[row.get<std::string>(0)] = true;
            }
        }
        return result;
    }

    // ------------------------------------------------------------------------
    // have_seen_event - Check if a single event exists
    // ------------------------------------------------------------------------
    bool have_seen_event(
        LoggingTransaction& txn,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT 1 FROM events WHERE event_id = ? LIMIT 1",
            {event_id});
        return row && !row->is_null(0);
    }

    // ========================================================================
    // Gap Detection
    // ========================================================================

    // ------------------------------------------------------------------------
    // is_event_next_to_backward_gap - Check if event is at a backward gap
    // ------------------------------------------------------------------------
    bool is_event_next_to_backward_gap(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& event_id) {

        // Event is next to a backward gap if it's a backward extremity
        auto row = txn.select_one(
            "SELECT 1 FROM event_backward_extremities "
            "WHERE room_id = ? AND event_id = ?",
            {room_id, event_id});
        return row && !row->is_null(0);
    }

    // ------------------------------------------------------------------------
    // is_event_next_to_forward_gap - Check if event is at a forward gap
    // ------------------------------------------------------------------------
    bool is_event_next_to_forward_gap(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& event_id) {

        // Event is next to a forward gap if it has no forward edges
        auto row = txn.select_one(
            "SELECT 1 FROM event_edges WHERE prev_event_id = ? LIMIT 1",
            {event_id});

        if (!row || row->is_null(0)) return true;

        // Or if it has forward edges but is itself a forward extremity
        auto ext_row = txn.select_one(
            "SELECT 1 FROM event_forward_extremities "
            "WHERE room_id = ? AND event_id = ?",
            {room_id, event_id});
        return ext_row && !ext_row->is_null(0);
    }

    // ========================================================================
    // Stream Ordering
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_room_max_stream_ordering - Get max stream ordering for a room
    // ------------------------------------------------------------------------
    int64_t get_room_max_stream_ordering(
        LoggingTransaction& txn,
        const std::string& room_id) {

        auto row = txn.select_one(
            "SELECT COALESCE(MAX(stream_ordering), 0) FROM events "
            "WHERE room_id = ?",
            {room_id});
        return row ? row->get<int64_t>(0) : 0;
    }

    // ------------------------------------------------------------------------
    // get_room_min_stream_ordering - Get min stream ordering for a room
    // ------------------------------------------------------------------------
    int64_t get_room_min_stream_ordering(
        LoggingTransaction& txn,
        const std::string& room_id) {

        auto row = txn.select_one(
            "SELECT COALESCE(MIN(stream_ordering), 0) FROM events "
            "WHERE room_id = ?",
            {room_id});
        return row ? row->get<int64_t>(0) : 0;
    }

    // ------------------------------------------------------------------------
    // get_global_max_stream_ordering - Get max stream ordering across all rooms
    // ------------------------------------------------------------------------
    int64_t get_global_max_stream_ordering(
        LoggingTransaction& txn) {

        auto row = txn.select_one(
            "SELECT COALESCE(MAX(stream_ordering), 0) FROM events");
        return row ? row->get<int64_t>(0) : 0;
    }

    // ------------------------------------------------------------------------
    // get_max_topological_ordering - Get max topological for a room
    // ------------------------------------------------------------------------
    int64_t get_max_topological_ordering(
        LoggingTransaction& txn,
        const std::string& room_id) {

        auto row = txn.select_one(
            "SELECT COALESCE(MAX(topological_ordering), 0) FROM events "
            "WHERE room_id = ?",
            {room_id});
        return row ? row->get<int64_t>(0) : 0;
    }

    // ========================================================================
    // Event Metadata
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_event_ordering - Get topological and stream ordering for an event
    // ------------------------------------------------------------------------
    std::tuple<int64_t, int64_t> get_event_ordering(
        LoggingTransaction& txn,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT topological_ordering, stream_ordering FROM events "
            "WHERE event_id = ?",
            {event_id});

        if (!row || row->is_null(0)) {
            throw std::runtime_error("Could not find event " + event_id);
        }

        return {row->get<int64_t>(0), row->get<int64_t>(1)};
    }

    // ------------------------------------------------------------------------
    // get_event_room_id - Get the room an event belongs to
    // ------------------------------------------------------------------------
    std::optional<std::string> get_event_room_id(
        LoggingTransaction& txn,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT room_id FROM events WHERE event_id = ?",
            {event_id});
        if (row && !row->is_null(0)) return row->get<std::string>(0);
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // get_event_depth - Get the depth of an event
    // ------------------------------------------------------------------------
    int64_t get_event_depth(
        LoggingTransaction& txn,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT depth FROM events WHERE event_id = ?",
            {event_id});
        return row ? row->get<int64_t>(0) : 0;
    }

    // ------------------------------------------------------------------------
    // get_event_sender - Get the sender of an event
    // ------------------------------------------------------------------------
    std::optional<std::string> get_event_sender(
        LoggingTransaction& txn,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT sender FROM events WHERE event_id = ?",
            {event_id});
        if (row && !row->is_null(0)) return row->get<std::string>(0);
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // get_event_type - Get the type of an event
    // ------------------------------------------------------------------------
    std::optional<std::string> get_event_type(
        LoggingTransaction& txn,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT type FROM events WHERE event_id = ?",
            {event_id});
        if (row && !row->is_null(0)) return row->get<std::string>(0);
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // get_event_prevs - Get the prev_event_ids for an event
    // ------------------------------------------------------------------------
    std::vector<std::string> get_event_prevs(
        LoggingTransaction& txn,
        const std::string& event_id) {

        std::vector<std::string> result;
        auto rows = txn.select(
            "SELECT prev_event_id FROM event_edges WHERE event_id = ?",
            {event_id});
        for (auto& row : rows) result.push_back(row.get<std::string>(0));
        return result;
    }

    // ------------------------------------------------------------------------
    // get_event_successors - Get events that reference this one as a prev event
    // ------------------------------------------------------------------------
    std::vector<std::string> get_event_successors(
        LoggingTransaction& txn,
        const std::string& event_id) {

        std::vector<std::string> result;
        auto rows = txn.select(
            "SELECT event_id FROM event_edges WHERE prev_event_id = ?",
            {event_id});
        for (auto& row : rows) result.push_back(row.get<std::string>(0));
        return result;
    }

    // ========================================================================
    // Event Lookup Utilities
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_event_id_for_timestamp - Find event closest to a given timestamp
    // ------------------------------------------------------------------------
    std::optional<std::string> get_event_id_for_timestamp(
        LoggingTransaction& txn,
        const std::string& room_id,
        int64_t timestamp,
        Direction direction = Direction::BACKWARDS) {

        std::string cmp = (direction == Direction::BACKWARDS) ? "<=" : ">=";
        std::string ord = (direction == Direction::BACKWARDS) ? "DESC" : "ASC";

        auto row = txn.select_one(
            "SELECT event_id FROM events "
            "WHERE room_id = ? AND origin_server_ts " + cmp + " ? "
            "AND is_outlier = 0 "
            "ORDER BY origin_server_ts " + ord +
            ", depth " + ord +
            ", stream_ordering " + ord + " LIMIT 1",
            {room_id, timestamp});

        if (row && !row->is_null(0)) return row->get<std::string>(0);
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // get_event_id_from_transaction_id - Resolve txn_id to event_id
    // ------------------------------------------------------------------------
    std::optional<std::string> get_event_id_from_transaction_id(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& user_id,
        const std::string& device_id,
        const std::string& txn_id) {

        auto row = txn.select_one(
            "SELECT event_id FROM event_txn_id_device_id "
            "WHERE room_id = ? AND user_id = ? AND device_id = ? AND txn_id = ?",
            {room_id, user_id, device_id, txn_id});

        if (row && !row->is_null(0)) return row->get<std::string>(0);
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // get_next_event_to_expire - Get the next event scheduled for expiry
    // ------------------------------------------------------------------------
    std::optional<std::tuple<std::string, int64_t>> get_next_event_to_expire(
        LoggingTransaction& txn) {

        auto row = txn.select_one(
            "SELECT event_id, expiry_ts FROM event_expiry "
            "ORDER BY expiry_ts ASC LIMIT 1");

        if (row && !row->is_null(0)) {
            return std::make_tuple(row->get<std::string>(0), row->get<int64_t>(1));
        }
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // get_events_sent_by_user_in_room - Events a user sent in a room
    // ------------------------------------------------------------------------
    std::vector<std::string> get_events_sent_by_user_in_room(
        LoggingTransaction& txn,
        const std::string& user_id,
        const std::string& room_id,
        int64_t limit,
        std::optional<std::vector<std::string>> type_filter = std::nullopt) {

        std::string query =
            "SELECT event_id FROM events "
            "WHERE sender = ? AND room_id = ? AND is_outlier = 0 ";
        std::vector<DatabaseType> params = {user_id, room_id};

        if (type_filter.has_value() && !type_filter->empty()) {
            query += "AND type IN (" +
                make_in_list_sql_clause("type", type_filter.value()) + ") ";
            auto type_params = to_db_params(type_filter.value());
            params.insert(params.end(), type_params.begin(), type_params.end());
        }

        query += "ORDER BY stream_ordering DESC LIMIT ?";
        params.push_back(limit);

        std::vector<std::string> result;
        auto rows = txn.select(query, params);
        for (auto& row : rows) result.push_back(row.get<std::string>(0));
        return result;
    }

    // ------------------------------------------------------------------------
    // get_sent_invite_count_by_user - Count sent invites since timestamp
    // ------------------------------------------------------------------------
    int64_t get_sent_invite_count_by_user(
        LoggingTransaction& txn,
        const std::string& user_id,
        int64_t from_ts) {

        auto row = txn.select_one(
            "SELECT COUNT(DISTINCT rm.event_id) "
            "FROM room_memberships rm "
            "JOIN events e ON rm.event_id = e.event_id "
            "WHERE rm.sender = ? AND rm.membership = ? "
            "AND e.type = 'm.room.member' AND e.origin_server_ts >= ?",
            {user_id, std::string("invite"), from_ts});

        return row ? row->get<int64_t>(0) : 0;
    }

    // ========================================================================
    // Current State Delta Stream (Replication)
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_current_state_delta - Get current state delta changes
    // ------------------------------------------------------------------------
    struct CurrentStateDeltaRow {
        int64_t stream_id;
        std::string room_id;
        std::string type;
        std::string state_key;
        std::string event_id;
    };

    std::vector<CurrentStateDeltaRow> get_current_state_delta_stream(
        LoggingTransaction& txn,
        int64_t from_token,
        int64_t to_token,
        int64_t limit) {

        std::vector<CurrentStateDeltaRow> result;
        auto rows = txn.select(
            "SELECT stream_id, room_id, type, state_key, event_id "
            "FROM current_state_delta_stream "
            "WHERE stream_id > ? AND stream_id <= ? "
            "ORDER BY stream_id ASC LIMIT ?",
            {from_token, to_token, limit});

        for (auto& row : rows) {
            CurrentStateDeltaRow r;
            r.stream_id = row.get<int64_t>(0);
            r.room_id = row.get<std::string>(1);
            r.type = row.get<std::string>(2);
            r.state_key = row.get<std::string>(3);
            r.event_id = row.get<std::string>(4);
            result.push_back(r);
        }
        return result;
    }

    // ========================================================================
    // Event Counting / Statistics
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_current_state_event_count - Count current state events in a room
    // ------------------------------------------------------------------------
    int64_t get_current_state_event_count(
        LoggingTransaction& txn,
        const std::string& room_id) {

        auto row = txn.select_one(
            "SELECT COUNT(*) FROM current_state_events WHERE room_id = ?",
            {room_id});
        return row ? row->get<int64_t>(0) : 0;
    }

    // ------------------------------------------------------------------------
    // get_total_event_count - Total events in a room
    // ------------------------------------------------------------------------
    int64_t get_total_event_count(
        LoggingTransaction& txn,
        const std::string& room_id) {

        auto row = txn.select_one(
            "SELECT COUNT(*) FROM events WHERE room_id = ? AND is_outlier = 0",
            {room_id});
        return row ? row->get<int64_t>(0) : 0;
    }

    // ------------------------------------------------------------------------
    // get_room_event_count_by_type - Event counts broken down by type
    // ------------------------------------------------------------------------
    std::map<std::string, int64_t> get_room_event_count_by_type(
        LoggingTransaction& txn,
        const std::string& room_id) {

        std::map<std::string, int64_t> result;
        auto rows = txn.select(
            "SELECT type, COUNT(*) as cnt FROM events "
            "WHERE room_id = ? AND is_outlier = 0 "
            "GROUP BY type",
            {room_id});

        for (auto& row : rows) {
            result[row.get<std::string>(0)] = row.get<int64_t>(1);
        }
        return result;
    }

    // ------------------------------------------------------------------------
    // get_room_complexity - Calculate room complexity metric
    // ------------------------------------------------------------------------
    std::map<std::string, double> get_room_complexity(
        LoggingTransaction& txn,
        const std::string& room_id) {

        int64_t state_events = get_current_state_event_count(txn, room_id);
        double complexity_v1 = std::round(state_events / 500.0 * 100.0) / 100.0;
        return {{"v1", complexity_v1}};
    }

    // ========================================================================
    // Event Edges / Relations
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_event_relations - Get events related to a parent event
    // ------------------------------------------------------------------------
    json get_event_relations(
        LoggingTransaction& txn,
        const std::string& parent_event_id,
        const std::optional<std::string>& rel_type = std::nullopt,
        int limit = 50) {

        json result;
        result["events"] = json::array();

        std::string query =
            "SELECT er.event_id, er.relation_type, er.aggregation_key, "
            "e.type, e.sender, e.content, e.stream_ordering, e.origin_server_ts "
            "FROM event_relations er "
            "JOIN events e ON er.event_id = e.event_id "
            "WHERE er.relates_to_id = ? AND e.is_outlier = 0 ";

        std::vector<DatabaseType> params = {parent_event_id};

        if (rel_type.has_value()) {
            query += "AND er.relation_type = ? ";
            params.push_back(rel_type.value());
        }

        query += "ORDER BY e.stream_ordering ASC LIMIT ?";
        params.push_back(limit);

        auto rows = txn.select(query, params);
        for (auto& row : rows) {
            json ev;
            ev["event_id"] = row.get<std::string>(0);
            ev["relation_type"] = row.get<std::string>(1);
            if (!row.is_null(2)) ev["aggregation_key"] = row.get<std::string>(2);
            ev["type"] = row.get<std::string>(3);
            ev["sender"] = row.get<std::string>(4);
            try {
                ev["content"] = json::parse(row.get<std::string>(5));
            } catch (...) {
                ev["content"] = row.get<std::string>(5);
            }
            ev["stream_ordering"] = row.get<int64_t>(6);
            ev["origin_server_ts"] = row.get<int64_t>(7);
            result["events"].push_back(ev);
        }

        return result;
    }

    // ------------------------------------------------------------------------
    // have_event_relations - Check if an event has relations
    // ------------------------------------------------------------------------
    bool have_event_relations(
        LoggingTransaction& txn,
        const std::string& parent_event_id) {

        auto row = txn.select_one(
            "SELECT 1 FROM event_relations WHERE relates_to_id = ? LIMIT 1",
            {parent_event_id});
        return row && !row->is_null(0);
    }

    // ========================================================================
    // Historical Event Stream
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_historical_events - Get events for historical timeline view
    // ------------------------------------------------------------------------
    json get_historical_events(
        LoggingTransaction& txn,
        const std::string& room_id,
        int64_t start_ts,
        int64_t end_ts,
        int limit) {

        json result;
        result["events"] = json::array();

        auto rows = txn.select(
            "SELECT event_id, type, sender, content, stream_ordering, "
            "origin_server_ts, topological_ordering, depth, state_key "
            "FROM events "
            "WHERE room_id = ? AND origin_server_ts >= ? "
            "AND origin_server_ts <= ? AND is_outlier = 0 "
            "ORDER BY origin_server_ts ASC, stream_ordering ASC LIMIT ?",
            {room_id, start_ts, end_ts, limit});

        for (auto& row : rows) {
            json ev;
            ev["event_id"] = row.get<std::string>(0);
            ev["type"] = row.get<std::string>(1);
            ev["sender"] = row.get<std::string>(2);
            try {
                ev["content"] = json::parse(row.get<std::string>(3));
            } catch (...) {
                ev["content"] = row.get<std::string>(3);
            }
            ev["stream_ordering"] = row.get<int64_t>(4);
            ev["origin_server_ts"] = row.get<int64_t>(5);
            ev["topological_ordering"] = row.get<int64_t>(6);
            ev["depth"] = row.get<int64_t>(7);
            if (!row.is_null(8)) ev["state_key"] = row.get<std::string>(8);
            result["events"].push_back(ev);
        }

        return result;
    }

    // ========================================================================
    // Rejection Management
    // ========================================================================

    // ------------------------------------------------------------------------
    // mark_event_rejected - Mark an event as rejected with a reason
    // ------------------------------------------------------------------------
    void mark_event_rejected(
        LoggingTransaction& txn,
        const std::string& event_id,
        std::optional<std::string> rejection_reason) {

        if (rejection_reason.has_value()) {
            int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

            txn.execute(
                "INSERT INTO rejections (event_id, reason, last_check) "
                "VALUES (?, ?, ?) ON CONFLICT (event_id) DO UPDATE SET "
                "reason = excluded.reason, last_check = excluded.last_check",
                {event_id, rejection_reason.value(), now_ms});

            txn.execute(
                "UPDATE events SET rejection_reason = ? WHERE event_id = ?",
                {rejection_reason.value(), event_id});
        } else {
            txn.execute("DELETE FROM rejections WHERE event_id = ?", {event_id});
            txn.execute(
                "UPDATE events SET rejection_reason = NULL WHERE event_id = ?",
                {event_id});
        }
    }

    // ------------------------------------------------------------------------
    // get_rejected_events - Get rejected events for a room
    // ------------------------------------------------------------------------
    std::vector<std::string> get_rejected_events(
        LoggingTransaction& txn,
        const std::string& room_id) {

        std::vector<std::string> result;
        auto rows = txn.select(
            "SELECT e.event_id FROM events e "
            "JOIN rejections r ON e.event_id = r.event_id "
            "WHERE e.room_id = ?",
            {room_id});
        for (auto& row : rows) result.push_back(row.get<std::string>(0));
        return result;
    }

    // ========================================================================
    // Failed Pull Attempts
    // ========================================================================

    // ------------------------------------------------------------------------
    // record_failed_pull_attempt - Record a failed backfill attempt
    // ------------------------------------------------------------------------
    void record_failed_pull_attempt(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& event_id,
        const std::string& cause) {

        int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        txn.execute(
            "INSERT INTO event_failed_pull_attempts "
            "(room_id, event_id, num_attempts, last_attempt_ts, last_cause) "
            "VALUES (?, ?, 1, ?, ?) "
            "ON CONFLICT (room_id, event_id) DO UPDATE SET "
            "num_attempts = event_failed_pull_attempts.num_attempts + 1, "
            "last_attempt_ts = excluded.last_attempt_ts, "
            "last_cause = excluded.last_cause",
            {room_id, event_id, now_ms, cause});
    }

    // ------------------------------------------------------------------------
    // get_failed_pull_attempts - Get failed pull attempts for a room
    // ------------------------------------------------------------------------
    std::vector<json> get_failed_pull_attempts(
        LoggingTransaction& txn,
        const std::string& room_id) {

        std::vector<json> result;
        auto rows = txn.select(
            "SELECT event_id, num_attempts, last_attempt_ts, last_cause "
            "FROM event_failed_pull_attempts WHERE room_id = ? "
            "ORDER BY last_attempt_ts DESC",
            {room_id});

        for (auto& row : rows) {
            json entry;
            entry["event_id"] = row.get<std::string>(0);
            entry["num_attempts"] = row.get<int64_t>(1);
            entry["last_attempt_ts"] = row.get<int64_t>(2);
            if (!row.is_null(3)) entry["last_cause"] = row.get<std::string>(3);
            result.push_back(entry);
        }
        return result;
    }

    // ========================================================================
    // Outlier Management
    // ========================================================================

    // ------------------------------------------------------------------------
    // is_outlier - Check if an event is an outlier
    // ------------------------------------------------------------------------
    bool is_outlier(
        LoggingTransaction& txn,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT is_outlier FROM events WHERE event_id = ?",
            {event_id});
        if (row && !row->is_null(0)) return row->get<int64_t>(0) != 0;
        return false;
    }

    // ------------------------------------------------------------------------
    // get_outlier_events - Get all outlier events for a room
    // ------------------------------------------------------------------------
    std::vector<std::string> get_outlier_events(
        LoggingTransaction& txn,
        const std::string& room_id) {

        std::vector<std::string> result;
        auto rows = txn.select(
            "SELECT event_id FROM events WHERE room_id = ? AND is_outlier = 1",
            {room_id});
        for (auto& row : rows) result.push_back(row.get<std::string>(0));
        return result;
    }

    // ========================================================================
    // Room State Utilities
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_room_version - Get the room version
    // ------------------------------------------------------------------------
    std::optional<std::string> get_room_version(
        LoggingTransaction& txn,
        const std::string& room_id) {

        // Room version is determined by the m.room.create event
        auto row = txn.select_one(
            "SELECT ej.json FROM current_state_events cse "
            "JOIN event_json ej ON cse.event_id = ej.event_id "
            "WHERE cse.room_id = ? AND cse.type = 'm.room.create' "
            "AND cse.state_key = ''",
            {room_id});

        if (row && !row->is_null(0)) {
            try {
                json create = json::parse(row->get<std::string>(0));
                if (create.contains("content") && create["content"].contains("room_version")) {
                    return create["content"]["room_version"].get<std::string>();
                }
            } catch (...) {}
        }
        return "1"; // Default to room version 1
    }

    // ------------------------------------------------------------------------
    // get_room_membership_for_user - Get user's membership in a room
    // ------------------------------------------------------------------------
    std::optional<std::string> get_room_membership_for_user(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& user_id) {

        auto row = txn.select_one(
            "SELECT e.membership FROM current_state_events cse "
            "JOIN events e ON cse.event_id = e.event_id "
            "WHERE cse.room_id = ? AND cse.type = 'm.room.member' "
            "AND cse.state_key = ?",
            {room_id, user_id});

        if (row && !row->is_null(0)) return row->get<std::string>(0);
        return std::nullopt;
    }

    // ------------------------------------------------------------------------
    // get_members_in_room - Get all users with a specific membership in a room
    // ------------------------------------------------------------------------
    std::vector<std::string> get_members_in_room(
        LoggingTransaction& txn,
        const std::string& room_id,
        const std::string& membership = "join") {

        std::vector<std::string> result;
        auto rows = txn.select(
            "SELECT cse.state_key FROM current_state_events cse "
            "JOIN events e ON cse.event_id = e.event_id "
            "WHERE cse.room_id = ? AND cse.type = 'm.room.member' "
            "AND e.membership = ?",
            {room_id, membership});

        for (auto& row : rows) result.push_back(row.get<std::string>(0));
        return result;
    }

    // ========================================================================
    // Timeline Gaps
    // ========================================================================

    // ------------------------------------------------------------------------
    // get_timeline_gaps - Find gaps in a room's timeline
    // ------------------------------------------------------------------------
    json get_timeline_gaps(
        LoggingTransaction& txn,
        const std::string& room_id,
        int limit = 10) {

        json result = json::array();

        // Find backward extremities that haven't been backfilled
        auto rows = txn.select(
            "SELECT ebe.event_id, ebe.room_id, e.depth "
            "FROM event_backward_extremities ebe "
            "JOIN events e ON ebe.event_id = e.event_id "
            "WHERE ebe.room_id = ? "
            "AND NOT EXISTS ("
            "  SELECT 1 FROM event_edges ee "
            "  WHERE ee.event_id = ebe.event_id"
            ") "
            "ORDER BY e.depth ASC "
            "LIMIT ?",
            {room_id, limit});

        for (auto& row : rows) {
            json gap;
            gap["event_id"] = row.get<std::string>(0);
            gap["room_id"] = row.get<std::string>(1);
            gap["depth"] = row.get<int64_t>(2);
            gap["type"] = "backward_gap";
            result.push_back(gap);
        }

        return result;
    }

    // ========================================================================
    // Cleanup
    // ========================================================================

    // ------------------------------------------------------------------------
    // cleanup_old_transaction_ids - Remove old txn_id mappings
    // ------------------------------------------------------------------------
    void cleanup_old_transaction_ids(LoggingTransaction& txn) {
        int64_t one_day_ago =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count() -
            24 * 60 * 60 * 1000;

        txn.execute(
            "DELETE FROM event_txn_id_device_id WHERE inserted_ts < ?",
            {one_day_ago});
    }

    // ------------------------------------------------------------------------
    // cleanup_expired_events - Remove events past their expiry time
    // ------------------------------------------------------------------------
    std::vector<std::string> cleanup_expired_events(LoggingTransaction& txn) {
        int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        auto rows = txn.select(
            "SELECT event_id FROM event_expiry WHERE expiry_ts <= ?",
            {now_ms});

        std::vector<std::string> expired_ids;
        for (auto& row : rows) expired_ids.push_back(row.get<std::string>(0));

        for (const auto& eid : expired_ids) {
            txn.execute("DELETE FROM event_expiry WHERE event_id = ?", {eid});
        }

        return expired_ids;
    }

    // ========================================================================
    // Internal helpers
    // ========================================================================

private:
    // Fetch a single event with full details
    std::optional<json> _fetch_single_event(
        LoggingTransaction& txn,
        const std::string& event_id) {

        auto row = txn.select_one(
            "SELECT e.event_id, e.room_id, e.type, e.sender, e.state_key, "
            "e.content, e.stream_ordering, e.origin_server_ts, e.depth, "
            "e.topological_ordering, e.membership, e.is_outlier, "
            "e.internal_metadata, ej.json, e.format_version "
            "FROM events e "
            "LEFT JOIN event_json ej ON e.event_id = ej.event_id "
            "WHERE e.event_id = ?",
            {event_id});

        if (!row || row->is_null(0)) return std::nullopt;

        json ev;
        ev["event_id"] = row->get<std::string>(0);
        ev["room_id"] = row->get<std::string>(1);
        ev["type"] = row->get<std::string>(2);
        ev["sender"] = row->get<std::string>(3);
        if (!row.is_null(4)) ev["state_key"] = row->get<std::string>(4);
        try {
            ev["content"] = json::parse(row->get<std::string>(5));
        } catch (...) {
            ev["content"] = json::object();
        }
        ev["stream_ordering"] = row->get<int64_t>(6);
        ev["origin_server_ts"] = row->get<int64_t>(7);
        ev["depth"] = row->get<int64_t>(8);
        ev["topological_ordering"] = row->get<int64_t>(9);
        if (!row.is_null(10)) ev["membership"] = row->get<std::string>(10);
        ev["is_outlier"] = row.is_null(11) ? false : (row->get<int64_t>(11) != 0);

        return ev;
    }

    // Fetch events with redaction info
    std::map<std::string, EventCacheEntry> _fetch_events_with_redactions(
        LoggingTransaction& txn,
        const std::vector<std::string>& event_ids,
        bool allow_rejected) {

        std::map<std::string, EventCacheEntry> result;
        if (event_ids.empty()) return result;

        for (size_t i = 0; i < event_ids.size(); i += 200) {
            size_t end = std::min(i + 200, event_ids.size());
            std::vector<std::string> batch(event_ids.begin() + i,
                                             event_ids.begin() + end);

            auto rows = txn.select(
                "SELECT e.event_id, e.room_id, e.type, e.sender, e.state_key, "
                "e.content, e.stream_ordering, e.origin_server_ts, e.depth, "
                "e.topological_ordering, e.membership, e.is_outlier, "
                "e.rejection_reason, e.is_redacted, "
                "e.internal_metadata, ej.json "
                "FROM events e "
                "LEFT JOIN event_json ej ON e.event_id = ej.event_id "
                "WHERE e.event_id IN (" +
                    make_in_list_sql_clause("e.event_id", batch) + ")",
                to_db_params(batch));

            for (auto& row : rows) {
                EventCacheEntry entry;
                json& ev = entry.event;
                ev["event_id"] = row.get<std::string>(0);
                ev["room_id"] = row.get<std::string>(1);
                ev["type"] = row.get<std::string>(2);
                ev["sender"] = row.get<std::string>(3);
                if (!row.is_null(4)) ev["state_key"] = row.get<std::string>(4);
                try {
                    ev["content"] = json::parse(row.get<std::string>(5));
                } catch (...) {
                    ev["content"] = json::object();
                }
                ev["stream_ordering"] = row.get<int64_t>(6);
                ev["origin_server_ts"] = row.get<int64_t>(7);
                ev["depth"] = row.get<int64_t>(8);
                if (!row.is_null(9)) ev["topological_ordering"] = row.get<int64_t>(9);
                if (!row.is_null(10)) ev["membership"] = row.get<std::string>(10);
                if (!row.is_null(12) && !allow_rejected) {
                    continue; // Skip rejected events
                }

                // Check if redacted
                if (!row.is_null(13) && row.get<int64_t>(13) != 0) {
                    json redacted = ev;
                    redacted["content"] = json::object();
                    redacted["unsigned"] = json::object();
                    redacted["unsigned"]["redacted_because"] = json::object();
                    entry.redacted_event = redacted;
                }

                result[ev["event_id"].get<std::string>()] = entry;
            }
        }

        return result;
    }

    // ========================================================================
    // Member variables
    // ========================================================================
    std::string server_name_;
    std::string instance_name_;
    int64_t stream_id_gen_current_;
    int64_t backfill_id_gen_current_;
};

// ============================================================================
// SQL DDL installation function
// ============================================================================

void install_events_worker_full_ddl(LoggingTransaction& txn) {
    txn.execute(sql_ddl_full::EVENTS_TABLE);
    txn.execute(sql_ddl_full::EVENT_JSON_TABLE);
    txn.execute(sql_ddl_full::EVENT_AUTH_TABLE);
    txn.execute(sql_ddl_full::EVENT_EDGES_TABLE);
    txn.execute(sql_ddl_full::STATE_EVENTS_TABLE);
    txn.execute(sql_ddl_full::CURRENT_STATE_EVENTS_TABLE);
    txn.execute(sql_ddl_full::ROOM_MEMBERSHIPS_TABLE);
    txn.execute(sql_ddl_full::LOCAL_CURRENT_MEMBERSHIP_TABLE);
    txn.execute(sql_ddl_full::REDACTIONS_TABLE);
    txn.execute(sql_ddl_full::THREAD_SUBSCRIPTIONS_TABLE);
    txn.execute(sql_ddl_full::PARTIAL_STATE_ROOMS_TABLE);
    txn.execute(sql_ddl_full::UNPARTIAL_STATED_ROOMS_TABLE);
    txn.execute(sql_ddl_full::PARTIAL_STATE_ROOMS_EVENTS_TABLE);
    txn.execute(sql_ddl_full::EVENT_FORWARD_EXTREMITIES_TABLE);
    txn.execute(sql_ddl_full::EVENT_BACKWARD_EXTREMITIES_TABLE);
    txn.execute(sql_ddl_full::EVENT_RELATIONS_TABLE);
    txn.execute(sql_ddl_full::STATE_GROUPS_TABLE);
    txn.execute(sql_ddl_full::STATE_GROUP_EDGES_TABLE);
    txn.execute(sql_ddl_full::STATE_GROUPS_STATE_TABLE);
    txn.execute(sql_ddl_full::EVENT_TO_STATE_GROUPS_TABLE);
    txn.execute(sql_ddl_full::REJECTIONS_TABLE);
    txn.execute(sql_ddl_full::EVENT_TXN_ID_TABLE);
    txn.execute(sql_ddl_full::EVENT_EXPIRY_TABLE);
    txn.execute(sql_ddl_full::CURRENT_STATE_DELTA_STREAM_TABLE);
    txn.execute(sql_ddl_full::EX_OUTLIER_STREAM_TABLE);
    txn.execute(sql_ddl_full::UN_PARTIAL_STATED_EVENT_STREAM_TABLE);
    txn.execute(sql_ddl_full::EVENT_SEARCH_TABLE);
    txn.execute(sql_ddl_full::EVENT_FAILED_PULL_ATTEMPTS_TABLE);
    txn.execute(sql_ddl_full::INSERTION_EVENTS_TABLE);
    txn.execute(sql_ddl_full::INSERTION_EVENT_EXTREMITIES_TABLE);
    txn.execute(sql_ddl_full::BATCH_EVENTS_TABLE);
    txn.execute(sql_ddl_full::ROOM_STATS_STATE_TABLE);
    txn.execute(sql_ddl_full::KNOCK_MEMBERSHIPS_TABLE);
}

}  // namespace progressive::storage
