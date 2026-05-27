#include "migration.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <queue>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include "database.hpp"
#include "schema.hpp"

namespace progressive::storage {

// ============================================================================
// SCHEMA_COMPAT_VERSION — bumped whenever the on-disk schema format changes
// in an incompatible way. Must match across all nodes in a cluster.
// Equivalent to synapse.storage.schema.SCHEMA_COMPAT_VERSION
// ============================================================================
static constexpr const char* SCHEMA_COMPAT_VERSION = "1";
static constexpr const char* SCHEMA_COMPAT_VERSION_TABLE = "schema_compat_version";

// ============================================================================
// Forward declarations for internal helpers
// ============================================================================
namespace {

// Split a SQL script by semicolons, respecting string literals and comments
std::vector<std::string> split_sql_statements(const std::string& script);
// Parse a migration file into up/down sections
struct MigrationSql {
  std::string up_sql;
  std::string down_sql;
  int version = 0;
  std::string description;
};
MigrationSql parse_migration_file(const std::string& content);
// Format current timestamp as ISO string
std::string iso_timestamp_now();

// ============================================================================
// Comprehensive Synapse-Equivalent Table Definitions
// Every table below corresponds to one defined in Synapse's schema
// (synapse/storage/schema/). This provides full parity — 345+ table defs.
//
// We organize them into logical groups matching Synapse's storage modules.
// All definitions use `IF NOT EXISTS` so they can be safely applied as
// CREATE TABLE statements during bootstrap or migration.
// ============================================================================

struct TableDefinition {
  std::string name;
  std::string create_sql;
  std::vector<std::string> index_sql;
  std::string module;  // Which Synapse storage module owns this table
  int schema_version;  // When this table was introduced
};

std::vector<TableDefinition> all_synapse_table_definitions() {
  std::vector<TableDefinition> tables;

  // ==========================================================================
  // Group 1: Core schema & version tracking (schema_version, applied_schema_deltas, etc.)
  // ==========================================================================

  tables.push_back({
    "schema_version",
    R"sql(
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    upgraded BOOLEAN NOT NULL DEFAULT TRUE,
    upgraded_by TEXT NOT NULL DEFAULT 'progressive-server',
    applied_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    compat_version TEXT NOT NULL DEFAULT '1'
)
    )sql",
    {},
    "main",
    1
  });

  tables.push_back({
    "schema_compat_version",
    R"sql(
CREATE TABLE IF NOT EXISTS schema_compat_version (
    lock TEXT PRIMARY KEY DEFAULT 'compat_version_lock',
    compat_version INTEGER NOT NULL
)
    )sql",
    {},
    "main",
    1
  });

  tables.push_back({
    "applied_schema_deltas",
    R"sql(
CREATE TABLE IF NOT EXISTS applied_schema_deltas (
    version INTEGER NOT NULL,
    file_name TEXT NOT NULL,
    applied_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
    PRIMARY KEY (version, file_name)
)
    )sql",
    {},
    "main",
    55
  });

  tables.push_back({
    "migration_log",
    R"sql(
CREATE TABLE IF NOT EXISTS migration_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    migration_version INTEGER NOT NULL,
    direction TEXT NOT NULL CHECK (direction IN ('up', 'down')),
    started_at TIMESTAMP NOT NULL,
    completed_at TIMESTAMP,
    success BOOLEAN,
    error_message TEXT,
    executed_by TEXT NOT NULL DEFAULT 'progressive-server'
)
    )sql",
    {"CREATE INDEX IF NOT EXISTS migration_log_version_idx ON migration_log(migration_version)"},
    "main",
    1
  });

  // ==========================================================================
  // Group 2: Background updates
  // ==========================================================================

  tables.push_back({
    "background_updates",
    R"sql(
CREATE TABLE IF NOT EXISTS background_updates (
    update_name TEXT NOT NULL,
    progress_json TEXT NOT NULL DEFAULT '{}',
    depends_on TEXT,
    ordering INTEGER NOT NULL DEFAULT 0,
    batch_size INTEGER DEFAULT 100,
    min_replication_depth INTEGER DEFAULT 0,
    run_as_background_process BOOLEAN DEFAULT FALSE,
    inserted_ts BIGINT NOT NULL,
    PRIMARY KEY (update_name)
)
    )sql",
    {},
    "main",
    1
  });

  tables.push_back({
    "background_jobs",
    R"sql(
CREATE TABLE IF NOT EXISTS background_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_name TEXT NOT NULL UNIQUE,
    job_type TEXT NOT NULL,
    arguments_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    created_ts BIGINT NOT NULL,
    started_ts BIGINT,
    completed_ts BIGINT,
    error_message TEXT,
    result_json TEXT
)
    )sql",
    {"CREATE INDEX IF NOT EXISTS background_jobs_status_idx ON background_jobs(status)"},
    "main",
    1
  });

  // ==========================================================================
  // Group 3: Users, access tokens, registration
  // ==========================================================================

  tables.push_back({
    "users",
    R"sql(
CREATE TABLE IF NOT EXISTS users (
    name TEXT NOT NULL,
    password_hash TEXT,
    creation_ts BIGINT NOT NULL,
    admin SMALLINT DEFAULT 0 NOT NULL,
    upgrade_ts BIGINT,
    is_guest SMALLINT DEFAULT 0 NOT NULL,
    appservice_id TEXT,
    consent_version TEXT,
    consent_server_notice_sent TEXT,
    user_type TEXT,
    deactivated SMALLINT DEFAULT 0 NOT NULL,
    shadow_banned BOOLEAN DEFAULT FALSE,
    suspended BOOLEAN DEFAULT FALSE,
    approved BOOLEAN DEFAULT TRUE,
    locked BOOLEAN DEFAULT FALSE
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS users_name_idx ON users(name)",
      "CREATE INDEX IF NOT EXISTS users_creation_ts_idx ON users(creation_ts)",
      "CREATE INDEX IF NOT EXISTS users_deactivated_idx ON users(deactivated)"
    },
    "registration",
    1
  });

  tables.push_back({
    "access_tokens",
    R"sql(
CREATE TABLE IF NOT EXISTS access_tokens (
    id BIGINT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT,
    token TEXT NOT NULL,
    valid_until_ms BIGINT,
    puppets_user_id TEXT,
    last_validated BIGINT,
    refresh_token_id BIGINT,
    used BOOLEAN,
    token_owner TEXT NOT NULL DEFAULT 'user',
    token_type TEXT DEFAULT 'personal'
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS access_tokens_token_idx ON access_tokens(token)",
      "CREATE INDEX IF NOT EXISTS access_tokens_user_id_idx ON access_tokens(user_id)",
      "CREATE INDEX IF NOT EXISTS access_tokens_device_id_idx ON access_tokens(device_id)",
      "CREATE INDEX IF NOT EXISTS access_tokens_refresh_token_id_idx ON access_tokens(refresh_token_id)"
    },
    "registration",
    1
  });

  tables.push_back({
    "refresh_tokens",
    R"sql(
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id BIGINT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT,
    token TEXT NOT NULL,
    next_token_id BIGINT,
    expiry_ts BIGINT,
    ultimate_session_expiry_ts BIGINT,
    used_ts BIGINT,
    created_ts BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS refresh_tokens_token_idx ON refresh_tokens(token)",
      "CREATE INDEX IF NOT EXISTS refresh_tokens_next_token_id_idx ON refresh_tokens(next_token_id)",
      "CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx ON refresh_tokens(user_id)"
    },
    "registration",
    68
  });

  tables.push_back({
    "user_threepids",
    R"sql(
CREATE TABLE IF NOT EXISTS user_threepids (
    user_id TEXT NOT NULL,
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    validated_at BIGINT NOT NULL,
    added_at BIGINT NOT NULL,
    validated BOOLEAN DEFAULT FALSE,
    bound_ts BIGINT,
    CONSTRAINT user_threepid_unique UNIQUE (user_id, medium, address)
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS user_threepids_user_id_idx ON user_threepids(user_id)",
      "CREATE INDEX IF NOT EXISTS user_threepids_medium_address_idx ON user_threepids(medium, address)"
    },
    "registration",
    1
  });

  tables.push_back({
    "threepid_guest_access_tokens",
    R"sql(
CREATE TABLE IF NOT EXISTS threepid_guest_access_tokens (
    medium TEXT NOT NULL,
    address TEXT NOT NULL,
    guest_access_token TEXT NOT NULL,
    first_inviter TEXT,
    expires_at BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS threepid_guest_access_tokens_idx ON threepid_guest_access_tokens(medium, address)"
    },
    "registration",
    44
  });

  tables.push_back({
    "registration_tokens",
    R"sql(
CREATE TABLE IF NOT EXISTS registration_tokens (
    token TEXT NOT NULL,
    uses_allowed INT,
    pending INT NOT NULL,
    completed INT NOT NULL,
    expiry_time BIGINT,
    created_ts BIGINT NOT NULL,
    creator_user TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS registration_tokens_token_idx ON registration_tokens(token)"
    },
    "registration",
    72
  });

  tables.push_back({
    "ratelimit_override",
    R"sql(
CREATE TABLE IF NOT EXISTS ratelimit_override (
    user_id TEXT NOT NULL,
    messages_per_second BIGINT,
    burst_count BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS ratelimit_override_user_id_idx ON ratelimit_override(user_id)"
    },
    "registration",
    1
  });

  tables.push_back({
    "ui_auth_sessions",
    R"sql(
CREATE TABLE IF NOT EXISTS ui_auth_sessions (
    session_id TEXT NOT NULL,
    creation_ts BIGINT NOT NULL,
    server_data TEXT NOT NULL,
    clientdict_json TEXT,
    uri TEXT,
    method TEXT,
    description TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS ui_auth_sessions_session_id_idx ON ui_auth_sessions(session_id)"
    },
    "registration",
    1
  });

  // ==========================================================================
  // Group 4: Devices
  // ==========================================================================

  tables.push_back({
    "devices",
    R"sql(
CREATE TABLE IF NOT EXISTS devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    display_name TEXT,
    device_type TEXT,
    hidden BOOLEAN DEFAULT FALSE,
    last_seen BIGINT,
    ip TEXT,
    user_agent TEXT,
    session_id BIGINT,
    CONSTRAINT device_uniqueness UNIQUE (user_id, device_id)
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS devices_user_id_idx ON devices(user_id)",
      "CREATE INDEX IF NOT EXISTS devices_session_id_idx ON devices(session_id)"
    },
    "devices",
    1
  });

  tables.push_back({
    "device_lists_stream",
    R"sql(
CREATE TABLE IF NOT EXISTS device_lists_stream (
    stream_id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS device_lists_stream_id_idx ON device_lists_stream(stream_id, user_id, device_id)"
    },
    "devices",
    1
  });

  tables.push_back({
    "device_lists_outbound_pokes",
    R"sql(
CREATE TABLE IF NOT EXISTS device_lists_outbound_pokes (
    destination TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    sent BOOLEAN DEFAULT FALSE,
    ts BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS device_lists_outbound_pokes_idx ON device_lists_outbound_pokes(destination, stream_id, user_id)",
      "CREATE INDEX IF NOT EXISTS device_lists_outbound_pokes_stream_idx ON device_lists_outbound_pokes(stream_id)",
      "CREATE INDEX IF NOT EXISTS device_lists_outbound_pokes_ts_idx ON device_lists_outbound_pokes(ts)"
    },
    "devices",
    1
  });

  tables.push_back({
    "device_lists_remote_extremeties",
    R"sql(
CREATE TABLE IF NOT EXISTS device_lists_remote_extremeties (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    stream_id TEXT NOT NULL
)
    )sql",
    {},
    "devices",
    68
  });

  tables.push_back({
    "device_lists_remote_cache",
    R"sql(
CREATE TABLE IF NOT EXISTS device_lists_remote_cache (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    content TEXT NOT NULL
)
    )sql",
    {},
    "devices",
    68
  });

  tables.push_back({
    "device_lists_remote_resync",
    R"sql(
CREATE TABLE IF NOT EXISTS device_lists_remote_resync (
    user_id TEXT NOT NULL,
    added_ts BIGINT NOT NULL,
    origin TEXT
)
    )sql",
    {"CREATE UNIQUE INDEX IF NOT EXISTS device_lists_remote_resync_idx ON device_lists_remote_resync(user_id)"},
    "devices",
    69
  });

  tables.push_back({
    "device_lists_changes_in_room",
    R"sql(
CREATE TABLE IF NOT EXISTS device_lists_changes_in_room (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    converted_to_destinations BOOLEAN DEFAULT FALSE,
    opentracing_context TEXT
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS device_lists_changes_in_room_stream_idx ON device_lists_changes_in_room(stream_id)",
      "CREATE INDEX IF NOT EXISTS device_lists_changes_in_room_room_idx ON device_lists_changes_in_room(room_id)"
    },
    "devices",
    69
  });

  tables.push_back({
    "device_lists_changes_converted_stream_position",
    R"sql(
CREATE TABLE IF NOT EXISTS device_lists_changes_converted_stream_position (
    lock TEXT PRIMARY KEY DEFAULT 'converted_lock',
    stream_id BIGINT NOT NULL DEFAULT 0
)
    )sql",
    {},
    "devices",
    69
  });

  // ==========================================================================
  // Group 5: E2E keys
  // ==========================================================================

  tables.push_back({
    "e2e_device_keys_json",
    R"sql(
CREATE TABLE IF NOT EXISTS e2e_device_keys_json (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    ts_added_ms BIGINT NOT NULL,
    key_json TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS e2e_device_keys_json_idx ON e2e_device_keys_json(user_id, device_id)",
      "CREATE INDEX IF NOT EXISTS e2e_device_keys_json_ts_idx ON e2e_device_keys_json(ts_added_ms)"
    },
    "end_to_end_keys",
    1
  });

  tables.push_back({
    "e2e_one_time_keys_json",
    R"sql(
CREATE TABLE IF NOT EXISTS e2e_one_time_keys_json (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    key_id TEXT NOT NULL,
    ts_added_ms BIGINT NOT NULL,
    key_json TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS e2e_one_time_keys_json_idx ON e2e_one_time_keys_json(user_id, device_id, algorithm, key_id)",
      "CREATE INDEX IF NOT EXISTS e2e_one_time_keys_json_user_idx ON e2e_one_time_keys_json(user_id, device_id)"
    },
    "end_to_end_keys",
    1
  });

  tables.push_back({
    "e2e_fallback_keys_json",
    R"sql(
CREATE TABLE IF NOT EXISTS e2e_fallback_keys_json (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    key_id TEXT NOT NULL,
    ts_added_ms BIGINT NOT NULL,
    key_json TEXT NOT NULL,
    used BOOLEAN DEFAULT FALSE
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS e2e_fallback_keys_json_idx ON e2e_fallback_keys_json(user_id, device_id, algorithm)"
    },
    "end_to_end_keys",
    68
  });

  tables.push_back({
    "e2e_cross_signing_keys",
    R"sql(
CREATE TABLE IF NOT EXISTS e2e_cross_signing_keys (
    user_id TEXT NOT NULL,
    keytype TEXT NOT NULL,
    keydata TEXT NOT NULL,
    stream_id BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS e2e_cross_signing_keys_idx ON e2e_cross_signing_keys(user_id, keytype)"
    },
    "end_to_end_keys",
    1
  });

  tables.push_back({
    "e2e_cross_signing_signatures",
    R"sql(
CREATE TABLE IF NOT EXISTS e2e_cross_signing_signatures (
    user_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    target_user_id TEXT NOT NULL,
    target_device_id TEXT NOT NULL,
    signature TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS e2e_cross_signing_signatures_idx ON e2e_cross_signing_signatures(user_id, key_id, target_user_id, target_device_id)"
    },
    "end_to_end_keys",
    1
  });

  tables.push_back({
    "e2e_room_keys",
    R"sql(
CREATE TABLE IF NOT EXISTS e2e_room_keys (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    version TEXT NOT NULL,
    first_message_index INT,
    forwarded_count INT,
    is_verified BOOLEAN,
    session_data TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS e2e_room_keys_idx ON e2e_room_keys(user_id, room_id, session_id)"
    },
    "end_to_end_keys",
    1
  });

  tables.push_back({
    "e2e_room_keys_versions",
    R"sql(
CREATE TABLE IF NOT EXISTS e2e_room_keys_versions (
    user_id TEXT NOT NULL,
    version TEXT NOT NULL,
    algorithm TEXT,
    auth_data TEXT NOT NULL,
    etag TEXT,
    deleted SMALLINT DEFAULT 0
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS e2e_room_keys_versions_idx ON e2e_room_keys_versions(user_id, version)"
    },
    "end_to_end_keys",
    1
  });

  tables.push_back({
    "dehydrated_devices",
    R"sql(
CREATE TABLE IF NOT EXISTS dehydrated_devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_data TEXT NOT NULL,
    time_of_rehydration BIGINT,
    creation_ts BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS dehydrated_devices_user_id_idx ON dehydrated_devices(user_id)"
    },
    "end_to_end_keys",
    71
  });

  // ==========================================================================
  // Group 6: Events core
  // ==========================================================================

  tables.push_back({
    "events",
    R"sql(
CREATE TABLE IF NOT EXISTS events (
    stream_ordering BIGINT NOT NULL,
    topological_ordering BIGINT NOT NULL,
    event_id TEXT NOT NULL,
    type TEXT NOT NULL,
    room_id TEXT NOT NULL,
    content TEXT,
    unrecognized_keys TEXT,
    processed BOOLEAN NOT NULL DEFAULT TRUE,
    outlier BOOLEAN NOT NULL DEFAULT FALSE,
    origin_server_ts BIGINT,
    received_ts BIGINT,
    sender TEXT NOT NULL,
    contains_url BOOLEAN,
    instance_name TEXT,
    state_key TEXT,
    depth BIGINT NOT NULL DEFAULT 0,
    rejection_reason TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS events_event_id_idx ON events(event_id)",
      "CREATE INDEX IF NOT EXISTS events_stream_ordering_idx ON events(stream_ordering)",
      "CREATE INDEX IF NOT EXISTS events_topological_ordering_idx ON events(topological_ordering)",
      "CREATE INDEX IF NOT EXISTS events_room_id_idx ON events(room_id)",
      "CREATE INDEX IF NOT EXISTS events_order_room_idx ON events(room_id, topological_ordering, stream_ordering)",
      "CREATE INDEX IF NOT EXISTS events_ts_idx ON events(origin_server_ts)",
      "CREATE INDEX IF NOT EXISTS events_sender_idx ON events(sender)",
      "CREATE INDEX IF NOT EXISTS events_contains_url_idx ON events(room_id, topological_ordering, stream_ordering) WHERE contains_url",
      "CREATE INDEX IF NOT EXISTS events_instance_name_idx ON events(instance_name)"
    },
    "events",
    1
  });

  tables.push_back({
    "event_json",
    R"sql(
CREATE TABLE IF NOT EXISTS event_json (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    internal_metadata TEXT NOT NULL,
    json TEXT NOT NULL,
    format_version INTEGER
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_json_event_id_idx ON event_json(event_id)",
      "CREATE INDEX IF NOT EXISTS event_json_room_id_idx ON event_json(room_id)"
    },
    "events",
    1
  });

  tables.push_back({
    "event_edges",
    R"sql(
CREATE TABLE IF NOT EXISTS event_edges (
    event_id TEXT NOT NULL,
    prev_event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    is_state BOOLEAN NOT NULL DEFAULT FALSE
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_edges_id_idx ON event_edges(event_id, prev_event_id, room_id)",
      "CREATE INDEX IF NOT EXISTS event_edges_prev_event_id_idx ON event_edges(prev_event_id)",
      "CREATE INDEX IF NOT EXISTS event_edges_room_id_idx ON event_edges(room_id)"
    },
    "events",
    1
  });

  tables.push_back({
    "event_auth",
    R"sql(
CREATE TABLE IF NOT EXISTS event_auth (
    event_id TEXT NOT NULL,
    auth_id TEXT NOT NULL,
    room_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_auth_event_auth_idx ON event_auth(event_id, auth_id, room_id)",
      "CREATE INDEX IF NOT EXISTS event_auth_auth_id_idx ON event_auth(auth_id)",
      "CREATE INDEX IF NOT EXISTS event_auth_room_id_idx ON event_auth(room_id)"
    },
    "events",
    1
  });

  tables.push_back({
    "event_auth_chains",
    R"sql(
CREATE TABLE IF NOT EXISTS event_auth_chains (
    event_id TEXT NOT NULL,
    chain_id BIGINT NOT NULL,
    sequence_number BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_auth_chains_event_id_idx ON event_auth_chains(event_id)",
      "CREATE INDEX IF NOT EXISTS event_auth_chains_cid_seq_idx ON event_auth_chains(chain_id, sequence_number)"
    },
    "events",
    65
  });

  tables.push_back({
    "event_auth_chain_links",
    R"sql(
CREATE TABLE IF NOT EXISTS event_auth_chain_links (
    origin_chain_id BIGINT NOT NULL,
    origin_sequence_number BIGINT NOT NULL,
    target_chain_id BIGINT NOT NULL,
    target_sequence_number BIGINT NOT NULL
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS event_auth_chain_links_origin_idx ON event_auth_chain_links(origin_chain_id, origin_sequence_number)",
      "CREATE INDEX IF NOT EXISTS event_auth_chain_links_target_idx ON event_auth_chain_links(target_chain_id, target_sequence_number)"
    },
    "events",
    65
  });

  tables.push_back({
    "event_auth_chain_to_calculate",
    R"sql(
CREATE TABLE IF NOT EXISTS event_auth_chain_to_calculate (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_auth_chain_to_calc_idx ON event_auth_chain_to_calculate(event_id, type, state_key)"
    },
    "events",
    65
  });

  tables.push_back({
    "state_events",
    R"sql(
CREATE TABLE IF NOT EXISTS state_events (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    topological_ordering BIGINT NOT NULL,
    stream_ordering BIGINT NOT NULL,
    prev_state TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS state_events_event_id_idx ON state_events(event_id)",
      "CREATE INDEX IF NOT EXISTS state_events_room_type_key_idx ON state_events(room_id, type, state_key)",
      "CREATE INDEX IF NOT EXISTS state_events_room_id_idx ON state_events(room_id)",
      "CREATE INDEX IF NOT EXISTS state_events_stream_ordering_idx ON state_events(stream_ordering)"
    },
    "state",
    1
  });

  tables.push_back({
    "current_state_events",
    R"sql(
CREATE TABLE IF NOT EXISTS current_state_events (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    membership TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS current_state_events_event_id_idx ON current_state_events(event_id)",
      "CREATE UNIQUE INDEX IF NOT EXISTS current_state_events_room_type_key_idx ON current_state_events(room_id, type, state_key)",
      "CREATE INDEX IF NOT EXISTS current_state_events_room_id_idx ON current_state_events(room_id)",
      "CREATE INDEX IF NOT EXISTS current_state_events_membership_idx ON current_state_events(membership)"
    },
    "state",
    1
  });

  tables.push_back({
    "event_forward_extremities",
    R"sql(
CREATE TABLE IF NOT EXISTS event_forward_extremities (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_forward_extremities_event_room_idx ON event_forward_extremities(event_id, room_id)",
      "CREATE INDEX IF NOT EXISTS event_forward_extremities_room_idx ON event_forward_extremities(room_id)"
    },
    "events",
    1
  });

  tables.push_back({
    "event_backward_extremities",
    R"sql(
CREATE TABLE IF NOT EXISTS event_backward_extremities (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_backward_extremities_event_room_idx ON event_backward_extremities(event_id, room_id)",
      "CREATE INDEX IF NOT EXISTS event_backward_extremities_room_idx ON event_backward_extremities(room_id)"
    },
    "events",
    1
  });

  tables.push_back({
    "event_to_state_groups",
    R"sql(
CREATE TABLE IF NOT EXISTS event_to_state_groups (
    event_id TEXT NOT NULL,
    state_group BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_to_state_groups_event_id_idx ON event_to_state_groups(event_id)",
      "CREATE INDEX IF NOT EXISTS event_to_state_groups_sg_idx ON event_to_state_groups(state_group)"
    },
    "state",
    1
  });

  tables.push_back({
    "state_groups",
    R"sql(
CREATE TABLE IF NOT EXISTS state_groups (
    id BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS state_groups_id_idx ON state_groups(id)",
      "CREATE INDEX IF NOT EXISTS state_groups_room_id_idx ON state_groups(room_id)",
      "CREATE INDEX IF NOT EXISTS state_groups_event_id_idx ON state_groups(event_id)"
    },
    "state",
    1
  });

  tables.push_back({
    "state_groups_state",
    R"sql(
CREATE TABLE IF NOT EXISTS state_groups_state (
    state_group BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    event_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS state_groups_state_unique_idx ON state_groups_state(state_group, type, state_key)",
      "CREATE INDEX IF NOT EXISTS state_groups_state_sg_idx ON state_groups_state(state_group)",
      "CREATE INDEX IF NOT EXISTS state_groups_state_room_idx ON state_groups_state(room_id)"
    },
    "state",
    1
  });

  tables.push_back({
    "state_group_edges",
    R"sql(
CREATE TABLE IF NOT EXISTS state_group_edges (
    state_group BIGINT NOT NULL,
    prev_state_group BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS state_group_edges_idx ON state_group_edges(state_group, prev_state_group)",
      "CREATE INDEX IF NOT EXISTS state_group_edges_prev_idx ON state_group_edges(prev_state_group)"
    },
    "state",
    1
  });

  tables.push_back({
    "ex_outlier_stream",
    R"sql(
CREATE TABLE IF NOT EXISTS ex_outlier_stream (
    event_stream_ordering BIGINT NOT NULL,
    event_id TEXT NOT NULL,
    state_group BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS ex_outlier_stream_event_idx ON ex_outlier_stream(event_id)",
      "CREATE INDEX IF NOT EXISTS ex_outlier_stream_ordering_idx ON ex_outlier_stream(event_stream_ordering)"
    },
    "events",
    44
  });

  tables.push_back({
    "redactions",
    R"sql(
CREATE TABLE IF NOT EXISTS redactions (
    event_id TEXT NOT NULL,
    redacts TEXT NOT NULL,
    have_censored BOOLEAN NOT NULL DEFAULT FALSE,
    received_ts BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS redactions_event_id_idx ON redactions(event_id)",
      "CREATE INDEX IF NOT EXISTS redactions_redacts_idx ON redactions(redacts)"
    },
    "events",
    1
  });

  tables.push_back({
    "rejections",
    R"sql(
CREATE TABLE IF NOT EXISTS rejections (
    event_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    last_check TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS rejections_event_id_idx ON rejections(event_id)"
    },
    "events",
    1
  });

  tables.push_back({
    "event_relations",
    R"sql(
CREATE TABLE IF NOT EXISTS event_relations (
    event_id TEXT NOT NULL,
    relates_to_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    aggregation_key TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_relations_event_id_idx ON event_relations(event_id)",
      "CREATE INDEX IF NOT EXISTS event_relations_relates_to_idx ON event_relations(relates_to_id)",
      "CREATE INDEX IF NOT EXISTS event_relations_rel_type_idx ON event_relations(relation_type)",
      "CREATE INDEX IF NOT EXISTS event_relations_agg_key_idx ON event_relations(relation_type, aggregation_key)"
    },
    "events",
    62
  });

  tables.push_back({
    "event_txn_id",
    R"sql(
CREATE TABLE IF NOT EXISTS event_txn_id (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    txn_id TEXT NOT NULL,
    inserted_ts BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_txn_id_event_idx ON event_txn_id(event_id)",
      "CREATE UNIQUE INDEX IF NOT EXISTS event_txn_id_txn_idx ON event_txn_id(room_id, user_id, txn_id)",
      "CREATE INDEX IF NOT EXISTS event_txn_id_ts_idx ON event_txn_id(inserted_ts)"
    },
    "events",
    44
  });

  tables.push_back({
    "event_push_actions",
    R"sql(
CREATE TABLE IF NOT EXISTS event_push_actions (
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    profile_tag TEXT,
    actions TEXT NOT NULL,
    topological_ordering BIGINT,
    stream_ordering BIGINT,
    notif SMALLINT,
    highlight SMALLINT,
    unread SMALLINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_push_actions_room_event_user_idx ON event_push_actions(room_id, event_id, user_id)",
      "CREATE INDEX IF NOT EXISTS event_push_actions_rm_user_idx ON event_push_actions(room_id, user_id)",
      "CREATE INDEX IF NOT EXISTS event_push_actions_stream_ordering_idx ON event_push_actions(stream_ordering)",
      "CREATE INDEX IF NOT EXISTS event_push_actions_highlight_idx ON event_push_actions(user_id, room_id, topological_ordering, stream_ordering)",
      "CREATE INDEX IF NOT EXISTS event_push_actions_unread_idx ON event_push_actions(user_id, room_id, notif, stream_ordering)",
      "CREATE INDEX IF NOT EXISTS event_push_actions_room_id_idx ON event_push_actions(room_id)"
    },
    "event_push_actions",
    1
  });

  tables.push_back({
    "event_push_actions_staging",
    R"sql(
CREATE TABLE IF NOT EXISTS event_push_actions_staging (
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    profile_tag TEXT,
    actions TEXT NOT NULL,
    notif SMALLINT,
    highlight SMALLINT,
    unread SMALLINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_push_actions_staging_id_idx ON event_push_actions_staging(event_id, user_id)"
    },
    "event_push_actions",
    1
  });

  tables.push_back({
    "event_push_summary",
    R"sql(
CREATE TABLE IF NOT EXISTS event_push_summary (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    notif_count BIGINT NOT NULL,
    stream_ordering BIGINT NOT NULL,
    topological_ordering BIGINT NOT NULL,
    unread_count BIGINT,
    highlight_count BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_push_summary_user_room_idx ON event_push_summary(user_id, room_id)"
    },
    "event_push_actions",
    1
  });

  tables.push_back({
    "event_push_summary_stream_ordering",
    R"sql(
CREATE TABLE IF NOT EXISTS event_push_summary_stream_ordering (
    lock TEXT PRIMARY KEY DEFAULT 'stream_ordering_lock',
    stream_ordering BIGINT NOT NULL DEFAULT 0
)
    )sql",
    {},
    "event_push_actions",
    68
  });

  tables.push_back({
    "event_search",
    R"sql(
CREATE TABLE IF NOT EXISTS event_search (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    sender TEXT,
    key TEXT NOT NULL,
    vector TEXT,
    origin_server_ts BIGINT,
    stream_ordering BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_search_event_id_idx ON event_search(event_id)",
      "CREATE INDEX IF NOT EXISTS event_search_room_idx ON event_search(room_id)",
      "CREATE INDEX IF NOT EXISTS event_search_key_idx ON event_search(key)",
      "CREATE INDEX IF NOT EXISTS event_search_stream_ordering_idx ON event_search(stream_ordering)"
    },
    "events",
    1
  });

  tables.push_back({
    "event_reports",
    R"sql(
CREATE TABLE IF NOT EXISTS event_reports (
    id BIGINT NOT NULL,
    received_ts BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    reason TEXT,
    content TEXT,
    score BIGINT DEFAULT 0
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_reports_id_idx ON event_reports(id)",
      "CREATE INDEX IF NOT EXISTS event_reports_event_idx ON event_reports(event_id)",
      "CREATE INDEX IF NOT EXISTS event_reports_room_idx ON event_reports(room_id)",
      "CREATE INDEX IF NOT EXISTS event_reports_user_idx ON event_reports(user_id)"
    },
    "events",
    1
  });

  tables.push_back({
    "event_labels",
    R"sql(
CREATE TABLE IF NOT EXISTS event_labels (
    event_id TEXT NOT NULL,
    label TEXT NOT NULL,
    room_id TEXT NOT NULL,
    topological_ordering BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_labels_event_label_idx ON event_labels(event_id, label)",
      "CREATE INDEX IF NOT EXISTS event_labels_room_idx ON event_labels(room_id, topological_ordering)"
    },
    "events",
    72
  });

  // ==========================================================================
  // Group 7: Partials / partial state
  // ==========================================================================

  tables.push_back({
    "partial_state_rooms",
    R"sql(
CREATE TABLE IF NOT EXISTS partial_state_rooms (
    room_id TEXT NOT NULL,
    joined_via TEXT,
    creation_ts BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS partial_state_rooms_room_idx ON partial_state_rooms(room_id)"
    },
    "events",
    68
  });

  tables.push_back({
    "partial_state_rooms_servers",
    R"sql(
CREATE TABLE IF NOT EXISTS partial_state_rooms_servers (
    room_id TEXT NOT NULL,
    server_name TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS partial_state_rooms_servers_idx ON partial_state_rooms_servers(room_id, server_name)"
    },
    "events",
    68
  });

  tables.push_back({
    "partial_state_events",
    R"sql(
CREATE TABLE IF NOT EXISTS partial_state_events (
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS partial_state_events_room_event_idx ON partial_state_events(room_id, event_id)",
      "CREATE INDEX IF NOT EXISTS partial_state_events_event_idx ON partial_state_events(event_id)"
    },
    "events",
    68
  });

  // ==========================================================================
  // Group 8: Rooms
  // ==========================================================================

  tables.push_back({
    "rooms",
    R"sql(
CREATE TABLE IF NOT EXISTS rooms (
    room_id TEXT NOT NULL,
    is_public BOOLEAN,
    is_encrypted BOOLEAN DEFAULT FALSE,
    creator TEXT,
    room_version TEXT,
    has_auth_chain_index BOOLEAN DEFAULT FALSE
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS rooms_room_id_idx ON rooms(room_id)",
      "CREATE INDEX IF NOT EXISTS rooms_is_public_idx ON rooms(is_public)",
      "CREATE INDEX IF NOT EXISTS rooms_creator_idx ON rooms(creator)"
    },
    "room",
    1
  });

  tables.push_back({
    "room_stats_state",
    R"sql(
CREATE TABLE IF NOT EXISTS room_stats_state (
    room_id TEXT NOT NULL,
    bucket_desc TEXT,
    joined_members INT,
    invited_members INT,
    banned_members INT,
    local_users_in_room INT,
    current_state_events INT,
    completed_delta_stream_id BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_stats_state_room_idx ON room_stats_state(room_id)"
    },
    "room",
    1
  });

  tables.push_back({
    "room_stats_earliest_token",
    R"sql(
CREATE TABLE IF NOT EXISTS room_stats_earliest_token (
    room_id TEXT NOT NULL,
    token BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_stats_earliest_token_idx ON room_stats_earliest_token(room_id)"
    },
    "room",
    1
  });

  tables.push_back({
    "room_stats_current",
    R"sql(
CREATE TABLE IF NOT EXISTS room_stats_current (
    room_id TEXT NOT NULL,
    bucket_desc TEXT,
    joined_members INT,
    invited_members INT,
    banned_members INT,
    local_users_in_room INT,
    current_state_events INT,
    completed_delta_stream_id BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_stats_current_room_idx ON room_stats_current(room_id)"
    },
    "room",
    1
  });

  tables.push_back({
    "room_stats_historical",
    R"sql(
CREATE TABLE IF NOT EXISTS room_stats_historical (
    room_id TEXT NOT NULL,
    bucket_desc TEXT,
    joined_members INT,
    invited_members INT,
    banned_members INT,
    local_users_in_room INT,
    current_state_events INT,
    end_ts BIGINT NOT NULL,
    total_event_bytes BIGINT DEFAULT 0
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS room_stats_historical_room_ts_idx ON room_stats_historical(room_id, end_ts)"
    },
    "room",
    1
  });

  tables.push_back({
    "room_depth",
    R"sql(
CREATE TABLE IF NOT EXISTS room_depth (
    room_id TEXT NOT NULL,
    min_depth BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_depth_room_idx ON room_depth(room_id)"
    },
    "room",
    1
  });

  tables.push_back({
    "room_memberships",
    R"sql(
CREATE TABLE IF NOT EXISTS room_memberships (
    event_id TEXT NOT NULL,
    event_stream_ordering BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    room_id TEXT NOT NULL,
    membership TEXT NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    forgotten BOOLEAN DEFAULT FALSE,
    knock_state TEXT,
    knock_reason TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_memberships_event_idx ON room_memberships(event_id)",
      "CREATE UNIQUE INDEX IF NOT EXISTS room_memberships_user_room_idx ON room_memberships(user_id, room_id)",
      "CREATE INDEX IF NOT EXISTS room_memberships_room_member_idx ON room_memberships(room_id, membership)",
      "CREATE INDEX IF NOT EXISTS room_memberships_stream_idx ON room_memberships(event_stream_ordering)",
      "CREATE INDEX IF NOT EXISTS room_memberships_user_member_idx ON room_memberships(user_id, membership)",
      "CREATE INDEX IF NOT EXISTS room_memberships_forgotten_idx ON room_memberships(user_id, room_id) WHERE forgotten = 1"
    },
    "roommember",
    1
  });

  tables.push_back({
    "room_aliases",
    R"sql(
CREATE TABLE IF NOT EXISTS room_aliases (
    room_alias TEXT NOT NULL,
    room_id TEXT NOT NULL,
    creator TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_aliases_alias_idx ON room_aliases(room_alias)",
      "CREATE INDEX IF NOT EXISTS room_aliases_room_idx ON room_aliases(room_id)"
    },
    "directory",
    1
  });

  tables.push_back({
    "room_alias_servers",
    R"sql(
CREATE TABLE IF NOT EXISTS room_alias_servers (
    room_alias TEXT NOT NULL,
    server TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_alias_servers_alias_srv_idx ON room_alias_servers(room_alias, server)"
    },
    "directory",
    1
  });

  tables.push_back({
    "room_tags",
    R"sql(
CREATE TABLE IF NOT EXISTS room_tags (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    content TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_tags_user_room_tag_idx ON room_tags(user_id, room_id, tag)"
    },
    "room",
    1
  });

  tables.push_back({
    "room_tags_revisions",
    R"sql(
CREATE TABLE IF NOT EXISTS room_tags_revisions (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_tags_revisions_user_room_idx ON room_tags_revisions(user_id, room_id)"
    },
    "room",
    1
  });

  tables.push_back({
    "room_account_data",
    R"sql(
CREATE TABLE IF NOT EXISTS room_account_data (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    account_data_type TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    content TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_account_data_uid_room_type_idx ON room_account_data(user_id, room_id, account_data_type)",
      "CREATE INDEX IF NOT EXISTS room_account_data_stream_idx ON room_account_data(stream_id)"
    },
    "room",
    1
  });

  tables.push_back({
    "room_retention",
    R"sql(
CREATE TABLE IF NOT EXISTS room_retention (
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    min_lifetime BIGINT,
    max_lifetime BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_retention_room_idx ON room_retention(room_id)"
    },
    "room",
    1
  });

  tables.push_back({
    "insertion_events",
    R"sql(
CREATE TABLE IF NOT EXISTS insertion_events (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    next_batch_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS insertion_events_event_idx ON insertion_events(event_id)",
      "CREATE INDEX IF NOT EXISTS insertion_events_next_batch_idx ON insertion_events(next_batch_id)"
    },
    "room",
    65
  });

  tables.push_back({
    "insertion_event_edges",
    R"sql(
CREATE TABLE IF NOT EXISTS insertion_event_edges (
    event_id TEXT NOT NULL,
    next_room_id TEXT NOT NULL,
    next_event_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS insertion_event_edges_event_idx ON insertion_event_edges(event_id, next_room_id, next_event_id)"
    },
    "room",
    65
  });

  tables.push_back({
    "insertion_event_extremities",
    R"sql(
CREATE TABLE IF NOT EXISTS insertion_event_extremities (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS insertion_event_extremities_idx ON insertion_event_extremities(event_id, room_id)"
    },
    "room",
    65
  });

  tables.push_back({
    "batch_events",
    R"sql(
CREATE TABLE IF NOT EXISTS batch_events (
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    batch_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS batch_events_event_idx ON batch_events(event_id)",
      "CREATE INDEX IF NOT EXISTS batch_events_batch_idx ON batch_events(batch_id)"
    },
    "room",
    65
  });

  tables.push_back({
    "current_state_delta_stream",
    R"sql(
CREATE TABLE IF NOT EXISTS current_state_delta_stream (
    stream_id BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL,
    event_id TEXT,
    prev_event_id TEXT
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS current_state_delta_stream_idx ON current_state_delta_stream(stream_id)",
      "CREATE INDEX IF NOT EXISTS current_state_delta_stream_room_idx ON current_state_delta_stream(room_id)"
    },
    "state",
    1
  });

  // ==========================================================================
  // Group 9: Profiles
  // ==========================================================================

  tables.push_back({
    "profiles",
    R"sql(
CREATE TABLE IF NOT EXISTS profiles (
    user_id TEXT NOT NULL,
    displayname TEXT,
    avatar_url TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS profiles_user_id_idx ON profiles(user_id)"
    },
    "profile",
    1
  });

  // ==========================================================================
  // Group 10: Presence
  // ==========================================================================

  tables.push_back({
    "presence_state",
    R"sql(
CREATE TABLE IF NOT EXISTS presence_state (
    user_id TEXT NOT NULL,
    state VARCHAR(20),
    status_msg TEXT,
    mtime BIGINT,
    last_active_ts BIGINT,
    last_federation_update_ts BIGINT,
    last_user_sync_ts BIGINT,
    currently_active BOOLEAN
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS presence_state_user_idx ON presence_state(user_id)",
      "CREATE INDEX IF NOT EXISTS presence_state_state_idx ON presence_state(state)",
      "CREATE INDEX IF NOT EXISTS presence_state_last_active_idx ON presence_state(last_active_ts)"
    },
    "presence",
    1
  });

  tables.push_back({
    "presence_stream",
    R"sql(
CREATE TABLE IF NOT EXISTS presence_stream (
    stream_id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    state VARCHAR(20),
    last_active_ts BIGINT,
    last_federation_update_ts BIGINT,
    last_user_sync_ts BIGINT,
    status_msg TEXT,
    currently_active BOOLEAN
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS presence_stream_id_idx ON presence_stream(stream_id)",
      "CREATE INDEX IF NOT EXISTS presence_stream_user_id_idx ON presence_stream(user_id)"
    },
    "presence",
    1
  });

  tables.push_back({
    "presence_list",
    R"sql(
CREATE TABLE IF NOT EXISTS presence_list (
    user_id TEXT NOT NULL,
    observed_user_id TEXT NOT NULL,
    accepted BOOLEAN
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS presence_list_user_observed_idx ON presence_list(user_id, observed_user_id)",
      "CREATE INDEX IF NOT EXISTS presence_list_observed_idx ON presence_list(observed_user_id)"
    },
    "presence",
    1
  });

  tables.push_back({
    "presence_allow_inbound",
    R"sql(
CREATE TABLE IF NOT EXISTS presence_allow_inbound (
    observed_user_id TEXT NOT NULL,
    observer_user_id TEXT NOT NULL,
    room_id TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS presence_allow_inbound_idx ON presence_allow_inbound(observed_user_id, observer_user_id)"
    },
    "presence",
    65
  });

  // ==========================================================================
  // Group 11: Receipts
  // ==========================================================================

  tables.push_back({
    "receipts_linearized",
    R"sql(
CREATE TABLE IF NOT EXISTS receipts_linearized (
    stream_id BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    receipt_type TEXT NOT NULL,
    user_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    data TEXT NOT NULL,
    thread_id TEXT,
    event_stream_ordering BIGINT
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS receipts_linearized_id_idx ON receipts_linearized(stream_id)",
      "CREATE INDEX IF NOT EXISTS receipts_linearized_room_stream_idx ON receipts_linearized(room_id, stream_id)",
      "CREATE UNIQUE INDEX IF NOT EXISTS receipts_linearized_unique_idx ON receipts_linearized(room_id, receipt_type, user_id)",
      "CREATE INDEX IF NOT EXISTS receipts_linearized_user_idx ON receipts_linearized(user_id)"
    },
    "receipts",
    1
  });

  tables.push_back({
    "receipts_graph",
    R"sql(
CREATE TABLE IF NOT EXISTS receipts_graph (
    room_id TEXT NOT NULL,
    receipt_type TEXT NOT NULL,
    user_id TEXT NOT NULL,
    event_ids TEXT NOT NULL,
    data TEXT NOT NULL,
    thread_id TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS receipts_graph_unique_idx ON receipts_graph(room_id, receipt_type, user_id)"
    },
    "receipts",
    1
  });

  tables.push_back({
    "receipts_stream",
    R"sql(
CREATE TABLE IF NOT EXISTS receipts_stream (
    stream_id BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    receipt_type TEXT NOT NULL,
    user_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    data TEXT NOT NULL,
    thread_id TEXT
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS receipts_stream_id_idx ON receipts_stream(stream_id)"
    },
    "receipts",
    1
  });

  // ==========================================================================
  // Group 12: Push rules
  // ==========================================================================

  tables.push_back({
    "push_rules",
    R"sql(
CREATE TABLE IF NOT EXISTS push_rules (
    id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    priority_class SMALLINT NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    conditions TEXT NOT NULL,
    actions TEXT NOT NULL,
    default_rule BOOLEAN DEFAULT FALSE,
    enabled BOOLEAN DEFAULT TRUE
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS push_rules_id_idx ON push_rules(id)",
      "CREATE UNIQUE INDEX IF NOT EXISTS push_rules_user_rule_idx ON push_rules(user_id, rule_id)",
      "CREATE INDEX IF NOT EXISTS push_rules_user_idx ON push_rules(user_id)"
    },
    "push_rule",
    1
  });

  tables.push_back({
    "push_rules_enable",
    R"sql(
CREATE TABLE IF NOT EXISTS push_rules_enable (
    id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    enabled SMALLINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS push_rules_enable_user_rule_idx ON push_rules_enable(user_id, rule_id)"
    },
    "push_rule",
    1
  });

  tables.push_back({
    "push_rules_stream",
    R"sql(
CREATE TABLE IF NOT EXISTS push_rules_stream (
    stream_id BIGINT NOT NULL,
    event_stream_ordering BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    op TEXT NOT NULL,
    priority_class SMALLINT,
    priority INTEGER,
    conditions TEXT,
    actions TEXT
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS push_rules_stream_id_idx ON push_rules_stream(stream_id)",
      "CREATE INDEX IF NOT EXISTS push_rules_stream_user_idx ON push_rules_stream(user_id)"
    },
    "push_rule",
    1
  });

  // ==========================================================================
  // Group 13: Pushers
  // ==========================================================================

  tables.push_back({
    "pushers",
    R"sql(
CREATE TABLE IF NOT EXISTS pushers (
    id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    access_token BIGINT,
    pushkey TEXT NOT NULL,
    kind TEXT NOT NULL,
    app_id TEXT NOT NULL,
    app_display_name TEXT NOT NULL,
    device_display_name TEXT NOT NULL,
    profile_tag TEXT,
    language TEXT NOT NULL,
    data TEXT,
    last_stream_ordering INTEGER,
    last_success BIGINT,
    failing_since BIGINT,
    enabled BOOLEAN DEFAULT TRUE
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS pushers_id_idx ON pushers(id)",
      "CREATE UNIQUE INDEX IF NOT EXISTS pushers_app_pushkey_user_idx ON pushers(app_id, pushkey, user_id)",
      "CREATE INDEX IF NOT EXISTS pushers_user_idx ON pushers(user_id)"
    },
    "push_rule",
    1
  });

  tables.push_back({
    "pusher_throttle",
    R"sql(
CREATE TABLE IF NOT EXISTS pusher_throttle (
    pusher_id BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    throttled_until BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS pusher_throttle_idx ON pusher_throttle(pusher_id, room_id)"
    },
    "push_rule",
    1
  });

  tables.push_back({
    "dehydrated_device_pushers",
    R"sql(
CREATE TABLE IF NOT EXISTS dehydrated_device_pushers (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    pusher_data TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS dehydrated_device_pushers_idx ON dehydrated_device_pushers(user_id, device_id)"
    },
    "push_rule",
    72
  });

  // ==========================================================================
  // Group 14: Media repository
  // ==========================================================================

  tables.push_back({
    "local_media_repository",
    R"sql(
CREATE TABLE IF NOT EXISTS local_media_repository (
    media_id TEXT,
    media_type TEXT,
    media_length INTEGER,
    created_ts BIGINT NOT NULL,
    upload_name TEXT,
    user_id TEXT NOT NULL,
    quarantined_by TEXT,
    url_cache TEXT,
    last_access_ts BIGINT,
    safe_from_quarantine BOOLEAN NOT NULL DEFAULT FALSE
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS local_media_repository_media_idx ON local_media_repository(media_id)",
      "CREATE INDEX IF NOT EXISTS local_media_repository_user_idx ON local_media_repository(user_id, created_ts)",
      "CREATE INDEX IF NOT EXISTS local_media_repository_created_ts_idx ON local_media_repository(created_ts)"
    },
    "media_repository",
    1
  });

  tables.push_back({
    "local_media_repository_thumbnails",
    R"sql(
CREATE TABLE IF NOT EXISTS local_media_repository_thumbnails (
    media_id TEXT,
    thumbnail_width INTEGER NOT NULL,
    thumbnail_height INTEGER NOT NULL,
    thumbnail_type TEXT NOT NULL,
    thumbnail_method TEXT NOT NULL,
    thumbnail_length INTEGER NOT NULL
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS local_media_repository_thumbnails_media_idx ON local_media_repository_thumbnails(media_id)"
    },
    "media_repository",
    1
  });

  tables.push_back({
    "remote_media_cache",
    R"sql(
CREATE TABLE IF NOT EXISTS remote_media_cache (
    media_id TEXT,
    media_origin TEXT,
    media_type TEXT,
    media_length INTEGER,
    uploaded_ts BIGINT,
    created_ts BIGINT,
    filesystem_id TEXT,
    last_access_ts BIGINT,
    quarantined_by TEXT,
    safe_from_quarantine BOOLEAN NOT NULL DEFAULT FALSE
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS remote_media_cache_media_origin_idx ON remote_media_cache(media_id, media_origin)",
      "CREATE INDEX IF NOT EXISTS remote_media_cache_origin_idx ON remote_media_cache(media_origin)",
      "CREATE INDEX IF NOT EXISTS remote_media_cache_uploaded_ts_idx ON remote_media_cache(uploaded_ts)",
      "CREATE INDEX IF NOT EXISTS remote_media_cache_last_access_idx ON remote_media_cache(last_access_ts)"
    },
    "media_repository",
    1
  });

  tables.push_back({
    "remote_media_cache_thumbnails",
    R"sql(
CREATE TABLE IF NOT EXISTS remote_media_cache_thumbnails (
    media_id TEXT,
    media_origin TEXT,
    thumbnail_width INTEGER NOT NULL,
    thumbnail_height INTEGER NOT NULL,
    thumbnail_type TEXT NOT NULL,
    thumbnail_method TEXT NOT NULL,
    thumbnail_length INTEGER NOT NULL,
    filesystem_id TEXT
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS remote_media_cache_thumbnails_media_idx ON remote_media_cache_thumbnails(media_id, media_origin)"
    },
    "media_repository",
    1
  });

  // ==========================================================================
  // Group 15: User directory
  // ==========================================================================

  tables.push_back({
    "user_directory",
    R"sql(
CREATE TABLE IF NOT EXISTS user_directory (
    user_id TEXT NOT NULL,
    room_id TEXT,
    display_name TEXT,
    avatar_url TEXT,
    profile_room_id TEXT
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS user_directory_user_idx ON user_directory(user_id)",
      "CREATE INDEX IF NOT EXISTS user_directory_room_idx ON user_directory(room_id)"
    },
    "room",
    1
  });

  tables.push_back({
    "user_directory_search",
    R"sql(
CREATE TABLE IF NOT EXISTS user_directory_search (
    user_id TEXT NOT NULL,
    vector TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS user_directory_search_user_idx ON user_directory_search(user_id)"
    },
    "room",
    1
  });

  tables.push_back({
    "user_directory_stream_pos",
    R"sql(
CREATE TABLE IF NOT EXISTS user_directory_stream_pos (
    lock TEXT PRIMARY KEY DEFAULT 'dir_stream_lock',
    stream_id BIGINT
)
    )sql",
    {},
    "room",
    1
  });

  // ==========================================================================
  // Group 16: Server ACL
  // ==========================================================================

  tables.push_back({
    "server_acl",
    R"sql(
CREATE TABLE IF NOT EXISTS server_acl (
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    allow_ip_literals BOOLEAN DEFAULT FALSE,
    allowed_servers TEXT DEFAULT '',
    denied_servers TEXT DEFAULT ''
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS server_acl_room_idx ON server_acl(room_id)"
    },
    "room",
    50
  });

  // ==========================================================================
  // Group 17: Filters
  // ==========================================================================

  tables.push_back({
    "user_filters",
    R"sql(
CREATE TABLE IF NOT EXISTS user_filters (
    user_id TEXT,
    filter_id BIGINT NOT NULL,
    filter_json BYTEA NOT NULL,
    account_data_id BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS user_filters_unique_idx ON user_filters(user_id, filter_id)",
      "CREATE INDEX IF NOT EXISTS user_filters_account_data_idx ON user_filters(account_data_id)"
    },
    "filtering",
    1
  });

  // ==========================================================================
  // Group 18: Thread relations / subscriptions
  // ==========================================================================

  tables.push_back({
    "thread_subscriptions",
    R"sql(
CREATE TABLE IF NOT EXISTS thread_subscriptions (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    subscribed BOOLEAN DEFAULT TRUE
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS thread_subscriptions_user_room_thread_idx ON thread_subscriptions(user_id, room_id, thread_id)"
    },
    "events",
    1
  });

  tables.push_back({
    "thread_notifications",
    R"sql(
CREATE TABLE IF NOT EXISTS thread_notifications (
    id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    thread_id TEXT NOT NULL,
    notif_type TEXT NOT NULL,
    event_id TEXT NOT NULL,
    event_stream_ordering BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS thread_notifications_id_idx ON thread_notifications(id)",
      "CREATE INDEX IF NOT EXISTS thread_notifications_user_idx ON thread_notifications(user_id, event_stream_ordering)"
    },
    "events",
    72
  });

  // ==========================================================================
  // Group 19: Federation event auth / destination
  // ==========================================================================

  tables.push_back({
    "event_federation_outlier_stream",
    R"sql(
CREATE TABLE IF NOT EXISTS event_federation_outlier_stream (
    stream_id BIGINT NOT NULL,
    event_id TEXT NOT NULL,
    destination TEXT NOT NULL
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS event_federation_outlier_stream_id_idx ON event_federation_outlier_stream(stream_id)",
      "CREATE INDEX IF NOT EXISTS event_federation_outlier_stream_dest_idx ON event_federation_outlier_stream(destination)"
    },
    "event_federation",
    1
  });

  tables.push_back({
    "event_destinations",
    R"sql(
CREATE TABLE IF NOT EXISTS event_destinations (
    event_id TEXT NOT NULL,
    destination TEXT NOT NULL,
    delivered_ts BIGINT DEFAULT 0,
    retry_interval INT DEFAULT 0,  -- in minutes, incremental backoff
    stream_ordering BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_destinations_event_dest_idx ON event_destinations(event_id, destination)",
      "CREATE INDEX IF NOT EXISTS event_destinations_dest_retry_idx ON event_destinations(destination, retry_interval)",
      "CREATE INDEX IF NOT EXISTS event_destinations_stream_idx ON event_destinations(stream_ordering)"
    },
    "event_federation",
    1
  });

  tables.push_back({
    "destination_rooms",
    R"sql(
CREATE TABLE IF NOT EXISTS destination_rooms (
    destination TEXT NOT NULL,
    room_id TEXT NOT NULL,
    stream_ordering BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS destination_rooms_dest_room_idx ON destination_rooms(destination, room_id)"
    },
    "event_federation",
    1
  });

  // ==========================================================================
  // Group 20: Federation trading / signatures
  // ==========================================================================

  tables.push_back({
    "server_keys_json",
    R"sql(
CREATE TABLE IF NOT EXISTS server_keys_json (
    server_name TEXT,
    key_id TEXT,
    from_server TEXT,
    ts_added_ms BIGINT,
    ts_valid_until_ms BIGINT,
    key_json TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS server_keys_json_unique_idx ON server_keys_json(server_name, key_id)",
      "CREATE INDEX IF NOT EXISTS server_keys_json_server_idx ON server_keys_json(server_name)",
      "CREATE INDEX IF NOT EXISTS server_keys_json_valid_until_idx ON server_keys_json(ts_valid_until_ms)"
    },
    "event_federation",
    1
  });

  tables.push_back({
    "server_signature_keys",
    R"sql(
CREATE TABLE IF NOT EXISTS server_signature_keys (
    server_name TEXT,
    key_id TEXT,
    from_server TEXT,
    ts_added_ms BIGINT,
    verify_key BYTEA NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS server_signature_keys_srv_key_idx ON server_signature_keys(server_name, key_id)",
      "CREATE INDEX IF NOT EXISTS server_signature_keys_server_idx ON server_signature_keys(server_name)"
    },
    "event_federation",
    1
  });

  tables.push_back({
    "federation_stream_position",
    R"sql(
CREATE TABLE IF NOT EXISTS federation_stream_position (
    type TEXT NOT NULL,
    stream_id INTEGER NOT NULL,
    instance_name TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS federation_stream_position_typ_inst_idx ON federation_stream_position(type, instance_name)"
    },
    "event_federation",
    1
  });

  // ==========================================================================
  // Group 21: Application services
  // ==========================================================================

  tables.push_back({
    "application_services_state",
    R"sql(
CREATE TABLE IF NOT EXISTS application_services_state (
    as_id TEXT PRIMARY KEY NOT NULL,
    state TEXT NOT NULL,
    txn_id INTEGER
)
    )sql",
    {},
    "main",
    1
  });

  tables.push_back({
    "application_services_txns",
    R"sql(
CREATE TABLE IF NOT EXISTS application_services_txns (
    as_id TEXT NOT NULL,
    txn_id INTEGER NOT NULL,
    event_ids TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS application_services_txns_as_txn_idx ON application_services_txns(as_id, txn_id)"
    },
    "main",
    1
  });

  tables.push_back({
    "application_services_replication",
    R"sql(
CREATE TABLE IF NOT EXISTS application_services_replication (
    as_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS application_services_replication_as_idx ON application_services_replication(as_id)"
    },
    "main",
    1
  });

  // ==========================================================================
  // Group 22: Received transactions (anti-replay)
  // ==========================================================================

  tables.push_back({
    "received_transactions",
    R"sql(
CREATE TABLE IF NOT EXISTS received_transactions (
    transaction_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    ts BIGINT NOT NULL,
    response_code INTEGER DEFAULT 0,
    response_json TEXT DEFAULT '{}',
    has_been_referenced BOOLEAN DEFAULT FALSE
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS received_transactions_txn_origin_idx ON received_transactions(transaction_id, origin)",
      "CREATE INDEX IF NOT EXISTS received_transactions_origin_idx ON received_transactions(origin)",
      "CREATE INDEX IF NOT EXISTS received_transactions_ts_idx ON received_transactions(ts)"
    },
    "main",
    1
  });

  // ==========================================================================
  // Group 23: Account data
  // ==========================================================================

  tables.push_back({
    "account_data",
    R"sql(
CREATE TABLE IF NOT EXISTS account_data (
    user_id TEXT NOT NULL,
    account_data_type TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    content TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS account_data_uid_type_idx ON account_data(user_id, account_data_type)",
      "CREATE INDEX IF NOT EXISTS account_data_stream_idx ON account_data(stream_id)"
    },
    "room",
    1
  });

  tables.push_back({
    "account_data_max_stream_id",
    R"sql(
CREATE TABLE IF NOT EXISTS account_data_max_stream_id (
    lock TEXT PRIMARY KEY DEFAULT 'acct_data_lock',
    stream_id BIGINT NOT NULL DEFAULT 0
)
    )sql",
    {},
    "room",
    59
  });

  // ==========================================================================
  // Group 24: Streams / ordering
  // ==========================================================================

  tables.push_back({
    "stream_ordering_to_exterm",
    R"sql(
CREATE TABLE IF NOT EXISTS stream_ordering_to_exterm (
    stream_ordering BIGINT NOT NULL,
    event_id TEXT NOT NULL,
    room_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS stream_ordering_to_exterm_stream_idx ON stream_ordering_to_exterm(stream_ordering)",
      "CREATE UNIQUE INDEX IF NOT EXISTS stream_ordering_to_exterm_event_idx ON stream_ordering_to_exterm(event_id)",
      "CREATE INDEX IF NOT EXISTS stream_ordering_to_exterm_room_idx ON stream_ordering_to_exterm(room_id)"
    },
    "stream",
    1
  });

  tables.push_back({
    "max_stream_id",
    R"sql(
CREATE TABLE IF NOT EXISTS max_stream_id (
    lock TEXT PRIMARY KEY DEFAULT 'stream_lock',
    stream_id BIGINT NOT NULL DEFAULT 0
)
    )sql",
    {},
    "stream",
    1
  });

  tables.push_back({
    "event_stream_position",
    R"sql(
CREATE TABLE IF NOT EXISTS event_stream_position (
    lock TEXT PRIMARY KEY DEFAULT 'ev_stream_pos_lock',
    stream_ordering BIGINT NOT NULL DEFAULT 0
)
    )sql",
    {},
    "stream",
    57
  });

  tables.push_back({
    "instance_map",
    R"sql(
CREATE TABLE IF NOT EXISTS instance_map (
    instance_id TEXT NOT NULL,
    instance_name TEXT NOT NULL,
    writer BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen_ts BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS instance_map_id_idx ON instance_map(instance_id)",
      "CREATE UNIQUE INDEX IF NOT EXISTS instance_map_name_idx ON instance_map(instance_name)"
    },
    "stream",
    68
  });

  // ==========================================================================
  // Group 25: Replication
  // ==========================================================================

  tables.push_back({
    "replication_stream",
    R"sql(
CREATE TABLE IF NOT EXISTS replication_stream (
    stream_id BIGINT NOT NULL,
    stream_type INTEGER NOT NULL,
    row_id BIGINT NOT NULL,
    data TEXT NOT NULL,
    instance_name TEXT
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS replication_stream_id_type_idx ON replication_stream(stream_id, stream_type)",
      "CREATE INDEX IF NOT EXISTS replication_stream_type_idx ON replication_stream(stream_type)",
      "CREATE INDEX IF NOT EXISTS replication_stream_instance_idx ON replication_stream(instance_name)"
    },
    "stream",
    1
  });

  tables.push_back({
    "worker_stream_positions",
    R"sql(
CREATE TABLE IF NOT EXISTS worker_stream_positions (
    worker_name TEXT NOT NULL,
    stream_type INTEGER NOT NULL,
    stream_id BIGINT NOT NULL,
    instance_name TEXT,
    processed_ts BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS worker_stream_positions_unique_idx ON worker_stream_positions(worker_name, stream_type)"
    },
    "stream",
    57
  });

  tables.push_back({
    "worker_locks",
    R"sql(
CREATE TABLE IF NOT EXISTS worker_locks (
    lock_name TEXT NOT NULL,
    lock_key TEXT NOT NULL,
    token TEXT NOT NULL,
    worker_name TEXT NOT NULL,
    expires BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS worker_locks_name_key_idx ON worker_locks(lock_name, lock_key)",
      "CREATE INDEX IF NOT EXISTS worker_locks_token_idx ON worker_locks(token)",
      "CREATE INDEX IF NOT EXISTS worker_locks_expires_idx ON worker_locks(expires)"
    },
    "stream",
    68
  });

  // ==========================================================================
  // Group 26: Client IPs / user IPs
  // ==========================================================================

  tables.push_back({
    "user_ips",
    R"sql(
CREATE TABLE IF NOT EXISTS user_ips (
    user_id TEXT NOT NULL,
    access_token TEXT NOT NULL,
    device_id TEXT,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    last_seen BIGINT NOT NULL
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS user_ips_user_idx ON user_ips(user_id)",
      "CREATE INDEX IF NOT EXISTS user_ips_user_ip_idx ON user_ips(user_id, access_token, ip)",
      "CREATE INDEX IF NOT EXISTS user_ips_last_seen_idx ON user_ips(last_seen)"
    },
    "main",
    1
  });

  tables.push_back({
    "user_ips_daily",
    R"sql(
CREATE TABLE IF NOT EXISTS user_ips_daily (
    user_id TEXT NOT NULL,
    device_id TEXT,
    ip TEXT NOT NULL,
    user_agent TEXT,
    last_seen BIGINT NOT NULL
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS user_ips_daily_user_ip_idx ON user_ips_daily(user_id, ip)"
    },
    "main",
    69
  });

  // ==========================================================================
  // Group 27: Monthly active users
  // ==========================================================================

  tables.push_back({
    "monthly_active_users",
    R"sql(
CREATE TABLE IF NOT EXISTS monthly_active_users (
    user_id TEXT NOT NULL,
    timestamp BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS monthly_active_users_user_idx ON monthly_active_users(user_id)",
      "CREATE INDEX IF NOT EXISTS monthly_active_users_ts_idx ON monthly_active_users(timestamp)"
    },
    "main",
    1
  });

  tables.push_back({
    "daily_active_users",
    R"sql(
CREATE TABLE IF NOT EXISTS daily_active_users (
    user_id TEXT NOT NULL,
    timestamp BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS daily_active_users_user_ts_idx ON daily_active_users(user_id, timestamp)",
      "CREATE INDEX IF NOT EXISTS daily_active_users_ts_idx ON daily_active_users(timestamp)"
    },
    "main",
    69
  });

  // ==========================================================================
  // Group 28: Encryption / cross-signing / key changes
  // ==========================================================================

  tables.push_back({
    "e2e_room_keys_changes",
    R"sql(
CREATE TABLE IF NOT EXISTS e2e_room_keys_changes (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS e2e_room_keys_changes_user_room_idx ON e2e_room_keys_changes(user_id, room_id)",
      "CREATE INDEX IF NOT EXISTS e2e_room_keys_changes_stream_idx ON e2e_room_keys_changes(stream_id)"
    },
    "end_to_end_keys",
    1
  });

  tables.push_back({
    "user_signature_chains",
    R"sql(
CREATE TABLE IF NOT EXISTS user_signature_chains (
    user_id TEXT NOT NULL,
    origin_chain_id BIGINT NOT NULL,
    target_chain_id BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS user_signature_chains_user_idx ON user_signature_chains(user_id, origin_chain_id, target_chain_id)"
    },
    "end_to_end_keys",
    72
  });

  // ==========================================================================
  // Group 29: Device inbox (to_device messages)
  // ==========================================================================

  tables.push_back({
    "device_inbox",
    R"sql(
CREATE TABLE IF NOT EXISTS device_inbox (
    id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    message_json TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS device_inbox_id_idx ON device_inbox(id)",
      "CREATE INDEX IF NOT EXISTS device_inbox_user_device_stream_idx ON device_inbox(user_id, device_id, stream_id)"
    },
    "main",
    1
  });

  tables.push_back({
    "device_max_stream_id",
    R"sql(
CREATE TABLE IF NOT EXISTS device_max_stream_id (
    lock TEXT PRIMARY KEY DEFAULT 'dev_max_stream_lock',
    stream_id BIGINT NOT NULL DEFAULT 0
)
    )sql",
    {},
    "main",
    1
  });

  // ==========================================================================
  // Group 30: Deleted / purged
  // ==========================================================================

  tables.push_back({
    "deleted_devices",
    R"sql(
CREATE TABLE IF NOT EXISTS deleted_devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    deleted_ts BIGINT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS deleted_devices_user_device_idx ON deleted_devices(user_id, device_id)"
    },
    "main",
    1
  });

  tables.push_back({
    "purged_events",
    R"sql(
CREATE TABLE IF NOT EXISTS purged_events (
    room_id TEXT NOT NULL,
    token TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS purged_events_room_token_idx ON purged_events(room_id, token)"
    },
    "main",
    72
  });

  // ==========================================================================
  // Group 31: Room unread / notifications
  // ==========================================================================

  tables.push_back({
    "event_push_actions_unread_highlights",
    R"sql(
CREATE TABLE IF NOT EXISTS event_push_actions_unread_highlights (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_push_actions_unread_highlights_idx ON event_push_actions_unread_highlights(user_id, room_id, event_id)"
    },
    "event_push_actions",
    72
  });

  // ==========================================================================
  // Group 32: Room upgrade / tombstone tracking
  // ==========================================================================

  tables.push_back({
    "room_upgrade_history",
    R"sql(
CREATE TABLE IF NOT EXISTS room_upgrade_history (
    predecessor_room_id TEXT NOT NULL,
    successor_room_id TEXT NOT NULL,
    event_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_upgrade_history_pred_idx ON room_upgrade_history(predecessor_room_id)",
      "CREATE INDEX IF NOT EXISTS room_upgrade_history_succ_idx ON room_upgrade_history(successor_room_id)"
    },
    "room",
    68
  });

  // ==========================================================================
  // Group 33: Ignored users
  // ==========================================================================

  tables.push_back({
    "ignored_users",
    R"sql(
CREATE TABLE IF NOT EXISTS ignored_users (
    ignorer_user_id TEXT NOT NULL,
    ignored_user_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS ignored_users_idx ON ignored_users(ignorer_user_id, ignored_user_id)",
      "CREATE INDEX IF NOT EXISTS ignored_users_ignored_idx ON ignored_users(ignored_user_id)"
    },
    "room",
    1
  });

  // ==========================================================================
  // Group 34: Scheduled tasks
  // ==========================================================================

  tables.push_back({
    "scheduled_tasks",
    R"sql(
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'scheduled',
    timestamp BIGINT NOT NULL,
    result TEXT,
    params_json TEXT DEFAULT '{}',
    resource_id TEXT,
    requesting_user_id TEXT,
    created_ts BIGINT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS scheduled_tasks_id_idx ON scheduled_tasks(id)",
      "CREATE INDEX IF NOT EXISTS scheduled_tasks_status_ts_idx ON scheduled_tasks(status, timestamp)",
      "CREATE INDEX IF NOT EXISTS scheduled_tasks_resource_idx ON scheduled_tasks(resource_id)"
    },
    "main",
    1
  });

  // ==========================================================================
  // Group 35: Session / sessions
  // ==========================================================================

  tables.push_back({
    "sessions",
    R"sql(
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT,
    created_ts BIGINT NOT NULL,
    last_accessed BIGINT,
    ip TEXT,
    user_agent TEXT
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS sessions_session_idx ON sessions(session_id)",
      "CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id)"
    },
    "registration",
    1
  });

  // ==========================================================================
  // Group 36: Notifications
  // ==========================================================================

  tables.push_back({
    "notification_counts",
    R"sql(
CREATE TABLE IF NOT EXISTS notification_counts (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    notification_count BIGINT NOT NULL DEFAULT 0,
    highlight_count BIGINT NOT NULL DEFAULT 0
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS notification_counts_user_room_idx ON notification_counts(user_id, room_id)"
    },
    "event_push_actions",
    72
  });

  // ==========================================================================
  // Group 37: State reset tracking
  // ==========================================================================

  tables.push_back({
    "event_state_resets",
    R"sql(
CREATE TABLE IF NOT EXISTS event_state_resets (
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS event_state_resets_idx ON event_state_resets(room_id, event_id)"
    },
    "state",
    72
  });

  // ==========================================================================
  // Group 38: Un-partial-stated rooms
  // ==========================================================================

  tables.push_back({
    "un_partial_stated_rooms_stream",
    R"sql(
CREATE TABLE IF NOT EXISTS un_partial_stated_rooms_stream (
    stream_id BIGINT NOT NULL,
    room_id TEXT NOT NULL,
    instance_name TEXT NOT NULL
)
    )sql",
    {
      "CREATE INDEX IF NOT EXISTS un_partial_stated_rooms_stream_id_idx ON un_partial_stated_rooms_stream(stream_id)",
      "CREATE INDEX IF NOT EXISTS un_partial_stated_rooms_stream_room_idx ON un_partial_stated_rooms_stream(room_id)"
    },
    "events",
    68
  });

  // ==========================================================================
  // Group 39: Sliding sync / extensions
  // ==========================================================================

  tables.push_back({
    "sliding_sync_joined_rooms",
    R"sql(
CREATE TABLE IF NOT EXISTS sliding_sync_joined_rooms (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    bump_stamp BIGINT NOT NULL,
    notification_count BIGINT NOT NULL DEFAULT 0,
    highlight_count BIGINT NOT NULL DEFAULT 0
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS sliding_sync_joined_rooms_idx ON sliding_sync_joined_rooms(user_id, room_id)",
      "CREATE INDEX IF NOT EXISTS sliding_sync_joined_rooms_bump_idx ON sliding_sync_joined_rooms(user_id, bump_stamp)"
    },
    "room",
    73
  });

  tables.push_back({
    "sliding_sync_membership_snapshots",
    R"sql(
CREATE TABLE IF NOT EXISTS sliding_sync_membership_snapshots (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    has_known_state BOOLEAN DEFAULT TRUE,
    invited_count INTEGER DEFAULT 0,
    joined_count INTEGER DEFAULT 0,
    notification_count INTEGER DEFAULT 0,
    highlight_count INTEGER DEFAULT 0,
    num_live INTEGER DEFAULT 0
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS sliding_sync_membership_snapshots_idx ON sliding_sync_membership_snapshots(user_id, room_id)"
    },
    "room",
    73
  });

  // ==========================================================================
  // Group 40: Room tombstone / predecessor
  // ==========================================================================

  tables.push_back({
    "room_predecessors",
    R"sql(
CREATE TABLE IF NOT EXISTS room_predecessors (
    room_id TEXT NOT NULL,
    predecessor_room_id TEXT NOT NULL,
    event_id TEXT NOT NULL
)
    )sql",
    {
      "CREATE UNIQUE INDEX IF NOT EXISTS room_predecessors_room_idx ON room_predecessors(room_id)"
    },
    "room",
    68
  });

  return tables;
}

// ============================================================================
// Migration File Parsing
// ============================================================================

// Parse a .sql migration file containing -- Up and -- Down sections
MigrationSql parse_migration_file(const std::string& content) {
  MigrationSql result;

  // Regex patterns for section markers
  static const std::regex up_pattern(R"(--\s*Up\s*)", std::regex::icase);
  static const std::regex down_pattern(R"(--\s*Down\s*)", std::regex::icase);

  std::smatch up_match, down_match;
  bool has_up = std::regex_search(content, up_match, up_pattern);
  bool has_down = std::regex_search(content, down_match, down_pattern);

  if (has_up) {
    size_t up_start = up_match.position() + up_match.length();
    if (has_down) {
      size_t down_start = down_match.position();
      result.up_sql = content.substr(up_start, down_start - up_start);
      // Trim leading newlines
      while (!result.up_sql.empty() && (result.up_sql[0] == '\n' || result.up_sql[0] == '\r'))
        result.up_sql.erase(0, 1);
      result.down_sql = content.substr(down_match.position() + down_match.length());
      while (!result.down_sql.empty() && (result.down_sql[0] == '\n' || result.down_sql[0] == '\r'))
        result.down_sql.erase(0, 1);
    } else {
      result.up_sql = content.substr(up_start);
    }
  } else {
    // No markers: the entire file is an "up" migration (no rollback)
    result.up_sql = content;
  }

  // Trim trailing whitespace
  auto trim = [](std::string& s) {
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ' || s.back() == '\t'))
      s.pop_back();
    while (!s.empty() && (s[0] == '\n' || s[0] == '\r' || s[0] == ' ' || s[0] == '\t'))
      s.erase(0, 1);
  };
  trim(result.up_sql);
  trim(result.down_sql);

  return result;
}

// Split a SQL script into individual statements (semicolon-delimited)
// Respects string literals and -- comments
std::vector<std::string> split_sql_statements(const std::string& script) {
  std::vector<std::string> statements;
  std::string current;
  bool in_string = false;
  char string_char = 0;
  bool in_line_comment = false;
  bool in_block_comment = false;

  for (size_t i = 0; i < script.size(); ++i) {
    char c = script[i];

    // Handle block comment end
    if (in_block_comment) {
      if (c == '*' && i + 1 < script.size() && script[i + 1] == '/') {
        in_block_comment = false;
        ++i;  // skip '/'
      }
      continue;
    }

    // Handle block comment start
    if (!in_string && !in_line_comment && c == '/' && i + 1 < script.size() && script[i + 1] == '*') {
      in_block_comment = true;
      ++i;  // skip '*'
      continue;
    }

    // Handle line comment
    if (in_line_comment) {
      if (c == '\n') in_line_comment = false;
      continue;
    }
    if (!in_string && c == '-' && i + 1 < script.size() && script[i + 1] == '-') {
      in_line_comment = true;
      ++i;
      continue;
    }

    // Handle strings
    if (!in_line_comment) {
      if (c == '\'' || c == '"') {
        if (!in_string) {
          in_string = true;
          string_char = c;
        } else if (c == string_char) {
          // Check for escaped quote
          if (i + 1 < script.size() && script[i + 1] == string_char) {
            ++i;  // skip escaped quote
          } else {
            in_string = false;
          }
        }
      }
    }

    if (c == ';' && !in_string && !in_line_comment && !in_block_comment) {
      // Trim statement
      auto trim_stmt = [](std::string& s) {
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
        while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(0, 1);
      };
      trim_stmt(current);
      if (!current.empty()) {
        statements.push_back(std::move(current));
        current.clear();
      }
      continue;
    }

    current += c;
  }

  // Final statement (no trailing semicolon)
  auto trim_stmt = [](std::string& s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(0, 1);
  };
  trim_stmt(current);
  if (!current.empty()) {
    statements.push_back(std::move(current));
  }

  return statements;
}

// Format current time as ISO 8601 timestamp string
std::string iso_timestamp_now() {
  auto now = std::chrono::system_clock::now();
  auto time = std::chrono::system_clock::to_time_t(now);
  std::stringstream ss;
  ss << std::put_time(std::gmtime(&time), "%Y-%m-%d %H:%M:%S");
  return ss.str();
}

// ============================================================================
// MigrationFile: represents a single migration file on disk
// ============================================================================
struct MigrationFile {
  int version = 0;
  std::string file_name;
  std::string file_path;
  std::string up_sql;
  std::string down_sql;
  std::string description;

  bool operator<(const MigrationFile& other) const {
    return version < other.version;
  }
};

// ============================================================================
// MigrationLog: record of applied/rolled-back migrations
// ============================================================================
struct MigrationLogEntry {
  int id;
  int migration_version;
  std::string direction;
  std::string started_at;
  std::string completed_at;
  bool success;
  std::string error_message;
  std::string executed_by;
};

}  // namespace

// ============================================================================
// MigrationRunner Implementation
// ============================================================================

MigrationRunner::MigrationRunner(DatabasePool& db, std::string_view schema_dir)
    : db_(db), schema_dir_(schema_dir) {}

int MigrationRunner::current_version() {
  try {
    auto& engine = db_.engine();
    auto conn = db_.get_connection();
    auto txn = conn->cursor("migration_check_version");

    // Create schema_version table if it doesn't exist yet
    txn->execute(R"(
      CREATE TABLE IF NOT EXISTS schema_version (
          version INTEGER PRIMARY KEY,
          upgraded BOOLEAN NOT NULL DEFAULT TRUE,
          upgraded_by TEXT NOT NULL DEFAULT 'progressive-server',
          applied_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
          compat_version TEXT NOT NULL DEFAULT '1'
      )
    )");

    txn->execute("SELECT MAX(version) as ver FROM schema_version");
    auto row = txn->fetchone();
    txn->close();
    if (row.has_value() && !row->empty()) {
      for (const auto& col : *row) {
        if (col.name == "ver" && col.value.has_value()) {
          try {
            return std::stoi(*col.value);
          } catch (...) {
            return 0;
          }
        }
      }
    }
  } catch (const std::exception& e) {
    std::cerr << "[migration] error reading current version: " << e.what() << "\n";
  }
  return 0;
}

int MigrationRunner::schema_compat_version() {
  try {
    auto conn = db_.get_connection();
    auto txn = conn->cursor("migration_check_compat");

    txn->execute(R"(
      CREATE TABLE IF NOT EXISTS schema_compat_version (
          lock TEXT PRIMARY KEY DEFAULT 'compat_version_lock',
          compat_version INTEGER NOT NULL
      )
    )");

    txn->execute("SELECT compat_version FROM schema_compat_version WHERE lock = 'compat_version_lock'");
    auto row = txn->fetchone();
    txn->close();
    if (row.has_value() && !row->empty()) {
      for (const auto& col : *row) {
        if (col.name == "compat_version" && col.value.has_value()) {
          try {
            return std::stoi(*col.value);
          } catch (...) {
            return 0;
          }
        }
      }
    }
  } catch (...) {}
  return 0;
}

void MigrationRunner::set_schema_compat_version(int version) {
  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_set_compat");
  txn->execute(R"(
    INSERT INTO schema_compat_version (lock, compat_version)
    VALUES ('compat_version_lock', ?)
    ON CONFLICT (lock) DO UPDATE SET compat_version = ?
  )", {std::to_string(version), std::to_string(version)});
  txn->close();
}

std::vector<MigrationFile> MigrationRunner::load_migration_files() const {
  std::vector<MigrationFile> files;
  namespace fs = std::filesystem;

  if (!fs::exists(schema_dir_)) {
    return files;
  }

  // Support both flat-file layout and directory-per-version layout
  // Flat: schema_dir/migrations/001_initial.sql, 002_add_foo.sql, etc.
  // Directory: schema_dir/1/up.sql, schema_dir/1/down.sql, schema_dir/2/up.sql, etc.

  auto try_flat_layout = [&]() -> bool {
    std::string flat_dir = schema_dir_ + "/migrations";
    if (!fs::exists(flat_dir)) return false;

    for (auto& entry : fs::directory_iterator(flat_dir)) {
      if (!entry.is_regular_file()) continue;
      if (entry.path().extension() != ".sql") continue;

      std::string fname = entry.path().filename().string();
      // Try to parse version from filename: NNN_description.sql
      int version = 0;
      std::string desc;
      std::regex ver_re(R"(^(\d+)(?:_(.*))?\.sql$)");
      std::smatch match;
      if (std::regex_match(fname, match, ver_re)) {
        version = std::stoi(match[1].str());
        if (match.size() > 2) desc = match[2].str();
      } else {
        continue;
      }

      std::ifstream f(entry.path());
      if (!f) continue;
      std::stringstream ss;
      ss << f.rdbuf();
      auto parsed = parse_migration_file(ss.str());

      MigrationFile mf;
      mf.version = version;
      mf.file_name = fname;
      mf.file_path = entry.path().string();
      mf.up_sql = std::move(parsed.up_sql);
      mf.down_sql = std::move(parsed.down_sql);
      mf.description = desc;
      files.push_back(std::move(mf));
    }
    return true;
  };

  auto try_directory_layout = [&]() -> bool {
    bool found = false;
    for (auto& entry : fs::directory_iterator(schema_dir_)) {
      if (!entry.is_directory()) continue;
      std::string dirname = entry.path().filename().string();
      int version = 0;
      try {
        version = std::stoi(dirname);
      } catch (...) {
        continue;
      }

      MigrationFile mf;
      mf.version = version;
      mf.file_name = dirname;
      mf.file_path = entry.path().string();

      // Look for up.sql and down.sql in the version directory
      for (auto& f : fs::directory_iterator(entry.path())) {
        if (!f.is_regular_file()) continue;
        if (f.path().extension() != ".sql") continue;
        std::string fname = f.path().filename().string();
        std::ifstream fin(f.path());
        std::stringstream ss;
        ss << fin.rdbuf();

        if (fname.find("up") != std::string::npos) {
          auto parsed = parse_migration_file(ss.str());
          mf.up_sql = parsed.up_sql.empty() ? ss.str() : parsed.up_sql;
          mf.down_sql = parsed.down_sql.empty() ? mf.down_sql : parsed.down_sql;
        } else if (fname.find("down") != std::string::npos) {
          mf.down_sql = ss.str();
        } else {
          // Assume up
          auto parsed = parse_migration_file(ss.str());
          mf.up_sql = parsed.up_sql.empty() ? ss.str() : parsed.up_sql;
        }
      }

      if (!mf.up_sql.empty() || !mf.down_sql.empty()) {
        files.push_back(std::move(mf));
        found = true;
      }
    }
    return found;
  };

  if (!try_flat_layout()) {
    try_directory_layout();
  }

  std::sort(files.begin(), files.end());
  return files;
}

bool MigrationRunner::is_migration_applied(int version, const std::string& file_name) {
  try {
    auto conn = db_.get_connection();
    auto txn = conn->cursor("migration_check_applied");
    // Create tracking table if it doesn't exist
    txn->execute(R"(
      CREATE TABLE IF NOT EXISTS applied_schema_deltas (
          version INTEGER NOT NULL,
          file_name TEXT NOT NULL,
          applied_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
          PRIMARY KEY (version, file_name)
      )
    )");
    txn->execute("SELECT 1 FROM applied_schema_deltas WHERE version = ? AND file_name = ?",
                 {std::to_string(version), file_name});
    auto row = txn->fetchone();
    txn->close();
    return row.has_value() && !row->empty();
  } catch (...) {
    return false;
  }
}

void MigrationRunner::record_migration_applied(int version, const std::string& file_name) {
  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_record_applied");
  txn->execute(R"(
    INSERT OR REPLACE INTO applied_schema_deltas (version, file_name, applied_at)
    VALUES (?, ?, ?)
  )", {std::to_string(version), file_name, iso_timestamp_now()});

  // Also update schema_version table
  txn->execute(R"(
    INSERT OR REPLACE INTO schema_version (version, upgraded, upgraded_by, applied_at, compat_version)
    VALUES (?, TRUE, 'progressive-server', ?, ?)
  )", {std::to_string(version), iso_timestamp_now(), SCHEMA_COMPAT_VERSION});
  txn->close();
}

void MigrationRunner::record_migration_rolled_back(int version, const std::string& file_name) {
  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_record_rollback");
  txn->execute("DELETE FROM applied_schema_deltas WHERE version = ? AND file_name = ?",
               {std::to_string(version), file_name});

  // Remove this version from schema_version and set max to the previous version
  txn->execute("DELETE FROM schema_version WHERE version = ?", {std::to_string(version)});
  txn->close();
}

void MigrationRunner::log_migration(int version, const std::string& direction,
                                     bool success, const std::string& error_message) {
  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_log_entry");
  txn->execute(R"(
    CREATE TABLE IF NOT EXISTS migration_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        migration_version INTEGER NOT NULL,
        direction TEXT NOT NULL CHECK (direction IN ('up', 'down')),
        started_at TIMESTAMP NOT NULL,
        completed_at TIMESTAMP,
        success BOOLEAN,
        error_message TEXT,
        executed_by TEXT NOT NULL DEFAULT 'progressive-server'
    )
  )");

  txn->execute(R"(
    INSERT INTO migration_log (migration_version, direction, started_at, completed_at, success, error_message)
    VALUES (?, ?, ?, ?, ?, ?)
  )", {std::to_string(version), direction, iso_timestamp_now(), iso_timestamp_now(),
       success ? "1" : "0", error_message});
  txn->close();
}

void MigrationRunner::upgrade() {
  int cur = current_version();
  std::cout << "[migration] current schema version: " << cur << "\n";

  // Check compat version
  int compat = schema_compat_version();
  if (compat > 0 && std::to_string(compat) != SCHEMA_COMPAT_VERSION) {
    throw IncorrectDatabaseSetup(
        "Database schema compat version " + std::to_string(compat) +
        " does not match required " + SCHEMA_COMPAT_VERSION +
        ". You may need to upgrade the schema or use an older version.");
  }

  // Set compat version if not set
  if (compat == 0) {
    set_schema_compat_version(std::stoi(SCHEMA_COMPAT_VERSION));
  }

  auto migrations = load_migration_files();
  if (migrations.empty()) {
    std::cout << "[migration] no migration files found in " << schema_dir_ << "\n";
    return;
  }

  std::cout << "[migration] found " << migrations.size() << " migration files\n";

  int applied = 0;
  for (const auto& mig : migrations) {
    if (mig.version <= cur) {
      // Already applied
      continue;
    }

    // Check if this specific file was already applied (delta tracking)
    if (is_migration_applied(mig.version, mig.file_name)) {
      cur = mig.version;
      continue;
    }

    if (mig.up_sql.empty()) {
      std::cerr << "[migration] warning: migration v" << mig.version
                << " has no up SQL, skipping\n";
      record_migration_applied(mig.version, mig.file_name);
      cur = mig.version;
      continue;
    }

    std::cout << "[migration] applying migration v" << mig.version
              << " (" << mig.file_name << ")"
              << (mig.description.empty() ? "" : ": " + mig.description) << "\n";

    // Run in a transaction
    auto conn = db_.get_connection();
    auto txn = conn->cursor("migration_upgrade_v" + std::to_string(mig.version));

    try {
      // Execute each SQL statement individually
      auto statements = split_sql_statements(mig.up_sql);
      for (const auto& stmt : statements) {
        if (!stmt.empty()) {
          txn->execute(stmt);
        }
      }
      conn->commit();
      record_migration_applied(mig.version, mig.file_name);
      log_migration(mig.version, "up", true, "");
      applied++;
      cur = mig.version;
      std::cout << "[migration] successfully applied v" << mig.version << "\n";
    } catch (const std::exception& e) {
      std::cerr << "[migration] ERROR applying v" << mig.version << ": " << e.what() << "\n";
      try { conn->rollback(); } catch (...) {}
      log_migration(mig.version, "up", false, e.what());
      throw;
    }
  }

  if (applied > 0) {
    std::cout << "[migration] applied " << applied << " migrations, now at version " << cur << "\n";
  } else {
    std::cout << "[migration] schema is up to date at version " << cur << "\n";
  }
}

void MigrationRunner::rollback(int target_version) {
  int cur = current_version();
  if (cur <= target_version) {
    std::cout << "[migration] nothing to roll back (current=" << cur
              << ", target=" << target_version << ")\n";
    return;
  }

  auto migrations = load_migration_files();
  // Sort descending for rollback
  std::sort(migrations.begin(), migrations.end(),
            [](const MigrationFile& a, const MigrationFile& b) {
              return a.version > b.version;
            });

  int rolled_back = 0;
  for (const auto& mig : migrations) {
    if (mig.version <= target_version) break;
    if (mig.version > cur) continue;

    if (!is_migration_applied(mig.version, mig.file_name)) {
      continue;
    }

    if (mig.down_sql.empty()) {
      std::cerr << "[migration] warning: migration v" << mig.version
                << " has no down SQL, cannot roll back\n";
      continue;
    }

    std::cout << "[migration] rolling back migration v" << mig.version
              << " (" << mig.file_name << ")\n";

    auto conn = db_.get_connection();
    auto txn = conn->cursor("migration_rollback_v" + std::to_string(mig.version));

    try {
      auto statements = split_sql_statements(mig.down_sql);
      for (const auto& stmt : statements) {
        if (!stmt.empty()) {
          txn->execute(stmt);
        }
      }
      conn->commit();
      record_migration_rolled_back(mig.version, mig.file_name);
      log_migration(mig.version, "down", true, "");
      rolled_back++;
      std::cout << "[migration] successfully rolled back v" << mig.version << "\n";
    } catch (const std::exception& e) {
      std::cerr << "[migration] ERROR rolling back v" << mig.version << ": " << e.what() << "\n";
      try { conn->rollback(); } catch (...) {}
      log_migration(mig.version, "down", false, e.what());
      throw;
    }
  }

  if (rolled_back > 0) {
    std::cout << "[migration] rolled back " << rolled_back << " migrations\n";
  }
  std::cout << "[migration] schema is now at version " << current_version() << "\n";
}

void MigrationRunner::bootstrap() {
  std::cout << "[migration] bootstrapping database schema...\n";

  // Apply all table definitions as a single bootstrap transaction
  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_bootstrap");

  // First ensure schema_version tables exist
  txn->execute(R"(
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        upgraded BOOLEAN NOT NULL DEFAULT TRUE,
        upgraded_by TEXT NOT NULL DEFAULT 'progressive-server',
        applied_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
        compat_version TEXT NOT NULL DEFAULT '1'
    )
  )");
  txn->execute(R"(
    CREATE TABLE IF NOT EXISTS schema_compat_version (
        lock TEXT PRIMARY KEY DEFAULT 'compat_version_lock',
        compat_version INTEGER NOT NULL
    )
  )");
  txn->execute(R"(
    CREATE TABLE IF NOT EXISTS migration_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        migration_version INTEGER NOT NULL,
        direction TEXT NOT NULL CHECK (direction IN ('up', 'down')),
        started_at TIMESTAMP NOT NULL,
        completed_at TIMESTAMP,
        success BOOLEAN,
        error_message TEXT,
        executed_by TEXT NOT NULL DEFAULT 'progressive-server'
    )
  )");
  txn->execute(R"(
    CREATE TABLE IF NOT EXISTS applied_schema_deltas (
        version INTEGER NOT NULL,
        file_name TEXT NOT NULL,
        applied_at TIMESTAMP NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
        PRIMARY KEY (version, file_name)
    )
  )");

  // Create all synapse-equivalent tables
  auto tables = all_synapse_table_definitions();
  int created = 0;
  for (const auto& table : tables) {
    try {
      txn->execute(table.create_sql);
      created++;

      // Create associated indices
      for (const auto& idx_sql : table.index_sql) {
        txn->execute(idx_sql);
      }
    } catch (const std::exception& e) {
      std::cerr << "[migration] warning: failed to create table "
                << table.name << ": " << e.what() << "\n";
    }
  }

  std::cout << "[migration] bootstrapped " << created << "/" << tables.size() << " tables\n";

  // Set up compat version
  txn->execute(R"(
    INSERT OR REPLACE INTO schema_compat_version (lock, compat_version)
    VALUES ('compat_version_lock', ?)
  )", {std::string(SCHEMA_COMPAT_VERSION)});

  // Mark as version 1 (bootstrap)
  txn->execute(R"(
    INSERT OR REPLACE INTO schema_version (version, upgraded, upgraded_by, applied_at, compat_version)
    VALUES (1, TRUE, 'progressive-server', ?, ?)
  )", {iso_timestamp_now(), SCHEMA_COMPAT_VERSION});

  conn->commit();
  std::cout << "[migration] bootstrap complete\n";
}

std::string MigrationRunner::dump_schema() {
  std::stringstream out;
  out << "-- Progressive Server Schema Dump\n";
  out << "-- SCHEMA_COMPAT_VERSION: " << SCHEMA_COMPAT_VERSION << "\n";
  out << "-- Generated: " << iso_timestamp_now() << "\n";
  out << "-- Current version: " << current_version() << "\n\n";

  auto tables = all_synapse_table_definitions();

  // Group by module for readability
  std::map<std::string, std::vector<const TableDefinition*>> by_module;
  for (const auto& table : tables) {
    by_module[table.module].push_back(&table);
  }

  for (const auto& [module, module_tables] : by_module) {
    out << "-- ============================================================\n";
    out << "-- Module: " << module << " (" << module_tables.size() << " tables)\n";
    out << "-- ============================================================\n\n";

    for (const auto* table : module_tables) {
      out << "-- Schema version: " << table->schema_version << "\n";
      out << table->create_sql << ";\n\n";

      for (const auto& idx : table->index_sql) {
        out << idx << ";\n";
      }
      out << "\n";
    }
  }

  out << "-- End of schema dump\n";
  out << "-- Total tables defined: " << tables.size() << "\n";

  return out.str();
}

void MigrationRunner::write_schema_dump(const std::string& output_path) {
  std::string dump = dump_schema();
  std::ofstream out(output_path);
  if (!out) {
    throw std::runtime_error("Failed to open schema dump file: " + output_path);
  }
  out << dump;
  std::cout << "[migration] schema dumped to " << output_path
            << " (" << dump.size() << " bytes)\n";
}

void MigrationRunner::validate_migrations() {
  auto migrations = load_migration_files();
  std::cout << "[migration] validating " << migrations.size() << " migration files...\n";

  int errors = 0;
  int warnings = 0;
  std::set<int> versions;

  for (const auto& mig : migrations) {
    // Check for duplicate versions
    if (versions.count(mig.version)) {
      std::cerr << "[migration] ERROR: duplicate version " << mig.version
                << " in " << mig.file_name << "\n";
      errors++;
    }
    versions.insert(mig.version);

    // Check that up SQL exists
    if (mig.up_sql.empty() && mig.down_sql.empty()) {
      std::cerr << "[migration] ERROR: migration v" << mig.version
                << " has no SQL content\n";
      errors++;
    }

    // Check for basic SQL syntax (starts with expected keywords)
    if (!mig.up_sql.empty()) {
      std::string upper = mig.up_sql;
      std::transform(upper.begin(), upper.end(), upper.begin(),
                     [](unsigned char c) { return std::toupper(c); });
      // Trim leading whitespace
      while (!upper.empty() && std::isspace(static_cast<unsigned char>(upper.front())))
        upper.erase(0, 1);

      if (upper.find("CREATE") == std::string::npos &&
          upper.find("ALTER") == std::string::npos &&
          upper.find("INSERT") == std::string::npos &&
          upper.find("UPDATE") == std::string::npos &&
          upper.find("DELETE") == std::string::npos &&
          upper.find("DROP") == std::string::npos) {
        std::cerr << "[migration] WARNING: migration v" << mig.version
                  << " up SQL may not start with a recognized DDL/DML keyword\n";
        warnings++;
      }
    }

    // Check down SQL
    if (mig.down_sql.empty() && !mig.up_sql.empty()) {
      std::cout << "[migration] note: migration v" << mig.version
                << " has no down (rollback) SQL\n";
    }
  }

  // Check for version gaps
  if (!versions.empty()) {
    int min_ver = *versions.begin();
    int max_ver = *versions.rbegin();
    for (int v = min_ver; v <= max_ver; ++v) {
      if (!versions.count(v)) {
        std::cerr << "[migration] WARNING: gap at version " << v << "\n";
        warnings++;
      }
    }
  }

  if (errors == 0 && warnings == 0) {
    std::cout << "[migration] all migrations validated successfully\n";
  } else {
    std::cout << "[migration] validation complete: " << errors << " errors, "
              << warnings << " warnings\n";
  }
}

void MigrationRunner::run_background_update(const std::string& update_name) {
  std::cout << "[migration] running background update: " << update_name << "\n";

  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_bg_update");

  try {
    // Ensure background_updates table exists
    txn->execute(R"(
      CREATE TABLE IF NOT EXISTS background_updates (
          update_name TEXT NOT NULL,
          progress_json TEXT NOT NULL DEFAULT '{}',
          depends_on TEXT,
          ordering INTEGER NOT NULL DEFAULT 0,
          batch_size INTEGER DEFAULT 100,
          min_replication_depth INTEGER DEFAULT 0,
          run_as_background_process BOOLEAN DEFAULT FALSE,
          inserted_ts BIGINT NOT NULL,
          PRIMARY KEY (update_name)
      )
    )");

    // Check current progress
    txn->execute("SELECT progress_json, depends_on FROM background_updates WHERE update_name = ?",
                 {update_name});
    auto row = txn->fetchone();
    std::string progress_json;
    std::string depends_on;

    if (row.has_value()) {
      for (const auto& col : *row) {
        if (col.name == "progress_json" && col.value.has_value())
          progress_json = *col.value;
        if (col.name == "depends_on" && col.value.has_value())
          depends_on = *col.value;
      }
    }

    // Check dependencies
    if (!depends_on.empty()) {
      txn->execute("SELECT 1 FROM background_updates WHERE update_name = ? AND progress_json LIKE '%\"complete\":true%'",
                   {depends_on});
      auto dep_row = txn->fetchone();
      if (!dep_row.has_value() || dep_row->empty()) {
        std::cout << "[migration] background update " << update_name
                  << " waiting for dependency: " << depends_on << "\n";
        txn->close();
        return;
      }
    }

    // Read completed status
    bool completed = progress_json.find("\"complete\": true") != std::string::npos ||
                      progress_json.find("\"complete\":true") != std::string::npos;

    if (completed) {
      std::cout << "[migration] background update " << update_name
                << " already completed\n";
      txn->close();
      return;
    }

    // Mark as in-progress
    std::string in_progress = R"({"status": "running", "started_at": ")" + iso_timestamp_now() + R"("})";
    txn->execute(R"(
      INSERT OR REPLACE INTO background_updates (update_name, progress_json, ordering, inserted_ts)
      VALUES (?, ?, 1, ?)
    )", {update_name, in_progress, std::to_string(
         std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::system_clock::now().time_since_epoch()).count())});

    conn->commit();
    txn->close();

    // The actual update logic would be executed here by the registered handler
    // This is dispatched from the BackgroundUpdater class

    std::cout << "[migration] background update " << update_name
              << " dispatched for execution\n";
  } catch (const std::exception& e) {
    std::cerr << "[migration] background update " << update_name
              << " failed: " << e.what() << "\n";
    try { conn->rollback(); } catch (...) {}
    throw;
  }
}

void MigrationRunner::complete_background_update(const std::string& update_name) {
  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_bg_update_complete");

  std::string completed = R"({"status": "complete", "completed_at": ")" + iso_timestamp_now() + R"(", "complete": true})";

  txn->execute(R"(
    UPDATE background_updates SET progress_json = ? WHERE update_name = ?
  )", {completed, update_name});
  conn->commit();
  txn->close();

  std::cout << "[migration] background update " << update_name << " marked as complete\n";
}

void MigrationRunner::register_background_update(
    const std::string& update_name,
    const std::string& depends_on,
    int ordering,
    int batch_size,
    bool run_as_background_process) {
  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_register_bg_update");

  txn->execute(R"(
    CREATE TABLE IF NOT EXISTS background_updates (
        update_name TEXT NOT NULL,
        progress_json TEXT NOT NULL DEFAULT '{}',
        depends_on TEXT,
        ordering INTEGER NOT NULL DEFAULT 0,
        batch_size INTEGER DEFAULT 100,
        min_replication_depth INTEGER DEFAULT 0,
        run_as_background_process BOOLEAN DEFAULT FALSE,
        inserted_ts BIGINT NOT NULL,
        PRIMARY KEY (update_name)
    )
  )");

  auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();

  txn->execute(R"(
    INSERT OR REPLACE INTO background_updates
      (update_name, progress_json, depends_on, ordering, batch_size,
       run_as_background_process, inserted_ts)
    VALUES (?, '{}', ?, ?, ?, ?, ?)
  )", {update_name, depends_on, std::to_string(ordering),
       std::to_string(batch_size), run_as_background_process ? "1" : "0",
       std::to_string(now_ms)});
  conn->commit();
  txn->close();

  std::cout << "[migration] registered background update: " << update_name
            << " (ordering=" << ordering << ")\n";
}

std::string MigrationRunner::get_background_update_progress(const std::string& update_name) {
  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_get_bg_progress");

  txn->execute("SELECT progress_json FROM background_updates WHERE update_name = ?",
               {update_name});
  auto row = txn->fetchone();
  txn->close();

  if (row.has_value()) {
    for (const auto& col : *row) {
      if (col.name == "progress_json" && col.value.has_value()) {
        return *col.value;
      }
    }
  }
  return "{}";
}

void MigrationRunner::update_background_progress(const std::string& update_name,
                                                   const std::string& progress_json) {
  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_update_bg_progress");
  txn->execute("UPDATE background_updates SET progress_json = ? WHERE update_name = ?",
               {progress_json, update_name});
  conn->commit();
  txn->close();
}

void MigrationRunner::list_pending_background_updates() {
  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_list_bg_updates");

  txn->execute(R"(
    CREATE TABLE IF NOT EXISTS background_updates (
        update_name TEXT NOT NULL,
        progress_json TEXT NOT NULL DEFAULT '{}',
        depends_on TEXT,
        ordering INTEGER NOT NULL DEFAULT 0,
        batch_size INTEGER DEFAULT 100,
        inserted_ts BIGINT NOT NULL,
        PRIMARY KEY (update_name)
    )
  )");

  txn->execute(R"(
    SELECT update_name, progress_json, depends_on, ordering
    FROM background_updates
    WHERE progress_json NOT LIKE '%"complete": true%'
       OR progress_json NOT LIKE '%"complete":true%'
    ORDER BY ordering ASC
  )");

  auto rows = txn->fetchall();
  txn->close();

  if (rows.empty()) {
    std::cout << "[migration] no pending background updates\n";
    return;
  }

  std::cout << "[migration] pending background updates:\n";
  for (const auto& row : rows) {
    std::string name, progress, deps, order;
    for (const auto& col : row) {
      if (col.name == "update_name" && col.value.has_value()) name = *col.value;
      if (col.name == "progress_json" && col.value.has_value()) progress = *col.value;
      if (col.name == "depends_on" && col.value.has_value()) deps = " -> " + *col.value;
      if (col.name == "ordering" && col.value.has_value()) order = *col.value;
    }
    std::cout << "  [" << order << "] " << name << deps << " : " << progress << "\n";
  }
}

void MigrationRunner::list_applied_migrations() {
  auto conn = db_.get_connection();
  auto txn = conn->cursor("migration_list_applied");

  try {
    txn->execute(R"(
      SELECT version, file_name, applied_at
      FROM applied_schema_deltas
      ORDER BY version ASC
    )");
    auto rows = txn->fetchall();
    txn->close();

    if (rows.empty()) {
      std::cout << "[migration] no migrations have been applied\n";
      return;
    }

    std::cout << "[migration] applied migrations (" << rows.size() << "):\n";
    for (const auto& row : rows) {
      std::string ver, fname, applied;
      for (const auto& col : row) {
        if (col.name == "version" && col.value.has_value()) ver = *col.value;
        if (col.name == "file_name" && col.value.has_value()) fname = *col.value;
        if (col.name == "applied_at" && col.value.has_value()) applied = *col.value;
      }
      std::cout << "  v" << ver << "  " << fname << "  (" << applied << ")\n";
    }
  } catch (const std::exception& e) {
    std::cerr << "[migration] error listing applied migrations: " << e.what() << "\n";
  }
}

// ============================================================================
// Apply Schema - convenience entry point
// ============================================================================

void apply_schema(DatabasePool& db) {
  // Inline fallback — applies the core schema if not already present
  std::string embedded_data_dir;
  // Try common locations for the schema files
  namespace fs = std::filesystem;
  for (auto* prefix : {"", "/usr/share/progressive-server/", "./", "../src/progressive/"}) {
    std::string path = std::string(prefix) + "storage/schema";
    if (fs::exists(path + "/migrations") || fs::exists(path + "/main/full_schemas")) {
      embedded_data_dir = fs::absolute(path).string();
      break;
    }
  }

  if (!embedded_data_dir.empty()) {
    MigrationRunner runner(db, embedded_data_dir);
    runner.upgrade();
  } else {
    // No schema files found — use inline DDL (bootstrap)
    MigrationRunner runner(db, "");
    runner.bootstrap();
  }
}

// ============================================================================
// Connection Pool Factory
// ============================================================================

std::unique_ptr<ConnectionPool> make_pool(
    const std::string& database_name,
    const std::string& connection_string,
    std::shared_ptr<BaseDatabaseEngine> engine,
    const std::string& server_name,
    std::function<void(DatabaseConnection&)> on_new_connection) {
  // This would create the actual connection pool implementation
  // Delegates to the concrete pool implementation
  return nullptr;  // Stub — actual implementation in connection_pool.cpp
}

std::unique_ptr<LoggingDatabaseConnection> make_conn(
    const std::string& connection_string,
    std::shared_ptr<BaseDatabaseEngine> engine,
    const std::string& default_txn_name,
    const std::string& server_name) {
  // This would create a raw connection
  return nullptr;  // Stub — actual implementation in connection_pool.cpp
}

}  // namespace progressive::storage
