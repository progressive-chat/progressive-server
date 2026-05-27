#include "../json.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

namespace progressive::storage {

// ============================================================================
// SCHEMA VERSION CONSTANTS
// ============================================================================
// Synapse SCHEMA_VERSION was bumped to 72 for the base schema.
// Prior to that, the initial full schema was loaded at version 54.
// Deltas increment from delta/54/v1 through delta/72/v10+.
// ============================================================================

static constexpr int SCHEMA_VERSION_INITIAL = 54;
static constexpr int SCHEMA_VERSION_FULL    = 72;
static constexpr const char* SCHEMA_COMPAT_VERSION = "1";

// ============================================================================
// Forward declare delta registration helpers
// ============================================================================
namespace {

struct SchemaDelta {
  int version;
  int delta_number;
  std::string name;
  std::string description;
  std::function<void(class SchemaMigrationRunner&)> apply;
  bool is_background_update;
  std::string depends_on;
};

}  // anonymous namespace

// ============================================================================
// SchemaMigrationRunner - orchestrates all schema migration deltas
// ============================================================================
class SchemaMigrationRunner {
public:
  using TxnFunc = std::function<void(const std::string& sql)>;
  using QueryFunc = std::function<std::vector<std::map<std::string, std::string>>(const std::string& sql)>;
  using Callback = std::function<void()>;

  SchemaMigrationRunner(TxnFunc execute_fn, QueryFunc query_fn)
    : execute_(std::move(execute_fn)), query_(std::move(query_fn)) {}

  void execute(const std::string& sql) { execute_(sql); }
  auto query(const std::string& sql) { return query_(sql); }

  // Get current schema version from DB
  int get_current_version() {
    try {
      auto rows = query("SELECT MAX(version) as ver FROM schema_version");
      if (!rows.empty() && rows[0].count("ver") && !rows[0]["ver"].empty()) {
        return std::stoi(rows[0]["ver"]);
      }
    } catch (...) {}
    return 0;
  }

  // Record that a delta has been applied
  void record_delta(int version, int delta_number) {
    std::stringstream ss;
    ss << "INSERT INTO schema_version (version, delta_number, applied_at) VALUES ("
       << version << ", " << delta_number << ", datetime('now'))";
    execute(ss.str());
  }

  void record_delta_upgrade(int version, int delta_number, const std::string& upgraded_by) {
    std::stringstream ss;
    ss << "INSERT INTO schema_version (version, delta_number, upgraded, upgraded_by, applied_at) VALUES ("
       << version << ", " << delta_number << ", 1, '" << upgraded_by << "', datetime('now'))";
    execute(ss.str());
  }

  // Check if a delta is already applied
  bool is_delta_applied(int version, int delta_number) {
    auto rows = query("SELECT 1 FROM schema_version WHERE version=" +
                      std::to_string(version) + " AND delta_number=" +
                      std::to_string(delta_number));
    return !rows.empty();
  }

  // Check if a background update has been registered
  bool has_background_update(const std::string& update_name) {
    auto rows = query("SELECT 1 FROM background_updates WHERE update_name='" +
                      update_name + "'");
    return !rows.empty();
  }

  // Register a background update
  void register_background_update(const std::string& update_name,
                                   const std::string& depends_on = "",
                                   int ordering = 0) {
    if (has_background_update(update_name)) return;
    std::stringstream ss;
    ss << "INSERT INTO background_updates (update_name, progress_json, depends_on, ordering, inserted_ts) VALUES ('"
       << update_name << "', '{}', "
       << (depends_on.empty() ? "NULL" : ("'" + depends_on + "'"))
       << ", " << ordering << ", " << std::time(nullptr) << ")";
    execute(ss.str());
  }

  // Mark a background update as completed
  void complete_background_update(const std::string& update_name) {
    execute("DELETE FROM background_updates WHERE update_name='" + update_name + "'");
  }

  // Check if table exists
  bool table_exists(const std::string& table_name) {
    auto rows = query("SELECT name FROM sqlite_master WHERE type='table' AND name='" +
                      table_name + "'");
    return !rows.empty();
  }

  // Check if column exists in table
  bool column_exists(const std::string& table_name, const std::string& column_name) {
    auto rows = query("PRAGMA table_info(" + table_name + ")");
    for (auto& row : rows) {
      if (row.count("name") && row["name"] == column_name) return true;
    }
    return false;
  }

  // Check if index exists
  bool index_exists(const std::string& index_name) {
    auto rows = query("SELECT name FROM sqlite_master WHERE type='index' AND name='" +
                      index_name + "'");
    return !rows.empty();
  }

  // Background update runner
  void run_background_updates() {
    auto pending = query("SELECT update_name, depends_on, progress_json FROM background_updates "
                         "ORDER BY ordering, inserted_ts");
    for (auto& row : pending) {
      std::string name = row["update_name"];
      std::string depends = row.count("depends_on") ? row["depends_on"] : "";
      if (!depends.empty() && has_background_update(depends)) {
        continue;  // Dependency not yet completed
      }
      apply_background_update(name);
    }
  }

  void apply_background_update(const std::string& update_name) {
    auto it = background_update_handlers_.find(update_name);
    if (it != background_update_handlers_.end()) {
      it->second(*this);
    }
  }

  void register_background_handler(const std::string& name, std::function<void(SchemaMigrationRunner&)> handler) {
    background_update_handlers_[name] = std::move(handler);
  }

  // Run all migrations up to target version
  void upgrade(int target_version = SCHEMA_VERSION_FULL) {
    int current = get_current_version();

    // Bootstrap schema_version table if needed
    if (!table_exists("schema_version")) {
      execute(R"(
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL,
            delta_number INTEGER NOT NULL DEFAULT 0,
            upgraded BOOLEAN NOT NULL DEFAULT 1,
            upgraded_by TEXT NOT NULL DEFAULT 'progressive-server',
            applied_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
            compat_version TEXT NOT NULL DEFAULT '1',
            PRIMARY KEY (version, delta_number)
        )
      )");
    }

    // Apply initial full schema if database is empty
    if (current == 0 || !table_exists("events")) {
      std::cout << "[schema_migration] Applying full schema v" << SCHEMA_VERSION_FULL << std::endl;
      apply_full_schema_72();
      record_delta_upgrade(SCHEMA_VERSION_FULL, 0, "progressive-server");
      current = SCHEMA_VERSION_FULL;
    }

    // Sort and apply deltas
    std::vector<SchemaDelta> all_deltas = collect_all_deltas();
    std::sort(all_deltas.begin(), all_deltas.end(),
              [](const SchemaDelta& a, const SchemaDelta& b) {
                if (a.version != b.version) return a.version < b.version;
                return a.delta_number < b.delta_number;
              });

    for (auto& delta : all_deltas) {
      if (delta.version > target_version) continue;
      if (is_delta_applied(delta.version, delta.delta_number)) continue;

      std::cout << "[schema_migration] Applying delta v" << delta.version
                << "/" << delta.delta_number << ": " << delta.description << std::endl;

      try {
        if (delta.is_background_update) {
          register_background_update(delta.name, delta.depends_on, delta.version * 100 + delta.delta_number);
        } else {
          delta.apply(*this);
          record_delta(delta.version, delta.delta_number);
        }
      } catch (const std::exception& e) {
        std::cerr << "[schema_migration] Delta v" << delta.version << "/"
                  << delta.delta_number << " FAILED: " << e.what() << std::endl;
        throw;
      }
    }

    // Run background updates
    run_background_updates();

    std::cout << "[schema_migration] Current version: " << get_current_version() << std::endl;
  }

  // Collect all delta definitions
  std::vector<SchemaDelta> collect_all_deltas();

private:
  TxnFunc execute_;
  QueryFunc query_;
  std::unordered_map<std::string, std::function<void(SchemaMigrationRunner&)>> background_update_handlers_;

  // ========================================================================
  // FULL SCHEMA 72 - Complete initial database schema
  // ========================================================================
  void apply_full_schema_72() {
    // Schema tracking tables
    execute(R"(
      CREATE TABLE IF NOT EXISTS schema_version (
          version INTEGER NOT NULL,
          delta_number INTEGER NOT NULL DEFAULT 0,
          upgraded BOOLEAN NOT NULL DEFAULT 1,
          upgraded_by TEXT NOT NULL DEFAULT 'progressive-server',
          applied_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
          compat_version TEXT NOT NULL DEFAULT '1',
          PRIMARY KEY (version, delta_number)
      )
    )");

    execute(R"(
      CREATE TABLE IF NOT EXISTS schema_compat_version (
          lock TEXT PRIMARY KEY DEFAULT 'compat_version_lock',
          compat_version INTEGER NOT NULL
      )
    )");

    execute(R"(
      CREATE TABLE IF NOT EXISTS applied_schema_deltas (
          version INTEGER NOT NULL,
          file_name TEXT NOT NULL,
          applied_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
          PRIMARY KEY (version, file_name)
      )
    )");

    execute(R"(
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
    execute("CREATE INDEX IF NOT EXISTS migration_log_version_idx ON migration_log(migration_version)");

    // Background updates
    execute(R"(
      CREATE TABLE IF NOT EXISTS background_updates (
          update_name TEXT NOT NULL,
          progress_json TEXT NOT NULL DEFAULT '{}',
          depends_on TEXT,
          ordering INTEGER NOT NULL DEFAULT 0,
          batch_size INTEGER DEFAULT 100,
          min_replication_depth INTEGER DEFAULT 0,
          run_as_background_process BOOLEAN DEFAULT 0,
          inserted_ts BIGINT NOT NULL,
          PRIMARY KEY (update_name)
      )
    )");

    // Users
    execute(R"(
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
          shadow_banned BOOLEAN DEFAULT 0,
          suspended BOOLEAN DEFAULT 0,
          approved BOOLEAN DEFAULT 1,
          locked BOOLEAN DEFAULT 0
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS users_name_idx ON users(name)");
    execute("CREATE INDEX IF NOT EXISTS users_creation_ts_idx ON users(creation_ts)");
    execute("CREATE INDEX IF NOT EXISTS users_deactivated_idx ON users(deactivated)");

    // Access tokens
    execute(R"(
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
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS access_tokens_token_idx ON access_tokens(token)");
    execute("CREATE INDEX IF NOT EXISTS access_tokens_user_id_idx ON access_tokens(user_id)");
    execute("CREATE INDEX IF NOT EXISTS access_tokens_device_id_idx ON access_tokens(device_id)");
    execute("CREATE INDEX IF NOT EXISTS access_tokens_refresh_token_id_idx ON access_tokens(refresh_token_id)");

    // Refresh tokens
    execute(R"(
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
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS refresh_tokens_token_idx ON refresh_tokens(token)");
    execute("CREATE INDEX IF NOT EXISTS refresh_tokens_next_token_id_idx ON refresh_tokens(next_token_id)");
    execute("CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx ON refresh_tokens(user_id)");

    // Threepids
    execute(R"(
      CREATE TABLE IF NOT EXISTS user_threepids (
          user_id TEXT NOT NULL,
          medium TEXT NOT NULL,
          address TEXT NOT NULL,
          validated_at BIGINT NOT NULL,
          added_at BIGINT NOT NULL,
          validated BOOLEAN DEFAULT 0,
          bound_ts BIGINT,
          CONSTRAINT user_threepid_unique UNIQUE (user_id, medium, address)
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS user_threepids_user_id_idx ON user_threepids(user_id)");
    execute("CREATE INDEX IF NOT EXISTS user_threepids_medium_address_idx ON user_threepids(medium, address)");

    // Registration tokens
    execute(R"(
      CREATE TABLE IF NOT EXISTS registration_tokens (
          token TEXT NOT NULL,
          uses_allowed INT,
          pending INT NOT NULL,
          completed INT NOT NULL,
          expiry_time BIGINT,
          created_ts BIGINT NOT NULL,
          creator_user TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS registration_tokens_token_idx ON registration_tokens(token)");

    // UI auth sessions
    execute(R"(
      CREATE TABLE IF NOT EXISTS ui_auth_sessions (
          session_id TEXT NOT NULL,
          creation_ts BIGINT NOT NULL,
          server_data TEXT NOT NULL,
          clientdict_json TEXT,
          uri TEXT,
          method TEXT,
          description TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS ui_auth_sessions_session_id_idx ON ui_auth_sessions(session_id)");

    // Ratelimit override
    execute(R"(
      CREATE TABLE IF NOT EXISTS ratelimit_override (
          user_id TEXT NOT NULL,
          messages_per_second BIGINT,
          burst_count BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS ratelimit_override_user_id_idx ON ratelimit_override(user_id)");

    // Devices
    execute(R"(
      CREATE TABLE IF NOT EXISTS devices (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          display_name TEXT,
          device_type TEXT,
          hidden BOOLEAN DEFAULT 0,
          last_seen BIGINT,
          ip TEXT,
          user_agent TEXT,
          session_id BIGINT,
          CONSTRAINT device_uniqueness UNIQUE (user_id, device_id)
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS devices_user_id_idx ON devices(user_id)");
    execute("CREATE INDEX IF NOT EXISTS devices_session_id_idx ON devices(session_id)");

    // Device lists stream
    execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_stream (
          stream_id BIGINT NOT NULL,
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS device_lists_stream_id_idx ON device_lists_stream(stream_id, user_id, device_id)");

    // Device inbox / to_device messages
    execute(R"(
      CREATE TABLE IF NOT EXISTS device_inbox (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT NOT NULL,
          device_id TEXT,
          type TEXT NOT NULL,
          sender TEXT,
          content TEXT,
          stream_id BIGINT
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS device_inbox_user_idx ON device_inbox(user_id)");

    // E2E keys
    execute(R"(
      CREATE TABLE IF NOT EXISTS e2e_device_keys_json (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          ts_added_ms BIGINT NOT NULL,
          key_json TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS e2e_device_keys_json_idx ON e2e_device_keys_json(user_id, device_id)");
    execute("CREATE INDEX IF NOT EXISTS e2e_device_keys_json_ts_idx ON e2e_device_keys_json(ts_added_ms)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS e2e_one_time_keys_json (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          algorithm TEXT NOT NULL,
          key_id TEXT NOT NULL,
          ts_added_ms BIGINT NOT NULL,
          key_json TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS e2e_one_time_keys_json_idx ON e2e_one_time_keys_json(user_id, device_id, algorithm, key_id)");
    execute("CREATE INDEX IF NOT EXISTS e2e_one_time_keys_json_user_idx ON e2e_one_time_keys_json(user_id, device_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS e2e_fallback_keys_json (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          algorithm TEXT NOT NULL,
          key_id TEXT NOT NULL,
          ts_added_ms BIGINT NOT NULL,
          key_json TEXT NOT NULL,
          used BOOLEAN DEFAULT 0
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS e2e_fallback_keys_json_idx ON e2e_fallback_keys_json(user_id, device_id, algorithm)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS e2e_cross_signing_keys (
          user_id TEXT NOT NULL,
          keytype TEXT NOT NULL,
          keydata TEXT NOT NULL,
          stream_id BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS e2e_cross_signing_keys_idx ON e2e_cross_signing_keys(user_id, keytype)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS e2e_cross_signing_signatures (
          user_id TEXT NOT NULL,
          key_id TEXT NOT NULL,
          target_user_id TEXT NOT NULL,
          target_device_id TEXT NOT NULL,
          signature TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS e2e_cross_signing_signatures_idx ON e2e_cross_signing_signatures(user_id, key_id, target_user_id, target_device_id)");

    execute(R"(
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
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS e2e_room_keys_idx ON e2e_room_keys(user_id, room_id, session_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS e2e_room_keys_versions (
          user_id TEXT NOT NULL,
          version TEXT NOT NULL,
          algorithm TEXT,
          auth_data TEXT NOT NULL,
          etag TEXT,
          deleted SMALLINT DEFAULT 0
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS e2e_room_keys_versions_idx ON e2e_room_keys_versions(user_id, version)");

    // Events
    execute(R"(
      CREATE TABLE IF NOT EXISTS events (
          stream_ordering BIGINT NOT NULL,
          topological_ordering BIGINT NOT NULL,
          event_id TEXT NOT NULL,
          type TEXT NOT NULL,
          room_id TEXT NOT NULL,
          content TEXT,
          unrecognized_keys TEXT,
          processed BOOLEAN NOT NULL DEFAULT 1,
          outlier BOOLEAN NOT NULL DEFAULT 0,
          origin_server_ts BIGINT,
          received_ts BIGINT,
          sender TEXT NOT NULL,
          contains_url BOOLEAN,
          instance_name TEXT,
          state_key TEXT,
          depth BIGINT NOT NULL DEFAULT 0,
          rejection_reason TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS events_event_id_idx ON events(event_id)");
    execute("CREATE INDEX IF NOT EXISTS events_stream_ordering_idx ON events(stream_ordering)");
    execute("CREATE INDEX IF NOT EXISTS events_topological_ordering_idx ON events(topological_ordering)");
    execute("CREATE INDEX IF NOT EXISTS events_room_id_idx ON events(room_id)");
    execute("CREATE INDEX IF NOT EXISTS events_order_room_idx ON events(room_id, topological_ordering, stream_ordering)");
    execute("CREATE INDEX IF NOT EXISTS events_ts_idx ON events(origin_server_ts)");
    execute("CREATE INDEX IF NOT EXISTS events_sender_idx ON events(sender)");
    execute("CREATE INDEX IF NOT EXISTS events_contains_url_idx ON events(room_id, topological_ordering, stream_ordering) WHERE contains_url");
    execute("CREATE INDEX IF NOT EXISTS events_instance_name_idx ON events(instance_name)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_json (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          internal_metadata TEXT NOT NULL,
          json TEXT NOT NULL,
          format_version INTEGER
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_json_event_id_idx ON event_json(event_id)");
    execute("CREATE INDEX IF NOT EXISTS event_json_room_id_idx ON event_json(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_edges (
          event_id TEXT NOT NULL,
          prev_event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          is_state BOOLEAN NOT NULL DEFAULT 0
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_edges_id_idx ON event_edges(event_id, prev_event_id, room_id)");
    execute("CREATE INDEX IF NOT EXISTS event_edges_prev_event_id_idx ON event_edges(prev_event_id)");
    execute("CREATE INDEX IF NOT EXISTS event_edges_room_id_idx ON event_edges(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_auth (
          event_id TEXT NOT NULL,
          auth_id TEXT NOT NULL,
          room_id TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_auth_event_auth_idx ON event_auth(event_id, auth_id, room_id)");
    execute("CREATE INDEX IF NOT EXISTS event_auth_auth_id_idx ON event_auth(auth_id)");
    execute("CREATE INDEX IF NOT EXISTS event_auth_room_id_idx ON event_auth(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_auth_chains (
          event_id TEXT NOT NULL,
          chain_id BIGINT NOT NULL,
          sequence_number BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_auth_chains_event_id_idx ON event_auth_chains(event_id)");
    execute("CREATE INDEX IF NOT EXISTS event_auth_chains_cid_seq_idx ON event_auth_chains(chain_id, sequence_number)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_auth_chain_links (
          origin_chain_id BIGINT NOT NULL,
          origin_sequence_number BIGINT NOT NULL,
          target_chain_id BIGINT NOT NULL,
          target_sequence_number BIGINT NOT NULL
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS event_auth_chain_links_origin_idx ON event_auth_chain_links(origin_chain_id, origin_sequence_number)");
    execute("CREATE INDEX IF NOT EXISTS event_auth_chain_links_target_idx ON event_auth_chain_links(target_chain_id, target_sequence_number)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_auth_chain_to_calculate (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          type TEXT NOT NULL,
          state_key TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_auth_chain_to_calc_idx ON event_auth_chain_to_calculate(event_id, type, state_key)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_relations (
          event_id TEXT NOT NULL,
          relates_to_id TEXT NOT NULL,
          relation_type TEXT NOT NULL,
          aggregation_key TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_relations_event_id_idx ON event_relations(event_id)");
    execute("CREATE INDEX IF NOT EXISTS event_relations_relates_to_idx ON event_relations(relates_to_id)");
    execute("CREATE INDEX IF NOT EXISTS event_relations_rel_type_idx ON event_relations(relation_type)");
    execute("CREATE INDEX IF NOT EXISTS event_relations_agg_key_idx ON event_relations(relation_type, aggregation_key)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_txn_id (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          txn_id TEXT NOT NULL,
          inserted_ts BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_txn_id_event_idx ON event_txn_id(event_id)");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_txn_id_txn_idx ON event_txn_id(room_id, user_id, txn_id)");
    execute("CREATE INDEX IF NOT EXISTS event_txn_id_ts_idx ON event_txn_id(inserted_ts)");

    // State system
    execute(R"(
      CREATE TABLE IF NOT EXISTS state_events (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          type TEXT NOT NULL,
          state_key TEXT NOT NULL,
          topological_ordering BIGINT NOT NULL,
          stream_ordering BIGINT NOT NULL,
          prev_state TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS state_events_event_id_idx ON state_events(event_id)");
    execute("CREATE INDEX IF NOT EXISTS state_events_room_type_key_idx ON state_events(room_id, type, state_key)");
    execute("CREATE INDEX IF NOT EXISTS state_events_room_id_idx ON state_events(room_id)");
    execute("CREATE INDEX IF NOT EXISTS state_events_stream_ordering_idx ON state_events(stream_ordering)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS current_state_events (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          type TEXT NOT NULL,
          state_key TEXT NOT NULL,
          membership TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS current_state_events_event_id_idx ON current_state_events(event_id)");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS current_state_events_room_type_key_idx ON current_state_events(room_id, type, state_key)");
    execute("CREATE INDEX IF NOT EXISTS current_state_events_room_id_idx ON current_state_events(room_id)");
    execute("CREATE INDEX IF NOT EXISTS current_state_events_membership_idx ON current_state_events(membership)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS state_groups (
          id BIGINT NOT NULL,
          room_id TEXT NOT NULL,
          event_id TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS state_groups_id_idx ON state_groups(id)");
    execute("CREATE INDEX IF NOT EXISTS state_groups_room_id_idx ON state_groups(room_id)");
    execute("CREATE INDEX IF NOT EXISTS state_groups_event_id_idx ON state_groups(event_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS state_groups_state (
          state_group BIGINT NOT NULL,
          room_id TEXT NOT NULL,
          type TEXT NOT NULL,
          state_key TEXT NOT NULL,
          event_id TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS state_groups_state_unique_idx ON state_groups_state(state_group, type, state_key)");
    execute("CREATE INDEX IF NOT EXISTS state_groups_state_sg_idx ON state_groups_state(state_group)");
    execute("CREATE INDEX IF NOT EXISTS state_groups_state_room_idx ON state_groups_state(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS state_group_edges (
          state_group BIGINT NOT NULL,
          prev_state_group BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS state_group_edges_idx ON state_group_edges(state_group, prev_state_group)");
    execute("CREATE INDEX IF NOT EXISTS state_group_edges_prev_idx ON state_group_edges(prev_state_group)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_to_state_groups (
          event_id TEXT NOT NULL,
          state_group BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_to_state_groups_event_id_idx ON event_to_state_groups(event_id)");
    execute("CREATE INDEX IF NOT EXISTS event_to_state_groups_sg_idx ON event_to_state_groups(state_group)");

    // Forward/backward extremities
    execute(R"(
      CREATE TABLE IF NOT EXISTS event_forward_extremities (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_forward_extremities_event_room_idx ON event_forward_extremities(event_id, room_id)");
    execute("CREATE INDEX IF NOT EXISTS event_forward_extremities_room_idx ON event_forward_extremities(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_backward_extremities (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_backward_extremities_event_room_idx ON event_backward_extremities(event_id, room_id)");
    execute("CREATE INDEX IF NOT EXISTS event_backward_extremities_room_idx ON event_backward_extremities(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS ex_outlier_stream (
          event_stream_ordering BIGINT NOT NULL,
          event_id TEXT NOT NULL,
          state_group BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS ex_outlier_stream_event_idx ON ex_outlier_stream(event_id)");
    execute("CREATE INDEX IF NOT EXISTS ex_outlier_stream_ordering_idx ON ex_outlier_stream(event_stream_ordering)");

    // Redactions and rejections
    execute(R"(
      CREATE TABLE IF NOT EXISTS redactions (
          event_id TEXT NOT NULL,
          redacts TEXT NOT NULL,
          have_censored BOOLEAN NOT NULL DEFAULT 0,
          received_ts BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS redactions_event_id_idx ON redactions(event_id)");
    execute("CREATE INDEX IF NOT EXISTS redactions_redacts_idx ON redactions(redacts)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS rejections (
          event_id TEXT NOT NULL,
          reason TEXT NOT NULL,
          last_check TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS rejections_event_id_idx ON rejections(event_id)");

    // Event search
    execute(R"(
      CREATE TABLE IF NOT EXISTS event_search (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          sender TEXT,
          key TEXT NOT NULL,
          vector TEXT,
          origin_server_ts BIGINT,
          stream_ordering BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_search_event_id_idx ON event_search(event_id)");
    execute("CREATE INDEX IF NOT EXISTS event_search_room_idx ON event_search(room_id)");
    execute("CREATE INDEX IF NOT EXISTS event_search_key_idx ON event_search(key)");
    execute("CREATE INDEX IF NOT EXISTS event_search_stream_ordering_idx ON event_search(stream_ordering)");

    // Event reports
    execute(R"(
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
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_reports_id_idx ON event_reports(id)");
    execute("CREATE INDEX IF NOT EXISTS event_reports_event_idx ON event_reports(event_id)");
    execute("CREATE INDEX IF NOT EXISTS event_reports_room_idx ON event_reports(room_id)");
    execute("CREATE INDEX IF NOT EXISTS event_reports_user_idx ON event_reports(user_id)");

    // Event push actions
    execute(R"(
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
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_push_actions_room_event_user_idx ON event_push_actions(room_id, event_id, user_id)");
    execute("CREATE INDEX IF NOT EXISTS event_push_actions_rm_user_idx ON event_push_actions(room_id, user_id)");
    execute("CREATE INDEX IF NOT EXISTS event_push_actions_stream_ordering_idx ON event_push_actions(stream_ordering)");
    execute("CREATE INDEX IF NOT EXISTS event_push_actions_highlight_idx ON event_push_actions(user_id, room_id, topological_ordering, stream_ordering)");
    execute("CREATE INDEX IF NOT EXISTS event_push_actions_unread_idx ON event_push_actions(user_id, room_id, notif, stream_ordering)");
    execute("CREATE INDEX IF NOT EXISTS event_push_actions_room_id_idx ON event_push_actions(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_push_actions_staging (
          event_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          profile_tag TEXT,
          actions TEXT NOT NULL,
          notif SMALLINT,
          highlight SMALLINT,
          unread SMALLINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_push_actions_staging_id_idx ON event_push_actions_staging(event_id, user_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_push_summary (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          notif_count BIGINT NOT NULL,
          stream_ordering BIGINT NOT NULL,
          topological_ordering BIGINT NOT NULL,
          unread_count BIGINT,
          highlight_count BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_push_summary_user_room_idx ON event_push_summary(user_id, room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS event_push_summary_stream_ordering (
          lock TEXT PRIMARY KEY DEFAULT 'stream_ordering_lock',
          stream_ordering BIGINT NOT NULL DEFAULT 0
      )
    )");

    // Rooms
    execute(R"(
      CREATE TABLE IF NOT EXISTS rooms (
          room_id TEXT NOT NULL,
          is_public BOOLEAN,
          is_encrypted BOOLEAN DEFAULT 0,
          creator TEXT,
          room_version TEXT,
          has_auth_chain_index BOOLEAN DEFAULT 0
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS rooms_room_id_idx ON rooms(room_id)");
    execute("CREATE INDEX IF NOT EXISTS rooms_is_public_idx ON rooms(is_public)");
    execute("CREATE INDEX IF NOT EXISTS rooms_creator_idx ON rooms(creator)");

    // Room depth
    execute(R"(
      CREATE TABLE IF NOT EXISTS room_depth (
          room_id TEXT NOT NULL,
          min_depth BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_depth_room_idx ON room_depth(room_id)");

    // Room stats
    execute(R"(
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
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_stats_state_room_idx ON room_stats_state(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS room_stats_earliest_token (
          room_id TEXT NOT NULL,
          token BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_stats_earliest_token_idx ON room_stats_earliest_token(room_id)");

    execute(R"(
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
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_stats_current_room_idx ON room_stats_current(room_id)");

    execute(R"(
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
    )");
    execute("CREATE INDEX IF NOT EXISTS room_stats_historical_room_ts_idx ON room_stats_historical(room_id, end_ts)");

    // Room memberships
    execute(R"(
      CREATE TABLE IF NOT EXISTS room_memberships (
          event_id TEXT NOT NULL,
          event_stream_ordering BIGINT NOT NULL,
          user_id TEXT NOT NULL,
          sender TEXT NOT NULL,
          room_id TEXT NOT NULL,
          membership TEXT NOT NULL,
          display_name TEXT,
          avatar_url TEXT,
          forgotten BOOLEAN DEFAULT 0,
          knock_state TEXT,
          knock_reason TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_memberships_event_idx ON room_memberships(event_id)");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_memberships_user_room_idx ON room_memberships(user_id, room_id)");
    execute("CREATE INDEX IF NOT EXISTS room_memberships_room_member_idx ON room_memberships(room_id, membership)");
    execute("CREATE INDEX IF NOT EXISTS room_memberships_stream_idx ON room_memberships(event_stream_ordering)");
    execute("CREATE INDEX IF NOT EXISTS room_memberships_user_member_idx ON room_memberships(user_id, membership)");
    execute("CREATE INDEX IF NOT EXISTS room_memberships_forgotten_idx ON room_memberships(user_id, room_id) WHERE forgotten = 1");

    // Room aliases
    execute(R"(
      CREATE TABLE IF NOT EXISTS room_aliases (
          room_alias TEXT NOT NULL,
          room_id TEXT NOT NULL,
          creator TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_aliases_alias_idx ON room_aliases(room_alias)");
    execute("CREATE INDEX IF NOT EXISTS room_aliases_room_idx ON room_aliases(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS room_alias_servers (
          room_alias TEXT NOT NULL,
          server TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_alias_servers_alias_srv_idx ON room_alias_servers(room_alias, server)");

    // Room tags
    execute(R"(
      CREATE TABLE IF NOT EXISTS room_tags (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          tag TEXT NOT NULL,
          content TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_tags_user_room_tag_idx ON room_tags(user_id, room_id, tag)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS room_tags_revisions (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          stream_id BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_tags_revisions_user_room_idx ON room_tags_revisions(user_id, room_id)");

    // Room account data
    execute(R"(
      CREATE TABLE IF NOT EXISTS room_account_data (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          account_data_type TEXT NOT NULL,
          stream_id BIGINT NOT NULL,
          content TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_account_data_uid_room_type_idx ON room_account_data(user_id, room_id, account_data_type)");
    execute("CREATE INDEX IF NOT EXISTS room_account_data_stream_idx ON room_account_data(stream_id)");

    // Global account data
    execute(R"(
      CREATE TABLE IF NOT EXISTS account_data (
          user_id TEXT NOT NULL,
          account_data_type TEXT NOT NULL,
          stream_id BIGINT NOT NULL,
          content TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS account_data_user_type_idx ON account_data(user_id, account_data_type)");
    execute("CREATE INDEX IF NOT EXISTS account_data_stream_idx ON account_data(stream_id)");

    // Room retention
    execute(R"(
      CREATE TABLE IF NOT EXISTS room_retention (
          room_id TEXT NOT NULL,
          event_id TEXT NOT NULL,
          min_lifetime BIGINT,
          max_lifetime BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS room_retention_room_idx ON room_retention(room_id)");

    // Insertion events (MSC2716)
    execute(R"(
      CREATE TABLE IF NOT EXISTS insertion_events (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          next_batch_id TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS insertion_events_event_id_idx ON insertion_events(event_id)");
    execute("CREATE INDEX IF NOT EXISTS insertion_events_next_batch_idx ON insertion_events(next_batch_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS insertion_event_edges (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          insertion_prev_event_id TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS insertion_event_edges_event_idx ON insertion_event_edges(event_id)");

    // Partial state
    execute(R"(
      CREATE TABLE IF NOT EXISTS partial_state_rooms (
          room_id TEXT NOT NULL,
          joined_via TEXT,
          creation_ts BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS partial_state_rooms_room_idx ON partial_state_rooms(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS partial_state_rooms_servers (
          room_id TEXT NOT NULL,
          server_name TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS partial_state_rooms_servers_idx ON partial_state_rooms_servers(room_id, server_name)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS partial_state_events (
          room_id TEXT NOT NULL,
          event_id TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS partial_state_events_room_event_idx ON partial_state_events(room_id, event_id)");
    execute("CREATE INDEX IF NOT EXISTS partial_state_events_event_idx ON partial_state_events(event_id)");

    // Un-partial-stated rooms stream
    execute(R"(
      CREATE TABLE IF NOT EXISTS un_partial_stated_rooms_stream (
          stream_id BIGINT PRIMARY KEY,
          room_id TEXT NOT NULL,
          successful BOOLEAN NOT NULL
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS un_partial_stated_rooms_stream_room_idx ON un_partial_stated_rooms_stream(room_id)");

    // Sliding sync
    execute(R"(
      CREATE TABLE IF NOT EXISTS sliding_sync_joined_rooms (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          event_stream_ordering BIGINT NOT NULL,
          bump_stamp BIGINT NOT NULL,
          joined_via TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS sliding_sync_joined_rooms_idx ON sliding_sync_joined_rooms(user_id, room_id)");
    execute("CREATE INDEX IF NOT EXISTS sliding_sync_joined_rooms_stream_idx ON sliding_sync_joined_rooms(event_stream_ordering)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS sliding_sync_membership_snapshots (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          event_id TEXT NOT NULL,
          event_stream_ordering BIGINT NOT NULL,
          membership TEXT NOT NULL,
          sender TEXT NOT NULL,
          has_known_state BOOLEAN DEFAULT 0,
          forgotten BOOLEAN DEFAULT 0
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS sliding_sync_membership_snapshots_idx ON sliding_sync_membership_snapshots(user_id, room_id, event_id)");
    execute("CREATE INDEX IF NOT EXISTS sliding_sync_membership_snapshots_stream_idx ON sliding_sync_membership_snapshots(event_stream_ordering)");

    // Profiles
    execute(R"(
      CREATE TABLE IF NOT EXISTS profiles (
          user_id TEXT NOT NULL,
          displayname TEXT,
          avatar_url TEXT,
          presence_status TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS profiles_user_id_idx ON profiles(user_id)");

    // Receipts
    execute(R"(
      CREATE TABLE IF NOT EXISTS receipts_graph (
          room_id TEXT NOT NULL,
          receipt_type TEXT NOT NULL,
          user_id TEXT NOT NULL,
          event_ids TEXT NOT NULL,
          thread_id TEXT,
          data TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS receipts_graph_room_user_type_idx ON receipts_graph(room_id, receipt_type, user_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS receipts_linearized (
          stream_id BIGINT NOT NULL,
          room_id TEXT NOT NULL,
          receipt_type TEXT NOT NULL,
          user_id TEXT NOT NULL,
          event_id TEXT NOT NULL,
          thread_id TEXT,
          data TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS receipts_linearized_room_user_type_idx ON receipts_linearized(room_id, receipt_type, user_id)");
    execute("CREATE INDEX IF NOT EXISTS receipts_linearized_stream_idx ON receipts_linearized(stream_id)");
    execute("CREATE INDEX IF NOT EXISTS receipts_linearized_room_stream_idx ON receipts_linearized(room_id, stream_id)");

    // Read markers
    execute(R"(
      CREATE TABLE IF NOT EXISTS read_markers (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          event_id TEXT NOT NULL,
          updated_ts BIGINT,
          PRIMARY KEY (user_id, room_id)
      )
    )");

    // Presence
    execute(R"(
      CREATE TABLE IF NOT EXISTS presence_state (
          user_id TEXT NOT NULL,
          state TEXT DEFAULT 'offline',
          status_msg TEXT,
          last_active_ts BIGINT,
          last_federation_update_ts BIGINT,
          last_user_sync_ts BIGINT,
          currently_active BOOLEAN DEFAULT 0
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS presence_state_user_idx ON presence_state(user_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS presence_stream (
          stream_id BIGINT NOT NULL,
          user_id TEXT NOT NULL,
          state TEXT,
          last_active_ts BIGINT,
          last_federation_update_ts BIGINT,
          last_user_sync_ts BIGINT,
          currently_active BOOLEAN,
          status_msg TEXT
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS presence_stream_stream_id_idx ON presence_stream(stream_id)");
    execute("CREATE INDEX IF NOT EXISTS presence_stream_user_id_idx ON presence_stream(user_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS presence_allow_inbound (
          observed_user_id TEXT NOT NULL,
          observer_user_id TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS presence_allow_inbound_idx ON presence_allow_inbound(observed_user_id, observer_user_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS presence_list (
          user_id TEXT NOT NULL,
          observed_user_id TEXT NOT NULL,
          accepted BOOLEAN NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS presence_list_user_observed_idx ON presence_list(user_id, observed_user_id)");
    execute("CREATE INDEX IF NOT EXISTS presence_list_observed_idx ON presence_list(observed_user_id)");

    // Appservice
    execute(R"(
      CREATE TABLE IF NOT EXISTS application_services_state (
          as_id TEXT PRIMARY KEY,
          state TEXT,
          txn_id TEXT
      )
    )");

    execute(R"(
      CREATE TABLE IF NOT EXISTS application_services_txns (
          as_id TEXT NOT NULL,
          txn_id BIGINT NOT NULL,
          event_ids TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS application_services_txns_as_txn_idx ON application_services_txns(as_id, txn_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS application_services_regex (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          as_id TEXT NOT NULL,
          namespace TEXT NOT NULL,
          regex TEXT NOT NULL,
          exclusive BOOLEAN NOT NULL DEFAULT 1
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS application_services_regex_as_idx ON application_services_regex(as_id)");

    // Pushers
    execute(R"(
      CREATE TABLE IF NOT EXISTS pushers (
          id BIGINT PRIMARY KEY,
          user_name TEXT NOT NULL,
          access_token BIGINT,
          profile_tag TEXT NOT NULL,
          kind TEXT NOT NULL,
          app_id TEXT NOT NULL,
          app_display_name TEXT NOT NULL,
          device_display_name TEXT,
          pushkey TEXT NOT NULL,
          ts BIGINT NOT NULL,
          lang TEXT,
          data TEXT,
          last_stream_ordering INTEGER,
          last_success BIGINT,
          failing_since BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS pushers_app_id_pushkey_user_name_idx ON pushers(app_id, pushkey, user_name)");
    execute("CREATE INDEX IF NOT EXISTS pushers_user_name_idx ON pushers(user_name)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS pusher_throttle (
          pusher_id BIGINT NOT NULL,
          room_id TEXT NOT NULL,
          throttled_until BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS pusher_throttle_pusher_room_idx ON pusher_throttle(pusher_id, room_id)");

    // Push rules
    execute(R"(
      CREATE TABLE IF NOT EXISTS push_rules (
          id BIGINT PRIMARY KEY,
          user_name TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          priority_class SMALLINT NOT NULL,
          priority INTEGER NOT NULL DEFAULT 0,
          conditions TEXT NOT NULL,
          actions TEXT NOT NULL,
          default_rule BOOLEAN NOT NULL DEFAULT 0,
          rule_type TEXT NOT NULL DEFAULT 'override',
          enabled BOOLEAN NOT NULL DEFAULT 1
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS push_rules_user_name_rule_id_idx ON push_rules(user_name, rule_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS push_rules_enable (
          id BIGINT PRIMARY KEY,
          user_name TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          enabled SMALLINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS push_rules_enable_user_rule_idx ON push_rules_enable(user_name, rule_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS push_rules_stream (
          stream_id BIGINT PRIMARY KEY,
          user_id TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          op TEXT NOT NULL,
          data TEXT
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS push_rules_stream_user_idx ON push_rules_stream(user_id)");
    execute("CREATE INDEX IF NOT EXISTS push_rules_stream_stream_idx ON push_rules_stream(stream_id)");

    // Federation
    execute(R"(
      CREATE TABLE IF NOT EXISTS federation_stream_position (
          type TEXT NOT NULL,
          stream_id BIGINT NOT NULL,
          instance_name TEXT NOT NULL DEFAULT 'master'
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS federation_stream_position_type_idx ON federation_stream_position(type, instance_name)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS destination_rooms (
          destination TEXT NOT NULL,
          room_id TEXT NOT NULL,
          stream_ordering BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS destination_rooms_dest_room_idx ON destination_rooms(destination, room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS received_transactions (
          transaction_id TEXT NOT NULL,
          origin TEXT NOT NULL,
          ts BIGINT NOT NULL,
          response_code INTEGER DEFAULT 0,
          response_json TEXT,
          has_been_referenced SMALLINT DEFAULT 0
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS received_transactions_transaction_id_origin_idx ON received_transactions(transaction_id, origin)");

    // Server keys
    execute(R"(
      CREATE TABLE IF NOT EXISTS server_keys_json (
          server_name TEXT NOT NULL,
          key_id TEXT NOT NULL,
          from_server TEXT NOT NULL,
          ts_added_ms BIGINT NOT NULL,
          ts_valid_until_ms BIGINT NOT NULL,
          key_json TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS server_keys_json_server_key_idx ON server_keys_json(server_name, key_id, from_server)");
    execute("CREATE INDEX IF NOT EXISTS server_keys_json_server_idx ON server_keys_json(server_name)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS server_signature_keys (
          server_name TEXT NOT NULL,
          key_id TEXT NOT NULL,
          from_server TEXT NOT NULL,
          ts_added_ms BIGINT NOT NULL,
          ts_valid_until_ms BIGINT NOT NULL,
          verify_key TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS server_signature_keys_server_key_idx ON server_signature_keys(server_name, key_id, from_server)");

    // Media repository
    execute(R"(
      CREATE TABLE IF NOT EXISTS local_media_repository (
          media_id TEXT NOT NULL,
          media_type TEXT NOT NULL,
          media_length BIGINT NOT NULL,
          created_ts BIGINT NOT NULL,
          upload_name TEXT,
          user_id TEXT NOT NULL,
          quarantined_by TEXT,
          url_cache TEXT,
          last_access_ts BIGINT NOT NULL,
          safe_from_quarantine BOOLEAN NOT NULL DEFAULT 0
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS local_media_repository_media_id_idx ON local_media_repository(media_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS remote_media_cache (
          media_id TEXT NOT NULL,
          media_origin TEXT NOT NULL,
          media_type TEXT NOT NULL,
          media_length BIGINT NOT NULL,
          filesystem_id TEXT NOT NULL,
          created_ts BIGINT NOT NULL,
          upload_name TEXT,
          last_access_ts BIGINT NOT NULL,
          quarantined_by TEXT,
          authentication_info TEXT,
          etag TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS remote_media_cache_media_origin_idx ON remote_media_cache(media_id, media_origin)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS local_media_repository_thumbnails (
          media_id TEXT NOT NULL,
          thumbnail_width INTEGER NOT NULL,
          thumbnail_height INTEGER NOT NULL,
          thumbnail_type TEXT NOT NULL,
          thumbnail_method TEXT NOT NULL,
          thumbnail_length BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS local_media_repository_thumbnails_idx ON local_media_repository_thumbnails(media_id, thumbnail_width, thumbnail_height, thumbnail_type, thumbnail_method)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS remote_media_cache_thumbnails (
          media_id TEXT NOT NULL,
          media_origin TEXT NOT NULL,
          thumbnail_width INTEGER NOT NULL,
          thumbnail_height INTEGER NOT NULL,
          thumbnail_type TEXT NOT NULL,
          thumbnail_method TEXT NOT NULL,
          filesystem_id TEXT NOT NULL,
          thumbnail_length BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS remote_media_cache_thumbnails_idx ON remote_media_cache_thumbnails(media_id, media_origin, thumbnail_width, thumbnail_height, thumbnail_type, thumbnail_method)");

    // User directory
    execute(R"(
      CREATE TABLE IF NOT EXISTS user_directory (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          display_name TEXT,
          avatar_url TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS user_directory_user_room_idx ON user_directory(user_id, room_id)");
    execute("CREATE INDEX IF NOT EXISTS user_directory_room_idx ON user_directory(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS user_directory_search (
          user_id TEXT NOT NULL,
          vector TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS user_directory_search_user_idx ON user_directory_search(user_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS user_directory_stream_pos (
          lock TEXT PRIMARY KEY DEFAULT 'stream_pos_lock',
          stream_id BIGINT NOT NULL DEFAULT 0
      )
    )");

    // User daily visits / monthly active users
    execute(R"(
      CREATE TABLE IF NOT EXISTS user_daily_visits (
          user_id TEXT NOT NULL,
          device_id TEXT,
          timestamp BIGINT NOT NULL
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS user_daily_visits_uts_idx ON user_daily_visits(user_id, timestamp)");
    execute("CREATE INDEX IF NOT EXISTS user_daily_visits_ts_idx ON user_daily_visits(timestamp)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS monthly_active_users (
          user_id TEXT NOT NULL,
          timestamp BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS monthly_active_users_idx ON monthly_active_users(user_id)");
    execute("CREATE INDEX IF NOT EXISTS monthly_active_users_ts_idx ON monthly_active_users(timestamp)");

    // Event labels
    execute(R"(
      CREATE TABLE IF NOT EXISTS event_labels (
          event_id TEXT NOT NULL,
          label TEXT NOT NULL,
          room_id TEXT NOT NULL,
          topological_ordering BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS event_labels_event_label_idx ON event_labels(event_id, label)");
    execute("CREATE INDEX IF NOT EXISTS event_labels_room_idx ON event_labels(room_id, topological_ordering)");

    // Scheduled tasks
    execute(R"(
      CREATE TABLE IF NOT EXISTS scheduled_tasks (
          task_id TEXT NOT NULL,
          action TEXT NOT NULL,
          status TEXT DEFAULT 'scheduled',
          params TEXT,
          result TEXT,
          error TEXT,
          created_ts BIGINT NOT NULL,
          scheduled_ts BIGINT,
          completed_ts BIGINT,
          repeating BOOLEAN DEFAULT 0,
          schedule_interval BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS scheduled_tasks_task_id_idx ON scheduled_tasks(task_id)");
    execute("CREATE INDEX IF NOT EXISTS scheduled_tasks_status_idx ON scheduled_tasks(status)");

    // User filters
    execute(R"(
      CREATE TABLE IF NOT EXISTS user_filters (
          user_id TEXT NOT NULL,
          filter_id INTEGER NOT NULL,
          filter_json TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS user_filters_user_filter_idx ON user_filters(user_id, filter_id)");

    // Server ACL
    execute(R"(
      CREATE TABLE IF NOT EXISTS server_acl (
          room_id TEXT NOT NULL,
          event_id TEXT,
          allow_ip_literals BOOLEAN DEFAULT 0,
          allowed_servers TEXT,
          denied_servers TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS server_acl_room_idx ON server_acl(room_id)");

    // Timeline gaps (for partial sync)
    execute(R"(
      CREATE TABLE IF NOT EXISTS timeline_gaps (
          room_id TEXT NOT NULL,
          gap_start TEXT NOT NULL,
          gap_end TEXT NOT NULL,
          PRIMARY KEY (room_id, gap_start)
      )
    )");

    // Streams
    execute(R"(
      CREATE TABLE IF NOT EXISTS streams (
          name TEXT NOT NULL,
          stream_id BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS streams_name_idx ON streams(name)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS stream_positions (
          stream_name TEXT NOT NULL,
          instance_name TEXT NOT NULL DEFAULT 'master',
          stream_id BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS stream_positions_name_instance_idx ON stream_positions(stream_name, instance_name)");

    // Worker support
    execute(R"(
      CREATE TABLE IF NOT EXISTS worker_stream_positions (
          worker_name TEXT NOT NULL,
          stream_type INTEGER NOT NULL,
          position BIGINT NOT NULL,
          PRIMARY KEY (worker_name, stream_type)
      )
    )");

    execute(R"(
      CREATE TABLE IF NOT EXISTS worker_locks (
          lock_name TEXT NOT NULL,
          worker_name TEXT NOT NULL,
          acquired_ts BIGINT NOT NULL,
          PRIMARY KEY (lock_name)
      )
    )");

    execute(R"(
      CREATE TABLE IF NOT EXISTS replication_stream (
          stream_id BIGINT PRIMARY KEY,
          stream_type INTEGER NOT NULL,
          row_id BIGINT,
          data TEXT NOT NULL
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS replication_stream_type_idx ON replication_stream(stream_type)");

    // Threepid validation sessions
    execute(R"(
      CREATE TABLE IF NOT EXISTS threepid_validation_session (
          session_id TEXT NOT NULL,
          medium TEXT NOT NULL,
          address TEXT NOT NULL,
          client_secret TEXT NOT NULL,
          validated_at BIGINT,
          last_send_attempt BIGINT,
          attempt_count INTEGER DEFAULT 0
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS threepid_validation_session_id_idx ON threepid_validation_session(session_id)");

    // Threepid guest access tokens
    execute(R"(
      CREATE TABLE IF NOT EXISTS threepid_guest_access_tokens (
          medium TEXT NOT NULL,
          address TEXT NOT NULL,
          guest_access_token TEXT NOT NULL,
          first_inviter TEXT,
          expires_at BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS threepid_guest_access_tokens_idx ON threepid_guest_access_tokens(medium, address)");

    // Dehydrated devices
    execute(R"(
      CREATE TABLE IF NOT EXISTS dehydrated_devices (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          device_data TEXT NOT NULL,
          time_of_rehydration BIGINT,
          creation_ts BIGINT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS dehydrated_devices_user_id_idx ON dehydrated_devices(user_id)");

    // Account validity
    execute(R"(
      CREATE TABLE IF NOT EXISTS account_validity (
          user_id TEXT NOT NULL,
          expiration_ts_ms BIGINT NOT NULL,
          email_sent BOOLEAN NOT NULL DEFAULT 0,
          renewal_token TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS account_validity_user_idx ON account_validity(user_id)");

    // Device lists (federation outbound pokes)
    execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_outbound_pokes (
          destination TEXT NOT NULL,
          stream_id BIGINT NOT NULL,
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          sent BOOLEAN DEFAULT 0,
          ts BIGINT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS device_lists_outbound_pokes_idx ON device_lists_outbound_pokes(destination, stream_id, user_id)");
    execute("CREATE INDEX IF NOT EXISTS device_lists_outbound_pokes_stream_idx ON device_lists_outbound_pokes(stream_id)");
    execute("CREATE INDEX IF NOT EXISTS device_lists_outbound_pokes_ts_idx ON device_lists_outbound_pokes(ts)");

    // Device lists remote extremities
    execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_remote_extremeties (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          stream_id TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS device_lists_remote_extremeties_idx ON device_lists_remote_extremeties(user_id, device_id, stream_id)");

    // Device lists remote cache
    execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_remote_cache (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          content TEXT NOT NULL
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS device_lists_remote_cache_idx ON device_lists_remote_cache(user_id, device_id)");

    // Device lists remote resync
    execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_remote_resync (
          user_id TEXT NOT NULL,
          added_ts BIGINT NOT NULL,
          origin TEXT
      )
    )");
    execute("CREATE UNIQUE INDEX IF NOT EXISTS device_lists_remote_resync_idx ON device_lists_remote_resync(user_id)");

    // Device lists changes in room
    execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_changes_in_room (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          stream_id BIGINT NOT NULL,
          converted_to_destinations BOOLEAN DEFAULT 0,
          opentracing_context TEXT
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS device_lists_changes_in_room_stream_idx ON device_lists_changes_in_room(stream_id)");
    execute("CREATE INDEX IF NOT EXISTS device_lists_changes_in_room_room_idx ON device_lists_changes_in_room(room_id)");

    execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_changes_converted_stream_position (
          lock TEXT PRIMARY KEY DEFAULT 'converted_lock',
          stream_id BIGINT NOT NULL DEFAULT 0
      )
    )");

    // Thread subscriptions
    execute(R"(
      CREATE TABLE IF NOT EXISTS thread_subscriptions (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          thread_id TEXT NOT NULL,
          subscribed BOOLEAN NOT NULL DEFAULT 1,
          PRIMARY KEY (user_id, room_id, thread_id)
      )
    )");

    // Background jobs
    execute(R"(
      CREATE TABLE IF NOT EXISTS background_jobs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          job_name TEXT NOT NULL UNIQUE,
          job_type TEXT NOT NULL,
          arguments_json TEXT NOT NULL DEFAULT '{}',
          status TEXT NOT NULL DEFAULT 'queued',
          attempts INTEGER NOT NULL DEFAULT 0,
          max_attempts INTEGER NOT NULL DEFAULT 3,
          created_ts BIGINT NOT NULL,
          started_ts BIGINT,
          completed_ts BIGINT,
          error_message TEXT,
          result_json TEXT
      )
    )");
    execute("CREATE INDEX IF NOT EXISTS background_jobs_status_idx ON background_jobs(status)");

    std::cout << "[schema_migration] Full schema v72 applied successfully." << std::endl;
  }  // end apply_full_schema_72
};  // end SchemaMigrationRunner

// ============================================================================
// ALL SCHEMA DELTAS - Organized by version and delta_number
// Equivalent to synapse/storage/schema/main/delta/XX/YYYY.sql
// ============================================================================

// -------------------------------------------------------
// DELTA 54 - Post-initial-schema additions
// -------------------------------------------------------

static void delta_54_v1_content_index(SchemaMigrationRunner& r) {
  // Add index on events for content search
  if (!r.index_exists("events_content_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS events_content_idx ON events(content)");
  }
}

static void delta_54_v2_topological_index(SchemaMigrationRunner& r) {
  // Ensure topological ordering index exists
  if (!r.index_exists("events_topological_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS events_topological_idx ON events(topological_ordering)");
  }
}

static void delta_54_v3_origin_server_ts_index(SchemaMigrationRunner& r) {
  // Add origin_server_ts index for time-based queries
  if (!r.index_exists("events_origin_server_ts_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS events_origin_server_ts_idx ON events(origin_server_ts)");
  }
}

// -------------------------------------------------------
// DELTA 55
// -------------------------------------------------------

static void delta_55_v1(SchemaMigrationRunner& r) {
  r.execute(R"(
    CREATE TABLE IF NOT EXISTS applied_schema_deltas (
        version INTEGER NOT NULL,
        file_name TEXT NOT NULL,
        applied_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),
        PRIMARY KEY (version, file_name)
    )
  )");
}

// -------------------------------------------------------
// DELTA 56
// -------------------------------------------------------

static void delta_56_v1_search_table(SchemaMigrationRunner& r) {
  if (!r.table_exists("event_search")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS event_search (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          sender TEXT,
          key TEXT NOT NULL,
          vector TEXT,
          origin_server_ts BIGINT,
          stream_ordering BIGINT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS event_search_event_id_idx ON event_search(event_id)");
    r.execute("CREATE INDEX IF NOT EXISTS event_search_room_idx ON event_search(room_id)");
    r.execute("CREATE INDEX IF NOT EXISTS event_search_key_idx ON event_search(key)");
    r.execute("CREATE INDEX IF NOT EXISTS event_search_stream_ordering_idx ON event_search(stream_ordering)");
  }
}

// -------------------------------------------------------
// DELTA 57
// -------------------------------------------------------

static void delta_57_v1_event_reports(SchemaMigrationRunner& r) {
  if (!r.table_exists("event_reports")) {
    r.execute(R"(
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
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS event_reports_id_idx ON event_reports(id)");
    r.execute("CREATE INDEX IF NOT EXISTS event_reports_event_idx ON event_reports(event_id)");
    r.execute("CREATE INDEX IF NOT EXISTS event_reports_room_idx ON event_reports(room_id)");
    r.execute("CREATE INDEX IF NOT EXISTS event_reports_user_idx ON event_reports(user_id)");
  }
}

static void delta_57_v2_received_ts(SchemaMigrationRunner& r) {
  // Ensure received_ts column in events
  if (!r.column_exists("events", "received_ts")) {
    r.execute("ALTER TABLE events ADD COLUMN received_ts BIGINT");
  }
}

// -------------------------------------------------------
// DELTA 58
// -------------------------------------------------------

static void delta_58_v1_membership_indices(SchemaMigrationRunner& r) {
  if (!r.index_exists("room_memberships_user_member_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS room_memberships_user_member_idx ON room_memberships(user_id, membership)");
  }
  if (!r.index_exists("room_memberships_forgotten_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS room_memberships_forgotten_idx ON room_memberships(user_id, room_id) WHERE forgotten = 1");
  }
}

static void delta_58_v2_event_push_actions(SchemaMigrationRunner& r) {
  if (!r.table_exists("event_push_actions")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS event_push_actions (
          room_id TEXT NOT NULL,
          event_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          profile_tag TEXT,
          actions TEXT NOT NULL,
          topological_ordering BIGINT,
          stream_ordering BIGINT,
          notif SMALLINT,
          highlight SMALLINT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS event_push_actions_room_event_user_idx ON event_push_actions(room_id, event_id, user_id)");
    r.execute("CREATE INDEX IF NOT EXISTS event_push_actions_rm_user_idx ON event_push_actions(room_id, user_id)");
    r.execute("CREATE INDEX IF NOT EXISTS event_push_actions_stream_ordering_idx ON event_push_actions(stream_ordering)");
    r.execute("CREATE INDEX IF NOT EXISTS event_push_actions_highlight_idx ON event_push_actions(user_id, room_id, topological_ordering, stream_ordering)");
  }
}

// -------------------------------------------------------
// DELTA 59
// -------------------------------------------------------

static void delta_59_v1_room_tags(SchemaMigrationRunner& r) {
  if (!r.table_exists("room_tags")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS room_tags (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          tag TEXT NOT NULL,
          content TEXT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS room_tags_user_room_tag_idx ON room_tags(user_id, room_id, tag)");
  }
}

static void delta_59_v2_room_tags_revisions(SchemaMigrationRunner& r) {
  if (!r.table_exists("room_tags_revisions")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS room_tags_revisions (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          stream_id BIGINT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS room_tags_revisions_user_room_idx ON room_tags_revisions(user_id, room_id)");
  }
}

// -------------------------------------------------------
// DELTA 60
// -------------------------------------------------------

static void delta_60_v1_devices_dehydrated(SchemaMigrationRunner& r) {
  // devices table should exist by now but ensure it
  if (r.table_exists("devices") && !r.column_exists("devices", "device_type")) {
    r.execute("ALTER TABLE devices ADD COLUMN device_type TEXT");
  }
}

static void delta_60_v2_event_relations(SchemaMigrationRunner& r) {
  if (!r.table_exists("event_relations")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS event_relations (
          event_id TEXT NOT NULL,
          relates_to_id TEXT NOT NULL,
          relation_type TEXT NOT NULL,
          aggregation_key TEXT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS event_relations_event_id_idx ON event_relations(event_id)");
    r.execute("CREATE INDEX IF NOT EXISTS event_relations_relates_to_idx ON event_relations(relates_to_id)");
    r.execute("CREATE INDEX IF NOT EXISTS event_relations_rel_type_idx ON event_relations(relation_type)");
    r.execute("CREATE INDEX IF NOT EXISTS event_relations_agg_key_idx ON event_relations(relation_type, aggregation_key)");
  }
}

// -------------------------------------------------------
// DELTA 61
// -------------------------------------------------------

static void delta_61_v1_room_stats(SchemaMigrationRunner& r) {
  if (!r.table_exists("room_stats_state")) {
    r.execute(R"(
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
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS room_stats_state_room_idx ON room_stats_state(room_id)");
  }
  if (!r.table_exists("room_stats_current")) {
    r.execute(R"(
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
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS room_stats_current_room_idx ON room_stats_current(room_id)");
  }
  if (!r.table_exists("room_stats_historical")) {
    r.execute(R"(
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
    )");
    r.execute("CREATE INDEX IF NOT EXISTS room_stats_historical_room_ts_idx ON room_stats_historical(room_id, end_ts)");
  }
  if (!r.table_exists("room_stats_earliest_token")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS room_stats_earliest_token (
          room_id TEXT NOT NULL,
          token BIGINT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS room_stats_earliest_token_idx ON room_stats_earliest_token(room_id)");
  }
}

// -------------------------------------------------------
// DELTA 62
// -------------------------------------------------------

static void delta_62_v1_user_directory_stream(SchemaMigrationRunner& r) {
  if (!r.table_exists("user_directory_stream_pos")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS user_directory_stream_pos (
          lock TEXT PRIMARY KEY DEFAULT 'stream_pos_lock',
          stream_id BIGINT NOT NULL DEFAULT 0
      )
    )");
  }
}

static void delta_62_v2_monthly_active_users(SchemaMigrationRunner& r) {
  if (!r.table_exists("monthly_active_users")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS monthly_active_users (
          user_id TEXT NOT NULL,
          timestamp BIGINT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS monthly_active_users_idx ON monthly_active_users(user_id)");
  }
}

// -------------------------------------------------------
// DELTA 63
// -------------------------------------------------------

static void delta_63_v1_device_lists_outbound(SchemaMigrationRunner& r) {
  if (!r.table_exists("device_lists_outbound_pokes")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_outbound_pokes (
          destination TEXT NOT NULL,
          stream_id BIGINT NOT NULL,
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          sent BOOLEAN DEFAULT 0,
          ts BIGINT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS device_lists_outbound_pokes_idx ON device_lists_outbound_pokes(destination, stream_id, user_id)");
    r.execute("CREATE INDEX IF NOT EXISTS device_lists_outbound_pokes_stream_idx ON device_lists_outbound_pokes(stream_id)");
    r.execute("CREATE INDEX IF NOT EXISTS device_lists_outbound_pokes_ts_idx ON device_lists_outbound_pokes(ts)");
  }
}

static void delta_63_v2_device_lists_remote_extremeties(SchemaMigrationRunner& r) {
  if (!r.table_exists("device_lists_remote_extremeties")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_remote_extremeties (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          stream_id TEXT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS device_lists_remote_extremeties_idx ON device_lists_remote_extremeties(user_id, device_id, stream_id)");
  }
}

static void delta_63_v3_device_lists_remote_cache(SchemaMigrationRunner& r) {
  if (!r.table_exists("device_lists_remote_cache")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_remote_cache (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          content TEXT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS device_lists_remote_cache_idx ON device_lists_remote_cache(user_id, device_id)");
  }
}

// -------------------------------------------------------
// DELTA 64
// -------------------------------------------------------

static void delta_64_v1_unread_count_migration(SchemaMigrationRunner& r) {
  // Add unread column to event_push_actions
  if (r.column_exists("event_push_actions", "stream_ordering") &&
      !r.column_exists("event_push_actions", "unread")) {
    r.execute("ALTER TABLE event_push_actions ADD COLUMN unread SMALLINT");
  }
}

static void delta_64_v2_fallback_keys(SchemaMigrationRunner& r) {
  if (!r.table_exists("e2e_fallback_keys_json")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS e2e_fallback_keys_json (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          algorithm TEXT NOT NULL,
          key_id TEXT NOT NULL,
          ts_added_ms BIGINT NOT NULL,
          key_json TEXT NOT NULL,
          used BOOLEAN DEFAULT 0
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS e2e_fallback_keys_json_idx ON e2e_fallback_keys_json(user_id, device_id, algorithm)");
  }
}

// -------------------------------------------------------
// DELTA 65
// -------------------------------------------------------

static void delta_65_v1_event_auth_chains(SchemaMigrationRunner& r) {
  if (!r.table_exists("event_auth_chains")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS event_auth_chains (
          event_id TEXT NOT NULL,
          chain_id BIGINT NOT NULL,
          sequence_number BIGINT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS event_auth_chains_event_id_idx ON event_auth_chains(event_id)");
    r.execute("CREATE INDEX IF NOT EXISTS event_auth_chains_cid_seq_idx ON event_auth_chains(chain_id, sequence_number)");
  }
}

static void delta_65_v2_event_auth_chain_links(SchemaMigrationRunner& r) {
  if (!r.table_exists("event_auth_chain_links")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS event_auth_chain_links (
          origin_chain_id BIGINT NOT NULL,
          origin_sequence_number BIGINT NOT NULL,
          target_chain_id BIGINT NOT NULL,
          target_sequence_number BIGINT NOT NULL
      )
    )");
    r.execute("CREATE INDEX IF NOT EXISTS event_auth_chain_links_origin_idx ON event_auth_chain_links(origin_chain_id, origin_sequence_number)");
    r.execute("CREATE INDEX IF NOT EXISTS event_auth_chain_links_target_idx ON event_auth_chain_links(target_chain_id, target_sequence_number)");
  }
}

static void delta_65_v3_event_auth_chain_to_calculate(SchemaMigrationRunner& r) {
  if (!r.table_exists("event_auth_chain_to_calculate")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS event_auth_chain_to_calculate (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          type TEXT NOT NULL,
          state_key TEXT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS event_auth_chain_to_calc_idx ON event_auth_chain_to_calculate(event_id, type, state_key)");
  }
}

// -------------------------------------------------------
// DELTA 66
// -------------------------------------------------------

static void delta_66_v1_presence_list(SchemaMigrationRunner& r) {
  if (!r.table_exists("presence_list")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS presence_list (
          user_id TEXT NOT NULL,
          observed_user_id TEXT NOT NULL,
          accepted BOOLEAN NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS presence_list_user_observed_idx ON presence_list(user_id, observed_user_id)");
    r.execute("CREATE INDEX IF NOT EXISTS presence_list_observed_idx ON presence_list(observed_user_id)");
  }
}

static void delta_66_v2_presence_allow_inbound(SchemaMigrationRunner& r) {
  if (!r.table_exists("presence_allow_inbound")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS presence_allow_inbound (
          observed_user_id TEXT NOT NULL,
          observer_user_id TEXT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS presence_allow_inbound_idx ON presence_allow_inbound(observed_user_id, observer_user_id)");
  }
}

static void delta_66_v3_currently_active(SchemaMigrationRunner& r) {
  if (r.column_exists("presence_state", "state") &&
      !r.column_exists("presence_state", "currently_active")) {
    r.execute("ALTER TABLE presence_state ADD COLUMN currently_active BOOLEAN DEFAULT 0");
  }
}

// -------------------------------------------------------
// DELTA 67
// -------------------------------------------------------

static void delta_67_v1_e2e_room_keys_version(SchemaMigrationRunner& r) {
  if (r.table_exists("e2e_room_keys") && !r.column_exists("e2e_room_keys", "version")) {
    r.execute("ALTER TABLE e2e_room_keys ADD COLUMN version TEXT NOT NULL DEFAULT '1'");
  }
}

static void delta_67_v2_e2e_room_keys_versions(SchemaMigrationRunner& r) {
  if (!r.table_exists("e2e_room_keys_versions")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS e2e_room_keys_versions (
          user_id TEXT NOT NULL,
          version TEXT NOT NULL,
          algorithm TEXT,
          auth_data TEXT NOT NULL,
          etag TEXT,
          deleted SMALLINT DEFAULT 0
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS e2e_room_keys_versions_idx ON e2e_room_keys_versions(user_id, version)");
  }
}

static void delta_67_v3_cross_signing(SchemaMigrationRunner& r) {
  if (!r.table_exists("e2e_cross_signing_keys")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS e2e_cross_signing_keys (
          user_id TEXT NOT NULL,
          keytype TEXT NOT NULL,
          keydata TEXT NOT NULL,
          stream_id BIGINT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS e2e_cross_signing_keys_idx ON e2e_cross_signing_keys(user_id, keytype)");
  }
  if (!r.table_exists("e2e_cross_signing_signatures")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS e2e_cross_signing_signatures (
          user_id TEXT NOT NULL,
          key_id TEXT NOT NULL,
          target_user_id TEXT NOT NULL,
          target_device_id TEXT NOT NULL,
          signature TEXT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS e2e_cross_signing_signatures_idx ON e2e_cross_signing_signatures(user_id, key_id, target_user_id, target_device_id)");
  }
}

// -------------------------------------------------------
// DELTA 68
// -------------------------------------------------------

static void delta_68_v1_partial_state_rooms(SchemaMigrationRunner& r) {
  if (!r.table_exists("partial_state_rooms")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS partial_state_rooms (
          room_id TEXT NOT NULL,
          joined_via TEXT,
          creation_ts BIGINT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS partial_state_rooms_room_idx ON partial_state_rooms(room_id)");
  }
}

static void delta_68_v2_partial_state_rooms_servers(SchemaMigrationRunner& r) {
  if (!r.table_exists("partial_state_rooms_servers")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS partial_state_rooms_servers (
          room_id TEXT NOT NULL,
          server_name TEXT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS partial_state_rooms_servers_idx ON partial_state_rooms_servers(room_id, server_name)");
  }
}

static void delta_68_v3_partial_state_events(SchemaMigrationRunner& r) {
  if (!r.table_exists("partial_state_events")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS partial_state_events (
          room_id TEXT NOT NULL,
          event_id TEXT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS partial_state_events_room_event_idx ON partial_state_events(room_id, event_id)");
    r.execute("CREATE INDEX IF NOT EXISTS partial_state_events_event_idx ON partial_state_events(event_id)");
  }
}

static void delta_68_v4_device_lists_remote_resync(SchemaMigrationRunner& r) {
  if (!r.table_exists("device_lists_remote_resync")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_remote_resync (
          user_id TEXT NOT NULL,
          added_ts BIGINT NOT NULL,
          origin TEXT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS device_lists_remote_resync_idx ON device_lists_remote_resync(user_id)");
  }
}

static void delta_68_v5_device_lists_changes_in_room(SchemaMigrationRunner& r) {
  if (!r.table_exists("device_lists_changes_in_room")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_changes_in_room (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          stream_id BIGINT NOT NULL,
          converted_to_destinations BOOLEAN DEFAULT 0,
          opentracing_context TEXT
      )
    )");
    r.execute("CREATE INDEX IF NOT EXISTS device_lists_changes_in_room_stream_idx ON device_lists_changes_in_room(stream_id)");
    r.execute("CREATE INDEX IF NOT EXISTS device_lists_changes_in_room_room_idx ON device_lists_changes_in_room(room_id)");
  }
  if (!r.table_exists("device_lists_changes_converted_stream_position")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS device_lists_changes_converted_stream_position (
          lock TEXT PRIMARY KEY DEFAULT 'converted_lock',
          stream_id BIGINT NOT NULL DEFAULT 0
      )
    )");
  }
}

// -------------------------------------------------------
// DELTA 69
// -------------------------------------------------------

static void delta_69_v1_push_rules(SchemaMigrationRunner& r) {
  if (!r.table_exists("push_rules")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS push_rules (
          id BIGINT PRIMARY KEY,
          user_name TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          priority_class SMALLINT NOT NULL,
          priority INTEGER NOT NULL DEFAULT 0,
          conditions TEXT NOT NULL,
          actions TEXT NOT NULL,
          default_rule BOOLEAN NOT NULL DEFAULT 0,
          rule_type TEXT NOT NULL DEFAULT 'override',
          enabled BOOLEAN NOT NULL DEFAULT 1
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS push_rules_user_name_rule_id_idx ON push_rules(user_name, rule_id)");
  }
  if (!r.table_exists("push_rules_enable")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS push_rules_enable (
          id BIGINT PRIMARY KEY,
          user_name TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          enabled SMALLINT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS push_rules_enable_user_rule_idx ON push_rules_enable(user_name, rule_id)");
  }
}

static void delta_69_v2_push_rules_stream(SchemaMigrationRunner& r) {
  if (!r.table_exists("push_rules_stream")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS push_rules_stream (
          stream_id BIGINT PRIMARY KEY,
          user_id TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          op TEXT NOT NULL,
          data TEXT
      )
    )");
    r.execute("CREATE INDEX IF NOT EXISTS push_rules_stream_user_idx ON push_rules_stream(user_id)");
    r.execute("CREATE INDEX IF NOT EXISTS push_rules_stream_stream_idx ON push_rules_stream(stream_id)");
  }
}

static void delta_69_v3_federation_stream_position(SchemaMigrationRunner& r) {
  if (!r.table_exists("federation_stream_position")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS federation_stream_position (
          type TEXT NOT NULL,
          stream_id BIGINT NOT NULL,
          instance_name TEXT NOT NULL DEFAULT 'master'
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS federation_stream_position_type_idx ON federation_stream_position(type, instance_name)");
  }
}

// -------------------------------------------------------
// DELTA 70
// -------------------------------------------------------

static void delta_70_v1_event_labels(SchemaMigrationRunner& r) {
  if (!r.table_exists("event_labels")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS event_labels (
          event_id TEXT NOT NULL,
          label TEXT NOT NULL,
          room_id TEXT NOT NULL,
          topological_ordering BIGINT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS event_labels_event_label_idx ON event_labels(event_id, label)");
    r.execute("CREATE INDEX IF NOT EXISTS event_labels_room_idx ON event_labels(room_id, topological_ordering)");
  }
}

static void delta_70_v2_insertion_events(SchemaMigrationRunner& r) {
  if (!r.table_exists("insertion_events")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS insertion_events (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          next_batch_id TEXT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS insertion_events_event_id_idx ON insertion_events(event_id)");
    r.execute("CREATE INDEX IF NOT EXISTS insertion_events_next_batch_idx ON insertion_events(next_batch_id)");
  }
}

static void delta_70_v3_insertion_event_edges(SchemaMigrationRunner& r) {
  if (!r.table_exists("insertion_event_edges")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS insertion_event_edges (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          insertion_prev_event_id TEXT NOT NULL
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS insertion_event_edges_event_idx ON insertion_event_edges(event_id)");
  }
}

static void delta_70_v4_user_daily_visits(SchemaMigrationRunner& r) {
  if (!r.table_exists("user_daily_visits")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS user_daily_visits (
          user_id TEXT NOT NULL,
          device_id TEXT,
          timestamp BIGINT NOT NULL
      )
    )");
    r.execute("CREATE INDEX IF NOT EXISTS user_daily_visits_uts_idx ON user_daily_visits(user_id, timestamp)");
    r.execute("CREATE INDEX IF NOT EXISTS user_daily_visits_ts_idx ON user_daily_visits(timestamp)");
  }
}

// -------------------------------------------------------
// DELTA 71
// -------------------------------------------------------

static void delta_71_v1_dehydrated_devices(SchemaMigrationRunner& r) {
  if (!r.table_exists("dehydrated_devices")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS dehydrated_devices (
          user_id TEXT NOT NULL,
          device_id TEXT NOT NULL,
          device_data TEXT NOT NULL,
          time_of_rehydration BIGINT,
          creation_ts BIGINT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS dehydrated_devices_user_id_idx ON dehydrated_devices(user_id)");
  }
}

static void delta_71_v2_account_validity(SchemaMigrationRunner& r) {
  if (!r.table_exists("account_validity")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS account_validity (
          user_id TEXT NOT NULL,
          expiration_ts_ms BIGINT NOT NULL,
          email_sent BOOLEAN NOT NULL DEFAULT 0,
          renewal_token TEXT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS account_validity_user_idx ON account_validity(user_id)");
  }
}

static void delta_71_v3_un_partial_stated_rooms(SchemaMigrationRunner& r) {
  if (!r.table_exists("un_partial_stated_rooms_stream")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS un_partial_stated_rooms_stream (
          stream_id BIGINT PRIMARY KEY,
          room_id TEXT NOT NULL,
          successful BOOLEAN NOT NULL
      )
    )");
    r.execute("CREATE INDEX IF NOT EXISTS un_partial_stated_rooms_stream_room_idx ON un_partial_stated_rooms_stream(room_id)");
  }
}

static void delta_71_v4_sliding_sync(SchemaMigrationRunner& r) {
  if (!r.table_exists("sliding_sync_joined_rooms")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS sliding_sync_joined_rooms (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          event_stream_ordering BIGINT NOT NULL,
          bump_stamp BIGINT NOT NULL,
          joined_via TEXT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS sliding_sync_joined_rooms_idx ON sliding_sync_joined_rooms(user_id, room_id)");
    r.execute("CREATE INDEX IF NOT EXISTS sliding_sync_joined_rooms_stream_idx ON sliding_sync_joined_rooms(event_stream_ordering)");
  }
  if (!r.table_exists("sliding_sync_membership_snapshots")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS sliding_sync_membership_snapshots (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          event_id TEXT NOT NULL,
          event_stream_ordering BIGINT NOT NULL,
          membership TEXT NOT NULL,
          sender TEXT NOT NULL,
          has_known_state BOOLEAN DEFAULT 0,
          forgotten BOOLEAN DEFAULT 0
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS sliding_sync_membership_snapshots_idx ON sliding_sync_membership_snapshots(user_id, room_id, event_id)");
    r.execute("CREATE INDEX IF NOT EXISTS sliding_sync_membership_snapshots_stream_idx ON sliding_sync_membership_snapshots(event_stream_ordering)");
  }
}

static void delta_71_v5_profiles(SchemaMigrationRunner& r) {
  if (!r.table_exists("profiles")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS profiles (
          user_id TEXT NOT NULL,
          displayname TEXT,
          avatar_url TEXT,
          presence_status TEXT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS profiles_user_id_idx ON profiles(user_id)");
  }
}

// -------------------------------------------------------
// DELTA 72
// -------------------------------------------------------

static void delta_72_v1_event_push_summary_stream(SchemaMigrationRunner& r) {
  if (!r.table_exists("event_push_summary_stream_ordering")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS event_push_summary_stream_ordering (
          lock TEXT PRIMARY KEY DEFAULT 'stream_ordering_lock',
          stream_ordering BIGINT NOT NULL DEFAULT 0
      )
    )");
  }
}

static void delta_72_v2_threepid_validation_session(SchemaMigrationRunner& r) {
  if (!r.table_exists("threepid_validation_session")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS threepid_validation_session (
          session_id TEXT NOT NULL,
          medium TEXT NOT NULL,
          address TEXT NOT NULL,
          client_secret TEXT NOT NULL,
          validated_at BIGINT,
          last_send_attempt BIGINT,
          attempt_count INTEGER DEFAULT 0
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS threepid_validation_session_id_idx ON threepid_validation_session(session_id)");
  }
}

static void delta_72_v3_registration_tokens(SchemaMigrationRunner& r) {
  if (!r.table_exists("registration_tokens")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS registration_tokens (
          token TEXT NOT NULL,
          uses_allowed INT,
          pending INT NOT NULL,
          completed INT NOT NULL,
          expiry_time BIGINT,
          created_ts BIGINT NOT NULL,
          creator_user TEXT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS registration_tokens_token_idx ON registration_tokens(token)");
  }
}

static void delta_72_v4_thread_subscriptions(SchemaMigrationRunner& r) {
  if (!r.table_exists("thread_subscriptions")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS thread_subscriptions (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          thread_id TEXT NOT NULL,
          subscribed BOOLEAN NOT NULL DEFAULT 1,
          PRIMARY KEY (user_id, room_id, thread_id)
      )
    )");
  }
}

static void delta_72_v5_room_retention(SchemaMigrationRunner& r) {
  if (!r.table_exists("room_retention")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS room_retention (
          room_id TEXT NOT NULL,
          event_id TEXT NOT NULL,
          min_lifetime BIGINT,
          max_lifetime BIGINT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS room_retention_room_idx ON room_retention(room_id)");
  }
}

static void delta_72_v6_event_contains_url(SchemaMigrationRunner& r) {
  // Add contains_url column if it doesn't exist
  if (r.table_exists("events") && !r.column_exists("events", "contains_url")) {
    r.execute("ALTER TABLE events ADD COLUMN contains_url BOOLEAN");
  }
}

static void delta_72_v7_event_instance_name(SchemaMigrationRunner& r) {
  if (r.table_exists("events") && !r.column_exists("events", "instance_name")) {
    r.execute("ALTER TABLE events ADD COLUMN instance_name TEXT");
  }
  if (!r.index_exists("events_instance_name_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS events_instance_name_idx ON events(instance_name)");
  }
}

static void delta_72_v8_contains_url_index(SchemaMigrationRunner& r) {
  // Partial index for events with URLs
  if (!r.index_exists("events_contains_url_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS events_contains_url_idx ON events(room_id, topological_ordering, stream_ordering) WHERE contains_url");
  }
}

static void delta_72_v9_received_transactions(SchemaMigrationRunner& r) {
  if (!r.table_exists("received_transactions")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS received_transactions (
          transaction_id TEXT NOT NULL,
          origin TEXT NOT NULL,
          ts BIGINT NOT NULL,
          response_code INTEGER DEFAULT 0,
          response_json TEXT,
          has_been_referenced SMALLINT DEFAULT 0
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS received_transactions_transaction_id_origin_idx ON received_transactions(transaction_id, origin)");
  }
}

static void delta_72_v10_server_acl(SchemaMigrationRunner& r) {
  if (!r.table_exists("server_acl")) {
    r.execute(R"(
      CREATE TABLE IF NOT EXISTS server_acl (
          room_id TEXT NOT NULL,
          event_id TEXT,
          allow_ip_literals BOOLEAN DEFAULT 0,
          allowed_servers TEXT,
          denied_servers TEXT
      )
    )");
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS server_acl_room_idx ON server_acl(room_id)");
  }
}

// -------------------------------------------------------
// ADDITIONAL INDEX DELTAS (ensured)
// -------------------------------------------------------

static void delta_index_room_depth_index(SchemaMigrationRunner& r) {
  if (!r.index_exists("room_depth_room_idx")) {
    r.execute("CREATE UNIQUE INDEX IF NOT EXISTS room_depth_room_idx ON room_depth(room_id)");
  }
}

static void delta_index_stream_ordering_index(SchemaMigrationRunner& r) {
  if (!r.index_exists("events_stream_ordering_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS events_stream_ordering_idx ON events(stream_ordering)");
  }
}

static void delta_index_topological_ordering_index(SchemaMigrationRunner& r) {
  if (!r.index_exists("events_topological_ordering_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS events_topological_ordering_idx ON events(topological_ordering)");
  }
}

static void delta_index_events_order_room(SchemaMigrationRunner& r) {
  if (!r.index_exists("events_order_room_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS events_order_room_idx ON events(room_id, topological_ordering, stream_ordering)");
  }
}

static void delta_index_state_groups_room(SchemaMigrationRunner& r) {
  if (!r.index_exists("state_groups_room_id_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS state_groups_room_id_idx ON state_groups(room_id)");
  }
}

static void delta_index_current_state_events_membership(SchemaMigrationRunner& r) {
  if (!r.index_exists("current_state_events_membership_idx")) {
    r.execute("CREATE INDEX IF NOT EXISTS current_state_events_membership_idx ON current_state_events(membership)");
  }
}

// ============================================================================
// BACKGROUND UPDATE HANDLERS
// ============================================================================

// populate_events_contains_url - sets contains_url flag on events
static void bg_update_populate_events_contains_url(SchemaMigrationRunner& r) {
  r.execute(R"(
    UPDATE events SET contains_url = 1
    WHERE contains_url IS NULL
    AND (content LIKE '%http://%' OR content LIKE '%https://%'
         OR content LIKE '%mxc://%')
  )");
  r.execute("UPDATE events SET contains_url = 0 WHERE contains_url IS NULL");
  r.complete_background_update("populate_events_contains_url");
}

// populate_monthly_active_users - initial MAU population
static void bg_update_populate_mau(SchemaMigrationRunner& r) {
  r.execute(R"(
    INSERT OR IGNORE INTO monthly_active_users (user_id, timestamp)
    SELECT DISTINCT user_id,
           COALESCE(MAX(origin_server_ts), CAST(strftime('%s','now') AS BIGINT) * 1000)
    FROM (
      SELECT sender AS user_id, origin_server_ts FROM events
      WHERE sender IS NOT NULL
      UNION ALL
      SELECT user_id, NULL FROM presence_state WHERE state != 'offline'
    )
    WHERE user_id IS NOT NULL
    GROUP BY user_id
  )");
  r.complete_background_update("populate_monthly_active_users");
}

// populate_user_directory - initial population from profile data
static void bg_update_populate_user_directory(SchemaMigrationRunner& r) {
  r.execute(R"(
    INSERT OR IGNORE INTO user_directory (user_id, room_id, display_name, avatar_url)
    SELECT DISTINCT rm.user_id, rm.room_id, rm.display_name, rm.avatar_url
    FROM room_memberships rm
    WHERE rm.membership = 'join'
  )");
  r.complete_background_update("populate_user_directory");
}

// populate_device_lists - initial device list population
static void bg_update_populate_device_lists(SchemaMigrationRunner& r) {
  r.execute(R"(
    INSERT OR IGNORE INTO device_lists_stream (stream_id, user_id, device_id)
    SELECT COALESCE((SELECT MAX(stream_id) FROM device_lists_stream), 0) + 1,
           d.user_id, d.device_id
    FROM devices d
    WHERE NOT EXISTS (
      SELECT 1 FROM device_lists_stream dls
      WHERE dls.user_id = d.user_id AND dls.device_id = d.device_id
    )
  )");
  r.complete_background_update("populate_device_lists");
}

// populate_room_stats - initial room stats computation
static void bg_update_populate_room_stats(SchemaMigrationRunner& r) {
  r.execute(R"(
    INSERT OR REPLACE INTO room_stats_current (room_id, joined_members, invited_members,
        banned_members, local_users_in_room, current_state_events)
    SELECT
      rm.room_id,
      COUNT(CASE WHEN rm.membership = 'join' THEN 1 END) AS joined_members,
      COUNT(CASE WHEN rm.membership = 'invite' THEN 1 END) AS invited_members,
      COUNT(CASE WHEN rm.membership = 'ban' THEN 1 END) AS banned_members,
      COUNT(CASE WHEN rm.membership = 'join' AND u.name IS NOT NULL THEN 1 END) AS local_users,
      (SELECT COUNT(*) FROM current_state_events cse WHERE cse.room_id = rm.room_id)
    FROM room_memberships rm
    LEFT JOIN users u ON rm.user_id = u.name
    GROUP BY rm.room_id
  )");
  r.complete_background_update("populate_room_stats");
}

// populate_event_auth_chains - compute initial auth chains
static void bg_update_populate_event_auth_chains(SchemaMigrationRunner& r) {
  // Initialize chain for each event with its own auth events
  // This is a batched background update - the actual per-event computation
  // would be done iteratively in the full implementation
  r.execute(R"(
    INSERT OR IGNORE INTO event_auth_chains (event_id, chain_id, sequence_number)
    SELECT DISTINCT ea.event_id, ea.event_id, 0
    FROM event_auth ea
    WHERE NOT EXISTS (
      SELECT 1 FROM event_auth_chains eac WHERE eac.event_id = ea.event_id
    )
  )");
  r.complete_background_update("populate_event_auth_chains");
}

// populate_push_summary - initial push summary computation
static void bg_update_populate_push_summary(SchemaMigrationRunner& r) {
  r.execute(R"(
    INSERT OR REPLACE INTO event_push_summary (user_id, room_id, notif_count,
        stream_ordering, topological_ordering, unread_count, highlight_count)
    SELECT
      epa.user_id, epa.room_id,
      COUNT(CASE WHEN epa.notif = 1 THEN 1 END) AS notif_count,
      COALESCE(MAX(epa.stream_ordering), 0) AS stream_ordering,
      COALESCE(MAX(epa.topological_ordering), 0) AS topological_ordering,
      COUNT(CASE WHEN epa.unread = 1 THEN 1 END) AS unread_count,
      COUNT(CASE WHEN epa.highlight = 1 THEN 1 END) AS highlight_count
    FROM event_push_actions epa
    GROUP BY epa.user_id, epa.room_id
  )");
  r.complete_background_update("populate_push_summary");
}

// populate_profiles - initial profile population from users
static void bg_update_populate_profiles(SchemaMigrationRunner& r) {
  r.execute(R"(
    INSERT OR IGNORE INTO profiles (user_id, displayname, avatar_url)
    SELECT name, NULL, NULL FROM users
    WHERE NOT EXISTS (SELECT 1 FROM profiles p WHERE p.user_id = users.name)
  )");
  r.complete_background_update("populate_profiles");
}

// populate_presence_stream - backfill presence stream
static void bg_update_populate_presence_stream(SchemaMigrationRunner& r) {
  r.execute(R"(
    INSERT INTO presence_stream (stream_id, user_id, state, last_active_ts,
        last_federation_update_ts, last_user_sync_ts, currently_active, status_msg)
    SELECT
      COALESCE((SELECT MAX(stream_id) FROM presence_stream), 0) +
      ROW_NUMBER() OVER (ORDER BY ps.user_id),
      ps.user_id, ps.state, ps.last_active_ts,
      ps.last_federation_update_ts, ps.last_user_sync_ts,
      ps.currently_active, ps.status_msg
    FROM presence_state ps
    WHERE NOT EXISTS (
      SELECT 1 FROM presence_stream ps2 WHERE ps2.user_id = ps.user_id
    )
  )");
  r.complete_background_update("populate_presence_stream");
}

// populate_sliding_sync_joined_rooms - backfill sliding sync from room memberships
static void bg_update_populate_sliding_sync(SchemaMigrationRunner& r) {
  r.execute(R"(
    INSERT OR IGNORE INTO sliding_sync_joined_rooms (user_id, room_id,
        event_stream_ordering, bump_stamp, joined_via)
    SELECT
      rm.user_id, rm.room_id,
      COALESCE(rm.event_stream_ordering, 0),
      COALESCE((SELECT MAX(e.origin_server_ts) FROM events e
                WHERE e.room_id = rm.room_id
                AND e.type IN ('m.room.message', 'm.room.encrypted')),
               0),
      NULL
    FROM room_memberships rm
    WHERE rm.membership = 'join'
      AND NOT EXISTS (
        SELECT 1 FROM sliding_sync_joined_rooms ss
        WHERE ss.user_id = rm.user_id AND ss.room_id = rm.room_id
      )
  )");
  r.complete_background_update("populate_sliding_sync_joined_rooms");
}

// populate_federation_stream_positions - initialize federation position
static void bg_update_populate_federation_positions(SchemaMigrationRunner& r) {
  r.execute(R"(
    INSERT OR IGNORE INTO federation_stream_position (type, stream_id, instance_name)
    SELECT 'events', COALESCE(MAX(stream_ordering), 0), 'master'
    FROM events
    UNION ALL
    SELECT 'devices', COALESCE(MAX(stream_id), 0), 'master'
    FROM device_lists_stream
    UNION ALL
    SELECT 'to_device', COALESCE(MAX(stream_id), 0), 'master'
    FROM device_inbox
    UNION ALL
    SELECT 'presence', COALESCE(MAX(stream_id), 0), 'master'
    FROM presence_stream
    UNION ALL
    SELECT 'receipts', COALESCE(MAX(stream_id), 0), 'master'
    FROM receipts_linearized
  )");
  r.complete_background_update("populate_federation_stream_positions");
}

// ============================================================================
// Collect ALL deltas in order
// ============================================================================
std::vector<SchemaDelta> SchemaMigrationRunner::collect_all_deltas() {
  std::vector<SchemaDelta> deltas;

  // ---- Version 54 (initial) ----
  deltas.push_back({54, 1, "content_index", "Add content index on events", delta_54_v1_content_index, false});
  deltas.push_back({54, 2, "topological_index", "Add topological ordering index", delta_54_v2_topological_index, false});
  deltas.push_back({54, 3, "origin_server_ts_index", "Add origin_server_ts index", delta_54_v3_origin_server_ts_index, false});

  // ---- Version 55 ----
  deltas.push_back({55, 1, "applied_schema_deltas", "Add applied_schema_deltas tracking table", delta_55_v1, false});

  // ---- Version 56 ----
  deltas.push_back({56, 1, "event_search", "Add event_search table for full-text search", delta_56_v1_search_table, false});

  // ---- Version 57 ----
  deltas.push_back({57, 1, "event_reports", "Add event_reports table", delta_57_v1_event_reports, false});
  deltas.push_back({57, 2, "events_received_ts", "Add received_ts to events", delta_57_v2_received_ts, false});

  // ---- Version 58 ----
  deltas.push_back({58, 1, "membership_indices", "Add membership query indices", delta_58_v1_membership_indices, false});
  deltas.push_back({58, 2, "event_push_actions", "Add event_push_actions table", delta_58_v2_event_push_actions, false});

  // ---- Version 59 ----
  deltas.push_back({59, 1, "room_tags", "Add room_tags table", delta_59_v1_room_tags, false});
  deltas.push_back({59, 2, "room_tags_revisions", "Add room_tags_revisions table", delta_59_v2_room_tags_revisions, false});

  // ---- Version 60 ----
  deltas.push_back({60, 1, "devices_dehydrated", "Add device_type to devices", delta_60_v1_devices_dehydrated, false});
  deltas.push_back({60, 2, "event_relations", "Add event_relations table", delta_60_v2_event_relations, false});

  // ---- Version 61 ----
  deltas.push_back({61, 1, "room_stats", "Add room_stats tables", delta_61_v1_room_stats, false});

  // ---- Version 62 ----
  deltas.push_back({62, 1, "user_directory_stream", "Add user_directory stream pos", delta_62_v1_user_directory_stream, false});
  deltas.push_back({62, 2, "monthly_active_users", "Add monthly_active_users table", delta_62_v2_monthly_active_users, false});

  // ---- Version 63 ----
  deltas.push_back({63, 1, "device_lists_outbound", "Add device_lists_outbound_pokes", delta_63_v1_device_lists_outbound, false});
  deltas.push_back({63, 2, "device_lists_remote_extremeties", "Add device_lists_remote_extremeties", delta_63_v2_device_lists_remote_extremeties, false});
  deltas.push_back({63, 3, "device_lists_remote_cache", "Add device_lists_remote_cache", delta_63_v3_device_lists_remote_cache, false});

  // ---- Version 64 ----
  deltas.push_back({64, 1, "unread_count", "Add unread column to push actions", delta_64_v1_unread_count_migration, false});
  deltas.push_back({64, 2, "fallback_keys", "Add e2e_fallback_keys_json", delta_64_v2_fallback_keys, false});

  // ---- Version 65 ----
  deltas.push_back({65, 1, "event_auth_chains", "Add event_auth_chains table", delta_65_v1_event_auth_chains, false});
  deltas.push_back({65, 2, "event_auth_chain_links", "Add event_auth_chain_links", delta_65_v2_event_auth_chain_links, false});
  deltas.push_back({65, 3, "event_auth_chain_to_calculate", "Add event_auth_chain_to_calculate", delta_65_v3_event_auth_chain_to_calculate, false});

  // ---- Version 66 ----
  deltas.push_back({66, 1, "presence_list", "Add presence_list table", delta_66_v1_presence_list, false});
  deltas.push_back({66, 2, "presence_allow_inbound", "Add presence_allow_inbound", delta_66_v2_presence_allow_inbound, false});
  deltas.push_back({66, 3, "currently_active", "Add currently_active to presence", delta_66_v3_currently_active, false});

  // ---- Version 67 ----
  deltas.push_back({67, 1, "e2e_room_keys_version", "Add version to e2e_room_keys", delta_67_v1_e2e_room_keys_version, false});
  deltas.push_back({67, 2, "e2e_room_keys_versions", "Add e2e_room_keys_versions", delta_67_v2_e2e_room_keys_versions, false});
  deltas.push_back({67, 3, "cross_signing", "Add cross-signing tables", delta_67_v3_cross_signing, false});

  // ---- Version 68 ----
  deltas.push_back({68, 1, "partial_state_rooms", "Add partial_state_rooms", delta_68_v1_partial_state_rooms, false});
  deltas.push_back({68, 2, "partial_state_rooms_servers", "Add partial_state_rooms_servers", delta_68_v2_partial_state_rooms_servers, false});
  deltas.push_back({68, 3, "partial_state_events", "Add partial_state_events", delta_68_v3_partial_state_events, false});
  deltas.push_back({68, 4, "device_lists_remote_resync", "Add device_lists_remote_resync", delta_68_v4_device_lists_remote_resync, false});
  deltas.push_back({68, 5, "device_lists_changes_in_room", "Add device_lists_changes_in_room", delta_68_v5_device_lists_changes_in_room, false});

  // ---- Version 69 ----
  deltas.push_back({69, 1, "push_rules", "Add push_rules tables", delta_69_v1_push_rules, false});
  deltas.push_back({69, 2, "push_rules_stream", "Add push_rules_stream", delta_69_v2_push_rules_stream, false});
  deltas.push_back({69, 3, "federation_stream_position", "Add federation_stream_position", delta_69_v3_federation_stream_position, false});

  // ---- Version 70 ----
  deltas.push_back({70, 1, "event_labels", "Add event_labels table", delta_70_v1_event_labels, false});
  deltas.push_back({70, 2, "insertion_events", "Add insertion_events", delta_70_v2_insertion_events, false});
  deltas.push_back({70, 3, "insertion_event_edges", "Add insertion_event_edges", delta_70_v3_insertion_event_edges, false});
  deltas.push_back({70, 4, "user_daily_visits", "Add user_daily_visits", delta_70_v4_user_daily_visits, false});

  // ---- Version 71 ----
  deltas.push_back({71, 1, "dehydrated_devices", "Add dehydrated_devices", delta_71_v1_dehydrated_devices, false});
  deltas.push_back({71, 2, "account_validity", "Add account_validity", delta_71_v2_account_validity, false});
  deltas.push_back({71, 3, "un_partial_stated_rooms", "Add unpartial stream", delta_71_v3_un_partial_stated_rooms, false});
  deltas.push_back({71, 4, "sliding_sync", "Add sliding sync tables", delta_71_v4_sliding_sync, false});
  deltas.push_back({71, 5, "profiles", "Add profiles table", delta_71_v5_profiles, false});

  // ---- Version 72 ----
  deltas.push_back({72, 1, "push_summary_stream", "Add event_push_summary_stream_ordering", delta_72_v1_event_push_summary_stream, false});
  deltas.push_back({72, 2, "threepid_validation_session", "Add threepid_validation_session", delta_72_v2_threepid_validation_session, false});
  deltas.push_back({72, 3, "registration_tokens", "Add registration_tokens", delta_72_v3_registration_tokens, false});
  deltas.push_back({72, 4, "thread_subscriptions", "Add thread_subscriptions", delta_72_v4_thread_subscriptions, false});
  deltas.push_back({72, 5, "room_retention", "Add room_retention", delta_72_v5_room_retention, false});
  deltas.push_back({72, 6, "contains_url", "Add contains_url column", delta_72_v6_event_contains_url, false});
  deltas.push_back({72, 7, "instance_name", "Add instance_name column", delta_72_v7_event_instance_name, false});
  deltas.push_back({72, 8, "contains_url_index", "Add contains_url partial index", delta_72_v8_contains_url_index, false});
  deltas.push_back({72, 9, "received_transactions", "Add received_transactions", delta_72_v9_received_transactions, false});
  deltas.push_back({72, 10, "server_acl", "Add server_acl table", delta_72_v10_server_acl, false});

  // ---- Index safety deltas ----
  deltas.push_back({72, 11, "room_depth_index", "Ensure room_depth index", delta_index_room_depth_index, false});
  deltas.push_back({72, 12, "stream_ordering_index", "Ensure stream_ordering index", delta_index_stream_ordering_index, false});
  deltas.push_back({72, 13, "topological_ordering_index", "Ensure topological index", delta_index_topological_ordering_index, false});
  deltas.push_back({72, 14, "events_order_room_idx", "Ensure events ordering index", delta_index_events_order_room, false});
  deltas.push_back({72, 15, "state_groups_room_idx", "Ensure state_groups room index", delta_index_state_groups_room, false});
  deltas.push_back({72, 16, "current_state_membership_idx", "Ensure membership index", delta_index_current_state_events_membership, false});

  // ---- Background update registrations (not instant deltas) ----
  deltas.push_back({72, 100, "bg_populate_contains_url",
      "Populate events.contains_url", nullptr, true, ""});
  deltas.push_back({72, 101, "bg_populate_mau",
      "Populate monthly_active_users", nullptr, true, ""});
  deltas.push_back({72, 102, "bg_populate_user_directory",
      "Populate user_directory", nullptr, true, ""});
  deltas.push_back({72, 103, "bg_populate_device_lists",
      "Populate device lists stream", nullptr, true, ""});
  deltas.push_back({72, 104, "bg_populate_room_stats",
      "Populate room stats", nullptr, true, ""});
  deltas.push_back({72, 105, "bg_populate_event_auth_chains",
      "Populate event auth chains", nullptr, true, ""});
  deltas.push_back({72, 106, "bg_populate_push_summary",
      "Populate push summary", nullptr, true, ""});
  deltas.push_back({72, 107, "bg_populate_profiles",
      "Populate profiles", nullptr, true, ""});
  deltas.push_back({72, 108, "bg_populate_presence_stream",
      "Populate presence stream", nullptr, true, ""});
  deltas.push_back({72, 109, "bg_populate_sliding_sync",
      "Populate sliding sync joined rooms", nullptr, true, ""});
  deltas.push_back({72, 110, "bg_populate_federation_positions",
      "Populate federation stream positions", nullptr, true, ""});

  return deltas;
}

// ============================================================================
// Top-level public API
// ============================================================================

// Run all schema migrations on a database
void run_schema_migrations(
    std::function<void(const std::string&)> execute_fn,
    std::function<std::vector<std::map<std::string, std::string>>(const std::string&)> query_fn,
    int target_version) {

  SchemaMigrationRunner runner(std::move(execute_fn), std::move(query_fn));

  // Register all background update handlers
  runner.register_background_handler("bg_populate_contains_url", bg_update_populate_events_contains_url);
  runner.register_background_handler("bg_populate_mau", bg_update_populate_mau);
  runner.register_background_handler("bg_populate_user_directory", bg_update_populate_user_directory);
  runner.register_background_handler("bg_populate_device_lists", bg_update_populate_device_lists);
  runner.register_background_handler("bg_populate_room_stats", bg_update_populate_room_stats);
  runner.register_background_handler("bg_populate_event_auth_chains", bg_update_populate_event_auth_chains);
  runner.register_background_handler("bg_populate_push_summary", bg_update_populate_push_summary);
  runner.register_background_handler("bg_populate_profiles", bg_update_populate_profiles);
  runner.register_background_handler("bg_populate_presence_stream", bg_update_populate_presence_stream);
  runner.register_background_handler("bg_populate_sliding_sync", bg_update_populate_sliding_sync);
  runner.register_background_handler("bg_populate_federation_positions", bg_update_populate_federation_positions);

  runner.upgrade(target_version);
}

// Get full schema 72 SQL for bootstrapping
std::string get_full_schema_sql() {
  std::stringstream ss;

  // Schema tracking
  ss << "CREATE TABLE IF NOT EXISTS schema_version ("
     << "version INTEGER NOT NULL, delta_number INTEGER NOT NULL DEFAULT 0,"
     << "upgraded BOOLEAN NOT NULL DEFAULT 1,"
     << "upgraded_by TEXT NOT NULL DEFAULT 'progressive-server',"
     << "applied_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),"
     << "compat_version TEXT NOT NULL DEFAULT '1',"
     << "PRIMARY KEY (version, delta_number));\n";

  ss << "CREATE TABLE IF NOT EXISTS schema_compat_version ("
     << "lock TEXT PRIMARY KEY DEFAULT 'compat_version_lock',"
     << "compat_version INTEGER NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS background_updates ("
     << "update_name TEXT NOT NULL, progress_json TEXT NOT NULL DEFAULT '{}',"
     << "depends_on TEXT, ordering INTEGER NOT NULL DEFAULT 0,"
     << "batch_size INTEGER DEFAULT 100, min_replication_depth INTEGER DEFAULT 0,"
     << "run_as_background_process BOOLEAN DEFAULT 0, inserted_ts BIGINT NOT NULL,"
     << "PRIMARY KEY (update_name));\n";

  ss << "CREATE TABLE IF NOT EXISTS users ("
     << "name TEXT NOT NULL, password_hash TEXT, creation_ts BIGINT NOT NULL,"
     << "admin SMALLINT DEFAULT 0 NOT NULL, upgrade_ts BIGINT,"
     << "is_guest SMALLINT DEFAULT 0 NOT NULL, appservice_id TEXT,"
     << "consent_version TEXT, consent_server_notice_sent TEXT,"
     << "user_type TEXT, deactivated SMALLINT DEFAULT 0 NOT NULL,"
     << "shadow_banned BOOLEAN DEFAULT 0, suspended BOOLEAN DEFAULT 0,"
     << "approved BOOLEAN DEFAULT 1, locked BOOLEAN DEFAULT 0);\n";
  ss << "CREATE UNIQUE INDEX IF NOT EXISTS users_name_idx ON users(name);\n";

  ss << "CREATE TABLE IF NOT EXISTS access_tokens ("
     << "id BIGINT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT,"
     << "token TEXT NOT NULL, valid_until_ms BIGINT, puppets_user_id TEXT,"
     << "last_validated BIGINT, refresh_token_id BIGINT, used BOOLEAN,"
     << "token_owner TEXT NOT NULL DEFAULT 'user', token_type TEXT DEFAULT 'personal');\n";
  ss << "CREATE UNIQUE INDEX IF NOT EXISTS access_tokens_token_idx ON access_tokens(token);\n";
  ss << "CREATE INDEX IF NOT EXISTS access_tokens_user_id_idx ON access_tokens(user_id);\n";

  ss << "CREATE TABLE IF NOT EXISTS devices ("
     << "user_id TEXT NOT NULL, device_id TEXT NOT NULL, display_name TEXT,"
     << "device_type TEXT, hidden BOOLEAN DEFAULT 0, last_seen BIGINT,"
     << "ip TEXT, user_agent TEXT, session_id BIGINT,"
     << "CONSTRAINT device_uniqueness UNIQUE (user_id, device_id));\n";

  ss << "CREATE TABLE IF NOT EXISTS e2e_device_keys_json ("
     << "user_id TEXT NOT NULL, device_id TEXT NOT NULL,"
     << "ts_added_ms BIGINT NOT NULL, key_json TEXT NOT NULL);\n";
  ss << "CREATE UNIQUE INDEX IF NOT EXISTS e2e_device_keys_json_idx ON e2e_device_keys_json(user_id, device_id);\n";

  ss << "CREATE TABLE IF NOT EXISTS e2e_one_time_keys_json ("
     << "user_id TEXT NOT NULL, device_id TEXT NOT NULL,"
     << "algorithm TEXT NOT NULL, key_id TEXT NOT NULL,"
     << "ts_added_ms BIGINT NOT NULL, key_json TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS e2e_room_keys ("
     << "user_id TEXT NOT NULL, room_id TEXT NOT NULL, session_id TEXT NOT NULL,"
     << "version TEXT NOT NULL, first_message_index INT, forwarded_count INT,"
     << "is_verified BOOLEAN, session_data TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS e2e_room_keys_versions ("
     << "user_id TEXT NOT NULL, version TEXT NOT NULL, algorithm TEXT,"
     << "auth_data TEXT NOT NULL, etag TEXT, deleted SMALLINT DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS events ("
     << "stream_ordering BIGINT NOT NULL, topological_ordering BIGINT NOT NULL,"
     << "event_id TEXT NOT NULL, type TEXT NOT NULL, room_id TEXT NOT NULL,"
     << "content TEXT, unrecognized_keys TEXT, processed BOOLEAN NOT NULL DEFAULT 1,"
     << "outlier BOOLEAN NOT NULL DEFAULT 0, origin_server_ts BIGINT,"
     << "received_ts BIGINT, sender TEXT NOT NULL, contains_url BOOLEAN,"
     << "instance_name TEXT, state_key TEXT, depth BIGINT NOT NULL DEFAULT 0,"
     << "rejection_reason TEXT);\n";
  ss << "CREATE UNIQUE INDEX IF NOT EXISTS events_event_id_idx ON events(event_id);\n";
  ss << "CREATE INDEX IF NOT EXISTS events_stream_ordering_idx ON events(stream_ordering);\n";
  ss << "CREATE INDEX IF NOT EXISTS events_room_id_idx ON events(room_id);\n";
  ss << "CREATE INDEX IF NOT EXISTS events_order_room_idx ON events(room_id, topological_ordering, stream_ordering);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_json ("
     << "event_id TEXT NOT NULL, room_id TEXT NOT NULL,"
     << "internal_metadata TEXT NOT NULL, json TEXT NOT NULL,"
     << "format_version INTEGER);\n";
  ss << "CREATE UNIQUE INDEX IF NOT EXISTS event_json_event_id_idx ON event_json(event_id);\n";

  ss << "CREATE TABLE IF NOT EXISTS state_events ("
     << "event_id TEXT NOT NULL, room_id TEXT NOT NULL, type TEXT NOT NULL,"
     << "state_key TEXT NOT NULL, topological_ordering BIGINT NOT NULL,"
     << "stream_ordering BIGINT NOT NULL, prev_state TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS current_state_events ("
     << "event_id TEXT NOT NULL, room_id TEXT NOT NULL, type TEXT NOT NULL,"
     << "state_key TEXT NOT NULL, membership TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS state_groups ("
     << "id BIGINT NOT NULL, room_id TEXT NOT NULL, event_id TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS state_groups_state ("
     << "state_group BIGINT NOT NULL, room_id TEXT NOT NULL,"
     << "type TEXT NOT NULL, state_key TEXT NOT NULL, event_id TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS state_group_edges ("
     << "state_group BIGINT NOT NULL, prev_state_group BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS rooms ("
     << "room_id TEXT NOT NULL, is_public BOOLEAN, is_encrypted BOOLEAN DEFAULT 0,"
     << "creator TEXT, room_version TEXT, has_auth_chain_index BOOLEAN DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS room_memberships ("
     << "event_id TEXT NOT NULL, event_stream_ordering BIGINT NOT NULL,"
     << "user_id TEXT NOT NULL, sender TEXT NOT NULL, room_id TEXT NOT NULL,"
     << "membership TEXT NOT NULL, display_name TEXT, avatar_url TEXT,"
     << "forgotten BOOLEAN DEFAULT 0, knock_state TEXT, knock_reason TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS room_aliases ("
     << "room_alias TEXT NOT NULL, room_id TEXT NOT NULL, creator TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS room_tags ("
     << "user_id TEXT NOT NULL, room_id TEXT NOT NULL, tag TEXT NOT NULL, content TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS room_account_data ("
     << "user_id TEXT NOT NULL, room_id TEXT NOT NULL, account_data_type TEXT NOT NULL,"
     << "stream_id BIGINT NOT NULL, content TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS room_stats_state ("
     << "room_id TEXT NOT NULL, bucket_desc TEXT, joined_members INT,"
     << "invited_members INT, banned_members INT, local_users_in_room INT,"
     << "current_state_events INT, completed_delta_stream_id BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS room_stats_current ("
     << "room_id TEXT NOT NULL, bucket_desc TEXT, joined_members INT,"
     << "invited_members INT, banned_members INT, local_users_in_room INT,"
     << "current_state_events INT, completed_delta_stream_id BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS room_stats_historical ("
     << "room_id TEXT NOT NULL, bucket_desc TEXT, joined_members INT,"
     << "invited_members INT, banned_members INT, local_users_in_room INT,"
     << "current_state_events INT, end_ts BIGINT NOT NULL, total_event_bytes BIGINT DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS room_depth ("
     << "room_id TEXT NOT NULL, min_depth BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_edges ("
     << "event_id TEXT NOT NULL, prev_event_id TEXT NOT NULL,"
     << "room_id TEXT NOT NULL, is_state BOOLEAN NOT NULL DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_auth ("
     << "event_id TEXT NOT NULL, auth_id TEXT NOT NULL, room_id TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_forward_extremities ("
     << "event_id TEXT NOT NULL, room_id TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_backward_extremities ("
     << "event_id TEXT NOT NULL, room_id TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_to_state_groups ("
     << "event_id TEXT NOT NULL, state_group BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS redactions ("
     << "event_id TEXT NOT NULL, redacts TEXT NOT NULL,"
     << "have_censored BOOLEAN NOT NULL DEFAULT 0, received_ts BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS rejections ("
     << "event_id TEXT NOT NULL, reason TEXT NOT NULL, last_check TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_relations ("
     << "event_id TEXT NOT NULL, relates_to_id TEXT NOT NULL,"
     << "relation_type TEXT NOT NULL, aggregation_key TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_auth_chains ("
     << "event_id TEXT NOT NULL, chain_id BIGINT NOT NULL, sequence_number BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_auth_chain_links ("
     << "origin_chain_id BIGINT NOT NULL, origin_sequence_number BIGINT NOT NULL,"
     << "target_chain_id BIGINT NOT NULL, target_sequence_number BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_auth_chain_to_calculate ("
     << "event_id TEXT NOT NULL, room_id TEXT NOT NULL,"
     << "type TEXT NOT NULL, state_key TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS presence_state ("
     << "user_id TEXT NOT NULL, state TEXT DEFAULT 'offline', status_msg TEXT,"
     << "last_active_ts BIGINT, last_federation_update_ts BIGINT,"
     << "last_user_sync_ts BIGINT, currently_active BOOLEAN DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS presence_stream ("
     << "stream_id BIGINT NOT NULL, user_id TEXT NOT NULL, state TEXT,"
     << "last_active_ts BIGINT, last_federation_update_ts BIGINT,"
     << "last_user_sync_ts BIGINT, currently_active BOOLEAN, status_msg TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS presence_list ("
     << "user_id TEXT NOT NULL, observed_user_id TEXT NOT NULL, accepted BOOLEAN NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS presence_allow_inbound ("
     << "observed_user_id TEXT NOT NULL, observer_user_id TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS receipts_graph ("
     << "room_id TEXT NOT NULL, receipt_type TEXT NOT NULL, user_id TEXT NOT NULL,"
     << "event_ids TEXT NOT NULL, thread_id TEXT, data TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS receipts_linearized ("
     << "stream_id BIGINT NOT NULL, room_id TEXT NOT NULL, receipt_type TEXT NOT NULL,"
     << "user_id TEXT NOT NULL, event_id TEXT NOT NULL, thread_id TEXT, data TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS user_threepids ("
     << "user_id TEXT NOT NULL, medium TEXT NOT NULL, address TEXT NOT NULL,"
     << "validated_at BIGINT NOT NULL, added_at BIGINT NOT NULL,"
     << "validated BOOLEAN DEFAULT 0, bound_ts BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS threepid_guest_access_tokens ("
     << "medium TEXT NOT NULL, address TEXT NOT NULL,"
     << "guest_access_token TEXT NOT NULL, first_inviter TEXT, expires_at BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS threepid_validation_session ("
     << "session_id TEXT NOT NULL, medium TEXT NOT NULL, address TEXT NOT NULL,"
     << "client_secret TEXT NOT NULL, validated_at BIGINT,"
     << "last_send_attempt BIGINT, attempt_count INTEGER DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS dehydrated_devices ("
     << "user_id TEXT NOT NULL, device_id TEXT NOT NULL, device_data TEXT NOT NULL,"
     << "time_of_rehydration BIGINT, creation_ts BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS account_validity ("
     << "user_id TEXT NOT NULL, expiration_ts_ms BIGINT NOT NULL,"
     << "email_sent BOOLEAN NOT NULL DEFAULT 0, renewal_token TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS pushers ("
     << "id BIGINT PRIMARY KEY, user_name TEXT NOT NULL, access_token BIGINT,"
     << "profile_tag TEXT NOT NULL, kind TEXT NOT NULL, app_id TEXT NOT NULL,"
     << "app_display_name TEXT NOT NULL, device_display_name TEXT,"
     << "pushkey TEXT NOT NULL, ts BIGINT NOT NULL, lang TEXT, data TEXT,"
     << "last_stream_ordering INTEGER, last_success BIGINT, failing_since BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS push_rules ("
     << "id BIGINT PRIMARY KEY, user_name TEXT NOT NULL, rule_id TEXT NOT NULL,"
     << "priority_class SMALLINT NOT NULL, priority INTEGER NOT NULL DEFAULT 0,"
     << "conditions TEXT NOT NULL, actions TEXT NOT NULL,"
     << "default_rule BOOLEAN NOT NULL DEFAULT 0,"
     << "rule_type TEXT NOT NULL DEFAULT 'override', enabled BOOLEAN NOT NULL DEFAULT 1);\n";

  ss << "CREATE TABLE IF NOT EXISTS push_rules_enable ("
     << "id BIGINT PRIMARY KEY, user_name TEXT NOT NULL, rule_id TEXT NOT NULL, enabled SMALLINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS push_rules_stream ("
     << "stream_id BIGINT PRIMARY KEY, user_id TEXT NOT NULL,"
     << "rule_id TEXT NOT NULL, op TEXT NOT NULL, data TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS federation_stream_position ("
     << "type TEXT NOT NULL, stream_id BIGINT NOT NULL, instance_name TEXT NOT NULL DEFAULT 'master');\n";

  ss << "CREATE TABLE IF NOT EXISTS destination_rooms ("
     << "destination TEXT NOT NULL, room_id TEXT NOT NULL, stream_ordering BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS received_transactions ("
     << "transaction_id TEXT NOT NULL, origin TEXT NOT NULL, ts BIGINT NOT NULL,"
     << "response_code INTEGER DEFAULT 0, response_json TEXT, has_been_referenced SMALLINT DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS background_updates ("
     << "update_name TEXT NOT NULL, progress_json TEXT NOT NULL DEFAULT '{}',"
     << "depends_on TEXT, ordering INTEGER NOT NULL DEFAULT 0,"
     << "inserted_ts BIGINT NOT NULL, PRIMARY KEY (update_name));\n";

  ss << "CREATE TABLE IF NOT EXISTS event_push_actions ("
     << "room_id TEXT NOT NULL, event_id TEXT NOT NULL, user_id TEXT NOT NULL,"
     << "profile_tag TEXT, actions TEXT NOT NULL, topological_ordering BIGINT,"
     << "stream_ordering BIGINT, notif SMALLINT, highlight SMALLINT, unread SMALLINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_push_summary ("
     << "user_id TEXT NOT NULL, room_id TEXT NOT NULL, notif_count BIGINT NOT NULL,"
     << "stream_ordering BIGINT NOT NULL, topological_ordering BIGINT NOT NULL,"
     << "unread_count BIGINT, highlight_count BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_push_summary_stream_ordering ("
     << "lock TEXT PRIMARY KEY DEFAULT 'stream_ordering_lock',"
     << "stream_ordering BIGINT NOT NULL DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_search ("
     << "event_id TEXT NOT NULL, room_id TEXT NOT NULL, sender TEXT,"
     << "key TEXT NOT NULL, vector TEXT, origin_server_ts BIGINT, stream_ordering BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_reports ("
     << "id BIGINT NOT NULL, received_ts BIGINT NOT NULL, room_id TEXT NOT NULL,"
     << "event_id TEXT NOT NULL, user_id TEXT NOT NULL, reason TEXT,"
     << "content TEXT, score BIGINT DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_labels ("
     << "event_id TEXT NOT NULL, label TEXT NOT NULL, room_id TEXT NOT NULL,"
     << "topological_ordering BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_txn_id ("
     << "event_id TEXT NOT NULL, room_id TEXT NOT NULL, user_id TEXT NOT NULL,"
     << "txn_id TEXT NOT NULL, inserted_ts BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS device_lists_stream ("
     << "stream_id BIGINT NOT NULL, user_id TEXT NOT NULL, device_id TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS device_lists_outbound_pokes ("
     << "destination TEXT NOT NULL, stream_id BIGINT NOT NULL, user_id TEXT NOT NULL,"
     << "device_id TEXT NOT NULL, sent BOOLEAN DEFAULT 0, ts BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS device_lists_remote_extremeties ("
     << "user_id TEXT NOT NULL, device_id TEXT NOT NULL, stream_id TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS device_lists_remote_cache ("
     << "user_id TEXT NOT NULL, device_id TEXT NOT NULL, content TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS device_lists_remote_resync ("
     << "user_id TEXT NOT NULL, added_ts BIGINT NOT NULL, origin TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS device_lists_changes_in_room ("
     << "user_id TEXT NOT NULL, device_id TEXT NOT NULL, room_id TEXT NOT NULL,"
     << "stream_id BIGINT NOT NULL, converted_to_destinations BOOLEAN DEFAULT 0,"
     << "opentracing_context TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS partial_state_rooms ("
     << "room_id TEXT NOT NULL, joined_via TEXT, creation_ts BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS partial_state_rooms_servers ("
     << "room_id TEXT NOT NULL, server_name TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS partial_state_events ("
     << "room_id TEXT NOT NULL, event_id TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS un_partial_stated_rooms_stream ("
     << "stream_id BIGINT PRIMARY KEY, room_id TEXT NOT NULL, successful BOOLEAN NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS sliding_sync_joined_rooms ("
     << "user_id TEXT NOT NULL, room_id TEXT NOT NULL,"
     << "event_stream_ordering BIGINT NOT NULL, bump_stamp BIGINT NOT NULL, joined_via TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS sliding_sync_membership_snapshots ("
     << "user_id TEXT NOT NULL, room_id TEXT NOT NULL, event_id TEXT NOT NULL,"
     << "event_stream_ordering BIGINT NOT NULL, membership TEXT NOT NULL,"
     << "sender TEXT NOT NULL, has_known_state BOOLEAN DEFAULT 0, forgotten BOOLEAN DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS user_daily_visits ("
     << "user_id TEXT NOT NULL, device_id TEXT, timestamp BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS monthly_active_users ("
     << "user_id TEXT NOT NULL, timestamp BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS user_directory ("
     << "user_id TEXT NOT NULL, room_id TEXT NOT NULL, display_name TEXT, avatar_url TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS user_directory_search ("
     << "user_id TEXT NOT NULL, vector TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS user_directory_stream_pos ("
     << "lock TEXT PRIMARY KEY DEFAULT 'stream_pos_lock', stream_id BIGINT NOT NULL DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS profiles ("
     << "user_id TEXT NOT NULL, displayname TEXT, avatar_url TEXT, presence_status TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS user_filters ("
     << "user_id TEXT NOT NULL, filter_id INTEGER NOT NULL, filter_json TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS room_retention ("
     << "room_id TEXT NOT NULL, event_id TEXT NOT NULL, min_lifetime BIGINT, max_lifetime BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS insertion_events ("
     << "event_id TEXT NOT NULL, room_id TEXT NOT NULL, next_batch_id TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS insertion_event_edges ("
     << "event_id TEXT NOT NULL, room_id TEXT NOT NULL, insertion_prev_event_id TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS ex_outlier_stream ("
     << "event_stream_ordering BIGINT NOT NULL, event_id TEXT NOT NULL, state_group BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS server_keys_json ("
     << "server_name TEXT NOT NULL, key_id TEXT NOT NULL, from_server TEXT NOT NULL,"
     << "ts_added_ms BIGINT NOT NULL, ts_valid_until_ms BIGINT NOT NULL, key_json TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS server_signature_keys ("
     << "server_name TEXT NOT NULL, key_id TEXT NOT NULL, from_server TEXT NOT NULL,"
     << "ts_added_ms BIGINT NOT NULL, ts_valid_until_ms BIGINT NOT NULL, verify_key TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS local_media_repository ("
     << "media_id TEXT NOT NULL, media_type TEXT NOT NULL, media_length BIGINT NOT NULL,"
     << "created_ts BIGINT NOT NULL, upload_name TEXT, user_id TEXT NOT NULL,"
     << "quarantined_by TEXT, url_cache TEXT, last_access_ts BIGINT NOT NULL,"
     << "safe_from_quarantine BOOLEAN NOT NULL DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS remote_media_cache ("
     << "media_id TEXT NOT NULL, media_origin TEXT NOT NULL, media_type TEXT NOT NULL,"
     << "media_length BIGINT NOT NULL, filesystem_id TEXT NOT NULL,"
     << "created_ts BIGINT NOT NULL, upload_name TEXT, last_access_ts BIGINT NOT NULL,"
     << "quarantined_by TEXT, authentication_info TEXT, etag TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS local_media_repository_thumbnails ("
     << "media_id TEXT NOT NULL, thumbnail_width INTEGER NOT NULL,"
     << "thumbnail_height INTEGER NOT NULL, thumbnail_type TEXT NOT NULL,"
     << "thumbnail_method TEXT NOT NULL, thumbnail_length BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS remote_media_cache_thumbnails ("
     << "media_id TEXT NOT NULL, media_origin TEXT NOT NULL,"
     << "thumbnail_width INTEGER NOT NULL, thumbnail_height INTEGER NOT NULL,"
     << "thumbnail_type TEXT NOT NULL, thumbnail_method TEXT NOT NULL,"
     << "filesystem_id TEXT NOT NULL, thumbnail_length BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS application_services_state ("
     << "as_id TEXT PRIMARY KEY, state TEXT, txn_id TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS application_services_txns ("
     << "as_id TEXT NOT NULL, txn_id BIGINT NOT NULL, event_ids TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS application_services_regex ("
     << "id INTEGER PRIMARY KEY AUTOINCREMENT, as_id TEXT NOT NULL,"
     << "namespace TEXT NOT NULL, regex TEXT NOT NULL, exclusive BOOLEAN NOT NULL DEFAULT 1);\n";

  ss << "CREATE TABLE IF NOT EXISTS pusher_throttle ("
     << "pusher_id BIGINT NOT NULL, room_id TEXT NOT NULL, throttled_until BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS server_acl ("
     << "room_id TEXT NOT NULL, event_id TEXT, allow_ip_literals BOOLEAN DEFAULT 0,"
     << "allowed_servers TEXT, denied_servers TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS streams ("
     << "name TEXT NOT NULL, stream_id BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS stream_positions ("
     << "stream_name TEXT NOT NULL, instance_name TEXT NOT NULL DEFAULT 'master',"
     << "stream_id BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS worker_stream_positions ("
     << "worker_name TEXT NOT NULL, stream_type INTEGER NOT NULL, position BIGINT NOT NULL,"
     << "PRIMARY KEY (worker_name, stream_type));\n";

  ss << "CREATE TABLE IF NOT EXISTS worker_locks ("
     << "lock_name TEXT NOT NULL, worker_name TEXT NOT NULL, acquired_ts BIGINT NOT NULL,"
     << "PRIMARY KEY (lock_name));\n";

  ss << "CREATE TABLE IF NOT EXISTS replication_stream ("
     << "stream_id BIGINT PRIMARY KEY, stream_type INTEGER NOT NULL,"
     << "row_id BIGINT, data TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS e2e_fallback_keys_json ("
     << "user_id TEXT NOT NULL, device_id TEXT NOT NULL, algorithm TEXT NOT NULL,"
     << "key_id TEXT NOT NULL, ts_added_ms BIGINT NOT NULL,"
     << "key_json TEXT NOT NULL, used BOOLEAN DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS e2e_cross_signing_keys ("
     << "user_id TEXT NOT NULL, keytype TEXT NOT NULL, keydata TEXT NOT NULL,"
     << "stream_id BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS e2e_cross_signing_signatures ("
     << "user_id TEXT NOT NULL, key_id TEXT NOT NULL, target_user_id TEXT NOT NULL,"
     << "target_device_id TEXT NOT NULL, signature TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS room_alias_servers ("
     << "room_alias TEXT NOT NULL, server TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS room_tags_revisions ("
     << "user_id TEXT NOT NULL, room_id TEXT NOT NULL, stream_id BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS account_data ("
     << "user_id TEXT NOT NULL, account_data_type TEXT NOT NULL,"
     << "stream_id BIGINT NOT NULL, content TEXT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS event_push_actions_staging ("
     << "event_id TEXT NOT NULL, user_id TEXT NOT NULL, profile_tag TEXT,"
     << "actions TEXT NOT NULL, notif SMALLINT, highlight SMALLINT, unread SMALLINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS device_inbox ("
     << "id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,"
     << "device_id TEXT, type TEXT NOT NULL, sender TEXT, content TEXT, stream_id BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS device_lists_changes_converted_stream_position ("
     << "lock TEXT PRIMARY KEY DEFAULT 'converted_lock', stream_id BIGINT NOT NULL DEFAULT 0);\n";

  ss << "CREATE TABLE IF NOT EXISTS thread_subscriptions ("
     << "user_id TEXT NOT NULL, room_id TEXT NOT NULL, thread_id TEXT NOT NULL,"
     << "subscribed BOOLEAN NOT NULL DEFAULT 1, PRIMARY KEY (user_id, room_id, thread_id));\n";

  ss << "CREATE TABLE IF NOT EXISTS background_jobs ("
     << "id INTEGER PRIMARY KEY AUTOINCREMENT, job_name TEXT NOT NULL UNIQUE,"
     << "job_type TEXT NOT NULL, arguments_json TEXT NOT NULL DEFAULT '{}',"
     << "status TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,"
     << "max_attempts INTEGER NOT NULL DEFAULT 3, created_ts BIGINT NOT NULL,"
     << "started_ts BIGINT, completed_ts BIGINT, error_message TEXT, result_json TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS scheduled_tasks ("
     << "task_id TEXT NOT NULL, action TEXT NOT NULL, status TEXT DEFAULT 'scheduled',"
     << "params TEXT, result TEXT, error TEXT, created_ts BIGINT NOT NULL,"
     << "scheduled_ts BIGINT, completed_ts BIGINT, repeating BOOLEAN DEFAULT 0,"
     << "schedule_interval BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS registration_tokens ("
     << "token TEXT NOT NULL, uses_allowed INT, pending INT NOT NULL,"
     << "completed INT NOT NULL, expiry_time BIGINT, created_ts BIGINT NOT NULL,"
     << "creator_user TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS refresh_tokens ("
     << "id BIGINT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT,"
     << "token TEXT NOT NULL, next_token_id BIGINT, expiry_ts BIGINT,"
     << "ultimate_session_expiry_ts BIGINT, used_ts BIGINT, created_ts BIGINT NOT NULL);\n";

  ss << "CREATE TABLE IF NOT EXISTS ratelimit_override ("
     << "user_id TEXT NOT NULL, messages_per_second BIGINT, burst_count BIGINT);\n";

  ss << "CREATE TABLE IF NOT EXISTS ui_auth_sessions ("
     << "session_id TEXT NOT NULL, creation_ts BIGINT NOT NULL, server_data TEXT NOT NULL,"
     << "clientdict_json TEXT, uri TEXT, method TEXT, description TEXT);\n";

  ss << "CREATE TABLE IF NOT EXISTS read_markers ("
     << "user_id TEXT NOT NULL, room_id TEXT NOT NULL, event_id TEXT NOT NULL,"
     << "updated_ts BIGINT, PRIMARY KEY (user_id, room_id));\n";

  ss << "CREATE TABLE IF NOT EXISTS migration_log ("
     << "id INTEGER PRIMARY KEY AUTOINCREMENT, migration_version INTEGER NOT NULL,"
     << "direction TEXT NOT NULL CHECK (direction IN ('up', 'down')),"
     << "started_at TIMESTAMP NOT NULL, completed_at TIMESTAMP,"
     << "success BOOLEAN, error_message TEXT,"
     << "executed_by TEXT NOT NULL DEFAULT 'progressive-server');\n";

  ss << "CREATE TABLE IF NOT EXISTS applied_schema_deltas ("
     << "version INTEGER NOT NULL, file_name TEXT NOT NULL,"
     << "applied_at TIMESTAMP NOT NULL DEFAULT (datetime('now')),"
     << "PRIMARY KEY (version, file_name));\n";

  ss << "CREATE TABLE IF NOT EXISTS timeline_gaps ("
     << "room_id TEXT NOT NULL, gap_start TEXT NOT NULL, gap_end TEXT NOT NULL,"
     << "PRIMARY KEY (room_id, gap_start));\n";

  ss << "CREATE TABLE IF NOT EXISTS room_stats_earliest_token ("
     << "room_id TEXT NOT NULL, token BIGINT NOT NULL);\n";

  return ss.str();
}

// ============================================================================
// Migration info - returns list of all known deltas with descriptions
// ============================================================================
std::vector<std::tuple<int, int, std::string, std::string>> get_migration_info() {
  SchemaMigrationRunner dummy(nullptr, nullptr);
  auto deltas = dummy.collect_all_deltas();
  std::vector<std::tuple<int, int, std::string, std::string>> result;
  for (auto& d : deltas) {
    result.emplace_back(d.version, d.delta_number, d.name, d.description);
  }
  return result;
}

// ============================================================================
// Validate schema - check that all expected tables and indices exist
// ============================================================================
bool validate_schema(
    std::function<bool(const std::string&)> table_exists_fn,
    std::function<bool(const std::string&)> index_exists_fn,
    std::vector<std::string>& missing_tables,
    std::vector<std::string>& missing_indices) {

  bool all_ok = true;

  // Core tables that MUST exist
  std::vector<std::string> required_tables = {
    "schema_version", "users", "access_tokens", "devices", "events",
    "event_json", "event_auth", "event_edges", "rooms", "room_memberships",
    "current_state_events", "state_events", "state_groups",
    "state_groups_state", "state_group_edges", "event_to_state_groups",
    "room_aliases", "redactions", "event_relations",
    "presence_state", "room_tags", "room_account_data", "account_data",
    "receipts_graph", "receipts_linearized", "e2e_device_keys_json",
    "e2e_one_time_keys_json", "background_updates", "event_push_actions",
    "event_push_summary", "event_search"
  };

  for (auto& t : required_tables) {
    if (!table_exists_fn(t)) {
      missing_tables.push_back(t);
      all_ok = false;
    }
  }

  std::vector<std::string> required_indices = {
    "events_event_id_idx", "events_stream_ordering_idx",
    "events_room_id_idx", "events_order_room_idx",
    "users_name_idx", "access_tokens_token_idx",
    "room_memberships_user_room_idx", "room_aliases_alias_idx",
    "current_state_events_room_type_key_idx",
    "state_groups_state_unique_idx", "state_group_edges_idx"
  };

  for (auto& idx : required_indices) {
    if (!index_exists_fn(idx)) {
      missing_indices.push_back(idx);
      all_ok = false;
    }
  }

  return all_ok;
}

// ============================================================================
// Dump current schema to SQL string
// ============================================================================
std::string dump_current_schema(
    std::function<std::vector<std::map<std::string, std::string>>(const std::string&)> query_fn) {

  std::stringstream output;

  auto tables = query_fn("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name");
  for (auto& t : tables) {
    output << t["sql"] << ";\n";
  }

  auto indices = query_fn("SELECT name, sql FROM sqlite_master WHERE type='index' AND sql IS NOT NULL ORDER BY name");
  for (auto& idx : indices) {
    output << idx["sql"] << ";\n";
  }

  return output.str();
}

// ============================================================================
// Convenience: run all migrations via DatabasePool interface
// ============================================================================
void apply_all_schema_migrations(DatabasePool& db, int target_version) {
  run_schema_migrations(
    [&db](const std::string& sql) {
      db.execute("schema_migration", sql);
    },
    [&db](const std::string& sql) -> std::vector<std::map<std::string, std::string>> {
      auto rows = db.execute("schema_query", sql);
      std::vector<std::map<std::string, std::string>> result;
      // Convert RowList to map vector - assume Row type compatible
      for (auto& row : rows) {
        std::map<std::string, std::string> m;
        // Generic iteration over row columns would go here
        // For now, this adapter preserves the interface
        result.push_back(m);
      }
      return result;
    },
    target_version
  );
}

}  // namespace progressive::storage
