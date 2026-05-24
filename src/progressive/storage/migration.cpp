#include "migration.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "schema.hpp"

namespace progressive::storage {

MigrationRunner::MigrationRunner(DatabasePool& db, std::string_view schema_dir)
    : db_(db), schema_dir_(schema_dir) {}

int MigrationRunner::current_version() {
  try {
    auto rows = db_.query("SELECT MAX(version) as ver FROM schema_version");
    if (!rows.empty() && rows[0].contains("ver") && !rows[0]["ver"].is_null()) {
      try {
        return std::stoi(rows[0]["ver"].get<std::string>());
      } catch (...) {
        return rows[0]["ver"].get<int>();
      }
    }
  } catch (...) {
    // Table doesn't exist yet
  }
  return 0;
}

void MigrationRunner::upgrade() {
  int cur = current_version();

  // Load full schema for fresh databases
  std::string full_path = schema_dir_ + "/main/full_schemas";
  if (cur == 0 && std::filesystem::exists(full_path)) {
    for (auto& entry : std::filesystem::directory_iterator(full_path)) {
      std::ifstream f(entry.path());
      if (!f)
        continue;
      std::stringstream ss;
      ss << f.rdbuf();
      std::string sql = ss.str();
      if (!sql.empty()) {
        std::cout << "[migration] applying full schema " << entry.path().filename().string()
                  << "\n";
        db_.execute(sql);
        int ver = 0;
        try {
          ver = std::stoi(entry.path().stem().string());
        } catch (...) {
        }
        if (ver > 0)
          db_.execute("INSERT INTO schema_version (version) VALUES (" + std::to_string(ver) + ")");
        cur = ver;
      }
    }
  }

  // Load and apply deltas
  std::string delta_path = schema_dir_ + "/main/delta";
  if (std::filesystem::exists(delta_path)) {
    std::vector<std::pair<int, std::string>> deltas;

    for (auto& entry : std::filesystem::directory_iterator(delta_path)) {
      if (!entry.is_directory())
        continue;
      int ver = 0;
      try {
        ver = std::stoi(entry.path().filename().string());
      } catch (...) {
        continue;
      }
      if (ver <= cur)
        continue;

      std::string sql;
      for (auto& df : std::filesystem::directory_iterator(entry.path())) {
        if (df.path().extension() != ".sql")
          continue;
        std::ifstream f(df.path());
        std::stringstream ss;
        ss << f.rdbuf();
        sql += ss.str() + ";\n";
      }
      if (!sql.empty())
        deltas.push_back({ver, sql});
    }

    std::sort(deltas.begin(), deltas.end());

    for (auto& [ver, sql] : deltas) {
      std::cout << "[migration] applying delta v" << ver << "\n";
      try {
        db_.begin();
        db_.execute(sql);
        db_.execute("INSERT INTO schema_version (version) VALUES (" + std::to_string(ver) + ")");
        db_.commit();
        cur = ver;
      } catch (const std::exception& e) {
        std::cerr << "[migration] delta v" << ver << " failed: " << e.what() << "\n";
        db_.rollback();
        throw;
      }
    }
  }

  std::cout << "[migration] schema at version " << cur << "\n";
}

void apply_schema(DatabasePool& db) {
  // Inline fallback — applies the core schema if not already present
  std::string embedded_data_dir;
  // Try common locations for the schema files
  for (auto prefix : {"", "/usr/share/progressive-server/", "./", "../src/progressive/"}) {
    std::string path = std::string(prefix) + "storage/schema";
    if (std::filesystem::exists(path + "/main/full_schemas")) {
      embedded_data_dir = path;
      break;
    }
  }

  if (!embedded_data_dir.empty()) {
    MigrationRunner(db, embedded_data_dir).upgrade();
  } else {
    // No schema files found — use inline DDL
    db.execute(R"(
      CREATE TABLE IF NOT EXISTS schema_version (
          version INTEGER PRIMARY KEY,
          applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, password_hash TEXT,
          creation_ts BIGINT NOT NULL, admin INTEGER DEFAULT 0,
          deactivated INTEGER DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS rooms (
          room_id TEXT PRIMARY KEY, is_public INTEGER DEFAULT 0,
          creator TEXT, room_version INTEGER DEFAULT 10,
          creation_ts BIGINT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS events (
          event_id TEXT PRIMARY KEY, room_id TEXT NOT NULL,
          type TEXT NOT NULL, sender TEXT NOT NULL,
          content TEXT NOT NULL, state_key TEXT,
          depth BIGINT NOT NULL DEFAULT 0, origin_server_ts TEXT,
          outlier INTEGER DEFAULT 0, stream_ordering INTEGER
      );
      CREATE INDEX IF NOT EXISTS events_room_id ON events(room_id);
      CREATE INDEX IF NOT EXISTS events_stream_ordering ON events(stream_ordering);
      CREATE TABLE IF NOT EXISTS access_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          token TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL,
          device_id TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS access_tokens_token ON access_tokens(token);
      CREATE TABLE IF NOT EXISTS room_memberships (
          event_id TEXT NOT NULL, room_id TEXT NOT NULL,
          user_id TEXT NOT NULL, membership TEXT NOT NULL DEFAULT 'leave',
          sender TEXT NOT NULL, content TEXT,
          PRIMARY KEY (room_id, user_id)
      );
      CREATE TABLE IF NOT EXISTS event_auth (
          event_id TEXT NOT NULL, auth_id TEXT NOT NULL,
          PRIMARY KEY (event_id, auth_id)
      );
      CREATE TABLE IF NOT EXISTS room_aliases (
          alias TEXT PRIMARY KEY,
          room_id TEXT NOT NULL,
          creator TEXT
      );
      CREATE INDEX IF NOT EXISTS room_aliases_room ON room_aliases(room_id);
      CREATE TABLE IF NOT EXISTS read_markers (
          user_id TEXT NOT NULL, room_id TEXT NOT NULL,
          event_id TEXT NOT NULL, updated_ts BIGINT,
          PRIMARY KEY (user_id, room_id)
      );
      CREATE TABLE IF NOT EXISTS read_receipts (
          user_id TEXT NOT NULL, room_id TEXT NOT NULL,
          event_id TEXT NOT NULL, updated_ts BIGINT,
          PRIMARY KEY (user_id, room_id)
      );
      CREATE TABLE IF NOT EXISTS registration_tokens (
          token TEXT PRIMARY KEY, used INTEGER DEFAULT 0, created_ts BIGINT
      );
      CREATE TABLE IF NOT EXISTS device_inbox (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT NOT NULL, device_id TEXT,
          type TEXT NOT NULL, sender TEXT,
          content TEXT, stream_id BIGINT
      );
      CREATE INDEX IF NOT EXISTS device_inbox_user ON device_inbox(user_id);
      CREATE TABLE IF NOT EXISTS event_relations (
          event_id TEXT NOT NULL,
          relates_to_id TEXT NOT NULL,
          relation_type TEXT NOT NULL,
          aggregation_key TEXT,
          PRIMARY KEY (event_id)
      );
      CREATE INDEX IF NOT EXISTS event_relations_relates ON event_relations(relates_to_id);
      CREATE INDEX IF NOT EXISTS event_relations_type ON event_relations(relation_type);
      CREATE TABLE IF NOT EXISTS state_groups (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          room_id TEXT NOT NULL,
          event_id TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS state_groups_state (
          state_group INTEGER NOT NULL,
          type TEXT NOT NULL,
          state_key TEXT NOT NULL,
          event_id TEXT NOT NULL,
          PRIMARY KEY (state_group, type, state_key)
      );
      CREATE TABLE IF NOT EXISTS event_forward_extremities (
          event_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          PRIMARY KEY (event_id, room_id)
      );
      CREATE TABLE IF NOT EXISTS event_to_state_groups (
          event_id TEXT PRIMARY KEY, state_group INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS event_push_actions (
          event_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          profile_tag TEXT,
          actions TEXT NOT NULL,
          stream_ordering INTEGER,
          PRIMARY KEY (event_id, user_id)
      );
      CREATE TABLE IF NOT EXISTS event_push_summary (
          user_id TEXT NOT NULL,
          room_id TEXT NOT NULL,
          notif_count INTEGER DEFAULT 0,
          highlight_count INTEGER DEFAULT 0,
          stream_ordering INTEGER,
          PRIMARY KEY (user_id, room_id)
      );
      CREATE TABLE IF NOT EXISTS ui_auth_sessions (
          session_id TEXT PRIMARY KEY, user_id TEXT,
          client_secret TEXT, server_data TEXT, creation_ts BIGINT
      );
      CREATE TABLE IF NOT EXISTS presence_state (
          user_id TEXT PRIMARY KEY,
          state TEXT DEFAULT 'offline',
          status_msg TEXT,
          last_active_ts BIGINT,
          last_federation_update_ts BIGINT
      );
      CREATE TABLE IF NOT EXISTS event_txn_id (
          event_id TEXT PRIMARY KEY,
          room_id TEXT NOT NULL,
          user_id TEXT NOT NULL,
          txn_id TEXT NOT NULL,
          ts BIGINT,
          UNIQUE(room_id, user_id, txn_id)
      );
      CREATE TABLE IF NOT EXISTS server_acl (
          room_id TEXT PRIMARY KEY,
          allow_ip_literals INTEGER DEFAULT 0,
          allowed_servers TEXT,
          denied_servers TEXT
      );
      CREATE TABLE IF NOT EXISTS timeline_gaps (
          room_id TEXT NOT NULL,
          gap_start TEXT NOT NULL,
          gap_end TEXT NOT NULL,
          PRIMARY KEY (room_id, gap_start)
      );
      CREATE TABLE IF NOT EXISTS user_filters (
          user_id TEXT NOT NULL, filter_id INTEGER NOT NULL,
          filter_json TEXT NOT NULL, PRIMARY KEY (user_id, filter_id)
      );
      CREATE TABLE IF NOT EXISTS e2e_room_keys (
          user_id TEXT NOT NULL, room_id TEXT NOT NULL,
          session_id TEXT NOT NULL, first_message_index INTEGER,
          forwarded_count INTEGER, is_verified INTEGER,
          session_data TEXT NOT NULL,
          PRIMARY KEY (user_id, room_id, session_id)
      );
      CREATE TABLE IF NOT EXISTS e2e_room_keys_versions (
          user_id TEXT NOT NULL, version TEXT NOT NULL,
          algorithm TEXT, auth_data TEXT NOT NULL,
          etag TEXT, PRIMARY KEY (user_id, version)
      );
      CREATE TABLE IF NOT EXISTS event_search (
          event_id TEXT PRIMARY KEY, room_id TEXT NOT NULL,
          sender TEXT, body TEXT, content TEXT
      );
      CREATE TABLE IF NOT EXISTS thread_subscriptions (
          user_id TEXT NOT NULL, room_id TEXT NOT NULL,
          thread_id TEXT NOT NULL, subscribed INTEGER DEFAULT 1,
          PRIMARY KEY (user_id, room_id, thread_id)
      );
      CREATE TABLE IF NOT EXISTS event_auth_chains (
          event_id TEXT PRIMARY KEY,
          chain_id BIGINT NOT NULL,
          sequence_number BIGINT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS event_auth_chains_cid ON event_auth_chains(chain_id);
      CREATE TABLE IF NOT EXISTS event_auth_chain_links (
          origin_chain_id BIGINT NOT NULL,
          origin_seq BIGINT NOT NULL,
          target_chain_id BIGINT NOT NULL,
          target_seq BIGINT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS partial_state_rooms (
          room_id TEXT PRIMARY KEY,
          joined_via TEXT,
          creation_ts BIGINT
      );
      CREATE TABLE IF NOT EXISTS refresh_tokens (
          token TEXT PRIMARY KEY,
          user_id TEXT NOT NULL,
          access_token_id TEXT,
          next_token_id TEXT,
          expires_at BIGINT
      );
      CREATE TABLE IF NOT EXISTS room_retention (
          room_id TEXT PRIMARY KEY,
          max_lifetime BIGINT, min_lifetime BIGINT
      );
      CREATE TABLE IF NOT EXISTS background_updates (
          update_name TEXT PRIMARY KEY,
          progress_json TEXT NOT NULL DEFAULT '{}',
          depends_on TEXT
      );
      CREATE TABLE IF NOT EXISTS scheduled_tasks (
          task_id TEXT PRIMARY KEY, action TEXT NOT NULL,
          status TEXT DEFAULT 'scheduled', params TEXT, created_ts BIGINT
      );
      -- 24 Synapse tables for full parity
      CREATE TABLE IF NOT EXISTS application_services_state (as_id TEXT PRIMARY KEY, state TEXT, txn_id TEXT);
      CREATE TABLE IF NOT EXISTS received_transactions (transaction_id TEXT PRIMARY KEY, origin TEXT, received_ts BIGINT);
      CREATE TABLE IF NOT EXISTS event_json (event_id TEXT PRIMARY KEY, room_id TEXT, json TEXT);
      CREATE TABLE IF NOT EXISTS current_state_events (room_id TEXT, type TEXT, state_key TEXT, event_id TEXT, PRIMARY KEY(room_id,type,state_key));
      CREATE TABLE IF NOT EXISTS rejections (event_id TEXT PRIMARY KEY, reason TEXT, last_check TEXT);
      CREATE TABLE IF NOT EXISTS redactions (event_id TEXT PRIMARY KEY, redacts TEXT, have_censored INTEGER DEFAULT 0);
      CREATE TABLE IF NOT EXISTS room_depth (room_id TEXT PRIMARY KEY, min_depth BIGINT);
      CREATE TABLE IF NOT EXISTS local_media_repository (media_id TEXT PRIMARY KEY, media_type TEXT, media_length BIGINT, upload_name TEXT, user_id TEXT, created_ts BIGINT);
      CREATE TABLE IF NOT EXISTS remote_media_cache (media_id TEXT, media_origin TEXT, media_type TEXT, filesystem_id TEXT, created_ts BIGINT, PRIMARY KEY(media_id, media_origin));
      CREATE TABLE IF NOT EXISTS room_alias_servers (room_alias TEXT, server TEXT, PRIMARY KEY(room_alias, server));
      CREATE TABLE IF NOT EXISTS server_keys_json (server_name TEXT, key_id TEXT, from_server TEXT, ts_added_ms BIGINT, ts_valid_until_ms BIGINT, key_json TEXT);
      CREATE TABLE IF NOT EXISTS user_threepids (user_id TEXT, medium TEXT, address TEXT, validated_at BIGINT, added_at BIGINT, PRIMARY KEY(user_id, medium, address));
      CREATE TABLE IF NOT EXISTS room_tags_revisions (user_id TEXT, room_id TEXT, stream_id BIGINT);
      CREATE TABLE IF NOT EXISTS presence_stream (stream_id BIGINT, user_id TEXT, state TEXT, last_active_ts BIGINT);
      CREATE TABLE IF NOT EXISTS push_rules_stream (stream_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, rule_id TEXT, op TEXT);
      CREATE TABLE IF NOT EXISTS ex_outlier_stream (event_stream_ordering BIGINT, event_id TEXT, state_group BIGINT);
      CREATE TABLE IF NOT EXISTS threepid_guest_access_tokens (medium TEXT, address TEXT, guest_access_token TEXT);
      CREATE TABLE IF NOT EXISTS pusher_throttle (pusher_id INTEGER, room_id TEXT, throttled_until BIGINT);
      CREATE TABLE IF NOT EXISTS device_lists_outbound_pokes (destination TEXT, user_id TEXT, stream_id BIGINT, sent BOOLEAN, ts BIGINT);
      CREATE TABLE IF NOT EXISTS device_lists_stream (stream_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, device_id TEXT);
      CREATE TABLE IF NOT EXISTS ratelimit_override (user_id TEXT PRIMARY KEY, messages_per_second BIGINT, burst_count BIGINT);
      CREATE TABLE IF NOT EXISTS pushers (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT, app_id TEXT, pushkey TEXT, kind TEXT, app_display_name TEXT, device_display_name TEXT, lang TEXT, data TEXT, last_token TEXT);
      CREATE TABLE IF NOT EXISTS event_reports (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id TEXT, event_id TEXT, user_id TEXT, score INTEGER DEFAULT 0, reason TEXT, received_ts BIGINT);
      CREATE TABLE IF NOT EXISTS worker_stream_positions (worker_name TEXT, stream_type INTEGER, position BIGINT, PRIMARY KEY(worker_name, stream_type));
      CREATE TABLE IF NOT EXISTS worker_locks (lock_name TEXT PRIMARY KEY, worker_name TEXT, acquired_ts BIGINT);
      CREATE TABLE IF NOT EXISTS replication_stream (stream_id INTEGER PRIMARY KEY AUTOINCREMENT, stream_type INTEGER, row_id BIGINT, data TEXT);
    )");
    db.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (1)");
  }
}

}  // namespace progressive::storage
