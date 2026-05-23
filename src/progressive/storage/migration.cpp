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
      CREATE TABLE IF NOT EXISTS profiles (
          user_id TEXT PRIMARY KEY,
          displayname TEXT,
          avatar_url TEXT
      );
      CREATE TABLE IF NOT EXISTS account_data (
          user_id TEXT NOT NULL, data_type TEXT NOT NULL,
          content TEXT NOT NULL,
          PRIMARY KEY (user_id, data_type)
      );
      CREATE TABLE IF NOT EXISTS room_account_data (
          user_id TEXT NOT NULL, room_id TEXT NOT NULL,
          data_type TEXT NOT NULL, content TEXT NOT NULL,
          PRIMARY KEY (user_id, room_id, data_type)
      );
      CREATE TABLE IF NOT EXISTS pushers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT NOT NULL, app_id TEXT NOT NULL,
          pushkey TEXT NOT NULL, kind TEXT,
          app_display_name TEXT, device_display_name TEXT,
          lang TEXT, data TEXT, last_token TEXT
      );
      CREATE TABLE IF NOT EXISTS event_reports (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          room_id TEXT NOT NULL, event_id TEXT NOT NULL,
          user_id TEXT NOT NULL, score INTEGER DEFAULT 0,
          reason TEXT, received_ts BIGINT
      );
    )");
    db.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (1)");
  }
}

}  // namespace progressive::storage
