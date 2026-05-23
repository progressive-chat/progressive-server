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
    )");
    db.execute("INSERT OR IGNORE INTO schema_version (version) VALUES (1)");
  }
}

}  // namespace progressive::storage
