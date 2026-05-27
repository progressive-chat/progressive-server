// =============================================================================
// progressive::database_migration_engine.cpp - Matrix Database Migration Engine
//
// A comprehensive database migration engine providing:
//   - Schema version tracking with multiple version tables
//   - Migration file parsing (SQL with -- Up / -- Down markers)
//   - Migration runner with full transaction support and savepoints
//   - Rollback support with dependency-aware ordering
//   - Migration dependency graph (topological sort, cycle detection)
//   - Background migrations with progress tracking and batching
//   - SCHEMA_COMPAT_VERSION enforcement with cluster-wide checks
//   - Migration admin API (REST endpoints for status, run, rollback, history)
//   - Migration locking to prevent concurrent runs
//   - Dry-run mode for validation
//   - Checksum verification of applied migrations
//   - Migration log / audit trail
//   - Configurable timeouts and retry logic
//
// Equivalent to:
//   synapse/storage/database.py (SchemaUpgradeController, _UpgradeDatabase)
//   synapse/storage/schema/__init__.py
//   synapse/storage/databases/main/schema.py
//   synapse/_scripts/update_synapse_database.py
//   alembic (conceptual equivalent)
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++
// =============================================================================

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
#include <exception>
#include <filesystem>
#include <fstream>
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
#include <stack>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/engine.hpp"
#include "progressive/storage/types.hpp"

// =============================================================================
// Namespace
// =============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;
namespace fs = std::filesystem;

// =============================================================================
// Forward declarations for all internal classes
// =============================================================================
class SchemaVersionTracker;
class MigrationFileParser;
class MigrationRunner;
class MigrationDependencyGraph;
class BackgroundMigrationManager;
class SchemaCompatEnforcer;
class MigrationAdminAPI;
class MigrationLockManager;
class MigrationChecksumVerifier;
class MigrationAuditLogger;
class MigrationDryRunner;
class MigrationEngine;

// =============================================================================
// Anonymous namespace - Internal constants, helpers, and utility types
// =============================================================================
namespace {

// ---------------------------------------------------------------------------
// Logging helper (matches pattern in db_pool.cpp)
// ---------------------------------------------------------------------------
struct Logger {
  std::string name_;
  void debug(const std::string& msg) {
    std::cout << "[mig-engine] [DEBUG] [" << name_ << "] " << msg << "\n";
  }
  void info(const std::string& msg) {
    std::cout << "[mig-engine] [INFO]  [" << name_ << "] " << msg << "\n";
  }
  void warn(const std::string& msg) {
    std::cerr << "[mig-engine] [WARN]  [" << name_ << "] " << msg << "\n";
  }
  void error(const std::string& msg) {
    std::cerr << "[mig-engine] [ERROR] [" << name_ << "] " << msg << "\n";
  }
};

Logger& get_logger(const std::string& name) {
  static thread_local std::map<std::string, Logger> loggers;
  auto it = loggers.find(name);
  if (it == loggers.end()) {
    loggers[name] = Logger{name};
    return loggers[name];
  }
  return it->second;
}

// ---------------------------------------------------------------------------
// SCHEMA_COMPAT_VERSION constants
// Equivalent to synapse.storage.schema.SCHEMA_COMPAT_VERSION
// ---------------------------------------------------------------------------
static constexpr const char* SCHEMA_COMPAT_VERSION = "1";
static constexpr const char* SCHEMA_COMPAT_VERSION_TABLE = "schema_compat_version";
static constexpr const char* SCHEMA_COMPAT_LOCK_KEY = "compat_version_lock";

// ---------------------------------------------------------------------------
// Migration table names
// ---------------------------------------------------------------------------
static constexpr const char* TABLE_SCHEMA_VERSION = "schema_version";
static constexpr const char* TABLE_APPLIED_SCHEMA_DELTAS = "applied_schema_deltas";
static constexpr const char* TABLE_MIGRATION_LOG = "migration_log";
static constexpr const char* TABLE_MIGRATION_LOCKS = "migration_locks";
static constexpr const char* TABLE_MIGRATION_CHECKSUMS = "migration_checksums";
static constexpr const char* TABLE_BACKGROUND_MIGRATIONS = "background_migrations";
static constexpr const char* TABLE_BG_MIGRATION_PROGRESS = "bg_migration_progress";

// ---------------------------------------------------------------------------
// Migration direction enum
// ---------------------------------------------------------------------------
enum class MigrationDirection {
  UP,
  DOWN,
  BOTH
};

const char* direction_str(MigrationDirection d) {
  switch (d) {
    case MigrationDirection::UP: return "up";
    case MigrationDirection::DOWN: return "down";
    case MigrationDirection::BOTH: return "both";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Migration status enum
// ---------------------------------------------------------------------------
enum class MigrationStatus {
  PENDING,
  IN_PROGRESS,
  APPLIED,
  FAILED,
  SKIPPED,
  ROLLED_BACK
};

const char* status_str(MigrationStatus s) {
  switch (s) {
    case MigrationStatus::PENDING: return "pending";
    case MigrationStatus::IN_PROGRESS: return "in_progress";
    case MigrationStatus::APPLIED: return "applied";
    case MigrationStatus::FAILED: return "failed";
    case MigrationStatus::SKIPPED: return "skipped";
    case MigrationStatus::ROLLED_BACK: return "rolled_back";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Background migration status enum
// ---------------------------------------------------------------------------
enum class BgMigrationStatus {
  PENDING,
  RUNNING,
  PAUSED,
  COMPLETED,
  FAILED,
  ROLLING_BACK
};

const char* bg_status_str(BgMigrationStatus s) {
  switch (s) {
    case BgMigrationStatus::PENDING: return "pending";
    case BgMigrationStatus::RUNNING: return "running";
    case BgMigrationStatus::PAUSED: return "paused";
    case BgMigrationStatus::COMPLETED: return "completed";
    case BgMigrationStatus::FAILED: return "failed";
    case BgMigrationStatus::ROLLING_BACK: return "rolling_back";
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Timeout and retry constants
// ---------------------------------------------------------------------------
static constexpr chr::seconds DEFAULT_LOCK_TIMEOUT(300);       // 5 minutes
static constexpr chr::seconds DEFAULT_MIGRATION_TIMEOUT(600);  // 10 minutes
static constexpr int DEFAULT_RETRY_ATTEMPTS = 3;
static constexpr chr::milliseconds DEFAULT_RETRY_DELAY(1000);
static constexpr chr::seconds BG_MIGRATION_POLL_INTERVAL(5);
static constexpr int64_t DEFAULT_BG_BATCH_SIZE = 100;
static constexpr int64_t MIN_BG_BATCH_SIZE = 1;
static constexpr int64_t MAX_BG_BATCH_SIZE = 10000;

// ---------------------------------------------------------------------------
// SIMD-friendly / hardware-aligned constants
// ---------------------------------------------------------------------------
static constexpr size_t CACHE_LINE_SIZE = 64;
static constexpr size_t ALIGN_TO = 64;

// ---------------------------------------------------------------------------
// Utility: simple DJB2 hash for checksums
// ---------------------------------------------------------------------------
uint64_t djb2_hash(const std::string& data) {
  uint64_t hash = 5381;
  for (char c : data) {
    hash = ((hash << 5) + hash) + static_cast<unsigned char>(c);
  }
  return hash;
}

// ---------------------------------------------------------------------------
// Utility: ISO 8601 timestamp
// ---------------------------------------------------------------------------
std::string iso_timestamp_now() {
  auto now = chr::system_clock::now();
  auto time_t_now = chr::system_clock::to_time_t(now);
  auto ms = chr::duration_cast<chr::milliseconds>(
      now.time_since_epoch()) % 1000;
  std::tm tm;
  gmtime_r(&time_t_now, &tm);
  std::ostringstream oss;
  oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S")
      << '.' << std::setfill('0') << std::setw(3) << ms.count() << "Z";
  return oss.str();
}

// ---------------------------------------------------------------------------
// Utility: trim whitespace
// ---------------------------------------------------------------------------
std::string_view trim_view(std::string_view sv) {
  while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t' ||
         sv.front() == '\r' || sv.front() == '\n'))
    sv.remove_prefix(1);
  while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' ||
         sv.back() == '\r' || sv.back() == '\n'))
    sv.remove_suffix(1);
  return sv;
}

std::string trim(const std::string& s) {
  return std::string(trim_view(s));
}

// ---------------------------------------------------------------------------
// Utility: split string by delimiter
// ---------------------------------------------------------------------------
std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> result;
  std::istringstream ss(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    result.push_back(trim(item));
  }
  return result;
}

// ---------------------------------------------------------------------------
// Utility: check if string starts with prefix
// ---------------------------------------------------------------------------
bool starts_with(std::string_view sv, std::string_view prefix) {
  return sv.size() >= prefix.size() && sv.substr(0, prefix.size()) == prefix;
}

// ---------------------------------------------------------------------------
// Utility: join strings
// ---------------------------------------------------------------------------
std::string join(const std::vector<std::string>& parts,
                 const std::string& delim) {
  std::ostringstream oss;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) oss << delim;
    oss << parts[i];
  }
  return oss.str();
}

// ---------------------------------------------------------------------------
// Utility: SQL-safe string escaping (basic)
// ---------------------------------------------------------------------------
std::string sql_escape(const std::string& s) {
  std::string result;
  result.reserve(s.size() + 16);
  for (char c : s) {
    if (c == '\'') result += "''";
    else result += c;
  }
  return result;
}

// ---------------------------------------------------------------------------
// Utility: Split SQL script into individual statements
// Respects semicolons inside string literals, block comments, etc.
// ---------------------------------------------------------------------------
std::vector<std::string> split_sql_statements(const std::string& script) {
  std::vector<std::string> statements;
  std::string current;
  bool in_single_quote = false;
  bool in_double_quote = false;
  bool in_line_comment = false;
  bool in_block_comment = false;

  for (size_t i = 0; i < script.size(); ++i) {
    char c = script[i];
    char nc = (i + 1 < script.size()) ? script[i + 1] : '\0';

    // Handle block comment state transitions
    if (in_block_comment) {
      if (c == '*' && nc == '/') {
        in_block_comment = false;
        ++i;
      }
      continue;
    }

    // Handle line comment
    if (in_line_comment) {
      if (c == '\n') {
        in_line_comment = false;
      }
      continue;
    }

    // Check for comment starts
    if (!in_single_quote && !in_double_quote) {
      if (c == '-' && nc == '-') {
        in_line_comment = true;
        ++i;
        continue;
      }
      if (c == '/' && nc == '*') {
        in_block_comment = true;
        ++i;
        continue;
      }
    }

    // Handle quotes
    if (c == '\'' && !in_double_quote && !in_line_comment && !in_block_comment) {
      in_single_quote = !in_single_quote;
    } else if (c == '"' && !in_single_quote && !in_line_comment && !in_block_comment) {
      in_double_quote = !in_double_quote;
    }

    // Handle statement separator
    if (c == ';' && !in_single_quote && !in_double_quote) {
      std::string stmt = trim(current);
      if (!stmt.empty()) {
        statements.push_back(stmt);
      }
      current.clear();
      continue;
    }

    current += c;
  }

  // Handle any remaining content
  std::string stmt = trim(current);
  if (!stmt.empty()) {
    statements.push_back(stmt);
  }

  return statements;
}

// =========================================================================
// MigrationFile - Parsed representation of a single migration file
// =========================================================================
struct MigrationFile {
  int version;
  std::string filename;
  std::string description;
  std::string up_sql;
  std::string down_sql;
  std::string raw_content;
  uint64_t checksum;
  std::vector<std::string> up_statements;
  std::vector<std::string> down_statements;
  std::set<int> depends_on;       // Versions this migration depends on
  std::set<int> required_by;      // Versions that require this migration
  bool has_up;
  bool has_down;
  bool is_transactional;          // Whether to wrap in transaction
  chr::milliseconds estimated_duration;

  MigrationFile()
    : version(0), checksum(0), has_up(false), has_down(false),
      is_transactional(true), estimated_duration(0) {}

  json to_json() const {
    json j;
    j["version"] = version;
    j["filename"] = filename;
    j["description"] = description;
    j["checksum"] = checksum;
    j["has_up"] = has_up;
    j["has_down"] = has_down;
    j["is_transactional"] = is_transactional;
    j["estimated_duration_ms"] = estimated_duration.count();
    j["depends_on"] = json::array();
    for (int d : depends_on) j["depends_on"].push_back(d);
    j["required_by"] = json::array();
    for (int r : required_by) j["required_by"].push_back(r);
    j["up_statement_count"] = up_statements.size();
    j["down_statement_count"] = down_statements.size();
    return j;
  }
};

}  // anonymous namespace

// =============================================================================
// MigrationFileParser - Parses SQL migration files with -- Up / -- Down markers
//
// Parsing format:
//   -- Up
//   <SQL statements for upgrading>
//   -- Down
//   <SQL statements for downgrading>
//
// Optional metadata comments at the top:
//   -- Description: <description>
//   -- Dependencies: <version1,version2,...>
//   -- Transactional: true|false
//   -- EstimatedDuration: <milliseconds>
// =============================================================================
class MigrationFileParser {
public:
  MigrationFileParser() = default;

  // Parse a single migration file from its content
  MigrationFile parse(const std::string& filename,
                      const std::string& content) {
    auto& log = get_logger("MigrationFileParser");
    MigrationFile mf;
    mf.filename = filename;
    mf.raw_content = content;
    mf.checksum = djb2_hash(content);

    // Try to extract version from filename (e.g., "01_initial_schema.sql")
    mf.version = extract_version(filename);

    // Parse the content
    std::istringstream stream(content);
    std::string line;
    std::string current_section;
    std::string current_sql;

    bool in_up = false;
    bool in_down = false;
    std::string metadata_description;
    std::string metadata_deps;
    std::string metadata_transactional;
    std::string metadata_duration;

    while (std::getline(stream, line)) {
      std::string_view trimmed = trim_view(line);

      // Check for metadata comments
      if (starts_with(trimmed, "-- Description:")) {
        metadata_description = trim(std::string(
            trimmed.substr(std::string_view("-- Description:").size())));
        continue;
      }
      if (starts_with(trimmed, "-- Dependencies:")) {
        metadata_deps = trim(std::string(
            trimmed.substr(std::string_view("-- Dependencies:").size())));
        continue;
      }
      if (starts_with(trimmed, "-- Transactional:")) {
        metadata_transactional = trim(std::string(
            trimmed.substr(std::string_view("-- Transactional:").size())));
        continue;
      }
      if (starts_with(trimmed, "-- EstimatedDuration:")) {
        metadata_duration = trim(std::string(
            trimmed.substr(std::string_view("-- EstimatedDuration:").size())));
        continue;
      }
      if (starts_with(trimmed, "-- SchemaVersion:")) {
        std::string sv = trim(std::string(
            trimmed.substr(std::string_view("-- SchemaVersion:").size())));
        try {
          mf.version = std::stoi(sv);
        } catch (...) {}
        continue;
      }

      // Check for Up/Down section markers
      if (trimmed == "-- Up" || trimmed == "-- UP" ||
          trimmed == "-- up") {
        if (in_up) {
          // Already in up, treat as regular SQL
          current_sql += line + "\n";
        } else if (in_down) {
          // Finalize down section
          mf.down_sql = current_sql;
          mf.down_statements = split_sql_statements(current_sql);
          mf.has_down = !mf.down_sql.empty();
          current_sql.clear();
          in_down = false;
          in_up = true;
        } else {
          in_up = true;
        }
        continue;
      }
      if (trimmed == "-- Down" || trimmed == "-- DOWN" ||
          trimmed == "-- down") {
        if (in_down) {
          current_sql += line + "\n";
        } else if (in_up) {
          // Finalize up section
          mf.up_sql = current_sql;
          mf.up_statements = split_sql_statements(current_sql);
          mf.has_up = !mf.up_sql.empty();
          current_sql.clear();
          in_up = false;
          in_down = true;
        } else {
          in_down = true;
        }
        continue;
      }

      // Accumulate SQL
      if (in_up || in_down) {
        current_sql += line + "\n";
      }
    }

    // Finalize last section
    if (in_up) {
      mf.up_sql = current_sql;
      mf.up_statements = split_sql_statements(current_sql);
      mf.has_up = !mf.up_sql.empty();
    } else if (in_down) {
      mf.down_sql = current_sql;
      mf.down_statements = split_sql_statements(current_sql);
      mf.has_down = !mf.down_sql.empty();
    }

    // If no markers found, treat entire file as up migration
    if (!mf.has_up && !mf.has_down && !content.empty()) {
      mf.up_sql = content;
      mf.up_statements = split_sql_statements(content);
      mf.has_up = true;
      mf.has_down = false;
      log.debug("No Up/Down markers found in " + filename +
                ", treating entire file as up migration");
    }

    // Apply metadata
    if (!metadata_description.empty())
      mf.description = metadata_description;
    if (!metadata_transactional.empty()) {
      mf.is_transactional = (metadata_transactional == "true" ||
                             metadata_transactional == "yes" ||
                             metadata_transactional == "1");
    }
    if (!metadata_duration.empty()) {
      try {
        mf.estimated_duration = chr::milliseconds(
            std::stoll(metadata_duration));
      } catch (...) {}
    }

    // Parse dependencies
    if (!metadata_deps.empty()) {
      for (auto& dep : split(metadata_deps, ',')) {
        try {
          mf.depends_on.insert(std::stoi(dep));
        } catch (...) {}
      }
    }

    // Auto-detect description from filename if not set
    if (mf.description.empty()) {
      mf.description = derive_description(filename);
    }

    if (mf.version == 0) {
      log.warn("Could not extract version from filename: " + filename);
    }

    log.info("Parsed migration v" + std::to_string(mf.version) +
             " [" + mf.filename + "] up=" +
             std::to_string(mf.up_statements.size()) + " stmts, down=" +
             std::to_string(mf.down_statements.size()) + " stmts");

    return mf;
  }

  // Parse all migration files in a directory structure
  // Supports flat directory with *.sql files or nested delta/<version>/ structure
  std::vector<MigrationFile> parse_directory(const std::string& schema_dir) {
    auto& log = get_logger("MigrationFileParser");
    std::vector<MigrationFile> migrations;

    if (!fs::exists(schema_dir)) {
      log.warn("Schema directory does not exist: " + schema_dir);
      return migrations;
    }

    // Strategy 1: Flat directory of *.sql files
    for (auto& entry : fs::directory_iterator(schema_dir)) {
      if (!entry.is_regular_file()) continue;
      if (entry.path().extension() != ".sql") continue;

      std::ifstream f(entry.path());
      if (!f) continue;

      std::stringstream ss;
      ss << f.rdbuf();
      std::string content = ss.str();

      if (!content.empty()) {
        migrations.push_back(
            parse(entry.path().filename().string(), content));
      }
    }

    // Strategy 2: Nested delta/<version>/*.sql structure (Synapse-style)
    std::string delta_path = schema_dir + "/delta";
    if (fs::exists(delta_path) && fs::is_directory(delta_path)) {
      for (auto& entry : fs::directory_iterator(delta_path)) {
        if (!entry.is_directory()) continue;
        std::string dir_ver = entry.path().filename().string();

        for (auto& df : fs::directory_iterator(entry.path())) {
          if (!df.is_regular_file()) continue;
          if (df.path().extension() != ".sql") continue;

          std::ifstream f(df.path());
          if (!f) continue;

          std::stringstream ss;
          ss << f.rdbuf();
          std::string content = ss.str();
          if (!content.empty()) {
            auto mf = parse(dir_ver + "/" + df.path().filename().string(),
                            content);
            // Override version from directory name if not already set
            if (mf.version == 0) {
              try {
                mf.version = std::stoi(dir_ver);
              } catch (...) {}
            }
            migrations.push_back(mf);
          }
        }
      }
    }

    // Strategy 3: Full schemas directory
    std::string full_path = schema_dir + "/full_schemas";
    if (fs::exists(full_path) && fs::is_directory(full_path)) {
      for (auto& entry : fs::directory_iterator(full_path)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() != ".sql") continue;

        std::ifstream f(entry.path());
        if (!f) continue;

        std::stringstream ss;
        ss << f.rdbuf();
        std::string content = ss.str();
        if (!content.empty()) {
          auto mf = parse("full/" + entry.path().filename().string(), content);
          // Full schemas may have version in filename
          if (mf.version == 0) {
            try {
              mf.version = std::stoi(entry.path().stem().string());
            } catch (...) {}
          }
          migrations.push_back(mf);
        }
      }
    }

    // Sort by version
    std::sort(migrations.begin(), migrations.end(),
              [](const MigrationFile& a, const MigrationFile& b) {
                return a.version < b.version;
              });

    log.info("Parsed " + std::to_string(migrations.size()) +
             " migration files from " + schema_dir);
    return migrations;
  }

private:
  // Extract version number from filename
  // Supports patterns: 01_initial.sql, v2_add_index.sql, 034_something.sql
  int extract_version(const std::string& filename) {
    // Strip directory prefix
    std::string name = fs::path(filename).filename().string();

    // Match leading digits
    std::regex ver_re("^(\\d+)");
    std::smatch match;
    if (std::regex_search(name, match, ver_re)) {
      return std::stoi(match[1].str());
    }

    // Match v<digits> pattern
    std::regex v_re("^v(\\d+)");
    if (std::regex_search(name, match, v_re)) {
      return std::stoi(match[1].str());
    }

    // Match version_<digits> pattern
    std::regex ver2_re("^version_(\\d+)");
    if (std::regex_search(name, match, ver2_re)) {
      return std::stoi(match[1].str());
    }

    return 0;
  }

  // Derive a human-readable description from filename
  std::string derive_description(const std::string& filename) {
    std::string name = fs::path(filename).stem().string();

    // Remove leading version prefix
    std::regex prefix_re("^(\\d+_|v\\d+_|version_\\d+_)");
    name = std::regex_replace(name, prefix_re, "");

    // Replace underscores with spaces
    std::replace(name.begin(), name.end(), '_', ' ');

    return name;
  }
};

// =============================================================================
// SchemaVersionTracker - Tracks schema version in the database
//
// Manages multiple version tables:
//   schema_version:         Current schema state per version
//   applied_schema_deltas:  Log of all applied deltas
//   migration_log:          Audit trail of migration operations
//   migration_checksums:    Checksums of applied migrations
// =============================================================================
class SchemaVersionTracker {
public:
  SchemaVersionTracker(storage::DatabasePool& db) : db_(db) {
    ensure_tracking_tables();
  }

  // Get the current schema version (highest applied)
  int current_version() {
    try {
      auto rows = db_.query(
          "SELECT MAX(version) as ver FROM " +
          std::string(TABLE_SCHEMA_VERSION) +
          " WHERE upgraded = 1");
      if (!rows.empty() && rows[0].contains("ver") &&
          !rows[0]["ver"].is_null()) {
        return rows[0]["ver"].get<int>();
      }
    } catch (const std::exception& e) {
      get_logger("SchemaVersionTracker").debug(
          "Error reading current version: " + std::string(e.what()));
    }
    return 0;
  }

  // Check if a specific migration version has been applied
  bool is_applied(int version) {
    try {
      auto rows = db_.query(
          "SELECT COUNT(*) as cnt FROM " +
          std::string(TABLE_SCHEMA_VERSION) +
          " WHERE version = " + std::to_string(version) +
          " AND upgraded = 1");
      if (!rows.empty() && rows[0].contains("cnt")) {
        return rows[0]["cnt"].get<int>() > 0;
      }
    } catch (...) {}
    return false;
  }

  // Check if a migration file has been applied (by name)
  bool is_file_applied(const std::string& filename) {
    try {
      std::string escaped = sql_escape(filename);
      auto rows = db_.query(
          "SELECT COUNT(*) as cnt FROM " +
          std::string(TABLE_APPLIED_SCHEMA_DELTAS) +
          " WHERE file = '" + escaped + "'");
      if (!rows.empty() && rows[0].contains("cnt")) {
        return rows[0]["cnt"].get<int>() > 0;
      }
    } catch (...) {}
    return false;
  }

  // Record that a migration was applied
  void record_applied(int version, const std::string& filename,
                      const std::string& description,
                      uint64_t checksum) {
    auto& log = get_logger("SchemaVersionTracker");
    std::string now = iso_timestamp_now();
    std::string escaped_file = sql_escape(filename);
    std::string escaped_desc = sql_escape(description);

    // Update or insert schema_version
    std::string sv_sql =
        "INSERT INTO " + std::string(TABLE_SCHEMA_VERSION) +
        " (version, upgraded, upgraded_by, applied_at, compat_version) "
        "VALUES (" + std::to_string(version) +
        ", 1, 'progressive-migration-engine', '" + now +
        "', '" + SCHEMA_COMPAT_VERSION + "') "
        "ON CONFLICT(version) DO UPDATE SET "
        "upgraded = 1, "
        "upgraded_by = 'progressive-migration-engine', "
        "applied_at = '" + now +
        "', compat_version = '" + SCHEMA_COMPAT_VERSION + "'";
    db_.execute(sv_sql);

    // Record in applied_schema_deltas log
    std::string delta_sql =
        "INSERT INTO " + std::string(TABLE_APPLIED_SCHEMA_DELTAS) +
        " (version, file, description, applied_at, checksum, compat_version) "
        "VALUES (" + std::to_string(version) +
        ", '" + escaped_file + "', '" + escaped_desc +
        "', '" + now + "', " + std::to_string(checksum) +
        ", '" + SCHEMA_COMPAT_VERSION + "')";
    db_.execute(delta_sql);

    log.info("Recorded migration v" + std::to_string(version) +
             " applied: " + filename);
  }

  // Record that a migration was rolled back
  void record_rolled_back(int version, const std::string& filename) {
    auto& log = get_logger("SchemaVersionTracker");
    std::string escaped_file = sql_escape(filename);

    // Mark as not upgraded in schema_version
    std::string sv_sql =
        "UPDATE " + std::string(TABLE_SCHEMA_VERSION) +
        " SET upgraded = 0 WHERE version = " + std::to_string(version);
    db_.execute(sv_sql);

    // Remove from applied_schema_deltas
    std::string delta_sql =
        "DELETE FROM " + std::string(TABLE_APPLIED_SCHEMA_DELTAS) +
        " WHERE version = " + std::to_string(version) +
        " AND file = '" + escaped_file + "'";
    db_.execute(delta_sql);

    log.info("Recorded migration v" + std::to_string(version) +
             " rolled back: " + filename);
  }

  // Get list of all applied migrations
  std::vector<json> list_applied_migrations() {
    std::vector<json> result;
    try {
      auto rows = db_.query(
          "SELECT version, file, description, applied_at, checksum, "
          "compat_version FROM " + std::string(TABLE_APPLIED_SCHEMA_DELTAS) +
          " ORDER BY version ASC");
      for (auto& row : rows) {
        json entry;
        entry["version"] = row["version"].get<int>();
        entry["file"] = row.value("file", "");
        entry["description"] = row.value("description", "");
        entry["applied_at"] = row.value("applied_at", "");
        entry["checksum"] = row["checksum"].get<uint64_t>();
        entry["compat_version"] = row.value("compat_version", "");
        result.push_back(entry);
      }
    } catch (...) {}
    return result;
  }

  // Get migration history including rollbacks
  std::vector<json> get_migration_history(int limit = 100) {
    std::vector<json> result;
    try {
      auto rows = db_.query(
          "SELECT id, version, file, direction, success, error_message, "
          "executed_at, duration_ms FROM " +
          std::string(TABLE_MIGRATION_LOG) +
          " ORDER BY id DESC LIMIT " + std::to_string(limit));
      for (auto& row : rows) {
        json entry;
        entry["id"] = row["id"].get<int64_t>();
        entry["version"] = row["version"].get<int>();
        entry["file"] = row.value("file", "");
        entry["direction"] = row.value("direction", "");
        entry["success"] = row.value("success", "1") == "1";
        entry["error_message"] = row.value("error_message", "");
        entry["executed_at"] = row.value("executed_at", "");
        entry["duration_ms"] = row["duration_ms"].get<int64_t>();
        result.push_back(entry);
      }
    } catch (...) {}
    return result;
  }

  // Get the stored checksum for a migration version
  std::optional<uint64_t> get_checksum(int version) {
    try {
      auto rows = db_.query(
          "SELECT checksum FROM " + std::string(TABLE_APPLIED_SCHEMA_DELTAS) +
          " WHERE version = " + std::to_string(version));
      if (!rows.empty() && rows[0].contains("checksum")) {
        return rows[0]["checksum"].get<uint64_t>();
      }
    } catch (...) {}
    return std::nullopt;
  }

  // Update stored checksum
  void update_checksum(int version, uint64_t checksum) {
    try {
      db_.execute(
          "UPDATE " + std::string(TABLE_APPLIED_SCHEMA_DELTAS) +
          " SET checksum = " + std::to_string(checksum) +
          " WHERE version = " + std::to_string(version));
    } catch (...) {}
  }

  // Log a migration execution
  void log_execution(int version, const std::string& filename,
                     const std::string& direction, bool success,
                     const std::string& error_message,
                     int64_t duration_ms) {
    std::string escaped_file = sql_escape(filename);
    std::string escaped_dir = sql_escape(direction);
    std::string escaped_err = sql_escape(error_message);
    std::string now = iso_timestamp_now();
    try {
      db_.execute(
          "INSERT INTO " + std::string(TABLE_MIGRATION_LOG) +
          " (version, file, direction, success, error_message, "
          "executed_at, duration_ms) VALUES (" +
          std::to_string(version) + ", '" + escaped_file + "', '" +
          escaped_dir + "', " + (success ? "1" : "0") + ", '" +
          escaped_err + "', '" + now + "', " +
          std::to_string(duration_ms) + ")");
    } catch (const std::exception& e) {
      get_logger("SchemaVersionTracker").error(
          "Failed to log migration execution: " + std::string(e.what()));
    }
  }

  // Get all applied version numbers as sorted set
  std::set<int> get_applied_versions() {
    std::set<int> result;
    try {
      auto rows = db_.query(
          "SELECT version FROM " + std::string(TABLE_SCHEMA_VERSION) +
          " WHERE upgraded = 1 ORDER BY version");
      for (auto& row : rows) {
        result.insert(row["version"].get<int>());
      }
    } catch (...) {}
    return result;
  }

private:
  storage::DatabasePool& db_;

  // Ensure tracking tables exist
  void ensure_tracking_tables() {
    auto& log = get_logger("SchemaVersionTracker");

    // schema_version table
    try {
      db_.execute(R"sql(
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER PRIMARY KEY,
            upgraded BOOLEAN NOT NULL DEFAULT TRUE,
            upgraded_by TEXT NOT NULL DEFAULT 'progressive-server',
            applied_at TEXT NOT NULL DEFAULT (datetime('now')),
            compat_version TEXT NOT NULL DEFAULT '1'
        )
      )sql");
    } catch (const std::exception& e) {
      log.warn("Failed to create schema_version: " + std::string(e.what()));
    }

    // applied_schema_deltas table
    try {
      db_.execute(R"sql(
        CREATE TABLE IF NOT EXISTS applied_schema_deltas (
            version INTEGER NOT NULL,
            file TEXT NOT NULL,
            description TEXT DEFAULT '',
            applied_at TEXT NOT NULL DEFAULT (datetime('now')),
            checksum INTEGER DEFAULT 0,
            compat_version TEXT DEFAULT '1',
            PRIMARY KEY (version, file)
        )
      )sql");
    } catch (const std::exception& e) {
      log.warn("Failed to create applied_schema_deltas: " +
               std::string(e.what()));
    }

    // migration_log table
    try {
      db_.execute(R"sql(
        CREATE TABLE IF NOT EXISTS migration_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            version INTEGER NOT NULL,
            file TEXT DEFAULT '',
            direction TEXT NOT NULL DEFAULT 'up',
            success BOOLEAN NOT NULL DEFAULT TRUE,
            error_message TEXT DEFAULT '',
            executed_at TEXT NOT NULL DEFAULT (datetime('now')),
            duration_ms INTEGER DEFAULT 0
        )
      )sql");
      db_.execute(R"sql(
        CREATE INDEX IF NOT EXISTS idx_migration_log_version
        ON migration_log(version)
      )sql");
      db_.execute(R"sql(
        CREATE INDEX IF NOT EXISTS idx_migration_log_executed
        ON migration_log(executed_at)
      )sql");
    } catch (const std::exception& e) {
      log.warn("Failed to create migration_log: " + std::string(e.what()));
    }

    // migration_checksums table
    try {
      db_.execute(R"sql(
        CREATE TABLE IF NOT EXISTS migration_checksums (
            version INTEGER PRIMARY KEY,
            checksum INTEGER NOT NULL,
            file TEXT NOT NULL,
            verified_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
      )sql");
    } catch (const std::exception& e) {
      log.warn("Failed to create migration_checksums: " +
               std::string(e.what()));
    }

    // migration_locks table
    try {
      db_.execute(R"sql(
        CREATE TABLE IF NOT EXISTS migration_locks (
            lock_name TEXT PRIMARY KEY,
            locked_by TEXT NOT NULL,
            locked_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT,
            purpose TEXT DEFAULT ''
        )
      )sql");
    } catch (const std::exception& e) {
      log.warn("Failed to create migration_locks: " +
               std::string(e.what()));
    }

    // background_migrations table
    try {
      db_.execute(R"sql(
        CREATE TABLE IF NOT EXISTS background_migrations (
            name TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'pending',
            depends_on TEXT DEFAULT '',
            batch_size INTEGER DEFAULT 100,
            ordering INTEGER DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            started_at TEXT,
            completed_at TEXT,
            error_message TEXT DEFAULT '',
            retry_count INTEGER DEFAULT 0
        )
      )sql");
    } catch (const std::exception& e) {
      log.warn("Failed to create background_migrations: " +
               std::string(e.what()));
    }

    // bg_migration_progress table
    try {
      db_.execute(R"sql(
        CREATE TABLE IF NOT EXISTS bg_migration_progress (
            name TEXT NOT NULL,
            progress_key TEXT NOT NULL DEFAULT 'main',
            total_rows INTEGER DEFAULT 0,
            processed_rows INTEGER DEFAULT 0,
            progress_json TEXT DEFAULT '{}',
            updated_at TEXT NOT NULL DEFAULT (datetime('now')),
            PRIMARY KEY (name, progress_key)
        )
      )sql");
    } catch (const std::exception& e) {
      log.warn("Failed to create bg_migration_progress: " +
               std::string(e.what()));
    }
  }
};

// =============================================================================
// MigrationDependencyGraph - Builds and manages dependency relationships
//
// Features:
//   - Topological ordering of migrations
//   - Cycle detection
//   - Dependency resolution
//   - Calculates upgrade/downgrade paths
// =============================================================================
class MigrationDependencyGraph {
public:
  MigrationDependencyGraph() = default;

  // Build graph from parsed migration files
  void build(const std::vector<MigrationFile>& migrations) {
    nodes_.clear();
    for (auto& m : migrations) {
      nodes_[m.version] = m;
      version_order_.push_back(m.version);
    }
    std::sort(version_order_.begin(), version_order_.end());

    // Build reverse dependency map
    for (auto& [ver, mf] : nodes_) {
      for (int dep : mf.depends_on) {
        if (nodes_.count(dep)) {
          nodes_[dep].required_by.insert(ver);
        }
      }
    }
  }

  // Topological sort - returns versions in dependency-respecting order
  std::vector<int> topological_order() {
    std::vector<int> result;
    std::map<int, int> in_degree;
    std::set<int> visited;

    for (auto& [ver, mf] : nodes_) {
      if (in_degree.find(ver) == in_degree.end()) {
        in_degree[ver] = 0;
      }
      for (int dep : mf.depends_on) {
        in_degree[ver]++;
      }
    }

    // Use Kahn's algorithm
    std::queue<int> q;
    for (auto& [ver, deg] : in_degree) {
      if (deg == 0) q.push(ver);
    }

    while (!q.empty()) {
      int ver = q.front();
      q.pop();
      result.push_back(ver);
      visited.insert(ver);

      auto it = nodes_.find(ver);
      if (it != nodes_.end()) {
        for (int req : it->second.required_by) {
          in_degree[req]--;
          if (in_degree[req] == 0 && visited.find(req) == visited.end()) {
            q.push(req);
          }
        }
      }
    }

    // If not all nodes visited, there's a cycle
    if (result.size() < nodes_.size()) {
      get_logger("MigrationDependencyGraph").error(
          "Cycle detected in migration dependency graph! " +
          std::to_string(result.size()) + "/" +
          std::to_string(nodes_.size()) + " nodes visited");
      // Fall back to numerical sort
      result = version_order_;
    }

    return result;
  }

  // Detect cycles in the dependency graph
  std::vector<std::vector<int>> detect_cycles() {
    std::vector<std::vector<int>> cycles;
    std::set<int> all_versions;
    for (auto& [ver, mf] : nodes_) all_versions.insert(ver);

    // DFS-based cycle detection
    enum class Color { WHITE, GRAY, BLACK };
    std::map<int, Color> color;
    std::map<int, int> parent;
    for (int v : all_versions) color[v] = Color::WHITE;

    std::function<void(int, std::vector<int>&)> dfs =
        [&](int v, std::vector<int>& path) {
      color[v] = Color::GRAY;
      path.push_back(v);

      auto it = nodes_.find(v);
      if (it != nodes_.end()) {
        for (int dep : it->second.depends_on) {
          if (color[dep] == Color::GRAY) {
            // Found a cycle - extract it
            std::vector<int> cycle;
            auto cycle_start = std::find(path.begin(), path.end(), dep);
            if (cycle_start != path.end()) {
              for (auto ci = cycle_start; ci != path.end(); ++ci) {
                cycle.push_back(*ci);
              }
              cycle.push_back(dep);
              cycles.push_back(cycle);
            }
          } else if (color[dep] == Color::WHITE) {
            parent[dep] = v;
            dfs(dep, path);
          }
        }
      }

      path.pop_back();
      color[v] = Color::BLACK;
    };

    std::vector<int> path;
    for (int v : all_versions) {
      if (color[v] == Color::WHITE) {
        dfs(v, path);
      }
    }

    return cycles;
  }

  // Get the upgrade path from current version to target
  std::vector<int> upgrade_path(int from_version, int to_version) {
    std::vector<int> path;
    for (int ver : version_order_) {
      if (ver > from_version && ver <= to_version) {
        path.push_back(ver);
      }
    }

    // Check dependencies and reorder if needed
    if (!path.empty()) {
      auto topo = topological_order();
      std::vector<int> reordered;
      std::set<int> path_set(path.begin(), path.end());
      for (int ver : topo) {
        if (path_set.count(ver)) {
          reordered.push_back(ver);
        }
      }
      if (reordered.size() == path.size()) {
        path = reordered;
      }
    }

    return path;
  }

  // Get the downgrade path from current version to target
  std::vector<int> downgrade_path(int from_version, int to_version) {
    std::vector<int> path;
    // Reverse order for downgrade
    for (auto it = version_order_.rbegin(); it != version_order_.rend(); ++it) {
      if (*it <= from_version && *it > to_version) {
        path.push_back(*it);
      }
    }
    return path;
  }

  // Get all dependencies for a version (recursive)
  std::set<int> get_all_dependencies(int version) {
    std::set<int> result;
    std::function<void(int)> collect = [&](int v) {
      auto it = nodes_.find(v);
      if (it == nodes_.end()) return;
      for (int dep : it->second.depends_on) {
        if (result.insert(dep).second) {
          collect(dep);
        }
      }
    };
    collect(version);
    return result;
  }

  // Get all dependents for a version (recursive - who needs this)
  std::set<int> get_all_dependents(int version) {
    std::set<int> result;
    std::function<void(int)> collect = [&](int v) {
      auto it = nodes_.find(v);
      if (it == nodes_.end()) return;
      for (int req : it->second.required_by) {
        if (result.insert(req).second) {
          collect(req);
        }
      }
    };
    collect(version);
    return result;
  }

  // Check if a version has all its dependencies satisfied
  bool dependencies_satisfied(int version,
                              const std::set<int>& applied_versions) {
    auto it = nodes_.find(version);
    if (it == nodes_.end()) return true;
    for (int dep : it->second.depends_on) {
      if (applied_versions.find(dep) == applied_versions.end()) {
        return false;
      }
    }
    return true;
  }

  // Get migration file by version
  const MigrationFile* get_migration(int version) const {
    auto it = nodes_.find(version);
    if (it != nodes_.end()) return &it->second;
    return nullptr;
  }

  // Export dependency graph as JSON for visualization
  json to_json() const {
    json j;
    j["nodes"] = json::array();
    j["edges"] = json::array();

    for (auto& [ver, mf] : nodes_) {
      json node;
      node["version"] = ver;
      node["filename"] = mf.filename;
      node["description"] = mf.description;
      j["nodes"].push_back(node);

      for (int dep : mf.depends_on) {
        json edge;
        edge["from"] = dep;
        edge["to"] = ver;
        j["edges"].push_back(edge);
      }
    }
    return j;
  }

  // Get all versions
  const std::vector<int>& versions() const { return version_order_; }

  // Count
  size_t size() const { return nodes_.size(); }

private:
  std::map<int, MigrationFile> nodes_;
  std::vector<int> version_order_;
};

// =============================================================================
// MigrationLockManager - Prevents concurrent migration runs
//
// Uses database-level locks so multiple processes/workers don't conflict.
// =============================================================================
class MigrationLockManager {
public:
  MigrationLockManager(storage::DatabasePool& db) : db_(db) {
    ensure_lock_table();
  }

  // Acquire the global migration lock
  bool acquire_lock(const std::string& lock_name = "global_migration",
                    chr::seconds timeout = DEFAULT_LOCK_TIMEOUT) {
    auto& log = get_logger("MigrationLockManager");
    std::string now = iso_timestamp_now();
    std::string expires = iso_timestamp_now();
    // We compute expires by adding timeout - approximate with string
    // for SQLite; in production use DB-specific date arithmetic

    // Try to cleanup expired locks first
    cleanup_expired_locks();

    // Try to acquire
    try {
      std::string escaped_name = sql_escape(lock_name);
      std::string escaped_purpose = sql_escape("migration_run");

      // Use INSERT OR IGNORE for atomic lock acquisition
      db_.execute(
          "INSERT OR IGNORE INTO " + std::string(TABLE_MIGRATION_LOCKS) +
          " (lock_name, locked_by, locked_at, expires_at, purpose) "
          "VALUES ('" + escaped_name +
          "', 'migration-engine', '" + now +
          "', '" + expires + "', '" + escaped_purpose + "')");

      // Check if we got the lock
      auto rows = db_.query(
          "SELECT locked_by FROM " + std::string(TABLE_MIGRATION_LOCKS) +
          " WHERE lock_name = '" + escaped_name + "'");
      if (!rows.empty()) {
        std::string locked_by = rows[0].value("locked_by", "");
        if (locked_by == "migration-engine") {
          log.info("Acquired migration lock: " + lock_name);
          held_locks_.insert(lock_name);
          return true;
        }
      }
    } catch (const std::exception& e) {
      log.error("Failed to acquire lock: " + std::string(e.what()));
    }

    log.warn("Could not acquire migration lock: " + lock_name +
             " (another migration may be running)");
    return false;
  }

  // Release a specific lock
  void release_lock(const std::string& lock_name = "global_migration") {
    auto& log = get_logger("MigrationLockManager");
    try {
      std::string escaped_name = sql_escape(lock_name);
      db_.execute(
          "DELETE FROM " + std::string(TABLE_MIGRATION_LOCKS) +
          " WHERE lock_name = '" + escaped_name +
          "' AND locked_by = 'migration-engine'");
      held_locks_.erase(lock_name);
      log.info("Released migration lock: " + lock_name);
    } catch (const std::exception& e) {
      log.error("Failed to release lock: " + std::string(e.what()));
    }
  }

  // Release all held locks
  void release_all() {
    auto locks = held_locks_;
    for (auto& lock : locks) {
      release_lock(lock);
    }
  }

  // Check if a lock is held
  bool is_locked(const std::string& lock_name = "global_migration") {
    try {
      std::string escaped_name = sql_escape(lock_name);
      auto rows = db_.query(
          "SELECT COUNT(*) as cnt FROM " +
          std::string(TABLE_MIGRATION_LOCKS) +
          " WHERE lock_name = '" + escaped_name + "'");
      if (!rows.empty() && rows[0].contains("cnt")) {
        return rows[0]["cnt"].get<int>() > 0;
      }
    } catch (...) {}
    return false;
  }

  // Force release a lock (admin operation)
  bool force_release(const std::string& lock_name = "global_migration") {
    try {
      std::string escaped_name = sql_escape(lock_name);
      db_.execute(
          "DELETE FROM " + std::string(TABLE_MIGRATION_LOCKS) +
          " WHERE lock_name = '" + escaped_name + "'");
      held_locks_.erase(lock_name);
      return true;
    } catch (...) {
      return false;
    }
  }

  // Get lock info
  json get_lock_info(const std::string& lock_name = "global_migration") {
    json j;
    try {
      std::string escaped_name = sql_escape(lock_name);
      auto rows = db_.query(
          "SELECT * FROM " + std::string(TABLE_MIGRATION_LOCKS) +
          " WHERE lock_name = '" + escaped_name + "'");
      if (!rows.empty()) {
        auto& row = rows[0];
        j["lock_name"] = row.value("lock_name", "");
        j["locked_by"] = row.value("locked_by", "");
        j["locked_at"] = row.value("locked_at", "");
        j["expires_at"] = row.value("expires_at", "");
        j["purpose"] = row.value("purpose", "");
        j["held"] = true;
      } else {
        j["lock_name"] = lock_name;
        j["held"] = false;
      }
    } catch (...) {
      j["error"] = "Failed to query lock info";
    }
    return j;
  }

  ~MigrationLockManager() {
    release_all();
  }

private:
  storage::DatabasePool& db_;
  std::set<std::string> held_locks_;

  void ensure_lock_table() {
    try {
      db_.execute(R"sql(
        CREATE TABLE IF NOT EXISTS migration_locks (
            lock_name TEXT PRIMARY KEY,
            locked_by TEXT NOT NULL,
            locked_at TEXT NOT NULL DEFAULT (datetime('now')),
            expires_at TEXT,
            purpose TEXT DEFAULT ''
        )
      )sql");
    } catch (...) {}
  }

  void cleanup_expired_locks() {
    try {
      std::string now = iso_timestamp_now();
      db_.execute(
          "DELETE FROM " + std::string(TABLE_MIGRATION_LOCKS) +
          " WHERE expires_at IS NOT NULL AND expires_at < '" + now + "'");
    } catch (...) {}
  }
};

// =============================================================================
// MigrationChecksumVerifier - Verifies checksums of applied migrations
//
// Detects if a migration file was changed after being applied.
// =============================================================================
class MigrationChecksumVerifier {
public:
  MigrationChecksumVerifier(SchemaVersionTracker& tracker)
    : tracker_(tracker) {}

  // Verify a migration's checksum against what was recorded
  bool verify(int version, uint64_t current_checksum) {
    auto stored = tracker_.get_checksum(version);
    if (!stored.has_value()) {
      // No checksum stored - first time
      tracker_.update_checksum(version, current_checksum);
      return true;
    }
    return *stored == current_checksum;
  }

  // Verify all migrations in a parsed set
  struct VerificationResult {
    int version;
    std::string filename;
    bool matches;
    uint64_t expected;
    uint64_t actual;
  };

  std::vector<VerificationResult> verify_all(
      const std::vector<MigrationFile>& migrations) {
    auto& log = get_logger("MigrationChecksumVerifier");
    std::vector<VerificationResult> results;

    for (auto& mf : migrations) {
      if (!tracker_.is_applied(mf.version)) continue;

      VerificationResult vr;
      vr.version = mf.version;
      vr.filename = mf.filename;
      vr.actual = mf.checksum;

      auto stored = tracker_.get_checksum(mf.version);
      if (stored.has_value()) {
        vr.expected = *stored;
        vr.matches = (vr.expected == vr.actual);
        if (!vr.matches) {
          log.error("Checksum mismatch for migration v" +
                    std::to_string(mf.version) + " (" + mf.filename +
                    "): expected " + std::to_string(vr.expected) +
                    ", got " + std::to_string(vr.actual));
        }
      } else {
        vr.expected = 0;
        vr.matches = true; // No checksum stored = first verification
        tracker_.update_checksum(mf.version, mf.actual);
      }

      results.push_back(vr);
    }

    return results;
  }

  // Store or update checksum
  void store_checksum(int version, uint64_t checksum) {
    tracker_.update_checksum(version, checksum);
  }

private:
  SchemaVersionTracker& tracker_;
};

// =============================================================================
// MigrationAuditLogger - Comprehensive audit trail for all migration ops
// =============================================================================
class MigrationAuditLogger {
public:
  MigrationAuditLogger(SchemaVersionTracker& tracker) : tracker_(tracker) {}

  struct AuditEntry {
    std::string timestamp;
    int version;
    std::string filename;
    std::string direction;
    bool success;
    std::string error;
    int64_t duration_ms;
    std::string executed_by;
    int rolled_back_from;  // If this was a rollback

    json to_json() const {
      json j;
      j["timestamp"] = timestamp;
      j["version"] = version;
      j["filename"] = filename;
      j["direction"] = direction;
      j["success"] = success;
      j["error"] = error;
      j["duration_ms"] = duration_ms;
      j["executed_by"] = executed_by;
      j["rolled_back_from"] = rolled_back_from;
      return j;
    }
  };

  void log(const AuditEntry& entry) {
    tracker_.log_execution(entry.version, entry.filename, entry.direction,
                           entry.success, entry.error, entry.duration_ms);
    history_.push_back(entry);
    if (history_.size() > 10000) {
      history_.erase(history_.begin(),
                     history_.begin() + (history_.size() - 5000));
    }
  }

  const std::vector<AuditEntry>& history() const { return history_; }

private:
  SchemaVersionTracker& tracker_;
  std::vector<AuditEntry> history_;
};

// =============================================================================
// MigrationDryRunner - Validates migrations without executing them
//
// Checks SQL syntax, dependency validity, and estimates timing.
// =============================================================================
class MigrationDryRunner {
public:
  MigrationDryRunner() = default;

  struct DryRunResult {
    int version;
    std::string filename;
    std::string direction;
    bool valid;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    std::vector<std::string> statements;
    int estimated_duration_ms;

    json to_json() const {
      json j;
      j["version"] = version;
      j["filename"] = filename;
      j["direction"] = direction;
      j["valid"] = valid;
      j["warnings"] = warnings;
      j["errors"] = errors;
      j["statement_count"] = statements.size();
      j["estimated_duration_ms"] = estimated_duration_ms;
      return j;
    }
  };

  // Dry run a set of migrations
  std::vector<DryRunResult> dry_run(
      const std::vector<MigrationFile>& migrations,
      MigrationDirection direction,
      const MigrationDependencyGraph& graph) {
    auto& log = get_logger("MigrationDryRunner");
    std::vector<DryRunResult> results;

    for (auto& mf : migrations) {
      DryRunResult result;
      result.version = mf.version;
      result.filename = mf.filename;
      result.direction = direction_str(direction);
      result.valid = true;
      result.estimated_duration_ms = mf.estimated_duration.count();

      // Check SQL statements
      const std::vector<std::string>* stmts = nullptr;
      if (direction == MigrationDirection::UP ||
          direction == MigrationDirection::BOTH) {
        stmts = &mf.up_statements;
      } else {
        stmts = &mf.down_statements;
      }

      if (stmts) {
        result.statements = *stmts;

        // Basic validation of each statement
        for (size_t i = 0; i < stmts->size(); ++i) {
          const auto& stmt = (*stmts)[i];
          validate_statement(stmt, result, static_cast<int>(i));
        }
      }

      // Check dependencies
      if (!mf.depends_on.empty()) {
        for (int dep : mf.depends_on) {
          if (graph.get_migration(dep) == nullptr) {
            result.warnings.push_back(
                "Dependency v" + std::to_string(dep) +
                " not found in available migrations");
          }
        }
      }

      // Check if up/down sections exist
      if (direction == MigrationDirection::UP && !mf.has_up) {
        result.warnings.push_back("No Up section found");
      }
      if (direction == MigrationDirection::DOWN && !mf.has_down) {
        result.warnings.push_back("No Down section found - rollback not possible");
      }

      results.push_back(result);
    }

    return results;
  }

private:
  void validate_statement(const std::string& stmt, DryRunResult& result,
                          int index) {
    std::string upper = stmt;
    std::transform(upper.begin(), upper.end(), upper.begin(),
                   [](char c) { return static_cast<char>(std::toupper(c)); });

    // Check for dangerous operations in dry-run
    auto trimmed = trim_view(upper);

    if (starts_with(trimmed, "DROP TABLE")) {
      result.warnings.push_back(
          "Statement " + std::to_string(index) +
          " drops a table: " + std::string(trimmed).substr(0, 80));
    }
    if (starts_with(trimmed, "DROP INDEX")) {
      result.warnings.push_back(
          "Statement " + std::to_string(index) + " drops an index");
    }
    if (starts_with(trimmed, "DELETE FROM") &&
        trimmed.find("WHERE") == std::string::npos) {
      result.warnings.push_back(
          "Statement " + std::to_string(index) +
          " is an unconditional DELETE");
    }
    if (starts_with(trimmed, "UPDATE") &&
        trimmed.find("WHERE") == std::string::npos) {
      result.warnings.push_back(
          "Statement " + std::to_string(index) +
          " is an unconditional UPDATE");
    }

    // Check for missing semicolon (non-block statements)
    if (!starts_with(trimmed, "BEGIN") && !starts_with(trimmed, "COMMIT") &&
        !starts_with(trimmed, "END") && stmt.back() != ';') {
      result.warnings.push_back(
          "Statement " + std::to_string(index) +
          " may be missing a semicolon");
    }
  }
};

// =============================================================================
// BackgroundMigrationManager - Manages long-running background migrations
//
// Background migrations run in small batches to avoid blocking the main
// event processing loop. They are used for data backfills, index creation
// on large tables, and similar long-running operations.
//
// Equivalent to:
//   synapse/storage/background_updates.py
//   synapse/storage/databases/main/events_bg_updates.py
// =============================================================================
class BackgroundMigrationManager {
public:
  BackgroundMigrationManager(storage::DatabasePool& db)
    : db_(db), running_(false), paused_(false) {}

  // Register a background migration
  void register_migration(const std::string& name,
                          const std::string& depends_on = "",
                          int ordering = 0,
                          int64_t batch_size = DEFAULT_BG_BATCH_SIZE,
                          bool run_as_background_process = false) {
    std::string escaped_name = sql_escape(name);
    std::string escaped_deps = sql_escape(depends_on);
    std::string now = iso_timestamp_now();

    try {
      db_.execute(
          "INSERT OR IGNORE INTO " +
          std::string(TABLE_BACKGROUND_MIGRATIONS) +
          " (name, status, depends_on, batch_size, ordering, created_at) "
          "VALUES ('" + escaped_name + "', 'pending', '" +
          escaped_deps + "', " + std::to_string(batch_size) +
          ", " + std::to_string(ordering) + ", '" + now + "')");
    } catch (const std::exception& e) {
      get_logger("BackgroundMigrationManager").error(
          "Failed to register migration '" + name + "': " + e.what());
    }
  }

  // Get next pending background migration ready to run
  std::optional<std::string> get_next_pending() {
    try {
      auto rows = db_.query(
          "SELECT bm.name FROM " +
          std::string(TABLE_BACKGROUND_MIGRATIONS) + " bm "
          "WHERE bm.status = 'pending' "
          "AND (bm.depends_on IS NULL OR bm.depends_on = '' "
          "  OR NOT EXISTS ("
          "    SELECT 1 FROM " +
          std::string(TABLE_BACKGROUND_MIGRATIONS) + " dep "
          "    WHERE dep.name = bm.depends_on "
          "    AND dep.status != 'completed'"
          "  )) "
          "ORDER BY bm.ordering ASC, bm.name ASC LIMIT 1");
      if (!rows.empty()) {
        return rows[0]["name"].get<std::string>();
      }
    } catch (...) {}
    return std::nullopt;
  }

  // Start a background migration
  bool start_migration(const std::string& name) {
    std::string escaped_name = sql_escape(name);
    std::string now = iso_timestamp_now();
    try {
      db_.execute(
          "UPDATE " + std::string(TABLE_BACKGROUND_MIGRATIONS) +
          " SET status = 'running', started_at = '" + now +
          "' WHERE name = '" + escaped_name + "' AND status = 'pending'");
      return true;
    } catch (...) {
      return false;
    }
  }

  // Update progress for a background migration
  void update_progress(const std::string& name,
                       int64_t total_rows,
                       int64_t processed_rows,
                       const json& progress_data = json::object()) {
    std::string escaped_name = sql_escape(name);
    std::string now = iso_timestamp_now();
    std::string progress_str = sql_escape(progress_data.dump());

    try {
      db_.execute(
          "INSERT OR REPLACE INTO " +
          std::string(TABLE_BG_MIGRATION_PROGRESS) +
          " (name, progress_key, total_rows, processed_rows, "
          "progress_json, updated_at) "
          "VALUES ('" + escaped_name + "', 'main', " +
          std::to_string(total_rows) + ", " +
          std::to_string(processed_rows) + ", '" +
          progress_str + "', '" + now + "')");
    } catch (const std::exception& e) {
      get_logger("BackgroundMigrationManager").error(
          "Failed to update progress for '" + name + "': " + e.what());
    }
  }

  // Get progress for a background migration
  json get_progress(const std::string& name) {
    std::string escaped_name = sql_escape(name);
    try {
      auto rows = db_.query(
          "SELECT total_rows, processed_rows, progress_json, updated_at "
          "FROM " + std::string(TABLE_BG_MIGRATION_PROGRESS) +
          " WHERE name = '" + escaped_name + "' AND progress_key = 'main'");
      if (!rows.empty()) {
        auto& row = rows[0];
        json j;
        j["name"] = name;
        j["total_rows"] = row["total_rows"].get<int64_t>();
        j["processed_rows"] = row["processed_rows"].get<int64_t>();
        j["updated_at"] = row.value("updated_at", "");
        double pct = 0.0;
        if (j["total_rows"].get<int64_t>() > 0) {
          pct = static_cast<double>(j["processed_rows"].get<int64_t>()) /
                static_cast<double>(j["total_rows"].get<int64_t>()) * 100.0;
        }
        j["progress_pct"] = std::round(pct * 100.0) / 100.0;

        try {
          j["data"] = json::parse(row.value("progress_json", "{}"));
        } catch (...) {
          j["data"] = json::object();
        }

        return j;
      }
    } catch (...) {}
    json j;
    j["name"] = name;
    j["total_rows"] = 0;
    j["processed_rows"] = 0;
    j["progress_pct"] = 0.0;
    return j;
  }

  // Complete a background migration
  void complete_migration(const std::string& name) {
    std::string escaped_name = sql_escape(name);
    std::string now = iso_timestamp_now();
    try {
      db_.execute(
          "UPDATE " + std::string(TABLE_BACKGROUND_MIGRATIONS) +
          " SET status = 'completed', completed_at = '" + now +
          "' WHERE name = '" + escaped_name + "'");
    } catch (...) {}
  }

  // Mark a background migration as failed
  void fail_migration(const std::string& name,
                      const std::string& error_message) {
    std::string escaped_name = sql_escape(name);
    std::string escaped_err = sql_escape(error_message);
    try {
      db_.execute(
          "UPDATE " + std::string(TABLE_BACKGROUND_MIGRATIONS) +
          " SET status = 'failed', error_message = '" + escaped_err +
          "', retry_count = retry_count + 1 "
          "WHERE name = '" + escaped_name + "'");
    } catch (...) {}
  }

  // Reset a failed migration for retry
  void reset_migration(const std::string& name) {
    std::string escaped_name = sql_escape(name);
    try {
      db_.execute(
          "UPDATE " + std::string(TABLE_BACKGROUND_MIGRATIONS) +
          " SET status = 'pending', error_message = '' "
          "WHERE name = '" + escaped_name + "'");
    } catch (...) {}
  }

  // Pause all background migrations
  void pause_all() {
    paused_ = true;
  }

  // Resume all background migrations
  void resume_all() {
    paused_ = false;
  }

  // List all background migrations
  json list_all() {
    json result = json::array();
    try {
      auto rows = db_.query(
          "SELECT bm.name, bm.status, bm.depends_on, bm.batch_size, "
          "bm.ordering, bm.created_at, bm.started_at, bm.completed_at, "
          "bm.error_message, bm.retry_count, "
          "bp.total_rows, bp.processed_rows "
          "FROM " + std::string(TABLE_BACKGROUND_MIGRATIONS) + " bm "
          "LEFT JOIN " + std::string(TABLE_BG_MIGRATION_PROGRESS) + " bp "
          "ON bm.name = bp.name AND bp.progress_key = 'main' "
          "ORDER BY bm.ordering ASC");
      for (auto& row : rows) {
        json entry;
        entry["name"] = row.value("name", "");
        entry["status"] = row.value("status", "");
        entry["depends_on"] = row.value("depends_on", "");
        entry["batch_size"] = row["batch_size"].get<int64_t>();
        entry["ordering"] = row["ordering"].get<int>();
        entry["created_at"] = row.value("created_at", "");
        entry["started_at"] = row.value("started_at", "");
        entry["completed_at"] = row.value("completed_at", "");
        entry["error_message"] = row.value("error_message", "");
        entry["retry_count"] = row["retry_count"].get<int>();

        int64_t total = row.value("total_rows", 0);
        int64_t processed = row.value("processed_rows", 0);
        entry["total_rows"] = total;
        entry["processed_rows"] = processed;
        double pct = 0.0;
        if (total > 0) {
          pct = static_cast<double>(processed) /
                static_cast<double>(total) * 100.0;
        }
        entry["progress_pct"] = std::round(pct * 100.0) / 100.0;

        result.push_back(entry);
      }
    } catch (...) {}
    return result;
  }

  // Check if manager is paused
  bool is_paused() const { return paused_; }

  // Check if manager is running
  bool is_running() const { return running_; }

  // Set running state
  void set_running(bool r) { running_ = r; }

  // Run background migrations in a loop (call from a dedicated thread)
  void run_loop(std::function<bool(const std::string&, int64_t)> batch_callback,
                int64_t batch_size = DEFAULT_BG_BATCH_SIZE,
                chr::seconds poll_interval = BG_MIGRATION_POLL_INTERVAL) {
    running_ = true;
    auto& log = get_logger("BackgroundMigrationManager");
    log.info("Background migration loop started");

    while (running_) {
      if (paused_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        continue;
      }

      auto next = get_next_pending();
      if (!next.has_value()) {
        std::this_thread::sleep_for(poll_interval);
        continue;
      }

      std::string name = *next;
      log.info("Starting background migration: " + name);
      start_migration(name);

      bool success = true;
      try {
        success = batch_callback(name, batch_size);
      } catch (const std::exception& e) {
        log.error("Background migration '" + name +
                  "' threw exception: " + e.what());
        fail_migration(name, e.what());
        success = false;
      }

      if (success) {
        complete_migration(name);
        log.info("Background migration completed: " + name);
      } else {
        log.warn("Background migration incomplete, will retry: " + name);
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    log.info("Background migration loop stopped");
  }

  // Stop the loop
  void stop() {
    running_ = false;
  }

private:
  storage::DatabasePool& db_;
  std::atomic<bool> running_;
  std::atomic<bool> paused_;
};

// =============================================================================
// SchemaCompatEnforcer - Enforces SCHEMA_COMPAT_VERSION across the cluster
//
// Ensures that all nodes in a cluster agree on the schema compatibility
// version. If a node attempts to run with a different version, the
// enforcement mechanism blocks it or raises alerts.
//
// Equivalent to synapse.storage.schema.SCHEMA_COMPAT_VERSION checks.
// =============================================================================
class SchemaCompatEnforcer {
public:
  SchemaCompatEnforcer(storage::DatabasePool& db,
                       const std::string& expected_version = SCHEMA_COMPAT_VERSION)
    : db_(db), expected_version_(expected_version) {
    ensure_compat_table();
  }

  // Check compatibility on startup
  struct CompatResult {
    bool compatible;
    std::string db_version;
    std::string expected_version;
    std::string message;
    bool needs_upgrade;

    json to_json() const {
      json j;
      j["compatible"] = compatible;
      j["db_version"] = db_version;
      j["expected_version"] = expected_version;
      j["message"] = message;
      j["needs_upgrade"] = needs_upgrade;
      return j;
    }
  };

  CompatResult check_compatibility() {
    auto& log = get_logger("SchemaCompatEnforcer");
    CompatResult result;
    result.expected_version = expected_version_;

    result.db_version = get_stored_version();
    if (result.db_version.empty()) {
      // No version stored yet - set it
      set_version(expected_version_);
      result.db_version = expected_version_;
      result.compatible = true;
      result.message = "Initialized schema compat version to " +
                       expected_version_;
      result.needs_upgrade = false;
      log.info(result.message);
      return result;
    }

    result.compatible = (result.db_version == expected_version_);

    if (result.compatible) {
      result.message = "Schema compat version matches: " + expected_version_;
      result.needs_upgrade = false;
    } else {
      // Check if this is a newer version (upgrade in progress)
      try {
        int db_ver = std::stoi(result.db_version);
        int exp_ver = std::stoi(expected_version_);
        if (db_ver < exp_ver) {
          result.message = "Schema compat version needs upgrade from " +
                           result.db_version + " to " + expected_version_;
          result.needs_upgrade = true;
        } else {
          result.message = "Database schema version (" + result.db_version +
                           ") is newer than expected (" + expected_version_ +
                           "). This software may be out of date.";
          result.needs_upgrade = false;
        }
      } catch (...) {
        result.message = "Schema compat version mismatch: db=" +
                         result.db_version + " expected=" +
                         expected_version_;
        result.needs_upgrade = false;
      }

      log.warn(result.message);
    }

    return result;
  }

  // Enforce compatibility (throws on mismatch if strict)
  void enforce(bool strict = true) {
    auto result = check_compatibility();
    if (!result.compatible && strict) {
      throw std::runtime_error(
          "SCHEMA_COMPAT_VERSION mismatch: " + result.message);
    }
  }

  // Get the stored version
  std::string get_stored_version() {
    try {
      auto rows = db_.query(
          "SELECT compat_version FROM " +
          std::string(SCHEMA_COMPAT_VERSION_TABLE) +
          " WHERE lock = '" + std::string(SCHEMA_COMPAT_LOCK_KEY) + "'");
      if (!rows.empty()) {
        return rows[0].value("compat_version", "");
      }
    } catch (...) {}
    return "";
  }

  // Set/update the stored version
  void set_version(const std::string& version) {
    std::string escaped_ver = sql_escape(version);
    try {
      db_.execute(
          "INSERT OR REPLACE INTO " +
          std::string(SCHEMA_COMPAT_VERSION_TABLE) +
          " (lock, compat_version) VALUES ('" +
          std::string(SCHEMA_COMPAT_LOCK_KEY) + "', '" +
          escaped_ver + "')");
    } catch (const std::exception& e) {
      get_logger("SchemaCompatEnforcer").error(
          "Failed to set compat version: " + std::string(e.what()));
    }
  }

  // Bump the compat version after a migration
  void bump_version(const std::string& new_version) {
    set_version(new_version);
    expected_version_ = new_version;
  }

  // Validate that all schema_version entries have matching compat_version
  json validate_all_entries() {
    json result;
    result["ok"] = true;
    result["mismatches"] = json::array();
    try {
      auto rows = db_.query(
          "SELECT version, compat_version FROM " +
          std::string(TABLE_SCHEMA_VERSION));
      for (auto& row : rows) {
        int version = row["version"].get<int>();
        std::string cv = row.value("compat_version", "");
        if (cv != expected_version_ && cv != "" && cv != "1") {
          json mismatch;
          mismatch["version"] = version;
          mismatch["stored"] = cv;
          mismatch["expected"] = expected_version_;
          result["mismatches"].push_back(mismatch);
          result["ok"] = false;
        }
      }
    } catch (...) {}
    return result;
  }

private:
  storage::DatabasePool& db_;
  std::string expected_version_;

  void ensure_compat_table() {
    try {
      db_.execute(R"sql(
        CREATE TABLE IF NOT EXISTS schema_compat_version (
            lock TEXT PRIMARY KEY DEFAULT 'compat_version_lock',
            compat_version INTEGER NOT NULL
        )
      )sql");
    } catch (...) {}
  }
};

// =============================================================================
// MigrationRunner - Core migration execution engine
//
// Orchestrates the full migration lifecycle:
//   1. Parse migration files
//   2. Build dependency graph
//   3. Acquire lock
//   4. Check compat version
//   5. Execute migrations in order within transactions
//   6. Record results
//   7. Release lock
//
// Supports:
//   - Upgrading to latest
//   - Upgrading to specific version
//   - Rolling back to specific version
//   - Bootstrap from scratch
//   - Dry-run mode
// =============================================================================
class MigrationRunner {
public:
  MigrationRunner(storage::DatabasePool& db,
                  const std::string& schema_dir)
    : db_(db),
      schema_dir_(schema_dir),
      version_tracker_(db),
      lock_manager_(db),
      bg_manager_(db),
      compat_enforcer_(db),
      checksum_verifier_(version_tracker_),
      audit_logger_(version_tracker_),
      dry_runner_() {}

  // -----------------------------------------------------------------------
  // Parse all migrations from the schema directory
  // -----------------------------------------------------------------------
  void load_migrations() {
    auto& log = get_logger("MigrationRunner");
    MigrationFileParser parser;
    migrations_ = parser.parse_directory(schema_dir_);
    graph_.build(migrations_);

    log.info("Loaded " + std::to_string(migrations_.size()) +
             " migrations from " + schema_dir_);

    // Check for cycles
    auto cycles = graph_.detect_cycles();
    if (!cycles.empty()) {
      log.warn("Detected " + std::to_string(cycles.size()) +
               " dependency cycles in migrations!");
      for (auto& cycle : cycles) {
        std::string cycle_str;
        for (int v : cycle) cycle_str += std::to_string(v) + " -> ";
        log.warn("  Cycle: " + cycle_str);
      }
    }
  }

  // -----------------------------------------------------------------------
  // Get current schema version
  // -----------------------------------------------------------------------
  int current_version() {
    return version_tracker_.current_version();
  }

  // -----------------------------------------------------------------------
  // Get the latest available migration version
  // -----------------------------------------------------------------------
  int latest_version() {
    if (migrations_.empty()) return 0;
    return migrations_.back().version;
  }

  // -----------------------------------------------------------------------
  // Upgrade database to latest version
  // -----------------------------------------------------------------------
  struct MigrationReport {
    bool success;
    int from_version;
    int to_version;
    int migrations_applied;
    int migrations_failed;
    int64_t total_duration_ms;
    std::vector<json> applied;
    std::vector<json> failed;
    json dependency_graph;
    json compat_check;

    json to_json() const {
      json j;
      j["success"] = success;
      j["from_version"] = from_version;
      j["to_version"] = to_version;
      j["migrations_applied"] = migrations_applied;
      j["migrations_failed"] = migrations_failed;
      j["total_duration_ms"] = total_duration_ms;
      j["applied"] = applied;
      j["failed"] = failed;
      j["dependency_graph"] = dependency_graph;
      j["compat_check"] = compat_check;
      return j;
    }
  };

  MigrationReport upgrade(int target_version = -1) {
    auto& log = get_logger("MigrationRunner");
    auto start_time = chr::steady_clock::now();
    MigrationReport report;
    report.from_version = current_version();

    if (target_version < 0) {
      target_version = latest_version();
    }
    report.to_version = target_version;
    report.dependency_graph = graph_.to_json();

    if (target_version <= report.from_version) {
      report.success = true;
      report.message_noop();
      return report;
    }

    // Compatibility check
    auto compat_result = compat_enforcer_.check_compatibility();
    report.compat_check = compat_result.to_json();
    if (!compat_result.compatible && !compat_result.needs_upgrade) {
      report.success = false;
      log.error("Schema compat version mismatch - aborting upgrade");
      return report;
    }

    // Acquire migration lock
    if (!lock_manager_.acquire_lock()) {
      report.success = false;
      log.error("Could not acquire migration lock - "
                "another migration may be in progress");
      return report;
    }

    // Load migrations if not already loaded
    if (migrations_.empty()) {
      load_migrations();
    }

    // Determine path
    auto path = graph_.upgrade_path(report.from_version, target_version);
    log.info("Upgrade path: " + std::to_string(report.from_version) +
             " -> " + std::to_string(target_version) +
             " (" + std::to_string(path.size()) + " steps)");

    std::set<int> applied = version_tracker_.get_applied_versions();

    // Execute each migration in the path
    for (int ver : path) {
      const MigrationFile* mf = graph_.get_migration(ver);
      if (!mf) {
        log.warn("Migration v" + std::to_string(ver) +
                 " not found, skipping");
        continue;
      }

      // Skip already applied
      if (version_tracker_.is_applied(ver)) {
        log.debug("Migration v" + std::to_string(ver) +
                  " already applied, skipping");
        applied.insert(ver);
        continue;
      }

      // Check dependencies
      if (!graph_.dependencies_satisfied(ver, applied)) {
        log.error("Dependencies not satisfied for v" +
                  std::to_string(ver) + ", aborting");
        json fail_entry;
        fail_entry["version"] = ver;
        fail_entry["filename"] = mf->filename;
        fail_entry["error"] = "Unsatisfied dependencies";
        report.failed.push_back(fail_entry);
        report.migrations_failed++;
        report.success = false;
        break;
      }

      // Execute the migration
      json result = execute_migration(*mf, MigrationDirection::UP);
      if (result.value("success", false)) {
        report.applied.push_back(result);
        report.migrations_applied++;
        applied.insert(ver);

        // If this was a compat_version bump, update
        if (compat_result.needs_upgrade) {
          compat_enforcer_.bump_version(SCHEMA_COMPAT_VERSION);
          compat_result.needs_upgrade = false;
        }
      } else {
        report.failed.push_back(result);
        report.migrations_failed++;
        report.success = false;
        log.error("Migration v" + std::to_string(ver) +
                  " failed: " + result.value("error", "unknown"));
        break;
      }
    }

    if (report.migrations_failed == 0 &&
        report.to_version == target_version) {
      report.success = true;
    }

    // Release lock
    lock_manager_.release_lock();

    auto end_time = chr::steady_clock::now();
    report.total_duration_ms = chr::duration_cast<chr::milliseconds>(
        end_time - start_time).count();
    report.to_version = current_version();

    log.info("Upgrade complete: " + std::to_string(report.from_version) +
             " -> " + std::to_string(report.to_version) +
             " (applied: " + std::to_string(report.migrations_applied) +
             ", failed: " + std::to_string(report.migrations_failed) + ")");

    return report;
  }

  // -----------------------------------------------------------------------
  // Rollback to a specific version
  // -----------------------------------------------------------------------
  MigrationReport rollback(int target_version) {
    auto& log = get_logger("MigrationRunner");
    auto start_time = chr::steady_clock::now();
    MigrationReport report;
    report.from_version = current_version();
    report.to_version = target_version;

    if (target_version >= report.from_version) {
      report.success = true;
      log.info("Already at or above target version, nothing to rollback");
      return report;
    }

    // Acquire lock
    if (!lock_manager_.acquire_lock()) {
      report.success = false;
      log.error("Could not acquire migration lock");
      return report;
    }

    if (migrations_.empty()) load_migrations();

    // Get downgrade path (reverse order)
    auto path = graph_.downgrade_path(report.from_version, target_version);
    log.info("Downgrade path: " + std::to_string(report.from_version) +
             " -> " + std::to_string(target_version) +
             " (" + std::to_string(path.size()) + " steps)");

    for (int ver : path) {
      if (!version_tracker_.is_applied(ver)) {
        log.debug("Migration v" + std::to_string(ver) +
                  " not applied, skipping rollback");
        continue;
      }

      // Check that nothing depends on this version
      auto dependents = graph_.get_all_dependents(ver);
      bool can_rollback = true;
      for (int dep : dependents) {
        if (version_tracker_.is_applied(dep)) {
          log.error("Cannot rollback v" + std::to_string(ver) +
                    " - v" + std::to_string(dep) + " depends on it");
          json fail_entry;
          fail_entry["version"] = ver;
          fail_entry["error"] = "Dependent migration v" +
                                std::to_string(dep) + " is still applied";
          report.failed.push_back(fail_entry);
          report.migrations_failed++;
          can_rollback = false;
        }
      }
      if (!can_rollback) {
        report.success = false;
        continue;
      }

      const MigrationFile* mf = graph_.get_migration(ver);
      if (!mf) {
        log.warn("Migration file for v" + std::to_string(ver) +
                 " not found, cannot rollback");
        continue;
      }

      if (!mf->has_down) {
        log.warn("No down migration for v" + std::to_string(ver) +
                 ", skipping rollback");
        continue;
      }

      json result = execute_migration(*mf, MigrationDirection::DOWN);
      if (result.value("success", false)) {
        report.applied.push_back(result);
        report.migrations_applied++;
        version_tracker_.record_rolled_back(ver, mf->filename);
      } else {
        report.failed.push_back(result);
        report.migrations_failed++;
        report.success = false;
        log.error("Rollback v" + std::to_string(ver) +
                  " failed: " + result.value("error", "unknown"));
        break;
      }
    }

    lock_manager_.release_lock();

    auto end_time = chr::steady_clock::now();
    report.total_duration_ms = chr::duration_cast<chr::milliseconds>(
        end_time - start_time).count();
    report.to_version = current_version();

    if (report.migrations_failed == 0) report.success = true;

    log.info("Rollback complete: " + std::to_string(report.from_version) +
             " -> " + std::to_string(report.to_version));

    return report;
  }

  // -----------------------------------------------------------------------
  // Bootstrap a fresh database
  // -----------------------------------------------------------------------
  MigrationReport bootstrap() {
    auto& log = get_logger("MigrationRunner");

    if (migrations_.empty()) load_migrations();

    int current = current_version();
    if (current > 0) {
      log.info("Database already initialized at v" + std::to_string(current));
      MigrationReport r;
      r.from_version = current;
      r.to_version = current;
      r.success = true;
      return r;
    }

    // Run full schema files first (if they exist and no version tracking yet)
    // Then apply all deltas
    log.info("Bootstrapping fresh database");
    return upgrade();
  }

  // -----------------------------------------------------------------------
  // Dry-run mode - validate without executing
  // -----------------------------------------------------------------------
  json dry_run(MigrationDirection direction = MigrationDirection::UP) {
    if (migrations_.empty()) load_migrations();

    auto results = dry_runner_.dry_run(migrations_, direction, graph_);

    json j;
    j["direction"] = direction_str(direction);
    j["total_migrations"] = results.size();
    j["results"] = json::array();

    int valid_count = 0;
    int warning_count = 0;
    int error_count = 0;

    for (auto& r : results) {
      if (r.valid) valid_count++;
      warning_count += r.warnings.size();
      error_count += r.errors.size();
      j["results"].push_back(r.to_json());
    }

    j["valid_count"] = valid_count;
    j["warning_count"] = warning_count;
    j["error_count"] = error_count;
    j["all_valid"] = (error_count == 0);

    return j;
  }

  // -----------------------------------------------------------------------
  // Verify checksums of all applied migrations
  // -----------------------------------------------------------------------
  json verify_checksums() {
    if (migrations_.empty()) load_migrations();

    auto results = checksum_verifier_.verify_all(migrations_);
    json j;
    j["verified"] = true;
    j["mismatches"] = json::array();

    for (auto& r : results) {
      if (!r.matches) {
        j["verified"] = false;
        json m;
        m["version"] = r.version;
        m["filename"] = r.filename;
        m["expected_checksum"] = r.expected;
        m["actual_checksum"] = r.actual;
        j["mismatches"].push_back(m);
      }
    }

    j["total_verified"] = results.size();
    return j;
  }

  // -----------------------------------------------------------------------
  // Validate all migration files (syntax, dependencies)
  // -----------------------------------------------------------------------
  json validate_migrations() {
    if (migrations_.empty()) load_migrations();

    json j;
    j["total"] = migrations_.size();
    j["cycles"] = json::array();

    auto cycles = graph_.detect_cycles();
    for (auto& cycle : cycles) {
      json c;
      for (int v : cycle) c.push_back(v);
      j["cycles"].push_back(c);
    }
    j["has_cycles"] = !cycles.empty();

    j["migrations"] = json::array();
    for (auto& mf : migrations_) {
      json entry = mf.to_json();
      entry["dependencies_valid"] = true;

      // Verify all dependencies exist
      for (int dep : mf.depends_on) {
        if (graph_.get_migration(dep) == nullptr) {
          entry["dependencies_valid"] = false;
          entry["missing_dependencies"].push_back(dep);
        }
      }
      j["migrations"].push_back(entry);
    }

    return j;
  }

  // -----------------------------------------------------------------------
  // Run a single migration by version number
  // -----------------------------------------------------------------------
  json run_single(int version, MigrationDirection direction) {
    if (migrations_.empty()) load_migrations();

    const MigrationFile* mf = graph_.get_migration(version);
    if (!mf) {
      json err;
      err["success"] = false;
      err["error"] = "Migration v" + std::to_string(version) + " not found";
      return err;
    }

    return execute_migration(*mf, direction);
  }

  // -----------------------------------------------------------------------
  // Get migration status overview
  // -----------------------------------------------------------------------
  json get_status() {
    json j;
    j["current_version"] = current_version();
    j["latest_available_version"] = latest_version();
    j["needs_upgrade"] = (j["current_version"] < j["latest_available_version"]);

    auto applied = version_tracker_.list_applied_migrations();
    j["applied_count"] = applied.size();
    j["applied_migrations"] = applied;

    j["compat_version"] = compat_enforcer_.get_stored_version();
    j["expected_compat_version"] = SCHEMA_COMPAT_VERSION;

    // Check for pending migrations
    json pending = json::array();
    if (!migrations_.empty()) {
      for (auto& mf : migrations_) {
        if (!version_tracker_.is_applied(mf.version)) {
          pending.push_back(mf.to_json());
        }
      }
    }
    j["pending_count"] = pending.size();
    j["pending_migrations"] = pending;

    // Lock status
    j["migration_lock"] = lock_manager_.get_lock_info();

    // Background migrations
    j["background_migrations"] = bg_manager_.list_all();

    return j;
  }

  // -----------------------------------------------------------------------
  // Get migration history
  // -----------------------------------------------------------------------
  json get_history(int limit = 100) {
    return version_tracker_.get_migration_history(limit);
  }

  // -----------------------------------------------------------------------
  // Force release migration lock (admin)
  // -----------------------------------------------------------------------
  json force_unlock() {
    bool released = lock_manager_.force_release();
    json j;
    j["released"] = released;
    return j;
  }

  // -----------------------------------------------------------------------
  // Run background migrations
  // -----------------------------------------------------------------------
  void run_background_migrations(
      std::function<bool(const std::string&, int64_t)> callback,
      bool async = false) {
    if (async) {
      std::thread([this, callback]() {
        bg_manager_.run_loop(callback);
      }).detach();
    } else {
      bg_manager_.run_loop(callback);
    }
  }

  // Background migration management access
  BackgroundMigrationManager& background_migrations() {
    return bg_manager_;
  }

  // Schema compat enforcer access
  SchemaCompatEnforcer& compat_enforcer() {
    return compat_enforcer_;
  }

  // Migration lock manager access
  MigrationLockManager& lock_manager() {
    return lock_manager_;
  }

  // Schema version tracker access
  SchemaVersionTracker& version_tracker() {
    return version_tracker_;
  }

  // Audit logger access
  MigrationAuditLogger& audit_logger() {
    return audit_logger_;
  }

  // Graph access
  const MigrationDependencyGraph& graph() const { return graph_; }

  // Get parsed migrations
  const std::vector<MigrationFile>& migrations() const { return migrations_; }

private:
  storage::DatabasePool& db_;
  std::string schema_dir_;
  SchemaVersionTracker version_tracker_;
  MigrationLockManager lock_manager_;
  BackgroundMigrationManager bg_manager_;
  SchemaCompatEnforcer compat_enforcer_;
  MigrationChecksumVerifier checksum_verifier_;
  MigrationAuditLogger audit_logger_;
  MigrationDryRunner dry_runner_;
  MigrationDependencyGraph graph_;
  std::vector<MigrationFile> migrations_;

  // Execute a single migration with transaction support
  json execute_migration(const MigrationFile& mf,
                         MigrationDirection direction) {
    auto& log = get_logger("MigrationRunner");
    auto start_time = chr::steady_clock::now();

    json result;
    result["version"] = mf.version;
    result["filename"] = mf.filename;
    result["description"] = mf.description;
    result["direction"] = direction_str(direction);
    result["success"] = false;

    const std::vector<std::string>* statements = nullptr;
    if (direction == MigrationDirection::UP) {
      statements = &mf.up_statements;
    } else {
      statements = &mf.down_statements;
    }

    if (!statements || statements->empty()) {
      result["error"] = "No SQL statements for " +
                        std::string(direction_str(direction)) +
                        " migration";
      result["duration_ms"] = 0;
      audit_logger_.log({
          iso_timestamp_now(), mf.version, mf.filename,
          direction_str(direction), false,
          result["error"].get<std::string>(), 0, "migration-runner", 0
      });
      return result;
    }

    log.info("Executing migration v" + std::to_string(mf.version) +
             " [" + mf.filename + "] direction=" +
             direction_str(direction) + " (" +
             std::to_string(statements->size()) + " statements)");

    bool success = true;
    std::string error_msg;

    try {
      if (mf.is_transactional) {
        // Execute within a transaction
        db_.begin();
        try {
          for (size_t i = 0; i < statements->size(); ++i) {
            const auto& stmt = (*statements)[i];
            if (!stmt.empty()) {
              db_.execute(stmt);
              log.debug("  Statement " + std::to_string(i + 1) + "/" +
                        std::to_string(statements->size()) + " OK");
            }
          }

          // Record the migration
          if (direction == MigrationDirection::UP) {
            version_tracker_.record_applied(
                mf.version, mf.filename, mf.description, mf.checksum);
          } else {
            version_tracker_.record_rolled_back(
                mf.version, mf.filename);
          }

          db_.commit();
        } catch (const std::exception& e) {
          db_.rollback();
          success = false;
          error_msg = e.what();
          log.error("Migration v" + std::to_string(mf.version) +
                    " failed (rolled back): " + error_msg);
        }
      } else {
        // Non-transactional execution (statement by statement)
        for (size_t i = 0; i < statements->size(); ++i) {
          const auto& stmt = (*statements)[i];
          if (!stmt.empty()) {
            try {
              db_.execute(stmt);
              log.debug("  Statement " + std::to_string(i + 1) + "/" +
                        std::to_string(statements->size()) + " OK");
            } catch (const std::exception& e) {
              success = false;
              error_msg = "Statement " + std::to_string(i + 1) +
                          " failed: " + e.what();
              log.error("Migration v" + std::to_string(mf.version) +
                        " non-transactional failure: " + error_msg);
              break;
            }
          }
        }

        // Record non-transactional as well
        if (success && direction == MigrationDirection::UP) {
          version_tracker_.record_applied(
              mf.version, mf.filename, mf.description, mf.checksum);
        }
      }
    } catch (const std::exception& e) {
      success = false;
      error_msg = std::string("Outer exception: ") + e.what();
      log.error("Migration v" + std::to_string(mf.version) +
                " outer failure: " + error_msg);
    }

    auto end_time = chr::steady_clock::now();
    int64_t duration_ms = chr::duration_cast<chr::milliseconds>(
        end_time - start_time).count();

    result["success"] = success;
    result["statement_count"] = static_cast<int>(statements->size());
    result["duration_ms"] = duration_ms;
    if (!success) {
      result["error"] = error_msg;
    }

    // Log to audit trail
    audit_logger_.log({
        iso_timestamp_now(), mf.version, mf.filename,
        direction_str(direction), success, error_msg,
        duration_ms, "migration-runner",
        direction == MigrationDirection::DOWN ? mf.version : 0
    });

    // Also log in the SchemaVersionTracker
    version_tracker_.log_execution(
        mf.version, mf.filename, direction_str(direction),
        success, error_msg, duration_ms);

    // Store checksum for non-transactional
    if (success && direction == MigrationDirection::UP) {
      checksum_verifier_.store_checksum(mf.version, mf.checksum);
    }

    return result;
  }
};

// =============================================================================
// MigrationAdminAPI - REST admin endpoints for migration management
//
// Provides administrative HTTP endpoints for:
//   GET  /_progressive/admin/v1/migrations/status
//   GET  /_progressive/admin/v1/migrations/history
//   POST /_progressive/admin/v1/migrations/upgrade
//   POST /_progressive/admin/v1/migrations/rollback
//   POST /_progressive/admin/v1/migrations/run_single
//   POST /_progressive/admin/v1/migrations/dry_run
//   POST /_progressive/admin/v1/migrations/validate
//   POST /_progressive/admin/v1/migrations/verify_checksums
//   POST /_progressive/admin/v1/migrations/force_unlock
//   GET  /_progressive/admin/v1/migrations/pending
//   GET  /_progressive/admin/v1/migrations/background
//   POST /_progressive/admin/v1/migrations/background/start
//   POST /_progressive/admin/v1/migrations/background/stop
//   POST /_progressive/admin/v1/migrations/background/reset
//   GET  /_progressive/admin/v1/migrations/compat
//   POST /_progressive/admin/v1/migrations/compat/bump
//   GET  /_progressive/admin/v1/migrations/dependency_graph
// =============================================================================
class MigrationAdminAPI {
public:
  MigrationAdminAPI(MigrationRunner& runner) : runner_(runner) {}

  // -----------------------------------------------------------------------
  // Handle GET /status
  // -----------------------------------------------------------------------
  json handle_get_status() {
    return runner_.get_status();
  }

  // -----------------------------------------------------------------------
  // Handle GET /history?limit=N
  // -----------------------------------------------------------------------
  json handle_get_history(int limit = 100) {
    return runner_.get_history(limit);
  }

  // -----------------------------------------------------------------------
  // Handle POST /upgrade - body: {"target_version": N}
  // -----------------------------------------------------------------------
  json handle_post_upgrade(const json& body) {
    int target = body.value("target_version", -1);
    auto report = runner_.upgrade(target);
    return report.to_json();
  }

  // -----------------------------------------------------------------------
  // Handle POST /rollback - body: {"target_version": N}
  // -----------------------------------------------------------------------
  json handle_post_rollback(const json& body) {
    if (!body.contains("target_version") || !body["target_version"].is_number()) {
      json err;
      err["error"] = "target_version is required";
      err["success"] = false;
      return err;
    }
    int target = body["target_version"].get<int>();
    auto report = runner_.rollback(target);
    return report.to_json();
  }

  // -----------------------------------------------------------------------
  // Handle POST /run_single - body: {"version": N, "direction": "up|down"}
  // -----------------------------------------------------------------------
  json handle_post_run_single(const json& body) {
    if (!body.contains("version")) {
      json err;
      err["error"] = "version is required";
      err["success"] = false;
      return err;
    }
    int version = body["version"].get<int>();
    std::string dir_str = body.value("direction", "up");

    MigrationDirection direction;
    if (dir_str == "down") {
      direction = MigrationDirection::DOWN;
    } else {
      direction = MigrationDirection::UP;
    }

    return runner_.run_single(version, direction);
  }

  // -----------------------------------------------------------------------
  // Handle POST /dry_run - body: {"direction": "up|down"}
  // -----------------------------------------------------------------------
  json handle_post_dry_run(const json& body) {
    std::string dir_str = body.value("direction", "up");

    MigrationDirection direction;
    if (dir_str == "down") {
      direction = MigrationDirection::DOWN;
    } else {
      direction = MigrationDirection::UP;
    }

    return runner_.dry_run(direction);
  }

  // -----------------------------------------------------------------------
  // Handle POST /validate
  // -----------------------------------------------------------------------
  json handle_post_validate() {
    return runner_.validate_migrations();
  }

  // -----------------------------------------------------------------------
  // Handle POST /verify_checksums
  // -----------------------------------------------------------------------
  json handle_post_verify_checksums() {
    return runner_.verify_checksums();
  }

  // -----------------------------------------------------------------------
  // Handle POST /force_unlock
  // -----------------------------------------------------------------------
  json handle_post_force_unlock() {
    return runner_.force_unlock();
  }

  // -----------------------------------------------------------------------
  // Handle GET /pending
  // -----------------------------------------------------------------------
  json handle_get_pending() {
    auto status = runner_.get_status();
    return status["pending_migrations"];
  }

  // -----------------------------------------------------------------------
  // Handle GET /background
  // -----------------------------------------------------------------------
  json handle_get_background() {
    return runner_.background_migrations().list_all();
  }

  // -----------------------------------------------------------------------
  // Handle POST /background/start
  // -----------------------------------------------------------------------
  json handle_post_background_start() {
    json result;
    result["started"] = true;
    result["message"] = "Background migration loop started in background thread";
    // Start in a background thread (fire and forget)
    runner_.background_migrations().set_running(true);
    std::thread([this]() {
      runner_.background_migrations().run_loop(
          [](const std::string& name, int64_t batch_size) -> bool {
            // Default batch callback - just log and succeed
            get_logger("MigrationAdminAPI").info(
                "Processing background migration batch: " + name +
                " (batch_size=" + std::to_string(batch_size) + ")");
            // In production, this would look up the actual handler
            return true;
          });
    }).detach();
    return result;
  }

  // -----------------------------------------------------------------------
  // Handle POST /background/stop
  // -----------------------------------------------------------------------
  json handle_post_background_stop() {
    runner_.background_migrations().stop();
    json result;
    result["stopped"] = true;
    return result;
  }

  // -----------------------------------------------------------------------
  // Handle POST /background/reset - body: {"name": "migration_name"}
  // -----------------------------------------------------------------------
  json handle_post_background_reset(const json& body) {
    if (!body.contains("name")) {
      json err;
      err["error"] = "name is required";
      return err;
    }
    std::string name = body["name"].get<std::string>();
    runner_.background_migrations().reset_migration(name);
    json result;
    result["reset"] = true;
    result["name"] = name;
    return result;
  }

  // -----------------------------------------------------------------------
  // Handle GET /compat
  // -----------------------------------------------------------------------
  json handle_get_compat() {
    return runner_.compat_enforcer().check_compatibility().to_json();
  }

  // -----------------------------------------------------------------------
  // Handle POST /compat/bump - body: {"new_version": "N"}
  // -----------------------------------------------------------------------
  json handle_post_compat_bump(const json& body) {
    if (!body.contains("new_version")) {
      json err;
      err["error"] = "new_version is required";
      return err;
    }
    std::string new_ver = body["new_version"].get<std::string>();
    runner_.compat_enforcer().bump_version(new_ver);
    json result;
    result["bumped"] = true;
    result["new_version"] = new_ver;
    return result;
  }

  // -----------------------------------------------------------------------
  // Handle GET /dependency_graph
  // -----------------------------------------------------------------------
  json handle_get_dependency_graph() {
    return runner_.graph().to_json();
  }

  // -----------------------------------------------------------------------
  // Route dispatcher - maps HTTP method + path to handler
  // Returns JSON response and HTTP status code
  // -----------------------------------------------------------------------
  struct APIResponse {
    int status_code;
    json body;
  };

  APIResponse dispatch(const std::string& method,
                       const std::string& path,
                       const json& body = json::object()) {
    // GET /status
    if (method == "GET" && path == "/status") {
      return {200, handle_get_status()};
    }

    // GET /history
    if (method == "GET" && path == "/history") {
      return {200, handle_get_history()};
    }

    // POST /upgrade
    if (method == "POST" && path == "/upgrade") {
      try {
        auto result = handle_post_upgrade(body);
        int code = result.value("success", false) ? 200 : 500;
        return {code, result};
      } catch (const std::exception& e) {
        return {500, {{"error", e.what()}}};
      }
    }

    // POST /rollback
    if (method == "POST" && path == "/rollback") {
      try {
        auto result = handle_post_rollback(body);
        int code = result.value("success", false) ? 200 : 400;
        return {code, result};
      } catch (const std::exception& e) {
        return {400, {{"error", e.what()}}};
      }
    }

    // POST /run_single
    if (method == "POST" && path == "/run_single") {
      auto result = handle_post_run_single(body);
      int code = result.value("success", false) ? 200 : 500;
      return {code, result};
    }

    // POST /dry_run
    if (method == "POST" && path == "/dry_run") {
      return {200, handle_post_dry_run(body)};
    }

    // POST /validate
    if (method == "POST" && path == "/validate") {
      return {200, handle_post_validate()};
    }

    // POST /verify_checksums
    if (method == "POST" && path == "/verify_checksums") {
      auto result = handle_post_verify_checksums();
      int code = result.value("verified", false) ? 200 : 409;
      return {code, result};
    }

    // POST /force_unlock
    if (method == "POST" && path == "/force_unlock") {
      return {200, handle_post_force_unlock()};
    }

    // GET /pending
    if (method == "GET" && path == "/pending") {
      return {200, handle_get_pending()};
    }

    // GET /background
    if (method == "GET" && path == "/background") {
      return {200, handle_get_background()};
    }

    // POST /background/start
    if (method == "POST" && path == "/background/start") {
      return {200, handle_post_background_start()};
    }

    // POST /background/stop
    if (method == "POST" && path == "/background/stop") {
      return {200, handle_post_background_stop()};
    }

    // POST /background/reset
    if (method == "POST" && path == "/background/reset") {
      return {200, handle_post_background_reset(body)};
    }

    // GET /compat
    if (method == "GET" && path == "/compat") {
      return {200, handle_get_compat()};
    }

    // POST /compat/bump
    if (method == "POST" && path == "/compat/bump") {
      return {200, handle_post_compat_bump(body)};
    }

    // GET /dependency_graph
    if (method == "GET" && path == "/dependency_graph") {
      return {200, handle_get_dependency_graph()};
    }

    // 404
    return {404, {{"error", "Unknown migration admin endpoint"},
                   {"path", path},
                   {"method", method}}};
  }

  // Convenience: handle a request and return the body directly
  json handle(const std::string& method, const std::string& path,
             const json& body = json::object()) {
    return dispatch(method, path, body).body;
  }

private:
  MigrationRunner& runner_;
};

// =============================================================================
// MigrationEngine - Top-level facade for the entire migration engine
//
// This is the main entry point that wires together all components:
//   - SchemaVersionTracker (version state)
//   - MigrationFileParser (file parsing)
//   - MigrationDependencyGraph (ordering)
//   - MigrationRunner (execution)
//   - BackgroundMigrationManager (background ops)
//   - SchemaCompatEnforcer (compat checks)
//   - MigrationAdminAPI (REST endpoints)
//   - MigrationLockManager (concurrency control)
//   - MigrationChecksumVerifier (integrity)
//   - MigrationAuditLogger (audit trail)
//   - MigrationDryRunner (validation)
//
// Equivalent to:
//   synapse.storage.database.DatabasePool.upgrade() pipeline
//   synapse._scripts.update_synapse_database
// =============================================================================
class MigrationEngine {
public:
  MigrationEngine(storage::DatabasePool& db,
                  const std::string& schema_dir)
    : db_(db),
      schema_dir_(schema_dir),
      runner_(db, schema_dir),
      admin_api_(runner_) {}

  // -----------------------------------------------------------------------
  // Initialize the engine - parse migrations, check compat, ensure tables
  // -----------------------------------------------------------------------
  json initialize() {
    auto& log = get_logger("MigrationEngine");
    json result;

    log.info("Initializing MigrationEngine with schema_dir=" + schema_dir_);

    // Load all migrations
    runner_.load_migrations();
    result["migrations_loaded"] =
        static_cast<int>(runner_.migrations().size());

    // Check schema compatibility
    auto compat = runner_.compat_enforcer().check_compatibility();
    result["compat_check"] = compat.to_json();

    if (!compat.compatible) {
      log.warn("Schema compatibility check failed: " + compat.message);
    }

    // Current version
    result["current_version"] = runner_.current_version();
    result["latest_version"] = runner_.latest_version();
    result["needs_upgrade"] =
        (result["current_version"].get<int>() <
         result["latest_version"].get<int>());

    log.info("MigrationEngine initialized. Version: " +
             std::to_string(runner_.current_version()) +
             ", Latest: " + std::to_string(runner_.latest_version()));

    return result;
  }

  // -----------------------------------------------------------------------
  // Auto-upgrade - run on startup to bring DB to latest version
  // -----------------------------------------------------------------------
  json auto_upgrade() {
    auto init = initialize();
    if (init["needs_upgrade"].get<bool>()) {
      auto report = runner_.upgrade();
      return report.to_json();
    }
    json result;
    result["action"] = "no_upgrade_needed";
    result["current_version"] = init["current_version"];
    return result;
  }

  // -----------------------------------------------------------------------
  // Delegate to runner
  // -----------------------------------------------------------------------
  MigrationRunner& runner() { return runner_; }

  // -----------------------------------------------------------------------
  // Delegate to admin API
  // -----------------------------------------------------------------------
  MigrationAdminAPI& admin() { return admin_api_; }

  // -----------------------------------------------------------------------
  // Get the schema directory
  // -----------------------------------------------------------------------
  const std::string& schema_dir() const { return schema_dir_; }

  // -----------------------------------------------------------------------
  // Handle a full admin API request with path resolution
  // The path should be relative to /_progressive/admin/v1/migrations/
  // -----------------------------------------------------------------------
  json handle_admin_request(const std::string& method,
                            const std::string& admin_path,
                            const json& body = json::object()) {
    return admin_api_.handle(method, admin_path, body);
  }

  // -----------------------------------------------------------------------
  // Full status report
  // -----------------------------------------------------------------------
  json full_status() {
    json j;
    j["engine"] = "progressive::MigrationEngine";
    j["schema_dir"] = schema_dir_;
    j["migration_status"] = runner_.get_status();
    j["dependency_graph"] = runner_.graph().to_json();
    j["compat"] = runner_.compat_enforcer().check_compatibility().to_json();
    j["validation"] = runner_.validate_migrations();
    j["checksums"] = runner_.verify_checksums();
    j["lock"] = runner_.lock_manager().get_lock_info();
    j["background"] = runner_.background_migrations().list_all();
    return j;
  }

private:
  storage::DatabasePool& db_;
  std::string schema_dir_;
  MigrationRunner runner_;
  MigrationAdminAPI admin_api_;
};

// =============================================================================
// Public API - Free functions in the progressive:: namespace
// =============================================================================

// Create and initialize a migration engine from a database pool and schema dir
// Returns a shared pointer to the initialized engine
std::shared_ptr<MigrationEngine> create_migration_engine(
    storage::DatabasePool& db,
    const std::string& schema_dir) {
  auto engine = std::make_shared<MigrationEngine>(db, schema_dir);
  engine->initialize();
  return engine;
}

// Run migrations on startup (convenience function)
// This is the primary entry point for the server bootstrap sequence
json run_startup_migrations(storage::DatabasePool& db,
                            const std::string& schema_dir) {
  MigrationEngine engine(db, schema_dir);
  return engine.auto_upgrade();
}

// Check if a database needs migration (lightweight check)
bool database_needs_migration(storage::DatabasePool& db,
                              const std::string& schema_dir) {
  MigrationEngine engine(db, schema_dir);
  auto init = engine.initialize();
  return init.value("needs_upgrade", false);
}

// Validate all migration files without connecting to a database
json validate_migration_files(const std::string& schema_dir) {
  MigrationFileParser parser;
  auto migrations = parser.parse_directory(schema_dir);

  MigrationDependencyGraph graph;
  graph.build(migrations);

  json j;
  j["total_files"] = migrations.size();
  j["cycles"] = json::array();

  auto cycles = graph.detect_cycles();
  for (auto& cycle : cycles) {
    json c;
    for (int v : cycle) c.push_back(v);
    j["cycles"].push_back(c);
  }
  j["has_cycles"] = !cycles.empty();

  j["files"] = json::array();
  for (auto& mf : migrations) {
    json entry = mf.to_json();
    entry["version"] = mf.version;
    entry["filename"] = mf.filename;
    entry["description"] = mf.description;
    entry["has_up"] = mf.has_up;
    entry["has_down"] = mf.has_down;
    entry["up_statement_count"] = mf.up_statements.size();
    entry["down_statement_count"] = mf.down_statements.size();
    entry["depends_on"] = json::array();
    for (int d : mf.depends_on) entry["depends_on"].push_back(d);
    j["files"].push_back(entry);
  }

  return j;
}

// Parse a single migration string (useful for testing)
json parse_migration_string(const std::string& content,
                            const std::string& filename = "inline.sql") {
  MigrationFileParser parser;
  auto mf = parser.parse(filename, content);

  json j;
  j["filename"] = mf.filename;
  j["version"] = mf.version;
  j["description"] = mf.description;
  j["has_up"] = mf.has_up;
  j["has_down"] = mf.has_down;
  j["up_statement_count"] = mf.up_statements.size();
  j["down_statement_count"] = mf.down_statements.size();
  j["checksum"] = mf.checksum;
  j["up_statements"] = mf.up_statements;
  j["down_statements"] = mf.down_statements;
  return j;
}

// =============================================================================
// MigrationEngineBuilder - Fluent builder for migration engine configuration
// =============================================================================
class MigrationEngineBuilder {
public:
  MigrationEngineBuilder() = default;

  MigrationEngineBuilder& with_database(storage::DatabasePool& db) {
    db_ = &db;
    return *this;
  }

  MigrationEngineBuilder& with_schema_dir(const std::string& dir) {
    schema_dir_ = dir;
    return *this;
  }

  MigrationEngineBuilder& with_compat_version(const std::string& version) {
    compat_version_ = version;
    return *this;
  }

  MigrationEngineBuilder& with_lock_timeout(chr::seconds timeout) {
    lock_timeout_ = timeout;
    return *this;
  }

  MigrationEngineBuilder& with_background_batch_size(int64_t size) {
    bg_batch_size_ = size;
    return *this;
  }

  MigrationEngineBuilder& with_auto_upgrade(bool auto_upgrade) {
    auto_upgrade_ = auto_upgrade;
    return *this;
  }

  MigrationEngineBuilder& with_strict_compat(bool strict) {
    strict_compat_ = strict;
    return *this;
  }

  std::shared_ptr<MigrationEngine> build() {
    if (!db_) {
      throw std::runtime_error("MigrationEngineBuilder: database not set");
    }
    if (schema_dir_.empty()) {
      throw std::runtime_error("MigrationEngineBuilder: schema_dir not set");
    }

    auto engine = std::make_shared<MigrationEngine>(*db_, schema_dir_);
    auto init = engine->initialize();

    if (auto_upgrade_) {
      auto& log = get_logger("MigrationEngineBuilder");
      if (init.value("needs_upgrade", false)) {
        log.info("Auto-upgrade triggered");
        engine->auto_upgrade();
      }
    }

    return engine;
  }

private:
  storage::DatabasePool* db_ = nullptr;
  std::string schema_dir_;
  std::string compat_version_ = SCHEMA_COMPAT_VERSION;
  chr::seconds lock_timeout_ = DEFAULT_LOCK_TIMEOUT;
  int64_t bg_batch_size_ = DEFAULT_BG_BATCH_SIZE;
  bool auto_upgrade_ = true;
  bool strict_compat_ = true;
};

}  // namespace progressive
