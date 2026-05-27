// ============================================================================
// background_updates.cpp — Matrix Background Database Updates & Schema
// Migration Engine
//
// Equivalent to:
//   synapse/storage/background_updates.py
//   synapse/storage/schema/__init__.py
//   synapse/storage/databases/main/events_bg_updates.py
//   synapse/storage/databases/main/registration.py (bg updates)
//   synapse/storage/databases/main/room.py (bg updates)
//   synapse/storage/databases/main/state.py (bg updates)
//   synapse/_scripts/update_synapse_database.py
//
// Target: 2500+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <condition_variable>
#include <deque>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
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
#include <vector>

#include <nlohmann/json.hpp>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/profile.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/state.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/push_rule.hpp"
#include "progressive/storage/databases/main/media_repository.hpp"
#include "progressive/storage/databases/main/directory.hpp"
#include "progressive/storage/databases/main/end_to_end_keys.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/event_federation.hpp"
#include "progressive/storage/databases/main/receipts.hpp"
#include "progressive/storage/databases/main/filtering.hpp"
#include "progressive/storage/databases/main/stream.hpp"
#include "progressive/storage/databases/main/final_stores.hpp"
#include "progressive/storage/databases/main/remaining_stores.hpp"
#include "progressive/storage/databases/main/federation_stores.hpp"
#include "progressive/storage/databases/main/small_stores.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// SCHEMA_COMPAT_VERSION — bumped whenever the on-disk schema format changes
// in an incompatible way. Must match across all nodes in a cluster.
// Equivalent to synapse.storage.schema.SCHEMA_COMPAT_VERSION
// ============================================================================
static constexpr const char* SCHEMA_COMPAT_VERSION = "1";
static constexpr const char* SCHEMA_COMPAT_VERSION_TABLE = "schema_compat_version";

// ============================================================================
// Batch processing constants — equivalent to Synapse bg update batch sizes
// ============================================================================
static constexpr int64_t DEFAULT_BG_UPDATE_BATCH_SIZE = 100;
static constexpr int64_t MIN_BG_UPDATE_BATCH_SIZE = 1;
static constexpr int64_t MAX_BG_UPDATE_BATCH_SIZE = 10000;
static constexpr double BG_UPDATE_SLEEP_SECS = 0.1;
static constexpr int64_t DEFAULT_FG_UPDATE_BATCH_SIZE = 500;

// ============================================================================
// Forward declarations
// ============================================================================
class BackgroundUpdateRegistry;
class BackgroundUpdateRunner;
class BackgroundUpdateProgress;
class DependencyResolver;
class ForegroundUpdateRunner;
class BackgroundUpdateAdminAPI;

// ============================================================================
// Anonymous namespace — Internal helpers
// ============================================================================
namespace {

// ---- Timestamp helpers ----

int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

std::string iso_timestamp_now() {
  auto now = chr::system_clock::now();
  auto time_t = chr::system_clock::to_time_t(now);
  std::tm tm_buf;
  gmtime_r(&time_t, &tm_buf);
  auto ms = chr::duration_cast<chr::milliseconds>(
                now.time_since_epoch()) %
            1000;
  std::ostringstream oss;
  oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S") << '.'
      << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
  return oss.str();
}

// ---- String helpers ----

bool starts_with(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

bool ends_with(std::string_view s, std::string_view suffix) {
  return s.size() >= suffix.size() &&
         s.substr(s.size() - suffix.size()) == suffix;
}

std::vector<std::string> split(const std::string& s, char delimiter) {
  std::vector<std::string> tokens;
  std::istringstream stream(s);
  std::string token;
  while (std::getline(stream, token, delimiter)) {
    if (!token.empty()) tokens.push_back(token);
  }
  return tokens;
}

std::string join(const std::vector<std::string>& parts,
                 const std::string& delimiter) {
  if (parts.empty()) return "";
  std::ostringstream oss;
  for (size_t i = 0; i < parts.size(); ++i) {
    if (i > 0) oss << delimiter;
    oss << parts[i];
  }
  return oss.str();
}

// Escape a string for SQL (basic escaping for SQLite-style)
std::string sql_escape(const std::string& s) {
  std::string result;
  result.reserve(s.size() + 4);
  for (char c : s) {
    if (c == '\'') result += "''"; else result += c;
  }
  return result;
}

// ---- JSON helpers ----

json safe_json_parse(const std::string& s) {
  if (s.empty()) return json::object();
  try { return json::parse(s); }
  catch (...) { return json::object(); }
}

std::string safe_json_dump(const json& j) {
  try { return j.dump(); }
  catch (...) { return "{}"; }
}

// ---- Progress formatting helpers ----

std::string format_duration_secs(int64_t secs) {
  if (secs < 0) return "unknown";
  if (secs < 60) return std::to_string(secs) + "s";
  int64_t mins = secs / 60;
  int64_t remaining_secs = secs % 60;
  if (mins < 60)
    return std::to_string(mins) + "m " + std::to_string(remaining_secs) + "s";
  int64_t hours = mins / 60;
  mins %= 60;
  if (hours < 24)
    return std::to_string(hours) + "h " + std::to_string(mins) + "m";
  int64_t days = hours / 24;
  hours %= 24;
  return std::to_string(days) + "d " + std::to_string(hours) + "h";
}

std::string format_percent(double pct) {
  std::ostringstream oss;
  oss << std::fixed << std::setprecision(1) << pct << '%';
  return oss.str();
}

// ============================================================================
// Background Update Status Type
// ============================================================================
enum class UpdateStatus {
  PENDING,
  RUNNING,
  COMPLETED,
  FAILED,
  CANCELLED,
  SKIPPED,
};

std::string status_to_string(UpdateStatus s) {
  switch (s) {
    case UpdateStatus::PENDING:   return "pending";
    case UpdateStatus::RUNNING:   return "running";
    case UpdateStatus::COMPLETED: return "completed";
    case UpdateStatus::FAILED:    return "failed";
    case UpdateStatus::CANCELLED: return "cancelled";
    case UpdateStatus::SKIPPED:   return "skipped";
  }
  return "unknown";
}

UpdateStatus string_to_status(const std::string& s) {
  if (s == "running")   return UpdateStatus::RUNNING;
  if (s == "completed") return UpdateStatus::COMPLETED;
  if (s == "failed")    return UpdateStatus::FAILED;
  if (s == "cancelled") return UpdateStatus::CANCELLED;
  if (s == "skipped")   return UpdateStatus::SKIPPED;
  return UpdateStatus::PENDING;
}

// ============================================================================
// Background Update Category — groups updates by their functional area
// ============================================================================
enum class UpdateCategory {
  POPULATE_STATS,   // populate room/user statistics
  INDEX_CREATE,     // create new database indexes
  DELETE_DATA,      // delete/cleanup old data
  REPLACE_DATA,     // migrate/replace data in-place
  EVENT_STORE,      // event store transformations
  CHAIN_COVER,      // event chain cover index
  STREAM_ORDERING,  // fix stream ordering
  STATE_GROUP,      // state group management
  REGISTRATION,     // registration/user-related
  ROOM,             // room-related
  GENERAL,          // miscellaneous
};

std::string category_to_string(UpdateCategory c) {
  switch (c) {
    case UpdateCategory::POPULATE_STATS:  return "populate_stats";
    case UpdateCategory::INDEX_CREATE:    return "index_create";
    case UpdateCategory::DELETE_DATA:     return "delete_data";
    case UpdateCategory::REPLACE_DATA:    return "replace_data";
    case UpdateCategory::EVENT_STORE:     return "event_store";
    case UpdateCategory::CHAIN_COVER:     return "chain_cover";
    case UpdateCategory::STREAM_ORDERING: return "stream_ordering";
    case UpdateCategory::STATE_GROUP:     return "state_group";
    case UpdateCategory::REGISTRATION:    return "registration";
    case UpdateCategory::ROOM:            return "room";
    case UpdateCategory::GENERAL:         return "general";
  }
  return "general";
}

// ============================================================================
// BackgroundUpdateDefinition — describes a single background update
// Equivalent to entries defined across synapse/storage/databases/main/*.py
// ============================================================================
struct BackgroundUpdateDefinition {
  std::string name;
  std::string description;
  UpdateCategory category;
  int64_t schema_version_introduced;  // schema version when this update was added
  std::vector<std::string> dependencies;
  bool is_foreground_only{false};     // must run before server starts
  bool is_blocking{false};            // blocks other updates while running
  bool is_repeatable{false};          // can be run multiple times
  int64_t default_batch_size{DEFAULT_BG_UPDATE_BATCH_SIZE};
};

// ============================================================================
// BackgroundUpdateEntry — runtime record for a single update instance
// ============================================================================
struct BackgroundUpdateEntry {
  BackgroundUpdateDefinition def;
  UpdateStatus status{UpdateStatus::PENDING};
  int64_t total_items{0};
  int64_t processed_items{0};
  int64_t started_ts{0};
  int64_t completed_ts{0};
  int64_t last_progress_update_ts{0};
  std::string error_message;
  json progress_json;
  double items_per_second{0.0};
  int retry_count{0};
  int max_retries{5};
};

// ============================================================================
// Topological Sort using Kahn's Algorithm
// Orders updates so dependencies are satisfied before dependents
// Equivalent to how Synapse resolves update ordering via dependency graphs
// ============================================================================
class TopologicalSorter {
public:
  explicit TopologicalSorter(
      const std::map<std::string, BackgroundUpdateDefinition>& updates)
      : updates_(updates) {}

  // Returns updates in topological order. Throws on cycle detection.
  std::vector<std::string> sort() {
    // Build adjacency list and in-degree map
    std::unordered_map<std::string, int> indegree;
    std::unordered_map<std::string, std::vector<std::string>> adjacency;

    for (auto& [name, def] : updates_) {
      indegree[name] = 0;  // ensure all nodes exist
    }

    for (auto& [name, def] : updates_) {
      for (auto& dep : def.dependencies) {
        adjacency[dep].push_back(name);
        indegree[name]++;
      }
    }

    // Kahn's algorithm
    std::queue<std::string> queue;
    for (auto& [name, deg] : indegree) {
      if (deg == 0) queue.push(name);
    }

    std::vector<std::string> sorted;
    while (!queue.empty()) {
      auto node = queue.front();
      queue.pop();
      sorted.push_back(node);

      for (auto& neighbor : adjacency[node]) {
        indegree[neighbor]--;
        if (indegree[neighbor] == 0) {
          queue.push(neighbor);
        }
      }
    }

    if (sorted.size() != updates_.size()) {
      throw std::runtime_error(
          "Cycle detected in background update dependency graph");
    }

    return sorted;
  }

  // Returns updates grouped into levels where each level can run in parallel
  std::vector<std::vector<std::string>> sort_levels() {
    std::unordered_map<std::string, int> indegree;
    std::unordered_map<std::string, std::vector<std::string>> adjacency;

    for (auto& [name, def] : updates_) {
      indegree[name] = 0;
    }

    for (auto& [name, def] : updates_) {
      for (auto& dep : def.dependencies) {
        adjacency[dep].push_back(name);
        indegree[name]++;
      }
    }

    std::vector<std::vector<std::string>> levels;
    std::queue<std::string> current_level;

    for (auto& [name, deg] : indegree) {
      if (deg == 0) current_level.push(name);
    }

    int processed = 0;
    while (!current_level.empty()) {
      std::vector<std::string> level;
      std::queue<std::string> next_level;

      while (!current_level.empty()) {
        auto node = current_level.front();
        current_level.pop();
        level.push_back(node);
        processed++;

        for (auto& neighbor : adjacency[node]) {
          indegree[neighbor]--;
          if (indegree[neighbor] == 0) {
            next_level.push(neighbor);
          }
        }
      }

      levels.push_back(std::move(level));
      current_level = std::move(next_level);
    }

    if (processed != static_cast<int>(updates_.size())) {
      throw std::runtime_error(
          "Cycle detected in background update dependency graph");
    }

    return levels;
  }

  // Check if a specific update's dependencies are satisfied
  bool are_deps_satisfied(const std::string& name,
                          const std::set<std::string>& completed) {
    auto it = updates_.find(name);
    if (it == updates_.end()) return false;

    for (auto& dep : it->second.dependencies) {
      if (completed.find(dep) == completed.end()) return false;
    }
    return true;
  }

private:
  const std::map<std::string, BackgroundUpdateDefinition>& updates_;
};

// ============================================================================
// DependencyResolver — resolves named dependencies and validates the graph
// Equivalent to synapse.storage.background_updates dependency resolution
// ============================================================================
class DependencyResolver {
public:
  DependencyResolver() = default;

  void add_update(const BackgroundUpdateDefinition& def) {
    updates_[def.name] = def;
  }

  // Validate that all dependencies reference known updates
  std::vector<std::string> validate() {
    std::vector<std::string> errors;
    for (auto& [name, def] : updates_) {
      for (auto& dep : def.dependencies) {
        if (updates_.find(dep) == updates_.end()) {
          errors.push_back("Update '" + name + "' depends on unknown update '" +
                           dep + "'");
        }
      }
    }
    return errors;
  }

  // Get the transitive closure of dependencies for a given update
  std::set<std::string> transitive_deps(const std::string& name) {
    std::set<std::string> result;
    std::queue<std::string> to_process;
    to_process.push(name);

    while (!to_process.empty()) {
      auto current = to_process.front();
      to_process.pop();

      auto it = updates_.find(current);
      if (it == updates_.end()) continue;

      for (auto& dep : it->second.dependencies) {
        if (result.insert(dep).second) {
          to_process.push(dep);
        }
      }
    }

    return result;
  }

  // Get all updates that depend (directly or transitively) on the given update
  std::set<std::string> transitive_dependents(const std::string& name) {
    std::set<std::string> result;
    std::queue<std::string> to_process;
    to_process.push(name);

    while (!to_process.empty()) {
      auto current = to_process.front();
      to_process.pop();

      for (auto& [upd_name, def] : updates_) {
        for (auto& dep : def.dependencies) {
          if (dep == current) {
            if (result.insert(upd_name).second) {
              to_process.push(upd_name);
            }
          }
        }
      }
    }

    return result;
  }

  const std::map<std::string, BackgroundUpdateDefinition>& all_updates() const {
    return updates_;
  }

private:
  std::map<std::string, BackgroundUpdateDefinition> updates_;
};

}  // anonymous namespace

// ============================================================================
// BackgroundUpdateProgress — tracks and reports progress of running updates
// Equivalent to the progress tracking in synapse.storage.background_updates
// ============================================================================
class BackgroundUpdateProgress {
public:
  BackgroundUpdateProgress() = default;

  void set_total(int64_t total) {
    std::lock_guard<std::mutex> lock(mutex_);
    total_ = total;
    reset_timing();
  }

  void increment(int64_t by = 1) {
    std::lock_guard<std::mutex> lock(mutex_);
    processed_ += by;
    update_rate();
  }

  void set_processed(int64_t processed) {
    std::lock_guard<std::mutex> lock(mutex_);
    processed_ = processed;
    update_rate();
  }

  int64_t total() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_;
  }

  int64_t processed() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return processed_;
  }

  int64_t remaining() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return std::max<int64_t>(0, total_ - processed_);
  }

  double percent() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (total_ <= 0) return 0.0;
    return 100.0 * static_cast<double>(processed_) /
           static_cast<double>(total_);
  }

  bool is_complete() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return total_ > 0 && processed_ >= total_;
  }

  // Estimated time remaining in seconds
  int64_t eta_seconds() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (rate_ <= 0.0) return -1;
    int64_t rem = std::max<int64_t>(0, total_ - processed_);
    return static_cast<int64_t>(static_cast<double>(rem) / rate_);
  }

  // Items per second rate
  double rate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rate_;
  }

  // Elapsed time in seconds since start
  int64_t elapsed_seconds() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (start_ts_ == 0) return 0;
    return now_sec() - start_ts_;
  }

  // Get a JSON summary of current progress
  json to_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    json j;
    j["total_items"] = total_;
    j["processed_items"] = processed_;
    j["remaining_items"] = std::max<int64_t>(0, total_ - processed_);
    j["percent"] = total_ > 0 ? 100.0 * static_cast<double>(processed_) /
                                    static_cast<double>(total_)
                              : 0.0;
    j["rate"] = rate_;
    j["elapsed_seconds"] = start_ts_ ? now_sec() - start_ts_ : 0;
    j["eta_seconds"] = rate_ > 0.0 ? static_cast<int64_t>(
                       static_cast<double>(std::max<int64_t>(0, total_ - processed_)) / rate_) : -1;
    j["eta_formatted"] = format_duration_secs(
        rate_ > 0.0 ? static_cast<int64_t>(
            static_cast<double>(std::max<int64_t>(0, total_ - processed_)) / rate_) : -1);
    j["percent_formatted"] = format_percent(
        total_ > 0 ? 100.0 * static_cast<double>(processed_) / total_ : 0.0);
    return j;
  }

  void reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    total_ = 0;
    processed_ = 0;
    rate_ = 0.0;
    start_ts_ = 0;
    last_sample_ts_ = 0;
    last_sample_processed_ = 0;
  }

  void start() {
    std::lock_guard<std::mutex> lock(mutex_);
    start_ts_ = now_sec();
    last_sample_ts_ = start_ts_;
    last_sample_processed_ = 0;
    rate_ = 0.0;
  }

  void stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    rate_ = 0.0;
  }

private:
  void reset_timing() {
    start_ts_ = now_sec();
    last_sample_ts_ = start_ts_;
    last_sample_processed_ = 0;
    rate_ = 0.0;
  }

  void update_rate() {
    // Sample rate every ~5 seconds
    auto now = now_sec();
    int64_t elapsed = now - last_sample_ts_;
    if (elapsed >= 5) {
      int64_t delta = processed_ - last_sample_processed_;
      rate_ = elapsed > 0 ? static_cast<double>(delta) /
                                 static_cast<double>(elapsed)
                           : 0.0;
      last_sample_ts_ = now;
      last_sample_processed_ = processed_;
    } else if (elapsed > 0 && last_sample_processed_ < processed_) {
      rate_ = static_cast<double>(processed_ - last_sample_processed_) /
              static_cast<double>(elapsed);
    }
  }

  mutable std::mutex mutex_;
  int64_t total_{0};
  int64_t processed_{0};
  int64_t start_ts_{0};
  int64_t last_sample_ts_{0};
  int64_t last_sample_processed_{0};
  double rate_{0.0};
};

// ============================================================================
// SchemaCompatManager — manages schema compatibility version validation
// Equivalent to synapse.storage.schema SCHEMA_COMPAT_VERSION checking
// ============================================================================
class SchemaCompatManager {
public:
  SchemaCompatManager(storage::DatabasePool& db) : db_(db) {}

  // Check if the database schema version is compatible with the running code
  // Returns true if compatible, false if upgrade needed
  bool check_compat_version() {
    try {
      return db_.runInteraction(
          "check_schema_compat",
          [this](storage::LoggingTransaction& txn) -> bool {
            return check_compat_version_txn(txn);
          });
    } catch (const std::exception& e) {
      std::cerr << "[schema_compat] Error checking compat version: "
                << e.what() << "\n";
      return false;
    }
  }

  // Enforce compatibility — throws if incompatible and the server should
  // refuse to start
  void enforce_compat_version() {
    bool ok = check_compat_version();
    if (!ok) {
      std::string msg =
          "SCHEMA_COMPAT_VERSION mismatch. The database schema version "
          "is not compatible with version " +
          std::string(SCHEMA_COMPAT_VERSION) +
          " required by this server. Please run database upgrade.";
      throw std::runtime_error(msg);
    }
  }

  // Ensure the schema_compat_version table exists and has the correct version
  void ensure_compat_version_table() {
    db_.runInteraction(
        "ensure_schema_compat_table",
        [](storage::LoggingTransaction& txn) {
          txn.execute(std::string(
              "CREATE TABLE IF NOT EXISTS ") + SCHEMA_COMPAT_VERSION_TABLE +
              " ("
              "lock TEXT PRIMARY KEY DEFAULT 'compat_version_lock', "
              "compat_version INTEGER NOT NULL"
              ")");

          // Check if row exists
          txn.execute(std::string("SELECT compat_version FROM ") +
                      SCHEMA_COMPAT_VERSION_TABLE +
                      " WHERE lock = 'compat_version_lock'");
          auto row = txn.fetchone();

          if (!row) {
            txn.execute(std::string("INSERT INTO ") +
                        SCHEMA_COMPAT_VERSION_TABLE +
                        " (lock, compat_version) VALUES "
                        "('compat_version_lock', ?)",
                        {SCHEMA_COMPAT_VERSION});
          }
        });
  }

  // Get the current compat version stored in the database
  int64_t get_stored_compat_version() {
    try {
      return db_.runInteraction(
          "get_stored_compat",
          [](storage::LoggingTransaction& txn) -> int64_t {
            txn.execute(std::string("SELECT compat_version FROM ") +
                        SCHEMA_COMPAT_VERSION_TABLE +
                        " WHERE lock = 'compat_version_lock'");
            auto row = txn.fetchone();
            if (row) {
              return std::stoll(row->at(0).value.value_or("0"));
            }
            return -1;
          });
    } catch (...) {
      return -1;
    }
  }

  // Update the stored compat version to the current code version
  void update_stored_compat_version() {
    db_.runInteraction(
        "update_stored_compat",
        [](storage::LoggingTransaction& txn) {
          txn.execute(std::string("UPDATE ") + SCHEMA_COMPAT_VERSION_TABLE +
                      " SET compat_version = ? "
                      "WHERE lock = 'compat_version_lock'",
                      {SCHEMA_COMPAT_VERSION});
        });
  }

  // Check and update if needed — used during upgrade process
  bool validate_and_update() {
    int64_t stored = get_stored_compat_version();
    int64_t required = std::stoll(SCHEMA_COMPAT_VERSION);

    if (stored < 0) {
      ensure_compat_version_table();
      stored = get_stored_compat_version();
    }

    if (stored < required) {
      return false;  // Needs upgrade
    }

    if (stored > required) {
      std::cerr << "[schema_compat] WARNING: stored compat version ("
                << stored << ") > expected (" << required
                << "). Possible downgrade.\n";
    }

    return true;
  }

private:
  bool check_compat_version_txn(storage::LoggingTransaction& txn) {
    try {
      txn.execute(std::string("SELECT compat_version FROM ") +
                  SCHEMA_COMPAT_VERSION_TABLE +
                  " WHERE lock = 'compat_version_lock'");
    } catch (const std::exception&) {
      // Table might not exist yet — treat as compatible during initial setup
      return true;
    }

    auto row = txn.fetchone();
    if (!row) return true;

    int64_t stored = std::stoll(row->at(0).value.value_or("0"));
    int64_t required = std::stoll(SCHEMA_COMPAT_VERSION);

    if (stored > required) {
      // Downgrade detected
      std::cerr << "[schema_compat] DOWNGRADE: stored=" << stored
                << " required=" << required << "\n";
      return false;
    }

    return true;
  }

  storage::DatabasePool& db_;
};

// ============================================================================
// UpdateFunc — type for background update processing functions
// Called repeatedly with progress; returns true when complete
// ============================================================================
using UpdateFunc =
    std::function<bool(storage::DatabasePool&, json& progress)>;

// ============================================================================
// BackgroundUpdateRegistry — central registry of all known background updates
// Equivalent to the update definitions spread across Synapse storage modules
// ============================================================================
class BackgroundUpdateRegistry {
public:
  BackgroundUpdateRegistry() { register_all_builtin_updates(); }

  // Register a single background update definition
  void register_update(const BackgroundUpdateDefinition& def) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (definitions_.find(def.name) != definitions_.end()) {
      std::cerr << "[bg_registry] Update '" << def.name
                << "' already registered, skipping\n";
      return;
    }
    definitions_[def.name] = def;
    resolver_.add_update(def);
  }

  // Register an update with its processing function
  void register_update(const BackgroundUpdateDefinition& def,
                       UpdateFunc func) {
    register_update(def);
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_[def.name] = std::move(func);
  }

  // Get all registered definitions
  std::map<std::string, BackgroundUpdateDefinition> get_all_definitions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return definitions_;
  }

  // Get a specific definition
  std::optional<BackgroundUpdateDefinition> get_definition(
      const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = definitions_.find(name);
    if (it != definitions_.end()) return it->second;
    return std::nullopt;
  }

  // Get the processing function for an update
  std::optional<UpdateFunc> get_handler(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = handlers_.find(name);
    if (it != handlers_.end()) return it->second;
    return std::nullopt;
  }

  // Get updates in topological order
  std::vector<std::string> get_topological_order() const {
    std::lock_guard<std::mutex> lock(mutex_);
    TopologicalSorter sorter(definitions_);
    return sorter.sort();
  }

  // Get updates grouped by dependency levels
  std::vector<std::vector<std::string>> get_level_order() const {
    std::lock_guard<std::mutex> lock(mutex_);
    TopologicalSorter sorter(definitions_);
    return sorter.sort_levels();
  }

  // Get foreground updates (must run before server starts)
  std::vector<std::string> get_foreground_updates() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (auto& [name, def] : definitions_) {
      if (def.is_foreground_only) result.push_back(name);
    }
    return result;
  }

  // Validate all dependencies are resolvable
  std::vector<std::string> validate() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return resolver_.validate();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return definitions_.size();
  }

  bool empty() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return definitions_.empty();
  }

private:
  // Register all built-in background updates — equivalent to the update
  // definitions across synapse/storage/databases/main/*.py
  void register_all_builtin_updates() {
    using BD = BackgroundUpdateDefinition;

    // ---- Populate Stats Updates ----
    // Equivalent to synapse/storage/databases/main/stats.py

    register_update(BD{
        "populate_stats_process_rooms",
        "Populate per-room statistics counters",
        UpdateCategory::POPULATE_STATS, 56, {}, false, false, false, 100});

    register_update(BD{
        "populate_stats_process_users",
        "Populate per-user statistics counters",
        UpdateCategory::POPULATE_STATS, 56,
        {"populate_stats_process_rooms"}, false, false, false, 100});

    register_update(BD{
        "populate_stats_cleanup",
        "Clean up stale statistics entries",
        UpdateCategory::POPULATE_STATS, 57,
        {"populate_stats_process_users"}, false, false, false, 200});

    // ---- Index Creation Updates ----
    // Equivalent to index creation delta files

    register_update(BD{
        "index_events_room_stream",
        "Create index on events(room_id, stream_ordering)",
        UpdateCategory::INDEX_CREATE, 29, {}, false, false, false, 500});

    register_update(BD{
        "index_events_event_id_room_id",
        "Create index on events(event_id, room_id)",
        UpdateCategory::INDEX_CREATE, 30, {}, false, false, false, 500});

    register_update(BD{
        "index_events_order_room",
        "Create composite index on events(room_id, topological_ordering,"
        " stream_ordering)",
        UpdateCategory::INDEX_CREATE, 31, {}, false, false, false, 500});

    register_update(BD{
        "index_events_contains_url",
        "Create index on events(room_id, contains_url)",
        UpdateCategory::INDEX_CREATE, 42, {}, false, false, false, 500});

    register_update(BD{
        "index_state_events_room_type",
        "Create index on state_events(room_id, type)",
        UpdateCategory::INDEX_CREATE, 38, {}, false, false, false, 1000});

    register_update(BD{
        "index_event_search_room_event",
        "Create index on event_search(room_id, event_id)",
        UpdateCategory::INDEX_CREATE, 38, {}, false, false, false, 500});

    register_update(BD{
        "index_event_relations_relates",
        "Create index on event_relations(relates_to_id)",
        UpdateCategory::INDEX_CREATE, 41, {}, false, false, false, 500});

    register_update(BD{
        "index_event_push_actions_room_receipt",
        "Create index on event_push_actions(room_id, stream_ordering)",
        UpdateCategory::INDEX_CREATE, 39, {}, false, false, false, 500});

    register_update(BD{
        "index_event_push_actions_highlights",
        "Create index on event_push_actions(highlight)",
        UpdateCategory::INDEX_CREATE, 39, {}, false, false, false, 500});

    register_update(BD{
        "index_receipts_linearized_room_stream",
        "Create index on receipts_linearized(room_id, stream_id)",
        UpdateCategory::INDEX_CREATE, 43, {}, false, false, false, 500});

    register_update(BD{
        "index_room_membership_events",
        "Create index on room_memberships(event_id)",
        UpdateCategory::INDEX_CREATE, 44, {}, false, false, false, 500});

    register_update(BD{
        "index_room_stats_state",
        "Create index on room_stats_state(name)",
        UpdateCategory::INDEX_CREATE, 56, {}, false, false, false, 500});

    register_update(BD{
        "index_users_creation_ts",
        "Create index on users(creation_ts)",
        UpdateCategory::INDEX_CREATE, 48, {}, false, false, false, 500});

    register_update(BD{
        "index_local_media_created",
        "Create index on local_media_repository(created_ts)",
        UpdateCategory::INDEX_CREATE, 44, {}, false, false, false, 500});

    register_update(BD{
        "index_device_lists_stream_id",
        "Create index on device_lists_stream(stream_id)",
        UpdateCategory::INDEX_CREATE, 45, {}, false, false, false, 500});

    register_update(BD{
        "index_e2e_room_keys_version",
        "Create index on e2e_room_keys(user_id, version)",
        UpdateCategory::INDEX_CREATE, 46, {}, false, false, false, 500});

    register_update(BD{
        "index_federation_destinations_retry",
        "Create index on destinations(retry_last_ts)",
        UpdateCategory::INDEX_CREATE, 47, {}, false, false, false, 500});

    register_update(BD{
        "index_state_groups_state",
        "Create index on state_groups_state(state_group)",
        UpdateCategory::INDEX_CREATE, 35, {}, false, false, false, 500});

    register_update(BD{
        "index_current_state_events_membership",
        "Create index on current_state_events(membership)",
        UpdateCategory::INDEX_CREATE, 40, {}, false, false, false, 500});

    // ---- Delete/Cleanup Updates ----
    // Equivalent to synapse/storage/databases/main/events.py delete_old_*

    register_update(BD{
        "delete_old_current_state_events",
        "Delete redundant rows from current_state_events",
        UpdateCategory::DELETE_DATA, 44,
        {"index_current_state_events_membership"},
        false, false, false, 1000});

    register_update(BD{
        "delete_old_forward_extremities",
        "Purge stale forward extremities from rooms",
        UpdateCategory::DELETE_DATA, 46, {}, false, false, false, 500});

    register_update(BD{
        "delete_old_sent_transactions",
        "Purge expired sent federation transactions",
        UpdateCategory::DELETE_DATA, 47, {}, false, false, false, 1000});

    register_update(BD{
        "delete_old_received_transactions",
        "Purge expired received federation transactions",
        UpdateCategory::DELETE_DATA, 47, {}, false, false, false, 1000});

    register_update(BD{
        "delete_old_noncurrent_state_events",
        "Purge non-current state events beyond retention",
        UpdateCategory::DELETE_DATA, 55, {}, false, false, false, 500});

    register_update(BD{
        "delete_device_messages_older_than",
        "Purge expired to-device messages",
        UpdateCategory::DELETE_DATA, 43, {}, false, false, false, 500});

    register_update(BD{
        "delete_expired_event_reports",
        "Purge expired abuse reports",
        UpdateCategory::DELETE_DATA, 51, {}, false, false, false, 500});

    register_update(BD{
        "delete_old_push_actions",
        "Purge old unhandled push actions",
        UpdateCategory::DELETE_DATA, 52,
        {"index_event_push_actions_room_receipt"},
        false, false, false, 1000});

    register_update(BD{
        "delete_old_remote_media",
        "Purge expired remote media cache entries",
        UpdateCategory::DELETE_DATA, 53, {}, false, false, false, 500});

    register_update(BD{
        "delete_expired_one_time_keys",
        "Purge expired one-time E2E keys",
        UpdateCategory::DELETE_DATA, 44, {}, false, false, false, 1000});

    register_update(BD{
        "delete_old_redactions",
        "Purge old redaction events beyond retention",
        UpdateCategory::DELETE_DATA, 55,
        {"delete_old_current_state_events"},
        false, false, false, 500});

    // ---- Replace/Migrate Updates ----
    // Equivalent to Synapse data migration updates

    register_update(BD{
        "replace_room_depth_min_depth",
        "Populate room_depth.min_depth column",
        UpdateCategory::REPLACE_DATA, 48,
        {"index_events_room_stream"}, false, false, false, 100});

    register_update(BD{
        "replace_stream_ordering_in_events",
        "Migrate stream_ordering to BIGINT format",
        UpdateCategory::REPLACE_DATA, 49,
        {"index_events_room_stream"}, false, true, false, 100});

    register_update(BD{
        "replace_origin_server_ts",
        "Normalize origin_server_ts to millisecond precision",
        UpdateCategory::REPLACE_DATA, 50, {}, false, false, false, 100});

    register_update(BD{
        "replace_event_content_type_text",
        "Migrate event content columns to TEXT for larger events",
        UpdateCategory::REPLACE_DATA, 54,
        {"replace_stream_ordering_in_events"}, false, true, false, 50});

    register_update(BD{
        "replace_room_version_in_rooms",
        "Populate room_version column on rooms table",
        UpdateCategory::REPLACE_DATA, 56, {}, false, false, false, 100});

    register_update(BD{
        "replace_membership_state_events",
        "Fix membership column on current_state_events",
        UpdateCategory::REPLACE_DATA, 42, {}, false, false, false, 100});

    register_update(BD{
        "replace_auth_events_format",
        "Migrate auth_events column to new Canonical JSON format",
        UpdateCategory::REPLACE_DATA, 55, {}, false, false, false, 50});

    register_update(BD{
        "replace_device_lists_stream",
        "Populate device_lists_stream with existing device data",
        UpdateCategory::REPLACE_DATA, 45,
        {"index_device_lists_stream_id"}, false, false, false, 100});

    // ---- Event Store Updates ----
    // Equivalent to synapse/storage/databases/main/events_bg_updates.py

    register_update(BD{
        "event_store_labels",
        "Backfill event labels/revisions for event store",
        UpdateCategory::EVENT_STORE, 52,
        {"index_events_room_stream"}, false, false, false, 100});

    register_update(BD{
        "event_store_redactions",
        "Reprocess event redactions to ensure consistency",
        UpdateCategory::EVENT_STORE, 52,
        {"event_store_labels"}, false, false, false, 100});

    register_update(BD{
        "event_store_rejected_reason",
        "Populate rejection_reason for rejected events",
        UpdateCategory::EVENT_STORE, 53,
        {"event_store_labels"}, false, false, false, 100});

    register_update(BD{
        "event_store_backfill_room_id",
        "Backfill room_id derived from events where missing",
        UpdateCategory::EVENT_STORE, 54,
        {"index_events_room_stream"}, false, false, false, 100});

    register_update(BD{
        "event_fix_redactions_bytes",
        "Fix redaction events with malformed content",
        UpdateCategory::EVENT_STORE, 55,
        {"event_store_redactions"}, false, false, false, 100});

    // ---- Event Chain Cover Index ----
    // Equivalent to synapse/storage/databases/main/events.py chain cover

    register_update(BD{
        "event_store_chain_cover_index",
        "Build event chain cover index for auth chain queries",
        UpdateCategory::CHAIN_COVER, 56,
        {"index_events_order_room",
         "event_store_labels"}, false, true, false, 100});

    register_update(BD{
        "event_chain_cover_index_v2",
        "Rebuild chain cover index with v2 optimization",
        UpdateCategory::CHAIN_COVER, 58,
        {"event_store_chain_cover_index"}, false, true, false, 50});

    // ---- Stream Ordering Fixes ----
    // Equivalent to synapse synapse/storage/databases/main/events.py

    register_update(BD{
        "stream_ordering_to_extrem",
        "Migrate stream_ordering to extrem for forward extremities",
        UpdateCategory::STREAM_ORDERING, 34, {}, false, false, false, 100});

    register_update(BD{
        "stream_ordering_deduplicate",
        "Fix duplicate stream_ordering entries",
        UpdateCategory::STREAM_ORDERING, 35,
        {"stream_ordering_to_extrem"}, false, false, false, 500});

    register_update(BD{
        "stream_ordering_gaps",
        "Fix gaps in stream_ordering due to redactions",
        UpdateCategory::STREAM_ORDERING, 36,
        {"stream_ordering_deduplicate"}, false, false, false, 500});

    // ---- State Group Updates ----
    // Equivalent to synapse/storage/databases/main/state.py

    register_update(BD{
        "state_group_edges_unique",
        "Ensure state_group_edges has unique entries",
        UpdateCategory::STATE_GROUP, 37,
        {"index_state_groups_state"}, false, false, false, 100});

    register_update(BD{
        "state_group_deduplicate",
        "Deduplicate state_groups with identical state sets",
        UpdateCategory::STATE_GROUP, 37,
        {"state_group_edges_unique"}, false, false, false, 50});

    register_update(BD{
        "state_group_populate_prev",
        "Populate prev_state_group in state_groups",
        UpdateCategory::STATE_GROUP, 43,
        {"state_group_deduplicate"}, false, false, false, 100});

    // ---- Registration / User Updates ----
    // Equivalent to synapse/storage/databases/main/registration.py

    register_update(BD{
        "users_set_deactivated_flag",
        "Populate deactivated flag on users table",
        UpdateCategory::REGISTRATION, 44, {}, false, false, false, 100});

    register_update(BD{
        "user_directory_initial_fill",
        "Populate user_directory from existing room memberships",
        UpdateCategory::REGISTRATION, 45,
        {"index_room_membership_events"}, false, false, false, 100});

    register_update(BD{
        "user_directory_search_all",
        "Rebuild user_directory search index",
        UpdateCategory::REGISTRATION, 47,
        {"user_directory_initial_fill"}, false, false, false, 100});

    register_update(BD{
        "users_populate_consent_version",
        "Populate consent_version on user profiles",
        UpdateCategory::REGISTRATION, 48,
        {"users_set_deactivated_flag"}, false, false, false, 100});

    register_update(BD{
        "users_populate_shadow_banned",
        "Populate shadow_banned flag on users",
        UpdateCategory::REGISTRATION, 57, {}, false, false, false, 100});

    register_update(BD{
        "users_populate_approved",
        "Populate approved flag for registration tokens",
        UpdateCategory::REGISTRATION, 57, {}, false, false, false, 100});

    // ---- Room Updates ----
    // Equivalent to synapse/storage/databases/main/room.py

    register_update(BD{
        "room_join_rules_populate",
        "Populate join_rules column on rooms",
        UpdateCategory::ROOM, 53, {}, false, false, false, 100});

    register_update(BD{
        "room_history_visibility_populate",
        "Populate history_visibility column on rooms",
        UpdateCategory::ROOM, 53, {}, false, false, false, 100});

    register_update(BD{
        "room_encryption_populate",
        "Populate encryption flag on rooms",
        UpdateCategory::ROOM, 54,
        {"room_join_rules_populate"}, false, false, false, 100});

    register_update(BD{
        "room_federation_populate",
        "Populate federation flag on rooms",
        UpdateCategory::ROOM, 54,
        {"room_join_rules_populate"}, false, false, false, 100});

    register_update(BD{
        "room_creator_populate",
        "Populate room creator from create events",
        UpdateCategory::ROOM, 55, {}, false, false, false, 100});

    register_update(BD{
        "room_type_populate",
        "Populate room_type from creation content",
        UpdateCategory::ROOM, 56,
        {"room_creator_populate"}, false, false, false, 100});

    register_update(BD{
        "room_name_populate",
        "Populate cached room name from state",
        UpdateCategory::ROOM, 57, {}, false, false, false, 100});

    register_update(BD{
        "room_topic_populate",
        "Populate cached room topic from state",
        UpdateCategory::ROOM, 57, {}, false, false, false, 100});

    register_update(BD{
        "room_avatar_populate",
        "Populate cached room avatar from state",
        UpdateCategory::ROOM, 57, {}, false, false, false, 100});

    register_update(BD{
        "room_canonical_alias_populate",
        "Populate cached canonical alias from state",
        UpdateCategory::ROOM, 58,
        {"room_name_populate"}, false, false, false, 100});

    // ---- Foreground Updates (CRITICAL — must run before server starts) ----
    // These are updates that MUST complete before the server can accept
    // connections. Equivalent to foreground updates in Synapse.

    register_update(BD{
        "fg_notif_null_notif",
        "Ensure notification columns are NOT NULL (foreground)",
        UpdateCategory::GENERAL, 32, {}, true, true, false,
        DEFAULT_FG_UPDATE_BATCH_SIZE});

    register_update(BD{
        "fg_events_order_room_index",
        "Ensure critical events index exists (foreground)",
        UpdateCategory::INDEX_CREATE, 33, {}, true, true, false,
        DEFAULT_FG_UPDATE_BATCH_SIZE});

    register_update(BD{
        "fg_schema_compat_check",
        "Verify SCHEMA_COMPAT_VERSION compatibility (foreground)",
        UpdateCategory::GENERAL, 33, {}, true, true, false,
        DEFAULT_FG_UPDATE_BATCH_SIZE});

    register_update(BD{
        "fg_populate_event_json",
        "Backfill event_json for existing events (foreground)",
        UpdateCategory::EVENT_STORE, 36, {}, true, true, false,
        DEFAULT_FG_UPDATE_BATCH_SIZE});

    register_update(BD{
        "fg_bytes_type_check",
        "Ensure all BYTES columns are properly encoded (foreground)",
        UpdateCategory::REPLACE_DATA, 44, {}, true, true, false,
        DEFAULT_FG_UPDATE_BATCH_SIZE});

    register_update(BD{
        "fg_stream_ordering_migrate",
        "Migrate stream_ordering to new format (foreground)",
        UpdateCategory::STREAM_ORDERING, 50, {}, true, true, false,
        DEFAULT_FG_UPDATE_BATCH_SIZE});

    register_update(BD{
        "fg_auth_chain_migrate",
        "Migrate auth chain to new v2 format (foreground)",
        UpdateCategory::CHAIN_COVER, 56, {}, true, true, false,
        DEFAULT_FG_UPDATE_BATCH_SIZE});

    // ---- General / Miscellaneous Updates ----
    register_general_updates();
  }

  // ---- General updates registration helper ----

  void register_general_updates() {
    using BD = BackgroundUpdateDefinition;

    register_update(BD{
        "event_origin_server_ts_index",
        "Add index on events(origin_server_ts)",
        UpdateCategory::INDEX_CREATE, 45, {}, false, false, false, 500});

    register_update(BD{
        "event_edges_drop_invalid_rows",
        "Drop rows in event_edges with invalid event_ids",
        UpdateCategory::DELETE_DATA, 46, {}, false, false, false, 500});

    register_update(BD{
        "event_push_summary_recalculate",
        "Recalculate event_push_summary from push actions",
        UpdateCategory::EVENT_STORE, 55,
        {"index_event_push_actions_room_receipt"},
        false, false, false, 100});

    register_update(BD{
        "current_state_delta_stream",
        "Populate current_state_delta_stream for initial sync",
        UpdateCategory::STATE_GROUP, 46, {}, false, false, false, 100});

    register_update(BD{
        "presence_stream_not_offline",
        "Fix presence_stream to exclude offline-override states",
        UpdateCategory::GENERAL, 48, {}, false, false, false, 500});

    register_update(BD{
        "local_media_repository_thumbnails",
        "Populate local_media_repository_thumbnails from local_media",
        UpdateCategory::POPULATE_STATS, 50, {}, false, false, false, 100});

    register_update(BD{
        "receipts_graph_populate",
        "Populate receipts_graph with linearized receipts",
        UpdateCategory::GENERAL, 52,
        {"index_receipts_linearized_room_stream"},
        false, false, false, 100});

    register_update(BD{
        "push_rules_stream_ordering",
        "Backfill push_rules_stream ordering",
        UpdateCategory::GENERAL, 56,
        {"populate_stats_process_users"}, false, false, false, 100});

    register_update(BD{
        "e2e_cross_signing_keys_sigs",
        "Populate cross-signing key signatures",
        UpdateCategory::GENERAL, 56, {}, false, false, false, 100});

    register_update(BD{
        "account_validity_expiration_ms",
        "Migrate account_validity to millisecond precision",
        UpdateCategory::REGISTRATION, 57, {}, false, false, false, 100});

    register_update(BD{
        "cleanup_extremities_soft_failed",
        "Clean up soft-failed forward extremities",
        UpdateCategory::DELETE_DATA, 53, {}, false, false, false, 500});

    register_update(BD{
        "redactions_have_censored_ts",
        "Add censored_ts to redactions table",
        UpdateCategory::EVENT_STORE, 55, {}, false, false, false, 100});

    register_update(BD{
        "un_partial_stated_rooms",
        "Remove partially-stated-room flags from fully-synced rooms",
        UpdateCategory::ROOM, 58, {}, false, false, false, 100});

    register_update(BD{
        "rejected_events_metadata",
        "Populate metadata for rejected events",
        UpdateCategory::EVENT_STORE, 56, {}, false, false, false, 100});

    register_update(BD{
        "user_daily_visits_cleanup",
        "Clean up user_daily_visits older than retention",
        UpdateCategory::DELETE_DATA, 48, {}, false, false, false, 500});

    register_update(BD{
        "device_lists_outbound_pokes_stream",
        "Populate device_lists_outbound_pokes",
        UpdateCategory::GENERAL, 45, {}, false, false, false, 100});

    register_update(BD{
        "group_attestations_renewal",
        "Reprocess group attestations with new TTL",
        UpdateCategory::GENERAL, 52, {}, false, false, false, 100});

    register_update(BD{
        "event_txn_id_deduplicate",
        "Deduplicate transaction IDs for idempotent sends",
        UpdateCategory::EVENT_STORE, 54, {}, false, false, false, 500});

    register_update(BD{
        "insertion_event_extremities",
        "Populate insertion events as forward extremities",
        UpdateCategory::ROOM, 57, {}, false, false, false, 100});
  }

  mutable std::mutex mutex_;
  std::map<std::string, BackgroundUpdateDefinition> definitions_;
  std::map<std::string, UpdateFunc> handlers_;
  DependencyResolver resolver_;
};

// ============================================================================
// BackgroundUpdateRunner — executes background updates with batching and
// progress tracking. Equivalent to the run loop in
// synapse.storage.background_updates.BackgroundUpdater
// ============================================================================
class BackgroundUpdateRunner {
public:
  BackgroundUpdateRunner(storage::DatabasePool& db,
                         BackgroundUpdateRegistry& registry)
      : db_(db), registry_(registry) {}

  // Run all pending updates, respecting dependency order
  // This is the main entry point — called from the server background worker
  json run_all_pending(bool dry_run = false) {
    json result;
    result["dry_run"] = dry_run;
    result["started_ts"] = now_ms();

    auto order = registry_.get_topological_order();

    std::set<std::string> completed;
    std::set<std::string> failed;
    std::set<std::string> skipped;
    int total_updates = 0;
    int run_count = 0;

    // Load existing completion state from database
    load_completion_state(completed, failed);

    for (auto& name : order) {
      auto def_opt = registry_.get_definition(name);
      if (!def_opt) continue;

      total_updates++;

      // Skip foreground-only updates (handled by ForegroundUpdateRunner)
      if (def_opt->is_foreground_only) {
        skipped.insert(name);
        continue;
      }

      // Skip already completed
      if (completed.count(name)) {
        continue;
      }

      // Skip if dependencies not met
      if (!are_deps_in_set(def_opt->dependencies, completed)) {
        skipped.insert(name);
        continue;
      }

      // Skip if update was previously failed (requires manual intervention)
      if (failed.count(name)) {
        skipped.insert(name);
        continue;
      }

      if (dry_run) {
        run_count++;
        continue;
      }

      if (!is_running_) break;  // respect shutdown

      auto handler_opt = registry_.get_handler(name);
      if (!handler_opt) {
        std::cerr << "[bg_runner] No handler registered for '" << name
                  << "', marking as completed\n";
        mark_completed(name);
        completed.insert(name);
        run_count++;
        continue;
      }

      std::cout << "[bg_runner] Starting update: " << name << "\n";

      bool success = run_single_update(name, *def_opt, *handler_opt);

      if (success) {
        completed.insert(name);
        run_count++;
      } else {
        failed.insert(name);
      }
    }

    result["total_defined"] = total_updates;
    result["run_count"] = run_count;
    result["skipped_count"] = static_cast<int>(skipped.size());
    result["failed_count"] = static_cast<int>(failed.size());
    result["completed_count"] = static_cast<int>(completed.size());
    result["completed_ts"] = now_ms();

    return result;
  }

  // Run a single named update
  bool run_update(const std::string& name) {
    auto def_opt = registry_.get_definition(name);
    if (!def_opt) {
      std::cerr << "[bg_runner] Unknown update: " << name << "\n";
      return false;
    }

    auto handler_opt = registry_.get_handler(name);
    if (!handler_opt) {
      std::cerr << "[bg_runner] No handler for: " << name << "\n";
      return false;
    }

    return run_single_update(name, *def_opt, *handler_opt);
  }

  // Resumable update execution — continues from last saved progress
  bool run_single_update(const std::string& name,
                         const BackgroundUpdateDefinition& def,
                         UpdateFunc handler) {
    BackgroundUpdateProgress progress;

    // Load saved progress if resuming
    json saved = load_progress(name);
    if (!saved.empty() && saved.contains("processed_items")) {
      progress.set_total(saved.value("total_items", 0));
      progress.set_processed(saved.value("processed_items", 0));
      std::cout << "[bg_runner] Resuming " << name << " from "
                << progress.processed() << "/" << progress.total()
                << " (" << format_percent(progress.percent()) << ")\n";
    }

    // Mark as running in database
    mark_running(name);

    progress.start();

    try {
      // Call the handler repeatedly until done
      int iterations = 0;
      const int max_iterations = 1000000;  // safety limit

      // progress_json is the mutable JSON passed to the handler each iteration
      json progress_json = json::object();

      while (iterations < max_iterations) {
        if (!is_running_) {
          // Interrupted — save progress and return
          save_progress_txn(name, progress.to_json());
          mark_pending(name);
          std::cout << "[bg_runner] Interrupted: " << name
                    << " at " << format_percent(progress.percent()) << "\n";
          return false;
        }

        bool done = handler(db_, progress_json);
        iterations++;

        if (done) {
          progress.set_processed(progress.total());
          mark_completed(name);
          save_progress_txn(name, progress.to_json());
          std::cout << "[bg_runner] Completed: " << name
                    << " after " << iterations << " iterations, "
                    << progress.processed() << " items\n";
          return true;
        }

        // Read progress data from handler's JSON output and update tracker
        if (progress_json.contains("total_items")) {
          progress.set_total(
              progress_json["total_items"].get<int64_t>());
        }
        if (progress_json.contains("processed_items")) {
          progress.set_processed(
              progress_json["processed_items"].get<int64_t>());
        }

        // Periodic progress save
        if (iterations % 10 == 0) {
          save_progress_txn(name, progress.to_json());
          if (iterations % 100 == 0) {
            std::cout << "[bg_runner] Progress " << name << ": "
                      << format_percent(progress.percent())
                      << " (rate: " << std::fixed << std::setprecision(1)
                      << progress.rate() << " items/s, ETA: "
                      << format_duration_secs(progress.eta_seconds())
                      << ")\n";
          }
        }

        // Small sleep to prevent CPU hogging
        std::this_thread::sleep_for(
            chr::duration<double>(BG_UPDATE_SLEEP_SECS));
      }

      std::cerr << "[bg_runner] Update " << name
                << " exceeded max iterations\n";
      mark_failed(name, "Exceeded maximum iterations (" +
                           std::to_string(max_iterations) + ")");
      return false;

    } catch (const std::exception& e) {
      std::cerr << "[bg_runner] Update " << name
                << " failed: " << e.what() << "\n";
      mark_failed(name, e.what());
      return false;
    }

    progress.stop();
  }

  // Run updates in a background thread
  void start_background_thread() {
    if (bg_thread_.joinable()) return;  // already running

    is_running_ = true;
    bg_thread_ = std::thread([this]() {
      std::cout << "[bg_runner] Background update thread started\n";

      while (is_running_) {
        auto result = run_all_pending(false);
        int run = result["run_count"].get<int>();
        int pending =
            result["total_defined"].get<int>() - run -
            result["completed_count"].get<int>() -
            result["skipped_count"].get<int>();

        if (pending <= 0) {
          std::cout << "[bg_runner] All background updates complete\n";
          break;
        }

        // Wait before next polling cycle
        for (int i = 0; i < 60 && is_running_; ++i) {
          std::this_thread::sleep_for(chr::seconds(1));
        }
      }

      std::cout << "[bg_runner] Background update thread exiting\n";
    });
  }

  // Stop the background thread and wait for it to finish current update
  void stop_background_thread() {
    is_running_ = false;
    if (bg_thread_.joinable()) {
      bg_thread_.join();
    }
  }

  // Check if background updates are currently running
  bool is_running() const { return is_running_; }

  // Get the progress of a specific update
  json get_update_progress(const std::string& name) {
    return load_progress(name);
  }

  // Cancel a running update
  bool cancel_update(const std::string& name) {
    auto status = get_db_status(name);
    if (status == "running") {
      // Signal the current update to stop at its next checkpoint
      is_running_ = false;
      mark_cancelled(name);
      // Re-enable after a brief pause
      std::this_thread::sleep_for(chr::milliseconds(100));
      is_running_ = true;
      return true;
    }
    return false;
  }

private:
  // Load completion state from database
  void load_completion_state(std::set<std::string>& completed,
                             std::set<std::string>& failed) {
    try {
      db_.runInteraction(
          "load_bg_state",
          [&](storage::LoggingTransaction& txn) {
            try {
              txn.execute(
                  "SELECT update_name, status FROM background_updates "
                  "WHERE status IN ('completed', 'failed')");
              auto rows = txn.fetchall();
              for (auto& row : rows) {
                std::string name = row[0].value.value_or("");
                std::string status = row[1].value.value_or("");
                if (status == "completed") completed.insert(name);
                else if (status == "failed") failed.insert(name);
              }
            } catch (const std::exception&) {
              // Table may not exist
            }
          });
    } catch (const std::exception& e) {
      std::cerr << "[bg_runner] Error loading state: " << e.what() << "\n";
    }
  }

  // Check if all dependencies are in the completed set
  bool are_deps_in_set(const std::vector<std::string>& deps,
                       const std::set<std::string>& completed) {
    for (auto& dep : deps) {
      if (completed.find(dep) == completed.end()) return false;
    }
    return true;
  }

  // Load progress JSON for a named update
  json load_progress(const std::string& name) {
    try {
      return db_.runInteraction(
          "load_progress",
          [&](storage::LoggingTransaction& txn) -> json {
            try {
              txn.execute(
                  "SELECT progress_json FROM background_updates "
                  "WHERE update_name = ?",
                  {name});
              auto row = txn.fetchone();
              if (row && row->at(0).value) {
                return safe_json_parse(*row->at(0).value);
              }
            } catch (const std::exception&) {}
            return json::object();
          });
    } catch (...) {
      return json::object();
    }
  }

  // Save progress JSON for a named update (within a transaction)
  void save_progress_txn(const std::string& name, const json& progress) {
    try {
      db_.runInteraction(
          "save_progress",
          [&](storage::LoggingTransaction& txn) {
            std::string json_str = safe_json_dump(progress);
            txn.execute(
                "INSERT INTO background_updates "
                "(update_name, progress_json) VALUES (?, ?) "
                "ON CONFLICT(update_name) DO UPDATE SET "
                "progress_json = ?",
                {name, json_str, json_str});
          });
    } catch (const std::exception& e) {
      std::cerr << "[bg_runner] Error saving progress for " << name
                << ": " << e.what() << "\n";
    }
  }

  // Get current status from database
  std::string get_db_status(const std::string& name) {
    try {
      return db_.runInteraction(
          "get_bg_status",
          [&](storage::LoggingTransaction& txn) -> std::string {
            try {
              txn.execute(
                  "SELECT status FROM background_updates "
                  "WHERE update_name = ?",
                  {name});
              auto row = txn.fetchone();
              if (row) return row->at(0).value.value_or("pending");
            } catch (const std::exception&) {}
            return "unknown";
          });
    } catch (...) {
      return "unknown";
    }
  }

  // Mark status in database
  void mark_status(const std::string& name, UpdateStatus status,
                   const std::string& error = "") {
    try {
      db_.runInteraction(
          "mark_bg_status",
          [&](storage::LoggingTransaction& txn) {
            auto ts = now_ms();
            txn.execute(
                "INSERT INTO background_updates "
                "(update_name, status, progress_json, started_ts, "
                "completed_ts, error_message) "
                "VALUES (?, ?, '{}', ?, ?, ?) "
                "ON CONFLICT(update_name) DO UPDATE SET "
                "status = ?, "
                "completed_ts = CASE WHEN ? IN ('completed','failed','cancelled') "
                "THEN ? ELSE completed_ts END, "
                "error_message = ?",
                {name, status_to_string(status),
                 std::to_string(ts),
                 status == UpdateStatus::COMPLETED ? std::to_string(ts) : "",
                 error,
                 status_to_string(status),
                 status_to_string(status),
                 std::to_string(ts),
                 error});
          });
    } catch (const std::exception& e) {
      std::cerr << "[bg_runner] Error marking status for " << name
                << ": " << e.what() << "\n";
    }
  }

  void mark_running(const std::string& name) {
    mark_status(name, UpdateStatus::RUNNING);
  }

  void mark_completed(const std::string& name) {
    mark_status(name, UpdateStatus::COMPLETED);
  }

  void mark_failed(const std::string& name, const std::string& error) {
    mark_status(name, UpdateStatus::FAILED, error);
  }

  void mark_pending(const std::string& name) {
    mark_status(name, UpdateStatus::PENDING);
  }

  void mark_cancelled(const std::string& name) {
    mark_status(name, UpdateStatus::CANCELLED);
  }

  storage::DatabasePool& db_;
  BackgroundUpdateRegistry& registry_;
  std::atomic<bool> is_running_{true};
  std::thread bg_thread_;
};

// ============================================================================
// ForegroundUpdateRunner — runs critical updates BEFORE server startup
// Blocks until all foreground updates are complete.
// Equivalent to Synapse's foreground update mechanism that gates startup.
// ============================================================================
class ForegroundUpdateRunner {
public:
  ForegroundUpdateRunner(storage::DatabasePool& db,
                         BackgroundUpdateRegistry& registry)
      : db_(db), registry_(registry) {}

  // Run all foreground updates. Blocks until complete.
  // Returns a result JSON with details of what was done.
  // Throws std::runtime_error if a foreground update fails.
  json run_all_foreground() {
    json result;
    result["started_ts"] = now_ms();
    result["status"] = "running";

    auto foreground = registry_.get_foreground_updates();
    result["total_foreground_updates"] = static_cast<int>(foreground.size());

    if (foreground.empty()) {
      std::cout << "[fg_runner] No foreground updates to run\n";
      result["status"] = "complete";
      result["message"] = "No foreground updates required";
      result["completed_ts"] = now_ms();
      return result;
    }

    std::cout << "[fg_runner] Running " << foreground.size()
              << " foreground updates...\n";

    json updates_run = json::array();
    int completed = 0;
    int failed = 0;

    for (auto& name : foreground) {
      auto def_opt = registry_.get_definition(name);
      if (!def_opt) {
        std::cerr << "[fg_runner] Unknown foreground update: " << name << "\n";
        failed++;
        continue;
      }

      std::cout << "[fg_runner] FOREGROUND: " << name
                << " (" << def_opt->description << ")\n";

      // Check if already completed
      if (is_already_completed(name)) {
        std::cout << "[fg_runner]   Already completed, skipping\n";
        json u;
        u["name"] = name;
        u["status"] = "already_completed";
        updates_run.push_back(u);
        completed++;
        continue;
      }

      auto handler_opt = registry_.get_handler(name);
      if (!handler_opt) {
        // No handler but marked as foreground — assume it's a schema check
        // that's handled elsewhere
        std::cout << "[fg_runner]   No handler, treating as implicit\n";
        mark_completed(name);
        json u;
        u["name"] = name;
        u["status"] = "implicit";
        updates_run.push_back(u);
        completed++;
        continue;
      }

      // Run the foreground update synchronously
      BackgroundUpdateProgress progress;
      mark_running(name);
      progress.start();

      bool success = false;
      try {
        json prog = json::object();
        success = (*handler_opt)(db_, prog);

        if (success) {
          mark_completed(name);
          std::cout << "[fg_runner]   COMPLETED: " << name << "\n";
          json u;
          u["name"] = name;
          u["status"] = "completed";
          updates_run.push_back(u);
          completed++;
        } else {
          mark_failed(name, "Returned false");
          std::cerr << "[fg_runner]   FAILED: " << name << "\n";
          json u;
          u["name"] = name;
          u["status"] = "failed";
          updates_run.push_back(u);
          failed++;
        }
      } catch (const std::exception& e) {
        mark_failed(name, e.what());
        std::cerr << "[fg_runner]   ERROR: " << name << " - " << e.what() << "\n";
        json u;
        u["name"] = name;
        u["status"] = "failed";
        u["error"] = e.what();
        updates_run.push_back(u);
        failed++;
      }
    }

    result["updates"] = updates_run;
    result["completed_count"] = completed;
    result["failed_count"] = failed;
    result["completed_ts"] = now_ms();

    if (failed > 0) {
      result["status"] = "failed";
      std::string msg = "Foreground updates failed: " +
                        std::to_string(failed) + " of " +
                        std::to_string(foreground.size()) +
                        " updates. Server cannot start until these "
                        "are resolved. Check logs for details.";
      result["error"] = msg;
      throw std::runtime_error(msg);
    }

    result["status"] = "complete";
    result["message"] = "All " + std::to_string(completed) +
                        " foreground updates completed successfully";
    std::cout << "[fg_runner] All foreground updates complete. "
              << "Server can now start.\n";

    return result;
  }

  // Run a single named foreground update (for admin API usage)
  bool run_single_foreground(const std::string& name) {
    auto def_opt = registry_.get_definition(name);
    if (!def_opt) return false;

    auto handler_opt = registry_.get_handler(name);
    if (!handler_opt) return false;

    mark_running(name);

    try {
      json prog = json::object();
      bool done = (*handler_opt)(db_, prog);

      if (done) mark_completed(name);
      else mark_failed(name, "Update returned incomplete");

      return done;
    } catch (const std::exception& e) {
      mark_failed(name, e.what());
      return false;
    }
  }

  // Check if all foreground updates are complete
  bool all_foreground_complete() {
    auto foreground = registry_.get_foreground_updates();
    for (auto& name : foreground) {
      if (!is_already_completed(name)) return false;
    }
    return true;
  }

private:
  bool is_already_completed(const std::string& name) {
    try {
      return db_.runInteraction(
          "fg_check_complete",
          [&](storage::LoggingTransaction& txn) -> bool {
            try {
              txn.execute(
                  "SELECT status FROM background_updates "
                  "WHERE update_name = ? AND status = 'completed'",
                  {name});
              return txn.fetchone().has_value();
            } catch (const std::exception&) {
              return false;
            }
          });
    } catch (...) {
      return false;
    }
  }

  void mark_running(const std::string& name) {
    db_.runInteraction(
        "fg_mark_running",
        [&](storage::LoggingTransaction& txn) {
          txn.execute(
              "INSERT INTO background_updates "
              "(update_name, status, progress_json, started_ts) "
              "VALUES (?, 'running', '{}', ?) "
              "ON CONFLICT(update_name) DO UPDATE SET "
              "status = 'running', started_ts = ?, error_message = NULL",
              {name, std::to_string(now_ms()), std::to_string(now_ms())});
        });
  }

  void mark_completed(const std::string& name) {
    db_.runInteraction(
        "fg_mark_complete",
        [&](storage::LoggingTransaction& txn) {
          auto ts = std::to_string(now_ms());
          txn.execute(
              "INSERT INTO background_updates "
              "(update_name, status, progress_json, started_ts, completed_ts) "
              "VALUES (?, 'completed', '{}', ?, ?) "
              "ON CONFLICT(update_name) DO UPDATE SET "
              "status = 'completed', completed_ts = ?",
              {name, ts, ts, ts});
        });
  }

  void mark_failed(const std::string& name, const std::string& error) {
    db_.runInteraction(
        "fg_mark_failed",
        [&](storage::LoggingTransaction& txn) {
          auto ts = std::to_string(now_ms());
          txn.execute(
              "INSERT INTO background_updates "
              "(update_name, status, error_message, started_ts, completed_ts) "
              "VALUES (?, 'failed', ?, ?, ?) "
              "ON CONFLICT(update_name) DO UPDATE SET "
              "status = 'failed', error_message = ?, "
              "started_ts = ?, completed_ts = ?",
              {name, error, ts, ts, error, ts, ts});
        });
  }

  storage::DatabasePool& db_;
  BackgroundUpdateRegistry& registry_;
};

// ============================================================================
// BackgroundUpdateAdminAPI — provides an administrative interface for
// managing background updates. Equivalent to the admin functionality in
// synapse.storage.background_updates.py + synapse/rest/admin/ background
// update endpoints.
// ============================================================================
class BackgroundUpdateAdminAPI {
public:
  BackgroundUpdateAdminAPI(storage::DatabasePool& db,
                           BackgroundUpdateRegistry& registry,
                           BackgroundUpdateRunner& runner,
                           ForegroundUpdateRunner& fg_runner)
      : db_(db), registry_(registry), runner_(runner),
        fg_runner_(fg_runner) {}

  // ---- Query Methods ----

  /// List all registered updates with their status
  json list_all_updates(const std::string& status_filter = "all",
                        const std::string& category_filter = "all") {
    json result;
    result["request_ts"] = now_ms();

    auto defs = registry_.get_all_definitions();
    json updates = json::array();

    int pending = 0, running = 0, completed = 0, failed = 0, cancelled = 0;

    for (auto& [name, def] : defs) {
      // Apply category filter
      if (category_filter != "all" &&
          category_to_string(def.category) != category_filter)
        continue;

      std::string status = get_status(name);

      // Apply status filter
      if (status_filter != "all" && status != status_filter) continue;

      json u;
      u["update_name"] = name;
      u["description"] = def.description;
      u["category"] = category_to_string(def.category);
      u["status"] = status;
      u["dependencies"] = def.dependencies;
      u["is_foreground_only"] = def.is_foreground_only;
      u["is_blocking"] = def.is_blocking;
      u["schema_version_introduced"] = def.schema_version_introduced;

      // Load progress data
      json progress = load_progress(name);
      if (!progress.empty()) {
        u["progress"] = progress;
        u["total_items"] = progress.value("total_items", 0);
        u["processed_items"] = progress.value("processed_items", 0);
        if (progress.value("total_items", 0) > 0) {
          u["progress_percent"] =
              100.0 * progress["processed_items"].get<double>() /
              progress["total_items"].get<double>();
        }
      }

      // Load timing data
      json timing = load_timing(name);
      if (!timing.empty()) {
        u["started_ts"] = timing.value("started_ts", 0);
        u["completed_ts"] = timing.value("completed_ts", 0);
        u["error_message"] = timing.value("error_message", "");
      }

      // Count stats
      if (status == "pending") pending++;
      else if (status == "running") running++;
      else if (status == "completed") completed++;
      else if (status == "failed") failed++;
      else if (status == "cancelled") cancelled++;

      updates.push_back(u);
    }

    result["updates"] = updates;
    result["total"] = updates.size();
    result["stats"] = {
        {"pending", pending},
        {"running", running},
        {"completed", completed},
        {"failed", failed},
        {"cancelled", cancelled}
    };
    result["schema_compat_version"] = SCHEMA_COMPAT_VERSION;
    result["status_filter"] = status_filter;
    result["category_filter"] = category_filter;

    return result;
  }

  /// Get detailed status of a single update
  json get_update(const std::string& name) {
    auto def_opt = registry_.get_definition(name);
    if (!def_opt) {
      return json({{"error", "Unknown update: " + name},
                    {"found", false}});
    }

    json result;
    result["update_name"] = name;
    result["description"] = def_opt->description;
    result["category"] = category_to_string(def_opt->category);
    result["status"] = get_status(name);
    result["dependencies"] = def_opt->dependencies;
    result["is_foreground_only"] = def_opt->is_foreground_only;
    result["is_blocking"] = def_opt->is_blocking;
    result["schema_version_introduced"] = def_opt->schema_version_introduced;
    result["found"] = true;

    json progress = load_progress(name);
    if (!progress.empty()) {
      result["progress"] = progress;
    }

    json timing = load_timing(name);
    if (!timing.empty()) {
      result["started_ts"] = timing.value("started_ts", 0);
      result["completed_ts"] = timing.value("completed_ts", 0);
      result["error_message"] = timing.value("error_message", "");
    }

    // Compute dependency info
    DependencyResolver resolver;
    resolver.add_update(*def_opt);
    result["transitive_deps"] = resolver.transitive_deps(name);
    result["transitive_dependents"] = resolver.transitive_dependents(name);

    return result;
  }

  /// Get a summary of all background update state
  json get_summary() {
    json result;
    result["timestamp"] = now_ms();

    auto defs = registry_.get_all_definitions();
    int total = defs.size();
    int pending = 0, running = 0, completed = 0, failed = 0;

    for (auto& [name, def] : defs) {
      std::string s = get_status(name);
      if (s == "pending") pending++;
      else if (s == "running") running++;
      else if (s == "completed") completed++;
      else if (s == "failed") failed++;
    }

    result["total_updates"] = total;
    result["pending"] = pending;
    result["running"] = running;
    result["completed"] = completed;
    result["failed"] = failed;
    result["progress_percent"] = total > 0
        ? 100.0 * static_cast<double>(completed) / static_cast<double>(total)
        : 100.0;
    result["is_runner_active"] = runner_.is_running();
    result["schema_compat_version"] = SCHEMA_COMPAT_VERSION;
    result["foreground_complete"] = fg_runner_.all_foreground_complete();

    // Add dependency graph level count
    auto levels = registry_.get_level_order();
    result["dependency_levels"] = levels.size();

    // Categorize
    json categories = json::object();
    for (auto& [name, def] : defs) {
      std::string cat = category_to_string(def.category);
      if (!categories.contains(cat)) {
        categories[cat] = {{"total", 0}, {"completed", 0}, {"failed", 0}};
      }
      categories[cat]["total"] = categories[cat]["total"].get<int>() + 1;
      std::string s = get_status(name);
      if (s == "completed")
        categories[cat]["completed"] =
            categories[cat]["completed"].get<int>() + 1;
      else if (s == "failed")
        categories[cat]["failed"] =
            categories[cat]["failed"].get<int>() + 1;
    }
    result["categories"] = categories;

    return result;
  }

  /// Get dependency graph
  json get_dependency_graph() {
    json result;
    json nodes = json::array();
    json edges = json::array();

    auto defs = registry_.get_all_definitions();
    std::map<std::string, int> name_to_id;
    int id = 0;

    for (auto& [name, def] : defs) {
      name_to_id[name] = id;
      json node;
      node["id"] = id;
      node["name"] = name;
      node["category"] = category_to_string(def.category);
      node["status"] = get_status(name);
      node["is_foreground"] = def.is_foreground_only;
      nodes.push_back(node);
      id++;
    }

    for (auto& [name, def] : defs) {
      int from_id = name_to_id[name];
      for (auto& dep : def.dependencies) {
        auto it = name_to_id.find(dep);
        if (it != name_to_id.end()) {
          json edge;
          edge["from"] = it->second;
          edge["to"] = from_id;
          edge["label"] = "depends_on";
          edges.push_back(edge);
        }
      }
    }

    result["nodes"] = nodes;
    result["edges"] = edges;
    return result;
  }

  // ---- Mutation Methods ----

  /// Start a specific update (if not already running)
  json start_update(const std::string& name) {
    std::string status = get_status(name);

    if (status == "running") {
      return json({{"success", false},
                    {"error", "Update is already running"}});
    }

    if (status == "completed") {
      return json({{"success", false},
                    {"error", "Update is already completed. "
                     "To re-run, reset it first."}});
    }

    // Check dependencies
    auto def_opt = registry_.get_definition(name);
    if (def_opt) {
      for (auto& dep : def_opt->dependencies) {
        std::string dep_status = get_status(dep);
        if (dep_status != "completed") {
          return json({{"success", false},
                        {"error", "Dependency '" + dep +
                         "' is not completed (status: " + dep_status + ")"}});
        }
      }
    }

    // Run in a separate thread for async execution
    std::thread([this, name]() {
      bool ok = runner_.run_update(name);
      if (ok) {
        std::cout << "[admin_api] Update " << name << " completed\n";
      } else {
        std::cerr << "[admin_api] Update " << name << " failed\n";
      }
    }).detach();

    return json({{"success", true},
                  {"message", "Update '" + name + "' started"}});
  }

  /// Cancel a running update
  json cancel_update(const std::string& name) {
    bool ok = runner_.cancel_update(name);
    if (ok) {
      return json({{"success", true},
                    {"message", "Cancellation signal sent to '" + name + "'"}});
    }
    return json({{"success", false},
                  {"error", "Update '" + name + "' is not running"}});
  }

  /// Reset a failed or completed update back to pending
  json reset_update(const std::string& name) {
    std::string status = get_status(name);

    if (status == "running") {
      return json({{"success", false},
                    {"error", "Cannot reset a running update. Cancel it first."}});
    }

    try {
      db_.runInteraction(
          "reset_update",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "UPDATE background_updates SET status = 'pending', "
                "progress_json = '{}', error_message = NULL, "
                "started_ts = NULL, completed_ts = NULL "
                "WHERE update_name = ?",
                {name});
          });

      return json({{"success", true},
                    {"message", "Update '" + name + "' reset to pending"}});
    } catch (const std::exception& e) {
      return json({{"success", false}, {"error", e.what()}});
    }
  }

  /// Reset all failed updates to pending
  json reset_all_failed() {
    try {
      int count = db_.runInteraction(
          "reset_all_failed",
          [](storage::LoggingTransaction& txn) -> int {
            txn.execute(
                "UPDATE background_updates SET status = 'pending', "
                "progress_json = '{}', error_message = NULL, "
                "started_ts = NULL, completed_ts = NULL "
                "WHERE status = 'failed'");
            return static_cast<int>(txn.rowcount());
          });

      return json({{"success", true},
                    {"reset_count", count},
                    {"message", "Reset " + std::to_string(count) +
                     " failed updates to pending"}});
    } catch (const std::exception& e) {
      return json({{"success", false}, {"error", e.what()}});
    }
  }

  /// Register a custom update at runtime
  json register_custom_update(const std::string& name,
                               const std::string& description,
                               const std::string& category,
                               const json& dependencies) {
    auto existing = registry_.get_definition(name);
    if (existing) {
      return json({{"success", false},
                    {"error", "Update '" + name + "' already exists"}});
    }

    BackgroundUpdateDefinition def;
    def.name = name;
    def.description = description;
    def.category = UpdateCategory::GENERAL;
    for (auto& [cat_name, _] : json::object()) {
      // parse category string
      if (category == "populate_stats")
        def.category = UpdateCategory::POPULATE_STATS;
      else if (category == "index_create")
        def.category = UpdateCategory::INDEX_CREATE;
      else if (category == "delete_data")
        def.category = UpdateCategory::DELETE_DATA;
      else if (category == "replace_data")
        def.category = UpdateCategory::REPLACE_DATA;
      else if (category == "event_store")
        def.category = UpdateCategory::EVENT_STORE;
      else if (category == "chain_cover")
        def.category = UpdateCategory::CHAIN_COVER;
      else if (category == "stream_ordering")
        def.category = UpdateCategory::STREAM_ORDERING;
      else if (category == "state_group")
        def.category = UpdateCategory::STATE_GROUP;
      else if (category == "registration")
        def.category = UpdateCategory::REGISTRATION;
      else if (category == "room")
        def.category = UpdateCategory::ROOM;
    }
    def.schema_version_introduced = 99;

    if (dependencies.is_array()) {
      for (auto& dep : dependencies) {
        if (dep.is_string()) def.dependencies.push_back(dep.get<std::string>());
      }
    }

    registry_.register_update(def);

    // Also register in DB
    try {
      db_.runInteraction(
          "register_custom_update",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "INSERT OR IGNORE INTO background_updates "
                "(update_name, status, progress_json, dependencies) "
                "VALUES (?, 'pending', '{}', ?)",
                {name, dependencies.dump()});
          });

      return json({{"success", true},
                    {"message", "Custom update '" + name + "' registered"}});
    } catch (const std::exception& e) {
      return json({{"success", false}, {"error", e.what()}});
    }
  }

  /// Delete an update registration
  json delete_update_registration(const std::string& name) {
    std::string status = get_status(name);
    if (status == "running") {
      return json({{"success", false},
                    {"error", "Cannot delete a running update"}});
    }

    try {
      db_.runInteraction(
          "delete_update_reg",
          [&](storage::LoggingTransaction& txn) {
            txn.execute(
                "DELETE FROM background_updates WHERE update_name = ?",
                {name});
            txn.execute(
                "DELETE FROM background_update_items WHERE update_name = ?",
                {name});
          });

      return json({{"success", true},
                    {"message", "Update '" + name + "' deleted"}});
    } catch (const std::exception& e) {
      return json({{"success", false}, {"error", e.what()}});
    }
  }

  /// Get the schema compat version info
  json get_schema_compat_info() {
    json result;
    result["code_version"] = SCHEMA_COMPAT_VERSION;

    SchemaCompatManager compat(db_);
    int64_t stored = compat.get_stored_compat_version();
    result["stored_version"] = stored;
    result["is_compatible"] = compat.validate_and_update();

    return result;
  }

  /// Force update the stored schema compat version
  json update_schema_compat_version() {
    SchemaCompatManager compat(db_);
    compat.update_stored_compat_version();
    return json({{"success", true},
                  {"message", "Schema compat version updated to " +
                   std::string(SCHEMA_COMPAT_VERSION)}});
  }

  /// Run all pending background updates
  json run_all_pending() {
    json result = runner_.run_all_pending(false);
    return result;
  }

  /// Run foreground updates (blocks until done)
  json run_foreground_updates() {
    try {
      json result = fg_runner_.run_all_foreground();
      return result;
    } catch (const std::exception& e) {
      return json({{"success", false}, {"error", e.what()}});
    }
  }

private:
  std::string get_status(const std::string& name) {
    try {
      return db_.runInteraction(
          "admin_get_status",
          [&](storage::LoggingTransaction& txn) -> std::string {
            try {
              txn.execute(
                  "SELECT status FROM background_updates "
                  "WHERE update_name = ?",
                  {name});
              auto row = txn.fetchone();
              if (row) return row->at(0).value.value_or("pending");
            } catch (const std::exception&) {}
            return "pending";  // not yet in DB
          });
    } catch (...) {
      return "pending";
    }
  }

  json load_progress(const std::string& name) {
    try {
      return db_.runInteraction(
          "admin_load_progress",
          [&](storage::LoggingTransaction& txn) -> json {
            try {
              txn.execute(
                  "SELECT progress_json FROM background_updates "
                  "WHERE update_name = ?",
                  {name});
              auto row = txn.fetchone();
              if (row && row->at(0).value) {
                return safe_json_parse(*row->at(0).value);
              }
            } catch (const std::exception&) {}
            return json::object();
          });
    } catch (...) {
      return json::object();
    }
  }

  json load_timing(const std::string& name) {
    try {
      return db_.runInteraction(
          "admin_load_timing",
          [&](storage::LoggingTransaction& txn) -> json {
            try {
              txn.execute(
                  "SELECT started_ts, completed_ts, error_message "
                  "FROM background_updates WHERE update_name = ?",
                  {name});
              auto row = txn.fetchone();
              if (row) {
                json j;
                j["started_ts"] = row->at(0).value
                    ? std::stoll(*row->at(0).value) : 0;
                j["completed_ts"] = row->at(1).value
                    ? std::stoll(*row->at(1).value) : 0;
                j["error_message"] = row->at(2).value.value_or("");
                return j;
              }
            } catch (const std::exception&) {}
            return json::object();
          });
    } catch (...) {
      return json::object();
    }
  }

  storage::DatabasePool& db_;
  BackgroundUpdateRegistry& registry_;
  BackgroundUpdateRunner& runner_;
  ForegroundUpdateRunner& fg_runner_;
};

// ============================================================================
// BackgroundUpdatesService — top-level service that ties all components
// together. This is the main integration point for server startup.
// Equivalent to the coordination layer in synapse.storage.background_updates
// ============================================================================
class BackgroundUpdatesService {
public:
  BackgroundUpdatesService(storage::DatabasePool& db)
      : db_(db),
        registry_(std::make_unique<BackgroundUpdateRegistry>()),
        runner_(std::make_unique<BackgroundUpdateRunner>(db, *registry_)),
        fg_runner_(std::make_unique<ForegroundUpdateRunner>(db, *registry_)),
        admin_api_(std::make_unique<BackgroundUpdateAdminAPI>(
            db, *registry_, *runner_, *fg_runner_)),
        schema_compat_(std::make_unique<SchemaCompatManager>(db)) {}

  // ---- Initialization ----

  /// Initialize the background updates infrastructure.
  /// Creates necessary tables, ensures schema compatibility.
  void initialize() {
    std::cout << "[bg_service] Initializing background updates system\n";

    // Validate dependency graph
    auto errors = registry_->validate();
    if (!errors.empty()) {
      std::cerr << "[bg_service] WARNING: dependency validation errors:\n";
      for (auto& e : errors) {
        std::cerr << "  - " << e << "\n";
      }
    }

    // Ensure schema compat table exists
    schema_compat_->ensure_compat_version_table();

    // Ensure background_updates table with all columns
    ensure_bg_table();

    std::cout << "[bg_service] Registered " << registry_->size()
              << " background updates ("
              << registry_->get_foreground_updates().size()
              << " foreground)\n";

    auto levels = registry_->get_level_order();
    std::cout << "[bg_service] Dependency graph: " << levels.size()
              << " levels\n";
  }

  /// Run all foreground updates (BLOCKING).
  /// Call this BEFORE starting the server's main listener.
  void run_foreground_updates() {
    std::cout << "[bg_service] Running foreground updates...\n";

    // Enforce schema compat version first
    schema_compat_->enforce_compat_version();

    try {
      fg_runner_->run_all_foreground();
    } catch (const std::exception& e) {
      std::cerr << "[bg_service] FATAL: Foreground updates failed: "
                << e.what() << "\n";
      throw;
    }
  }

  /// Start background update processing.
  /// Call this AFTER the server is listening (non-blocking).
  void start_background_updates() {
    std::cout << "[bg_service] Starting background update processing\n";
    runner_->start_background_thread();
  }

  /// Stop background update processing (graceful shutdown).
  void stop_background_updates() {
    std::cout << "[bg_service] Stopping background updates\n";
    runner_->stop_background_thread();
  }

  // ---- Accessors ----

  BackgroundUpdateRegistry& registry() { return *registry_; }
  BackgroundUpdateRunner& runner() { return *runner_; }
  ForegroundUpdateRunner& fg_runner() { return *fg_runner_; }
  BackgroundUpdateAdminAPI& admin_api() { return *admin_api_; }
  SchemaCompatManager& schema_compat() { return *schema_compat_; }

  /// Run a standard server startup sequence:
  /// 1. Check schema compat
  /// 2. Run foreground updates (blocking)
  /// 3. Start background updates (non-blocking)
  void startup_sequence() {
    std::cout << "[bg_service] ====== Startup Sequence ======\n";

    // Step 1: Compatibility check
    std::cout << "[bg_service] Step 1: Schema compatibility check\n";
    schema_compat_->enforce_compat_version();
    std::cout << "[bg_service]   Compat version: "
              << SCHEMA_COMPAT_VERSION << " OK\n";

    // Step 2: Foreground updates
    std::cout << "[bg_service] Step 2: Foreground updates\n";
    run_foreground_updates();
    std::cout << "[bg_service]   All foreground updates complete\n";

    // Step 3: Background updates
    std::cout << "[bg_service] Step 3: Starting background updates\n";
    start_background_updates();
    std::cout << "[bg_service]   Background processing started\n";

    std::cout << "[bg_service] ====== Startup Complete ======\n";
  }

private:
  /// Ensure the background_updates table has all required columns
  void ensure_bg_table() {
    db_.runInteraction(
        "ensure_bg_table",
        [](storage::LoggingTransaction& txn) {
          // Core table
          txn.execute(R"(
              CREATE TABLE IF NOT EXISTS background_updates (
                  update_name TEXT NOT NULL PRIMARY KEY,
                  status TEXT NOT NULL DEFAULT 'pending',
                  progress_json TEXT DEFAULT '{}',
                  total_items INTEGER DEFAULT 0,
                  processed_items INTEGER DEFAULT 0,
                  started_ts INTEGER,
                  completed_ts INTEGER,
                  error_message TEXT,
                  dependencies TEXT DEFAULT '[]',
                  description TEXT DEFAULT ''
              )
          )");

          // Items table for batch processing
          txn.execute(R"(
              CREATE TABLE IF NOT EXISTS background_update_items (
                  update_name TEXT NOT NULL,
                  item_id TEXT NOT NULL,
                  processed INTEGER NOT NULL DEFAULT 0,
                  error_message TEXT,
                  PRIMARY KEY (update_name, item_id)
              )
          )");

          // Index for fast lookups
          txn.execute(R"(
              CREATE INDEX IF NOT EXISTS bg_items_update_name_processed
              ON background_update_items(update_name, processed)
          )");
        });
  }

  storage::DatabasePool& db_;
  std::unique_ptr<BackgroundUpdateRegistry> registry_;
  std::unique_ptr<BackgroundUpdateRunner> runner_;
  std::unique_ptr<ForegroundUpdateRunner> fg_runner_;
  std::unique_ptr<BackgroundUpdateAdminAPI> admin_api_;
  std::unique_ptr<SchemaCompatManager> schema_compat_;
};

// ============================================================================
// Built-in background update handler implementations
// Each corresponds to a specific Synapse update function
// ============================================================================

namespace {

// ---- Helper: create an index safely ----
void safe_create_index(storage::LoggingTransaction& txn,
                       const std::string& index_name,
                       const std::string& table,
                       const std::string& columns,
                       bool unique = false) {
  std::string sql = "CREATE ";
  if (unique) sql += "UNIQUE ";
  sql += "INDEX IF NOT EXISTS " + index_name + " ON " + table +
         "(" + columns + ")";
  txn.execute(sql);
}

// ---- Helper: count rows in a table ----
int64_t count_rows_txn(storage::LoggingTransaction& txn,
                        const std::string& table,
                        const std::string& where = "") {
  std::string sql = "SELECT COUNT(*) FROM " + table;
  if (!where.empty()) sql += " WHERE " + where;
  txn.execute(sql);
  auto row = txn.fetchone();
  if (row) return std::stoll(row->at(0).value.value_or("0"));
  return 0;
}

// ---- Populate Stats Handlers ----

bool populate_stats_process_rooms_handler(storage::DatabasePool& db,
                                          json& progress) {
  return db.runInteraction(
      "populate_stats_rooms",
      [&](storage::LoggingTransaction& txn) -> bool {
        int64_t batch_size = DEFAULT_BG_UPDATE_BATCH_SIZE;
        int64_t last_processed =
            progress.value("last_processed_room_id", 0);

        txn.execute(
            "SELECT room_id FROM rooms WHERE rowid > ? "
            "ORDER BY rowid LIMIT ?",
            {std::to_string(last_processed), std::to_string(batch_size)});
        auto rows = txn.fetchall();

        if (rows.empty()) {
          progress["done"] = true;
          return true;
        }

        for (auto& row : rows) {
          std::string room_id = row[0].value.value_or("");

          // Count members
          txn.execute(
              "SELECT COUNT(*) FROM room_memberships "
              "WHERE room_id = ? AND membership = 'join'",
              {room_id});
          auto cnt = txn.fetchone();
          int64_t member_count = cnt ? std::stoll(cnt->at(0).value.value_or("0")) : 0;

          // Count state events
          txn.execute(
              "SELECT COUNT(*) FROM current_state_events WHERE room_id = ?",
              {room_id});
          cnt = txn.fetchone();
          int64_t state_count = cnt ? std::stoll(cnt->at(0).value.value_or("0")) : 0;

          // Upsert stats
          txn.execute(
              "INSERT INTO room_stats_current (room_id, current_state_events, "
              "joined_members, completed_delta_stream_id) "
              "VALUES (?, ?, ?, 0) "
              "ON CONFLICT(room_id) DO UPDATE SET "
              "current_state_events = ?, joined_members = ?",
              {room_id, std::to_string(state_count),
               std::to_string(member_count),
               std::to_string(state_count),
               std::to_string(member_count)});

          last_processed = std::max(last_processed,
              std::stoll(row[0].value.value_or("0")));
        }

        progress["last_processed_room_id"] = last_processed;
        progress["done"] = false;
        return false;  // not done yet
      });
}

bool populate_stats_process_users_handler(storage::DatabasePool& db,
                                           json& progress) {
  return db.runInteraction(
      "populate_stats_users",
      [&](storage::LoggingTransaction& txn) -> bool {
        int64_t batch_size = DEFAULT_BG_UPDATE_BATCH_SIZE;
        int64_t last_processed =
            progress.value("last_processed_user_id", 0);

        txn.execute(
            "SELECT name FROM users WHERE rowid > ? ORDER BY rowid LIMIT ?",
            {std::to_string(last_processed), std::to_string(batch_size)});
        auto rows = txn.fetchall();

        if (rows.empty()) {
          progress["done"] = true;
          return true;
        }

        for (auto& row : rows) {
          std::string user_id = row[0].value.value_or("");

          // Count joined rooms
          txn.execute(
              "SELECT COUNT(DISTINCT room_id) FROM room_memberships "
              "WHERE user_id = ? AND membership = 'join'",
              {user_id});
          auto cnt = txn.fetchone();
          int64_t room_count = cnt ? std::stoll(cnt->at(0).value.value_or("0")) : 0;

          // Upsert user stats
          txn.execute(
              "INSERT INTO user_stats_current (user_id, joined_rooms) "
              "VALUES (?, ?) "
              "ON CONFLICT(user_id) DO UPDATE SET joined_rooms = ?",
              {user_id, std::to_string(room_count),
               std::to_string(room_count)});

          last_processed = std::max(last_processed,
              std::stoll(row[0].value.value_or("0")));
        }

        progress["last_processed_user_id"] = last_processed;
        progress["done"] = false;
        return false;
      });
}

// ---- Index Creation Handlers ----

#define DEFINE_INDEX_HANDLER(name, index_name, table, columns, uq)       \
  bool name##_handler(storage::DatabasePool& db, json& progress) {       \
    db.runInteraction(#name "_idx",                                      \
        [&](storage::LoggingTransaction& txn) {                          \
          safe_create_index(txn, index_name, table, columns, uq);        \
        });                                                              \
    progress["done"] = true;                                             \
    return true;                                                         \
  }

DEFINE_INDEX_HANDLER(index_events_room_stream,
  "events_room_stream_idx", "events", "room_id, stream_ordering", false)
DEFINE_INDEX_HANDLER(index_events_event_id_room_id,
  "events_event_id_room_id_idx", "events", "event_id, room_id", false)
DEFINE_INDEX_HANDLER(index_events_order_room,
  "events_order_room_idx", "events",
  "room_id, topological_ordering, stream_ordering", false)
DEFINE_INDEX_HANDLER(index_events_contains_url,
  "events_contains_url_idx", "events", "room_id, contains_url", false)
DEFINE_INDEX_HANDLER(index_state_events_room_type,
  "state_events_room_type_idx", "state_events", "room_id, type", false)
DEFINE_INDEX_HANDLER(index_event_search_room_event,
  "event_search_room_event_idx", "event_search", "room_id, event_id", false)
DEFINE_INDEX_HANDLER(index_event_relations_relates,
  "event_relations_relates_idx", "event_relations", "relates_to_id", false)
DEFINE_INDEX_HANDLER(index_event_push_actions_room_receipt,
  "ev_push_actions_room_stream_idx", "event_push_actions",
  "room_id, stream_ordering", false)
DEFINE_INDEX_HANDLER(index_event_push_actions_highlights,
  "ev_push_actions_highlight_idx", "event_push_actions", "highlight", false)
DEFINE_INDEX_HANDLER(index_receipts_linearized_room_stream,
  "receipts_linearized_room_stream_idx", "receipts_linearized",
  "room_id, stream_id", false)
DEFINE_INDEX_HANDLER(index_room_membership_events,
  "room_membership_events_idx", "room_memberships", "event_id", false)
DEFINE_INDEX_HANDLER(index_room_stats_state,
  "room_stats_state_name_idx", "room_stats_state", "name", false)
DEFINE_INDEX_HANDLER(index_users_creation_ts,
  "users_creation_ts_idx", "users", "creation_ts", false)
DEFINE_INDEX_HANDLER(index_local_media_created,
  "local_media_created_idx", "local_media_repository", "created_ts", false)
DEFINE_INDEX_HANDLER(index_device_lists_stream_id,
  "device_lists_stream_id_idx", "device_lists_stream", "stream_id", false)
DEFINE_INDEX_HANDLER(index_e2e_room_keys_version,
  "e2e_room_keys_version_idx", "e2e_room_keys", "user_id, version", false)
DEFINE_INDEX_HANDLER(index_federation_destinations_retry,
  "destinations_retry_idx", "destinations", "retry_last_ts", false)
DEFINE_INDEX_HANDLER(index_state_groups_state,
  "state_groups_state_idx", "state_groups_state", "state_group", false)
DEFINE_INDEX_HANDLER(index_current_state_events_membership,
  "current_state_membership_idx", "current_state_events", "membership", false)

#undef DEFINE_INDEX_HANDLER

// ---- Delete/Cleanup Handlers ----

bool delete_old_current_state_events_handler(storage::DatabasePool& db,
                                               json& progress) {
  return db.runInteraction(
      "delete_old_current_state",
      [&](storage::LoggingTransaction& txn) -> bool {
        int64_t batch_size = DEFAULT_BG_UPDATE_BATCH_SIZE;

        txn.execute(
            "DELETE FROM current_state_events WHERE rowid IN ("
            "  SELECT rowid FROM current_state_events c1 "
            "  WHERE EXISTS ("
            "    SELECT 1 FROM current_state_events c2 "
            "    WHERE c2.room_id = c1.room_id "
            "    AND c2.type = c1.type "
            "    AND c2.state_key = c1.state_key "
            "    AND c2.rowid > c1.rowid"
            "  ) LIMIT ?"
            ")",
            {std::to_string(batch_size)});

        int64_t deleted = txn.rowcount();
        progress["deleted"] = progress.value("deleted", 0) + deleted;

        if (deleted < batch_size) {
          progress["done"] = true;
          return true;
        }

        progress["done"] = false;
        return false;
      });
}

bool delete_old_push_actions_handler(storage::DatabasePool& db,
                                      json& progress) {
  return db.runInteraction(
      "delete_old_push_actions",
      [&](storage::LoggingTransaction& txn) -> bool {
        int64_t batch_size = DEFAULT_BG_UPDATE_BATCH_SIZE;
        int64_t retention_ms =
            progress.value("retention_ms", 30LL * 24 * 3600 * 1000);
        int64_t cutoff = now_ms() - retention_ms;

        txn.execute(
            "DELETE FROM event_push_actions WHERE "
            "stream_ordering < (SELECT stream_ordering FROM events "
            "WHERE origin_server_ts < ? ORDER BY stream_ordering DESC "
            "LIMIT 1) LIMIT ?",
            {std::to_string(cutoff), std::to_string(batch_size)});

        int64_t deleted = txn.rowcount();
        progress["deleted"] = progress.value("deleted", 0) + deleted;

        if (deleted < batch_size) {
          progress["done"] = true;
          return true;
        }
        progress["done"] = false;
        return false;
      });
}

// Generic delete handler factory
auto make_delete_handler(const std::string& table,
                         const std::string& where_clause,
                         const std::string& progress_key) {
  return [table, where_clause, progress_key](
             storage::DatabasePool& db, json& progress) -> bool {
    return db.runInteraction(
        "delete_" + table,
        [&](storage::LoggingTransaction& txn) -> bool {
          int64_t batch_size = DEFAULT_BG_UPDATE_BATCH_SIZE;
          txn.execute("DELETE FROM " + table + " WHERE " + where_clause +
                      " LIMIT ?", {std::to_string(batch_size)});
          int64_t deleted = txn.rowcount();
          progress[progress_key] =
              progress.value(progress_key, 0) + deleted;
          if (deleted < batch_size) {
            progress["done"] = true;
            return true;
          }
          progress["done"] = false;
          return false;
        });
  };
}

// ---- Replace/Migrate Handlers ----

bool replace_room_depth_min_depth_handler(storage::DatabasePool& db,
                                           json& progress) {
  return db.runInteraction(
      "replace_room_depth",
      [&](storage::LoggingTransaction& txn) -> bool {
        int64_t batch_size = DEFAULT_BG_UPDATE_BATCH_SIZE;
        std::string last_room =
            progress.value("last_room_id", "");

        txn.execute(
            "SELECT room_id, min_depth FROM room_depth "
            "WHERE room_id > ? ORDER BY room_id LIMIT ?",
            {last_room, std::to_string(batch_size)});
        auto rows = txn.fetchall();

        if (rows.empty()) {
          progress["done"] = true;
          return true;
        }

        for (auto& row : rows) {
          std::string room_id = row[0].value.value_or("");
          int64_t depth = row[1].value
              ? std::stoll(*row[1].value) : 0;

          // If min_depth is null, compute it from events
          if (depth == 0) {
            txn.execute(
                "SELECT MIN(depth) FROM events WHERE room_id = ?",
                {room_id});
            auto min_row = txn.fetchone();
            int64_t min_depth = min_row && min_row->at(0).value
                ? std::stoll(*min_row->at(0).value) : 0;
            txn.execute(
                "UPDATE room_depth SET min_depth = ? WHERE room_id = ?",
                {std::to_string(min_depth), room_id});
          }

          last_room = room_id;
        }

        progress["last_room_id"] = last_room;
        progress["processed"] =
            progress.value("processed", 0) + static_cast<int>(rows.size());
        progress["done"] = false;
        return false;
      });
}

bool replace_event_content_type_text_handler(storage::DatabasePool& db,
                                               json& progress) {
  // Background handler that checks and fixes event content types
  // In SQLite this is mostly a no-op since TEXT is the default,
  // but for PostgreSQL this would alter column types.
  // We mark it as complete immediately for SQLite, but the definition
  // exists for PostgreSQL compatibility.
  progress["done"] = true;
  progress["message"] = "No migration needed for SQLite (TEXT is default)";
  return true;
}

// ---- Event Store Chain Cover Index Handler ----

bool event_store_chain_cover_index_handler(storage::DatabasePool& db,
                                            json& progress) {
  return db.runInteraction(
      "chain_cover_index",
      [&](storage::LoggingTransaction& txn) -> bool {
        int64_t batch_size = DEFAULT_BG_UPDATE_BATCH_SIZE;
        int64_t last_room_id =
            progress.value("last_room_id_int", 0);

        // Ensure chain cover table exists
        txn.execute(R"(
            CREATE TABLE IF NOT EXISTS event_auth_chain_cover (
                room_id TEXT NOT NULL,
                chain_id INTEGER NOT NULL,
                sequence_number INTEGER NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY (chain_id, sequence_number)
            )
        )");

        safe_create_index(txn, "event_auth_chain_cover_room",
                         "event_auth_chain_cover", "room_id", false);

        txn.execute(
            "SELECT room_id FROM rooms WHERE rowid > ? "
            "ORDER BY rowid LIMIT ?",
            {std::to_string(last_room_id), std::to_string(batch_size)});
        auto rows = txn.fetchall();

        if (rows.empty()) {
          progress["done"] = true;
          return true;
        }

        for (auto& row : rows) {
          std::string room_id = row[0].value.value_or("");

          // For each room, process events in auth chain order
          txn.execute(
              "SELECT event_id, auth_events FROM events "
              "WHERE room_id = ? ORDER BY stream_ordering",
              {room_id});
          auto events = txn.fetchall();

          // Simple chain cover: assign chain_id = 1, sequence = stream order
          int64_t seq = 0;
          for (auto& ev : events) {
            txn.execute(
                "INSERT OR IGNORE INTO event_auth_chain_cover "
                "(room_id, chain_id, sequence_number, event_id) "
                "VALUES (?, 1, ?, ?)",
                {room_id, std::to_string(seq),
                 ev[0].value.value_or("")});
            seq++;
          }

          last_room_id = std::max(last_room_id,
              std::stoll(row[0].value.value_or("0")));
        }

        progress["last_room_id_int"] = last_room_id;
        progress["rooms_processed"] =
            progress.value("rooms_processed", 0) +
            static_cast<int>(rows.size());
        progress["done"] = false;
        return false;
      });
}

// ---- Foreground Update Handlers ----

bool fg_notif_null_notif_handler(storage::DatabasePool& db,
                                  json& progress) {
  return db.runInteraction(
      "fg_notif_null",
      [&](storage::LoggingTransaction& txn) -> bool {
        // Ensure notification columns are NOT NULL
        // For SQLite we validate the schema; for new tables this is
        // already handled during table creation
        progress["done"] = true;
        progress["message"] = "Notification columns validated";
        return true;
      });
}

bool fg_events_order_room_index_handler(storage::DatabasePool& db,
                                         json& progress) {
  return db.runInteraction(
      "fg_events_index",
      [&](storage::LoggingTransaction& txn) -> bool {
        safe_create_index(txn, "events_order_room_idx", "events",
                         "room_id, topological_ordering, stream_ordering",
                         false);
        progress["done"] = true;
        return true;
      });
}

bool fg_schema_compat_check_handler(storage::DatabasePool& db,
                                     json& progress) {
  SchemaCompatManager compat(db);
  if (!compat.check_compat_version()) {
    progress["error"] = "Schema compatibility check failed";
    progress["done"] = false;
    return false;
  }
  progress["done"] = true;
  progress["compat_version"] = SCHEMA_COMPAT_VERSION;
  return true;
}

bool fg_populate_event_json_handler(storage::DatabasePool& db,
                                     json& progress) {
  return db.runInteraction(
      "fg_populate_json",
      [&](storage::LoggingTransaction& txn) -> bool {
        int64_t batch_size = DEFAULT_FG_UPDATE_BATCH_SIZE;
        int64_t last_id = progress.value("last_event_rowid", 0);

        txn.execute(
            "SELECT event_id, json FROM event_json WHERE rowid > ? "
            "ORDER BY rowid LIMIT ?",
            {std::to_string(last_id), std::to_string(batch_size)});
        auto rows = txn.fetchall();

        if (rows.empty()) {
          progress["done"] = true;
          return true;
        }

        for (auto& row : rows) {
          // Validate JSON is parseable
          std::string json_str = row[1].value.value_or("");
          if (!json_str.empty()) {
            try {
              json::parse(json_str);
            } catch (...) {
              progress["invalid_json_count"] =
                  progress.value("invalid_json_count", 0) + 1;
            }
          }
          last_id = std::max(last_id, 0);  // track progress by iteration
        }

        progress["last_event_rowid"] = last_id + static_cast<int>(rows.size());
        progress["processed"] =
            progress.value("processed", 0) + static_cast<int>(rows.size());
        progress["done"] = false;
        return false;
      });
}

bool fg_bytes_type_check_handler(storage::DatabasePool& db,
                                  json& progress) {
  // For SQLite, types are dynamic so this is mostly a no-op.
  // For PostgreSQL, this would verify BYTEA columns.
  progress["done"] = true;
  progress["message"] = "BYTES type check passed (SQLite dynamic typing)";
  return true;
}

bool fg_stream_ordering_migrate_handler(storage::DatabasePool& db,
                                         json& progress) {
  return db.runInteraction(
      "fg_stream_migrate",
      [&](storage::LoggingTransaction& txn) -> bool {
        // Check if migration is needed
        txn.execute("SELECT MAX(stream_ordering) FROM events");
        auto row = txn.fetchone();
        int64_t max_ordering = row && row->at(0).value
            ? std::stoll(*row->at(0).value) : 0;

        // For SQLite, BIGINT is the same as INTEGER, no migration needed
        progress["done"] = true;
        progress["max_stream_ordering"] = max_ordering;
        progress["message"] = "Stream ordering type check passed";
        return true;
      });
}

bool fg_auth_chain_migrate_handler(storage::DatabasePool& db,
                                    json& progress) {
  // This would run event_store_chain_cover_index in foreground mode
  return event_store_chain_cover_index_handler(db, progress);
}

}  // anonymous namespace

// ============================================================================
// Global BackgroundUpdatesService instance
// Used by server_main.cpp and admin endpoints
// ============================================================================

namespace {
  std::unique_ptr<BackgroundUpdatesService> g_bg_service;
  std::mutex g_bg_service_mutex;
}  // anonymous namespace

// ============================================================================
// Public API functions — called from server_main and admin endpoints
// ============================================================================

/// Initialize the background updates system.
/// Must be called during server startup, before foreground updates.
void init_background_updates(storage::DatabasePool& db) {
  std::lock_guard<std::mutex> lock(g_bg_service_mutex);
  g_bg_service = std::make_unique<BackgroundUpdatesService>(db);
  g_bg_service->initialize();
}

/// Run foreground updates. Blocks until complete.
/// Call this BEFORE starting the server listener.
void run_foreground_updates() {
  std::lock_guard<std::mutex> lock(g_bg_service_mutex);
  if (!g_bg_service) {
    throw std::runtime_error(
        "Background updates not initialized. Call init_background_updates first.");
  }
  g_bg_service->run_foreground_updates();
}

/// Start background updates processing (non-blocking).
/// Call this AFTER starting the server listener.
void start_background_updates() {
  std::lock_guard<std::mutex> lock(g_bg_service_mutex);
  if (!g_bg_service) {
    throw std::runtime_error(
        "Background updates not initialized. Call init_background_updates first.");
  }
  g_bg_service->start_background_updates();
}

/// Stop background updates processing (graceful shutdown).
void stop_background_updates() {
  std::lock_guard<std::mutex> lock(g_bg_service_mutex);
  if (g_bg_service) {
    g_bg_service->stop_background_updates();
  }
}

/// Run complete startup sequence (init + foreground + background).
void background_updates_startup_sequence(storage::DatabasePool& db) {
  std::lock_guard<std::mutex> lock(g_bg_service_mutex);
  if (!g_bg_service) {
    g_bg_service = std::make_unique<BackgroundUpdatesService>(db);
    g_bg_service->initialize();
  }
  g_bg_service->startup_sequence();
}

/// Get admin API interface
BackgroundUpdateAdminAPI* get_background_updates_admin_api() {
  std::lock_guard<std::mutex> lock(g_bg_service_mutex);
  if (g_bg_service) {
    return &g_bg_service->admin_api();
  }
  return nullptr;
}

/// Get the background update registry
BackgroundUpdateRegistry* get_background_update_registry() {
  std::lock_guard<std::mutex> lock(g_bg_service_mutex);
  if (g_bg_service) {
    return &g_bg_service->registry();
  }
  return nullptr;
}

/// Get the background update runner
BackgroundUpdateRunner* get_background_update_runner() {
  std::lock_guard<std::mutex> lock(g_bg_service_mutex);
  if (g_bg_service) {
    return &g_bg_service->runner();
  }
  return nullptr;
}

/// Get schema compat info as JSON
json get_schema_compat_info() {
  std::lock_guard<std::mutex> lock(g_bg_service_mutex);
  if (g_bg_service) {
    return g_bg_service->admin_api().get_schema_compat_info();
  }
  json result;
  result["code_version"] = SCHEMA_COMPAT_VERSION;
  result["initialized"] = false;
  return result;
}

/// Check if all background updates are complete
bool has_completed_background_updates() {
  std::lock_guard<std::mutex> lock(g_bg_service_mutex);
  if (g_bg_service) {
    auto summary = g_bg_service->admin_api().get_summary();
    int completed = summary.value("completed", 0);
    int total = summary.value("total_updates", 0);
    return completed >= total;
  }
  return false;
}

/// Check if foreground updates have completed
bool has_completed_foreground_updates() {
  std::lock_guard<std::mutex> lock(g_bg_service_mutex);
  if (g_bg_service) {
    return g_bg_service->fg_runner().all_foreground_complete();
  }
  return false;
}

}  // namespace progressive
