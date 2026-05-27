#pragma once
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "types.hpp"

namespace progressive::storage {

// Unique indexes which have been added in background updates. Maps from table name
// to the name of the background update which added the unique index to that table.
//
// This is used by the upsert logic to figure out which tables are safe to do a proper
// UPSERT on: until the relevant background update has completed, we
// have to emulate an upsert by locking the table.
inline const std::vector<std::pair<std::string, std::string>>
    UNIQUE_INDEX_BACKGROUND_UPDATES = {
        {"user_ips", "user_ips_device_unique_index"},
        {"device_lists_remote_extremeties",
         "device_lists_remote_extremeties_unique_idx"},
        {"device_lists_remote_cache", "device_lists_remote_cache_unique_idx"},
        {"event_search", "event_search_event_id_idx"},
        {"local_media_repository_thumbnails",
         "local_media_repository_thumbnails_method_idx"},
        {"remote_media_cache_thumbnails",
         "remote_media_repository_thumbnails_method_idx"},
        {"event_push_summary", "event_push_summary_unique_index2"},
        {"receipts_linearized", "receipts_linearized_unique_index"},
        {"receipts_graph", "receipts_graph_unique_index"},
};

// Forward declaration
class LoggingDatabaseConnection;

// IncorrectDatabaseSetup exception
class IncorrectDatabaseSetup : public std::runtime_error {
public:
  explicit IncorrectDatabaseSetup(const std::string& msg)
      : std::runtime_error(msg) {}
};

// Base class for database engines (PostgreSQL, SQLite)
// Equivalent to synapse.storage.engines._base.BaseDatabaseEngine
class BaseDatabaseEngine {
public:
  virtual ~BaseDatabaseEngine() = default;

  // Whether the engine is single-threaded
  virtual bool single_threaded() const = 0;

  // Do we support using `a = ANY(?)` and passing a list
  virtual bool supports_using_any_list() const = 0;

  // Check that the database is correctly set up
  virtual void check_database(DatabaseConnection& db_conn,
                               bool allow_outdated_version = false) = 0;

  // Gets called when setting up a brand new database
  virtual void check_new_database(DatabaseTransaction& txn) = 0;

  // Convert param style from ? to the native engine format
  virtual std::string convert_param_style(const std::string& sql) const = 0;

  // Called when a new connection is established
  virtual void on_new_connection(LoggingDatabaseConnection& db_conn) = 0;

  // Check if an error is a deadlock
  virtual bool is_deadlock(const DBException& error) const = 0;

  // Check if a connection is closed
  virtual bool is_connection_closed(DatabaseConnection& conn) const = 0;

  // Lock a table for exclusive access
  virtual void lock_table(DatabaseTransaction& txn,
                           const std::string& table) = 0;

  // Get the server version string (e.g., "3.22.0")
  virtual std::string server_version() const = 0;

  // Get the literal name representing a row id for this engine
  virtual std::string row_id_name() const = 0;

  // Whether the connection is currently in a transaction
  virtual bool in_transaction(DatabaseConnection& conn) const = 0;

  // Attempt to set autocommit mode (PostgreSQL only, no-op on SQLite)
  virtual void attempt_to_set_autocommit(DatabaseConnection& conn,
                                          bool autocommit) = 0;

  // Attempt to set isolation level (PostgreSQL only, no-op on SQLite)
  virtual void attempt_to_set_isolation_level(
      DatabaseConnection& conn,
      std::optional<IsolationLevel> isolation_level) = 0;

  // Execute a chunk of SQL containing multiple semicolon-delimited statements
  virtual void executescript(DatabaseTransaction& txn,
                              const std::string& script) = 0;

  // Execute a file containing multiple SQL statements
  virtual void execute_script_file(DatabaseTransaction& txn,
                                    const std::string& filepath) = 0;
};

// PostgreSQL engine
// Equivalent to synapse.storage.engines.postgres.PostgresEngine
class PostgresEngine : public BaseDatabaseEngine {
public:
  PostgresEngine();
  ~PostgresEngine() override;

  bool single_threaded() const override;
  bool supports_using_any_list() const override;
  void check_database(DatabaseConnection& db_conn,
                       bool allow_outdated_version = false) override;
  void check_new_database(DatabaseTransaction& txn) override;
  std::string convert_param_style(const std::string& sql) const override;
  void on_new_connection(LoggingDatabaseConnection& db_conn) override;
  bool is_deadlock(const DBException& error) const override;
  bool is_connection_closed(DatabaseConnection& conn) const override;
  void lock_table(DatabaseTransaction& txn,
                   const std::string& table) override;
  std::string server_version() const override;
  std::string row_id_name() const override;
  bool in_transaction(DatabaseConnection& conn) const override;
  void attempt_to_set_autocommit(DatabaseConnection& conn,
                                  bool autocommit) override;
  void attempt_to_set_isolation_level(
      DatabaseConnection& conn,
      std::optional<IsolationLevel> isolation_level) override;
  void executescript(DatabaseTransaction& txn,
                      const std::string& script) override;
  void execute_script_file(DatabaseTransaction& txn,
                            const std::string& filepath) override;
};

// SQLite engine
// Equivalent to synapse.storage.engines.sqlite.Sqlite3Engine
class SqliteEngine : public BaseDatabaseEngine {
public:
  SqliteEngine();
  ~SqliteEngine() override;

  bool single_threaded() const override;
  bool supports_using_any_list() const override;
  void check_database(DatabaseConnection& db_conn,
                       bool allow_outdated_version = false) override;
  void check_new_database(DatabaseTransaction& txn) override;
  std::string convert_param_style(const std::string& sql) const override;
  void on_new_connection(LoggingDatabaseConnection& db_conn) override;
  bool is_deadlock(const DBException& error) const override;
  bool is_connection_closed(DatabaseConnection& conn) const override;
  void lock_table(DatabaseTransaction& txn,
                   const std::string& table) override;
  std::string server_version() const override;
  std::string row_id_name() const override;
  bool in_transaction(DatabaseConnection& conn) const override;
  void attempt_to_set_autocommit(DatabaseConnection& conn,
                                  bool autocommit) override;
  void attempt_to_set_isolation_level(
      DatabaseConnection& conn,
      std::optional<IsolationLevel> isolation_level) override;
  void executescript(DatabaseTransaction& txn,
                      const std::string& script) override;
  void execute_script_file(DatabaseTransaction& txn,
                            const std::string& filepath) override;
};

// Factory function to create the appropriate engine
// Equivalent to synapse.storage.engines.create_engine
std::unique_ptr<BaseDatabaseEngine> create_engine(const std::string& name);

}  // namespace progressive::storage
