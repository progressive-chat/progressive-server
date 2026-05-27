#pragma once
#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>

#include "engine.hpp"
#include "types.hpp"

namespace progressive::storage {

// Forward declarations
class DatabasePool;
class BackgroundUpdater;

// ============================================================================
// DatabaseConnection - Abstract interface for database connections
// Equivalent to synapse.storage.types.Connection
// ============================================================================
class DatabaseConnection {
public:
  virtual ~DatabaseConnection() = default;

  // Create a new transaction cursor from this connection
  virtual std::unique_ptr<DatabaseTransaction> cursor(
      const std::string& txn_name = "connection") = 0;

  virtual void close() = 0;
  virtual void commit() = 0;
  virtual void rollback() = 0;
  virtual bool is_connected() const = 0;
};

// ============================================================================
// DatabaseTransaction - Abstract interface for database cursors/transactions
// Equivalent to synapse.storage.types.Cursor
// ============================================================================
class DatabaseTransaction {
public:
  virtual ~DatabaseTransaction() = default;

  virtual void execute(const std::string& sql) = 0;
  virtual void execute(const std::string& sql,
                        const std::vector<SQLParam>& params) = 0;
  virtual void executemany(const std::string& sql,
                            const std::vector<std::vector<SQLParam>>& params_list) = 0;

  virtual std::optional<Row> fetchone() = 0;
  virtual RowList fetchmany(std::optional<int> size = std::nullopt) = 0;
  virtual RowList fetchall() = 0;

  virtual int64_t rowcount() const = 0;
  virtual void close() = 0;

  // Property: description of columns in the result set
  virtual std::vector<std::string> description() const = 0;

  // Iterator support via virtual methods
  virtual bool iter_next(Row& row) = 0;
  virtual void iter_reset() = 0;

  // SQL scripts (multiple statements separated by ;)
  virtual void executescript(const std::string& script) = 0;
};

// ============================================================================
// ConnectionPool - Manages a pool of database connections
// Equivalent to twisted.enterprise.adbapi.ConnectionPool
// ============================================================================
class ConnectionPool {
public:
  virtual ~ConnectionPool() = default;

  using ConnectionFunc = std::function<void(DatabaseConnection&)>;

  virtual void runWithConnection(ConnectionFunc func) = 0;
  virtual bool is_running() const = 0;
  virtual int threadID() const = 0;
};

// ============================================================================
// LoggingDatabaseConnection
// Wraps a database connection with logging and metrics
// Equivalent to synapse.storage.database.LoggingDatabaseConnection
// ============================================================================
class LoggingDatabaseConnection : public DatabaseConnection {
public:
  LoggingDatabaseConnection(std::unique_ptr<DatabaseConnection> conn,
                             std::shared_ptr<BaseDatabaseEngine> engine,
                             const std::string& default_txn_name,
                             const std::string& server_name);

  ~LoggingDatabaseConnection() override;

  std::unique_ptr<DatabaseTransaction> cursor(
      const std::string& txn_name = "") override;

  void close() override;
  void commit() override;
  void rollback() override;
  bool is_connected() const override;

  const std::string& default_txn_name() const { return default_txn_name_; }
  const std::string& server_name() const { return server_name_; }
  BaseDatabaseEngine& engine() { return *engine_; }

private:
  std::unique_ptr<DatabaseConnection> conn_;
  std::shared_ptr<BaseDatabaseEngine> engine_;
  std::string default_txn_name_;
  std::string server_name_;
};

// ============================================================================
// Callback list entry types
// Equivalent to _CallbackListEntry and _AsyncCallbackListEntry in Synapse
// ============================================================================
using CallbackListEntry =
    std::tuple<AfterCallback, std::vector<std::string>, std::map<std::string, std::string>>;
using AsyncCallbackListEntry =
    std::tuple<AsyncAfterCallback, std::vector<std::string>, std::map<std::string, std::string>>;

// ============================================================================
// LoggingTransaction
// Wraps a database transaction with logging, metrics, and callback support
// Equivalent to synapse.storage.database.LoggingTransaction (lines 270-543)
// ============================================================================
class LoggingTransaction : public DatabaseTransaction {
public:
  LoggingTransaction(std::unique_ptr<DatabaseTransaction> txn,
                      const std::string& name,
                      const std::string& server_name,
                      std::shared_ptr<BaseDatabaseEngine> engine,
                      std::vector<CallbackListEntry>* after_callbacks = nullptr,
                      std::vector<AsyncCallbackListEntry>* async_after_callbacks = nullptr,
                      std::vector<CallbackListEntry>* exception_callbacks = nullptr);

  ~LoggingTransaction() override;

  // Transaction execution
  void execute(const std::string& sql) override;
  void execute(const std::string& sql,
                const std::vector<SQLParam>& params) override;
  void executemany(const std::string& sql,
                    const std::vector<std::vector<SQLParam>>& params_list) override;

  // Batch execution - more efficient than executemany for PostgreSQL
  void execute_batch(const std::string& sql,
                      const std::vector<std::vector<SQLParam>>& args);
  // execute_values - PostgreSQL-only efficient bulk insert with RETURNING
  void execute_values(const std::string& sql,
                       const std::vector<std::vector<SQLParam>>& values,
                       const std::optional<std::string>& templ = std::nullopt,
                       bool fetch = true);

  // Fetching
  std::optional<Row> fetchone() override;
  RowList fetchmany(std::optional<int> size = std::nullopt) override;
  RowList fetchall() override;

  // Properties
  int64_t rowcount() const override;
  std::vector<std::string> description() const override;

  // Iterator support
  bool iter_next(Row& row) override;
  void iter_reset() override;
  void close() override;

  // SQL scripts
  void executescript(const std::string& script) override;

  // Callback scheduling (equivalent to call_after, async_call_after, call_on_exception)
  void call_after(AfterCallback callback);
  void async_call_after(AsyncAfterCallback callback);
  void call_on_exception(ExceptionCallback callback);

  const std::string& name() const { return name_; }
  const std::string& server_name() const { return server_name_; }
  BaseDatabaseEngine& database_engine() { return *engine_; }

private:
  static std::string make_sql_one_line(const std::string& sql);

  template <typename Func, typename... Args>
  auto do_execute(Func&& func, const std::string& sql, Args&&... args)
      -> decltype(func(sql, std::forward<Args>(args)...));

  std::unique_ptr<DatabaseTransaction> txn_;
  std::string name_;
  std::string server_name_;
  std::shared_ptr<BaseDatabaseEngine> engine_;

  std::vector<CallbackListEntry>* after_callbacks_;
  std::vector<AsyncCallbackListEntry>* async_after_callbacks_;
  std::vector<CallbackListEntry>* exception_callbacks_;
};

// ============================================================================
// PerformanceCounters
// Tracks database transaction performance for logging/debugging
// Equivalent to synapse.storage.database.PerformanceCounters (lines 546-578)
// ============================================================================
class PerformanceCounters {
public:
  PerformanceCounters() = default;

  void update(const std::string& key, double duration_secs);
  std::string interval(double interval_duration_secs, int limit = 3);

private:
  std::unordered_map<std::string, std::pair<int, double>> current_counters_;
  std::unordered_map<std::string, std::pair<int, double>> previous_counters_;
};

// ============================================================================
// DatabasePool
// Wraps a single physical database and connection pool.
// Equivalent to synapse.storage.database.DatabasePool (lines 581-2737)
// ============================================================================
class DatabasePool {
public:
  DatabasePool(const std::string& server_name,
                const std::string& database_name,
                const std::string& connection_string);

  ~DatabasePool();

  // Property accessors
  const std::string& name() const { return database_name_; }
  const std::string& server_name() const { return server_name_; }
  BaseDatabaseEngine& engine() { return *engine_; }
  bool is_running() const;

  // Background updates management
  BackgroundUpdater& updates() { return *updates_; }
  void stop_background_updates();

  // Transaction management
  // Simple runInteraction — executes func with a fresh transaction
  template <typename Func, typename... Args>
  auto runInteraction(const std::string& desc, Func&& func, Args&&... args)
      -> decltype(std::declval<std::decay_t<Func>>()(
          std::declval<LoggingTransaction&>(), std::declval<Args>()...)) {
    auto conn = create_connection(connection_string_);
    auto raw_txn = conn->cursor(desc);
    LoggingTransaction txn(std::move(raw_txn), desc, server_name_, engine_);
    return func(txn, std::forward<Args>(args)...);
  }

  // Simple runWithConnection
  template <typename Func, typename... Args>
  auto runWithConnection(Func&& func, Args&&... args)
      -> decltype(std::declval<std::decay_t<Func>>()(
          std::declval<LoggingDatabaseConnection&>(),
          std::declval<Args>()...)) {
    auto conn = get_connection();
    return func(*conn, std::forward<Args>(args)...);
  }

  // Helper to get a connection
  std::unique_ptr<LoggingDatabaseConnection> get_connection();

  // Simple SQL API (equivalent to methods starting at line 1138 in Synapse)
  // simple_insert
  void simple_insert(const std::string& table,
                      const std::map<std::string, std::string>& values,
                      const std::string& desc = "simple_insert");

  static void simple_insert_txn(LoggingTransaction& txn,
                                  const std::string& table,
                                  const std::map<std::string, std::string>& values);

  // simple_insert_returning
  Row simple_insert_returning_txn(
      LoggingTransaction& txn, const std::string& table,
      const std::map<std::string, std::string>& values,
      const std::vector<std::string>& returning);

  // simple_insert_many
  void simple_insert_many(
      const std::string& table,
      const std::vector<std::string>& keys,
      const std::vector<std::vector<std::string>>& values,
      const std::string& desc);

  static void simple_insert_many_txn(
      LoggingTransaction& txn, const std::string& table,
      const std::vector<std::string>& keys,
      const std::vector<std::vector<std::string>>& values);

  // simple_upsert
  bool simple_upsert(const std::string& table,
                      const std::map<std::string, std::string>& keyvalues,
                      const std::map<std::string, std::string>& values,
                      const std::map<std::string, std::string>& insertion_values = {},
                      const std::optional<std::string>& where_clause = std::nullopt,
                      const std::string& desc = "simple_upsert");

  bool simple_upsert_txn(LoggingTransaction& txn, const std::string& table,
                          const std::map<std::string, std::string>& keyvalues,
                          const std::map<std::string, std::string>& values,
                          const std::map<std::string, std::string>& insertion_values = {},
                          const std::optional<std::string>& where_clause = std::nullopt);

  bool simple_upsert_txn_emulated(
      LoggingTransaction& txn, const std::string& table,
      const std::map<std::string, std::string>& keyvalues,
      const std::map<std::string, std::string>& values,
      const std::map<std::string, std::string>& insertion_values = {},
      const std::optional<std::string>& where_clause = std::nullopt,
      bool lock = true);

  static bool simple_upsert_txn_native_upsert(
      LoggingTransaction& txn, const std::string& table,
      const std::map<std::string, std::string>& keyvalues,
      const std::map<std::string, std::string>& values,
      const std::map<std::string, std::string>& insertion_values = {},
      const std::optional<std::string>& where_clause = std::nullopt);

  // simple_select_one
  std::optional<Row> simple_select_one(
      const std::string& table,
      const std::map<std::string, std::string>& keyvalues,
      const std::vector<std::string>& retcols,
      bool allow_none = false,
      const std::string& desc = "simple_select_one");

  // simple_select_onecol
  std::vector<std::string> simple_select_onecol(
      const std::string& table,
      const std::map<std::string, std::string>& keyvalues,
      const std::string& retcol,
      const std::string& desc = "simple_select_onecol");

  // simple_select_list
  RowList simple_select_list(
      const std::string& table,
      const std::map<std::string, std::string>& keyvalues,
      const std::vector<std::string>& retcols,
      const std::string& desc = "simple_select_list");

  // simple_update_one
  void simple_update_one(const std::string& table,
                          const std::map<std::string, std::string>& keyvalues,
                          const std::map<std::string, std::string>& updatevalues,
                          const std::string& desc = "simple_update_one");

  // simple_update_many
  void simple_update_many(const std::string& table,
                           const std::map<std::string, std::string>& keynames,
                           const std::vector<std::map<std::string, std::string>>& keyvalues,
                           const std::vector<std::map<std::string, std::string>>& valuevalues,
                           const std::string& desc = "simple_update_many");

  // simple_delete_one
  void simple_delete_one(const std::string& table,
                          const std::map<std::string, std::string>& keyvalues,
                          const std::string& desc = "simple_delete_one");

  // simple_delete_many
  void simple_delete_many(const std::string& table,
                           const std::string& column,
                           const std::vector<std::string>& keys,
                           const std::string& desc = "simple_delete_many");

  // Execute a query directly
  RowList execute(const std::string& desc, const std::string& query,
                   const std::vector<SQLParam>& args = {});

  // Convenience overloads for simple SQL execution (backward compatibility)
  void execute(const std::string& query) {
    auto txn = conn_->cursor("exec");
    txn->execute(query);
  }
  nlohmann::json query(const std::string& query);
  void execute(const std::string& query, const std::vector<SQLParam>& args) {
    execute("raw", query, args);
  }

  // Static: create a raw database connection from connection string
  static std::unique_ptr<DatabaseConnection> create_connection(
      const std::string& connection_string);

  // Transaction running helpers
  static constexpr int MAX_NUMBER_OF_ATTEMPTS = 5;

  void start_profiling();
  std::unique_ptr<LoggingDatabaseConnection> make_new_connection();

private:
  // Check if safe to use native UPSERT on tables
  void check_safe_to_upsert();
  void schedule_upsert_safety_check();

  // Internal new_transaction - equivalent to DatabasePool.new_transaction
  template <typename Func, typename... Args>
  auto new_transaction(LoggingDatabaseConnection& conn, const std::string& desc,
                        std::vector<CallbackListEntry>& after_callbacks,
                        std::vector<AsyncCallbackListEntry>& async_after_callbacks,
                        std::vector<CallbackListEntry>& exception_callbacks,
                        Func&& func, Args&&... args)
      -> decltype(std::declval<std::decay_t<Func>>()(std::declval<LoggingTransaction&>(),
                                        std::declval<Args>()...));

  // Thread-local transaction counter
  void check_txn_limit();

  std::string server_name_;
  std::string database_name_;
  std::string connection_string_;
  std::shared_ptr<BaseDatabaseEngine> engine_;
  std::unique_ptr<DatabaseConnection> conn_;  // persistent connection
  std::unique_ptr<ConnectionPool> db_pool_;
  std::unique_ptr<BackgroundUpdater> updates_;

  // Transaction counting / limits
  std::atomic<int64_t> txn_id_{0};
  int txn_limit_{0};

  // Performance tracking
  PerformanceCounters txn_perf_counters_;
  double previous_txn_total_time_{0.0};
  double current_txn_total_time_{0.0};
  double previous_loop_ts_{0.0};

  // Tables unsafe to upsert
  std::set<std::string> unsafe_to_upsert_tables_;
  mutable std::mutex upsert_check_mutex_;
};

// ============================================================================
// BackgroundUpdater - Manages background database updates/migrations
// Equivalent to synapse.storage.background_updates.BackgroundUpdater
// ============================================================================
class BackgroundUpdater {
public:
  BackgroundUpdater(const std::string& server_name, DatabasePool& db_pool);
  ~BackgroundUpdater();

  void shutdown();
  bool has_completed_background_updates() const;
  void register_background_update_handler(
      const std::string& update_name,
      std::function<void(DatabasePool&)> handler);

  // Register a background update that will run on a schedule
  void register_background_controller(
      const std::string& update_name,
      std::function<void()> controller);

  // Start a background update
  void start_doing_background_updates();

  // Get the list of pending updates
  std::vector<std::string> get_pending_updates() const;

private:
  std::string server_name_;
  DatabasePool& db_pool_;
  bool running_{true};

  std::unordered_map<std::string, std::function<void(DatabasePool&)>> handlers_;
  std::unordered_map<std::string, std::function<void()>> controllers_;
};

// ============================================================================
// make_pool - Create a connection pool for the database
// Equivalent to synapse.storage.database.make_pool (lines 127-167)
// ============================================================================
std::unique_ptr<ConnectionPool> make_pool(
    const std::string& database_name,
    const std::string& connection_string,
    std::shared_ptr<BaseDatabaseEngine> engine,
    const std::string& server_name,
    std::function<void(DatabaseConnection&)> on_new_connection = nullptr);

// ============================================================================
// make_conn - Create a single database connection
// Equivalent to synapse.storage.database.make_conn (lines 170-197)
// ============================================================================
std::unique_ptr<LoggingDatabaseConnection> make_conn(
    const std::string& connection_string,
    std::shared_ptr<BaseDatabaseEngine> engine,
    const std::string& default_txn_name,
    const std::string& server_name);

}  // namespace progressive::storage
