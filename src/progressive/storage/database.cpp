#include "database.hpp"

#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>

#include <sqlite3.h>
#include <nlohmann/json.hpp>

namespace progressive::storage {

// ============================================================================
// Engines
// ============================================================================
SqliteEngine::SqliteEngine() = default;
SqliteEngine::~SqliteEngine() = default;
bool SqliteEngine::single_threaded() const { return true; }
bool SqliteEngine::supports_using_any_list() const { return false; }
void SqliteEngine::check_database(DatabaseConnection&, bool) {}
void SqliteEngine::check_new_database(DatabaseTransaction&) {}
std::string SqliteEngine::convert_param_style(const std::string& sql) const { return sql; }
void SqliteEngine::on_new_connection(LoggingDatabaseConnection&) {}
bool SqliteEngine::is_deadlock(const DBException&) const { return false; }
bool SqliteEngine::is_connection_closed(DatabaseConnection&) const { return false; }
void SqliteEngine::lock_table(DatabaseTransaction&, const std::string&) {}
std::string SqliteEngine::server_version() const { return "3.0.0"; }
std::string SqliteEngine::row_id_name() const { return "rowid"; }
bool SqliteEngine::in_transaction(DatabaseConnection&) const { return false; }
void SqliteEngine::attempt_to_set_autocommit(DatabaseConnection&, bool) {}
void SqliteEngine::attempt_to_set_isolation_level(DatabaseConnection&, std::optional<IsolationLevel>) {}
void SqliteEngine::executescript(DatabaseTransaction& txn, const std::string& s) { txn.executescript(s); }
void SqliteEngine::execute_script_file(DatabaseTransaction& txn, const std::string& path) {
  std::ifstream f(path);
  if (!f) throw DBException(DBErrorClass::OperationalError, "no file: " + path);
  std::stringstream ss; ss << f.rdbuf();
  executescript(txn, ss.str());
}

PostgresEngine::PostgresEngine() = default;
PostgresEngine::~PostgresEngine() = default;
bool PostgresEngine::single_threaded() const { return false; }
bool PostgresEngine::supports_using_any_list() const { return true; }
void PostgresEngine::check_database(DatabaseConnection&, bool) {}
void PostgresEngine::check_new_database(DatabaseTransaction&) {}
std::string PostgresEngine::convert_param_style(const std::string& sql) const {
  std::string r = sql; int n = 1;
  for (size_t p = 0; (p = r.find('?', p)) != std::string::npos; p += 2)
    r.replace(p, 1, "$" + std::to_string(n++));
  return r;
}
void PostgresEngine::on_new_connection(LoggingDatabaseConnection&) {}
bool PostgresEngine::is_deadlock(const DBException&) const { return false; }
bool PostgresEngine::is_connection_closed(DatabaseConnection&) const { return false; }
void PostgresEngine::lock_table(DatabaseTransaction&, const std::string&) {}
std::string PostgresEngine::server_version() const { return "14.0"; }
std::string PostgresEngine::row_id_name() const { return "ctid"; }
bool PostgresEngine::in_transaction(DatabaseConnection&) const { return false; }
void PostgresEngine::attempt_to_set_autocommit(DatabaseConnection&, bool) {}
void PostgresEngine::attempt_to_set_isolation_level(DatabaseConnection&, std::optional<IsolationLevel>) {}
void PostgresEngine::executescript(DatabaseTransaction& txn, const std::string& s) { txn.executescript(s); }
void PostgresEngine::execute_script_file(DatabaseTransaction& txn, const std::string& path) {
  std::ifstream f(path);
  if (!f) throw DBException(DBErrorClass::OperationalError, "no file: " + path);
  std::stringstream ss; ss << f.rdbuf();
  executescript(txn, ss.str());
}

std::unique_ptr<BaseDatabaseEngine> create_engine(const std::string& name) {
  if (name.find("sql") == 0) return std::make_unique<SqliteEngine>();
  if (name.find("pg") == 0 || name.find("post") == 0) return std::make_unique<PostgresEngine>();
  return std::make_unique<SqliteEngine>();
}

// ============================================================================
// SQLite connection & transaction
// ============================================================================
struct SQLite3Conn : public DatabaseConnection {
  sqlite3* db_ = nullptr;
  explicit SQLite3Conn(const std::string& path) {
    if (sqlite3_open_v2(path.c_str(), &db_,
          SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr) != SQLITE_OK) {
      std::string e = sqlite3_errmsg(db_);
      sqlite3_close(db_);
      throw DBException(DBErrorClass::OperationalError, "open: " + e);
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr);
  }
  ~SQLite3Conn() override { if (db_) sqlite3_close(db_); }
  std::unique_ptr<DatabaseTransaction> cursor(const std::string&) override;
  void close() override { if (db_) { sqlite3_close(db_); db_ = nullptr; } }
  void commit() override {}
  void rollback() override {}
  bool is_connected() const override { return db_ != nullptr; }
};

struct SQLite3Txn : public DatabaseTransaction {
  sqlite3* db_;
  std::vector<std::string> col_names_;
  RowList rows_;
  size_t iter_pos_ = 0;

  explicit SQLite3Txn(sqlite3* db) : db_(db) {}

  void execute(const std::string& sql) override {
    // Use sqlite3_exec for multi-statement SQL (DDL, schema, etc.)
    // Then collect results via a callback
    rows_.clear();
    col_names_.clear();
    char* err = nullptr;
    auto callback = [](void* data, int argc, char** argv, char** col_names) -> int {
      auto* self = static_cast<SQLite3Txn*>(data);
      if (self->col_names_.empty()) {
        for (int i = 0; i < argc; i++)
          self->col_names_.push_back(col_names[i] ? col_names[i] : "");
      }
      Row row;
      for (int i = 0; i < argc; i++) {
        ColumnValue cv;
        cv.name = self->col_names_[i];
        cv.value = argv[i] ? std::optional<std::string>(argv[i]) : std::nullopt;
        row.push_back(std::move(cv));
      }
      self->rows_.push_back(std::move(row));
      return 0;
    };
    int rc = sqlite3_exec(db_, sql.c_str(), callback, this, &err);
    if (rc != SQLITE_OK) {
      std::string msg = err ? err : sqlite3_errmsg(db_);
      sqlite3_free(err);
      throw DBException(DBErrorClass::OperationalError, "exec: " + msg);
    }
    iter_pos_ = 0;
  }

  void execute(const std::string& sql, const std::vector<SQLParam>& params) override {
    // Execute once, collect results into rows_
    rows_.clear();
    col_names_.clear();
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
      throw DBException(DBErrorClass::OperationalError, "prepare: " + std::string(sqlite3_errmsg(db_)));
    }
    for (size_t i = 0; i < params.size(); i++) {
      int idx = static_cast<int>(i + 1);
      std::visit([&](const auto& v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, std::string>)
          sqlite3_bind_text(stmt, idx, v.c_str(), -1, SQLITE_TRANSIENT);
        else if constexpr (std::is_same_v<T, int64_t>)
          sqlite3_bind_int64(stmt, idx, v);
        else if constexpr (std::is_same_v<T, double>)
          sqlite3_bind_double(stmt, idx, v);
      }, params[i]);
    }
    // Collect column names from first row
    int nc = sqlite3_column_count(stmt);
    for (int i = 0; i < nc; i++)
      col_names_.push_back(sqlite3_column_name(stmt, i));
    // Step through all rows
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
      Row row;
      for (int i = 0; i < nc; i++) {
        ColumnValue cv;
        cv.name = col_names_[i];
        int t = sqlite3_column_type(stmt, i);
        if (t == SQLITE_NULL) cv.value = std::nullopt;
        else if (t == SQLITE_INTEGER) cv.value = std::to_string(sqlite3_column_int64(stmt, i));
        else if (t == SQLITE_FLOAT) cv.value = std::to_string(sqlite3_column_double(stmt, i));
        else if (t == SQLITE_TEXT)
          cv.value = std::string(reinterpret_cast<const char*>(sqlite3_column_text(stmt, i)));
        row.push_back(std::move(cv));
      }
      rows_.push_back(std::move(row));
    }
    sqlite3_finalize(stmt);
    iter_pos_ = 0;
  }

  void executemany(const std::string& sql, const std::vector<std::vector<SQLParam>>&) override {
    execute(sql);
  }

  std::optional<Row> fetchone() override {
    if (iter_pos_ < rows_.size()) return rows_[iter_pos_++];
    return std::nullopt;
  }

  RowList fetchmany(std::optional<int> size) override {
    RowList out;
    int n = size.value_or(static_cast<int>(rows_.size()));
    while (n-- > 0 && iter_pos_ < rows_.size())
      out.push_back(rows_[iter_pos_++]);
    return out;
  }

  RowList fetchall() override {
    RowList out = rows_;
    rows_.clear();
    iter_pos_ = 0;
    return out;
  }

  int64_t rowcount() const override { return static_cast<int64_t>(rows_.size()); }
  void close() override { rows_.clear(); }
  std::vector<std::string> description() const override { return col_names_; }
  bool iter_next(Row& row) override {
    if (iter_pos_ < rows_.size()) { row = rows_[iter_pos_++]; return true; }
    return false;
  }
  void iter_reset() override { iter_pos_ = 0; }
  void executescript(const std::string& script) override { execute(script); }
};

std::unique_ptr<DatabaseTransaction> SQLite3Conn::cursor(const std::string&) {
  return std::make_unique<SQLite3Txn>(db_);
}

// ============================================================================
// DatabasePool
// ============================================================================
DatabasePool::DatabasePool(
    const std::string& server_name, const std::string& database_name,
    const std::string& connection_string)
    : server_name_(server_name), database_name_(database_name),
      connection_string_(connection_string),
      engine_(create_engine("sqlite3")) {
  // Open persistent connection
  conn_ = std::make_unique<SQLite3Conn>(connection_string_);
}

DatabasePool::~DatabasePool() = default;

RowList DatabasePool::execute(const std::string&, const std::string& query,
                                const std::vector<SQLParam>& args) {
  auto txn = conn_->cursor("exec");
  txn->execute(query, args);
  return txn->fetchall();
}

nlohmann::json DatabasePool::query(const std::string& sql) {
  auto txn = conn_->cursor("query");
  txn->execute(sql);
  auto rows = txn->fetchall();
  nlohmann::json result = nlohmann::json::array();
  for (auto& row : rows) {
    nlohmann::json obj = nlohmann::json::object();
    for (auto& cv : row) {
      if (cv.value) {
        // Try to parse as number first (SQLite returns all values as strings)
        const std::string& s = *cv.value;
        if (s.empty() || s == "null") {
          obj[cv.name] = nullptr;
        } else {
          // Check if it's an integer
          bool is_int = true;
          for (size_t i = (s[0] == '-' ? 1 : 0); i < s.size(); i++) {
            if (s[i] < '0' || s[i] > '9') { is_int = false; break; }
          }
          if (is_int && !s.empty() && s != "-") {
            obj[cv.name] = std::stoll(s);
          } else {
            // Check if it's a float
            bool is_float = true;
            int dots = 0;
            for (size_t i = (s[0] == '-' ? 1 : 0); i < s.size(); i++) {
              if (s[i] == '.') dots++;
              else if (s[i] < '0' || s[i] > '9') { is_float = false; break; }
            }
            if (is_float && dots == 1 && !s.empty() && s != "-" && s != ".") {
              obj[cv.name] = std::stod(s);
            } else {
              obj[cv.name] = s;
            }
          }
        }
      } else {
        obj[cv.name] = nullptr;
      }
    }
    result.push_back(obj);
  }
  return result;
}

std::unique_ptr<LoggingDatabaseConnection> DatabasePool::get_connection() {
  return nullptr;
}

// ============================================================================
// LoggingTransaction implementation
// ============================================================================
LoggingTransaction::LoggingTransaction(
    std::unique_ptr<DatabaseTransaction> txn,
    const std::string& /*name*/,
    const std::string& /*server_name*/,
    std::shared_ptr<BaseDatabaseEngine> /*engine*/,
    std::vector<CallbackListEntry>* /*after_callbacks*/,
    std::vector<AsyncCallbackListEntry>* /*async_after_callbacks*/,
    std::vector<CallbackListEntry>* /*exception_callbacks*/)
    : txn_(std::move(txn)) {}

LoggingTransaction::~LoggingTransaction() = default;

void LoggingTransaction::execute(const std::string& sql) { txn_->execute(sql); }
void LoggingTransaction::execute(const std::string& sql, const std::vector<SQLParam>& params) { txn_->execute(sql, params); }
void LoggingTransaction::executemany(const std::string& sql, const std::vector<std::vector<SQLParam>>& params_list) { txn_->executemany(sql, params_list); }
std::optional<Row> LoggingTransaction::fetchone() { return txn_->fetchone(); }
RowList LoggingTransaction::fetchmany(std::optional<int> size) { return txn_->fetchmany(size); }
RowList LoggingTransaction::fetchall() { return txn_->fetchall(); }
int64_t LoggingTransaction::rowcount() const { return txn_->rowcount(); }
void LoggingTransaction::close() { txn_->close(); }
std::vector<std::string> LoggingTransaction::description() const { return txn_->description(); }
bool LoggingTransaction::iter_next(Row& row) { return txn_->iter_next(row); }
void LoggingTransaction::iter_reset() { txn_->iter_reset(); }
void LoggingTransaction::executescript(const std::string& script) { txn_->executescript(script); }

// ============================================================================
// BackgroundUpdater, factories
// ============================================================================
BackgroundUpdater::BackgroundUpdater(const std::string& sn, DatabasePool& dp)
    : server_name_(sn), db_pool_(dp) {}
BackgroundUpdater::~BackgroundUpdater() { shutdown(); }
void BackgroundUpdater::shutdown() { running_ = false; }
bool BackgroundUpdater::has_completed_background_updates() const { return true; }
void BackgroundUpdater::register_background_update_handler(const std::string&, std::function<void(DatabasePool&)>) {}
void BackgroundUpdater::register_background_controller(const std::string&, std::function<void()>) {}
void BackgroundUpdater::start_doing_background_updates() {}
std::vector<std::string> BackgroundUpdater::get_pending_updates() const { return {}; }

std::unique_ptr<ConnectionPool> make_pool(
    const std::string&, const std::string&, std::shared_ptr<BaseDatabaseEngine>,
    const std::string&, std::function<void(DatabaseConnection&)>) { return nullptr; }

std::unique_ptr<LoggingDatabaseConnection> make_conn(
    const std::string&, std::shared_ptr<BaseDatabaseEngine>,
    const std::string&, const std::string&) { return nullptr; }

}  // namespace progressive::storage
