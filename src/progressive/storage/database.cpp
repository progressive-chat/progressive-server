#include "database.hpp"
#include <stdexcept>
#include <sstream>
#include <vector>
#include <sqlite3.h>
#ifdef PROGRESSIVE_HAS_POSTGRES
#include <libpq-fe.h>
#endif

namespace progressive::storage {

class SqlitePool : public DatabasePool {
  sqlite3* db_ = nullptr;

public:
  explicit SqlitePool(std::string_view path) {
    if (sqlite3_open(std::string(path).c_str(), &db_) != SQLITE_OK) {
      throw std::runtime_error(std::string("sqlite open: ") + sqlite3_errmsg(db_));
    }
    sqlite3_exec(db_, "PRAGMA journal_mode=WAL", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA foreign_keys=ON", nullptr, nullptr, nullptr);
  }

  ~SqlitePool() override { if (db_) sqlite3_close(db_); }

  void execute(std::string_view sql) override {
    char* err = nullptr;
    if (sqlite3_exec(db_, std::string(sql).c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
      std::string msg = err ? err : "unknown";
      sqlite3_free(err);
      throw std::runtime_error("sqlite execute: " + msg);
    }
  }

  nlohmann::json query(std::string_view sql) override {
    nlohmann::json rows = nlohmann::json::array();
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db_, std::string(sql).c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
      throw std::runtime_error(std::string("sqlite query: ") + sqlite3_errmsg(db_));
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
      nlohmann::json row;
      int cols = sqlite3_column_count(stmt);
      for (int i = 0; i < cols; i++) {
        const char* name = sqlite3_column_name(stmt, i);
        const unsigned char* text = sqlite3_column_text(stmt, i);
        if (text) row[name] = std::string(reinterpret_cast<const char*>(text));
        else row[name] = nlohmann::json(nullptr);
      }
      rows.push_back(row);
    }
    sqlite3_finalize(stmt);
    return rows;
  }

  void begin() override { execute("BEGIN"); }
  void commit() override { execute("COMMIT"); }
  void rollback() override { execute("ROLLBACK"); }
  std::string driver_name() const override { return "sqlite3"; }
};

#ifdef PROGRESSIVE_HAS_POSTGRES

class PostgresPool : public DatabasePool {
  PGconn* conn_ = nullptr;

public:
  explicit PostgresPool(std::string_view conninfo) {
    conn_ = PQconnectdb(std::string(conninfo).c_str());
    if (PQstatus(conn_) != CONNECTION_OK) {
      std::string err = PQerrorMessage(conn_);
      PQfinish(conn_);
      throw std::runtime_error("postgres connect: " + err);
    }
  }

  ~PostgresPool() override { if (conn_) PQfinish(conn_); }

  void execute(std::string_view sql) override {
    PGresult* res = PQexec(conn_, std::string(sql).c_str());
    if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) {
      std::string err = PQresultErrorMessage(res);
      PQclear(res);
      throw std::runtime_error("postgres execute: " + err);
    }
    PQclear(res);
  }

  nlohmann::json query(std::string_view sql) override {
    nlohmann::json rows = nlohmann::json::array();
    PGresult* res = PQexec(conn_, std::string(sql).c_str());
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
      std::string err = PQresultErrorMessage(res);
      PQclear(res);
      throw std::runtime_error("postgres query: " + err);
    }
    int ncols = PQnfields(res);
    int nrows = PQntuples(res);
    for (int r = 0; r < nrows; r++) {
      nlohmann::json row;
      for (int c = 0; c < ncols; c++) {
        const char* name = PQfname(res, c);
        const char* val = PQgetvalue(res, r, c);
        if (val) row[name] = std::string(val);
        else row[name] = nlohmann::json(nullptr);
      }
      rows.push_back(row);
    }
    PQclear(res);
    return rows;
  }

  void begin() override { execute("BEGIN"); }
  void commit() override { execute("COMMIT"); }
  void rollback() override { execute("ROLLBACK"); }
  std::string driver_name() const override { return "postgresql"; }
};

#endif // PROGRESSIVE_HAS_POSTGRES

std::unique_ptr<DatabasePool> DatabasePool::create(std::string_view conn_string) {
  std::string cs(conn_string);
  if (cs.starts_with("sqlite://") || cs.starts_with("sqlite3://")) {
    auto path = cs.substr(cs.find("://") + 3);
    return std::make_unique<SqlitePool>(path);
  }
  if (cs.starts_with("postgres://") || cs.starts_with("postgresql://")) {
#ifdef PROGRESSIVE_HAS_POSTGRES
    return std::make_unique<PostgresPool>(cs);
#else
    throw std::runtime_error("PostgreSQL support not compiled in");
#endif
  }
  throw std::runtime_error("unsupported database: " + cs);
}

}
