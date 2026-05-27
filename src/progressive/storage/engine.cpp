#include "engine.hpp"
#include "database.hpp"

namespace progressive::storage {

// connect() and apply_schema() exist only in database.hpp implementation.
// The real implementations are in database.cpp.

// make_engine factory - maps engine name string to engine instance
std::unique_ptr<BaseDatabaseEngine> create_engine(const std::string& name) {
  if (name == "sqlite3" || name.find("sql") == 0)
    return std::make_unique<SqliteEngine>();
  if (name.find("pg") == 0 || name.find("post") == 0)
    return std::make_unique<PostgresEngine>();
  return std::make_unique<SqliteEngine>();
}

}  // namespace progressive::storage
