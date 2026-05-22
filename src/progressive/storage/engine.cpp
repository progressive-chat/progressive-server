#include "engine.hpp"

namespace progressive::storage {

std::unique_ptr<DatabasePool> PostgresEngine::connect(std::string_view conn_string) {
  return DatabasePool::create(conn_string);
}

void PostgresEngine::apply_schema(DatabasePool& db, std::string_view schema_sql) {
  db.execute(schema_sql);
}

std::unique_ptr<DatabasePool> SqliteEngine::connect(std::string_view conn_string) {
  return DatabasePool::create(conn_string);
}

void SqliteEngine::apply_schema(DatabasePool& db, std::string_view schema_sql) {
  db.execute(schema_sql);
}

std::unique_ptr<Engine> make_engine(std::string_view name) {
  if (name == "sqlite3" || name.starts_with("sql")) return std::make_unique<SqliteEngine>();
  if (name.starts_with("pg") || name.starts_with("post")) return std::make_unique<PostgresEngine>();
  return std::make_unique<SqliteEngine>();
}

}
