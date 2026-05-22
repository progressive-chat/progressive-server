#pragma once
#include <memory>
#include <string>
#include <string_view>

#include "database.hpp"

namespace progressive::storage {

class Engine {
public:
  virtual ~Engine() = default;
  virtual std::unique_ptr<DatabasePool> connect(std::string_view conn_string) = 0;
  virtual void apply_schema(DatabasePool& db, std::string_view schema_sql) = 0;
  virtual std::string driver_name() const = 0;
};

class PostgresEngine : public Engine {
public:
  std::unique_ptr<DatabasePool> connect(std::string_view conn_string) override;
  void apply_schema(DatabasePool& db, std::string_view schema_sql) override;
  std::string driver_name() const override { return "postgresql"; }
};

class SqliteEngine : public Engine {
public:
  std::unique_ptr<DatabasePool> connect(std::string_view conn_string) override;
  void apply_schema(DatabasePool& db, std::string_view schema_sql) override;
  std::string driver_name() const override { return "sqlite3"; }
};

std::unique_ptr<Engine> make_engine(std::string_view name);

}  // namespace progressive::storage
