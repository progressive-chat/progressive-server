#pragma once
#include <string>
#include <string_view>
#include <memory>
#include <nlohmann/json.hpp>

namespace progressive::storage {

class DatabasePool {
public:
  virtual ~DatabasePool() = default;
  virtual void execute(std::string_view sql) = 0;
  virtual nlohmann::json query(std::string_view sql) = 0;
  virtual void begin() = 0;
  virtual void commit() = 0;
  virtual void rollback() = 0;
  virtual std::string driver_name() const = 0;

  static std::unique_ptr<DatabasePool> create(std::string_view conn_string);
};

}
