#pragma once
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace progressive::storage {

class DatabasePool {
public:
  virtual ~DatabasePool() = default;

  virtual void execute(std::string_view sql) = 0;
  virtual nlohmann::json query(std::string_view sql) = 0;

  template <typename... Args>
  void execute_params(std::string_view sql, Args&&... args) {
    auto replace = [&](std::string& s) -> std::string {
      int idx = 0;
      auto repl = [&](std::string_view val) {
        auto pos = s.find('?');
        if (pos != std::string::npos)
          s.replace(pos, 1, val);
      };
      (repl(escape_param(std::forward<Args>(args))), ...);
      return s;
    };
    std::string expanded(sql);
    execute(replace(expanded));
  }

  virtual void begin() = 0;
  virtual void commit() = 0;
  virtual void rollback() = 0;
  virtual std::string driver_name() const = 0;

  static std::unique_ptr<DatabasePool> create(std::string_view conn_string);

private:
  std::string escape_param(const std::string& v) {
    std::string out = "'";
    for (char c : v) {
      if (c == '\'')
        out += "''";
      else
        out += c;
    }
    out += "'";
    return out;
  }
  std::string escape_param(int64_t v) { return std::to_string(v); }
  std::string escape_param(uint64_t v) { return std::to_string(v); }
  std::string escape_param(int v) { return std::to_string(v); }
  std::string escape_param(std::string_view v) { return escape_param(std::string(v)); }
  std::string escape_param(const char* v) { return escape_param(std::string(v)); }
};

}  // namespace progressive::storage
