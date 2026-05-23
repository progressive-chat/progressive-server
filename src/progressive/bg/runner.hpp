#pragma once
#include <functional>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "../storage/database.hpp"

namespace progressive::bg {

using UpdateFunc = std::function<bool(storage::DatabasePool&, nlohmann::json& progress)>;

class BackgroundUpdateRunner {
public:
  explicit BackgroundUpdateRunner(storage::DatabasePool& db);
  void register_update(std::string_view name, UpdateFunc func, std::string_view depends = "");
  void run();

private:
  storage::DatabasePool& db_;
  std::map<std::string, UpdateFunc, std::less<>> updates_;
  std::map<std::string, std::string, std::less<>> depends_;
};

}  // namespace progressive::bg
