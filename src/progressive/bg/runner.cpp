#include "runner.hpp"

#include <iostream>

namespace progressive::bg {

BackgroundUpdateRunner::BackgroundUpdateRunner(storage::DatabasePool& db) : db_(db) {}

void BackgroundUpdateRunner::register_update(std::string_view name, UpdateFunc func,
                                             std::string_view depends) {
  updates_[std::string(name)] = func;
  if (!depends.empty())
    depends_[std::string(name)] = std::string(depends);
}

void BackgroundUpdateRunner::run() {
  for (auto& [name, func] : updates_) {
    auto rows =
        db_.query("SELECT progress_json FROM background_updates WHERE update_name='" + name + "'");
    nlohmann::json progress;
    if (!rows.empty()) {
      try {
        progress = nlohmann::json::parse(rows[0]["progress_json"].template get<std::string>());
      } catch (...) {
        progress = nlohmann::json::object();
      }
    }

    if (progress.value("done", false))
      continue;

    auto dep_it = depends_.find(name);
    if (dep_it != depends_.end()) {
      auto dep_rows = db_.query("SELECT progress_json FROM background_updates WHERE update_name='" +
                                dep_it->second + "'");
      if (dep_rows.empty())
        continue;  // dependency not yet run
    }

    std::cout << "[bg] running update: " << name << "\n";
    try {
      bool done = func(db_, progress);
      progress["done"] = done;
      db_.execute(
          "INSERT OR REPLACE INTO background_updates (update_name,progress_json) VALUES ('" + name +
          "','" + progress.dump() + "')");
    } catch (const std::exception& e) {
      std::cerr << "[bg] update failed: " << name << " - " << e.what() << "\n";
    }
  }
}

}  // namespace progressive::bg
