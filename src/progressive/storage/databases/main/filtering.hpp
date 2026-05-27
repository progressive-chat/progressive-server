#pragma once
// filtering.hpp - filtering.py C++ translation
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"
namespace progressive::storage { using json = nlohmann::json;

struct EventFilter {
  std::string filter_id;
  std::string user_id;
  json filter_json;
};

class FilteringStore {
public:
  explicit FilteringStore(DatabasePool& db);
  // Add user filter
  void add_user_filter(const std::string& user_id, const std::string& filter_id,
      const json& filter_json);
  // Get user filter
  std::optional<json> get_user_filter(const std::string& user_id,
      const std::string& filter_id);
  // Get all filters for user
  std::vector<EventFilter> get_user_filters(const std::string& user_id);
  // Delete user filter
  void delete_user_filter(const std::string& user_id, const std::string& filter_id);
  // Add server filter (for federation)
  void add_server_filter(const std::string& filter_id, const json& filter_json);
  // Get server filter
  std::optional<json> get_server_filter(const std::string& filter_id);
private:
  DatabasePool& db_;
};
} // namespace
