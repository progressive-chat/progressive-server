#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

#include "../storage/database.hpp"

namespace progressive::handlers {

class AdminHandler {
public:
  explicit AdminHandler(storage::DatabasePool& db);

  // synapse/handlers/admin.py line-by-line ports
  nlohmann::json get_whois(std::string_view user_id);
  void suspend_user(std::string_view user_id, bool suspend);
  void deactivate_user(std::string_view user_id);
  void reset_password(std::string_view user_id, std::string_view new_password);
  nlohmann::json search_users(std::string_view query);
  void make_admin(std::string_view user_id, bool admin);
  nlohmann::json get_user_stats(std::string_view user_id);
  nlohmann::json get_room_stats(std::string_view room_id);

private:
  storage::DatabasePool& db_;
};

class StatsHandler {
public:
  explicit StatsHandler(storage::DatabasePool& db);
  nlohmann::json compute_room_stats(std::string_view room_id);
  nlohmann::json compute_user_stats(std::string_view user_id);
  nlohmann::json compute_server_stats();

private:
  storage::DatabasePool& db_;
};

}  // namespace progressive::handlers
