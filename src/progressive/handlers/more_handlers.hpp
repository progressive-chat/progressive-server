#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

#include "../storage/database.hpp"

namespace progressive::handlers {

class PresenceHandler {
public:
  explicit PresenceHandler(storage::DatabasePool& db);
  void set_presence(std::string_view user_id, std::string_view state,
                    std::string_view status_msg = "");
  nlohmann::json get_presence(std::string_view user_id);
  void bump_last_active(std::string_view user_id);

private:
  storage::DatabasePool& db_;
};

class SearchHandler {
public:
  explicit SearchHandler(storage::DatabasePool& db);
  nlohmann::json search_events(std::string_view term, int limit = 20);
  nlohmann::json search_users(std::string_view term, int limit = 20);

private:
  storage::DatabasePool& db_;
};

class RoomMemberHandler {
public:
  explicit RoomMemberHandler(storage::DatabasePool& db);
  void join_room(std::string_view room_id, std::string_view user_id);
  void leave_room(std::string_view room_id, std::string_view user_id);
  void invite_user(std::string_view room_id, std::string_view sender, std::string_view target);
  void ban_user(std::string_view room_id, std::string_view sender, std::string_view target,
                std::string_view reason = "");
  void kick_user(std::string_view room_id, std::string_view sender, std::string_view target,
                 std::string_view reason = "");
  void unban_user(std::string_view room_id, std::string_view target);
  void knock_room(std::string_view room_id, std::string_view user_id, std::string_view reason = "");

private:
  storage::DatabasePool& db_;
};

class RelationsHandler {
public:
  explicit RelationsHandler(storage::DatabasePool& db);
  nlohmann::json get_relations(std::string_view event_id, std::string_view rel_type = "",
                               std::string_view event_type = "", int limit = 20);
  nlohmann::json get_bundled_aggregations(const std::vector<std::string>& event_ids,
                                          std::string_view user_id);

private:
  storage::DatabasePool& db_;
};

}  // namespace progressive::handlers
