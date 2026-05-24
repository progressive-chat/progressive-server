#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "../storage/database.hpp"

namespace progressive::handlers {

class MessageHandler {
public:
  explicit MessageHandler(storage::DatabasePool& db);

  // synapse/handlers/message.py MessageHandler ports
  nlohmann::json get_room_data(std::string_view room_id, std::string_view event_type,
                               std::string_view state_key);
  nlohmann::json get_state_events(std::string_view room_id);
  nlohmann::json get_joined_members(std::string_view room_id);

private:
  storage::DatabasePool& db_;
};

}  // namespace progressive::handlers
