#include "message_handler.hpp"

namespace progressive::handlers {

MessageHandler::MessageHandler(storage::DatabasePool& db) : db_(db) {}

nlohmann::json MessageHandler::get_room_data(std::string_view room_id, std::string_view event_type,
                                             std::string_view state_key) {
  auto rows = db_.query("SELECT * FROM events WHERE room_id='" + std::string(room_id) +
                        "' AND type='" + std::string(event_type) + "' AND state_key='" +
                        std::string(state_key) + "' ORDER BY depth DESC LIMIT 1");
  if (rows.empty() || rows[0]["event_id"].is_null())
    return {};

  nlohmann::json result;
  result["event_id"] = rows[0]["event_id"];
  result["type"] = rows[0]["type"];
  result["sender"] = rows[0]["sender"];
  try {
    result["content"] = nlohmann::json::parse(rows[0]["content"].template get<std::string>());
  } catch (...) {
    result["content"] = nlohmann::json::object();
  }
  return result;
}

nlohmann::json MessageHandler::get_state_events(std::string_view room_id) {
  auto rows = db_.query("SELECT * FROM events WHERE room_id='" + std::string(room_id) +
                        "' AND state_key != '' ORDER BY depth");
  nlohmann::json result = nlohmann::json::array();
  for (auto& r : rows) {
    nlohmann::json ev;
    ev["event_id"] = r["event_id"];
    ev["type"] = r["type"];
    ev["sender"] = r["sender"];
    ev["state_key"] = r.value("state_key", "");
    try {
      ev["content"] = nlohmann::json::parse(r["content"].template get<std::string>());
    } catch (...) {
      ev["content"] = nlohmann::json::object();
    }
    result.push_back(ev);
  }
  return result;
}

nlohmann::json MessageHandler::get_joined_members(std::string_view room_id) {
  auto rows = db_.query("SELECT user_id FROM room_memberships WHERE room_id='" +
                        std::string(room_id) + "' AND membership='join'");
  nlohmann::json result;
  result["joined"] = nlohmann::json::object();
  for (auto& r : rows) {
    std::string uid = r["user_id"].template get<std::string>();
    result["joined"][uid] = {{"display_name", uid}, {"avatar_url", ""}};
  }
  return result;
}

}  // namespace progressive::handlers
