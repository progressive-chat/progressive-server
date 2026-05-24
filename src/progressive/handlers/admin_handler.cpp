#include "admin_handler.hpp"

#include "../util/time.hpp"

namespace progressive::handlers {

AdminHandler::AdminHandler(storage::DatabasePool& db) : db_(db) {}

nlohmann::json AdminHandler::get_whois(std::string_view user_id) {
  auto rows = db_.query("SELECT * FROM users WHERE id='" + std::string(user_id) + "'");
  if (rows.empty())
    return {};
  nlohmann::json j;
  j["user_id"] = rows[0]["id"];
  j["admin"] = rows[0].value("admin", 0);
  j["deactivated"] = rows[0].value("deactivated", 0);
  j["creation_ts"] = rows[0].value("creation_ts", int64_t(0));
  return j;
}

void AdminHandler::suspend_user(std::string_view user_id, bool suspend) {
  db_.execute("UPDATE users SET deactivated=" + std::to_string(suspend ? 1 : 0) + " WHERE id='" +
              std::string(user_id) + "'");
}

void AdminHandler::deactivate_user(std::string_view user_id) {
  db_.execute("UPDATE users SET deactivated=1 WHERE id='" + std::string(user_id) + "'");
  db_.execute("DELETE FROM access_tokens WHERE user_id='" + std::string(user_id) + "'");
  db_.execute("DELETE FROM refresh_tokens WHERE user_id='" + std::string(user_id) + "'");
}

void AdminHandler::reset_password(std::string_view user_id, std::string_view new_password) {
  db_.execute("UPDATE users SET password_hash='" + std::string(new_password) + "' WHERE id='" +
              std::string(user_id) + "'");
}

nlohmann::json AdminHandler::search_users(std::string_view query) {
  auto rows = db_.query("SELECT id,admin,deactivated FROM users WHERE id LIKE '%" +
                        std::string(query) + "%' LIMIT 20");
  nlohmann::json j;
  j["users"] = nlohmann::json::array();
  for (auto& r : rows) {
    nlohmann::json u;
    u["name"] = r["id"];
    u["admin"] = r.value("admin", 0);
    u["deactivated"] = r.value("deactivated", 0);
    j["users"].push_back(u);
  }
  j["total"] = j["users"].size();
  return j;
}

void AdminHandler::make_admin(std::string_view user_id, bool admin) {
  db_.execute("UPDATE users SET admin=" + std::to_string(admin ? 1 : 0) + " WHERE id='" +
              std::string(user_id) + "'");
}

nlohmann::json AdminHandler::get_user_stats(std::string_view user_id) {
  auto rooms = db_.query("SELECT COUNT(*) as cnt FROM room_memberships WHERE user_id='" +
                         std::string(user_id) + "' AND membership='join'");
  auto events =
      db_.query("SELECT COUNT(*) as cnt FROM events WHERE sender='" + std::string(user_id) + "'");
  nlohmann::json j;
  j["joined_rooms"] =
      (!rooms.empty() && rooms[0]["cnt"].is_number()) ? rooms[0]["cnt"].template get<int>() : 0;
  j["events_sent"] =
      (!events.empty() && events[0]["cnt"].is_number()) ? events[0]["cnt"].template get<int>() : 0;
  return j;
}

nlohmann::json AdminHandler::get_room_stats(std::string_view room_id) {
  auto members = db_.query("SELECT COUNT(*) as cnt FROM room_memberships WHERE room_id='" +
                           std::string(room_id) + "'");
  auto events =
      db_.query("SELECT COUNT(*) as cnt FROM events WHERE room_id='" + std::string(room_id) + "'");
  nlohmann::json j;
  j["member_count"] = (!members.empty() && members[0]["cnt"].is_number())
                          ? members[0]["cnt"].template get<int>()
                          : 0;
  j["event_count"] =
      (!events.empty() && events[0]["cnt"].is_number()) ? events[0]["cnt"].template get<int>() : 0;
  j["room_id"] = room_id;
  return j;
}

// StatsHandler
StatsHandler::StatsHandler(storage::DatabasePool& db) : db_(db) {}

nlohmann::json StatsHandler::compute_room_stats(std::string_view room_id) {
  AdminHandler admin(db_);
  return admin.get_room_stats(room_id);
}

nlohmann::json StatsHandler::compute_user_stats(std::string_view user_id) {
  AdminHandler admin(db_);
  return admin.get_user_stats(user_id);
}

nlohmann::json StatsHandler::compute_server_stats() {
  auto users = db_.query("SELECT COUNT(*) as cnt FROM users");
  auto rooms = db_.query("SELECT COUNT(*) as cnt FROM rooms");
  auto events = db_.query("SELECT COUNT(*) as cnt FROM events");
  nlohmann::json j;
  j["user_count"] =
      (!users.empty() && users[0]["cnt"].is_number()) ? users[0]["cnt"].template get<int>() : 0;
  j["room_count"] =
      (!rooms.empty() && rooms[0]["cnt"].is_number()) ? rooms[0]["cnt"].template get<int>() : 0;
  j["event_count"] =
      (!events.empty() && events[0]["cnt"].is_number()) ? events[0]["cnt"].template get<int>() : 0;
  return j;
}

}  // namespace progressive::handlers
