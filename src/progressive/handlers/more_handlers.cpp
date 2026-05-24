#include "more_handlers.hpp"

#include "../util/time.hpp"

namespace progressive::handlers {

// === PresenceHandler ===
PresenceHandler::PresenceHandler(storage::DatabasePool& db) : db_(db) {}

void PresenceHandler::set_presence(std::string_view user_id, std::string_view state,
                                   std::string_view status_msg) {
  uint64_t now = util::now_ms();
  db_.execute(
      "INSERT OR REPLACE INTO presence_state "
      "(user_id,state,status_msg,last_active_ts,last_federation_update_ts) VALUES ('" +
      std::string(user_id) + "','" + std::string(state) + "','" + std::string(status_msg) + "'," +
      std::to_string(now) + "," + std::to_string(now) + ")");
}

nlohmann::json PresenceHandler::get_presence(std::string_view user_id) {
  auto rows =
      db_.query("SELECT state,status_msg,last_active_ts FROM presence_state WHERE user_id='" +
                std::string(user_id) + "'");
  nlohmann::json j;
  if (rows.empty()) {
    j["presence"] = "offline";
    j["last_active_ago"] = 3600000;
  } else {
    j["presence"] = rows[0].value("state", "offline");
    j["status_msg"] = rows[0].value("status_msg", "");
    int64_t ago = util::now_ms() - rows[0].value("last_active_ts", int64_t(0));
    j["last_active_ago"] = ago > 0 ? ago : 0;
  }
  return j;
}

void PresenceHandler::bump_last_active(std::string_view user_id) {
  db_.execute(
      "INSERT OR REPLACE INTO presence_state "
      "(user_id,state,last_active_ts) VALUES ('" +
      std::string(user_id) + "','online'," + std::to_string(util::now_ms()) + ")");
}

// === SearchHandler ===
SearchHandler::SearchHandler(storage::DatabasePool& db) : db_(db) {}

nlohmann::json SearchHandler::search_events(std::string_view term, int limit) {
  auto rows = db_.query(
      "SELECT e.event_id,e.room_id,e.type,e.sender,e.content "
      "FROM event_search s JOIN events e ON s.event_id=e.event_id "
      "WHERE s.body LIKE '%" +
      std::string(term) + "%' LIMIT " + std::to_string(limit));
  nlohmann::json j;
  j["results"] = nlohmann::json::array();
  for (auto& r : rows) {
    nlohmann::json ev;
    ev["event_id"] = r["event_id"];
    ev["room_id"] = r["room_id"];
    ev["type"] = r["type"];
    ev["sender"] = r["sender"];
    try {
      ev["content"] = nlohmann::json::parse(r["content"].template get<std::string>());
    } catch (...) {
      ev["content"] = nlohmann::json::object();
    }
    j["results"].push_back({{"result", ev}, {"rank", 1.0}});
  }
  j["count"] = j["results"].size();
  return j;
}

nlohmann::json SearchHandler::search_users(std::string_view term, int limit) {
  auto rows = db_.query("SELECT id FROM users WHERE id LIKE '%" + std::string(term) + "%' LIMIT " +
                        std::to_string(limit));
  nlohmann::json j;
  j["results"] = nlohmann::json::array();
  for (auto& r : rows)
    j["results"].push_back({{"user_id", r["id"]}, {"display_name", r["id"]}});
  j["limited"] = j["results"].size() >= static_cast<size_t>(limit);
  return j;
}

// === RoomMemberHandler ===
RoomMemberHandler::RoomMemberHandler(storage::DatabasePool& db) : db_(db) {}

void RoomMemberHandler::join_room(std::string_view room_id, std::string_view user_id) {
  std::string eid = "$join_" + std::to_string(util::now_ms());
  db_.execute(
      "INSERT OR REPLACE INTO room_memberships "
      "(event_id,room_id,user_id,membership,sender) VALUES ('" +
      eid + "','" + std::string(room_id) + "','" + std::string(user_id) + "','join','" +
      std::string(user_id) + "')");
}

void RoomMemberHandler::leave_room(std::string_view room_id, std::string_view user_id) {
  db_.execute("UPDATE room_memberships SET membership='leave' WHERE room_id='" +
              std::string(room_id) + "' AND user_id='" + std::string(user_id) + "'");
}

void RoomMemberHandler::invite_user(std::string_view room_id, std::string_view sender,
                                    std::string_view target) {
  db_.execute(
      "INSERT OR REPLACE INTO room_memberships "
      "(event_id,room_id,user_id,membership,sender) VALUES ('$inv_" +
      std::to_string(util::now_ms()) + "','" + std::string(room_id) + "','" + std::string(target) +
      "','invite','" + std::string(sender) + "')");
}

void RoomMemberHandler::ban_user(std::string_view room_id, std::string_view sender,
                                 std::string_view target, std::string_view reason) {
  std::string eid = "$ban_" + std::to_string(util::now_ms());
  db_.execute("UPDATE room_memberships SET membership='ban',content='" + std::string(reason) +
              "' WHERE room_id='" + std::string(room_id) + "' AND user_id='" + std::string(target) +
              "'");
  (void)sender;
  (void)eid;
}

void RoomMemberHandler::kick_user(std::string_view room_id, std::string_view sender,
                                  std::string_view target, std::string_view reason) {
  leave_room(room_id, target);
  (void)sender;
  (void)reason;
}

void RoomMemberHandler::unban_user(std::string_view room_id, std::string_view target) {
  db_.execute("UPDATE room_memberships SET membership='leave' WHERE room_id='" +
              std::string(room_id) + "' AND user_id='" + std::string(target) + "'");
}

void RoomMemberHandler::knock_room(std::string_view room_id, std::string_view user_id,
                                   std::string_view reason) {
  db_.execute(
      "INSERT OR REPLACE INTO room_memberships "
      "(event_id,room_id,user_id,membership,sender) VALUES ('$knock_" +
      std::to_string(util::now_ms()) + "','" + std::string(room_id) + "','" + std::string(user_id) +
      "','knock','" + std::string(user_id) + "')");
  (void)reason;
}

// === RelationsHandler ===
RelationsHandler::RelationsHandler(storage::DatabasePool& db) : db_(db) {}

nlohmann::json RelationsHandler::get_relations(std::string_view event_id, std::string_view rel_type,
                                               std::string_view event_type, int limit) {
  std::string sql =
      "SELECT e.event_id,e.type,e.sender,e.content FROM events e "
      "JOIN event_relations r ON e.event_id=r.event_id "
      "WHERE r.relates_to_id='" +
      std::string(event_id) + "'";
  if (!rel_type.empty())
    sql += " AND r.relation_type='" + std::string(rel_type) + "'";
  sql += " LIMIT " + std::to_string(limit);

  auto rows = db_.query(sql);
  nlohmann::json j;
  j["chunk"] = nlohmann::json::array();
  for (auto& r : rows) {
    nlohmann::json ev;
    ev["event_id"] = r["event_id"];
    ev["type"] = r["type"];
    ev["sender"] = r["sender"];
    try {
      ev["content"] = nlohmann::json::parse(r["content"].template get<std::string>());
    } catch (...) {
      ev["content"] = nlohmann::json::object();
    }
    if (!event_type.empty() && ev["type"] != event_type)
      continue;
    j["chunk"].push_back(ev);
  }
  return j;
}

nlohmann::json RelationsHandler::get_bundled_aggregations(const std::vector<std::string>& event_ids,
                                                          std::string_view user_id) {
  nlohmann::json aggs;
  for (auto& eid : event_ids) {
    auto rels = get_relations(eid, "m.annotation", "", 5);
    if (!rels["chunk"].empty()) {
      aggs[eid] = nlohmann::json::object();
      aggs[eid]["m.annotation"] = rels;
    }
  }
  (void)user_id;
  return aggs;
}

}  // namespace progressive::handlers
