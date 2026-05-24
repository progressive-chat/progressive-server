#include "sliding_sync.hpp"

#include <nlohmann/json.hpp>

namespace progressive::sync {

SlidingSyncEngine::SlidingSyncEngine(storage::DatabasePool& db) : db_(db) {}

nlohmann::json SlidingSyncEngine::sync(const std::string& conn_id, const std::string& user_id,
                                       const nlohmann::json& req) {
  uint64_t now = util::now_ms();
  if (connections_.find(conn_id) == connections_.end()) {
    SlidingSyncConnection c;
    c.conn_id = conn_id;
    c.user_id = user_id;
    c.pos = std::to_string(now);
    c.created_ts = now;
    c.updated_ts = now;
    connections_[conn_id] = c;
  }
  auto& conn = connections_[conn_id];
  conn.updated_ts = now;
  conn.pos = std::to_string(now);

  nlohmann::json resp;
  resp["conn_id"] = conn_id;
  resp["pos"] = conn.pos;
  resp["rooms"] = nlohmann::json::object();
  resp["extensions"] = nlohmann::json::object();

  // Return room data for tracked rooms
  for (auto& rid : conn.rooms) {
    auto rows =
        db_.query("SELECT * FROM events WHERE room_id='" + rid + "' ORDER BY depth DESC LIMIT 20");
    nlohmann::json rm;
    rm["timeline"] = nlohmann::json::array();
    for (auto& ev : rows) {
      nlohmann::json e;
      e["event_id"] = ev["event_id"];
      e["type"] = ev["type"];
      e["sender"] = ev["sender"];
      try {
        e["content"] = nlohmann::json::parse(ev["content"].template get<std::string>());
      } catch (...) {
        e["content"] = nlohmann::json::object();
      }
      rm["timeline"].push_back(e);
    }
    resp["rooms"][rid] = rm;
  }
  return resp;
}

void SlidingSyncEngine::add_room(const std::string& conn_id, const std::string& room_id) {
  connections_[conn_id].rooms.insert(room_id);
}

}  // namespace progressive::sync
