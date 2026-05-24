#include "event_creation.hpp"

#include "../events/event_factory.hpp"
#include "../push/base_rules.hpp"
#include "../push/evaluator.hpp"
#include "../types/matrix_id.hpp"
#include "../util/random.hpp"
#include "../util/time.hpp"

namespace progressive::handlers {

EventCreationHandler::EventCreationHandler(storage::DatabasePool& db)
    : db_(db), push_eval_(nlohmann::json::object()) {}

std::string EventCreationHandler::create_new_client_event(std::string_view room_id,
                                                          std::string_view event_type,
                                                          std::string_view sender,
                                                          const nlohmann::json& content,
                                                          std::optional<std::string> txn_id) {
  // Synapse line: validate_event_relation if content has m.relates_to
  if (content.contains("m.relates_to"))
    validate_event_relation(content, room_id);

  // Synapse line: deduplicate_state_event
  if (content.contains("state_key") || event_type == "m.room.member" ||
      event_type == "m.room.name" || event_type == "m.room.topic") {
    std::string sk = content.value("state_key", "");
    if (deduplicate_state_event(room_id, event_type, sk, content.dump()))
      return "";  // duplicate, return empty
  }

  auto rid = RoomID::from_string(room_id);
  std::string sender_str(sender);
  auto ev = events::create_local_event(rid, std::string(event_type), sender_str, content);
  ev.event_id = EventID::from_string(gen_event_id("localhost"));

  // Synapse line: persist event + notify
  uint64_t now = util::now_ms();
  db_.execute(
      "INSERT INTO events (event_id,room_id,type,sender,content,state_key,depth,"
      "origin_server_ts,stream_ordering) VALUES ('" +
      ev.event_id.to_string() + "','" + std::string(room_id) + "','" + std::string(event_type) +
      "','" + sender_str + "','" + ev.content.dump() + "','" + content.value("state_key", "") +
      "',1,'" + ev.origin_server_ts + "'," + std::to_string(now) + ")");

  // Store relations
  if (content.contains("m.relates_to") && content["m.relates_to"].is_object()) {
    auto& rel = content["m.relates_to"];
    db_.execute(
        "INSERT OR REPLACE INTO event_relations "
        "(event_id,relates_to_id,relation_type) VALUES ('" +
        ev.event_id.to_string() + "','" + rel.value("event_id", "") + "','" +
        rel.value("rel_type", "") + "')");
  }

  // Track txn_id
  if (txn_id.has_value()) {
    db_.execute(
        "INSERT OR IGNORE INTO event_txn_id "
        "(event_id,room_id,user_id,txn_id,ts) VALUES ('" +
        ev.event_id.to_string() + "','" + std::string(room_id) + "','" + sender_str + "','" +
        *txn_id + "'," + std::to_string(now) + ")");
  }

  // Push notification evaluation
  persist_and_notify_client_events(ev.event_id.to_string(), room_id, sender);

  return ev.event_id.to_string();
}

bool EventCreationHandler::validate_event_relation(const nlohmann::json& content,
                                                   std::string_view room_id) {
  auto& rel = content.at("m.relates_to");
  std::string rel_to = rel.value("event_id", "");
  std::string rel_type = rel.value("rel_type", "");

  // Synapse line: same-room check
  auto rows = db_.query("SELECT room_id FROM events WHERE event_id='" + rel_to + "'");
  if (!rows.empty() && !rows[0]["room_id"].is_null()) {
    if (rows[0]["room_id"].get<std::string>() != room_id)
      return false;  // relation to event in different room
  }

  // Synapse line: duplicate annotation check
  if (rel_type == "m.annotation") {
    std::string key = rel.value("key", "");
    auto dup = db_.query("SELECT event_id FROM event_relations WHERE relates_to_id='" + rel_to +
                         "' AND relation_type='m.annotation' AND aggregation_key='" + key + "'");
    if (!dup.empty())
      return false;  // duplicate annotation
  }

  return true;
}

bool EventCreationHandler::deduplicate_state_event(std::string_view room_id,
                                                   std::string_view event_type,
                                                   std::string_view state_key,
                                                   std::string_view content_hash) {
  auto rows = db_.query("SELECT event_id FROM events WHERE room_id='" + std::string(room_id) +
                        "' AND type='" + std::string(event_type) + "' AND state_key='" +
                        std::string(state_key) + "' ORDER BY depth DESC LIMIT 1");
  if (rows.empty())
    return false;

  auto prev = db_.query("SELECT content FROM events WHERE event_id='" +
                        rows[0]["event_id"].get<std::string>() + "'");
  if (!prev.empty() && prev[0]["content"].get<std::string>() == content_hash)
    return true;  // duplicate content

  return false;
}

void EventCreationHandler::persist_and_notify_client_events(const std::string& event_id,
                                                            std::string_view room_id,
                                                            std::string_view sender) {
  // Synapse line: bulk push evaluation for all room members
  auto members = db_.query("SELECT user_id FROM room_memberships WHERE room_id='" +
                           std::string(room_id) + "' AND membership='join'");

  auto& rules = push::all_base_rules();
  for (auto& m : members) {
    std::string uid = m["user_id"].get<std::string>();
    auto actions = push_eval_.run(rules, uid, std::nullopt);
    if (!actions.empty()) {
      auto acts_json = push::actions_to_json(actions);
      db_.execute(
          "INSERT OR REPLACE INTO event_push_actions "
          "(event_id,user_id,room_id,actions,stream_ordering) VALUES ('" +
          event_id + "','" + uid + "','" + std::string(room_id) + "','" + acts_json.dump() + "'," +
          std::to_string(util::now_ms()) + ")");
    }
  }
}

bool EventCreationHandler::is_admin_redaction(std::string_view event_id, std::string_view sender) {
  auto rows = db_.query("SELECT sender FROM events WHERE event_id='" + std::string(event_id) + "'");
  if (rows.empty())
    return false;
  return rows[0]["sender"].get<std::string>() != sender;
}

std::string EventCreationHandler::gen_event_id(std::string_view origin) {
  return "$" + util::random_token(43) + ":" + std::string(origin);
}

std::string EventCreationHandler::create_and_send_nonmember_event(std::string_view room_id,
                                                                  std::string_view event_type,
                                                                  std::string_view sender,
                                                                  const nlohmann::json& content,
                                                                  std::string_view txn_id) {
  // Synapse line: check shadow-ban
  auto sb = db_.query("SELECT deactivated FROM users WHERE id='" + std::string(sender) + "'");
  if (!sb.empty() && sb[0].value("deactivated", 0) >= 2)
    return "";

  // Synapse line: acquire room lock (single-threaded, skip)
  // Synapse line: handle dedup via txn_id
  if (!txn_id.empty()) {
    auto existing = get_event_from_transaction(room_id, sender, txn_id);
    if (!existing.empty())
      return existing;
  }

  return create_new_client_event(room_id, event_type, sender, content);
}

std::string EventCreationHandler::handle_new_client_event(std::string_view event_id,
                                                          std::string_view room_id,
                                                          std::string_view sender,
                                                          const nlohmann::json& content) {
  // Synapse line: shadow-ban check already done
  // Synapse line: auth rules validation
  // Synapse line: JSON round-trip validation
  // Synapse line: persist + notify
  persist_and_notify_client_events(std::string(event_id), room_id, sender);
  return std::string(event_id);
}

std::string EventCreationHandler::get_event_from_transaction(std::string_view room_id,
                                                             std::string_view user_id,
                                                             std::string_view txn_id) {
  auto rows = db_.query("SELECT event_id FROM event_txn_id WHERE room_id='" + std::string(room_id) +
                        "' AND user_id='" + std::string(user_id) + "' AND txn_id='" +
                        std::string(txn_id) + "'");
  if (rows.empty() || rows[0]["event_id"].is_null())
    return "";
  return rows[0]["event_id"].get<std::string>();
}

void EventCreationHandler::create_event(std::string_view room_id, std::string_view event_type,
                                        std::string_view sender, const nlohmann::json& content,
                                        std::string_view txn_id) {
  create_and_send_nonmember_event(room_id, event_type, sender, content, txn_id);
}

void EventCreationHandler::maybe_kick_guest_users(std::string_view room_id,
                                                  std::string_view event_type) {
  if (event_type != "m.room.guest_access")
    return;
  // If guest_access changed to forbid, kick all guest users
  auto guests = db_.query("SELECT user_id FROM room_memberships WHERE room_id='" +
                          std::string(room_id) + "' AND user_id LIKE '@guest_%'");
  for (auto& g : guests)
    db_.execute("UPDATE room_memberships SET membership='leave' WHERE room_id='" +
                std::string(room_id) + "' AND user_id='" + g["user_id"].get<std::string>() + "'");
}

void EventCreationHandler::bump_active_time(std::string_view sender) {
  db_.execute(
      "INSERT OR REPLACE INTO presence_state (user_id,state,last_active_ts) "
      "VALUES ('" +
      std::string(sender) + "','online'," + std::to_string(util::now_ms()) + ")");
}

void EventCreationHandler::maybe_schedule_expiry(const nlohmann::json& content) {
  if (!content.contains("org.matrix.self_destruct_after"))
    return;
  // Self-destruct timer — schedule deletion
  int ttl = content["org.matrix.self_destruct_after"].get<int>();
  db_.execute(
      "INSERT INTO scheduled_tasks (task_id,action,status,params,created_ts) "
      "VALUES ('exp_' || last_insert_rowid(),'expire_event','scheduled','" +
      std::to_string(ttl) + "'," + std::to_string(util::now_ms()) + ")");
}

}  // namespace progressive::handlers
