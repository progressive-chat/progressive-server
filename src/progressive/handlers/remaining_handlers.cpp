#include "remaining_handlers.hpp"

#include "../util/random.hpp"

namespace progressive::handlers {

// DirectoryHandler
DirectoryHandler::DirectoryHandler(storage::DatabasePool& db) : db_(db) {}
nlohmann::json DirectoryHandler::lookup_alias(std::string_view alias) {
  auto rows = db_.query("SELECT room_id,creator FROM room_aliases WHERE alias='" +
                        std::string(alias) + "'");
  nlohmann::json j;
  if (!rows.empty()) {
    j["room_id"] = rows[0]["room_id"];
    j["servers"] = nlohmann::json::array({"localhost"});
  }
  return j;
}
void DirectoryHandler::create_alias(std::string_view alias, std::string_view room_id,
                                    std::string_view creator) {
  db_.execute("INSERT OR REPLACE INTO room_aliases (alias,room_id,creator) VALUES ('" +
              std::string(alias) + "','" + std::string(room_id) + "','" + std::string(creator) +
              "')");
}
void DirectoryHandler::delete_alias(std::string_view alias) {
  db_.execute("DELETE FROM room_aliases WHERE alias='" + std::string(alias) + "'");
}
nlohmann::json DirectoryHandler::list_room_aliases(std::string_view room_id) {
  auto rows =
      db_.query("SELECT alias FROM room_aliases WHERE room_id='" + std::string(room_id) + "'");
  nlohmann::json j;
  j["aliases"] = nlohmann::json::array();
  for (auto& r : rows)
    j["aliases"].push_back(r["alias"]);
  return j;
}

// ProfileHandler
ProfileHandler::ProfileHandler(storage::DatabasePool& db) : db_(db) {}
nlohmann::json ProfileHandler::get_profile(std::string_view user_id) {
  auto rows = db_.query("SELECT displayname,avatar_url FROM profiles WHERE user_id='" +
                        std::string(user_id) + "'");
  nlohmann::json j;
  if (!rows.empty()) {
    j["displayname"] = rows[0].value("displayname", "");
    j["avatar_url"] = rows[0].value("avatar_url", "");
  }
  return j;
}
void ProfileHandler::set_displayname(std::string_view user_id, std::string_view name) {
  db_.execute("INSERT OR REPLACE INTO profiles (user_id,displayname) VALUES ('" +
              std::string(user_id) + "','" + std::string(name) + "')");
}
void ProfileHandler::set_avatar(std::string_view user_id, std::string_view url) {
  db_.execute("INSERT OR REPLACE INTO profiles (user_id,avatar_url) VALUES ('" +
              std::string(user_id) + "','" + std::string(url) + "')");
}
void ProfileHandler::delete_displayname(std::string_view user_id) {
  db_.execute("UPDATE profiles SET displayname=NULL WHERE user_id='" + std::string(user_id) + "'");
}
void ProfileHandler::delete_avatar(std::string_view user_id) {
  db_.execute("UPDATE profiles SET avatar_url=NULL WHERE user_id='" + std::string(user_id) + "'");
}

// FilterHandler
FilterHandler::FilterHandler(storage::DatabasePool& db) : db_(db) {}
std::string FilterHandler::create_filter(std::string_view user_id, const nlohmann::json& def) {
  auto fid = util::random_token(16);
  db_.execute("INSERT INTO user_filters (user_id,filter_id,filter_json) VALUES ('" +
              std::string(user_id) + "',1,'" + def.dump() + "')");
  return fid;
}
nlohmann::json FilterHandler::get_filter(std::string_view user_id, std::string_view filter_id) {
  auto rows = db_.query("SELECT filter_json FROM user_filters WHERE user_id='" +
                        std::string(user_id) + "' AND filter_id=1");
  if (!rows.empty())
    return nlohmann::json::parse(rows[0]["filter_json"].template get<std::string>());
  return {};
}

// AccountHandler
AccountHandler::AccountHandler(storage::DatabasePool& db) : db_(db) {}
void AccountHandler::change_password(std::string_view user_id, std::string_view new_pw) {
  db_.execute("UPDATE users SET password_hash='" + std::string(new_pw) + "' WHERE id='" +
              std::string(user_id) + "'");
}
void AccountHandler::deactivate_account(std::string_view user_id) {
  db_.execute("UPDATE users SET deactivated=1 WHERE id='" + std::string(user_id) + "'");
  db_.execute("DELETE FROM access_tokens WHERE user_id='" + std::string(user_id) + "'");
}
nlohmann::json AccountHandler::get_threepids(std::string_view user_id) {
  auto rows = db_.query("SELECT auth_provider,external_id FROM user_external_ids WHERE user_id='" +
                        std::string(user_id) + "'");
  nlohmann::json j;
  j["threepids"] = nlohmann::json::array();
  for (auto& r : rows) {
    nlohmann::json t;
    t["medium"] = r["auth_provider"];
    t["address"] = r["external_id"];
    j["threepids"].push_back(t);
  }
  return j;
}
void AccountHandler::add_threepid(std::string_view user_id, std::string_view medium,
                                  std::string_view address) {
  db_.execute(
      "INSERT OR IGNORE INTO user_external_ids (auth_provider,external_id,user_id) VALUES ('" +
      std::string(medium) + "','" + std::string(address) + "','" + std::string(user_id) + "')");
}
void AccountHandler::bind_threepid(std::string_view user_id, std::string_view medium,
                                   std::string_view address) {
  add_threepid(user_id, medium, address);
}
void AccountHandler::unbind_threepid(std::string_view user_id, std::string_view medium,
                                     std::string_view address) {
  db_.execute("DELETE FROM user_external_ids WHERE user_id='" + std::string(user_id) +
              "' AND auth_provider='" + std::string(medium) + "' AND external_id='" +
              std::string(address) + "'");
}
void AccountHandler::delete_threepid(std::string_view user_id, std::string_view medium,
                                     std::string_view address) {
  unbind_threepid(user_id, medium, address);
}

// PushRulesHandler
PushRulesHandler::PushRulesHandler(storage::DatabasePool& db) : db_(db) {}
nlohmann::json PushRulesHandler::get_push_rules(std::string_view user_id) {
  nlohmann::json j;
  j["global"] = nlohmann::json::object();
  j["global"]["override"] = nlohmann::json::array();
  j["global"]["content"] = nlohmann::json::array();
  j["global"]["room"] = nlohmann::json::array();
  j["global"]["sender"] = nlohmann::json::array();
  j["global"]["underride"] = nlohmann::json::array();
  return j;
}
void PushRulesHandler::add_push_rule(std::string_view, std::string_view, std::string_view,
                                     std::string_view, const nlohmann::json&) {}
void PushRulesHandler::delete_push_rule(std::string_view, std::string_view, std::string_view,
                                        std::string_view) {}
void PushRulesHandler::set_enabled(std::string_view, std::string_view, std::string_view,
                                   std::string_view, bool) {}
void PushRulesHandler::set_actions(std::string_view, std::string_view, std::string_view,
                                   std::string_view, const nlohmann::json&) {}

// ReceiptsHandler
ReceiptsHandler::ReceiptsHandler(storage::DatabasePool& db) : db_(db) {}
void ReceiptsHandler::send_receipt(std::string_view user_id, std::string_view room_id,
                                   std::string_view event_id, std::string_view) {
  uint64_t now = util::now_ms();
  db_.execute(
      "INSERT OR REPLACE INTO read_receipts (user_id,room_id,event_id,updated_ts) VALUES ('" +
      std::string(user_id) + "','" + std::string(room_id) + "','" + std::string(event_id) + "'," +
      std::to_string(now) + ")");
}
void ReceiptsHandler::send_read_marker(std::string_view user_id, std::string_view room_id,
                                       std::string_view event_id) {
  uint64_t now = util::now_ms();
  db_.execute(
      "INSERT OR REPLACE INTO read_markers (user_id,room_id,event_id,updated_ts) VALUES ('" +
      std::string(user_id) + "','" + std::string(room_id) + "','" + std::string(event_id) + "'," +
      std::to_string(now) + ")");
}
nlohmann::json ReceiptsHandler::get_receipts(std::string_view room_id) {
  auto rows = db_.query("SELECT user_id,event_id FROM read_receipts WHERE room_id='" +
                        std::string(room_id) + "'");
  nlohmann::json j;
  j["receipts"] = nlohmann::json::array();
  for (auto& r : rows)
    j["receipts"].push_back({{"user_id", r["user_id"]}, {"event_id", r["event_id"]}});
  return j;
}

// TypingHandler
TypingHandler::TypingHandler(storage::DatabasePool& db) : db_(db) {}
void TypingHandler::send_typing(std::string_view, std::string_view, bool, int) {}
nlohmann::json TypingHandler::get_typing(std::string_view) {
  nlohmann::json j;
  j["users"] = nlohmann::json::array();
  return j;
}

// AppServiceHandler
AppServiceHandler::AppServiceHandler(storage::DatabasePool& db) : db_(db) {}
void AppServiceHandler::register_service(std::string_view as_id, std::string_view token) {
  db_.execute("INSERT OR REPLACE INTO appservice_txns (as_id,txn_id,sent_ts) VALUES ('" +
              std::string(as_id) + "','" + std::string(token) + "'," +
              std::to_string(util::now_ms()) + ")");
}
void AppServiceHandler::push_transaction(std::string_view, const nlohmann::json&) {}
nlohmann::json AppServiceHandler::get_service(std::string_view) {
  return {};
}

// NotifierHandler
NotifierHandler::NotifierHandler(storage::DatabasePool& db) : db_(db) {}
void NotifierHandler::notify_new_event(std::string_view event_id, std::string_view room_id) {
  auto members = db_.query("SELECT user_id FROM room_memberships WHERE room_id='" +
                           std::string(room_id) + "' AND membership='join'");
  for (auto& m : members) {
    std::string uid = m["user_id"].template get<std::string>();
    db_.execute(
        "INSERT OR IGNORE INTO event_push_actions "
        "(event_id,user_id,room_id,actions,stream_ordering) VALUES ('" +
        std::string(event_id) + "','" + uid + "','" + std::string(room_id) + "','[\"notify\"]'," +
        std::to_string(util::now_ms()) + ")");
  }
}
void NotifierHandler::notify_device_update(std::string_view) {}
void NotifierHandler::notify_presence_change(std::string_view, std::string_view) {}
void NotifierHandler::notify_receipt(std::string_view, std::string_view, std::string_view) {}
void NotifierHandler::notify_typing(std::string_view, std::string_view, bool) {}

}  // namespace progressive::handlers
