#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

#include "../storage/database.hpp"
#include "../util/time.hpp"

namespace progressive::handlers {

class DirectoryHandler {
public:
  explicit DirectoryHandler(storage::DatabasePool& db);
  nlohmann::json lookup_alias(std::string_view alias);
  void create_alias(std::string_view alias, std::string_view room_id, std::string_view creator);
  void delete_alias(std::string_view alias);
  nlohmann::json list_room_aliases(std::string_view room_id);

private:
  storage::DatabasePool& db_;
};

class ProfileHandler {
public:
  explicit ProfileHandler(storage::DatabasePool& db);
  nlohmann::json get_profile(std::string_view user_id);
  void set_displayname(std::string_view user_id, std::string_view name);
  void set_avatar(std::string_view user_id, std::string_view url);
  void delete_displayname(std::string_view user_id);
  void delete_avatar(std::string_view user_id);

private:
  storage::DatabasePool& db_;
};

class FilterHandler {
public:
  explicit FilterHandler(storage::DatabasePool& db);
  std::string create_filter(std::string_view user_id, const nlohmann::json& def);
  nlohmann::json get_filter(std::string_view user_id, std::string_view filter_id);

private:
  storage::DatabasePool& db_;
};

class AccountHandler {
public:
  explicit AccountHandler(storage::DatabasePool& db);
  void change_password(std::string_view user_id, std::string_view new_pw);
  void deactivate_account(std::string_view user_id);
  nlohmann::json get_threepids(std::string_view user_id);
  void add_threepid(std::string_view user_id, std::string_view medium, std::string_view address);
  void bind_threepid(std::string_view user_id, std::string_view medium, std::string_view address);
  void unbind_threepid(std::string_view user_id, std::string_view medium, std::string_view address);
  void delete_threepid(std::string_view user_id, std::string_view medium, std::string_view address);

private:
  storage::DatabasePool& db_;
};

class PushRulesHandler {
public:
  explicit PushRulesHandler(storage::DatabasePool& db);
  nlohmann::json get_push_rules(std::string_view user_id);
  void add_push_rule(std::string_view user_id, std::string_view scope, std::string_view kind,
                     std::string_view rule_id, const nlohmann::json& rule);
  void delete_push_rule(std::string_view user_id, std::string_view scope, std::string_view kind,
                        std::string_view rule_id);
  void set_enabled(std::string_view user_id, std::string_view scope, std::string_view kind,
                   std::string_view rule_id, bool enabled);
  void set_actions(std::string_view user_id, std::string_view scope, std::string_view kind,
                   std::string_view rule_id, const nlohmann::json& actions);

private:
  storage::DatabasePool& db_;
};

class ReceiptsHandler {
public:
  explicit ReceiptsHandler(storage::DatabasePool& db);
  void send_receipt(std::string_view user_id, std::string_view room_id, std::string_view event_id,
                    std::string_view receipt_type);
  void send_read_marker(std::string_view user_id, std::string_view room_id,
                        std::string_view event_id);
  nlohmann::json get_receipts(std::string_view room_id);

private:
  storage::DatabasePool& db_;
};

class TypingHandler {
public:
  explicit TypingHandler(storage::DatabasePool& db);
  void send_typing(std::string_view user_id, std::string_view room_id, bool typing,
                   int timeout_ms = 30000);
  nlohmann::json get_typing(std::string_view room_id);

private:
  storage::DatabasePool& db_;
};

class AppServiceHandler {
public:
  explicit AppServiceHandler(storage::DatabasePool& db);
  void register_service(std::string_view as_id, std::string_view token);
  void push_transaction(std::string_view as_id, const nlohmann::json& events);
  nlohmann::json get_service(std::string_view as_id);

private:
  storage::DatabasePool& db_;
};

class NotifierHandler {
public:
  explicit NotifierHandler(storage::DatabasePool& db);
  void notify_new_event(std::string_view event_id, std::string_view room_id);
  void notify_device_update(std::string_view user_id);
  void notify_presence_change(std::string_view user_id, std::string_view state);
  void notify_receipt(std::string_view room_id, std::string_view user_id,
                      std::string_view event_id);
  void notify_typing(std::string_view room_id, std::string_view user_id, bool typing);

private:
  storage::DatabasePool& db_;
};

}  // namespace progressive::handlers
