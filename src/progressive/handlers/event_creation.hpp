#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "../push/evaluator.hpp"
#include "../storage/database.hpp"

namespace progressive::handlers {

class EventCreationHandler {
public:
  explicit EventCreationHandler(storage::DatabasePool& db);

  // Line-by-line from synapse/handlers/message.py
  std::string create_new_client_event(std::string_view room_id, std::string_view event_type,
                                      std::string_view sender, const nlohmann::json& content,
                                      std::optional<std::string> txn_id = {});

  bool validate_event_relation(const nlohmann::json& content, std::string_view room_id);
  bool deduplicate_state_event(std::string_view room_id, std::string_view event_type,
                               std::string_view state_key, std::string_view content_hash);
  void persist_and_notify_client_events(const std::string& event_id, std::string_view room_id,
                                        std::string_view sender);

  bool is_admin_redaction(std::string_view event_id, std::string_view sender);
  std::string create_and_send_nonmember_event(std::string_view room_id, std::string_view event_type,
                                              std::string_view sender,
                                              const nlohmann::json& content,
                                              std::string_view txn_id);
  std::string handle_new_client_event(std::string_view event_id, std::string_view room_id,
                                      std::string_view sender, const nlohmann::json& content);
  std::string get_event_from_transaction(std::string_view room_id, std::string_view user_id,
                                         std::string_view txn_id);
  void create_event(std::string_view room_id, std::string_view event_type, std::string_view sender,
                    const nlohmann::json& content, std::string_view txn_id);
  void maybe_kick_guest_users(std::string_view room_id, std::string_view event_type);
  void bump_active_time(std::string_view sender);
  void maybe_schedule_expiry(const nlohmann::json& content);
  void create_and_send_new_client_events(
      const std::string& room_id, const std::vector<std::pair<std::string, nlohmann::json>>& events,
      std::string_view sender);
  void cache_joined_hosts_for_events(const std::vector<std::string>& event_ids);
  void validate_canonical_alias(std::string_view room_id, std::string_view alias);
  void send_dummy_events_to_fill_extremities();
  void send_dummy_event_for_room(std::string_view room_id);
  void rebuild_event_after_third_party_rules(nlohmann::json& content);

private:
  storage::DatabasePool& db_;
  push::PushRuleEvaluator push_eval_;
  std::string gen_event_id(std::string_view origin);
};

}  // namespace progressive::handlers
