#pragma once
#include <map>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "../storage/database.hpp"
#include "../util/cache.hpp"
#include "../util/time.hpp"

namespace progressive::handlers {

class SyncHandler {
public:
  SyncHandler(storage::DatabasePool& db);

  // Full synapse/handlers/sync.py line-by-line port
  nlohmann::json generate_sync_response(std::string_view user_id, std::string_view since_token,
                                        int timeout_ms = 0, std::string_view filter = "");

  void compute_state_delta(std::string_view room_id, const nlohmann::json& timeline_events,
                           std::string_view since_token, nlohmann::json& state_events,
                           nlohmann::json& timeline_output);

  nlohmann::json load_filtered_recents(std::string_view room_id, std::string_view user_id,
                                       int limit = 20);

  void handle_to_device(std::string_view user_id, nlohmann::json& response);
  void handle_presence(std::string_view user_id, nlohmann::json& response);
  void handle_device_lists(std::string_view user_id, nlohmann::json& response);
  void handle_account_data(std::string_view user_id, nlohmann::json& response);
  void handle_notifications(std::string_view user_id, nlohmann::json& response);
  void handle_ephemeral(std::string_view room_id, nlohmann::json& response);
  void compute_room_summary(std::string_view room_id, nlohmann::json& response);

private:
  storage::DatabasePool& db_;
  util::LruCache<nlohmann::json> response_cache_{100, 30};
  std::string make_sync_token(uint64_t stream_pos);

  // Lazy member tracking
  std::map<std::string, std::set<std::string>, std::less<>> sent_members_;
  bool has_sent_member(std::string_view user_id, std::string_view member);
  void mark_member_sent(std::string_view user_id, std::string_view member);
};

class FederationEventHandler {
public:
  explicit FederationEventHandler(storage::DatabasePool& db);

  // synapse/handlers/federation_event.py line-by-line port
  bool process_received_pdu(const nlohmann::json& pdu);
  bool validate_pdu_signature(const nlohmann::json& pdu);
  bool check_event_auth(const nlohmann::json& pdu, const nlohmann::json& auth_events);
  void handle_soft_fail(const std::string& event_id, const std::string& reason);
  void update_extremities(const std::string& room_id, const std::string& event_id);
  void process_backfill(std::string_view room_id, const nlohmann::json& events);

private:
  storage::DatabasePool& db_;
};

class RoomMemberHandler {
public:
  RoomMemberHandler(storage::DatabasePool& db);

  // Full synapse/handlers/room_member.py port
  bool validate_membership_transition(std::string_view room_id, std::string_view sender,
                                      std::string_view target, std::string_view old_membership,
                                      std::string_view new_membership);

  void handle_join(std::string_view room_id, std::string_view user_id, std::string_view sender);
  void handle_leave(std::string_view room_id, std::string_view user_id, std::string_view sender);
  void handle_invite(std::string_view room_id, std::string_view sender, std::string_view target,
                     std::string_view reason = "");
  void handle_ban(std::string_view room_id, std::string_view sender, std::string_view target,
                  std::string_view reason = "");
  void handle_kick(std::string_view room_id, std::string_view sender, std::string_view target,
                   std::string_view reason = "");
  void handle_unban(std::string_view room_id, std::string_view target);
  void handle_knock(std::string_view room_id, std::string_view user_id,
                    std::string_view reason = "");

  int get_power_level(std::string_view room_id, std::string_view user_id);
  void check_join_rules(std::string_view room_id, std::string_view user_id);

private:
  storage::DatabasePool& db_;
  bool is_user_in_room(std::string_view room_id, std::string_view user_id);
  std::string get_membership(std::string_view room_id, std::string_view user_id);
};

}  // namespace progressive::handlers
