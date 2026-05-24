#pragma once
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "../storage/database.hpp"
#include "../util/random.hpp"

namespace progressive::handlers {

class FullAuthHandler {
public:
  explicit FullAuthHandler(storage::DatabasePool& db);

  // Missing auth methods from comparison
  nlohmann::json login_with_3pid(std::string_view medium, std::string_view address,
                                 std::string_view password);
  nlohmann::json request_email_token(std::string_view email, std::string_view client_secret);
  nlohmann::json request_msisdn_token(std::string_view phone, std::string_view client_secret);
  nlohmann::json validate_3pid_token(std::string_view sid, std::string_view token,
                                     std::string_view client_secret);
  bool start_ui_auth_session(std::string_view user_id, const nlohmann::json& flows);
  nlohmann::json check_ui_auth(std::string_view session_id, const nlohmann::json& auth);
  bool verify_recaptcha(std::string_view response, std::string_view secret);
  bool verify_email_token(std::string_view sid, std::string_view token);
  bool check_password_policy(std::string_view password);
  nlohmann::json get_login_flows();

private:
  storage::DatabasePool& db_;
  std::string gen_sid();
};

class FullE2eeHandler {
public:
  explicit FullE2eeHandler(storage::DatabasePool& db);

  // Real E2EE storage
  void store_device_keys(std::string_view user_id, std::string_view device_id,
                         const nlohmann::json& keys);
  nlohmann::json get_device_keys(std::string_view user_id);
  void store_one_time_keys(std::string_view user_id, std::string_view device_id,
                           const nlohmann::json& keys);
  nlohmann::json claim_one_time_keys(std::string_view user_id, std::string_view device_id,
                                     const std::vector<std::string>& algorithms);
  int count_one_time_keys(std::string_view user_id, std::string_view device_id);
  void store_cross_signing_keys(std::string_view user_id, const nlohmann::json& keys);
  nlohmann::json get_cross_signing_keys(std::string_view user_id);
  bool verify_cross_signing_signature(const nlohmann::json& key, const nlohmann::json& signature);

private:
  storage::DatabasePool& db_;
};

class FullFederationHandler {
public:
  explicit FullFederationHandler(storage::DatabasePool& db);

  // Real federation operations
  nlohmann::json backfill_events(std::string_view room_id, const nlohmann::json& event_ids,
                                 int limit = 50);
  nlohmann::json query_profile(std::string_view user_id, std::string_view field = "");
  nlohmann::json query_directory(std::string_view room_alias);
  nlohmann::json get_user_devices(std::string_view user_id);
  nlohmann::json query_client_keys(const nlohmann::json& query);
  nlohmann::json claim_client_keys(const nlohmann::json& query);
  nlohmann::json get_room_hierarchy(std::string_view room_id, bool suggested_only = false);
  nlohmann::json get_room_complexity(std::string_view room_id);

private:
  storage::DatabasePool& db_;
};

class SpamChecker {
public:
  explicit SpamChecker(storage::DatabasePool& db);

  bool check_event_for_spam(std::string_view sender, std::string_view room_id,
                            const nlohmann::json& content);
  bool check_username_for_spam(std::string_view username);
  bool check_media_for_spam(std::string_view media_id, std::string_view user_id);
  bool user_may_join_room(std::string_view user_id, std::string_view room_id);
  bool user_may_create_room(std::string_view user_id);
  bool user_may_invite(std::string_view inviter, std::string_view invitee,
                       std::string_view room_id);

private:
  storage::DatabasePool& db_;
};

}  // namespace progressive::handlers
