#pragma once
// handlers_misc.hpp - remaining handler files: pagination, room_list, profile, identity,
// search, typing, directory, admin, initial_sync, relations, delayed_events, receipts,
// e2e_room_keys, devicemessage, event_auth, deactivate_account, account_validity,
// account_data, stats, room_policy, send_email, events, thread_subscriptions,
// read_marker, password_policy, worker_lock, room_member_worker
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"

namespace progressive::handlers {
using json = nlohmann::json;
using namespace storage;

class PaginationHandler { public:
  explicit PaginationHandler(DatabasePool& db);
  json get_messages(const std::string& user_id, const std::string& room_id,
    const std::string& from, const std::string& dir, int limit, const std::string& filter);
  json get_room_events(const std::string& room_id, int64_t from_token, int64_t to_token, int limit);
  std::string get_pagination_token(int64_t stream_ordering);
private: DatabasePool& db_; };

class RoomListHandler { public:
  explicit RoomListHandler(DatabasePool& db);
  json get_public_rooms(const std::string& server, int limit, const std::string& since,
    const std::string& search_term, bool include_all, const std::string& network);
  json get_remote_public_rooms(const std::string& server, int limit, const std::string& since);
private: DatabasePool& db_; };

class ProfileHandler { public:
  explicit ProfileHandler(DatabasePool& db);
  json get_profile(const std::string& user_id);
  void set_display_name(const std::string& user_id, const std::string& requester, const std::string& name);
  void set_avatar_url(const std::string& user_id, const std::string& requester, const std::string& url);
private: DatabasePool& db_; };

class IdentityHandler { public:
  explicit IdentityHandler(DatabasePool& db);
  json lookup_3pid(const std::string& medium, const std::string& address);
  json invite_by_3pid(const std::string& room_id, const std::string& medium,
    const std::string& address, const std::string& sender);
  json bind_3pid(const std::string& sid, const std::string& client_secret, const std::string& mxid);
  json request_3pid_token(const std::string& medium, const std::string& address,
    const std::string& client_secret, int send_attempt);
private: DatabasePool& db_; };

class SearchHandler { public:
  explicit SearchHandler(DatabasePool& db);
  json search(const std::string& user_id, const json& search_categories, const std::string& order_by,
    const std::string& group_by, bool include_profile);
  json search_room_events(const std::string& room_id, const std::string& search_term,
    const std::string& keys, const std::string& order_by, int limit, const std::string& filter,
    bool include_profile);
private: DatabasePool& db_; };

class TypingHandler { public:
  explicit TypingHandler(DatabasePool& db);
  void set_typing(const std::string& user_id, const std::string& room_id, bool typing, int timeout_ms);
  json get_typing_users(const std::string& room_id);
  void handle_timeout(); void process_federation_typing(const std::string& origin,
    const std::string& room_id, const std::string& user_id, bool typing);
private: DatabasePool& db_;
  std::map<std::string,std::map<std::string,int64_t>> typing_users_;
  int64_t default_timeout_ms_{30000}; };

class DirectoryHandler { public:
  explicit DirectoryHandler(DatabasePool& db);
  json create_association(const std::string& user_id, const std::string& room_alias,
    const std::string& room_id, const std::vector<std::string>& servers);
  json delete_association(const std::string& user_id, const std::string& room_alias);
  json get_association(const std::string& room_alias);
private: DatabasePool& db_; };

class AdminHandler { public:
  explicit AdminHandler(DatabasePool& db);
  json get_users(int64_t from, int64_t limit, const std::string& name, bool guests, bool deactivated);
  json get_user(const std::string& user_id);
  json create_user(const std::string& user_id, const std::string& password, bool admin);
  json deactivate_user(const std::string& user_id, bool erase);
  json set_user_admin(const std::string& user_id, bool admin);
  json reset_password(const std::string& user_id, const std::string& new_password);
  json get_rooms(int64_t from, int64_t limit, const std::string& order_by, const std::string& dir, const std::string& search_term);
  json get_room(const std::string& room_id);
  json delete_room(const std::string& room_id, bool block, bool purge, bool force_purge);
  json get_room_members(const std::string& room_id);
  json get_media(const std::string& room_id);
  json quarantine_media(const std::string& room_id, bool quarantine);
  json get_statistics();
  json get_federation_destinations(); json get_federation_destination(const std::string& dest);
  void update_room_visibility(const std::string& room_id, const std::string& visibility);
private: DatabasePool& db_; };

class InitialSyncHandler { public:
  explicit InitialSyncHandler(DatabasePool& db);
  json initial_sync(const std::string& user_id, int limit, const std::string& device_id);
private: DatabasePool& db_; };

class RelationsHandler { public:
  explicit RelationsHandler(DatabasePool& db);
  json get_relations(const std::string& room_id, const std::string& event_id,
    const std::optional<std::string>& relation_type, const std::optional<std::string>& event_type,
    const std::string& from, const std::string& dir, int limit);
  json get_aggregations(const std::string& room_id, const std::string& event_id,
    const std::string& relation_type, const std::string& event_type);
private: DatabasePool& db_; };

class DelayedEventsHandler { public:
  explicit DelayedEventsHandler(DatabasePool& db);
  void send_delayed_events(); void process_delayed_events();
private: DatabasePool& db_; };

class ReceiptsHandler { public:
  explicit ReceiptsHandler(DatabasePool& db);
  void received_client_receipt(const std::string& room_id, const std::string& receipt_type,
    const std::string& user_id, const std::string& event_id);
  json get_receipts(const std::string& room_id, const std::string& event_id);
  void process_federation_receipts(const std::string& room_id, const std::string& receipt_type,
    const std::string& user_id, const std::string& event_id);
private: DatabasePool& db_; };

class E2eRoomKeysHandler { public:
  explicit E2eRoomKeysHandler(DatabasePool& db);
  json upload_room_keys(const std::string& user_id, const std::string& version, const json& room_keys);
  json get_room_keys(const std::string& user_id, const std::string& version, const std::optional<std::string>& room_id);
  json delete_room_keys(const std::string& user_id, const std::string& version);
  json get_room_key_versions(const std::string& user_id);
  json upload_room_key_version(const std::string& user_id, const std::string& version, const json& version_data);
private: DatabasePool& db_; };

class DeviceMessageHandler { public:
  explicit DeviceMessageHandler(DatabasePool& db);
  void send_device_message(const std::string& sender, const std::string& device_id,
    const std::string& message_type, const json& content);
  void send_device_messages(const std::string& sender, const std::string& message_type,
    const std::map<std::string,std::map<std::string,json>>& messages);
private: DatabasePool& db_; };

class EventAuthHandler { public:
  explicit EventAuthHandler(DatabasePool& db);
  json compute_event_auth(const json& event, const json& auth_events, const std::string& room_version);
  json get_auth_chain(const std::string& room_id, const std::vector<std::string>& event_ids);
  bool verify_event(const json& event, const json& auth_events, const std::string& room_version);
private: DatabasePool& db_; };

class DeactivateAccountHandler { public:
  explicit DeactivateAccountHandler(DatabasePool& db);
  json deactivate_account(const std::string& user_id, bool erase, const std::string& requester);
  void part_user_from_all_rooms(const std::string& user_id);
private: DatabasePool& db_; };

class AccountValidityHandler { public:
  explicit AccountValidityHandler(DatabasePool& db);
  bool is_account_valid(const std::string& user_id);
  void set_account_validity(const std::string& user_id, int64_t expiration_ts);
  void renew_account(const std::string& renewal_token);
  void send_renewal_emails();
private: DatabasePool& db_; };

class AccountDataHandler { public:
  explicit AccountDataHandler(DatabasePool& db);
  json get_account_data(const std::string& user_id, const std::string& type);
  json get_room_account_data(const std::string& user_id, const std::string& room_id, const std::string& type);
  void set_account_data(const std::string& user_id, const std::string& type, const json& content);
  void set_room_account_data(const std::string& user_id, const std::string& room_id, const std::string& type, const json& content);
private: DatabasePool& db_; };

class StatsHandler { public:
  explicit StatsHandler(DatabasePool& db);
  json get_room_stats(const std::string& room_id);
  json get_user_stats(const std::string& user_id);
  json get_server_stats();
private: DatabasePool& db_; };

class RoomPolicyHandler { public:
  explicit RoomPolicyHandler(DatabasePool& db);
  void handle_policy_room(const std::string& room_id);
  bool check_event_against_policies(const std::string& room_id, const json& event);
  std::vector<std::string> get_rooms_affected_by_policy(const std::string& policy_event_id);
private: DatabasePool& db_; };

class SendEmailHandler { public:
  explicit SendEmailHandler(DatabasePool& db);
  void send_email(const std::string& recipient, const std::string& subject, const std::string& body);
  void send_password_reset_email(const std::string& user_id, const std::string& email, const std::string& token);
  void send_registration_email(const std::string& email, const std::string& token, const std::string& client_secret);
  void send_threepid_validation_email(const std::string& email, const std::string& token, const std::string& client_secret);
  void send_add_threepid_email(const std::string& email, const std::string& token, const std::string& client_secret);
  void send_notification_email(const std::string& user_id, const std::string& email, const std::string& room_name, const std::string& sender, const std::string& body);
private: DatabasePool& db_; };

class EventsHandler { public:
  explicit EventsHandler(DatabasePool& db);
  json get_events(const std::string& user_id, const std::string& from, int timeout, int limit);
  json get_event(const std::string& user_id, const std::string& event_id);
private: DatabasePool& db_; };

class ThreadSubscriptionsHandler { public:
  explicit ThreadSubscriptionsHandler(DatabasePool& db);
  void subscribe(const std::string& user_id, const std::string& room_id, const std::string& thread_id);
  void unsubscribe(const std::string& user_id, const std::string& room_id, const std::string& thread_id);
  json get_subscriptions(const std::string& user_id, const std::string& room_id);
private: DatabasePool& db_; };

class ReadMarkerHandler { public:
  explicit ReadMarkerHandler(DatabasePool& db);
  void set_read_marker(const std::string& user_id, const std::string& room_id,
    const std::string& event_id, const std::string& receipt_type);
  json get_read_markers(const std::string& user_id, const std::string& room_id);
private: DatabasePool& db_; };

class PasswordPolicyHandler { public:
  explicit PasswordPolicyHandler(DatabasePool& db);
  bool is_password_valid(const std::string& password);
  json get_password_policy();
private: DatabasePool& db_; };

class WorkerLockHandler { public:
  explicit WorkerLockHandler(DatabasePool& db);
  bool acquire_lock(const std::string& lock_name, const std::string& instance_name, int64_t timeout_ms);
  void release_lock(const std::string& lock_name, const std::string& instance_name);
  bool is_locked(const std::string& lock_name);
private: DatabasePool& db_; };

class RoomMemberWorkerHandler { public:
  explicit RoomMemberWorkerHandler(DatabasePool& db);
  json get_room_members(const std::string& room_id);
  json get_joined_members(const std::string& room_id);
  json get_member(const std::string& room_id, const std::string& user_id);
private: DatabasePool& db_; };

} // namespace
