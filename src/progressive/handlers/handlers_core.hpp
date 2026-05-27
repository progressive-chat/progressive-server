#pragma once
// handlers_core.hpp - Core handler classes: sync, room, message, room_member, auth, federation_event, federation
// Translates synapse/handlers/{sync,room,message,room_member,auth,federation_event,federation}.py
// Original: 21,797 lines of Python combined

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/events.hpp"
#include "progressive/storage/databases/main/room.hpp"
#include "progressive/storage/databases/main/roommember.hpp"
#include "progressive/storage/databases/main/registration.hpp"
#include "progressive/storage/databases/main/event_push_actions.hpp"
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/state.hpp"

namespace progressive::handlers {

using json = nlohmann::json;
using namespace storage;

// ============================================================================
// SyncHandler - handles /sync requests
// Equivalent to synapse/handlers/sync.py (3,249 lines)
// ============================================================================
class SyncHandler {
public:
  SyncHandler(DatabasePool& db);

  struct SyncConfig {
    std::string user_id; std::string since; int64_t timeout_ms{0};
    bool full_state{false}; std::string filter_id; std::string device_id;
  };

  struct SyncResult {
    std::string next_batch;
    json rooms; json presence; json account_data;
    json to_device; json device_lists; json device_one_time_keys_count;
    json device_unused_fallback_key_types;
  };

  // Main sync operation
  SyncResult sync(const SyncConfig& config);

  // Generate sync response for user
  SyncResult generate_sync_response(const std::string& user_id,
      const std::string& since_token, int64_t timeout_ms, bool full_state);

  // ---- Room sync helpers ----
  json generate_room_entry(const std::string& room_id, const std::string& user_id,
      int64_t since_stream_ordering, bool full_state, int64_t now_token);
  json get_room_state_for_sync(const std::string& room_id, const std::string& user_id,
      int64_t since_stream_ordering);
  json get_timeline_events(const std::string& room_id, int64_t from_token,
      int64_t to_token, int limit = 20);
  json get_ephemeral_events(const std::string& room_id, int64_t from_token);
  json get_account_data_for_room(const std::string& user_id,
      const std::string& room_id);

  // ---- Stream token management ----
  std::string get_stream_token();
  int64_t parse_stream_token(const std::string& token);
  int64_t get_max_stream_ordering();

  // ---- Presence sync ----
  json get_presence_sync(const std::string& user_id, int64_t since_ts);

  // ---- To-device messages ----
  json get_to_device_messages(const std::string& user_id, int64_t since_token);

  // ---- Device list changes ----
  struct DeviceListChanges { std::vector<std::string> changed; std::vector<std::string> left; };
  DeviceListChanges get_device_list_changes(const std::string& user_id,
      int64_t since_token);

private:
  DatabasePool& db_;
  EventsStore events_;
  RoomStore rooms_;
  RoomMemberStore members_;
  StateStore state_;
};

// ============================================================================
// RoomCreationHandler - handles room creation and configuration
// Equivalent to synapse/handlers/room.py (2,485 lines)
// ============================================================================
class RoomCreationHandler {
public:
  RoomCreationHandler(DatabasePool& db);

  struct RoomConfig {
    std::string creator; std::string room_version{"1"};
    std::optional<std::string> name; std::optional<std::string> topic;
    std::optional<std::string> room_alias_name; bool is_public{false};
    std::string visibility{"private"}; std::vector<std::string> invite_list;
    std::optional<std::string> preset; std::optional<bool> is_direct;
    std::optional<std::string> power_level_content_override;
    std::optional<json> initial_state; std::optional<json> creation_content;
  };

  struct CreateRoomResult {
    std::string room_id; std::string room_alias;
  };

  // Create a new room
  CreateRoomResult create_room(const Requester& requester, const RoomConfig& config);

  // Clone an existing room (room upgrade)
  CreateRoomResult clone_room(const std::string& existing_room_id,
      const std::string& new_room_id, const Requester& requester);

  // Upgrade a room to a new version
  std::string upgrade_room(const std::string& room_id,
      const std::string& new_version, const Requester& requester);

private:
  // Send initial state events
  void send_initial_state_events(const std::string& room_id,
      const std::string& creator, const RoomConfig& config,
      int64_t stream_ordering);

  // Generate room ID
  std::string generate_room_id();

  // Handle preset configurations
  void handle_preset(const std::string& room_id, const std::string& preset,
      const std::string& creator, int64_t stream_ordering);

  // Send room creation event
  std::string send_room_create_event(const std::string& room_id,
      const std::string& creator, const std::string& version,
      const json& creation_content, int64_t stream_ordering);

  DatabasePool& db_;
};

// ============================================================================
// MessageHandler - handles message sending, editing, redaction
// Equivalent to synapse/handlers/message.py (2,435 lines)
// ============================================================================
class MessageHandler {
public:
  MessageHandler(DatabasePool& db);

  // Send a message event
  struct SendResult {
    std::string event_id; int64_t stream_ordering;
  };
  SendResult send_message(const std::string& room_id, const std::string& user_id,
      const std::string& event_type, const json& content,
      const std::optional<std::string>& txn_id = std::nullopt);

  // Redact an event
  SendResult redact_event(const std::string& room_id, const std::string& user_id,
      const std::string& event_id, const std::optional<std::string>& reason,
      const std::optional<std::string>& txn_id = std::nullopt);

  // Update a message (edit)
  SendResult update_message(const std::string& room_id, const std::string& user_id,
      const std::string& original_event_id, const json& new_content);

  // Send a reaction
  SendResult send_reaction(const std::string& room_id, const std::string& user_id,
      const std::string& event_id, const std::string& key);

  // Check if user can send message in room
  bool can_send_message(const std::string& room_id, const std::string& user_id,
      bool is_guest);

  // Check rate limiting
  bool check_rate_limit(const std::string& user_id, const std::string& room_id);

  // Get rate limit config
  struct RatelimitConfig {
    int64_t messages_per_second{0}; int64_t burst_count{0};
  };
  RatelimitConfig get_rate_limit_config();

  // Handle event deduplication
  bool is_event_duplicate(const std::string& room_id,
      const std::string& txn_id);

  // Process event content (strip, validate, add metadata)
  json process_event_content(const std::string& event_type,
      const json& content, const std::string& room_id);

private:
  // Build and persist the event
  EventData build_event(const std::string& room_id, const std::string& user_id,
      const std::string& event_type, const json& content, int64_t stream_ordering);

  // Handle notifications for new messages
  void notify_for_event(const EventData& event, int64_t stream_ordering);

  // Mark device as having sent a message
  void mark_device_for_event(const std::string& user_id,
      const std::string& device_id, int64_t stream_ordering);

  // Generate push actions
  void generate_push_actions(const EventData& event);

  DatabasePool& db_;
};

// ============================================================================
// RoomMemberHandler - handles joins, leaves, invites, kicks, bans
// Equivalent to synapse/handlers/room_member.py (2,427 lines)
// ============================================================================
class RoomMemberHandler {
public:
  RoomMemberHandler(DatabasePool& db);

  // Update membership
  struct MembershipResult {
    std::string event_id; std::string room_id; int64_t stream_ordering;
  };
  MembershipResult update_membership(
      const Requester& requester, const std::string& target_user_id,
      const std::string& room_id, const std::string& action,
      const std::optional<std::string>& reason = std::nullopt,
      const std::optional<std::string>& third_party_signed = std::nullopt);

  // Join room
  MembershipResult join_room(const Requester& requester,
      const std::string& room_id_or_alias,
      const std::vector<std::string>& server_names = {});

  // Leave room
  MembershipResult leave_room(const std::string& user_id,
      const std::string& room_id);

  // Invite user
  MembershipResult invite_user(const Requester& requester,
      const std::string& target_user_id, const std::string& room_id);

  // Kick user
  MembershipResult kick_user(const Requester& requester,
      const std::string& target_user_id, const std::string& room_id,
      const std::optional<std::string>& reason);

  // Ban user
  MembershipResult ban_user(const Requester& requester,
      const std::string& target_user_id, const std::string& room_id,
      const std::optional<std::string>& reason);

  // Unban user
  MembershipResult unban_user(const Requester& requester,
      const std::string& target_user_id, const std::string& room_id);

  // Knock on room
  MembershipResult knock_room(const Requester& requester,
      const std::string& room_id_or_alias,
      const std::vector<std::string>& server_names = {});

  // Accept/deny knock
  MembershipResult answer_knock(const Requester& requester,
      const std::string& room_id, const std::string& target_user_id,
      bool accept);

  // Check if user can join room
  bool can_join_room(const std::string& user_id, const std::string& room_id,
      bool is_guest);

  // Get user's current membership
  std::optional<std::string> get_current_membership(
      const std::string& room_id, const std::string& user_id);

  // Look up room alias
  std::optional<std::string> lookup_room_alias(const std::string& alias);

  // Handle third party invites
  void send_third_party_invite(const std::string& room_id,
      const std::string& inviter, const json& invite);

  // Handle invite via email/3pid
  MembershipResult invite_by_third_party_id(const Requester& requester,
      const std::string& room_id, const std::string& medium,
      const std::string& address);

  // Transfer room state on invite
  void transfer_room_state_on_invite(const std::string& room_id,
      const std::string& target_user_id);

  // Reject invite seen in sync
  void handle_rejected_invite(const std::string& user_id,
      const std::string& room_id);

private:
  // Validate membership transition
  bool validate_membership_transition(const std::string& old_membership,
      const std::string& new_membership, bool is_user_admin);

  // Check power levels for membership change
  bool check_power_levels_for_membership(const std::string& room_id,
      const std::string& actor_user_id, const std::string& target_user_id,
      const std::string& new_membership);

  // Send membership event
  std::string send_membership_event(const std::string& room_id,
      const std::string& user_id, const std::string& target_user_id,
      const std::string& membership, const std::string& event_type,
      const json& content, int64_t stream_ordering);

  DatabasePool& db_;
};

// ============================================================================
// AuthHandler - handles user authentication
// Equivalent to synapse/handlers/auth.py (2,497 lines)
// ============================================================================
class AuthHandler {
public:
  AuthHandler(DatabasePool& db);

  // Validate login
  struct LoginResult {
    std::string user_id; std::string access_token; std::string device_id;
    std::optional<std::string> refresh_token; int64_t expires_in_ms{0};
    std::optional<std::string> session_id;
  };
  LoginResult validate_login(const std::string& user_id,
      const json& login_submission);

  // Complete UIA stage
  struct UIAStageResult {
    bool completed{false}; json params; std::string session_id;
    std::vector<json> flows; json completed_stages;
  };
  UIAStageResult complete_ui_auth_stage(const std::string& user_id,
      const std::string& session_id, const json& auth_params);

  // Get available login flows
  std::vector<json> get_login_flows();

  // Get available registration flows
  std::vector<json> get_registration_flows();

  // Record successful login
  void record_successful_login(const std::string& user_id,
      const std::string& device_id, const std::string& client_ip);

  // Register a new device
  std::string register_device(const std::string& user_id,
      const std::string& device_id, const std::optional<std::string>& display_name);

  // Create access token
  std::string create_access_token(const std::string& user_id,
      const std::string& device_id);

  // Create refresh token
  std::string create_refresh_token(const std::string& user_id,
      const std::string& device_id, const std::string& access_token);

  // Generate session ID
  std::string generate_session_id();

  // Check if the account is deactivated
  bool is_account_deactivated(const std::string& user_id);

  // Handle password authentication
  bool validate_password(const std::string& user_id,
      const std::string& password);

  // Handle token-based authentication
  bool validate_token_auth(const std::string& user_id,
      const std::string& login_token);

  // SSO user mapping
  struct SSOUserMapping {
    std::string user_id; std::string display_name;
    std::map<std::string, std::string> attributes;
  };
  std::optional<SSOUserMapping> get_sso_user_mapping(
      const std::string& auth_provider, const std::string& remote_user_id);

  // Create account from SSO
  std::string create_account_from_sso(const SSOUserMapping& mapping,
      const std::string& auth_provider);

private:
  DatabasePool& db_;
};

// ============================================================================
// FederationEventHandler - processes incoming federation events
// Equivalent to synapse/handlers/federation_event.py (2,430 lines)
// ============================================================================
class FederationEventHandler {
public:
  FederationEventHandler(DatabasePool& db);

  // Process a federation event (PDU)
  struct ProcessResult {
    std::string event_id; int64_t stream_ordering;
    bool backfilled{false}; bool is_new{true};
  };
  ProcessResult process_federation_event(const std::string& origin,
      const json& event, const std::optional<std::string>& room_version = std::nullopt);

  // Backfill events
  struct BackfillResult {
    std::vector<json> events; std::string origin;
    bool backwards_extremity_more{false};
  };
  BackfillResult backfill(const std::string& origin,
      const std::string& room_id, int limit,
      const std::vector<std::string>& extremities);

  // Process state in a room
  void process_state_events(const std::string& room_id,
      const std::string& origin, const std::vector<json>& state_events,
      bool backfilled);

  // Handle auth events
  void handle_auth_events(const std::vector<json>& auth_events,
      const std::string& room_id, const std::string& origin);

  // Precompute event auth
  json precompute_event_auth(const json& event, const json& auth_events,
      const std::string& room_version);

  // Get missing auth events
  std::vector<std::string> get_missing_auth_events(
      const std::vector<std::string>& auth_event_ids);

  // Handle rejected events
  void on_reject_federation_event(const std::string& event_id,
      const std::string& reason);

  // Pull event from remote
  std::optional<json> pull_event(const std::string& origin,
      const std::string& event_id);

  // Check event hash
  bool check_event_hash(const json& event);

  // Verify event signatures
  bool verify_event_signatures(const json& event);

  // Check room state resolution
  std::map<std::pair<std::string,std::string>, std::string>
  resolve_state_conflicts(const std::string& room_id,
      const std::vector<std::map<std::pair<std::string,std::string>, std::string>>& states);

private:
  DatabasePool& db_;
};

// ============================================================================
// FederationHandler - manages federation with other servers
// Equivalent to synapse/handlers/federation.py (2,071 lines)
// ============================================================================
class FederationHandler {
public:
  FederationHandler(DatabasePool& db);

  // Handle incoming federation transaction
  json handle_transaction(const std::string& origin,
      const std::string& transaction_id, const json& transaction_data);

  // Send federation transaction
  json send_transaction(const std::string& destination,
      const json& transaction_data);

  // Query remote server for room state
  json query_room_state(const std::string& destination,
      const std::string& room_id, const std::string& event_id);

  // Query remote server for room members
  json query_room_members(const std::string& destination,
      const std::string& room_id);

  // Query remote server for room events
  json query_room_events(const std::string& destination,
      const std::string& room_id, int64_t depth);

  // Make join request
  json make_join(const std::string& destination,
      const std::string& room_id, const std::string& user_id);

  // Send join
  json send_join(const std::string& destination,
      const std::string& room_id, const std::string& event_id);

  // Make leave request  
  json make_leave(const std::string& destination,
      const std::string& room_id, const std::string& user_id);

  // Send leave
  json send_leave(const std::string& destination,
      const std::string& room_id, const std::string& event_id);

  // Make invite
  json make_invite(const std::string& destination,
      const std::string& room_id, const std::string& event_id);

  // Send invite
  json send_invite(const std::string& destination,
      const std::string& room_id, const std::string& event_id,
      const json& invite_room_state);

  // Get missing events from remote
  std::vector<json> get_missing_events(const std::string& destination,
      const std::string& room_id, const std::vector<std::string>& missing_event_ids,
      const std::vector<std::string>& earliest_events,
      const std::vector<std::string>& latest_events);

  // Exchange third party invite
  json exchange_third_party_invite(const std::string& destination,
      const std::string& room_id, const json& event);

  // Get event from remote
  std::optional<json> get_event(const std::string& destination,
      const std::string& event_id);

  // Query profile from remote
  json query_profile(const std::string& destination,
      const std::string& user_id);

  // Query keys from remote
  json query_keys(const std::string& destination,
      const json& query_content);

  // Claim one-time keys from remote
  json claim_keys(const std::string& destination,
      const json& claim_content);

  // Notify remote about device list update
  void notify_device_update(const std::string& destination,
      const std::string& user_id, const std::vector<std::string>& device_ids);

  // Send EDU to remote
  void send_edu(const std::string& destination,
      const std::string& edu_type, const json& content);

  // Get server keys
  json get_server_keys(const std::string& server_name,
      const std::set<std::string>& key_ids = {});

private:
  DatabasePool& db_;
};

} // namespace progressive::handlers
