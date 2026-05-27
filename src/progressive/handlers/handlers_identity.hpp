#pragma once
// handlers_identity.hpp - presence, device, e2e_keys, oidc, register handlers
// Translates 11,270 lines of Python combined

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
#include "progressive/storage/databases/main/presence.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/end_to_end_keys.hpp"
#include "progressive/storage/databases/main/registration.hpp"

namespace progressive::handlers {
using json = nlohmann::json;
using namespace storage;

// ============================================================================
// PresenceHandler - manages user presence states (2,634 lines)
// ============================================================================
class PresenceHandler {
public:
  PresenceHandler(DatabasePool& db);

  // Get current presence state for a user
  struct PresenceInfo {
    std::string user_id; std::string state; int64_t last_active_ago{0};
    bool currently_active{false}; std::optional<std::string> status_msg;
  };
  PresenceInfo get_presence(const std::string& user_id);

  // Set user presence state
  void set_presence(const std::string& user_id, const std::string& state,
      const std::optional<std::string>& status_msg = std::nullopt);

  // Get presence for multiple users
  std::map<std::string, PresenceInfo> get_presence_for_users(
      const std::set<std::string>& user_ids);

  // User started/stopped syncing
  void user_syncing(const std::string& user_id, bool syncing, int64_t last_sync_ts);

  // Get all presence updates for federation
  std::vector<PresenceInfo> get_presence_for_federation(int64_t from_ts, int limit);

  // Propagate presence to interested users (presence lists)
  void propagate_presence(const std::string& user_id);

  // Time out stale presence
  void handle_timeout(); void handle_timeout_for_user(const std::string& user_id);
  int64_t get_timeout_ms();

  // Update local presence from federation
  void process_federation_presence(const std::string& origin,
      const std::string& user_id, const PresenceInfo& presence);

  // Set state (internal persistence)
  void set_state(const std::string& user_id, const std::string& state,
      const std::string& status_msg, int64_t last_active_ts, bool currently_active);

  // Get allowed presence observers
  std::set<std::string> get_interested_remotes(const std::string& user_id);

  // Notify interested parties
  void notify_interested_parties(const std::string& user_id, const PresenceInfo& info);

  // Presence list management
  void send_presence_to_destinations(const std::string& user_id, const PresenceInfo& info);

private:
  DatabasePool& db_;
  PresenceStore presence_store_;
};

// ============================================================================
// DeviceHandler - manages user devices (1,840 lines)
// ============================================================================
class DeviceHandler {
public:
  DeviceHandler(DatabasePool& db);

  // Get all devices for user
  std::vector<DeviceInfo> get_devices(const std::string& user_id);

  // Get specific device
  std::optional<DeviceInfo> get_device(const std::string& user_id,
      const std::string& device_id);

  // Create/register a new device
  std::string create_device(const std::string& user_id,
      const std::optional<std::string>& device_id = std::nullopt,
      const std::optional<std::string>& display_name = std::nullopt);

  // Update device metadata
  void update_device(const std::string& user_id, const std::string& device_id,
      const std::optional<std::string>& display_name,
      const std::optional<std::string>& device_type, bool hidden = false);

  // Delete a device
  void delete_device(const std::string& user_id, const std::string& device_id);

  // Delete multiple devices (with auth)
  void delete_devices(const std::string& user_id,
      const std::vector<std::string>& device_ids);

  // Update last seen for a device
  void update_device_last_seen(const std::string& user_id,
      const std::string& device_id, const std::string& ip,
      const std::string& user_agent);

  // Notify federation about device list changes
  void notify_device_list_update(const std::string& user_id,
      const std::vector<std::string>& device_ids);

  // Handle device list updates from federation
  void process_federation_device_list_update(const std::string& origin,
      const std::string& user_id, const std::vector<std::string>& device_ids);

  // Check if device exists
  bool device_exists(const std::string& user_id, const std::string& device_id);

  // Get device stream token
  int64_t get_device_stream_token();

  // Get users whose devices changed
  std::map<std::string, std::vector<std::string>> get_users_whose_devices_changed(
      int64_t from_token, int64_t to_token);

  // Handle device list EDU from federation
  void handle_device_list_update_edu(const std::string& origin,
      const std::string& user_id, int64_t stream_id,
      const std::vector<std::string>& device_ids,
      const std::vector<std::string>& left_device_ids);

  // Generate device ID
  std::string generate_device_id();

private:
  DatabasePool& db_;
  DeviceStore device_store_;
};

// ============================================================================
// E2eKeysHandler - handles end-to-end encryption keys (1,835 lines)
// ============================================================================
class E2eKeysHandler {
public:
  E2eKeysHandler(DatabasePool& db);

  // Upload device keys
  struct UploadResult {
    json one_time_key_counts;
    std::optional<std::string> device_id;
    json device_keys;
    json one_time_keys;
    json fallback_keys;
  };
  UploadResult upload_keys(const std::string& user_id, const std::string& device_id,
      const json& device_keys, const json& one_time_keys = json::object(),
      const json& fallback_keys = json::object());

  // Query device keys for users
  struct QueryResult {
    json device_keys; json master_keys; json self_signing_keys;
    json user_signing_keys; json failures;
  };
  QueryResult query_keys(const json& query_content);

  // Claim one-time keys for pre-key messages
  struct ClaimResult {
    json one_time_keys; json failures;
  };
  ClaimResult claim_one_time_keys(const json& claim_content);

  // Get one-time key counts for users
  json count_one_time_keys(const std::string& user_id, const std::string& device_id);

  // Upload cross-signing keys
  void upload_signing_keys(const std::string& user_id,
      const std::optional<json>& master_key,
      const std::optional<json>& self_signing_key,
      const std::optional<json>& user_signing_key);

  // Upload cross-signing signatures
  void upload_signatures(const std::string& user_id,
      const std::map<std::string, std::map<std::string, json>>& signatures);

  // Get cross-signing keys for users
  std::map<std::string, std::map<std::string, json>> get_cross_signing_keys(
      const std::set<std::string>& user_ids);

  // Verify device key signature
  bool verify_device_key_signature(const std::string& user_id,
      const std::string& device_id, const json& device_key);

  // Handle key queries from federation
  QueryResult query_keys_for_federation(const std::string& user_id,
      const std::vector<std::string>& device_ids);

  // Claim keys for federation
  ClaimResult claim_keys_for_federation(const json& claim_content);

  // Get key changes since token
  json get_key_changes(const std::string& from_token, const std::string& to_token);

private:
  DatabasePool& db_;
  EndToEndKeyStore e2e_store_;
};

// ============================================================================
// OidcHandler - OpenID Connect authentication (1,859 lines)
// ============================================================================
class OidcHandler {
public:
  OidcHandler(DatabasePool& db);

  // Handle OIDC callback
  struct OidcCallbackResult {
    std::string user_id; std::string access_token; std::string device_id;
    std::optional<std::string> display_name;
  };
  OidcCallbackResult handle_oidc_callback(const json& token_response,
      const std::string& client_redirect_url, const std::string& nonce);

  // Handle OIDC token validation
  json validate_oidc_token(const std::string& id_token,
      const std::string& provider_id);

  // Map OIDC user to local account
  std::string map_oidc_user(const std::string& provider_id,
      const std::string& subject, const std::map<std::string,std::string>& attributes);

  // Handle OIDC userinfo
  json query_userinfo(const std::string& provider_id, const std::string& access_token);

  // OIDC provider configuration
  struct OidcProviderConfig {
    std::string issuer; std::string client_id; std::string client_secret;
    std::string authorization_endpoint; std::string token_endpoint;
    std::string userinfo_endpoint; std::string jwks_uri;
    std::vector<std::string> scopes;
  };
  OidcProviderConfig get_provider_config(const std::string& provider_id);

  // JWKS handling
  json get_jwks(const std::string& provider_id);
  bool verify_jwt_signature(const std::string& jwt, const json& jwks);

  // Handle OIDC logout
  void handle_oidc_logout(const std::string& user_id);

private:
  DatabasePool& db_;
};

// ============================================================================
// RegisterHandler - user registration (1,059 lines)
// ============================================================================
class RegisterHandler {
public:
  RegisterHandler(DatabasePool& db);

  // Register a new user
  struct RegisterResult {
    std::string user_id; std::string access_token;
    std::string device_id; std::string home_server;
    std::optional<std::string> refresh_token;
  };
  RegisterResult register_user(const json& registration_params);

  // Check if username is available
  bool is_username_available(const std::string& username);

  // Check if username is valid
  bool is_username_valid(const std::string& username);

  // Generate user ID
  std::string generate_user_id(const std::string& username);

  // Handle guest registration
  RegisterResult register_guest(const json& params);

  // Create registration session
  std::string create_registration_session(const json& params);

  // Complete registration with session
  RegisterResult complete_registration(const std::string& session_id,
      const json& auth_params);

  // Add third-party identifier to registration
  void add_threepid_to_registration(const std::string& session_id,
      const std::string& medium, const std::string& address);

  // Check if registration is allowed
  bool is_registration_allowed();

  // Get registration flows
  std::vector<json> get_registration_flows();

private:
  DatabasePool& db_;
  RegistrationStore reg_store_;
};

// ============================================================================
// RoomSummaryHandler - room summary and hero calculation (1,054 lines)
// ============================================================================
class RoomSummaryHandler {
public:
  RoomSummaryHandler(DatabasePool& db);

  // Get room summary for one room
  struct RoomSummary {
    int64_t joined_members{0}; int64_t invited_members{0};
    std::vector<std::string> heroes; std::optional<std::string> room_name;
    std::optional<std::string> room_topic; std::optional<std::string> room_avatar;
    bool is_direct{false}; std::string membership;
  };
  RoomSummary get_room_summary(const std::string& user_id,
      const std::string& room_id);

  // Get summaries for multiple rooms
  std::map<std::string, RoomSummary> get_room_summaries(
      const std::string& user_id, const std::set<std::string>& room_ids);

  // Calculate heroes for a room
  std::vector<std::string> calculate_heroes(const std::string& room_id,
      int limit = 5);

  // Check if room is a direct chat
  bool is_direct_room(const std::string& user_id, const std::string& room_id);

  // Get room display name for user
  std::string get_room_display_name(const std::string& user_id,
      const std::string& room_id);

  // Invalidate room summary cache for room
  void invalidate_room_summary(const std::string& room_id);

  // Invalidate summaries for all rooms a user is in
  void invalidate_user_room_summaries(const std::string& user_id);

  // Get last event in room for summary
  std::optional<json> get_last_room_event(const std::string& room_id);

private:
  DatabasePool& db_;
};

// ============================================================================
// AppserviceHandler - application service integration (989 lines)
// ============================================================================
class AppserviceHandler {
public:
  AppserviceHandler(DatabasePool& db);

  // Register an application service
  void register_appservice(const ApplicationService& service);

  // Unregister an application service
  void unregister_appservice(const std::string& service_id);

  // Notify appservices about an event
  void notify_appservices(const std::string& room_id,
      const std::string& event_id, const std::string& event_type);

  // Check if an appservice is interested in an event
  std::vector<std::string> get_interested_services(const std::string& room_id);

  // Schedule transaction for appservice
  void schedule_appservice_transaction(const std::string& service_id);

  // Send pending transactions to appservice
  void send_pending_transactions(const std::string& service_id);

  // Handle appservice ping
  bool handle_ping(const std::string& service_id, const std::string& txn_id);

  // Check if user is an appservice user
  bool is_appservice_user(const std::string& user_id);

  // Get appservice for user
  std::optional<ApplicationService> get_appservice_for_user(
      const std::string& user_id);

  // Check if room alias is exclusive to an appservice
  bool is_exclusive_alias(const std::string& alias);

  // Check if user namespace is exclusive to an appservice
  bool is_exclusive_user(const std::string& user_id);

  // Process appservice events
  void process_appservice_events(const std::string& service_id,
      const std::vector<json>& events);

  // Handle appservice ephemeral events
  void handle_appservice_ephemeral(const std::string& service_id,
      const std::string& stream_key, const std::vector<json>& events);

private:
  DatabasePool& db_;
  AppServiceStore as_store_;
};

} // namespace progressive::handlers
