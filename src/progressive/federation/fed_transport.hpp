#pragma once
// fed_transport.hpp - Federation transport layer
// Translates synapse/federation/transport/ (2,915 lines)

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"

namespace progressive::federation {

using json = nlohmann::json;

// ============================================================================
// FederationClient - client for sending requests to other servers (1,188 lines)
// ============================================================================
class FederationClient {
public:
  FederationClient(storage::DatabasePool& db);

  // Send a federation transaction to a remote server
  json send_transaction(const std::string& destination, const json& transaction_data);

  // Make a join request
  json make_join(const std::string& destination, const std::string& room_id,
      const std::string& user_id, const std::vector<std::string>& supported_versions = {"1"});

  // Send a join event
  json send_join(const std::string& destination, const std::string& room_id,
      const std::string& event_id, const json& event);

  // Make a leave request
  json make_leave(const std::string& destination, const std::string& room_id,
      const std::string& user_id);

  // Send a leave event
  json send_leave(const std::string& destination, const std::string& room_id,
      const std::string& event_id, const json& event);

  // Make an invite
  json make_invite(const std::string& destination, const std::string& room_id,
      const std::string& event_id, const json& event);

  // Send an invite
  json send_invite(const std::string& destination, const std::string& room_id,
      const std::string& event_id, const json& event,
      const json& invite_room_state);

  // Send an invite v2
  json send_invite_v2(const std::string& destination, const std::string& room_id,
      const std::string& event_id, const json& event,
      const json& invite_room_state, const std::string& room_version);

  // Get missing events from a remote server
  json get_missing_events(const std::string& destination, const std::string& room_id,
      const std::vector<std::string>& missing_event_ids,
      const std::vector<std::string>& earliest_events,
      const std::vector<std::string>& latest_events, int limit, int min_depth);

  // Backfill events
  json backfill(const std::string& destination, const std::string& room_id,
      const std::vector<std::string>& extremities, int limit);

  // Get event from remote
  json get_event(const std::string& destination, const std::string& event_id);

  // Get event auth from remote
  json get_event_auth(const std::string& destination, const std::string& room_id,
      const std::string& event_id);

  // Query room state
  json get_room_state(const std::string& destination, const std::string& room_id,
      const std::string& event_id);

  // Query room state IDs
  json get_room_state_ids(const std::string& destination, const std::string& room_id,
      const std::string& event_id);

  // Query profile
  json get_profile(const std::string& destination, const std::string& user_id);

  // Query keys
  json claim_client_keys(const std::string& destination,
      const json& one_time_keys);

  // Query device keys
  json query_client_keys(const std::string& destination,
      const json& query_content);

  // Get server keys
  json get_server_keys(const std::string& destination,
      const std::set<std::string>& key_ids = {});

  // Get server version
  json get_server_version(const std::string& destination);

  // Exchange third party invite
  json exchange_third_party_invite(const std::string& destination,
      const std::string& room_id, const json& event);

  // Send knock
  json make_knock(const std::string& destination, const std::string& room_id,
      const std::string& user_id, const std::vector<std::string>& supported_versions);

  json send_knock(const std::string& destination, const std::string& room_id,
      const std::string& event_id, const json& event);

  // Get room hierarchy
  json get_room_hierarchy(const std::string& destination, const std::string& room_id,
      bool suggested_only);

  // Sign and send request
  json send_request(const std::string& method, const std::string& destination,
      const std::string& path, const json& content, int64_t timeout_ms = 30000);

  // Sign JSON for federation
  json sign_json(const json& data, const std::string& destination);

  // Verify signed JSON from federation
  bool verify_signed_json(const json& data, const std::string& origin);

private:
  storage::DatabasePool& db_;
  int64_t default_timeout_ms_{30000};
};

// ============================================================================
// FederationServer - server handling incoming federation requests (1,699 lines)
// ============================================================================
class FederationServer {
public:
  FederationServer(storage::DatabasePool& db);

  // Handle incoming federation transaction
  json on_incoming_transaction(const std::string& origin,
      const std::string& transaction_id, const json& content);

  // Handle make_join request
  json on_make_join(const std::string& origin, const std::string& room_id,
      const std::string& user_id, const std::vector<std::string>& supported_versions);

  // Handle send_join request
  json on_send_join(const std::string& origin, const std::string& room_id,
      const std::string& event_id, const json& content);

  // Handle make_leave request
  json on_make_leave(const std::string& origin, const std::string& room_id,
      const std::string& user_id);

  // Handle send_leave request
  json on_send_leave(const std::string& origin, const std::string& room_id,
      const std::string& event_id, const json& content);

  // Handle invite
  json on_make_invite(const std::string& origin, const std::string& room_id,
      const std::string& event_id, const json& content);

  json on_send_invite(const std::string& origin, const std::string& room_id,
      const std::string& event_id, const json& content,
      const json& invite_room_state);

  // Handle get_missing_events
  json on_get_missing_events(const std::string& origin, const std::string& room_id,
      const std::vector<std::string>& missing_event_ids,
      const std::vector<std::string>& earliest_events,
      const std::vector<std::string>& latest_events, int limit, int min_depth);

  // Handle backfill
  json on_backfill(const std::string& origin, const std::string& room_id,
      const std::vector<std::string>& extremities, int limit);

  // Handle get_event
  json on_get_event(const std::string& origin, const std::string& event_id);

  // Handle get_event_auth
  json on_get_event_auth(const std::string& origin, const std::string& room_id,
      const std::string& event_id);

  // Handle query
  json on_query_request(const std::string& origin, const std::string& query_type,
      const json& content);

  // Handle client keys query
  json on_query_client_keys(const std::string& origin, const json& content);

  // Handle claim keys
  json on_claim_client_keys(const std::string& origin, const json& content);

  // Handle profile query
  json on_query_profile(const std::string& origin, const std::string& user_id,
      const std::optional<std::string>& field);

  // Handle make_knock
  json on_make_knock(const std::string& origin, const std::string& room_id,
      const std::string& user_id, const std::vector<std::string>& supported_versions);

  json on_send_knock(const std::string& origin, const std::string& room_id,
      const std::string& event_id, const json& content);

  // Handle room hierarchy
  json on_get_room_hierarchy(const std::string& origin, const std::string& room_id,
      bool suggested_only);

  // Handle timestamp to event
  json on_timestamp_to_event(const std::string& origin, const std::string& room_id,
      int64_t timestamp, const std::string& direction);

  // Handle get spaces
  json on_get_spaces(const std::string& origin);

  // Handle get room summary
  json on_get_public_rooms(const std::string& origin, int limit, const std::string& since,
      const std::string& search_term, bool include_all, const std::string& network,
      const std::string& third_party_instance_id);

  // Handle exchange third party invite
  json on_exchange_third_party_invite(const std::string& origin,
      const std::string& room_id, const json& event);

  // Validate incoming request
  bool validate_request(const std::string& origin, const std::string& method,
      const std::string& path, const json& content);

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// FederationTransport - HTTP-level transport for federation
// Translates the HTTP server + client infrastructure
// ============================================================================
class FederationTransport {
public:
  FederationTransport(storage::DatabasePool& db);

  // Start listening for federation traffic
  void start(int port);

  // Stop the transport
  void stop();

  // Send HTTP request to a remote server
  struct HttpResponse {
    int code; json body; std::map<std::string,std::string> headers;
  };
  HttpResponse send_http_request(const std::string& method,
      const std::string& destination, const std::string& path,
      const json& content, int64_t timeout_ms = 30000);

  // Resolve server name to host:port
  std::string resolve_server(const std::string& server_name);

  // Check if server is reachable
  bool is_server_reachable(const std::string& server_name);

  // Wake up a destination (send a no-op)
  void wake_destination(const std::string& destination);

  // Get TLS certificate for destination
  std::optional<std::string> get_tls_certificate(const std::string& destination);

  // Set our TLS certificate
  void set_tls_certificate(const std::string& cert_pem);

  // Set our signing key
  void set_signing_key(const std::string& key_id, const std::string& key_pem);

private:
  storage::DatabasePool& db_;
};

} // namespace progressive::federation
