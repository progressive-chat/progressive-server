// server_server.hpp — translation of Conduit's src/server_server.rs
// (send_request from b0d9ccdb; server identity routes arrive in 1af6dd98).

#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

class Data;

namespace federation {

// NEW in 0b56589/b4c001de: typed federation destination (upstream
// FederationDestination enum). Either an IP-literal socket address or a named
// host + port. Replaces the stringly (url, host) tuples so the TLS override
// below can compare hosts without re-splitting strings.
struct FederationDestination {
  bool is_literal = false;  // true: Literal socket addr, false: Named host+port
  std::string host;         // literal: ip string; named: hostname
  std::string port;         // literal: numeric port; named: ":port" or ""
  static FederationDestination literal(const std::string& ip, const std::string& port);
  static FederationDestination named(const std::string& host, const std::string& port);
  std::string into_url() const;  // https://host:port
  std::string into_uri() const;  // host:port (literal: ip:port)
  std::string tls_host() const;  // host part used for TLS/SNI comparison
};

// Returns a Literal for "ip", "ip:port" or "[v6]:port", nullopt otherwise.
std::optional<FederationDestination> get_ip_with_port(const std::string& s);
// Appends the default :8448 port when missing.
FederationDestination add_port_to_hostname(const std::string& s);
// Upstream find_actual_destination: (actual_destination, host header).
std::pair<FederationDestination, FederationDestination> find_actual_destination(
    const std::string& destination);

// NEW in 0b56589: TLS server-name override for delegated hosts (upstream
// Globals::tls_name_override). When .well-known delegates example.com to
// other.example, the TLS handshake must verify other.example's cert against
// the DELEGATED name. e73de231 fallback: retry with the original name + warn.
void note_tls_name_override(const std::string& actual_host, const std::string& tls_name);
std::string tls_name_for(const std::string& actual_host, const std::string& fallback);

// Signs {method, uri, origin, destination, content} and POSTs it to
// https://destination<path>. Returns the parsed JSON response or nullopt.
// Updated in f7816b1 to take Data& (Globals) instead of individual params.
std::optional<nlohmann::json> send_request(
    Data& data, const std::string& destination, const std::string& path,
    const nlohmann::json& content = {});
// NEW in 4cc0a070: request_well_known — fetches
// https://<destination>/.well-known/matrix/server and returns the m.server
// delegation hint. Returns nullopt on any network/parse/format error.
std::optional<std::string> request_well_known(const std::string& destination);

// NEW in a77fcd1: /state_ids federation endpoint
nlohmann::json get_room_state_ids(Data& db, const std::string& event_id);

// NEW in f3f95a73: /event federation endpoint
nlohmann::json get_event(Data& db, const std::string& event_id);

// NEW in eedac4fd: make_join, send_join and /directory federation endpoints
nlohmann::json make_join(Data& db, const std::string& room_id, const std::string& user_id);
nlohmann::json send_join(Data& db, const std::string& room_id, const nlohmann::json& event);
nlohmann::json get_public_rooms_federation(Data& db, const nlohmann::json& request);

// NEW in 71ed1b29: federation /user/devices route — remote servers fetch a
// user's device list (stream_id = devicelist version for change tracking).
nlohmann::json get_user_devices(Data& db, const std::string& user_id);

// NEW in 1f84013b: verify X-Matrix signatures on incoming federation
// requests (upstream Ruma ServerSignatures guard). Parses the Authorization
// header (origin/key/sig), rebuilds the canonical {content?, method, uri,
// origin, destination, signatures} JSON and verifies it against the origin's
// signing keys (cache, else live fetch of /_matrix/key/v2/server).
// Returns the origin server name on success, nullopt on any failure.
// (Takes plain strings so this header stays httplib-free.)
std::optional<std::string> verify_federation_request(
    Data& db, const std::string& method, const std::string& uri,
    const std::string& auth_header, const nlohmann::json& body);

// NEW in d4e0ba24: fetch_and_handle_events fix for federation event fetching
// Fetches missing events (by event_id) from cache, DB, or federation.
// Used to populate auth chains when handling incoming PDUs.
std::vector<nlohmann::json> fetch_and_handle_events(
    Data& db,
    const std::string& origin,
    const std::vector<std::string>& event_ids,
    std::map<std::string, nlohmann::json>& auth_cache
);



}  // namespace federation
