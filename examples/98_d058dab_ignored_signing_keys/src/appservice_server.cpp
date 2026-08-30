// appservice_server.cpp — translation of Conduit commit 6e5b35ea's
// src/appservice_server.rs (104 lines).
//
// Appservice (bridge) protocol client. The homeserver pushes events to
// bridges via signed HTTPS POST requests. The bridge responds with a
// list of events it wants the homeserver to inject on its behalf
// (typically ghost-user membership changes / display name updates).

#include "appservice_server.hpp"
#include "crypto.hpp"
#include "data.hpp"
#include "utils.hpp"

#include <httplib.h>

#include <iostream>

namespace appservice {

std::optional<nlohmann::json> send_request(
    const std::string& hostname,
    const std::string& keypair_seed,
    const nlohmann::json& registration,
    const std::string& method,
    const std::string& path,
    const nlohmann::json& body) {
  using json = nlohmann::json;

  // Pull URL and hs_token from the registration.
  if (!registration.is_object() || !registration.contains("url") ||
      !registration.contains("hs_token")) {
    return std::nullopt;
  }
  const std::string destination = registration["url"].get<std::string>();
  const std::string hs_token = registration["hs_token"].get<std::string>();

  // Build the signed request map. The body lives under the "content" key
  // because the homeserver signs the whole request envelope (method, uri,
  // origin, destination, content) with its Ed25519 keypair.
  json request_map = json::object();
  request_map["method"] = method;
  request_map["uri"] = path;
  request_map["origin"] = hostname;
  request_map["destination"] = destination;
  if (body.is_object() && !body.empty()) {
    request_map["content"] = body;
  }
  crypto::sign_json(hostname, keypair_seed, request_map);

  // X-Matrix origin=...,key="...",sig="..." — the appservice uses this to
  // verify the request really came from the homeserver.
  std::string auth = "X-Matrix origin=" + hostname + ",key=\"";
  for (const auto& [server, sigs] : request_map["signatures"].items()) {
    for (auto it = sigs.begin(); it != sigs.end(); ++it) {
      auth += it.key() + "\",sig=\"" + it.value().get<std::string>() + "\"";
    }
    break;  // single key
  }

  // Strip scheme (http:// or https://) from destination to get the host.
  std::string host = destination;
  if (host.rfind("https://", 0) == 0) host = host.substr(8);
  else if (host.rfind("http://", 0) == 0) host = host.substr(7);
  // Strip any trailing slash or path.
  const auto slash = host.find('/');
  if (slash != std::string::npos) host = host.substr(0, slash);

  // Append ?access_token=<hs_token> so the appservice can verify us.
  std::string url = path;
  url += (url.find('?') == std::string::npos) ? "?" : "&";
  url += "access_token=" + hs_token;

  // Send the request. Try HTTPS first; fall back to HTTP if the bridge
  // doesn't have TLS (e.g. localhost development bridges).
  httplib::SSLClient https_client(host, 443);
  https_client.enable_server_certificate_verification(false);
  https_client.set_connection_timeout(5);
  https_client.set_read_timeout(30);
  https_client.set_write_timeout(30);
  httplib::Headers headers{
      {"Authorization", auth},
      {"Content-Type", "application/json"},
  };
  auto res = https_client.Post(url, headers, request_map.dump(),
                               "application/json");
  if (!res) {
    // Fall back to plain HTTP.
    httplib::Client http_client(host, 80);
    http_client.set_connection_timeout(5);
    http_client.set_read_timeout(30);
    http_client.set_write_timeout(30);
    res = http_client.Post(url, headers, request_map.dump(),
                           "application/json");
  }
  if (!res) {
    std::cerr << "[warn] appservice request to " << destination
              << " failed: " << static_cast<int>(res.error()) << "\n";
    return std::nullopt;
  }
  if (res->status < 200 || res->status >= 300) {
    std::cerr << "[warn] appservice " << destination << " returned HTTP "
              << res->status << "\n";
    return std::nullopt;
  }
  return json::parse(res->body, nullptr, false);
}

}  // namespace appservice
