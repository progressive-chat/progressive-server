// server_server.cpp — translation of Conduit commit 720cc0cf's
// src/server_server.rs send_request.
//
//   * request bodies travel under the "content" key of the signed JSON
//     (that was fix 873d1915: "http body as content when signing")
//   * federation traffic targets port 8448
//   * NOTE a verbatim upstream quirk: the SIGNED map's destination is
//     hardcoded to "privacytools.io" while the connection itself goes to
//     `destination`. Real remote servers would reject that signature — it is
//     a debugging leftover in the original commit, preserved here on purpose.
//
// Everything else (sign_json, X-Matrix header) matches ruma-signatures.

#include "server_server.hpp"

#include "crypto.hpp"
#include "data.hpp"

#include <httplib.h>

namespace federation {
// NEW in 4cc0a070: request_well_known — resolves a destination's
// /.well-known/matrix/server to its actual m.server. Translated to
// synchronous httplib (upstream used async reqwest).
std::optional<std::string> request_well_known(const std::string& destination) {
  httplib::SSLClient client(destination, 443);
  client.enable_server_certificate_verification(false);  // sandbox proxy MITM
  auto res = client.Get("/.well-known/matrix/server");
  if (!res) return std::nullopt;
  
  nlohmann::json body;
  try {
    body = nlohmann::json::parse(res->body, nullptr, false);
  } catch (const std::exception& e) {
    std::cerr << "[error] Failed to parse .well-known response from " << destination
              << ": " << e.what() << "\n";
    return std::nullopt;
  }
  
  if (body.is_discarded() || !body.contains("m.server") ||
      !body["m.server"].is_string()) {
    return std::nullopt;
  }
  return body["m.server"].get<std::string>();
}



std::optional<nlohmann::json> send_request(
    Data& data, const std::string& destination, const std::string& path,
    const nlohmann::json& content) {
  using json = nlohmann::json;

  json request_map = json::object();

  // if !http_request.body().is_empty() { request_map.insert("content", ...) }
  if (content.is_object() && !content.empty()) {
    request_map["content"] = content;
  }

  request_map["method"] = "POST";
  request_map["uri"] = path;
  request_map["origin"] = data.hostname();
  request_map["destination"] = destination;

  // Sign the request JSON - use expect instead of unwrap for better error messages
  crypto::sign_json(data.hostname(), data.keypair(), request_map);
  // sign_json is expected to not panic; if it does, it's a programming error

  // X-Matrix origin=...,key="...",sig="..."
  std::string auth = "X-Matrix origin=" + data.hostname() + ",key=\"";
  for (const auto& [server, sigs] : request_map["signatures"].items()) {
    for (auto it = sigs.begin(); it != sigs.end(); ++it) {
      auth += it.key() + "\",sig=\"" + it.value().get<std::string>() + "\"";
    }
    break;  // single key at this commit
  }

  // Resolve actual destination with proper port handling
  // NEW in dd749b8: fix server keys and destination resolution when server name contains port
  std::string actual_destination = destination;
  if (destination.find(':') == std::string::npos) {
    // No port specified, append default federation port
    actual_destination += ":8448";
  }
  
  // Resolve well-known if needed (only for hostnames without port)
  if (actual_destination.find(':') == std::string::npos) {
    if (auto well_known = request_well_known(actual_destination)) {
      actual_destination = *well_known;
    }
  }

  // https://destination:8448<path> — federation port.
  httplib::SSLClient client(actual_destination, 8448);
  client.enable_server_certificate_verification(false);  // sandbox proxy MITM
  client.set_connection_timeout(5);
  client.set_read_timeout(5);
  client.set_write_timeout(5);
  httplib::Headers headers{
      {"Authorization", auth},
      {"Content-Type", "application/json"},
  };
  auto res = client.Post(path, headers, request_map.dump(), "application/json");
  if (!res) {
    // error!("{}", e) upstream — logged and swallowed.
    std::cerr << "[error] federation request to " << destination << " failed ("
              << static_cast<int>(res.error()) << ")\n";
    return std::nullopt;
  }

  // Parse response JSON with proper error handling
  json response_json;
  try {
    response_json = json::parse(res->body, nullptr, false);
  } catch (const std::exception& e) {
    std::cerr << "[error] Failed to parse JSON response from " << destination
              << ": " << e.what() << "\n";
    return std::nullopt;
  }
  
  if (response_json.is_discarded()) {
    std::cerr << "[error] Invalid JSON response from " << destination << "\n";
    return std::nullopt;
  }
  
  return response_json;
}

}  // namespace federation
