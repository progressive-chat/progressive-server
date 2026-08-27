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

std::optional<nlohmann::json> send_request(
    const std::string& hostname, const std::string& keypair_seed,
    const std::string& destination, const std::string& path,
    const nlohmann::json& content) {
  using json = nlohmann::json;

  json request_map = json::object();

  // if !http_request.body().is_empty() { request_map.insert("content", ...) }
  if (content.is_object() && !content.empty()) {
    request_map["content"] = content;
  }

  request_map["method"] = "POST";
  request_map["uri"] = path;
  request_map["origin"] = hostname;
  request_map["destination"] = destination;

  crypto::sign_json(hostname, keypair_seed, request_map);

  // X-Matrix origin=...,key="...",sig="..."
  std::string auth = "X-Matrix origin=" + hostname + ",key=\"";
  for (const auto& [server, sigs] : request_map["signatures"].items()) {
    for (auto it = sigs.begin(); it != sigs.end(); ++it) {
      auth += it.key() + "\",sig=\"" + it.value().get<std::string>() + "\"";
    }
    break;  // single key at this commit
  }

  // https://destination:8448<path> — federation port.
  httplib::SSLClient client(destination, 8448);
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
  return json::parse(res->body, nullptr, false);
}

}  // namespace federation
