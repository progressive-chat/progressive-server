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

  // Build the signed request map (ruma_signatures::sign_json input).
  json request_map = content.is_object() ? content : json::object();
  request_map["method"] = "POST";
  request_map["uri"] = path;
  request_map["origin"] = hostname;
  request_map["destination"] = destination;

  crypto::hash_and_sign_event(hostname, keypair_seed, request_map);

  // X-Matrix origin=...,key="...",sig="..."
  std::string auth = "X-Matrix origin=" + hostname + ",key=\"";
  for (const auto& [server, sigs] : request_map["signatures"].items()) {
    for (auto it = sigs.begin(); it != sigs.end(); ++it) {
      auth += it.key() + "\",sig=\"" + it.value().get<std::string>() + "\"";
    }
    break;  // single key at this commit
  }

  httplib::SSLClient client(destination, 443);
  client.enable_server_certificate_verification(false);  // sandbox proxy MITM
  httplib::Headers headers{
      {"Authorization", auth},
      {"Content-Type", "application/json"},
  };
  auto res = client.Post(path, headers, request_map.dump(), "application/json");
  if (!res) {
    std::cout << "ERROR: federation request to " << destination
              << " failed (" << static_cast<int>(res.error()) << ")\n";
    return std::nullopt;
  }
  return json::parse(res->body, nullptr, false);
}

}  // namespace federation
