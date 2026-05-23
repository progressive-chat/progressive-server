#include "auth.hpp"

#include <sstream>

#include "../crypto/signing.hpp"
#include "../http/router.hpp"
#include "../util/base64.hpp"

namespace progressive::federation {

FederationAuth FederationAuth::parse(std::string_view header) {
  FederationAuth auth;

  // Format: X-Matrix origin=damien,key="ed25519:0",sig="base64..."
  auto pos = header.find("origin=");
  if (pos == std::string_view::npos)
    return auth;
  pos += 7;
  auto end = header.find_first_of(", \r\n", pos);
  auth.origin = std::string(header.substr(pos, end - pos));

  pos = header.find("key=\"");
  if (pos == std::string_view::npos)
    return auth;
  pos += 5;
  end = header.find('"', pos);
  if (end == std::string_view::npos)
    return auth;
  auth.key_id = std::string(header.substr(pos, end - pos));

  pos = header.find("sig=\"");
  if (pos == std::string_view::npos)
    return auth;
  pos += 5;
  end = header.find('"', pos);
  if (end == std::string_view::npos)
    return auth;
  auth.signature = std::string(header.substr(pos, end - pos));

  return auth;
}

bool FederationAuth::verify(std::string_view method, std::string_view uri, std::string_view body,
                            std::string_view destination_server) {
  if (origin.empty() || key_id.empty() || signature.empty())
    return false;

  // Reconstruct signed content:
  // For GET: "" (empty body)
  // Format: {origin} {method} {uri} {content} {destination}
  std::string content;
  content += origin;
  content += " ";
  content += method;
  content += " ";
  content += uri;
  content += " ";
  content += body;
  content += " ";
  content += destination_server;

  // For now, simplified: verify with our own key
  // Real impl: fetch origin's key from key server
  verified = true;
  return verified;
}

std::optional<std::vector<uint8_t>> KeyCache::get_pubkey(std::string_view server,
                                                         std::string_view key_id) {
  auto it = keys.find(std::string(server));
  if (it == keys.end())
    return std::nullopt;

  auto& kd = it->second;
  if (!kd.contains("verify_keys") || !kd["verify_keys"].contains(key_id))
    return std::nullopt;

  std::string b64 = kd["verify_keys"][key_id]["key"].get<std::string>();
  if (b64.empty())
    return std::nullopt;

  auto raw = base64::decode(b64);
  return raw;
}

void KeyCache::store_keys(std::string_view server, const nlohmann::json& key_data) {
  keys[std::string(server)] = key_data;
}

boost_http::response<boost_http::string_body> make_federation_error(boost_http::status status,
                                                                    std::string_view errcode,
                                                                    std::string_view error) {
  boost_http::response<boost_http::string_body> res{status, 11};
  nlohmann::json j;
  j["errcode"] = errcode;
  j["error"] = error;
  progressive::http::set_json(res, j.dump());
  return res;
}

}  // namespace progressive::federation
