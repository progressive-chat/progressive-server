#include "server_key.hpp"

#include <nlohmann/json.hpp>

#include "../../../crypto/signing.hpp"
#include "../../../http/router.hpp"
#include "../../../json/canonical.hpp"

namespace progressive::federation {

void register_key_routes(const crypto::SigningKey& key, progressive::http::Router& router,
                         std::string_view server_name) {
  namespace bhttp = boost::beast::http;

  router.add_route(
      bhttp::verb::get, "/_matrix/key/v2/server",
      [&key, server_name](bhttp::request<bhttp::string_body>&&, std::map<std::string, std::string>)
          -> bhttp::response<bhttp::string_body> {
        nlohmann::json j;
        j["server_name"] = server_name;
        j["valid_until_ts"] = 3000000000000ULL;

        nlohmann::json vk;
        vk["key"] = "base64_ed25519_public_key_placeholder";
        j["verify_keys"] = nlohmann::json::object();
        j["verify_keys"]["ed25519:" + key.version] = vk;

        j["old_verify_keys"] = nlohmann::json::object();
        j["signatures"] = nlohmann::json::object();
        j["signatures"][server_name] = nlohmann::json::object();
        j["signatures"][server_name]["ed25519:" + key.version] = "base64_signature_placeholder";

        bhttp::response<bhttp::string_body> res{bhttp::status::ok, 11};
        progressive::http::set_json(res, j.dump());
        return res;
      },
      "key_server");

  // Legacy key endpoint
  router.add_route(
      bhttp::verb::get, "/_matrix/key/v2/server/{keyId}",
      [](bhttp::request<bhttp::string_body>&&,
         std::map<std::string, std::string> p) -> bhttp::response<bhttp::string_body> {
        nlohmann::json j;
        j["server_name"] = "localhost";
        bhttp::response<bhttp::string_body> res{bhttp::status::ok, 11};
        progressive::http::set_json(res, j.dump());
        return res;
      },
      "key_server_legacy");
}

}  // namespace progressive::federation
