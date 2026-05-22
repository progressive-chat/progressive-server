#include "server_key.hpp"

#include <nlohmann/json.hpp>

#include "../../../crypto/signing.hpp"
#include "../../../http/router.hpp"

namespace progressive::federation {

void register_key_routes(const crypto::Ed25519Keypair& key, progressive::http::Router& router,
                         std::string_view server_name) {
  namespace bhttp = boost::beast::http;

  router.add_route(
      bhttp::verb::get, "/_matrix/key/v2/server",
      [&key, server_name](bhttp::request<bhttp::string_body>&&, std::map<std::string, std::string>)
          -> bhttp::response<bhttp::string_body> {
        auto j = crypto::make_key_server_json(server_name, key);
        bhttp::response<bhttp::string_body> res{bhttp::status::ok, 11};
        progressive::http::set_json(res, j.dump());
        return res;
      },
      "key_server");

  // Legacy key endpoint
  router.add_route(
      bhttp::verb::get, "/_matrix/key/v2/server/{keyId}",
      [&key, server_name](bhttp::request<bhttp::string_body>&&, std::map<std::string, std::string>)
          -> bhttp::response<bhttp::string_body> {
        auto j = crypto::make_key_server_json(server_name, key);
        bhttp::response<bhttp::string_body> res{bhttp::status::ok, 11};
        progressive::http::set_json(res, j.dump());
        return res;
      },
      "key_server_legacy");
}

}  // namespace progressive::federation
