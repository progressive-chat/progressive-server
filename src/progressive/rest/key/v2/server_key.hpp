#pragma once
#include <boost/beast/http.hpp>
#include <map>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>

#include "../../../crypto/signing.hpp"
#include "../../../http/router.hpp"

namespace progressive::federation {

void register_key_routes(const crypto::Ed25519Keypair& key, progressive::http::Router& router,
                         std::string_view server_name);

}
