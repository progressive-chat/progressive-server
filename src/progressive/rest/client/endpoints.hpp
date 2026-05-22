#pragma once
#include <boost/beast/http.hpp>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

#include "../../auth/auth.hpp"
#include "../../http/router.hpp"
#include "../../server/server.hpp"
#include "../../storage/database.hpp"

namespace boost_http = boost::beast::http;

namespace progressive::rest::client {

void register_routes(progressive::server::Server& server, http::Router& router);

}
