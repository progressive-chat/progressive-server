#pragma once
#include <boost/beast/http.hpp>
#include <map>
#include <string>
#include <string_view>

#include "../auth/auth.hpp"
#include "../http/router.hpp"

namespace progressive::media {

void register_routes(progressive::http::Router& router, auth::Auth& auth_unit,
                     std::string_view media_dir, std::string_view server_name);

}
