#pragma once
#include <boost/asio/io_context.hpp>
#include <boost/beast/http.hpp>
#include <map>
#include <string>
#include <string_view>

#include "../http/router.hpp"
#include "../storage/database.hpp"

namespace progressive::lemmy {

void register_lemmy_routes(progressive::http::Router& router, storage::DatabasePool& db,
                           std::string_view server_name);

}
