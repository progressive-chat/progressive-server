// admin.hpp — Conduit admin subsystem (9db1f5a13c-era).
//
// Adds the `/_conduit/admin/*` routes: a minimal but real admin API built on
// the existing Data layer. Includes the 9db1f5a13c fix that rejects creation
// of remote (non-local) users via the admin register endpoint.

#pragma once

#include "httplib.h"
#include "routes.hpp"

void register_admin_routes(httplib::Server& svr, Context& ctx);
