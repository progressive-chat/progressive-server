// admin.cpp — Conduit admin subsystem (9db1f5a13c-era).
//
// Implements a focused, real admin API on top of the existing Data layer:
//   GET  /_conduit/admin/version             — server version
//   GET  /_conduit/admin/ping                — liveness
//   GET  /_conduit/admin/users               — list all users
//   GET  /_conduit/admin/users/{userId}      — get a user's profile
//   POST /_conduit/admin/register            — create a user (admin only)
//   PUT  /_conduit/admin/users/{userId}/displayname — set displayname
//   POST /_conduit/admin/user/{userId}/deactivate   — deactivate an account
//   POST /_conduit/admin/user/{userId}/password     — reset a user's password
//
// Every endpoint requires the requester to be an admin (seeded from the
// CONDUIT_ADMINS env var at startup). The register endpoint applies the
// 9db1f5a13c fix: it refuses to create users whose server name is not this
// server.

#include "admin.hpp"
#include "data.hpp"
#include "ruma_wrapper.hpp"
#include "utils.hpp"

#include <optional>

namespace {

// Returns the sender if authenticated and an admin, otherwise responds with the
// appropriate Matrix error and returns std::nullopt.
std::optional<std::string> require_admin(Context& ctx, const httplib::Request& req,
                                         httplib::Response& res) {
  auto token = extract_token(req);
  if (!token) {
    ruma::respond(res,
                  ruma::json{{"errcode", "M_MISSING_TOKEN"},
                             {"error", "Missing access token"}},
                  401);
    return std::nullopt;
  }
  auto sender = ctx.data->user_from_token(*token);
  if (!sender) {
    ruma::respond(res,
                  ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                             {"error", "Unrecognized access token"}},
                  401);
    return std::nullopt;
  }
  if (!ctx.data->user_is_admin(*sender)) {
    ruma::respond(res,
                  ruma::json{{"errcode", "M_FORBIDDEN"},
                             {"error", "You are not an admin"}},
                  403);
    return std::nullopt;
  }
  return sender;
}

ruma::json parse_body(const httplib::Request& req) {
  ruma::json body;
  try {
    body = ruma::json::parse(req.body.empty() ? "{}" : req.body);
  } catch (...) {
    body = ruma::json::object();
  }
  if (!body.is_object()) body = ruma::json::object();
  return body;
}

}  // namespace

void register_admin_routes(httplib::Server& svr, Context& ctx) {
  // GET /_conduit/admin/version
  svr.Get("/_conduit/admin/version",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             if (!require_admin(ctx, req, res)) return;
             ruma::respond(
                 res, ruma::json{{"server_version", "0.11.0-alpha"}});
           });

  // GET /_conduit/admin/users
  svr.Get("/_conduit/admin/users",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             if (!require_admin(ctx, req, res)) return;
             ruma::json users = ruma::json::array();
             for (const auto& u : ctx.data->users_all()) users.push_back(u);
             ruma::respond(res, ruma::json{{"users", users}});
           });

  // GET /_conduit/admin/users/{userId}
  svr.Get(R"(/_conduit/admin/users/(.+))",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             if (!require_admin(ctx, req, res)) return;
             const std::string user_id = req.matches[1];
             ruma::json info;
             info["user_id"] = user_id;
             if (auto dn = ctx.data->displayname_get(user_id))
               info["displayname"] = *dn;
             info["admin"] = ctx.data->user_is_admin(user_id);
             ruma::respond(res, info);
           });

  // POST /_conduit/admin/register — create a user (admin only).
  // NEW in 9db1f5a13c: do not allow creation of remote users.
  svr.Post("/_conduit/admin/register",
            [&ctx](const httplib::Request& req, httplib::Response& res) {
              if (!require_admin(ctx, req, res)) return;
              ruma::json body = parse_body(req);
              std::string password = body.value("password", "");

              std::string user_id;
              std::string requested =
                  body.contains("user_id")
                      ? body["user_id"].get<std::string>()
                      : "";
              if (!requested.empty()) {
                // NEW in 9db1f5a13c: reject remote users.
                if (requested.front() == '@') {
                  size_t colon = requested.find(':');
                  if (colon != std::string::npos) {
                    std::string server = requested.substr(colon + 1);
                    if (!server.empty() && server != ctx.data->hostname()) {
                      ruma::respond(
                          res,
                          ruma::json{
                              {"errcode", "M_INVALID_PARAM"},
                              {"error",
                               "The specified user is not from this server!"}},
                          400);
                      return;
                    }
                  }
                  user_id = requested;
                } else {
                  user_id = "@" + requested + ":" + ctx.data->hostname();
                }
              } else {
                std::string localpart = body.value("username", "");
                if (localpart.empty()) {
                  ruma::respond(
                      res,
                      ruma::json{{"errcode", "M_INVALID_PARAM"},
                                 {"error", "Missing username or user_id"}},
                      400);
                  return;
                }
                user_id = "@" + localpart + ":" + ctx.data->hostname();
              }

              if (ctx.data->user_exists(user_id)) {
                ruma::respond(res,
                              ruma::json{{"errcode", "M_USER_IN_USE"},
                                         {"error", "User ID already taken."}},
                              400);
                return;
              }

              auto hash = utils::calculate_hash(password);
              if (!hash) {
                ruma::respond(
                    res, ruma::json{{"errcode", "M_INVALID_PARAM"},
                                    {"error", "Password did not meet requirements"}},
                    400);
                return;
              }

              ctx.data->user_add(user_id, *hash);
              const std::string device_id = utils::random_string(10);
              ctx.data->device_add(user_id, device_id);
              const std::string token = utils::random_string(32);
              ctx.data->token_replace(user_id, device_id, token);
              if (body.contains("displayname") &&
                  !body["displayname"].get<std::string>().empty()) {
                ctx.data->displayname_set(user_id,
                                          body["displayname"].get<std::string>());
              }
              ruma::respond(
                  res,
                  ruma::json{{"access_token", token},
                             {"home_server", ctx.data->hostname()},
                             {"user_id", user_id},
                             {"device_id", device_id}});
            });

  // PUT /_conduit/admin/users/{userId}/displayname
  svr.Put(R"(/_conduit/admin/users/(.+)/displayname)",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             if (!require_admin(ctx, req, res)) return;
             const std::string user_id = req.matches[1];
             ruma::json body = parse_body(req);
             std::string displayname = body.value("displayname", "");
             if (displayname.empty()) {
               ruma::respond(
                   res, ruma::json{{"errcode", "M_INVALID_PARAM"},
                                    {"error", "Missing displayname"}},
                   400);
               return;
             }
             ctx.data->displayname_set(user_id, displayname);
             ruma::respond(res, ruma::json::object());
           });

  // POST /_conduit/admin/user/{userId}/deactivate — deactivate an account.
  svr.Post(R"(/_conduit/admin/user/(.+)/deactivate)",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             auto admin = require_admin(ctx, req, res);
             if (!admin) return;
             const std::string user_id = req.matches[1];
             if (!ctx.data->user_exists(user_id)) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_NOT_FOUND"},
                                        {"error", "User not found."}},
                             404);
               return;
             }
             ctx.data->deactivate_account(user_id);
             ruma::respond(res, ruma::json{{"deactivated", true}});
           });

  // POST /_conduit/admin/user/{userId}/password — reset a user's password.
  svr.Post(R"(/_conduit/admin/user/(.+)/password)",
           [&ctx](const httplib::Request& req, httplib::Response& res) {
             auto admin = require_admin(ctx, req, res);
             if (!admin) return;
             const std::string user_id = req.matches[1];
             if (!ctx.data->user_exists(user_id)) {
               ruma::respond(res,
                             ruma::json{{"errcode", "M_NOT_FOUND"},
                                        {"error", "User not found."}},
                             404);
               return;
             }
             ruma::json body = parse_body(req);
             const std::string password = body.value("password", "");
             if (password.empty()) {
               ruma::respond(
                   res, ruma::json{{"errcode", "M_INVALID_PARAM"},
                                    {"error", "Missing password"}},
                   400);
               return;
             }
             if (!ctx.data->set_password(user_id, password)) {
               ruma::respond(
                   res, ruma::json{{"errcode", "M_INVALID_PARAM"},
                                    {"error",
                                     "Password did not meet requirements"}},
                   400);
               return;
             }
             if (body.value("logout_devices", true)) {
               for (const auto& d : ctx.data->all_device_ids(user_id))
                 ctx.data->remove_device(user_id, d);
             }
             ruma::respond(res, ruma::json::object());
           });

  // GET /_conduit/admin/ping — liveness check.
  svr.Get("/_conduit/admin/ping",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            if (!require_admin(ctx, req, res)) return;
            ruma::respond(res, ruma::json{{"pong", true}});
          });
}
