// main.cpp — translation of Conduit commit c2c18b46, src/main.rs
//
// "feat: database". sled::Db opened at the data dir, injected via
// rocket .manage(db); register persists into the "users" tree (plaintext
// passwords — as upstream) and rejects duplicates; new POST /login route that
// still accepts any password.

#include "ruma_wrapper.hpp"
#include "sled.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <optional>

namespace {

bool user_id_from_localpart(const std::string& localpart, std::string* out) {
  // What UserId's TryFrom checked in ruma-identifiers 0.14.
  if (localpart.empty()) return false;
  for (const char c : localpart) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '=' || c == '-' || c == '/' ||
                    c == '+';
    if (!ok) return false;
  }
  *out = "@" + localpart + ":localhost";
  return true;
}

struct Context {
  sled::Db* db;
};

ruma::MatrixResult<ruma::RegisterResponse> register_route(
    Context* ctx, const ruma::RegisterRequest& body) {
  sled::Tree users = ctx->db->open_tree("users");

  std::string user_id;
  if (!user_id_from_localpart(body.username.value_or("randomname"), &user_id)) {
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::InvalidUsername,
        .message = "Username was invalid.",
        .status_code = 400,
    });
  }

  if (users.contains_key(user_id)) {
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::UserInUse,
        .message = "Desired user ID is already taken.",
        .status_code = 400,
    });
  }

  users.insert(user_id, body.password.value_or(""));

  return ruma::MatrixResult<ruma::RegisterResponse>::ok(ruma::RegisterResponse{
      .access_token = "randomtoken",
      .home_server = "localhost",
      .user_id = std::move(user_id),
      .device_id = body.device_id.value_or("randomid"),
  });
}

ruma::MatrixResult<ruma::LoginResponse> login_route(Context* ctx,
                                                    const ruma::LoginRequest& body) {
  if (!body.user_is_matrix_id) {
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Unknown,
        .message = "Bad login type.",
        .status_code = 400,
    });
  }

  const std::string user_id = "@" + *body.user_localpart + ":localhost";
  sled::Tree users = ctx->db->open_tree("users");
  if (!users.contains_key(user_id)) {
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Forbidden,
        .message = "UserId not found.",
        .status_code = 400,
    });
  }

  // Password ignored! Any password logs you in at this commit.
  return ruma::MatrixResult<ruma::LoginResponse>::ok(ruma::LoginResponse{
      .user_id = user_id,
      .access_token = "randomtoken",
      .home_server = std::string{"localhost"},
      .device_id = body.device_id.value_or("randomid"),
  });
}

}  // namespace

int main() {
  const char* home = ::getenv("HOME");
  const std::filesystem::path data_dir =
      (home ? std::filesystem::path{home} : std::filesystem::path{"/tmp"}) /
      ".local/share/conduit-step03";

  static sled::Db db = sled::Db::open(data_dir);
  static Context ctx{&db};

  httplib::Server svr;

  svr.Get("/_matrix/client/versions", [](const httplib::Request&, httplib::Response& res) {
    ruma::respond(res, ruma::MatrixResult<ruma::GetSupportedVersionsResponse>::ok(
                           ruma::GetSupportedVersionsResponse{
                               .versions = {"r0.6.0"},
                               .unstable_features = {},
                           }));
  });

  svr.Post("/_matrix/client/r0/register", [](const httplib::Request& req,
                                             httplib::Response& res) {
    auto wrapper = ruma::Ruma<ruma::RegisterRequest>::from_request(req);
    ruma::respond(res, register_route(&ctx, wrapper.value));
  });

  svr.Post("/_matrix/client/r0/login", [](const httplib::Request& req,
                                          httplib::Response& res) {
    auto wrapper = ruma::Ruma<ruma::LoginRequest>::from_request(req);
    ruma::respond(res, login_route(&ctx, wrapper.value));
  });

  svr.Get("/_matrix/client/r0/directory/room/:room_alias",
          [](const httplib::Request& req, httplib::Response& res) {
            const std::string room_alias = req.path_params.at("room_alias");
            if (room_alias != "#room:localhost") {
              ruma::respond(res, ruma::json{{"errcode", "M_NOT_FOUND"},
                                            {"error", "Room not found."}},
                            404);
              return;
            }
            ruma::respond(res, ruma::json{{"room_id", "!xclkjvdlfj:localhost"},
                                          {"servers", ruma::json::array({"localhost"})}});
          });

  svr.Post(R"(/_matrix/client/r0/rooms/(.+)/join)",
           [](const httplib::Request& req, httplib::Response& res) {
             ruma::respond(res, ruma::json{{"room_id", req.matches[1]}});
           });

  svr.Put(R"(/_matrix/client/r0/rooms/(.+)/send/(.+)/(.+))",
          [](const httplib::Request& req, httplib::Response& res) {
            // dbg!(body.0)
            std::cout << "[debug] content: " << req.body << "\n";
            ruma::respond(res, ruma::json{{"event_id", "$randomeventid"}});
          });

  std::cout << "[info] port: 8000\n";
  svr.listen("127.0.0.1", 8000);
}
