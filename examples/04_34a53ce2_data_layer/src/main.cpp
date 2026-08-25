// main.cpp — translation of Conduit commit 34a53ce2, src/main.rs
//
// "Better database structure": handlers get State<Data> and call named domain
// methods (user_exists/user_add/hostname); hostname lives in the database and
// is appended when building user ids; login accepts full @user:server ids or
// bare localparts.

#include "data.hpp"
#include "ruma_wrapper.hpp"

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
  Data* data;
};

ruma::MatrixResult<ruma::RegisterResponse> register_route(
    Context* ctx, const ruma::RegisterRequest& body) {
  const std::string localpart = body.username.value_or("randomname");
  std::string user_id;
  if (!user_id_from_localpart(localpart, &user_id)) {
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::InvalidUsername,
        .message = "Username was invalid.",
        .status_code = 400,
    });
  }
  user_id = "@" + localpart + ":" + ctx->data->hostname();

  if (ctx->data->user_exists(user_id)) {
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::UserInUse,
        .message = "Desired user ID is already taken.",
        .status_code = 400,
    });
  }

  ctx->data->user_add(user_id, body.password);

  return ruma::MatrixResult<ruma::RegisterResponse>::ok(ruma::RegisterResponse{
      .access_token = "randomtoken",
      .home_server = ctx->data->hostname(),
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

  std::string username = *body.user_localpart;
  if (username.find(':') == std::string::npos) {
    username = "@" + username + ":" + ctx->data->hostname();
  }
  std::string user_id;
  const bool valid = [&] {
    if (username.size() < 3 || username[0] != '@') return false;
    const size_t colon = username.find(':');
    return colon != std::string::npos && colon > 1 && colon + 1 < username.size() &&
           user_id_from_localpart(username.substr(1, colon - 1), &user_id);
  }();
  user_id = username;
  if (!valid) {
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Unknown,
        .message = "Bad login type.",
        .status_code = 400,
    });
  }
  if (!ctx->data->user_exists(user_id)) {
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
      ".local/share/conduit-step04";

  // let data = Data::load_or_create(); data.set_hostname("localhost");
  static Data data = Data::load_or_create(data_dir);
  data.set_hostname("localhost");
  static Context ctx{&data};

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
