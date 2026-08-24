// main.cpp — translation of Conduit commit fa322689, src/main.rs
//
// "feat: save pdus": PDUs are saved in a pduid -> pdus map, roomid_pduleaves
// tracks the leaves of the event graph and eventid_pduid maps event ids to
// pdu ids. Event ids are REAL reference hashes now:
//   "$" + base64url(sha256(canonical(redact(event))))  [OpenSSL SHA-256]
// Also new: GET /sync (upstream timeline todo!() — we return stored PDUs)
// and the catch-all OPTIONS route returning 404.

#include "crypto.hpp"
#include "data.hpp"
#include "ruma_wrapper.hpp"
#include "utils.hpp"

#include <string_view>

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

constexpr std::string_view kPlaceholderToken = "TODO:randomtoken";
constexpr std::string_view kPlaceholderDeviceId = "TODO:randomdeviceid";

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
  user_id = "@" + localpart + ":" + ctx->data->hostname();

  if (ctx->data->user_exists(user_id)) {
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::UserInUse,
        .message = "Desired user ID is already taken.",
        .status_code = 400,
    });
  }

  // Create user
  ctx->data->user_add(user_id, body.password);

  // Generate new device id if the user didn't specify one; add device; token.
  const std::string device_id =
      body.device_id.value_or(std::string{kPlaceholderDeviceId});
  ctx->data->device_add(user_id, device_id);
  const std::string token{kPlaceholderToken};
  ctx->data->token_replace(user_id, device_id, token);

  return ruma::MatrixResult<ruma::RegisterResponse>::ok(ruma::RegisterResponse{
      .access_token = token,
      .home_server = ctx->data->hostname(),
      .user_id = std::move(user_id),
      .device_id = device_id,
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

  // Check password — the new thing in 533260ed.
  if (!body.password) {
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Unknown,
        .message = "Bad login type.",
        .status_code = 400,
    });
  }
  if (const auto correct_password = ctx->data->password_get(user_id)) {
    if (*body.password != *correct_password) {
      std::cerr << "[debug] Invalid password.\n";
      return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
          .kind = ruma::ErrorKind::Unknown,
          .message = "",   // empty message upstream!
          .status_code = 403,
      });
    }
  } else {
    std::cerr << "[debug] UserId does not exist (has no assigned password).\n";
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Forbidden,
        .message = "",
        .status_code = 403,
    });
  }

  const std::string device_id =
      body.device_id.value_or(std::string{kPlaceholderDeviceId});
  ctx->data->device_add(user_id, device_id);
  const std::string token{kPlaceholderToken};
  ctx->data->token_replace(user_id, device_id, token);

  return ruma::MatrixResult<ruma::LoginResponse>::ok(ruma::LoginResponse{
      .user_id = user_id,
      .access_token = token,
      .home_server = ctx->data->hostname(),
      .device_id = device_id,
  });
}

ruma::MatrixResult<ruma::CreateMessageEventResponse> create_message_event_route(
    Context* ctx, const ruma::CreateMessageEventRequest& body) {
  // Check if content is valid (into_result().unwrap() upstream).
  json content;
  try {
    content = json::parse(body.content_json);
    if (!content.is_object()) throw std::runtime_error("no object");
  } catch (...) {
    std::cerr << "[debug] No content.\n";
    return ruma::MatrixResult<ruma::CreateMessageEventResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::NotFound,
        .message = "No content.",
        .status_code = 400,
    });
  }

  // Construct event; placeholder event_id replaced after hashing.
  json event{
      {"type", "m.room.message"},
      {"content", std::move(content)},
      {"event_id", "$thiswillbefilledinlater"},
      {"origin_server_ts", utils::millis_since_unix_epoch()},
      {"room_id", body.room_id},
      {"sender", body.sender_user_id},
      {"unsigned", json::object()},
  };

  // Generate event id via reference hash.
  const std::string event_id = crypto::reference_hash(event);
  event["event_id"] = event_id;

  // Add PDU to the graph.
  ctx->data->pdu_append(event_id, body.room_id, std::move(event));

  return ruma::MatrixResult<ruma::CreateMessageEventResponse>::ok(
      ruma::CreateMessageEventResponse{.event_id = event_id});
}

ruma::MatrixResult<ruma::SyncResponse> sync_route(Context* ctx) {
  ruma::SyncResponse resp;
  resp.joined_room_id = "!roomid:" + ctx->data->hostname();
  resp.timeline_events = ctx->data->pdus_all();
  return ruma::MatrixResult<ruma::SyncResponse>::ok(std::move(resp));
}

// Ruma<T>'s FromRequest auth half: token from header or query.
std::optional<std::string> extract_token(const httplib::Request& req) {
  if (req.has_header("Authorization")) {
    std::string v = req.get_header_value("Authorization");
    constexpr std::string_view kBearer = "Bearer ";
    if (v.rfind(kBearer, 0) == 0) {
      v.erase(0, kBearer.size());
      if (!v.empty()) return v;
    }
  } else if (req.has_param("access_token")) {
    const std::string token = req.get_param_value("access_token");
    if (!token.empty()) return token;
  }
  return std::nullopt;  // TODO upstream: M_MISSING_TOKEN
}

}  // namespace

int main() {
  const char* home = ::getenv("HOME");
  const std::filesystem::path data_dir =
      (home ? std::filesystem::path{home} : std::filesystem::path{"/tmp"}) /
      ".local/share/conduit-step06";

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
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            auto wrapper = ruma::Ruma<ruma::CreateMessageEventRequest>::from_request(req);
            const auto token = extract_token(req);
            if (!token || !(wrapper.user_id = ctx.data->user_from_token(*token))) {
              ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                            {"error", "Unrecognised access token"}},
                            401);
              return;
            }
            wrapper.value.room_id = req.matches[1];
            wrapper.value.event_type = req.matches[2];
            wrapper.value.txn_id = req.matches[3];
            wrapper.value.sender_user_id = *wrapper.user_id;
            ruma::respond(res, create_message_event_route(&ctx, wrapper.value));
          });

  svr.Get("/_matrix/client/r0/sync", [&ctx](const httplib::Request& req,
                                            httplib::Response& res) {
    auto wrapper = ruma::Ruma<ruma::SyncRequest>::from_request(req);
    const auto token =
        req.has_header("Authorization")
            ? std::optional<std::string>(req.get_header_value("Authorization"))
            : std::nullopt;
    if (!token || !(wrapper.user_id = ctx.data->user_from_token(*token))) {
      ruma::respond(res, ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                                    {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    ruma::respond(res, sync_route(&ctx));
  });

  // NEW: OPTIONS catch-all — upstream answers with a plain 404 M_NOT_FOUND.
  svr.Options(R"(.*)", [](const httplib::Request&, httplib::Response& res) {
    ruma::respond(res, ruma::json{{"errcode", "M_NOT_FOUND"},
                                  {"error", "Room not found."}},
                  404);
  });

  std::cout << "[info] port: 8000\n";
  svr.listen("127.0.0.1", 8000);
}
