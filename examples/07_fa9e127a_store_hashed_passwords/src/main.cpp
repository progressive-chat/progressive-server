// main.cpp — translation of Conduit commit fa322689, src/main.rs
//
// "feat: save pdus": PDUs are saved in a pduid -> pdus map, roomid_pduleaves
// tracks the leaves of the event graph and eventid_pduid maps event ids to
// pdu ids. Event ids are REAL reference hashes now:
//   "$" + base64url(sha256(canonical(redact(event))))  [OpenSSL SHA-256]
// Also new: GET /sync (upstream timeline todo!() — we return stored PDUs)
// and the catch-all OPTIONS route returning 404.

#include "crypto.hpp"
#include "routes.hpp"
#include "data.hpp"
#include "ruma_wrapper.hpp"
#include "utils.hpp"

#include <argon2.h>

#include <httplib.h>

#include <csignal>

using json = nlohmann::json;
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace {

constexpr uint16_t kListenPort = 8000;

// "TODO:randomtoken" / "TODO:randomdeviceid" — verbatim placeholders.
ruma::MatrixResult<ruma::GetSupportedVersionsResponse> get_supported_versions_route() {
  // Trimmed back to a single version in fa322689.
  return ruma::MatrixResult<ruma::GetSupportedVersionsResponse>::ok(
      ruma::GetSupportedVersionsResponse{
          .versions = {"r0.6.0"},
          .unstable_features = {},
      });
}

ruma::MatrixResult<ruma::GetAliasResponse> get_alias_route(
    const std::string& room_alias) {
  // Hardcoded directory, verbatim from the original commits.
  if (room_alias != "#room:localhost") {
    std::cerr << "[debug] Room not found.\n";
    return ruma::MatrixResult<ruma::GetAliasResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::NotFound,
        .message = "Room not found.",
        .status_code = 404,
    });
  }
  return ruma::MatrixResult<ruma::GetAliasResponse>::ok(ruma::GetAliasResponse{
      .room_id = "!xclkjvdlfj:localhost",
      .servers = {"localhost"},
  });
}

ruma::MatrixResult<ruma::JoinRoomByIdResponse> join_room_by_id_route(
    const ruma::JoinRoomByIdRequest& body) {
  return ruma::MatrixResult<ruma::JoinRoomByIdResponse>::ok(
      ruma::JoinRoomByIdResponse{.room_id = body.room_id});
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

}  // namespace

int main(int argc, char** argv) {
  ::signal(SIGPIPE, SIG_IGN);

  int port = static_cast<int>(kListenPort);
  std::string dir_override;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--port" && i + 1 < argc) port = std::stoi(argv[++i]);
    if (arg == "--data-dir" && i + 1 < argc) dir_override = argv[++i];
  }

  std::filesystem::path data_dir;
  if (!dir_override.empty()) {
    data_dir = dir_override;
  } else {
    const char* home = ::getenv("HOME");
    data_dir = (home ? std::filesystem::path{home} : std::filesystem::path{"/tmp"}) /
               ".local/share/conduit-step07";
  }

  static Data data = Data::load_or_create(data_dir);
  data.set_hostname("localhost");
  static Context ctx{&data};

  httplib::Server svr;

  svr.Get("/_matrix/client/versions", [](const httplib::Request&, httplib::Response& res) {
    ruma::respond(res, get_supported_versions_route());
  });

  svr.Post("/_matrix/client/r0/register", [](const httplib::Request& req,
                                             httplib::Response& res) {
    handle_register(&ctx, req, res);
  });

  svr.Post("/_matrix/client/r0/login", [](const httplib::Request& req,
                                          httplib::Response& res) {
    handle_login(&ctx, req, res);
  });

  svr.Get("/_matrix/client/r0/directory/room/:room_alias",
          [](const httplib::Request& req, httplib::Response& res) {
            ruma::respond(res, get_alias_route(req.path_params.at("room_alias")));
          });

  svr.Post(R"(/_matrix/client/r0/rooms/(.+)/join)",
           [](const httplib::Request& req, httplib::Response& res) {
             ruma::JoinRoomByIdRequest body;
             body.room_id = req.matches[1];
             ruma::respond(res, join_room_by_id_route(body));
           });

  svr.Put(R"(/_matrix/client/r0/rooms/(.+)/send/(.+)/(.+))",
          [&ctx](const httplib::Request& req, httplib::Response& res) {
            auto wrapper = ruma::Ruma<ruma::CreateMessageEventRequest>::from_request(req);
            const auto token = extract_token(req);
            if (!token || !(wrapper.user_id = ctx.data->user_from_token(*token))) {
              ruma::respond(res,
                            ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
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
    const auto token = extract_token(req);
    if (!token || !(wrapper.user_id = ctx.data->user_from_token(*token))) {
      ruma::respond(res,
                    ruma::json{{"errcode", "M_UNKNOWN_TOKEN"},
                               {"error", "Unrecognised access token"}},
                    401);
      return;
    }
    ruma::respond(res, sync_route(&ctx));
  });

  // NEW: OPTIONS catch-all — upstream answers with a plain 404 M_NOT_FOUND.
  svr.Options(R"(.*)", [](const httplib::Request&, httplib::Response& res) {
    ruma::respond(res,
                  ruma::json{{"errcode", "M_NOT_FOUND"}, {"error", "Room not found."}},
                  404);
  });

  std::cout << "[info] port: " << kListenPort << "\n[info] hostname: "
            << data.hostname() << std::endl;
  svr.listen("127.0.0.1", static_cast<uint16_t>(port));
}

