// main.cpp — translation of Conduit commit cd777af4, src/main.rs
//
// "feat: simple endpoint handlers". Deltas from the initial commit:
//   * four new stub routes (versions, get_alias, join, send)
//   * register validates the localpart and can fail with M_INVALID_USERNAME
//   * handlers return MatrixResult<T> so they can fail with typed errors

#include "ruma_wrapper.hpp"

#include <iostream>

namespace {

bool localpart_valid(const std::string& localpart) {
  // What UserId's TryFrom checked in ruma-identifiers 0.14.
  if (localpart.empty()) return false;
  for (const char c : localpart) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '=' || c == '-' || c == '/' ||
                    c == '+';
    if (!ok) return false;
  }
  return true;
}

ruma::MatrixResult<ruma::GetSupportedVersionsResponse> get_supported_versions_route() {
  return ruma::MatrixResult<ruma::GetSupportedVersionsResponse>::ok(
      ruma::GetSupportedVersionsResponse{.versions = {"r0.6.0"}});
}

ruma::MatrixResult<ruma::RegisterResponse> register_route(
    const ruma::RegisterRequest& body) {
  const std::string user_id =
      "@" + body.username.value_or("randomname") + ":localhost";
  if (!localpart_valid(body.username.value_or("randomname"))) {
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::InvalidUsername,
        .message = "Username was invalid. ",
        .status_code = 400,  // trailing space verbatim from this commit
    });
  }

  return ruma::MatrixResult<ruma::RegisterResponse>::ok(ruma::RegisterResponse{
      .access_token = "randomtoken",
      .home_server = "localhost",
      .user_id = user_id,
      .device_id = body.device_id.value_or("randomid"),
  });
}

ruma::MatrixResult<ruma::GetAliasResponse> get_alias_route(
    const std::string& room_alias) {
  // Hardcoded directory, verbatim from the commit.
  if (room_alias != "#room:localhost") {
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
    const std::string& room_id) {
  return ruma::MatrixResult<ruma::JoinRoomByIdResponse>::ok(
      ruma::JoinRoomByIdResponse{.room_id = room_id});
}

ruma::MatrixResult<ruma::CreateMessageEventResponse> create_message_event_route(
    const httplib::Request& req) {
  // dbg!(body.0)
  std::cout << "[debug] content: " << req.body << "\n";
  return ruma::MatrixResult<ruma::CreateMessageEventResponse>::ok(
      ruma::CreateMessageEventResponse{.event_id = "$randomeventid"});
}

}  // namespace

int main() {
  httplib::Server svr;

  svr.Get("/_matrix/client/versions", [](const httplib::Request&, httplib::Response& res) {
    ruma::respond(res, get_supported_versions_route());
  });

  svr.Post("/_matrix/client/r0/register", [](const httplib::Request& req,
                                             httplib::Response& res) {
    auto wrapper = ruma::Ruma<ruma::RegisterRequest>::from_request(req);
    ruma::respond(res, register_route(wrapper.value));
  });

  // #[get("/_matrix/client/r0/directory/room/<room_alias>")]
  svr.Get(R"(/_matrix/client/r0/directory/room/(.*))",
          [](const httplib::Request& req, httplib::Response& res) {
            ruma::respond(res, get_alias_route(req.matches[1]));
          });

  // #[post(".../rooms/<_room_id>/join")]
  svr.Post(R"(/_matrix/client/r0/rooms/(.+)/join)",
           [](const httplib::Request& req, httplib::Response& res) {
             ruma::respond(res, join_room_by_id_route(req.matches[1]));
           });

  // #[put(".../rooms/<_room_id>/send/<_event_type>/<_txn_id>")]
  svr.Put(R"(/_matrix/client/r0/rooms/(.+)/send/(.+)/(.+))",
          [](const httplib::Request& req, httplib::Response& res) {
            ruma::respond(res, create_message_event_route(req));
          });

  svr.listen("127.0.0.1", 8000);
}
