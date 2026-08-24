// main.cpp — translation of Conduit commit 6264628c, src/main.rs
//
//   #[post("/_matrix/client/r0/register", data = "<body>")]
//   fn register_route(body: Ruma<register::Request>) -> Ruma<register::Response> {
//       Ruma(register::Response {
//           access_token: "42".to_owned(),
//           home_server: "deprecated".to_owned(),
//           user_id: "@yourrequestedid:homeserver.com".try_into().unwrap(),
//           device_id: body.device_id.clone().unwrap_or_default(),
//       })
//   }
//
// Rocket's launch() becomes httplib's listen().

#include "ruma_wrapper.hpp"

#include <iostream>

static ruma::MatrixResult<ruma::RegisterResponse> register_route(
    const ruma::RegisterRequest& body) {
  return ruma::MatrixResult<ruma::RegisterResponse>::ok(ruma::RegisterResponse{
      .access_token = "42",
      .home_server = "deprecated",
      .user_id = "@yourrequestedid:homeserver.com",
      .device_id = body.device_id.value_or(""),
  });
}

int main() {
  httplib::Server svr;

  svr.Post("/_matrix/client/r0/register", [](const httplib::Request& req,
                                             httplib::Response& res) {
    const auto wrapper = ruma::Ruma<ruma::RegisterRequest>::from_request(req);
    ruma::respond(res, register_route(wrapper.value));
  });

  std::cout << "[info] POST /_matrix/client/r0/register available.\n";
  svr.listen("127.0.0.1", 8000);
}
