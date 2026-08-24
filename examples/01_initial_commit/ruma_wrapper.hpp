// ruma_wrapper.hpp — translation of Conduit's initial-commit src/ruma_wrapper.rs
//
// Rust original (ruma 0.6, Rocket 0.4):
//
//   pub struct Ruma<T> { ... }          // Rocket request guard that deserializes
//                                       // the JSON body into a ruma request type
//   impl<T: Outgoing> FromRequest for Ruma<T> {
//       fn from_request(req: &Request) -> Result<Self, Self::Error> {
//           let body = req.remote().unwrap()...; // read + serde_json::from_str::<T>
//       }
//   }
//
// In C++ there is no framework doing this for us, so `Ruma<T>` becomes a small
// template the route handler calls explicitly: parse the HTTP body into typed
// structs first, hand the typed value to the handler. Same idea, explicit steps.

#pragma once

#include <map>
#include <optional>
#include <string>
#include <utility>

namespace ruma {

// Minimal top-level JSON object reader: enough for one stub endpoint.
// A real homeserver (Conduit, tuwunel, progressive-server) uses a full parser —
// serde_json in Rust, nlohmann::json in progressive-server. Hand-rolled here so
// step 1 has zero dependencies and you can see what a parser actually does.
class JsonObject {
 public:
  static JsonObject parse(const std::string& body);

  std::optional<std::string> string(const std::string& key) const;

 private:
  std::map<std::string, std::string> fields_;
};

// ruma_client_api::r0::account::register::Request (only fields used at step 1).
struct RegisterRequest {
  std::optional<std::string> username;
  std::optional<std::string> password;
  std::optional<std::string> device_id;
};

// ruma_client_api::r0::account::register::Response.
struct RegisterResponse {
  std::string access_token;
  std::string home_server;  // deprecated field name kept verbatim from the spec era
  std::string user_id;      // ruma: OwnedUserId — strong-typed; plain string until a later step
  std::string device_id;
};

// The extractor itself. Rust: `fn register_route(body: Ruma<RegisterRequest>)`.
// C++: construct it from the raw body before entering the handler.
template <typename T>
struct Ruma {
  T value{};

  static Ruma from_body(const std::string& body);
};

}  // namespace ruma
