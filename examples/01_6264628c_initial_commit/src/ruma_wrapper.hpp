// ruma_wrapper.hpp — translation of Conduit's src/ruma_wrapper.rs
//
// Rust original:
//
//   pub struct Ruma<T>(pub T);   // Rocket FromData guard: JSON body -> ruma type
//   pub struct MatrixResult<T>(pub Result<T, Error>);  // Responder
//
// C++: httplib gives us raw requests; `Ruma<T>::from_request` does the body
// deserialization with nlohmann (our serde_json), MatrixResult serializes the
// typed response or a spec-shaped error.

#pragma once

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <variant>

namespace ruma {

using json = nlohmann::json;  // sorted object keys => canonical-ish output

enum class ErrorKind {
  InvalidUsername,
  UserInUse,
  Forbidden,
  Unknown,
  NotFound,
};

struct Error {
  ErrorKind kind;
  std::string message;
  int status_code;
};

const char* errcode(ErrorKind kind);

// --- typed requests/responses (the ruma-client-api structs) ------------------

struct RegisterRequest {
  std::optional<std::string> username;
  std::optional<std::string> password;
  std::optional<std::string> device_id;
};

struct RegisterResponse {
  std::string access_token;
  std::string home_server;
  std::string user_id;
  std::string device_id;
};

template <typename T>
struct Ruma {
  T value{};

  static Ruma from_request(const httplib::Request& req);
};

// Result<T, Error>, serialized by respond().
template <typename T>
struct MatrixResult {
  std::variant<T, Error> result;

  static MatrixResult ok(T value) { return MatrixResult{std::move(value)}; }
  static MatrixResult err(Error e) { return MatrixResult{std::move(e)}; }
};

// The Serialize impls serde would derive:
json to_json(const RegisterResponse& r);
json to_error_json(const Error& e);

// The Responder impl Rocket would run.
void respond(httplib::Response& res, const json& body, int status = 200);
void respond(httplib::Response& res, const MatrixResult<RegisterResponse>& result);

}  // namespace ruma
