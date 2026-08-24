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
#include <vector>

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

// NEW in cd777af4:
struct GetSupportedVersionsResponse {
  std::vector<std::string> versions;
};

struct GetAliasResponse {
  std::string room_id;
  std::vector<std::string> servers;
};

struct JoinRoomByIdResponse {
  std::string room_id;
};

struct CreateMessageEventResponse {
  std::string event_id;
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
json to_json(const GetSupportedVersionsResponse& r);
json to_json(const GetAliasResponse& r);
json to_json(const JoinRoomByIdResponse& r);
json to_json(const CreateMessageEventResponse& r);
json to_error_json(const Error& e);

// The Responder impls Rocket would run (one overload per response type).
void respond(httplib::Response& res, const json& body, int status = 200);

template <typename T>
void respond(httplib::Response& res, const MatrixResult<T>& result) {
  if (result.result.index() == 0) {
    respond(res, to_json(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}

}  // namespace ruma
