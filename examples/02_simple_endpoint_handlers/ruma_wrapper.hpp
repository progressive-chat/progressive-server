// ruma_wrapper.hpp — translation of Conduit commit cd777af4, src/ruma_wrapper.rs
//
// This commit added two things to the wrapper:
//
// 1. ruma's `Error` type (errcode + message + HTTP status), which handlers
//    return when a request violates the spec.
// 2. `MatrixResult<T>` — a Responder wrapping Result<T, Error>, letting every
//    route handler be fallible. In C++: std::variant<T, Error> plus a shared
//    respond() that turns either side into an HttpResponse.
//
// The Ruma<T> body extractor from step 1 is unchanged.

#pragma once

#include <map>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace ruma {

// Minimal top-level JSON object reader (unchanged from step 1).
class JsonObject {
 public:
  static JsonObject parse(const std::string& body);

  std::optional<std::string> string(const std::string& key) const;

 private:
  std::map<std::string, std::string> fields_;
};

// --- NEW in cd777af4: typed errors -------------------------------------------
//
// Rust: ruma_client_api::error::{Error, ErrorKind}. Only the two kinds this
// commit actually raises are enumerated; the real enum has dozens.

enum class ErrorKind {
  InvalidUsername,
  NotFound,
};

struct Error {
  ErrorKind kind;
  std::string message;
  int status_code;
};

const char* errcode(ErrorKind kind);  // "M_INVALID_USERNAME", "M_NOT_FOUND"

// --- request/response types --------------------------------------------------

// ruma_client_api::r0::account::register.
struct RegisterRequest {
  std::optional<std::string> username;
  std::optional<std::string> password;
  std::optional<std::string> device_id;
};

struct RegisterResponse {
  std::string access_token;
  std::string home_server;  // deprecated field name kept verbatim from the spec era
  std::string user_id;
  std::string device_id;
};

// NEW: ruma_client_api::unversioned::get_supported_versions.
struct GetSupportedVersionsResponse {
  std::vector<std::string> versions;
};

// NEW: ruma_client_api::r0::alias::get_alias. Path parameter instead of body.
struct GetAliasResponse {
  std::string room_id;
  std::vector<std::string> servers;
};

// NEW: ruma_client_api::r0::membership::join_room_by_id.
struct JoinRoomByIdRequest {
  std::string room_id;
};

struct JoinRoomByIdResponse {
  std::string room_id;
};

// NEW: ruma_client_api::r0::message::create_message_event.
struct CreateMessageEventRequest {
  std::string room_id;
  std::string event_type;
  std::string txn_id;
  std::string content_json;  // raw body; ruma parsed it, we log it like dbg! did
};

struct CreateMessageEventResponse {
  std::string event_id;
};

// Ruma<T>: deserializes the JSON body into T before the handler runs.
template <typename T>
struct Ruma {
  T value{};

  static Ruma from_body(const std::string& body);
};

// --- NEW: MatrixResult<T> ----------------------------------------------------
//
// Rust: pub struct MatrixResult<T>(pub Result<T, Error>);
template <typename T>
struct MatrixResult {
  std::variant<T, Error> result;

  static MatrixResult ok(T value) { return MatrixResult{std::move(value)}; }
  static MatrixResult err(Error e) { return MatrixResult{std::move(e)}; }
};

}  // namespace ruma
