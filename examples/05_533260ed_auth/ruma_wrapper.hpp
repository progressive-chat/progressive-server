// ruma_wrapper.hpp — translation of Conduit commit 533260ed, src/ruma_wrapper.rs
//
// THE AUTH COMMIT. Ruma<T> stopped being a plain body extractor:
//
//   pub struct Ruma<T: Outgoing> {
//       body: T::Incoming,
//       pub user_id: Option<UserId>,   // NEW: resolved during extraction
//   }
//
// When T::METADATA.requires_authentication, the extractor pulls the token from
// the Authorization header or ?access_token= query param and resolves it via
// Data::user_from_token; missing/unknown -> 401 Unauthorized (TODO comments in
// the original for M_MISSING_TOKEN / M_UNKNOWN_TOKEN).
//
// C++ mapping: each request struct declares `static constexpr bool
// REQUIRES_AUTH`; the dispatcher calls authenticate() before invoking handlers.

#pragma once

#include <map>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

namespace ruma {

class JsonObject {
 public:
  static JsonObject parse(const std::string& body);

  std::optional<std::string> string(const std::string& key) const;
  JsonObject object(const std::string& key) const;  // nested objects (login identifier)
  bool empty() const { return fields_.empty() && raw_values_.empty(); }

 private:
  std::map<std::string, std::string> fields_;
  std::map<std::string, std::string> raw_values_;
};

enum class ErrorKind {
  InvalidUsername,
  UserInUse,
  Forbidden,
  Unknown,
  NotFound,
  MissingToken,  // TODO upstream: M_MISSING_TOKEN not emitted yet (bare 401)
  UnknownToken,  // TODO upstream: M_UNKNOWN_TOKEN not emitted yet (bare 401)
};

struct Error {
  ErrorKind kind;
  std::string message;
  int status_code;
};

const char* errcode(ErrorKind kind);

struct RegisterRequest {
  static constexpr bool REQUIRES_AUTH = false;
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

// NEW: ruma_client_api::r0::session::login. The wire form (flattened in old
// ruma, nested under "identifier" today) is:
//   {"type":"m.login.password","identifier":{"type":"m.id.user","user":"neo"},
//    "password":"...", "device_id":"..."}
// UserInfo::MatrixId(username) becomes matrix_id + localpart below.
struct LoginRequest {
  static constexpr bool REQUIRES_AUTH = false;

  bool user_is_matrix_id = false;
  std::optional<std::string> user_localpart;
  std::optional<std::string> password;   // NOW CHECKED (was ignored)
  std::optional<std::string> device_id;
};

struct LoginResponse {
  std::string user_id;
  std::string access_token;
  std::optional<std::string> home_server;  // Option<String> -> omitted when None
  std::string device_id;
};

struct GetSupportedVersionsResponse {
  std::vector<std::string> versions;
  std::map<std::string, std::string>
      unstable_features;  // NEW in 34a53ce2; always empty at this point
};

struct GetAliasResponse {
  std::string room_id;
  std::vector<std::string> servers;
};

struct JoinRoomByIdRequest {
  static constexpr bool REQUIRES_AUTH = false;
  std::string room_id;
};

struct JoinRoomByIdResponse {
  std::string room_id;
};

struct CreateMessageEventRequest {
  static constexpr bool REQUIRES_AUTH = true;  // METADATA.requires_authentication

  std::string room_id;
  std::string event_type;
  std::string txn_id;
  std::string content_json;   // EventResult<Raw<JsonObject>>: Err -> "No content."
  std::string sender_user_id; // body.user_id.expect("user is authenticated")
};

struct CreateMessageEventResponse {
  std::string event_id;
};

template <typename T>
struct Ruma {
  T value{};
  std::optional<std::string> user_id;  // NEW in 533260ed

  static Ruma from_body(const std::string& body);
};

template <typename T>
struct MatrixResult {
  std::variant<T, Error> result;

  static MatrixResult ok(T value) { return MatrixResult{std::move(value)}; }
  static MatrixResult err(Error e) { return MatrixResult{std::move(e)}; }
};

}  // namespace ruma
