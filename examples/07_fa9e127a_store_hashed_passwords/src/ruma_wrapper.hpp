// ruma_wrapper.hpp — translation of Conduit's src/ruma_wrapper.rs as of
// commit fa322689.
//
//   Ruma<T>       : body extractor + auth resolution (user_id since 533260ed)
//   MatrixResult<T>: Result<T, Error> responder
//
// Each request struct carries REQUIRES_AUTH, standing in for ruma's
// Endpoint::METADATA.requires_authentication.

#pragma once

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace ruma {

using json = nlohmann::json;  // sorted object keys => canonical dumps

enum class ErrorKind {
  InvalidUsername,
  UserInUse,
  Forbidden,
  Unknown,
  NotFound,
  InvalidParam,  // NEW in fa9e127a
  MissingToken,
  UnknownToken,
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

struct LoginRequest {
  static constexpr bool REQUIRES_AUTH = false;

  bool user_is_matrix_id = false;
  std::optional<std::string> user_localpart;
  std::optional<std::string> password;   // checked since 533260ed
  std::optional<std::string> device_id;
};

struct LoginResponse {
  std::string user_id;
  std::string access_token;
  std::optional<std::string> home_server;  // omitted when None, like serde skip
  std::string device_id;
};

struct GetSupportedVersionsResponse {
  std::vector<std::string> versions;
  std::map<std::string, std::string> unstable_features;
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

// NEW in 533260ed / fa322689:
struct CreateMessageEventRequest {
  static constexpr bool REQUIRES_AUTH = true;  // METADATA.requires_authentication
  std::string room_id;
  std::string event_type;
  std::string txn_id;
  std::string content_json;   // EventResult: invalid -> "No content."
  std::string sender_user_id; // body.user_id.expect("user is authenticated")
};

struct CreateMessageEventResponse {
  std::string event_id;
};

// NEW in fa322689: GET /_matrix/client/r0/sync (requires auth).
struct SyncRequest {
  static constexpr bool REQUIRES_AUTH = true;
};

struct SyncResponse {
  std::string joined_room_id;
  std::vector<std::string> timeline_events;  // canonical PDU JSON
};

template <typename T>
struct Ruma {
  T value{};
  std::optional<std::string> user_id;  // NEW in 533260ed

  static Ruma from_request(const httplib::Request& req);
};

template <typename T>
struct MatrixResult {
  std::variant<T, Error> result;

  static MatrixResult ok(T value) { return MatrixResult{std::move(value)}; }
  static MatrixResult err(Error e) { return MatrixResult{std::move(e)}; }
};

json to_json(const RegisterResponse& r);
json to_json(const LoginResponse& r);
json to_json(const GetSupportedVersionsResponse& r);
json to_json(const GetAliasResponse& r);
json to_json(const JoinRoomByIdResponse& r);
json to_json(const CreateMessageEventResponse& r);
json to_error_json(const Error& e);

void respond(httplib::Response& res, const json& body, int status = 200);

void respond(httplib::Response& res, const MatrixResult<RegisterResponse>& result);
void respond(httplib::Response& res, const MatrixResult<LoginResponse>& result);
void respond(httplib::Response& res,
             const MatrixResult<GetSupportedVersionsResponse>& result);
void respond(httplib::Response& res, const MatrixResult<GetAliasResponse>& result);
void respond(httplib::Response& res, const MatrixResult<JoinRoomByIdResponse>& result);
void respond(httplib::Response& res,
             const MatrixResult<CreateMessageEventResponse>& result);
void respond(httplib::Response& res, const MatrixResult<SyncResponse>& result);

}  // namespace ruma
