// ruma_wrapper.hpp — as of Conduit commit 34a53ce2
//
// Deltas from c2c18b46:
//
//   * get_supported_versions::Response gained `unstable_features`
//     (HashMap<String,String>) — serialized here as an empty object.
//   * Ruma<T> also grew a headers field and Debug impl upstream; cosmetic and
//     omitted here.
//   * Everything else unchanged from step 3.

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
  JsonObject object(const std::string& key) const;  // NEW: nested objects

 private:
  std::map<std::string, std::string> fields_;
  std::map<std::string, std::string> raw_values_;
};

enum class ErrorKind {
  InvalidUsername,
  UserInUse,  // NEW
  Forbidden,  // NEW
  Unknown,    // NEW
  NotFound,
};

struct Error {
  ErrorKind kind;
  std::string message;
  int status_code;
};

const char* errcode(ErrorKind kind);

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

// NEW: ruma_client_api::r0::session::login. The wire form (flattened in old
// ruma, nested under "identifier" today) is:
//   {"type":"m.login.password","identifier":{"type":"m.id.user","user":"neo"},
//    "password":"...", "device_id":"..."}
// UserInfo::MatrixId(username) becomes matrix_id + localpart below.
struct LoginRequest {
  bool user_is_matrix_id = false;
  std::optional<std::string> user_localpart;
  std::optional<std::string> password;
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
  std::string room_id;
};

struct JoinRoomByIdResponse {
  std::string room_id;
};

struct CreateMessageEventRequest {
  std::string room_id;
  std::string event_type;
  std::string txn_id;
  std::string content_json;
};

struct CreateMessageEventResponse {
  std::string event_id;
};

template <typename T>
struct Ruma {
  T value{};

  static Ruma from_body(const std::string& body);
};

template <typename T>
struct MatrixResult {
  std::variant<T, Error> result;

  static MatrixResult ok(T value) { return MatrixResult{std::move(value)}; }
  static MatrixResult err(Error e) { return MatrixResult{std::move(e)}; }
};

}  // namespace ruma
