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
  InvalidParam,      // NEW in fa9e127a
  UserDeactivated,   // NEW in b8193984
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
  // NEW in 6e5b35ea: appservice bridges set this to true.
  bool from_appservice = false;
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
  std::string device_id;     // NEW in 4954df3c: resolved from token for txn dedup
};

struct CreateMessageEventResponse {
  std::string event_id;
};

// NEW in fa322689: GET /_matrix/client/r0/sync (requires auth).
struct SyncRequest {
  static constexpr bool REQUIRES_AUTH = true;
};

// abcce95d: multiple joined rooms (per-room timelines) + invited rooms with
// stripped state events.
struct SyncResponse {
  std::string joined_room_id;  // legacy single-room field kept for step-6 style use
  std::vector<std::string> timeline_events;
  std::string prev_batch;  // NEW in 23cb550d: pagination token for the timeline
  bool limited = false;    // NEW in b4d65ab6: true on a room's first sync
  std::map<std::string, SyncResponse> joined;
  std::map<std::string, SyncResponse> invited;
  std::map<std::string, SyncResponse> knocked;  // NEW in 21af83e: knocked rooms
  std::vector<std::string> stripped_state;
};

// NEW in 23cb550d: GET /_matrix/client/r0/rooms/<id>/messages
struct GetMessagesRequest {
  static constexpr bool REQUIRES_AUTH = true;
  std::string room_id;   // path param
  std::string from;      // stream position to paginate from
  std::string dir = "b"; // b (backwards) supported; f -> todo!() upstream
};

struct GetMessagesResponse {
  std::string start;
  std::string end;  // empty when no more events
  std::vector<std::string> chunk;
};

// NEW in abcce95d (+ folded prerequisite createRoom):
struct CreateRoomRequest {
  static constexpr bool REQUIRES_AUTH = true;
  std::optional<std::string> name;
  std::optional<std::string> topic;
  std::vector<std::string> invite;
  std::string visibility;         // NEW in 3aa0c8ed: "public" | "private"
  std::optional<std::string> room_alias_name;  // NEW in 3aa0c8ed
  std::optional<std::string> preset;  // "public_chat" | "private_chat" | "trusted_private_chat"
  // NEW in b5e3185 (MSC4289): list of additional creators
  std::optional<std::vector<std::string>> additional_creators;
  // NEW in 660dd9c: room version to use for the new room
  std::optional<std::string> room_version;
  std::string user_id;  // resolved from token
  // NEW in 6e5b35ea: appservice bridges set this to true.
  bool from_appservice = false;
};

// NEW in 3aa0c8ed: PUT /directory/room/<alias>
struct CreateAliasRequest {
  static constexpr bool REQUIRES_AUTH = false;  // upstream had no auth here yet
  std::string room_alias;
  std::string room_id;
};

struct DeleteAliasRequest {
  static constexpr bool REQUIRES_AUTH = false;
  std::string room_alias;
};

// NEW in df55e8ed: POST /rooms/<id>/upgrade
struct RoomUpgradeRequest {
  static constexpr bool REQUIRES_AUTH = true;
  std::string new_version;
  std::string room_id;     // from URL path
  std::string user_id;     // resolved from token
};

struct RoomUpgradeResponse {
  std::string replacement_room;
};

// GET /_matrix/client/r0/directory/list/room/<room_id>
struct GetVisibilityRequest {
  std::string room_id;
};

struct CreateRoomResponse {
  std::string room_id;
};

struct InviteRequest {
  static constexpr bool REQUIRES_AUTH = true;
  std::string room_id;   // path param
  std::string user_id;   // sender, from token
  std::string target;    // InvitationRecipient::UserId
  std::string reason;    // optional invite reason (NEW in 346913268f)
};

struct SearchUsersRequest {
  static constexpr bool REQUIRES_AUTH = true;
  std::string search_term;
};

// NEW in 4cc0a070: profile displayname routes.
struct SetDisplaynameRequest {
  static constexpr bool REQUIRES_AUTH = true;
  std::string user_id;            // path param (must equal token user upstream)
  std::optional<std::string> displayname;
};

struct GetMemberEventsRequest {
  static constexpr bool REQUIRES_AUTH = true;
  std::string room_id;  // path param
};

struct PublicRoomsResponse {
  nlohmann::json chunk = nlohmann::json::array();
  size_t total_room_count_estimate = 0;
  size_t federation_rooms = 0;  // NEW in b0d9ccdb: rooms fetched from matrix.org
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
void respond(httplib::Response& res,
             const MatrixResult<CreateRoomResponse>& result);
void respond(httplib::Response& res,
             const MatrixResult<PublicRoomsResponse>& result);
void respond(httplib::Response& res, const MatrixResult<SyncResponse>& result);
void respond(httplib::Response& res,
             const MatrixResult<GetMessagesResponse>& result);

}  // namespace ruma
