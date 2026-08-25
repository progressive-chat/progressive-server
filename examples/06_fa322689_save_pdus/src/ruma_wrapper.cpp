#include "ruma_wrapper.hpp"

namespace ruma {

const char* errcode(ErrorKind kind) {
  switch (kind) {
    case ErrorKind::InvalidUsername: return "M_INVALID_USERNAME";
    case ErrorKind::UserInUse: return "M_USER_IN_USE";
    case ErrorKind::Forbidden: return "M_FORBIDDEN";
    case ErrorKind::Unknown: return "M_UNKNOWN";
    case ErrorKind::NotFound: return "M_NOT_FOUND";
  }
  return "M_UNKNOWN";
}

// serde_json::from_str::<RegisterRequest>(body)

template <>
Ruma<RegisterRequest> Ruma<RegisterRequest>::from_request(const httplib::Request& req) {
  RegisterRequest parsed;
  if (!req.body.empty()) {
    const json body = json::parse(req.body, nullptr, false);
    if (!body.is_discarded() && body.is_object()) {
      if (auto it = body.find("username"); it != body.end() && it->is_string())
        parsed.username = it->get<std::string>();
      if (auto it = body.find("password"); it != body.end() && it->is_string())
        parsed.password = it->get<std::string>();
      if (auto it = body.find("device_id"); it != body.end() && it->is_string())
        parsed.device_id = it->get<std::string>();
    }
  }
  Ruma<RegisterRequest> wrapper;
  wrapper.value = std::move(parsed);
  return wrapper;
}

// serde_json::from_str::<LoginRequest>: flattened legacy form preferred, like
// old ruma; modern "identifier" nesting accepted too.
template <>
Ruma<LoginRequest> Ruma<LoginRequest>::from_request(const httplib::Request& req) {
  LoginRequest parsed;
  if (!req.body.empty()) {
    const json body = json::parse(req.body, nullptr, false);
    if (!body.is_discarded() && body.is_object()) {
      auto type = body.find("type");
      if (type != body.end() && *type == "m.id.user") {
        auto user = body.find("user");
        if (user != body.end() && user->is_string()) {
          parsed.user_is_matrix_id = true;
          parsed.user_localpart = user->get<std::string>();
        }
      } else {
        auto ident = body.find("identifier");
        if (ident != body.end() && ident->is_object()) {
          auto id_type = ident->find("type");
          auto id_user = ident->find("user");
          if (id_type != ident->end() && *id_type == "m.id.user" &&
              id_user != ident->end() && id_user->is_string()) {
            parsed.user_is_matrix_id = true;
            parsed.user_localpart = id_user->get<std::string>();
          }
        }
      }
      if (auto it = body.find("password"); it != body.end() && it->is_string())
        parsed.password = it->get<std::string>();
      if (auto it = body.find("device_id"); it != body.end() && it->is_string())
        parsed.device_id = it->get<std::string>();
    }
  }
  Ruma<LoginRequest> wrapper;
  wrapper.value = std::move(parsed);
  return wrapper;
}

// NEW in fa322689: /sync has no body to parse.
template <>
Ruma<SyncRequest> Ruma<SyncRequest>::from_request(const httplib::Request&) {
  return Ruma<SyncRequest>{};
}

// NEW in 533260ed: raw content kept; EventResult validity checked in handler.
template <>
Ruma<CreateMessageEventRequest> Ruma<CreateMessageEventRequest>::from_request(
    const httplib::Request& req) {
  Ruma<CreateMessageEventRequest> wrapper;
  wrapper.value.content_json = req.body;
  return wrapper;
}

json to_json(const RegisterResponse& r) {
  return json{{"access_token", r.access_token},
              {"device_id", r.device_id},
              {"home_server", r.home_server},
              {"user_id", r.user_id}};
}

json to_json(const LoginResponse& r) {
  json out{{"access_token", r.access_token},
           {"device_id", r.device_id},
           {"user_id", r.user_id}};
  if (r.home_server) out["home_server"] = *r.home_server;
  return out;
}

json to_json(const GetSupportedVersionsResponse& r) {
  return json{{"versions", r.versions}, {"unstable_features", r.unstable_features}};
}

json to_json(const GetAliasResponse& r) {
  return json{{"room_id", r.room_id}, {"servers", r.servers}};
}

json to_json(const JoinRoomByIdResponse& r) {
  return json{{"room_id", r.room_id}};
}

json to_json(const CreateMessageEventResponse& r) {
  return json{{"event_id", r.event_id}};
}

json to_error_json(const Error& e) {
  return json{{"errcode", errcode(e.kind)}, {"error", e.message}};
}

void respond(httplib::Response& res, const json& body, int status) {
  res.status = status;
  res.set_content(body.dump(), "application/json");
}

namespace {

template <typename T>
void respond_result(httplib::Response& res, const MatrixResult<T>& result,
                    json (*serialize)(const T&)) {
  if (result.result.index() == 0) {
    respond(res, serialize(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}

}  // namespace

void respond(httplib::Response& res, const MatrixResult<RegisterResponse>& result) {
  respond_result(res, result, to_json);
}
void respond(httplib::Response& res, const MatrixResult<LoginResponse>& result) {
  respond_result(res, result, to_json);
}
void respond(httplib::Response& res,
             const MatrixResult<GetSupportedVersionsResponse>& result) {
  respond_result(res, result, to_json);
}
void respond(httplib::Response& res,
             const MatrixResult<CreateMessageEventResponse>& result) {
  respond_result(res, result, to_json);
}

// sync_events::Response skeleton — only join.<room>.timeline.events filled
// (upstream left timeline.events as todo!(); we return the stored PDUs).
void respond(httplib::Response& res,
             const MatrixResult<GetAliasResponse>& result) {
  if (result.result.index() == 0) {
    respond(res, to_json(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}

void respond(httplib::Response& res,
             const MatrixResult<JoinRoomByIdResponse>& result) {
  if (result.result.index() == 0) {
    respond(res, to_json(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}

void respond(httplib::Response& res, const MatrixResult<SyncResponse>& result) {
  if (result.result.index() != 0) {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
    return;
  }
  const SyncResponse& r = std::get<0>(result.result);

  json events = json::array();
  for (const auto& pdu : r.timeline_events) events.push_back(json::parse(pdu));

  json timeline = {{"events", std::move(events)}};
  json joined_room = {
      {"account_data", {{"events", json::array()}}},
      {"ephemeral", {{"events", json::array()}}},
      {"state", {{"events", json::array()}}},
      {"summary", json::object()},
      {"unread_notifications", json::object()},
      {"timeline", std::move(timeline)},
  };
  json join;
  join[r.joined_room_id] = std::move(joined_room);

  json out = {
      {"next_batch", ""},
      {"rooms",
       {{"invite", json::object()}, {"join", std::move(join)}, {"leave", json::object()}}},
      {"to_device", {{"events", json::array()}}},
  };
  respond(res, out);
}

}  // namespace ruma
