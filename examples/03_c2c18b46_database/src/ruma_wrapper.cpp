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
// serde_json::from_str::<LoginRequest>: {"type":"m.login.password",
// "identifier":{"type":"m.id.user","user":"neo"}, ...} (flattened legacy form
// preferred, like old ruma).
template <>
Ruma<LoginRequest> Ruma<LoginRequest>::from_request(const httplib::Request& req) {
  LoginRequest parsed;
  if (!req.body.empty()) {
    const json body = json::parse(req.body, nullptr, false);
    if (!body.is_discarded() && body.is_object()) {
      if (auto type = body.find("type"); type != body.end() && *type == "m.id.user") {
        if (auto user = body.find("user"); user != body.end() && user->is_string()) {
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

void respond(httplib::Response& res, const json& body, int status) {
  res.status = status;
  res.set_content(body.dump(), "application/json");
}

json to_json(const RegisterResponse& r) {
  return json{{"access_token", r.access_token},
              {"device_id", r.device_id},
              {"home_server", r.home_server},
              {"user_id", r.user_id}};
}

json to_error_json(const Error& e) {
  return json{{"errcode", errcode(e.kind)}, {"error", e.message}};
}

}  // namespace ruma

// The MatrixResult Responder: Ok -> 200 + typed response, Err -> status+error.
namespace ruma {
void respond(httplib::Response& res, const MatrixResult<RegisterResponse>& result) {
  if (result.result.index() == 0) {
    respond(res, to_json(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}
}  // namespace ruma

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

}  // namespace ruma

// Responder overloads.
namespace ruma {
void respond(httplib::Response& res, const MatrixResult<LoginResponse>& result) {
  if (result.result.index() == 0) {
    respond(res, to_json(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}
void respond(httplib::Response& res,
             const MatrixResult<GetSupportedVersionsResponse>& result) {
  if (result.result.index() == 0) {
    respond(res, to_json(std::get<0>(result.result)));
  } else {
    const Error& e = std::get<1>(result.result);
    respond(res, to_error_json(e), e.status_code);
  }
}
}  // namespace ruma
