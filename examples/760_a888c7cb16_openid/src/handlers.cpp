// handlers.cpp — POST /register and /login logic (fa9e127a state).
//
//   register: Argon2id-hash the password before storing; hash failure ->
//             M_INVALID_PARAM "Password did not met requirements" [sic].
//   login:    argon2 verify against stored hash; mismatch -> M_UNKNOWN "" 403,
//             no account -> M_FORBIDDEN "" 403 (both verbatim upstream).

#include "routes.hpp"
#include "utils.hpp"

#include <argon2.h>

#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace {

// Folded prerequisite (ddcd423e): real random tokens/devices instead of the
// early "TODO:" placeholders, so multiple users can be tested at once.
constexpr std::string_view kPlaceholderDeviceId = "TODO:randomdeviceid";

std::string new_token() { return utils::random_string(32); }

bool localpart_valid(const std::string& localpart) {
  if (localpart.empty()) return false;
  // NEW in 3248efbe4b: enforce the strict user-ID grammar (ruma's
  // UserId::validate_strict) instead of the lenient historical grammar. The
  // strict grammar allows only a-z 0-9 . _ = - /; '+' (and uppercase, '~')
  // are rejected. Dropping '+' is the only change from the prior lenient set.
  for (const char c : localpart) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                    c == '.' || c == '_' || c == '=' || c == '-' || c == '/';
    if (!ok) return false;
  }
  return true;
}

bool full_user_id_valid(const std::string& user_id, std::string* normalized) {
  const size_t colon = user_id.find(':');
  if (user_id.size() < 3 || user_id[0] != '@' || colon == std::string::npos ||
      colon == 1 || colon + 1 >= user_id.size())
    return false;
  if (!localpart_valid(user_id.substr(1, colon - 1))) return false;
  *normalized = user_id;
  return true;
}

}  // namespace

std::optional<std::string> extract_token(const httplib::Request& req) {
  if (req.has_header("Authorization")) {
    std::string v = req.get_header_value("Authorization");
    constexpr std::string_view kBearer = "Bearer ";
    if (v.rfind(kBearer, 0) == 0) {
      v.erase(0, kBearer.size());
      if (!v.empty()) return v;
    }
  } else if (req.has_param("access_token")) {
    const std::string token = req.get_param_value("access_token");
    if (!token.empty()) return token;
  }
  return std::nullopt;  // TODO upstream: should be M_MISSING_TOKEN
}

ruma::MatrixResult<ruma::RegisterResponse> register_route(
    Context* ctx, const ruma::RegisterRequest& body) {
  const std::string localpart = body.username.value_or("randomname");
  std::string user_id;
  if (!localpart_valid(localpart)) {
    std::cerr << "[debug] Username was invalid\n";
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::InvalidUsername,
        .message = "Username was invalid.",
        .status_code = 400,
    });
  }
  user_id = "@" + localpart + ":" + ctx->data->hostname();

  if (ctx->data->user_exists(user_id)) {
    std::cerr << "[debug] ID already taken\n";
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::UserInUse,
        .message = "Desired user ID is already taken.",
        .status_code = 400,
    });
  }

  // Store hashed passwords (fa9e127a): Argon2id before persisting.
  const std::string password = body.password.value_or("");
  auto hash = utils::calculate_hash(password);
  if (!hash) {
    return ruma::MatrixResult<ruma::RegisterResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::InvalidParam,
        .message = "Password did not met requirements",  // [sic] upstream
        .status_code = 400,
    });
  }

  // Create user
  ctx->data->user_add(user_id, *hash);

  // Generate new device id if the user didn't specify one; add device; token.
  const std::string device_id =
      body.device_id.value_or(utils::random_string(10));
  ctx->data->device_add(user_id, device_id);
  const std::string token = new_token();
  ctx->data->token_replace(user_id, device_id, token);

  return ruma::MatrixResult<ruma::RegisterResponse>::ok(ruma::RegisterResponse{
      .access_token = token,
      .home_server = ctx->data->hostname(),
      .user_id = std::move(user_id),
      .device_id = device_id,
  });
}

ruma::MatrixResult<ruma::LoginResponse> login_route(Context* ctx,
                                                    const ruma::LoginRequest& body) {
  if (!body.user_is_matrix_id) {
    std::cerr << "[debug] Bad login type\n";
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Unknown,
        .message = "Bad login type.",
        .status_code = 400,
    });
  }

  std::string username = *body.user_localpart;
  if (username.find(':') == std::string::npos) {
    username = "@" + username + ":" + ctx->data->hostname();
  }

  std::string user_id;
  if (!full_user_id_valid(username, &user_id)) {
    std::cerr << "[debug] Invalid UserId.\n";
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Unknown,
        .message = "Bad login type.",
        .status_code = 400,
    });
  }

  // Check password against the stored Argon2id hash (fa9e127a).
  if (const auto hash = ctx->data->password_hash_get(user_id)) {
    if (hash->empty()) {
      // b8193984: deactivated accounts store an empty password hash.
      std::cerr << "[debug] The user has been deactivated.\n";
      return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
          .kind = ruma::ErrorKind::UserDeactivated,
          .message = "The user has been deactivated",
          .status_code = 403,
      });
    }
    const bool password_supplied = body.password.has_value();
    // argon2::verify_encoded(&hash, password.as_bytes()).unwrap_or(false)
    const bool hash_matches =
        password_supplied &&
        argon2id_verify(hash->c_str(), body.password->data(),
                        body.password->size()) == ARGON2_OK;

    if (!hash_matches) {
      std::cerr << "[debug] Invalid password.\n";
      // Upstream's own test asserts errcode M_FORBIDDEN here.
      return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
          .kind = ruma::ErrorKind::Forbidden,
          .message = "",
          .status_code = 403,
      });
    }
  } else {
    std::cerr << "[debug] UserId does not exist (has no assigned password).\n";
    return ruma::MatrixResult<ruma::LoginResponse>::err(ruma::Error{
        .kind = ruma::ErrorKind::Forbidden,
        .message = "",
        .status_code = 403,
    });
  }

  const std::string device_id =
      body.device_id.value_or(utils::random_string(10));
  ctx->data->device_add(user_id, device_id);
  const std::string token = new_token();
  ctx->data->token_replace(user_id, device_id, token);

  return ruma::MatrixResult<ruma::LoginResponse>::ok(ruma::LoginResponse{
      .user_id = user_id,
      .access_token = token,
      .home_server = ctx->data->hostname(),
      .device_id = device_id,
  });
}

void handle_register(Context* ctx, const httplib::Request& req, httplib::Response& res) {
  auto wrapper = ruma::Ruma<ruma::RegisterRequest>::from_request(req);
  ruma::respond(res, register_route(ctx, wrapper.value));
}

void handle_login(Context* ctx, const httplib::Request& req, httplib::Response& res) {
  auto wrapper = ruma::Ruma<ruma::LoginRequest>::from_request(req);
  ruma::respond(res, login_route(ctx, wrapper.value));
}
