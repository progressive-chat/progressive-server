#include "auth.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <nlohmann/json.hpp>
#include <string>

#include "../util/base64.hpp"
#include "../util/random.hpp"
#include "../util/time.hpp"
#include "../util/token.hpp"

namespace progressive::auth {

static std::string sql_escape(std::string_view s) {
  std::string out;
  for (char c : s) {
    if (c == '\'')
      out += "''";
    else
      out += c;
  }
  return out;
}

Auth::Auth(storage::DatabasePool& db) : db_(db) {}

std::string Auth::hash_password(std::string_view password) const {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), hash);
  return base64::encode(
      std::string_view(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH));
}

bool Auth::verify_password(std::string_view password, std::string_view hash) const {
  return hash_password(password) == hash;
}

AuthResult Auth::validate_token(std::string_view token) {
  AuthResult result;

  auto rows = db_.query(
      "SELECT user_id, device_id FROM access_tokens "
      "WHERE token = '" +
      sql_escape(token) + "'");

  if (rows.empty() || !rows[0].contains("user_id") || rows[0]["user_id"].is_null()) {
    result.error = "Unknown token";
    result.errcode = "M_UNKNOWN_TOKEN";
    return result;
  }

  std::string user_id = rows[0]["user_id"].get<std::string>();
  result.user_id = user_id;
  result.success = true;
  result.requester = Requester(UserID::from_string(user_id));
  result.requester.access_token_id = std::string(token);
  return result;
}

std::string Auth::create_token(std::string_view user_id) {
  auto token = util::generate_access_token();
  db_.execute(
      "INSERT INTO access_tokens (token, user_id) "
      "VALUES ('" +
      sql_escape(token) + "', '" + sql_escape(user_id) + "')");
  return token;
}

nlohmann::json Auth::register_user(std::string_view user_id, std::string_view password) {
  // Check if user exists
  auto rows = db_.query("SELECT id FROM users WHERE id = '" + sql_escape(user_id) + "'");
  if (!rows.empty() && !rows[0]["id"].is_null()) {
    return {{"errcode", "M_USER_IN_USE"}, {"error", "User ID already taken"}};
  }

  std::string pw_hash = hash_password(password);
  uint64_t now = util::now_ms();

  db_.execute(
      "INSERT INTO users (id, password_hash, creation_ts) "
      "VALUES ('" +
      sql_escape(user_id) + "', '" + sql_escape(pw_hash) + "', " + std::to_string(now) + ")");

  std::string token = create_token(user_id);
  std::string uid(user_id);

  return {{"user_id", uid},
          {"access_token", token},
          {"home_server", "localhost"},  // TODO: from config
          {"device_id", ""}};
}

std::optional<Requester> Auth::get_user_by_token(std::string_view token) {
  auto result = validate_token(token);
  if (!result.success)
    return std::nullopt;
  return result.requester;
}

}  // namespace progressive::auth
