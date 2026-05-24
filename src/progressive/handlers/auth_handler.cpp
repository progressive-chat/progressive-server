#include "auth_handler.hpp"

#include <openssl/sha.h>

#include "../util/base64.hpp"
#include "../util/random.hpp"
#include "../util/time.hpp"

namespace progressive::handlers {

AuthHandler::AuthHandler(storage::DatabasePool& db) : db_(db) {}

std::string AuthHandler::gen_token(const char* prefix, int len) const {
  return std::string(prefix) + "_" + util::random_token(len);
}

std::string AuthHandler::create_access_token(std::string_view user_id, std::string_view device_id) {
  auto tok = gen_token("syt", 64);
  db_.execute("INSERT INTO access_tokens (token,user_id,device_id) VALUES ('" + tok + "','" +
              std::string(user_id) + "','" + std::string(device_id) + "')");
  return tok;
}

std::string AuthHandler::create_refresh_token(std::string_view user_id,
                                              std::string_view access_token) {
  auto tok = gen_token("syr", 48);
  uint64_t expires = util::now_ms() + 2592000000LL;  // 30 days
  db_.execute("INSERT INTO refresh_tokens (token,user_id,access_token_id,expires_at) VALUES ('" +
              tok + "','" + std::string(user_id) + "','" + std::string(access_token) + "'," +
              std::to_string(expires) + ")");
  return tok;
}

std::string AuthHandler::refresh_token(std::string_view refresh_token) {
  std::string rt(refresh_token);
  auto rows = db_.query(
      "SELECT user_id,next_token_id,expires_at FROM refresh_tokens WHERE token='" + rt + "'");
  if (rows.empty())
    return "";
  auto& r = rows[0];
  if (r["expires_at"].is_number() &&
      r["expires_at"].template get<int64_t>() < static_cast<int64_t>(util::now_ms()))
    return "";  // expired

  std::string uid = r["user_id"].get<std::string>();
  auto new_access = create_access_token(uid);
  auto new_refresh = create_refresh_token(uid, new_access);

  db_.execute("UPDATE refresh_tokens SET next_token_id='" + new_refresh + "' WHERE token='" + rt +
              "'");

  // Store new refresh token for this user
  return new_access;
}

std::string AuthHandler::create_login_token(std::string_view user_id) {
  auto tok = gen_token("syl", 24);
  db_.execute("INSERT INTO open_id_tokens (token,user_id,expires_at) VALUES ('" + tok + "','" +
              std::string(user_id) + "'," + std::to_string(util::now_ms() + 300000) +
              ")");  // 5 min
  return tok;
}

std::string AuthHandler::consume_login_token(std::string_view token) {
  std::string t(token);
  auto rows = db_.query("SELECT user_id,expires_at FROM open_id_tokens WHERE token='" + t + "'");
  if (rows.empty())
    return "";
  auto& r = rows[0];
  if (r["expires_at"].is_number() &&
      r["expires_at"].template get<int64_t>() < static_cast<int64_t>(util::now_ms()))
    return "";
  std::string uid = r["user_id"].get<std::string>();
  db_.execute("DELETE FROM open_id_tokens WHERE token='" + t + "'");
  return uid;
}

void AuthHandler::delete_access_token(std::string_view token) {
  db_.execute("DELETE FROM access_tokens WHERE token='" + std::string(token) + "'");
}

void AuthHandler::delete_access_tokens_for_user(std::string_view user_id,
                                                std::string_view except_token) {
  std::string uid(user_id);
  std::string ex(except_token);
  db_.execute("DELETE FROM access_tokens WHERE user_id='" + uid + "' AND token!='" + ex + "'");
  db_.execute("DELETE FROM refresh_tokens WHERE user_id='" + uid + "'");
}

bool AuthHandler::check_user_exists(std::string_view user_id) {
  auto rows = db_.query("SELECT id FROM users WHERE id='" + std::string(user_id) + "'");
  return !rows.empty();
}

std::string AuthHandler::hash_password(std::string_view password) const {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(password.data()), password.size(), hash);
  return base64::encode(
      std::string_view(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH));
}

bool AuthHandler::validate_hash(std::string_view password, std::string_view hash) const {
  return hash_password(password) == hash;
}

}  // namespace progressive::handlers
