#pragma once
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>

#include "../storage/database.hpp"
#include "../types/requester.hpp"

namespace progressive::auth {

struct AuthResult {
  Requester requester;
  std::string user_id;
  bool success = false;
  std::string error;
  std::string errcode;
};

class Auth {
public:
  explicit Auth(storage::DatabasePool& db);

  AuthResult validate_token(std::string_view token);
  std::string create_token(std::string_view user_id);
  nlohmann::json register_user(std::string_view user_id, std::string_view password);
  std::optional<Requester> get_user_by_token(std::string_view token);
  bool verify_password(std::string_view password, std::string_view hash) const;

private:
  storage::DatabasePool& db_;
  std::string hash_password(std::string_view password) const;
};

}  // namespace progressive::auth
