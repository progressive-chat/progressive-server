#pragma once
#include <string>
#include <string_view>

#include "../storage/database.hpp"
#include "../util/random.hpp"

namespace progressive::handlers {

class AuthHandler {
public:
  explicit AuthHandler(storage::DatabasePool& db);

  // synapse/handlers/auth.py line-by-line ports
  std::string refresh_token(std::string_view refresh_token);
  std::string create_access_token(std::string_view user_id, std::string_view device_id = "");
  std::string create_refresh_token(std::string_view user_id, std::string_view access_token);
  std::string create_login_token(std::string_view user_id);
  std::string consume_login_token(std::string_view token);
  void delete_access_token(std::string_view token);
  void delete_access_tokens_for_user(std::string_view user_id, std::string_view except_token = "");
  bool check_user_exists(std::string_view user_id);
  std::string hash_password(std::string_view password) const;
  bool validate_hash(std::string_view password, std::string_view hash) const;
  void add_threepid(std::string_view user_id, std::string_view medium, std::string_view address);
  void delete_local_threepid(std::string_view user_id, std::string_view medium,
                             std::string_view address);
  bool is_user_approved(std::string_view user_id);
  bool can_change_password();
  std::string generate_access_token();
  std::string generate_refresh_token();
  void delete_access_tokens_for_devices(std::string_view user_id,
                                        const std::vector<std::string>& devices);

private:
  storage::DatabasePool& db_;
  std::string gen_token(const char* prefix, int len) const;
};

}  // namespace progressive::handlers
