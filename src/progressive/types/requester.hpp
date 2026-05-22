#pragma once
#include <optional>
#include <string>

#include "matrix_id.hpp"

namespace progressive {

struct Requester {
  UserID user;
  std::optional<std::string> access_token_id;
  bool is_guest = false;
  std::optional<std::string> device_id;
  std::optional<std::string> app_service_id;

  Requester(UserID user, std::optional<std::string> access_token_id = {})
      : user(std::move(user)), access_token_id(std::move(access_token_id)) {}
};

}  // namespace progressive
