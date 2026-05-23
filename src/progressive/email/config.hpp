#pragma once
#include <string>
#include <string_view>

namespace progressive::email {

struct EmailConfig {
  std::string smtp_host;
  int smtp_port = 587;
  std::string smtp_user;
  std::string smtp_pass;
  std::string from_addr = "noreply@localhost";
  bool enabled = false;
};

}  // namespace progressive::email
