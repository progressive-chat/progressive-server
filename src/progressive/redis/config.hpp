#pragma once
#include <string>
#include <string_view>

namespace progressive::redis {

struct RedisConfig {
  std::string host = "127.0.0.1";
  int port = 6379;
  std::string password;
  int db = 0;
  bool enabled = false;
};

}  // namespace progressive::redis
