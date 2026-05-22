#pragma once
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>

namespace progressive::crypto {

struct ServerKey {
  std::string server_name;
  std::string key_id;
  std::vector<uint8_t> public_key;
  std::vector<uint8_t> private_key;
  uint64_t valid_until_ts = 0;
};

ServerKey load_key(std::string_view path);

}
