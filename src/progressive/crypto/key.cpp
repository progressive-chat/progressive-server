#include "key.hpp"

#include <fstream>
#include <nlohmann/json.hpp>

namespace progressive::crypto {

ServerKey load_key(std::string_view path) {
  std::ifstream f{std::string(path)};
  if (!f)
    throw std::runtime_error("cannot open key file");
  auto j = nlohmann::json::parse(f);
  ServerKey k;
  k.server_name = j.value("server_name", "");
  k.key_id = j.value("key_id", "ed25519:a_aaaa");
  return k;
}

}  // namespace progressive::crypto
