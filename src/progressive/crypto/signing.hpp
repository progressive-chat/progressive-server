#pragma once
#include <openssl/evp.h>

#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace progressive::crypto {

struct SigningKey {
  std::string version;
  std::vector<uint8_t> seed;

  SigningKey(std::string ver, std::vector<uint8_t> seed_)
      : version(std::move(ver)), seed(std::move(seed_)) {}
};

nlohmann::json sign_json(const nlohmann::json& object, const SigningKey& key,
                         std::string_view origin);
bool verify_json(const nlohmann::json& object, std::string_view origin,
                 std::string_view server_name);

nlohmann::json generate_signing_key();

}  // namespace progressive::crypto
