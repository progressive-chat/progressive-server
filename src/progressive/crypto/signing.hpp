#pragma once
#include <string>
#include <string_view>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <vector>
#include <cstdint>

namespace progressive::crypto {

struct SigningKey {
  std::string version;
  std::vector<uint8_t> seed;

  SigningKey(std::string ver, std::vector<uint8_t> seed_)
    : version(std::move(ver)), seed(std::move(seed_)) {}
};

nlohmann::json sign_json(const nlohmann::json& object, const SigningKey& key, std::string_view origin);
bool verify_json(const nlohmann::json& object, std::string_view origin, std::string_view server_name);

nlohmann::json generate_signing_key();

}
