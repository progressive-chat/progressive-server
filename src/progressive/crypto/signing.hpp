#pragma once
#include <openssl/evp.h>

#include <cstdint>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <vector>

namespace progressive::crypto {

struct Ed25519Keypair {
  std::string version;
  std::vector<uint8_t> public_key;   // 32 bytes
  std::vector<uint8_t> private_key;  // 32 bytes (seed)

  std::string public_key_b64() const;
  std::string key_id() const;
};

Ed25519Keypair generate_ed25519_keypair(std::string_view version = "v0");

std::string ed25519_sign(std::string_view message, const std::vector<uint8_t>& private_key);

bool ed25519_verify(std::string_view message, std::string_view signature_b64,
                    const std::vector<uint8_t>& public_key);

nlohmann::json sign_json(const nlohmann::json& object, const Ed25519Keypair& key,
                         std::string_view origin);

bool verify_json_signature(const nlohmann::json& object, std::string_view origin,
                           std::string_view key_id, const std::vector<uint8_t>& public_key);

nlohmann::json make_key_server_json(std::string_view server_name, const Ed25519Keypair& key);

}  // namespace progressive::crypto
