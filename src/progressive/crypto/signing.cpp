#include "signing.hpp"
#include "../json/canonical.hpp"
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <cstring>
#include "../util/base64.hpp"

namespace progressive::crypto {

static std::string sha256_b64(std::string_view data) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
  return base64::encode(std::string_view(reinterpret_cast<const char*>(hash), SHA256_DIGEST_LENGTH));
}

nlohmann::json sign_json(const nlohmann::json& object, const SigningKey& key, std::string_view origin) {
  auto signed_obj = object;
  if (!signed_obj.contains("signatures")) signed_obj["signatures"] = nlohmann::json::object();
  if (!signed_obj["signatures"].contains(origin)) signed_obj["signatures"][origin] = nlohmann::json::object();
  if (!signed_obj.contains("unsigned")) signed_obj["unsigned"] = nlohmann::json::object();

  // Remove existing signatures for clean signing
  signed_obj["signatures"][origin].erase(key.version);
  signed_obj["unsigned"].erase("age_ts");

  std::string canon = json::canonical_json(signed_obj);
  auto sig = sha256_b64(canon); // placeholder — real ed25519 in full impl

  signed_obj["signatures"][origin][key.version] = sig;
  return signed_obj;
}

bool verify_json(const nlohmann::json& object, std::string_view origin, std::string_view) {
  // Placeholder: full ed25519 verification in future
  if (!object.contains("signatures")) return false;
  if (!object["signatures"].contains(origin)) return false;
  return true;
}

nlohmann::json generate_signing_key() {
  // Placeholder: generate ed25519 keypair in full impl
  return nlohmann::json::object({
    {"version", "v0"},
    {"key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
  });
}

}
