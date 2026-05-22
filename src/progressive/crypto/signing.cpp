#include "signing.hpp"

#include <openssl/err.h>

#include <iostream>

#include "../json/canonical.hpp"
#include "../util/base64.hpp"

namespace progressive::crypto {

Ed25519Keypair generate_ed25519_keypair(std::string_view version) {
  Ed25519Keypair kp;
  kp.version = std::string(version);

  EVP_PKEY* pkey = nullptr;
  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (!ctx)
    throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

  if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("ed25519 keygen failed");
  }
  EVP_PKEY_CTX_free(ctx);

  size_t pub_len = 32;
  kp.public_key.resize(pub_len);
  EVP_PKEY_get_raw_public_key(pkey, kp.public_key.data(), &pub_len);

  size_t priv_len = 32;
  kp.private_key.resize(priv_len);
  EVP_PKEY_get_raw_private_key(pkey, kp.private_key.data(), &priv_len);

  EVP_PKEY_free(pkey);
  return kp;
}

std::string Ed25519Keypair::public_key_b64() const {
  return base64::encode(
      std::string_view(reinterpret_cast<const char*>(public_key.data()), public_key.size()));
}

std::string Ed25519Keypair::key_id() const {
  return "ed25519:" + version;
}

std::string ed25519_sign(std::string_view message, const std::vector<uint8_t>& private_key) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, private_key.data(),
                                                private_key.size());
  if (!pkey)
    throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_MD_CTX_new failed");
  }

  if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_DigestSignInit failed");
  }

  size_t sig_len = 64;
  std::vector<uint8_t> sig(sig_len);
  if (EVP_DigestSign(md_ctx, sig.data(), &sig_len, reinterpret_cast<const uint8_t*>(message.data()),
                     message.size()) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_DigestSign failed");
  }
  sig.resize(sig_len);

  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);

  return base64::encode(std::string_view(reinterpret_cast<const char*>(sig.data()), sig.size()));
}

bool ed25519_verify(std::string_view message, std::string_view signature_b64,
                    const std::vector<uint8_t>& public_key) {
  auto sig = base64::decode(signature_b64);

  EVP_PKEY* pkey =
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size());
  if (!pkey)
    return false;

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  int ok = EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey);
  if (ok <= 0) {
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return false;
  }

  ok = EVP_DigestVerify(md_ctx, sig.data(), sig.size(),
                        reinterpret_cast<const uint8_t*>(message.data()), message.size());

  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  return ok == 1;
}

nlohmann::json sign_json(const nlohmann::json& object, const Ed25519Keypair& key,
                         std::string_view origin) {
  auto signed_obj = object;
  if (!signed_obj.contains("signatures"))
    signed_obj["signatures"] = nlohmann::json::object();
  if (!signed_obj["signatures"].contains(origin))
    signed_obj["signatures"][origin] = nlohmann::json::object();
  if (!signed_obj.contains("unsigned"))
    signed_obj["unsigned"] = nlohmann::json::object();

  // Remove existing signatures for clean re-signing
  signed_obj["signatures"][origin].erase(key.key_id());
  signed_obj["unsigned"].erase("age_ts");

  std::string canon = json::canonical_json(signed_obj);

  // Ed25519 sign the canonical JSON bytes
  auto sig = ed25519_sign(canon, key.private_key);

  signed_obj["signatures"][origin][key.key_id()] = sig;
  return signed_obj;
}

bool verify_json_signature(const nlohmann::json& object, std::string_view origin,
                           std::string_view key_id, const std::vector<uint8_t>& public_key) {
  if (!object.contains("signatures"))
    return false;
  if (!object["signatures"].contains(origin))
    return false;
  if (!object["signatures"][origin].contains(key_id))
    return false;

  std::string sig = object["signatures"][origin][key_id].get<std::string>();

  // Rebuild canonical JSON without the signature being verified
  auto obj_copy = object;
  obj_copy["signatures"][origin].erase(std::string(key_id));
  obj_copy["unsigned"].erase("age_ts");

  std::string canon = json::canonical_json(obj_copy);
  return ed25519_verify(canon, sig, public_key);
}

nlohmann::json make_key_server_json(std::string_view server_name, const Ed25519Keypair& key) {
  nlohmann::json j;
  j["server_name"] = server_name;
  j["valid_until_ts"] = 3000000000000ULL;

  nlohmann::json verify_keys;
  nlohmann::json vk;
  vk["key"] = key.public_key_b64();
  verify_keys[key.key_id()] = vk;
  j["verify_keys"] = verify_keys;
  j["old_verify_keys"] = nlohmann::json::object();

  // Self-sign
  nlohmann::json self;
  self["server_name"] = server_name;
  self["verify_keys"] = verify_keys;
  self["old_verify_keys"] = nlohmann::json::object();

  std::string canon = json::canonical_json(self);
  auto sig = ed25519_sign(canon, key.private_key);

  j["signatures"] = nlohmann::json::object();
  j["signatures"][server_name] = nlohmann::json::object();
  j["signatures"][server_name][key.key_id()] = sig;

  return j;
}

}  // namespace progressive::crypto
