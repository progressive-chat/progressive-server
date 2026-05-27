// device_dehydration.cpp - Matrix Device Dehydration and MSC2697 Support
//
// Implements: device dehydration (create dehydrated device, store secret key
// material in database), rehydrate device on login (recover E2E keys from
// dehydrated device), upload device keys from dehydrated device, send
// to-device messages to dehydrated devices, key backup for dehydrated devices,
// cross-signing integration with master key, and MSC2697 API endpoints.
//
// Device dehydration allows a user to log out of all their devices while
// retaining the ability to decrypt messages received during the offline
// period. A "dehydrated device" holds the user's cryptographic identity
// in encrypted form, and on next login the client can "rehydrate" the
// device to recover missed messages.
//
// Workflow:
//   1. Client creates a dehydrated device (stores encrypted key material)
//   2. Client logs out
//   3. Server receives messages; can queue them for the dehydrated device
//   4. Client logs in again
//   5. Client rehydrates the device (recovers keys, decrypts queued messages)
//   6. Client deletes the dehydrated device (or it auto-expires)
//
// Based on: matrix-org/matrix-spec proposals (MSC 2697, MSC 3814, MSC 3861),
// synapse/handlers/device.py, synapse/storage/databases/main/devices.py,
// matrix-nio/crypto/dehydration.py, matrix-org/matrix-rust-sdk/
//
// Copyright (C) 2024-2026 Progressive Server contributors
// Licensed under AGPL v3

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <regex>
#include <set>
#include <shared_mutex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/curve25519.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/md5.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "progressive/storage/database.hpp"
#include "progressive/storage/databases/main/devices.hpp"
#include "progressive/storage/databases/main/end_to_end_keys.hpp"

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;

// ============================================================================
// Forward declarations
// ============================================================================
class DehydratedDeviceManager;
class DehydratedDeviceStore;
class DehydrationKeyManager;
class DehydratedDeviceService;

// ============================================================================
// Constants
// ============================================================================
namespace dehydration_constants {

// Dehydrated device algorithm identifier
constexpr const char* DEHYDRATION_ALGORITHM = "org.matrix.msc2697.v1.dehydrated_device";

// Default device ID prefix for dehydrated devices
constexpr const char* DEHYDRATED_DEVICE_PREFIX = "DEHYDRATED_";

// Maximum number of dehydrated devices per user
constexpr int MAX_DEHYDRATED_DEVICES_PER_USER = 1;

// Default expiry time for dehydrated devices (7 days in milliseconds)
constexpr int64_t DEFAULT_EXPIRY_MS = 7LL * 24LL * 3600LL * 1000LL;

// Maximum expiry time (28 days)
constexpr int64_t MAX_EXPIRY_MS = 28LL * 24LL * 3600LL * 1000LL;

// Minimum expiry time (1 hour)
constexpr int64_t MIN_EXPIRY_MS = 3600LL * 1000LL;

// Key sizes
constexpr size_t AES_KEY_LEN = 32;
constexpr size_t AES_IV_LEN = 16;
constexpr size_t HMAC_KEY_LEN = 32;
constexpr size_t HMAC_OUTPUT_LEN = 32;
constexpr size_t ED25519_PUBKEY_LEN = 32;
constexpr size_t ED25519_PRIVKEY_LEN = 32;
constexpr size_t ED25519_SIGNATURE_LEN = 64;
constexpr size_t CURVE25519_PUBKEY_LEN = 32;
constexpr size_t CURVE25519_PRIVKEY_LEN = 32;
constexpr size_t PBKDF2_SALT_LEN = 32;
constexpr size_t PBKDF2_KEY_LEN = 32;

// PBKDF2 iteration count for pickling the dehydration key
constexpr int DEHYDRATION_PICKLE_ITERATIONS = 500000;

// Field names
constexpr const char* FIELD_DEVICE_ID = "device_id";
constexpr const char* FIELD_USER_ID = "user_id";
constexpr const char* FIELD_DEVICE_DATA = "device_data";
constexpr const char* FIELD_DEVICE_KEYS = "device_keys";
constexpr const char* FIELD_ALGORITHM = "algorithm";
constexpr const char* FIELD_EXPIRES_AT = "expires_at";
constexpr const char* FIELD_CREATED_AT = "created_at";
constexpr const char* FIELD_RECLAIMED = "reclaimed";
constexpr const char* FIELD_PICKLE_KEY = "pickle_key";
constexpr const char* FIELD_SIGNATURES = "signatures";
constexpr const char* FIELD_CROSS_SIGNING_KEYS = "cross_signing_keys";
constexpr const char* FIELD_ONE_TIME_KEYS = "one_time_keys";
constexpr const char* FIELD_FALLBACK_KEYS = "fallback_keys";
constexpr const char* FIELD_MASTER_KEY = "master_key";
constexpr const char* FIELD_SELF_SIGNING_KEY = "self_signing_key";
constexpr const char* FIELD_USER_SIGNING_KEY = "user_signing_key";

// Dehydrated device states
enum class DehydratedDeviceState : int {
  PENDING = 0,     // Created but not yet used
  ACTIVE = 1,      // Actively receiving to-device messages
  RECLAIMED = 2,   // Rehydrated and claimed by a real device
  EXPIRED = 3,     // Past its expiry time
  REVOKED = 4      // Explicitly revoked by user
};

// Event types for dehydrated device protocol
constexpr const char* EVENT_TYPE_DEHYDRATED_DEVICE = "org.matrix.msc2697.v1.dehydrated_device";
constexpr const char* EVENT_TYPE_RECLAIM_DEVICE = "org.matrix.msc2697.v1.reclaim_device";
constexpr const char* EVENT_TYPE_DEHYDRATED_TO_DEVICE = "org.matrix.msc3814.v1.dehydrated_to_device";

// MSC2697 API endpoint paths
constexpr const char* API_DEHYDRATED_DEVICE = "/org.matrix.msc2697.v1/dehydrated_device";
constexpr const char* API_DEHYDRATED_DEVICE_EVENTS = "/org.matrix.msc2697.v1/dehydrated_device/events";
constexpr const char* API_DEHYDRATED_DEVICE_CLAIM = "/org.matrix.msc2697.v1/dehydrated_device/claim";
constexpr const char* API_DEHYDRATED_DEVICE_EXPORT = "/org.matrix.msc2697.v1/dehydrated_device/export";

// Cleanup interval for expired devices (1 hour in ms)
constexpr int64_t CLEANUP_INTERVAL_MS = 3600LL * 1000LL;

// Maximum to-device messages to queue per dehydrated device
constexpr int MAX_QUEUED_MESSAGES = 1000;

// Dehydrated device key types for upload
constexpr const char* KEY_TYPE_CURVE25519 = "curve25519";
constexpr const char* KEY_TYPE_SIGNED_CURVE25519 = "signed_curve25519";
constexpr const char* KEY_TYPE_ED25519 = "ed25519";

// Device signing algorithms
constexpr const char* SIGNING_ALGORITHM_ED25519 = "ed25519";

} // namespace dehydration_constants

// ============================================================================
// Anonymous namespace: utility helpers
// ============================================================================
namespace {

using namespace dehydration_constants;

// --------------------------------------------------------------------------
// Timing
// --------------------------------------------------------------------------
int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

int64_t now_sec() {
  return chr::duration_cast<chr::seconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// --------------------------------------------------------------------------
// Base64 encoding (unpadded, for Matrix)
// --------------------------------------------------------------------------
std::string base64_encode(const std::string& data) {
  static const char* chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string result;
  result.reserve(((data.size() + 2) / 3) * 4);
  int val = 0, valb = -6;
  for (unsigned char c : data) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      result.push_back(chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) result.push_back(chars[((val << 8) >> (valb + 8)) & 0x3F]);
  while (result.size() % 4) result.push_back('=');
  return result;
}

// --------------------------------------------------------------------------
// Base64 decoding
// --------------------------------------------------------------------------
std::string base64_decode(const std::string& data) {
  static const unsigned char decode_table[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63,52,53,54,55,56,57,58,59,60,61,0,
    0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,
    22,23,24,25,0,0,0,0,0,0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  };
  std::string result;
  result.reserve(data.size() * 3 / 4);
  int val = 0, valb = -8;
  for (unsigned char c : data) {
    if (c == '=') break;
    if (decode_table[c] == 0 && c != 'A') continue;
    val = (val << 6) + decode_table[c];
    valb += 6;
    if (valb >= 0) {
      result.push_back(char((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return result;
}

// --------------------------------------------------------------------------
// Hex encoding
// --------------------------------------------------------------------------
std::string hex_encode(const std::string& data) {
  static const char* hex = "0123456789abcdef";
  std::string result;
  result.reserve(data.size() * 2);
  for (unsigned char c : data) {
    result.push_back(hex[c >> 4]);
    result.push_back(hex[c & 0x0F]);
  }
  return result;
}

// --------------------------------------------------------------------------
// Hex decoding
// --------------------------------------------------------------------------
std::string hex_decode(const std::string& hex) {
  std::string result;
  result.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    int high = hex[i] >= 'a' ? hex[i] - 'a' + 10 :
               hex[i] >= 'A' ? hex[i] - 'A' + 10 : hex[i] - '0';
    int low  = hex[i+1] >= 'a' ? hex[i+1] - 'a' + 10 :
               hex[i+1] >= 'A' ? hex[i+1] - 'A' + 10 : hex[i+1] - '0';
    result.push_back(static_cast<char>((high << 4) | low));
  }
  return result;
}

// --------------------------------------------------------------------------
// Unpadded base64 (Matrix-style, '=' padding stripped)
// --------------------------------------------------------------------------
std::string base64_unpadded(const std::string& data) {
  std::string enc = base64_encode(data);
  while (!enc.empty() && enc.back() == '=') enc.pop_back();
  return enc;
}

// --------------------------------------------------------------------------
// Generate cryptographically random bytes
// --------------------------------------------------------------------------
std::string random_bytes(size_t count) {
  std::string out(count, '\0');
  if (RAND_bytes(reinterpret_cast<unsigned char*>(out.data()),
                  static_cast<int>(count)) != 1) {
    throw std::runtime_error("Failed to generate random bytes");
  }
  return out;
}

// --------------------------------------------------------------------------
// SQL string escaping (basic, for string building)
// --------------------------------------------------------------------------
std::string sql_escape(const std::string& input) {
  std::string result;
  result.reserve(input.size() + 4);
  for (char c : input) {
    if (c == '\'') result += "''";
    else result.push_back(c);
  }
  return result;
}

// --------------------------------------------------------------------------
// Generate a unique device ID for a dehydrated device
// --------------------------------------------------------------------------
std::string generate_dehydrated_device_id(const std::string& user_id) {
  // Use a deterministic hash of user_id as part of the ID to ensure uniqueness
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(user_id.data()),
         user_id.size(), hash);
  std::string hash_hex = hex_encode(std::string(
      reinterpret_cast<char*>(hash), 8));
  return std::string(DEHYDRATED_DEVICE_PREFIX) + hash_hex;
}

// --------------------------------------------------------------------------
// Generate a device signing key ID
// --------------------------------------------------------------------------
std::string make_signing_key_id(const std::string& user_id,
                                 const std::string& device_id) {
  return std::string(SIGNING_ALGORITHM_ED25519) + ":" + device_id;
}

// ==========================================================================
// AES-256-CBC encryption with HMAC-SHA256 authentication
// Uses the matrix pickling scheme:
//   ciphertext = AES-256-CBC(plaintext, key, iv)
//   mac = HMAC-SHA256(ciphertext, hmac_key)
//   output = base64(iv || ciphertext || mac)
// ==========================================================================
std::string aes_cbc_encrypt_authenticated(const std::string& plaintext,
                                           const std::string& key,
                                           const std::string& hmac_key) {
  if (key.size() != AES_KEY_LEN) {
    throw std::runtime_error("AES key must be " +
                             std::to_string(AES_KEY_LEN) + " bytes");
  }
  if (hmac_key.size() != HMAC_KEY_LEN) {
    throw std::runtime_error("HMAC key must be " +
                             std::to_string(HMAC_KEY_LEN) + " bytes");
  }

  std::string iv = random_bytes(AES_IV_LEN);

  // Pad plaintext to AES block size (PKCS7)
  size_t pad_len = AES_BLOCK_SIZE - (plaintext.size() % AES_BLOCK_SIZE);
  std::string padded = plaintext + std::string(pad_len, static_cast<char>(pad_len));

  // Encrypt
  std::string ciphertext(padded.size(), '\0');
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

  int len = 0, ciphertext_len = 0;
  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                     reinterpret_cast<const unsigned char*>(key.data()),
                     reinterpret_cast<const unsigned char*>(iv.data()));
  EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()),
                    &len,
                    reinterpret_cast<const unsigned char*>(padded.data()),
                    static_cast<int>(padded.size()));
  ciphertext_len = len;
  EVP_EncryptFinal_ex(ctx,
                      reinterpret_cast<unsigned char*>(ciphertext.data()) + len,
                      &len);
  ciphertext_len += len;
  ciphertext.resize(ciphertext_len);
  EVP_CIPHER_CTX_free(ctx);

  // Compute HMAC-SHA256(IV || ciphertext)
  std::string mac_input = iv + ciphertext;
  unsigned char mac[EVP_MAX_MD_SIZE];
  unsigned int mac_len = 0;
  HMAC(EVP_sha256(), hmac_key.data(), static_cast<int>(hmac_key.size()),
       reinterpret_cast<const unsigned char*>(mac_input.data()),
       mac_input.size(), mac, &mac_len);

  // Return base64(IV || ciphertext || MAC)
  return base64_encode(iv + ciphertext +
                       std::string(reinterpret_cast<char*>(mac), mac_len));
}

// ==========================================================================
// AES-256-CBC decryption with HMAC-SHA256 verification
// ==========================================================================
std::optional<std::string> aes_cbc_decrypt_authenticated(
    const std::string& ciphertext_b64,
    const std::string& key,
    const std::string& hmac_key) {

  std::string decoded;
  try {
    decoded = base64_decode(ciphertext_b64);
  } catch (...) {
    return std::nullopt;
  }

  if (decoded.size() < AES_IV_LEN + HMAC_OUTPUT_LEN) {
    return std::nullopt;
  }

  // Extract IV, ciphertext, MAC
  std::string iv = decoded.substr(0, AES_IV_LEN);
  std::string mac = decoded.substr(decoded.size() - HMAC_OUTPUT_LEN);
  std::string ct = decoded.substr(AES_IV_LEN,
                                   decoded.size() - AES_IV_LEN - HMAC_OUTPUT_LEN);

  // Verify HMAC
  std::string mac_input = iv + ct;
  unsigned char computed_mac[EVP_MAX_MD_SIZE];
  unsigned int computed_mac_len = 0;
  HMAC(EVP_sha256(), hmac_key.data(), static_cast<int>(hmac_key.size()),
       reinterpret_cast<const unsigned char*>(mac_input.data()),
       mac_input.size(), computed_mac, &computed_mac_len);

  if (computed_mac_len != mac.size() ||
      CRYPTO_memcmp(computed_mac, mac.data(), computed_mac_len) != 0) {
    return std::nullopt; // MAC verification failed
  }

  // Decrypt
  std::string plaintext(ct.size(), '\0');
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return std::nullopt;

  int len = 0, plaintext_len = 0;
  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                     reinterpret_cast<const unsigned char*>(key.data()),
                     reinterpret_cast<const unsigned char*>(iv.data()));
  EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()),
                    &len,
                    reinterpret_cast<const unsigned char*>(ct.data()),
                    static_cast<int>(ct.size()));
  plaintext_len = len;
  if (EVP_DecryptFinal_ex(ctx,
      reinterpret_cast<unsigned char*>(plaintext.data()) + len, &len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return std::nullopt;
  }
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  plaintext.resize(plaintext_len);

  // Remove PKCS7 padding
  if (plaintext_len > 0) {
    unsigned char pad = static_cast<unsigned char>(plaintext.back());
    if (pad > 0 && pad <= AES_BLOCK_SIZE && static_cast<int>(pad) <= plaintext_len) {
      plaintext.resize(plaintext_len - pad);
    }
  }

  return plaintext;
}

// ==========================================================================
// HKDF-SHA256 key derivation
// ==========================================================================
std::string hkdf_sha256_derive(const std::string& input_key_material,
                                const std::string& salt,
                                const std::string& info,
                                size_t out_len) {
  std::string out(out_len, '\0');
  if (HKDF(reinterpret_cast<unsigned char*>(out.data()), out_len,
           EVP_sha256(),
           reinterpret_cast<const unsigned char*>(input_key_material.data()),
           input_key_material.size(),
           reinterpret_cast<const unsigned char*>(salt.data()),
           salt.size(),
           reinterpret_cast<const unsigned char*>(info.data()),
           info.size()) != 1) {
    throw std::runtime_error("HKDF derivation failed");
  }
  return out;
}

// ==========================================================================
// PBKDF2-HMAC-SHA512 for pickle key derivation
// ==========================================================================
std::string pbkdf2_derive_key(const std::string& passphrase,
                                const std::string& salt,
                                int iterations,
                                size_t key_len) {
  std::string out(key_len, '\0');
  if (PKCS5_PBKDF2_HMAC(passphrase.data(), static_cast<int>(passphrase.size()),
                         reinterpret_cast<const unsigned char*>(salt.data()),
                         static_cast<int>(salt.size()),
                         iterations, EVP_sha512(),
                         static_cast<int>(key_len),
                         reinterpret_cast<unsigned char*>(out.data())) != 1) {
    throw std::runtime_error("PBKDF2 derivation failed");
  }
  return out;
}

// ==========================================================================
// Ed25519 key pair generation
// ==========================================================================
struct Ed25519KeyPair {
  std::string public_key;   // 32 bytes raw
  std::string private_key;  // 32 bytes raw
};

Ed25519KeyPair generate_ed25519_keypair() {
  Ed25519KeyPair kp;
  kp.public_key.resize(ED25519_PUBKEY_LEN);
  kp.private_key.resize(ED25519_PRIVKEY_LEN);
  EVP_PKEY* pkey = nullptr;
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (!pctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
  if (EVP_PKEY_keygen_init(pctx) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("EVP_PKEY_keygen_init failed");
  }
  if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("EVP_PKEY_keygen failed");
  }
  EVP_PKEY_CTX_free(pctx);

  size_t pub_len = ED25519_PUBKEY_LEN, priv_len = ED25519_PRIVKEY_LEN;
  EVP_PKEY_get_raw_public_key(pkey,
      reinterpret_cast<unsigned char*>(kp.public_key.data()), &pub_len);
  EVP_PKEY_get_raw_private_key(pkey,
      reinterpret_cast<unsigned char*>(kp.private_key.data()), &priv_len);
  EVP_PKEY_free(pkey);
  return kp;
}

// ==========================================================================
// Ed25519 sign
// ==========================================================================
std::string ed25519_sign(const std::string& message,
                           const std::string& private_key) {
  std::string sig(ED25519_SIGNATURE_LEN, '\0');
  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
      reinterpret_cast<const unsigned char*>(private_key.data()),
      private_key.size());
  if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_DigestSignInit failed");
  }
  size_t sig_len = ED25519_SIGNATURE_LEN;
  if (EVP_DigestSign(ctx,
                     reinterpret_cast<unsigned char*>(sig.data()), &sig_len,
                     reinterpret_cast<const unsigned char*>(message.data()),
                     message.size()) <= 0) {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_DigestSign failed");
  }
  sig.resize(sig_len);
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return sig;
}

// ==========================================================================
// Ed25519 verify
// ==========================================================================
bool ed25519_verify(const std::string& message,
                     const std::string& signature,
                     const std::string& public_key) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
      reinterpret_cast<const unsigned char*>(public_key.data()),
      public_key.size());
  if (!pkey) return false;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return false;
  }
  int result = EVP_DigestVerify(ctx,
      reinterpret_cast<const unsigned char*>(signature.data()),
      signature.size(),
      reinterpret_cast<const unsigned char*>(message.data()),
      message.size());
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return result == 1;
}

// ==========================================================================
// Curve25519 key pair generation
// ==========================================================================
struct Curve25519KeyPair {
  std::string public_key;
  std::string private_key;
};

Curve25519KeyPair generate_curve25519_keypair() {
  Curve25519KeyPair kp;
  kp.public_key.resize(CURVE25519_PUBKEY_LEN);
  kp.private_key.resize(CURVE25519_PRIVKEY_LEN);
  EVP_PKEY* pkey = nullptr;
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (!pctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
  if (EVP_PKEY_keygen_init(pctx) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("EVP_PKEY_keygen_init failed");
  }
  if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("EVP_PKEY_keygen failed");
  }
  EVP_PKEY_CTX_free(pctx);

  size_t pub_len = CURVE25519_PUBKEY_LEN, priv_len = CURVE25519_PRIVKEY_LEN;
  EVP_PKEY_get_raw_public_key(pkey,
      reinterpret_cast<unsigned char*>(kp.public_key.data()), &pub_len);
  EVP_PKEY_get_raw_private_key(pkey,
      reinterpret_cast<unsigned char*>(kp.private_key.data()), &priv_len);
  EVP_PKEY_free(pkey);
  return kp;
}

} // anonymous namespace

// ============================================================================
// Data structures
// ============================================================================

// ---------------------------------------------------------------------------
// DehydratedDevice - Core data structure representing a dehydrated device
// Equivalent to dehydrated device record in Synapse/sqlite
// ---------------------------------------------------------------------------
struct DehydratedDevice {
  std::string device_id;
  std::string user_id;
  DehydratedDeviceState state{DehydratedDeviceState::PENDING};
  std::string device_data;          // Encrypted/pickled device key material
  std::string device_keys;          // JSON: uploaded device identity keys
  std::string one_time_keys;        // JSON: one-time keys for the device
  std::string fallback_keys;        // JSON: fallback keys
  std::string pickle_key_hash;      // Hash of the pickle key for verification
  std::string cross_signing_keys;   // JSON: cross-signing keys
  int64_t created_at_ms{0};
  int64_t expires_at_ms{0};
  int64_t reclaimed_at_ms{0};
  std::optional<std::string> reclaimed_by;
  int message_count{0};             // Number of queued to-device messages
};

// ---------------------------------------------------------------------------
// DehydratedDeviceEvent - A to-device event queued for a dehydrated device
// ---------------------------------------------------------------------------
struct DehydratedDeviceEvent {
  std::string event_id;
  std::string dehydrated_device_id;
  std::string sender;
  std::string event_type;
  std::string content;              // JSON content
  int64_t timestamp_ms{0};
  bool sent{false};
};

// ---------------------------------------------------------------------------
// PickleKey - Cryptographic material for encrypting/decrypting pickle data
// ---------------------------------------------------------------------------
struct PickleKey {
  std::string cipher_key;           // AES-256 key
  std::string hmac_key;             // HMAC-SHA256 key
  std::string salt;                 // PBKDF2 salt
  int iterations{DEHYDRATION_PICKLE_ITERATIONS};
};

// ============================================================================
// DehydratedDeviceStore - Persistent storage for dehydrated devices
// Manages the database tables for dehydrated device CRUD operations.
// ============================================================================
class DehydratedDeviceStore {
public:
  explicit DehydratedDeviceStore(storage::DatabasePool& db)
      : db_(db) {}

  // Load all dehydrated devices from the database into memory cache
  void load_from_database() {
    auto rows = db_.execute("load_dehydrated",
        "SELECT device_id, user_id, state, device_data, device_keys, "
        "one_time_keys, fallback_keys, pickle_key_hash, cross_signing_keys, "
        "created_at_ms, expires_at_ms, reclaimed_at_ms, reclaimed_by, "
        "message_count FROM dehydrated_devices");

    std::lock_guard<std::mutex> lock(mutex_);
    devices_.clear();
    for (const auto& row : rows) {
      DehydratedDevice dd;
      dd.device_id = row[0];
      dd.user_id = row[1];
      dd.state = static_cast<DehydratedDeviceState>(std::stoi(row[2]));
      dd.device_data = row[3];
      dd.device_keys = row[4];
      dd.one_time_keys = row[5];
      dd.fallback_keys = row[6];
      dd.pickle_key_hash = row[7];
      dd.cross_signing_keys = row[8];
      dd.created_at_ms = std::stoll(row[9]);
      dd.expires_at_ms = std::stoll(row[10]);
      dd.reclaimed_at_ms = std::stoll(row[11]);
      dd.reclaimed_by = row[12].empty()
          ? std::optional<std::string>() : row[12];
      dd.message_count = std::stoi(row[13]);
      devices_[dd.user_id] = dd;
    }
  }

  // Create a new dehydrated device for a user
  bool create_dehydrated_device(const DehydratedDevice& dd) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Check if user already has a dehydrated device (only one allowed)
    auto it = devices_.find(dd.user_id);
    if (it != devices_.end() &&
        it->second.state != DehydratedDeviceState::EXPIRED &&
        it->second.state != DehydratedDeviceState::REVOKED) {
      return false; // Already exists
    }

    devices_[dd.user_id] = dd;

    // Persist to database
    db_.execute("insert_dehydrated",
        "INSERT OR REPLACE INTO dehydrated_devices "
        "(device_id, user_id, state, device_data, device_keys, "
        "one_time_keys, fallback_keys, pickle_key_hash, cross_signing_keys, "
        "created_at_ms, expires_at_ms, reclaimed_at_ms, reclaimed_by, "
        "message_count) VALUES "
        "('" + sql_escape(dd.device_id) + "','" + sql_escape(dd.user_id) +
        "'," + std::to_string(static_cast<int>(dd.state)) +
        ",'" + sql_escape(dd.device_data) +
        "','" + sql_escape(dd.device_keys) +
        "','" + sql_escape(dd.one_time_keys) +
        "','" + sql_escape(dd.fallback_keys) +
        "','" + sql_escape(dd.pickle_key_hash) +
        "','" + sql_escape(dd.cross_signing_keys) +
        "'," + std::to_string(dd.created_at_ms) +
        "," + std::to_string(dd.expires_at_ms) +
        "," + std::to_string(dd.reclaimed_at_ms) +
        "," + (dd.reclaimed_by.has_value()
               ? "'" + sql_escape(*dd.reclaimed_by) + "'" : "NULL") +
        "," + std::to_string(dd.message_count) + ")");

    return true;
  }

  // Get a dehydrated device by user ID
  std::optional<DehydratedDevice> get_dehydrated_device(
      const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = devices_.find(user_id);
    if (it == devices_.end()) return std::nullopt;
    return it->second;
  }

  // Get a dehydrated device by device ID
  std::optional<DehydratedDevice> get_dehydrated_device_by_id(
      const std::string& device_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& [uid, dd] : devices_) {
      if (dd.device_id == device_id) return dd;
    }
    return std::nullopt;
  }

  // Update device state
  void update_device_state(const std::string& user_id,
                            DehydratedDeviceState new_state,
                            const std::optional<std::string>& reclaimed_by = std::nullopt) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = devices_.find(user_id);
    if (it == devices_.end()) return;

    it->second.state = new_state;
    if (reclaimed_by) it->second.reclaimed_by = *reclaimed_by;

    db_.execute("update_state",
        "UPDATE dehydrated_devices SET state=" +
        std::to_string(static_cast<int>(new_state)) +
        (reclaimed_by.has_value()
         ? ", reclaimed_by='" + sql_escape(*reclaimed_by) + "'" : "") +
        ", reclaimed_at_ms=" +
        std::to_string(new_state == DehydratedDeviceState::RECLAIMED
                       ? now_ms() : it->second.reclaimed_at_ms) +
        " WHERE user_id='" + sql_escape(user_id) + "'");
  }

  // Update device keys
  bool update_device_keys(const std::string& user_id,
                           const std::string& device_keys,
                           const std::string& one_time_keys,
                           const std::string& fallback_keys) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = devices_.find(user_id);
    if (it == devices_.end()) return false;

    it->second.device_keys = device_keys;
    it->second.one_time_keys = one_time_keys;
    it->second.fallback_keys = fallback_keys;

    db_.execute("update_keys",
        "UPDATE dehydrated_devices SET "
        "device_keys='" + sql_escape(device_keys) + "', "
        "one_time_keys='" + sql_escape(one_time_keys) + "', "
        "fallback_keys='" + sql_escape(fallback_keys) +
        "' WHERE user_id='" + sql_escape(user_id) + "'");
    return true;
  }

  // Delete a dehydrated device
  bool delete_dehydrated_device(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Also delete associated to-device events
    auto dd_it = devices_.find(user_id);
    if (dd_it != devices_.end()) {
      db_.execute("del_events",
          "DELETE FROM dehydrated_device_events WHERE "
          "dehydrated_device_id='" + sql_escape(dd_it->second.device_id) + "'");
    }

    devices_.erase(user_id);

    db_.execute("delete_dehydrated",
        "DELETE FROM dehydrated_devices WHERE user_id='" +
        sql_escape(user_id) + "'");

    // Also clean up in-memory to-device cache
    to_device_events_.erase(user_id);
    return true;
  }

  // Queue a to-device event for a dehydrated device
  bool queue_to_device_event(const DehydratedDeviceEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);

    to_device_events_[event.dehydrated_device_id].push_back(event);

    // Enforce max queue size (drop oldest)
    auto& queue = to_device_events_[event.dehydrated_device_id];
    while (queue.size() > static_cast<size_t>(MAX_QUEUED_MESSAGES)) {
      queue.erase(queue.begin());
    }

    // Update message count on the device
    for (auto& [uid, dd] : devices_) {
      if (dd.device_id == event.dehydrated_device_id) {
        dd.message_count = static_cast<int>(queue.size());
        break;
      }
    }

    // Persist event
    db_.execute("insert_event",
        "INSERT INTO dehydrated_device_events "
        "(event_id, dehydrated_device_id, sender, event_type, content, "
        "timestamp_ms, sent) VALUES "
        "('" + sql_escape(event.event_id) + "','" +
        sql_escape(event.dehydrated_device_id) + "','" +
        sql_escape(event.sender) + "','" +
        sql_escape(event.event_type) + "','" +
        sql_escape(event.content) + "'," +
        std::to_string(event.timestamp_ms) + ",0)");
    return true;
  }

  // Get queued to-device events for a dehydrated device
  std::vector<DehydratedDeviceEvent> get_queued_events(
      const std::string& device_id, int limit = 100) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = to_device_events_.find(device_id);
    if (it == to_device_events_.end()) return {};

    std::vector<DehydratedDeviceEvent> result;
    auto& queue = it->second;
    size_t count = std::min(queue.size(), static_cast<size_t>(limit));
    result.assign(queue.begin(), queue.begin() + count);
    return result;
  }

  // Mark queued events as sent and remove them
  void mark_events_sent(const std::string& device_id,
                         const std::vector<std::string>& event_ids) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = to_device_events_.find(device_id);
    if (it == to_device_events_.end()) return;

    std::set<std::string> to_remove(event_ids.begin(), event_ids.end());
    auto& queue = it->second;
    queue.erase(
        std::remove_if(queue.begin(), queue.end(),
                       [&](const DehydratedDeviceEvent& e) {
                         return to_remove.count(e.event_id) > 0;
                       }),
        queue.end());

    // Batch update in database
    for (const auto& eid : event_ids) {
      db_.execute("mark_sent",
          "UPDATE dehydrated_device_events SET sent=1 WHERE event_id='" +
          sql_escape(eid) + "'");
    }

    // Update message count
    for (auto& [uid, dd] : devices_) {
      if (dd.device_id == device_id) {
        dd.message_count = static_cast<int>(queue.size());
        break;
      }
    }
  }

  // Get all expired devices that need cleanup
  std::vector<DehydratedDevice> get_expired_devices(int64_t current_time_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DehydratedDevice> expired;
    for (const auto& [uid, dd] : devices_) {
      if (dd.state == DehydratedDeviceState::PENDING ||
          dd.state == DehydratedDeviceState::ACTIVE) {
        if (dd.expires_at_ms > 0 && dd.expires_at_ms < current_time_ms) {
          expired.push_back(dd);
        }
      }
    }
    return expired;
  }

  // Get all dehydrated devices (for cleanup scanning)
  std::vector<DehydratedDevice> get_all_devices() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<DehydratedDevice> result;
    for (const auto& [uid, dd] : devices_) {
      result.push_back(dd);
    }
    return result;
  }

  // Count dehydrated devices for a user
  int count_for_user(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = devices_.find(user_id);
    if (it == devices_.end()) return 0;
    return (it->second.state != DehydratedDeviceState::EXPIRED &&
            it->second.state != DehydratedDeviceState::REVOKED) ? 1 : 0;
  }

  // Export device data for MSC2697 export endpoint
  json export_device_data(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = devices_.find(user_id);
    if (it == devices_.end()) return json::object();

    const auto& dd = it->second;
    json exported;
    exported[FIELD_DEVICE_ID] = dd.device_id;
    exported[FIELD_DEVICE_DATA] = dd.device_data;
    exported[FIELD_ALGORITHM] = DEHYDRATION_ALGORITHM;
    exported[FIELD_CREATED_AT] = dd.created_at_ms;
    exported[FIELD_EXPIRES_AT] = dd.expires_at_ms;
    return exported;
  }

  // Get DDL for database tables
  static std::string get_ddl() {
    return R"SQL(
CREATE TABLE IF NOT EXISTS dehydrated_devices(
  device_id TEXT NOT NULL PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE,
  state INTEGER NOT NULL DEFAULT 0,
  device_data TEXT NOT NULL DEFAULT '',
  device_keys TEXT NOT NULL DEFAULT '{}',
  one_time_keys TEXT NOT NULL DEFAULT '{}',
  fallback_keys TEXT NOT NULL DEFAULT '{}',
  pickle_key_hash TEXT NOT NULL DEFAULT '',
  cross_signing_keys TEXT NOT NULL DEFAULT '{}',
  created_at_ms INTEGER NOT NULL DEFAULT 0,
  expires_at_ms INTEGER NOT NULL DEFAULT 0,
  reclaimed_at_ms INTEGER NOT NULL DEFAULT 0,
  reclaimed_by TEXT,
  message_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dehydrated_device_events(
  event_id TEXT NOT NULL PRIMARY KEY,
  dehydrated_device_id TEXT NOT NULL,
  sender TEXT NOT NULL,
  event_type TEXT NOT NULL,
  content TEXT NOT NULL DEFAULT '{}',
  timestamp_ms INTEGER NOT NULL DEFAULT 0,
  sent INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_dd_user ON dehydrated_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_dd_state ON dehydrated_devices(state);
CREATE INDEX IF NOT EXISTS idx_dd_expires ON dehydrated_devices(expires_at_ms);
CREATE INDEX IF NOT EXISTS idx_dde_device ON dehydrated_device_events(dehydrated_device_id);
CREATE INDEX IF NOT EXISTS idx_dde_sent ON dehydrated_device_events(dehydrated_device_id, sent);
)SQL";
  }

private:
  storage::DatabasePool& db_;
  std::mutex mutex_;
  std::unordered_map<std::string, DehydratedDevice> devices_;
  std::unordered_map<std::string,
    std::vector<DehydratedDeviceEvent>> to_device_events_;
};

// ============================================================================
// DehydratedDeviceManager - Core business logic for device dehydration
// Handles the full lifecycle: create, rehydrate, delete, key management,
// cross-signing integration, and backup coordination.
// ============================================================================
class DehydratedDeviceManager {
public:
  explicit DehydratedDeviceManager(storage::DatabasePool& db)
      : store_(std::make_unique<DehydratedDeviceStore>(db)) {}

  // Initialize: load state, start cleanup timer
  void initialize() {
    store_->load_from_database();
    last_cleanup_ms_ = now_ms();
  }

  // ------------------------------------------------------------------------
  // CREATE: Register a new dehydrated device
  //
  // The client provides:
  //   - device_data: encrypted/pickled device key material
  //   - device_keys: the device's identity keys (ed25519, curve25519)
  //   - one_time_keys: pre-generated one-time keys for the device
  //   - initial_device_display_name: optional display name
  //
  // Returns the created dehydrated device ID on success.
  // ------------------------------------------------------------------------
  std::optional<std::string> create_dehydrated_device(
      const std::string& user_id,
      const std::string& device_data,
      const json& device_keys,
      const json& one_time_keys,
      const std::string& pickle_key_hash = "",
      const std::optional<std::string>& initial_device_display_name = std::nullopt) {

    // Generate a unique device ID
    std::string device_id = generate_dehydrated_device_id(user_id);

    // Parse and validate expiry from keys if present
    int64_t expires_at_ms = now_ms() + DEFAULT_EXPIRY_MS;

    // Build the dehydrated device record
    DehydratedDevice dd;
    dd.device_id = device_id;
    dd.user_id = user_id;
    dd.state = DehydratedDeviceState::PENDING;
    dd.device_data = device_data;
    dd.device_keys = device_keys.dump();
    dd.one_time_keys = one_time_keys.dump();
    dd.fallback_keys = json::object().dump();
    dd.pickle_key_hash = pickle_key_hash;
    dd.cross_signing_keys = json::object().dump();
    dd.created_at_ms = now_ms();
    dd.expires_at_ms = expires_at_ms;
    dd.message_count = 0;

    if (!store_->create_dehydrated_device(dd)) {
      return std::nullopt; // User already has a dehydrated device
    }

    // Backup the device keys to key backup if available
    backup_device_keys_for_dehydrated(user_id, device_id);

    return device_id;
  }

  // ------------------------------------------------------------------------
  // CREATE with extended options (MSC 2697 full)
  // ------------------------------------------------------------------------
  json create_dehydrated_device_extended(
      const std::string& user_id,
      const json& request_body) {

    // Extract fields from request
    std::string device_data;
    if (request_body.contains(FIELD_DEVICE_DATA)) {
      device_data = request_body[FIELD_DEVICE_DATA].get<std::string>();
    }

    json device_keys = json::object();
    if (request_body.contains(FIELD_DEVICE_KEYS)) {
      device_keys = request_body[FIELD_DEVICE_KEYS];
    }

    json one_time_keys = json::object();
    if (request_body.contains(FIELD_ONE_TIME_KEYS)) {
      one_time_keys = request_body[FIELD_ONE_TIME_KEYS];
    }

    json fallback_keys = json::object();
    if (request_body.contains(FIELD_FALLBACK_KEYS)) {
      fallback_keys = request_body[FIELD_FALLBACK_KEYS];
    }

    std::string pickle_key_hash;
    if (request_body.contains(FIELD_PICKLE_KEY)) {
      pickle_key_hash = request_body[FIELD_PICKLE_KEY].get<std::string>();
    }

    auto result = create_dehydrated_device(
        user_id, device_data, device_keys, one_time_keys, pickle_key_hash);

    json response;
    if (result.has_value()) {
      response["device_id"] = *result;
      response["success"] = true;

      // Store fallback keys if provided
      if (!fallback_keys.empty() && !fallback_keys.is_null()) {
        store_->update_device_keys(user_id,
            device_keys.dump(),
            one_time_keys.dump(),
            fallback_keys.dump());
      }
    } else {
      response["success"] = false;
      response["errcode"] = "M_LIMIT_EXCEEDED";
      response["error"] = "A dehydrated device already exists for this user";
    }

    return response;
  }

  // ------------------------------------------------------------------------
  // REHYDRATE: Claim and recover a dehydrated device on login
  //
  // The client calls this after logging in to recover the dehydrated
  // device's key material. The client provides the pickle key (if one
  // was used to encrypt the device data) to decrypt it.
  //
  // Returns the decrypted device data and device keys.
  // ------------------------------------------------------------------------
  json rehydrate_device(const std::string& user_id,
                         const std::optional<std::string>& pickle_key = std::nullopt) {
    auto dd_opt = store_->get_dehydrated_device(user_id);
    if (!dd_opt.has_value()) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "No dehydrated device found for this user";
      return err;
    }

    const auto& dd = *dd_opt;

    // Check if already reclaimed
    if (dd.state == DehydratedDeviceState::RECLAIMED) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_FORBIDDEN";
      err["error"] = "Dehydrated device has already been reclaimed";
      return err;
    }

    // Check expiry
    if (dd.expires_at_ms > 0 && now_ms() > dd.expires_at_ms) {
      store_->update_device_state(user_id, DehydratedDeviceState::EXPIRED);
      json err;
      err["success"] = false;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "Dehydrated device has expired";
      return err;
    }

    std::string device_data = dd.device_data;

    // If a pickle key was provided, verify and decrypt
    if (pickle_key.has_value() && !pickle_key->empty()) {
      // Verify pickle key hash
      unsigned char hash[SHA256_DIGEST_LENGTH];
      SHA256(reinterpret_cast<const unsigned char*>(pickle_key->data()),
             pickle_key->size(), hash);
      std::string computed_hash = hex_encode(
          std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH));

      if (!dd.pickle_key_hash.empty() && computed_hash != dd.pickle_key_hash) {
        json err;
        err["success"] = false;
        err["errcode"] = "M_BAD_PICKLE_KEY";
        err["error"] = "Pickle key verification failed";
        return err;
      }

      // Try to decrypt the device data using the pickle key
      std::string salt = dd.pickle_key_hash.substr(0,
          std::min(dd.pickle_key_hash.size(), size_t(16)));
      if (salt.size() < 16) {
        salt = "MATRIX_DEHYDRATED"; // default salt
      }

      auto decryption_key = pbkdf2_derive_key(
          *pickle_key, salt,
          DEHYDRATION_PICKLE_ITERATIONS, AES_KEY_LEN + HMAC_KEY_LEN);
      std::string cipher_key = decryption_key.substr(0, AES_KEY_LEN);
      std::string hmac_key = decryption_key.substr(AES_KEY_LEN);

      auto decrypted = aes_cbc_decrypt_authenticated(
          device_data, cipher_key, hmac_key);
      if (decrypted.has_value()) {
        device_data = *decrypted;
      }
      // If decryption fails, return the raw device_data (client handles it)
    }

    // Mark as reclaimed
    store_->update_device_state(user_id, DehydratedDeviceState::RECLAIMED);

    // Build response with recovered data
    json response;
    response["success"] = true;
    response[FIELD_DEVICE_ID] = dd.device_id;
    response[FIELD_DEVICE_DATA] = device_data;

    // Parse and include device keys
    try {
      response[FIELD_DEVICE_KEYS] = json::parse(dd.device_keys);
    } catch (...) {
      response[FIELD_DEVICE_KEYS] = dd.device_keys;
    }

    try {
      if (!dd.one_time_keys.empty()) {
        response[FIELD_ONE_TIME_KEYS] = json::parse(dd.one_time_keys);
      }
    } catch (...) {}

    try {
      if (!dd.fallback_keys.empty()) {
        response[FIELD_FALLBACK_KEYS] = json::parse(dd.fallback_keys);
      }
    } catch (...) {}

    try {
      if (!dd.cross_signing_keys.empty()) {
        response[FIELD_CROSS_SIGNING_KEYS] = json::parse(dd.cross_signing_keys);
      }
    } catch (...) {}

    response["message_count"] = dd.message_count;
    response["created_at_ms"] = dd.created_at_ms;

    return response;
  }

  // ------------------------------------------------------------------------
  // DELETE: Remove a dehydrated device
  // ------------------------------------------------------------------------
  json delete_dehydrated_device(const std::string& user_id) {
    auto dd_opt = store_->get_dehydrated_device(user_id);
    if (!dd_opt.has_value()) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    store_->delete_dehydrated_device(user_id);

    json resp;
    resp["success"] = true;
    return resp;
  }

  // ------------------------------------------------------------------------
  // GET: Retrieve information about a dehydrated device
  // ------------------------------------------------------------------------
  json get_dehydrated_device(const std::string& user_id) {
    auto dd_opt = store_->get_dehydrated_device(user_id);
    if (!dd_opt.has_value()) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    const auto& dd = *dd_opt;

    json response;
    response[FIELD_DEVICE_ID] = dd.device_id;
    response["state"] = static_cast<int>(dd.state);
    response[FIELD_CREATED_AT] = dd.created_at_ms;
    response[FIELD_EXPIRES_AT] = dd.expires_at_ms;
    response["message_count"] = dd.message_count;

    // Parse JSON fields
    try {
      response[FIELD_DEVICE_KEYS] = json::parse(dd.device_keys);
    } catch (...) {
      response[FIELD_DEVICE_KEYS] = json::object();
    }

    try {
      response[FIELD_ONE_TIME_KEYS] = json::parse(dd.one_time_keys);
    } catch (...) {
      response[FIELD_ONE_TIME_KEYS] = json::object();
    }

    response["algorithm"] = DEHYDRATION_ALGORITHM;

    return response;
  }

  // ------------------------------------------------------------------------
  // Device key upload for dehydrated device
  // ------------------------------------------------------------------------
  json upload_device_keys_for_dehydrated(
      const std::string& user_id,
      const std::string& device_id,
      const json& device_keys,
      const json& one_time_keys,
      const json& fallback_keys) {

    auto dd_opt = store_->get_dehydrated_device(user_id);
    if (!dd_opt.has_value()) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "No dehydrated device found";
      return err;
    }

    if (dd_opt->device_id != device_id) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_INVALID_PARAM";
      err["error"] = "Device ID mismatch";
      return err;
    }

    bool ok = store_->update_device_keys(user_id,
        device_keys.dump(),
        one_time_keys.dump(),
        fallback_keys.dump());

    json resp;
    resp["success"] = ok;
    return resp;
  }

  // ------------------------------------------------------------------------
  // Queue a to-device message for a dehydrated device
  // Called when sending room keys or other to-device messages while user
  // is offline; the messages get held until the device is rehydrated.
  // ------------------------------------------------------------------------
  bool queue_to_device_for_dehydrated(
      const std::string& sender,
      const std::string& target_user_id,
      const std::string& event_type,
      const json& content) {

    auto dd_opt = store_->get_dehydrated_device(target_user_id);
    if (!dd_opt.has_value()) return false;

    // Only queue for pending or active dehydrated devices
    if (dd_opt->state != DehydratedDeviceState::PENDING &&
        dd_opt->state != DehydratedDeviceState::ACTIVE) {
      return false;
    }

    // Generate event ID
    std::string event_id = "$dehydrated_" +
        hex_encode(random_bytes(16));

    DehydratedDeviceEvent event;
    event.event_id = event_id;
    event.dehydrated_device_id = dd_opt->device_id;
    event.sender = sender;
    event.event_type = event_type;
    event.content = content.dump();
    event.timestamp_ms = now_ms();

    return store_->queue_to_device_event(event);
  }

  // ------------------------------------------------------------------------
  // Get queued to-device events for rehydration
  // ------------------------------------------------------------------------
  json get_queued_events_for_device(const std::string& user_id, int limit = 100) {
    auto dd_opt = store_->get_dehydrated_device(user_id);
    if (!dd_opt.has_value()) {
      json err;
      err["events"] = json::array();
      err["next_batch"] = "";
      return err;
    }

    auto events = store_->get_queued_events(dd_opt->device_id, limit);

    json response;
    json events_arr = json::array();
    std::vector<std::string> event_ids;

    for (const auto& evt : events) {
      json jevt;
      jevt["event_id"] = evt.event_id;
      jevt["sender"] = evt.sender;
      jevt["type"] = evt.event_type;
      try {
        jevt["content"] = json::parse(evt.content);
      } catch (...) {
        jevt["content"] = json::object();
      }
      jevt["origin_server_ts"] = evt.timestamp_ms;
      events_arr.push_back(jevt);
      event_ids.push_back(evt.event_id);
    }

    response["events"] = events_arr;
    response["next_batch"] = "";

    // Mark events as sent
    if (!event_ids.empty()) {
      store_->mark_events_sent(dd_opt->device_id, event_ids);
    }

    return response;
  }

  // ------------------------------------------------------------------------
  // Sign a dehydrated device with the user's cross-signing master key
  // This establishes trust for the dehydrated device in the cross-signing
  // web of trust.
  // ------------------------------------------------------------------------
  json sign_dehydrated_device_with_master_key(
      const std::string& user_id,
      const std::string& master_private_key,
      const std::string& master_public_key) {

    auto dd_opt = store_->get_dehydrated_device(user_id);
    if (!dd_opt.has_value()) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    // Parse the device keys to find the ed25519 key to sign
    json dev_keys;
    try {
      dev_keys = json::parse(dd_opt->device_keys);
    } catch (...) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_INVALID_PARAM";
      err["error"] = "Invalid device keys JSON";
      return err;
    }

    // Build the object to sign: { user_id, device_id, algorithms, keys }
    json to_sign;
    to_sign["user_id"] = user_id;
    to_sign["device_id"] = dd_opt->device_id;
    to_sign["algorithms"] = dev_keys.value("algorithms",
        json::array({"m.olm.v1.curve25519-aes-sha2",
                      "m.megolm.v1.aes-sha2"}));
    to_sign["keys"] = dev_keys.value("keys", json::object());

    std::string to_sign_str = to_sign.dump();

    // Sign with master key (Ed25519)
    std::string signature;
    try {
      signature = ed25519_sign(to_sign_str, master_private_key);
    } catch (const std::exception& e) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_UNKNOWN";
      err["error"] = std::string("Signing failed: ") + e.what();
      return err;
    }

    // Store the signature on the device
    std::string signing_key_id = std::string(SIGNING_ALGORITHM_ED25519) +
        ":" + user_id;

    json sig_obj;
    sig_obj[signing_key_id] = base64_unpadded(signature);

    // Update cross-signing keys field with signature
    json cs_keys;
    try {
      cs_keys = json::parse(dd_opt->cross_signing_keys);
    } catch (...) {
      cs_keys = json::object();
    }

    cs_keys[FIELD_SIGNATURES] = sig_obj;
    cs_keys["signed_by_master"] = true;
    cs_keys["master_key"] = base64_unpadded(master_public_key);
    cs_keys["signed_at_ms"] = now_ms();

    // Persist
    dd_opt->cross_signing_keys = cs_keys.dump();
    store_->create_dehydrated_device(*dd_opt); // overwrite

    json response;
    response["success"] = true;
    response[FIELD_SIGNATURES] = sig_obj;
    response["signed_by_master"] = true;

    return response;
  }

  // ------------------------------------------------------------------------
  // Verify that a dehydrated device is signed by the user's master key
  // ------------------------------------------------------------------------
  bool verify_device_signature(const std::string& user_id,
                                 const std::string& master_public_key) {
    auto dd_opt = store_->get_dehydrated_device(user_id);
    if (!dd_opt.has_value()) return false;

    // Parse cross-signing keys to get signature
    json cs_keys;
    try {
      cs_keys = json::parse(dd_opt->cross_signing_keys);
    } catch (...) {
      return false;
    }

    if (!cs_keys.contains(FIELD_SIGNATURES) ||
        !cs_keys.value("signed_by_master", false)) {
      return false;
    }

    // Rebuild signed payload
    json dev_keys;
    try {
      dev_keys = json::parse(dd_opt->device_keys);
    } catch (...) {
      return false;
    }

    json to_sign;
    to_sign["user_id"] = user_id;
    to_sign["device_id"] = dd_opt->device_id;
    to_sign["algorithms"] = dev_keys.value("algorithms",
        json::array({"m.olm.v1.curve25519-aes-sha2",
                      "m.megolm.v1.aes-sha2"}));
    to_sign["keys"] = dev_keys.value("keys", json::object());

    std::string to_sign_str = to_sign.dump();

    // Get the signature
    std::string signing_key_id = std::string(SIGNING_ALGORITHM_ED25519) +
        ":" + user_id;
    if (!cs_keys[FIELD_SIGNATURES].contains(signing_key_id)) {
      return false;
    }

    std::string sig_b64 = cs_keys[FIELD_SIGNATURES][signing_key_id]
        .get<std::string>();
    std::string signature = base64_decode(sig_b64);

    return ed25519_verify(to_sign_str, signature, master_public_key);
  }

  // ------------------------------------------------------------------------
  // Backup device keys for a dehydrated device
  // Creates a key backup entry for the dehydrated device's identity keys
  // so they can be recovered if the dehydrated device is lost.
  // ------------------------------------------------------------------------
  json backup_device_keys_for_dehydrated(
      const std::string& user_id,
      const std::string& device_id,
      const std::string& backup_version = "dehydrated_backup") {

    auto dd_opt = store_->get_dehydrated_device(user_id);
    if (!dd_opt.has_value()) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    // Build backup payload
    json backup_data;
    backup_data["device_id"] = device_id;
    backup_data["user_id"] = user_id;
    backup_data["algorithm"] = DEHYDRATION_ALGORITHM;
    backup_data["created_at_ms"] = dd_opt->created_at_ms;

    try {
      backup_data["device_keys"] = json::parse(dd_opt->device_keys);
    } catch (...) {
      backup_data["device_keys"] = json::object();
    }

    try {
      backup_data["one_time_keys"] = json::parse(dd_opt->one_time_keys);
    } catch (...) {
      backup_data["one_time_keys"] = json::object();
    }

    try {
      backup_data["cross_signing_keys"] = json::parse(dd_opt->cross_signing_keys);
    } catch (...) {
      backup_data["cross_signing_keys"] = json::object();
    }

    // Encrypt backup data with a derived key
    std::string backup_key_material = random_bytes(AES_KEY_LEN);
    std::string backup_salt = random_bytes(PBKDF2_SALT_LEN);
    auto derived = pbkdf2_derive_key(backup_key_material, backup_salt,
                                     100000, AES_KEY_LEN + HMAC_KEY_LEN);
    std::string enc_key = derived.substr(0, AES_KEY_LEN);
    std::string hmac_key = derived.substr(AES_KEY_LEN);

    std::string encrypted = aes_cbc_encrypt_authenticated(
        backup_data.dump(), enc_key, hmac_key);

    // Store backup record in database
    db_.execute("backup_dehydrated",
        "INSERT OR REPLACE INTO dehydrated_device_backup "
        "(device_id, user_id, backup_version, encrypted_data, "
        "salt, backup_key_hash, created_at_ms) VALUES "
        "('" + sql_escape(device_id) + "','" + sql_escape(user_id) +
        "','" + sql_escape(backup_version) +
        "','" + sql_escape(encrypted) +
        "','" + sql_escape(backup_salt) +
        "','" + sql_escape(base64_unpadded(backup_key_material)) +
        "'," + std::to_string(now_ms()) + ")");

    json response;
    response["success"] = true;
    response["backup_version"] = backup_version;
    response["backup_key"] = base64_unpadded(backup_key_material);
    response["salt"] = base64_unpadded(backup_salt);

    return response;
  }

  // ------------------------------------------------------------------------
  // Restore device keys from backup
  // Used when rehydrating a device to recover backed-up key material.
  // ------------------------------------------------------------------------
  json restore_dehydrated_device_backup(
      const std::string& user_id,
      const std::string& device_id,
      const std::string& backup_key_b64) {

    auto rows = db_.execute("get_backup",
        "SELECT encrypted_data, salt FROM dehydrated_device_backup "
        "WHERE device_id='" + sql_escape(device_id) +
        "' AND user_id='" + sql_escape(user_id) + "'");

    if (rows.empty()) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_NOT_FOUND";
      err["error"] = "No backup found for this device";
      return err;
    }

    std::string encrypted = rows[0][0];
    std::string salt = rows[0][1];
    std::string backup_key = base64_decode(backup_key_b64);

    // Derive decryption keys
    auto derived = pbkdf2_derive_key(backup_key, salt, 100000,
                                      AES_KEY_LEN + HMAC_KEY_LEN);
    std::string enc_key = derived.substr(0, AES_KEY_LEN);
    std::string hmac_key = derived.substr(AES_KEY_LEN);

    auto decrypted = aes_cbc_decrypt_authenticated(
        encrypted, enc_key, hmac_key);

    if (!decrypted.has_value()) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_BAD_KEY";
      err["error"] = "Backup decryption failed";
      return err;
    }

    json backup_data;
    try {
      backup_data = json::parse(*decrypted);
    } catch (...) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_UNKNOWN";
      err["error"] = "Invalid backup data format";
      return err;
    }

    json response;
    response["success"] = true;
    response["backup_data"] = backup_data;
    return response;
  }

  // ------------------------------------------------------------------------
  // Export dehydrated device data (MSC2697 export endpoint)
  // Allows exporting the dehydrated device data for transfer to another
  // server or for client-side backup.
  // ------------------------------------------------------------------------
  json export_dehydrated_device(const std::string& user_id) {
    auto dd_opt = store_->get_dehydrated_device(user_id);
    if (!dd_opt.has_value()) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    return store_->export_device_data(user_id);
  }

  // ------------------------------------------------------------------------
  // Import dehydrated device data (MSC2697 import)
  // Allows importing a previously exported dehydrated device.
  // ------------------------------------------------------------------------
  json import_dehydrated_device(const std::string& user_id,
                                  const json& import_data) {
    // Validate import data
    if (!import_data.contains(FIELD_DEVICE_ID) ||
        !import_data.contains(FIELD_DEVICE_DATA)) {
      json err;
      err["success"] = false;
      err["errcode"] = "M_INVALID_PARAM";
      err["error"] = "Missing required fields: device_id, device_data";
      return err;
    }

    // Check for existing device
    auto existing = store_->get_dehydrated_device(user_id);
    if (existing.has_value() &&
        existing->state != DehydratedDeviceState::EXPIRED &&
        existing->state != DehydratedDeviceState::REVOKED) {
      // Replace existing
      store_->delete_dehydrated_device(user_id);
    }

    DehydratedDevice dd;
    dd.device_id = import_data[FIELD_DEVICE_ID].get<std::string>();
    dd.user_id = user_id;
    dd.state = DehydratedDeviceState::PENDING;
    dd.device_data = import_data[FIELD_DEVICE_DATA].get<std::string>();
    dd.device_keys = import_data.value(FIELD_DEVICE_KEYS, json::object()).dump();
    dd.one_time_keys = import_data.value(FIELD_ONE_TIME_KEYS, json::object()).dump();
    dd.fallback_keys = import_data.value(FIELD_FALLBACK_KEYS, json::object()).dump();
    dd.created_at_ms = import_data.value(FIELD_CREATED_AT, now_ms());
    dd.expires_at_ms = import_data.value(FIELD_EXPIRES_AT,
        now_ms() + DEFAULT_EXPIRY_MS);

    bool ok = store_->create_dehydrated_device(dd);

    json response;
    response["success"] = ok;
    if (ok) response[FIELD_DEVICE_ID] = dd.device_id;
    return response;
  }

  // ------------------------------------------------------------------------
  // Cleanup expired dehydrated devices
  // Should be called periodically (e.g., every hour by a background worker).
  // ------------------------------------------------------------------------
  json cleanup_expired_devices() {
    int64_t current_time = now_ms();
    auto expired = store_->get_expired_devices(current_time);

    json result;
    result["cleaned_up"] = json::array();
    int count = 0;

    for (const auto& dd : expired) {
      store_->update_device_state(dd.user_id, DehydratedDeviceState::EXPIRED);
      result["cleaned_up"].push_back({
        {"device_id", dd.device_id},
        {"user_id", dd.user_id},
        {"was_active_since", dd.created_at_ms},
        {"expired_at", dd.expires_at_ms}
      });
      count++;
    }

    result["total"] = count;
    result["cleaned_at_ms"] = current_time;
    last_cleanup_ms_ = current_time;

    return result;
  }

  // ------------------------------------------------------------------------
  // Periodic maintenance: check for expired devices
  // ------------------------------------------------------------------------
  bool needs_cleanup() {
    return (now_ms() - last_cleanup_ms_) >= CLEANUP_INTERVAL_MS;
  }

  void run_maintenance_if_needed() {
    if (needs_cleanup()) {
      cleanup_expired_devices();
    }
  }

  // ------------------------------------------------------------------------
  // Serialize the full dehydrated device state for sync responses
  // ------------------------------------------------------------------------
  json get_dehydrated_device_for_sync(const std::string& user_id) {
    auto dd_opt = store_->get_dehydrated_device(user_id);
    if (!dd_opt.has_value()) return json::object();

    const auto& dd = *dd_opt;
    json data;

    // Include in device_lists section of sync
    data[FIELD_DEVICE_ID] = dd.device_id;

    try {
      data[FIELD_DEVICE_KEYS] = json::parse(dd.device_keys);
    } catch (...) {
      data[FIELD_DEVICE_KEYS] = json::object();
    }

    try {
      data[FIELD_CROSS_SIGNING_KEYS] = json::parse(dd.cross_signing_keys);
    } catch (...) {
      data[FIELD_CROSS_SIGNING_KEYS] = json::object();
    }

    data["algorithm"] = DEHYDRATION_ALGORITHM;
    data["dehydrated"] = true;

    return data;
  }

  // ------------------------------------------------------------------------
  // Check if a device ID belongs to a dehydrated device
  // ------------------------------------------------------------------------
  bool is_dehydrated_device(const std::string& device_id) {
    return device_id.find(DEHYDRATED_DEVICE_PREFIX) == 0;
  }

  // ------------------------------------------------------------------------
  // Get the owner user_id for a dehydrated device ID
  // ------------------------------------------------------------------------
  std::optional<std::string> get_owner_of_device(const std::string& device_id) {
    auto dd_opt = store_->get_dehydrated_device_by_id(device_id);
    if (!dd_opt.has_value()) return std::nullopt;
    return dd_opt->user_id;
  }

  // ------------------------------------------------------------------------
  // Access to the underlying store
  // ------------------------------------------------------------------------
  DehydratedDeviceStore& store() { return *store_; }

private:
  std::unique_ptr<DehydratedDeviceStore> store_;
  storage::DatabasePool& db_;
  int64_t last_cleanup_ms_{0};
};

// ============================================================================
// DehydratedDeviceService - REST API servlets for MSC2697 endpoints
// Provides the HTTP API for clients to manage dehydrated devices.
// ============================================================================
namespace rest {

using namespace dehydration_constants;

// Local response helpers (delegate to BaseRestServlet statics)
static HttpResponse build_error(int code, const std::string& errcode,
                                 const std::string& error) {
  return BaseRestServlet::error_response(code, errcode, error);
}
static HttpResponse build_success(const json& data = json::object()) {
  return BaseRestServlet::success_response(data);
}

// ==========================================================================
// DehydratedDeviceServlet - Main MSC2697 endpoint handler
//
// Endpoints:
//   PUT  /org.matrix.msc2697.v1/dehydrated_device
//        - Create or update a dehydrated device
//   GET  /org.matrix.msc2697.v1/dehydrated_device
//        - Get information about the current dehydrated device
//   POST /org.matrix.msc2697.v1/dehydrated_device/claim
//        - Claim/rehydrate a dehydrated device
//   DELETE /org.matrix.msc2697.v1/dehydrated_device
//        - Delete the dehydrated device
// ==========================================================================
class DehydratedDeviceServlet : public BaseRestServlet {
public:
  explicit DehydratedDeviceServlet(DehydratedDeviceManager& manager)
      : manager_(manager) {}

  std::vector<std::string> patterns() const override {
    return {
      std::string(API_DEHYDRATED_DEVICE),
      std::string(API_DEHYDRATED_DEVICE_CLAIM),
      std::string(API_DEHYDRATED_DEVICE_EXPORT),
      std::string(API_DEHYDRATED_DEVICE_EVENTS)
    };
  }

  std::vector<std::string> methods() const override {
    return {"GET", "PUT", "POST", "DELETE", "OPTIONS"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    // Require authentication
    if (!req.auth_user.has_value()) {
      return error_response(401, "M_MISSING_TOKEN", "Missing access token");
    }

    const std::string& user_id = *req.auth_user;

    try {
      // Route based on path and method
      if (req.path.find(API_DEHYDRATED_DEVICE_EVENTS) != std::string::npos) {
        return handle_events(req, user_id);
      }

      if (req.path.find(API_DEHYDRATED_DEVICE_CLAIM) != std::string::npos) {
        return handle_claim(req, user_id);
      }

      if (req.path.find(API_DEHYDRATED_DEVICE_EXPORT) != std::string::npos) {
        return handle_export(req, user_id);
      }

      // Main dehydrated device endpoint
      return handle_dehydrated_device(req, user_id);

    } catch (const std::exception& e) {
      return error_response(500, "M_UNKNOWN",
          std::string("Internal error: ") + e.what());
    }
  }

private:
  // Handle the main dehydrated_device endpoint
  HttpResponse handle_dehydrated_device(const HttpRequest& req,
                                          const std::string& user_id) {
    if (req.method == "PUT") {
      return handle_put_device(req, user_id);
    } else if (req.method == "GET") {
      return handle_get_device(user_id);
    } else if (req.method == "DELETE") {
      return handle_delete_device(user_id);
    } else if (req.method == "OPTIONS") {
      return success_response(json::object());
    } else {
      return error_response(405, "M_UNRECOGNIZED",
                             "Method not allowed");
    }
  }

  // PUT: Create/update dehydrated device
  HttpResponse handle_put_device(const HttpRequest& req,
                                   const std::string& user_id) {
    json body;
    try {
      body = BaseRestServlet::parse_json_body(req);
    } catch (const std::exception& e) {
      return error_response(400, "M_NOT_JSON",
          std::string("Invalid JSON: ") + e.what());
    }

    // Validate required fields
    if (!body.contains(FIELD_DEVICE_DATA)) {
      return error_response(400, "M_MISSING_PARAM",
                             "Missing required field: device_data");
    }

    // Parse optional fields
    std::string device_data = body[FIELD_DEVICE_DATA].get<std::string>();
    json device_keys = body.value(FIELD_DEVICE_KEYS, json::object());
    json one_time_keys = body.value(FIELD_ONE_TIME_KEYS, json::object());
    std::string pickle_key_hash = body.value(FIELD_PICKLE_KEY, "");

    auto result = manager_.create_dehydrated_device(
        user_id, device_data, device_keys, one_time_keys, pickle_key_hash);

    if (result.has_value()) {
      json resp;
      resp[FIELD_DEVICE_ID] = *result;
      resp["success"] = true;
      return success_response(resp);
    } else {
      return error_response(409, "M_LIMIT_EXCEEDED",
          "A dehydrated device already exists for this user. Delete it first.");
    }
  }

  // GET: Retrieve dehydrated device info
  HttpResponse handle_get_device(const std::string& user_id) {
    auto result = manager_.get_dehydrated_device(user_id);
    if (result.contains("errcode")) {
      return error_response(404,
          result.value("errcode", "M_NOT_FOUND"),
          result.value("error", "No dehydrated device found"));
    }
    return success_response(result);
  }

  // DELETE: Remove dehydrated device
  HttpResponse handle_delete_device(const std::string& user_id) {
    auto result = manager_.delete_dehydrated_device(user_id);
    return success_response(result);
  }

  // POST: Claim/rehydrate device
  HttpResponse handle_claim(const HttpRequest& req,
                              const std::string& user_id) {
    json body;
    try {
      body = BaseRestServlet::parse_json_body(req);
    } catch (...) {
      body = json::object();
    }

    std::optional<std::string> pickle_key;
    if (body.contains(FIELD_PICKLE_KEY)) {
      pickle_key = body[FIELD_PICKLE_KEY].get<std::string>();
    }

    auto result = manager_.rehydrate_device(user_id, pickle_key);

    if (result.value("success", false)) {
      return success_response(result);
    } else {
      return error_response(
          result.contains("errcode") ? 404 : 500,
          result.value("errcode", "M_UNKNOWN"),
          result.value("error", "Rehydration failed"));
    }
  }

  // GET: Export dehydrated device data
  HttpResponse handle_export(const HttpRequest& req,
                               const std::string& user_id) {
    auto result = manager_.export_dehydrated_device(user_id);
    if (result.empty() || (result.is_object() && result.contains("errcode"))) {
      return error_response(404, "M_NOT_FOUND",
                             "No dehydrated device to export");
    }
    return success_response(result);
  }

  // GET: Queued events for dehydrated device
  HttpResponse handle_events(const HttpRequest& req,
                               const std::string& user_id) {
    int limit = 100;
    auto limit_opt = BaseRestServlet::parse_integer(req, "limit");
    if (limit_opt.has_value() && *limit_opt > 0 && *limit_opt <= 1000) {
      limit = static_cast<int>(*limit_opt);
    }

    auto result = manager_.get_queued_events_for_device(user_id, limit);
    return success_response(result);
  }

  DehydratedDeviceManager& manager_;
};

// ==========================================================================
// DehydratedDeviceKeysServlet - Device key upload for dehydrated devices
//
// Endpoint:
//   POST /org.matrix.msc2697.v1/dehydrated_device/keys/upload
//        - Upload device identity keys for the dehydrated device
// ==========================================================================
class DehydratedDeviceKeysServlet : public BaseRestServlet {
public:
  explicit DehydratedDeviceKeysServlet(DehydratedDeviceManager& manager)
      : manager_(manager) {}

  std::vector<std::string> patterns() const override {
    return {"/org.matrix.msc2697.v1/dehydrated_device/keys/upload"};
  }

  std::vector<std::string> methods() const override {
    return {"POST", "OPTIONS"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (!req.auth_user.has_value()) {
      return error_response(401, "M_MISSING_TOKEN", "Missing access token");
    }

    const std::string& user_id = *req.auth_user;

    if (req.method == "OPTIONS") {
      return success_response(json::object());
    }

    try {
      json body = BaseRestServlet::parse_json_body(req);

      std::string device_id = body.value(FIELD_DEVICE_ID, "");
      if (device_id.empty()) {
        return error_response(400, "M_MISSING_PARAM",
                               "Missing required field: device_id");
      }

      json device_keys = body.value("device_keys",
          body.value(FIELD_DEVICE_KEYS, json::object()));
      json one_time_keys = body.value("one_time_keys",
          body.value(FIELD_ONE_TIME_KEYS, json::object()));
      json fallback_keys = body.value("fallback_keys",
          body.value(FIELD_FALLBACK_KEYS, json::object()));

      auto result = manager_.upload_device_keys_for_dehydrated(
          user_id, device_id, device_keys, one_time_keys, fallback_keys);

      if (result.value("success", false)) {
        json resp;
        resp["success"] = true;
        resp[FIELD_DEVICE_ID] = device_id;
        return success_response(resp);
      } else {
        return error_response(400,
            result.value("errcode", "M_INVALID_PARAM"),
            result.value("error", "Failed to upload keys"));
      }

    } catch (const std::exception& e) {
      return error_response(400, "M_NOT_JSON",
          std::string("Invalid request: ") + e.what());
    }
  }

private:
  DehydratedDeviceManager& manager_;
};

// ==========================================================================
// DehydratedDeviceSignServlet - Cross-signing for dehydrated devices
//
// Endpoint:
//   POST /org.matrix.msc2697.v1/dehydrated_device/sign
//        - Sign a dehydrated device with a cross-signing key
// ==========================================================================
class DehydratedDeviceSignServlet : public BaseRestServlet {
public:
  explicit DehydratedDeviceSignServlet(DehydratedDeviceManager& manager)
      : manager_(manager) {}

  std::vector<std::string> patterns() const override {
    return {"/org.matrix.msc2697.v1/dehydrated_device/sign"};
  }

  std::vector<std::string> methods() const override {
    return {"POST", "OPTIONS"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (!req.auth_user.has_value()) {
      return error_response(401, "M_MISSING_TOKEN", "Missing access token");
    }

    const std::string& user_id = *req.auth_user;

    if (req.method == "OPTIONS") {
      return success_response(json::object());
    }

    try {
      json body = BaseRestServlet::parse_json_body(req);

      // The client sends its master key (public and private) to sign
      // In production, the private key would never leave the client;
      // the signing happens client-side. This endpoint is for server-side
      // cross-signing where the server holds the keys.
      std::string master_priv = body.value("master_private_key",
          body.value("master_key", ""));
      std::string master_pub = body.value("master_public_key", "");

      if (master_priv.empty() || master_pub.empty()) {
        return error_response(400, "M_MISSING_PARAM",
            "Missing required fields: master_private_key, master_public_key");
      }

      // Decode base64 keys
      std::string priv_raw = base64_decode(master_priv);
      std::string pub_raw = base64_decode(master_pub);

      auto result = manager_.sign_dehydrated_device_with_master_key(
          user_id, priv_raw, pub_raw);

      if (result.value("success", false)) {
        return success_response(result);
      } else {
        return error_response(500,
            result.value("errcode", "M_UNKNOWN"),
            result.value("error", "Signing failed"));
      }

    } catch (const std::exception& e) {
      return error_response(400, "M_UNKNOWN",
          std::string("Request error: ") + e.what());
    }
  }

private:
  DehydratedDeviceManager& manager_;
};

// ==========================================================================
// DehydratedDeviceBackupServlet - Key backup for dehydrated devices
//
// Endpoints:
//   POST /org.matrix.msc2697.v1/dehydrated_device/backup
//        - Create a backup of the dehydrated device keys
//   POST /org.matrix.msc2697.v1/dehydrated_device/restore
//        - Restore device keys from backup
// ==========================================================================
class DehydratedDeviceBackupServlet : public BaseRestServlet {
public:
  explicit DehydratedDeviceBackupServlet(DehydratedDeviceManager& manager)
      : manager_(manager) {}

  std::vector<std::string> patterns() const override {
    return {
      "/org.matrix.msc2697.v1/dehydrated_device/backup",
      "/org.matrix.msc2697.v1/dehydrated_device/restore"
    };
  }

  std::vector<std::string> methods() const override {
    return {"POST", "OPTIONS"};
  }

  HttpResponse on_request(const HttpRequest& req) override {
    if (!req.auth_user.has_value()) {
      return error_response(401, "M_MISSING_TOKEN", "Missing access token");
    }

    const std::string& user_id = *req.auth_user;

    if (req.method == "OPTIONS") {
      return success_response(json::object());
    }

    try {
      json body = BaseRestServlet::parse_json_body(req);

      if (req.path.find("/restore") != std::string::npos) {
        return handle_restore(user_id, body);
      }
      return handle_backup(user_id, body);

    } catch (const std::exception& e) {
      return error_response(400, "M_NOT_JSON",
          std::string("Invalid request: ") + e.what());
    }
  }

private:
  HttpResponse handle_backup(const std::string& user_id, const json& body) {
    std::string backup_version = body.value("version", "dehydrated_backup");
    std::string device_id = body.value(FIELD_DEVICE_ID, "");

    if (device_id.empty()) {
      // Derive device_id from the user's dehydrated device
      auto dd = manager_.store().get_dehydrated_device(user_id);
      if (!dd.has_value()) {
        return error_response(404, "M_NOT_FOUND",
                               "No dehydrated device to backup");
      }
      device_id = dd->device_id;
    }

    auto result = manager_.backup_device_keys_for_dehydrated(
        user_id, device_id, backup_version);

    if (result.value("success", false)) {
      return success_response(result);
    }
    return error_response(500,
        result.value("errcode", "M_UNKNOWN"),
        result.value("error", "Backup failed"));
  }

  HttpResponse handle_restore(const std::string& user_id, const json& body) {
    std::string device_id = body.value(FIELD_DEVICE_ID, "");
    std::string backup_key = body.value("backup_key", "");

    if (device_id.empty() || backup_key.empty()) {
      return error_response(400, "M_MISSING_PARAM",
          "Missing required fields: device_id, backup_key");
    }

    auto result = manager_.restore_dehydrated_device_backup(
        user_id, device_id, backup_key);

    if (result.value("success", false)) {
      return success_response(result);
    }
    return error_response(400,
        result.value("errcode", "M_BAD_KEY"),
        result.value("error", "Restore failed"));
  }

  DehydratedDeviceManager& manager_;
};

} // namespace rest

// ============================================================================
// Background cleanup worker
// ============================================================================
class DehydratedDeviceCleanupWorker {
public:
  explicit DehydratedDeviceCleanupWorker(DehydratedDeviceManager& manager)
      : manager_(manager), running_(false) {}

  void start() {
    if (running_.exchange(true)) return;
    worker_thread_ = std::thread([this]() {
      while (running_.load()) {
        try {
          manager_.run_maintenance_if_needed();
        } catch (...) {
          // Log and continue
        }
        std::this_thread::sleep_for(
            chr::milliseconds(CLEANUP_INTERVAL_MS));
      }
    });
  }

  void stop() {
    running_.store(false);
    if (worker_thread_.joinable()) {
      worker_thread_.join();
    }
  }

  ~DehydratedDeviceCleanupWorker() {
    stop();
  }

private:
  DehydratedDeviceManager& manager_;
  std::atomic<bool> running_;
  std::thread worker_thread_;
};

// ============================================================================
// Public API: global singleton access
// Follows the same pattern as key_backup.cpp and e2e_encryption.cpp
// ============================================================================
namespace {

std::unique_ptr<DehydratedDeviceManager> g_dehydration_manager;
std::unique_ptr<DehydratedDeviceCleanupWorker> g_cleanup_worker;
std::mutex g_dehydration_mutex;

} // anonymous namespace

DehydratedDeviceManager* init_device_dehydration(storage::DatabasePool& db) {
  std::lock_guard<std::mutex> lk(g_dehydration_mutex);
  if (!g_dehydration_manager) {
    g_dehydration_manager = std::make_unique<DehydratedDeviceManager>(db);
    g_dehydration_manager->initialize();

    // Start background cleanup worker
    g_cleanup_worker = std::make_unique<DehydratedDeviceCleanupWorker>(
        *g_dehydration_manager);
    g_cleanup_worker->start();
  }
  return g_dehydration_manager.get();
}

DehydratedDeviceManager* get_device_dehydration() {
  std::lock_guard<std::mutex> lk(g_dehydration_mutex);
  return g_dehydration_manager.get();
}

void shutdown_device_dehydration() {
  std::lock_guard<std::mutex> lk(g_dehydration_mutex);
  if (g_cleanup_worker) {
    g_cleanup_worker->stop();
    g_cleanup_worker.reset();
  }
  g_dehydration_manager.reset();
}

std::string get_dehydrated_device_ddl() {
  return DehydratedDeviceStore::get_ddl();
}

// ============================================================================
// REST Servlet factory functions for external registration
// ============================================================================
namespace rest {

std::unique_ptr<BaseRestServlet> create_dehydrated_device_servlet(
    DehydratedDeviceManager& manager) {
  return std::make_unique<DehydratedDeviceServlet>(manager);
}

std::unique_ptr<BaseRestServlet> create_dehydrated_device_keys_servlet(
    DehydratedDeviceManager& manager) {
  return std::make_unique<DehydratedDeviceKeysServlet>(manager);
}

std::unique_ptr<BaseRestServlet> create_dehydrated_device_sign_servlet(
    DehydratedDeviceManager& manager) {
  return std::make_unique<DehydratedDeviceSignServlet>(manager);
}

std::unique_ptr<BaseRestServlet> create_dehydrated_device_backup_servlet(
    DehydratedDeviceManager& manager) {
  return std::make_unique<DehydratedDeviceBackupServlet>(manager);
}

} // namespace rest

} // namespace progressive
