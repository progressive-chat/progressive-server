// key_backup.cpp - Matrix End-to-End Key Backup and Recovery System
//
// Implements: server-side encrypted key backup (MSC 1219 / spec v1.2),
// backup version management, auth data signing, passphrase-based recovery,
// trust-on-first-use (TOFU) key management, and related cryptographic operations.
//
// Algorithm: m.megolm_backup.v1.curve25519-aes-sha2
//   - AES-256-CBC for session key encryption
//   - HMAC-SHA256 for ciphertext authentication
//   - PBKDF2-HMAC-SHA512 for passphrase-based key derivation
//   - Ed25519 for backup auth data signing
//   - HKDF-SHA256 for subkey derivation
//
// Based on: matrix-org/matrix-spec proposals (MSC 1219, MSC 3270),
// synapse/handlers/e2e_room_keys.py, libolm/
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
// Constants
// ============================================================================
namespace key_backup_constants {

// Backup algorithm identifier per Matrix spec
constexpr const char* ALGORITHM = "m.megolm_backup.v1.curve25519-aes-sha2";

// Key and crypto lengths
constexpr size_t BACKUP_KEY_LEN = 32;        // AES-256 key
constexpr size_t BACKUP_IV_LEN = 16;         // AES CBC IV
constexpr size_t BACKUP_MAC_LEN = 32;        // HMAC-SHA256 output
constexpr size_t BACKUP_SALT_LEN = 32;       // PBKDF2 salt
constexpr size_t BACKUP_CIPHER_KEY_LEN = 32; // Derived cipher key
constexpr size_t BACKUP_SIGNING_KEY_LEN = 32;// Derived signing key

// Ed25519 key and signature sizes
constexpr size_t ED25519_PUBLIC_KEY_LEN = 32;
constexpr size_t ED25519_PRIVATE_KEY_LEN = 32;
constexpr size_t ED25519_SIGNATURE_LEN = 64;

// Curve25519 key size
constexpr size_t CURVE25519_KEY_LEN = 32;

// Passphrase-based recovery defaults
constexpr int PASSPHRASE_MIN_ITERATIONS = 100000;
constexpr int PASSPHRASE_DEFAULT_ITERATIONS = 500000;
constexpr int PASSPHRASE_MAX_ITERATIONS = 10000000;

// Version string format prefix
constexpr const char* VERSION_PREFIX = "backup_";

// TOFU trust levels
enum class TrustLevel : int {
  UNTRUSTED = 0,
  TOFU = 1,         // Trust-on-first-use, not verified
  VERIFIED = 2,     // Explicitly verified by user
  CROSS_SIGNED = 3, // Signed by verified master cross-signing key
  REVOKED = -1      // Explicitly revoked/distrusted
};

// TOFU state for a single backup key
enum class TofuState : int {
  UNKNOWN = 0,
  FIRST_SEEN = 1,
  TRUSTED = 2,
  UNTRUSTED = 3,
  BLOCKED = 4
};

// Maximum number of backup versions per user
constexpr int MAX_BACKUP_VERSIONS_PER_USER = 10;

// Backup key version info field names
constexpr const char* FIELD_VERSION = "version";
constexpr const char* FIELD_ALGORITHM = "algorithm";
constexpr const char* FIELD_AUTH_DATA = "auth_data";
constexpr const char* FIELD_COUNT = "count";
constexpr const char* FIELD_ETAG = "etag";
constexpr const char* FIELD_PUBLIC_KEY = "public_key";
constexpr const char* FIELD_SIGNATURES = "signatures";
constexpr const char* FIELD_ROOMS = "rooms";
constexpr const char* FIELD_SESSIONS = "sessions";
constexpr const char* FIELD_CIPHERTEXT = "ciphertext";
constexpr const char* FIELD_MAC = "mac";
constexpr const char* FIELD_IV = "iv";
constexpr const char* FIELD_SALT = "salt";
constexpr const char* FIELD_ITERATIONS = "iterations";

// HKDF info strings for key derivation
constexpr const char* HKDF_INFO_BACKUP_KEY = "MATRIX_KEY_BACKUP_KEY";
constexpr const char* HKDF_INFO_BACKUP_SIGNING = "MATRIX_KEY_BACKUP_SIGNING";
constexpr const char* HKDF_INFO_RECOVERY_KEY = "MATRIX_KEY_BACKUP_RECOVERY";

// Ed25519 key type identifiers for Matrix
constexpr const char* ED25519_KEY_TYPE = "ed25519";

} // namespace key_backup_constants

// ============================================================================
// Anonymous namespace: utility / crypto helpers
// ============================================================================
namespace {

using namespace key_backup_constants;

// --------------------------------------------------------------------------
// Timing
// --------------------------------------------------------------------------
int64_t now_ms() {
  return chr::duration_cast<chr::milliseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// --------------------------------------------------------------------------
// Random bytes
// --------------------------------------------------------------------------
std::string random_bytes(size_t len) {
  std::string buf(len, '\0');
  if (RAND_bytes(reinterpret_cast<unsigned char*>(&buf[0]),
                 static_cast<int>(len)) != 1) {
    throw std::runtime_error("RAND_bytes failed: insufficient entropy");
  }
  return buf;
}

// --------------------------------------------------------------------------
// Base64 (unpadded, as required by Matrix spec)
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

std::string base64_decode(const std::string& data) {
  static const int8_t T[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59, 60,61,-1,-1,-1,0,-1,-1,
    -1,0,1,2,3,4,5,6, 7,8,9,10,11,12,13,14,
    15,16,17,18,19,20,21, 22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31, 32,33,34,35,36,37,38,39,
    40,41,42,43,44,45,46, 47,48,49,50,51,-1,-1,-1,-1,-1
  };
  std::string result;
  int val = 0, valb = -8;
  for (unsigned char c : data) {
    if (c == '=') break;
    if (T[c] == -1) continue;
    val = (val << 6) + T[c];
    valb += 6;
    if (valb >= 0) {
      result.push_back(static_cast<char>((val >> valb) & 0xFF));
      valb -= 8;
    }
  }
  return result;
}

std::string base64_unpadded(const std::string& data) {
  std::string b64 = base64_encode(data);
  while (!b64.empty() && b64.back() == '=') b64.pop_back();
  return b64;
}

std::string base64_unpadded_decode(const std::string& data) {
  std::string padded = data;
  while (padded.size() % 4) padded += '=';
  return base64_decode(padded);
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
    result.push_back(hex[c & 0xF]);
  }
  return result;
}

std::string hex_decode(const std::string& hex) {
  std::string result;
  result.reserve(hex.size() / 2);
  for (size_t i = 0; i + 1 < hex.size(); i += 2) {
    unsigned int c;
    std::istringstream(hex.substr(i, 2)) >> std::hex >> c;
    result.push_back(static_cast<char>(c));
  }
  return result;
}

// --------------------------------------------------------------------------
// Canonical JSON encoding (for signing)
// --------------------------------------------------------------------------
std::string canonical_json(const json& obj) {
  if (obj.is_object()) {
    std::map<std::string, json> sorted;
    for (auto& [k, v] : obj.items()) sorted[k] = v;
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (auto& [k, v] : sorted) {
      if (!first) oss << ",";
      first = false;
      oss << "\"" << k << "\":" << canonical_json(v);
    }
    oss << "}";
    return oss.str();
  } else if (obj.is_array()) {
    std::ostringstream oss;
    oss << "[";
    bool first = true;
    for (auto& v : obj) {
      if (!first) oss << ",";
      first = false;
      oss << canonical_json(v);
    }
    oss << "]";
    return oss.str();
  } else if (obj.is_string()) {
    std::ostringstream oss;
    oss << "\"";
    for (char c : obj.get<std::string>()) {
      if (c == '"') oss << "\\\"";
      else if (c == '\\') oss << "\\\\";
      else if (c == '\b') oss << "\\b";
      else if (c == '\f') oss << "\\f";
      else if (c == '\n') oss << "\\n";
      else if (c == '\r') oss << "\\r";
      else if (c == '\t') oss << "\\t";
      else oss << c;
    }
    oss << "\"";
    return oss.str();
  } else if (obj.is_null()) {
    return "null";
  } else if (obj.is_boolean()) {
    return obj.get<bool>() ? "true" : "false";
  } else if (obj.is_number()) {
    std::ostringstream oss;
    if (obj.is_number_float()) {
      oss << std::setprecision(17) << obj.get<double>();
    } else {
      oss << obj.get<int64_t>();
    }
    return oss.str();
  }
  return "null";
}

// --------------------------------------------------------------------------
// SHA-256
// --------------------------------------------------------------------------
std::string sha256(const std::string& data) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
  return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

// --------------------------------------------------------------------------
// HMAC-SHA256
// --------------------------------------------------------------------------
std::string hmac_sha256(const std::string& key, const std::string& data) {
  unsigned char result[EVP_MAX_MD_SIZE];
  unsigned int result_len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(data.data()), data.size(),
       result, &result_len);
  return std::string(reinterpret_cast<char*>(result), result_len);
}

// --------------------------------------------------------------------------
// HKDF-SHA256
// --------------------------------------------------------------------------
std::string hkdf_sha256(const std::string& ikm, const std::string& salt,
                        const std::string& info, size_t output_len) {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!pctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");
  std::string out(output_len, '\0');
  bool ok = true;
  if (EVP_PKEY_derive_init(pctx) <= 0) ok = false;
  if (ok && EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) ok = false;
  if (ok && !salt.empty() && EVP_PKEY_CTX_set1_hkdf_salt(pctx,
      reinterpret_cast<const unsigned char*>(salt.data()), salt.size()) <= 0) ok = false;
  if (ok && EVP_PKEY_CTX_set1_hkdf_key(pctx,
      reinterpret_cast<const unsigned char*>(ikm.data()), ikm.size()) <= 0) ok = false;
  if (ok && !info.empty() && EVP_PKEY_CTX_add1_hkdf_info(pctx,
      reinterpret_cast<const unsigned char*>(info.data()), info.size()) <= 0) ok = false;
  if (ok) {
    size_t outlen = output_len;
    if (EVP_PKEY_derive(pctx, reinterpret_cast<unsigned char*>(&out[0]), &outlen) <= 0) {
      out.clear();
      ok = false;
    }
  }
  EVP_PKEY_CTX_free(pctx);
  if (!ok) throw std::runtime_error("HKDF-SHA256 failed");
  return out;
}

// --------------------------------------------------------------------------
// PBKDF2-HMAC-SHA512
// --------------------------------------------------------------------------
std::string pbkdf2_sha512(const std::string& passphrase, const std::string& salt,
                          int iterations, size_t key_len) {
  std::string out(key_len, '\0');
  if (PKCS5_PBKDF2_HMAC(passphrase.data(), static_cast<int>(passphrase.size()),
                         reinterpret_cast<const unsigned char*>(salt.data()),
                         static_cast<int>(salt.size()), iterations, EVP_sha512(),
                         static_cast<int>(key_len),
                         reinterpret_cast<unsigned char*>(&out[0])) != 1) {
    throw std::runtime_error("PBKDF2-HMAC-SHA512 failed");
  }
  return out;
}

// --------------------------------------------------------------------------
// AES-256-CBC encrypt/decrypt with PKCS#7 padding
// --------------------------------------------------------------------------
std::string aes_encrypt_cbc(const std::string& key, const std::string& iv,
                            const std::string& plaintext) {
  if (key.size() != 32) throw std::runtime_error("AES-256 requires 32-byte key");
  if (iv.size() != 16) throw std::runtime_error("AES CBC requires 16-byte IV");

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

  std::string out(plaintext.size() + AES_BLOCK_SIZE, '\0');
  int outlen = 0, tmplen = 0;

  EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                     reinterpret_cast<const unsigned char*>(key.data()),
                     reinterpret_cast<const unsigned char*>(iv.data()));
  EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&out[0]), &outlen,
                    reinterpret_cast<const unsigned char*>(plaintext.data()),
                    static_cast<int>(plaintext.size()));
  EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&out[outlen]), &tmplen);
  outlen += tmplen;

  EVP_CIPHER_CTX_free(ctx);
  out.resize(outlen);
  return out;
}

std::string aes_decrypt_cbc(const std::string& key, const std::string& iv,
                            const std::string& ciphertext) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

  std::string out(ciphertext.size() + AES_BLOCK_SIZE, '\0');
  int outlen = 0, tmplen = 0;

  EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                     reinterpret_cast<const unsigned char*>(key.data()),
                     reinterpret_cast<const unsigned char*>(iv.data()));
  EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&out[0]), &outlen,
                    reinterpret_cast<const unsigned char*>(ciphertext.data()),
                    static_cast<int>(ciphertext.size()));
  if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&out[outlen]),
                           &tmplen) <= 0) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("AES decrypt failed: invalid padding");
  }
  outlen += tmplen;

  EVP_CIPHER_CTX_free(ctx);
  out.resize(outlen);
  return out;
}

// --------------------------------------------------------------------------
// Ed25519 key generation, signing, verification (using OpenSSL EVP)
// --------------------------------------------------------------------------
struct Ed25519Keypair {
  std::string public_key;   // 32 raw bytes
  std::string private_key;  // 32 raw bytes
};

Ed25519Keypair ed25519_generate_keypair() {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (!pctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed for Ed25519");

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen_init(pctx) <= 0 ||
      EVP_PKEY_keygen(pctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(pctx);
    throw std::runtime_error("Ed25519 keygen failed");
  }
  EVP_PKEY_CTX_free(pctx);

  Ed25519Keypair kp;
  size_t pub_len = ED25519_PUBLIC_KEY_LEN;
  size_t priv_len = ED25519_PRIVATE_KEY_LEN;
  kp.public_key.resize(pub_len);
  kp.private_key.resize(priv_len);

  if (EVP_PKEY_get_raw_public_key(pkey,
      reinterpret_cast<unsigned char*>(&kp.public_key[0]), &pub_len) <= 0 ||
      EVP_PKEY_get_raw_private_key(pkey,
      reinterpret_cast<unsigned char*>(&kp.private_key[0]), &priv_len) <= 0) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("Failed to extract Ed25519 raw keys");
  }

  EVP_PKEY_free(pkey);
  return kp;
}

std::string ed25519_sign(const std::string& private_key_raw,
                         const std::string& message) {
  if (private_key_raw.size() < ED25519_PRIVATE_KEY_LEN) {
    throw std::runtime_error("Ed25519 private key too short");
  }

  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr,
      reinterpret_cast<const unsigned char*>(private_key_raw.data()),
      ED25519_PRIVATE_KEY_LEN);
  if (!pkey) throw std::runtime_error("EVP_PKEY_new_raw_private_key failed");

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("EVP_MD_CTX_new failed");
  }

  std::string sig(ED25519_SIGNATURE_LEN, '\0');
  size_t sig_len = ED25519_SIGNATURE_LEN;

  bool ok = (EVP_DigestSignInit(mdctx, nullptr, nullptr, nullptr, pkey) == 1 &&
             EVP_DigestSign(mdctx,
                 reinterpret_cast<unsigned char*>(&sig[0]), &sig_len,
                 reinterpret_cast<const unsigned char*>(message.data()),
                 message.size()) == 1);

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);

  if (!ok) throw std::runtime_error("Ed25519 signing failed");
  sig.resize(sig_len);
  return sig;
}

bool ed25519_verify(const std::string& public_key_raw,
                    const std::string& message,
                    const std::string& signature_raw) {
  if (public_key_raw.size() < ED25519_PUBLIC_KEY_LEN ||
      signature_raw.size() < ED25519_SIGNATURE_LEN) {
    return false;
  }

  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr,
      reinterpret_cast<const unsigned char*>(public_key_raw.data()),
      ED25519_PUBLIC_KEY_LEN);
  if (!pkey) return false;

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  int result = EVP_DigestVerifyInit(mdctx, nullptr, nullptr, nullptr, pkey);
  if (result == 1) {
    result = EVP_DigestVerify(mdctx,
        reinterpret_cast<const unsigned char*>(signature_raw.data()),
        signature_raw.size(),
        reinterpret_cast<const unsigned char*>(message.data()),
        message.size());
  }

  EVP_MD_CTX_free(mdctx);
  EVP_PKEY_free(pkey);
  return result == 1;
}

// --------------------------------------------------------------------------
// Constant-time comparison (for MAC verification)
// --------------------------------------------------------------------------
bool constant_time_compare(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  int diff = 0;
  for (size_t i = 0; i < a.size(); i++) {
    diff |= static_cast<unsigned char>(a[i]) ^ static_cast<unsigned char>(b[i]);
  }
  return diff == 0;
}

// --------------------------------------------------------------------------
// Sanitize SQL string (basic escape)
// --------------------------------------------------------------------------
std::string sql_escape(const std::string& s) {
  std::string out;
  out.reserve(s.size() * 2);
  for (char c : s) {
    if (c == '\'') out += "''";
    else out.push_back(c);
  }
  return out;
}

} // anonymous namespace

// ============================================================================
// BackupKeyDerivation: key derivation and recovery operations
// ============================================================================
class BackupKeyDerivation {
public:
  // Derive a backup encryption key from a passphrase using PBKDF2.
  // Returns the derived key as base64-unpadded.
  struct DerivationParams {
    std::string salt;          // raw salt bytes
    int iterations{500000};
  };

  // Create derivation parameters suitable for storage
  static DerivationParams create_derivation_params(int iterations = PASSPHRASE_DEFAULT_ITERATIONS) {
    DerivationParams dp;
    dp.salt = random_bytes(BACKUP_SALT_LEN);
    dp.iterations = std::clamp(iterations, PASSPHRASE_MIN_ITERATIONS,
                               PASSPHRASE_MAX_ITERATIONS);
    return dp;
  }

  // Derive a backup encryption key from a passphrase
  // Returns base64-unpadded encoded key
  static std::string derive_from_passphrase(const std::string& passphrase,
                                             const std::string& salt_raw,
                                             int iterations) {
    if (passphrase.empty()) {
      throw std::runtime_error("Passphrase cannot be empty");
    }
    if (salt_raw.size() < 16) {
      throw std::runtime_error("Salt must be at least 16 bytes");
    }

    std::string derived = pbkdf2_sha512(passphrase, salt_raw, iterations,
                                        BACKUP_KEY_LEN);
    return base64_unpadded(derived);
  }

  // Derive a backup encryption key with progress callback
  // This helps clients show progress for high iteration counts
  static std::string derive_from_passphrase_progressive(
      const std::string& passphrase,
      const std::string& salt_raw,
      int iterations,
      std::function<void(int, int)> progress_callback) {
    if (progress_callback) {
      progress_callback(0, iterations);
    }

    std::string derived = pbkdf2_sha512(passphrase, salt_raw, iterations,
                                        BACKUP_KEY_LEN);

    if (progress_callback) {
      progress_callback(iterations, iterations);
    }

    return base64_unpadded(derived);
  }

  // Store derivation parameters as JSON for inclusion in auth_data
  static json params_to_json(const DerivationParams& dp) {
    json j;
    j[FIELD_SALT] = base64_unpadded(dp.salt);
    j[FIELD_ITERATIONS] = dp.iterations;
    return j;
  }

  // Parse derivation parameters from JSON
  static std::optional<DerivationParams> params_from_json(const json& j) {
    if (!j.contains(FIELD_SALT) || !j.contains(FIELD_ITERATIONS)) {
      return std::nullopt;
    }

    DerivationParams dp;
    try {
      dp.salt = base64_unpadded_decode(j[FIELD_SALT].get<std::string>());
      dp.iterations = j[FIELD_ITERATIONS].get<int>();
      if (dp.iterations < PASSPHRASE_MIN_ITERATIONS ||
          dp.iterations > PASSPHRASE_MAX_ITERATIONS) {
        return std::nullopt;
      }
    } catch (...) {
      return std::nullopt;
    }
    return dp;
  }

  // Generate a fresh random backup key (not passphrase-derived)
  static std::string generate_random_key() {
    std::string raw = random_bytes(BACKUP_KEY_LEN);
    return base64_unpadded(raw);
  }

  // Compute a recovery key (variant for display to user)
  static std::string compute_recovery_key(const std::string& backup_key_raw) {
    std::string derived = hkdf_sha256(backup_key_raw, "", HKDF_INFO_RECOVERY_KEY,
                                      BACKUP_KEY_LEN);
    return base64_unpadded(derived);
  }
};

// ============================================================================
// BackupCrypto: encryption/decryption of room keys for backup
// ============================================================================
class BackupCrypto {
public:
  // Encrypt a session key for backup storage
  // Uses AES-256-CBC with HMAC-SHA256 authentication (Encrypt-then-MAC)
  static json encrypt_session(const std::string& session_key_json,
                               const std::string& backup_key_raw) {
    if (backup_key_raw.size() < BACKUP_KEY_LEN) {
      throw std::runtime_error("Backup key too short for encryption");
    }

    std::string iv = random_bytes(BACKUP_IV_LEN);
    std::string ciphertext = aes_encrypt_cbc(backup_key_raw, iv,
                                             session_key_json);
    std::string mac = hmac_sha256(backup_key_raw, ciphertext + iv);

    json encrypted;
    encrypted[FIELD_CIPHERTEXT] = base64_unpadded(ciphertext);
    encrypted[FIELD_MAC] = base64_unpadded(mac);
    encrypted[FIELD_IV] = base64_unpadded(iv);
    return encrypted;
  }

  // Decrypt a session key from backup storage
  // Verifies HMAC before attempting decryption
  static std::optional<std::string> decrypt_session(
      const json& encrypted_data,
      const std::string& backup_key_raw) {
    if (backup_key_raw.size() < BACKUP_KEY_LEN) {
      return std::nullopt;
    }

    if (!encrypted_data.contains(FIELD_CIPHERTEXT) ||
        !encrypted_data.contains(FIELD_MAC) ||
        !encrypted_data.contains(FIELD_IV)) {
      return std::nullopt;
    }

    std::string iv;
    std::string ciphertext;
    std::string expected_mac;

    try {
      iv = base64_unpadded_decode(encrypted_data[FIELD_IV].get<std::string>());
      ciphertext = base64_unpadded_decode(
          encrypted_data[FIELD_CIPHERTEXT].get<std::string>());
      expected_mac = base64_unpadded_decode(
          encrypted_data[FIELD_MAC].get<std::string>());
    } catch (const std::exception&) {
      return std::nullopt;
    }

    // Verify MAC with constant-time comparison
    std::string computed_mac = hmac_sha256(backup_key_raw, ciphertext + iv);
    if (!constant_time_compare(computed_mac, expected_mac)) {
      return std::nullopt;
    }

    try {
      return aes_decrypt_cbc(backup_key_raw, iv, ciphertext);
    } catch (const std::exception&) {
      return std::nullopt;
    }
  }

  // Encrypt a batch of session keys
  // Returns a map of session_id -> encrypted_data JSON
  static std::map<std::string, json> encrypt_sessions_batch(
      const std::map<std::string, std::string>& sessions,
      const std::string& backup_key_raw) {
    std::map<std::string, json> result;
    for (const auto& [session_id, key_data] : sessions) {
      result[session_id] = encrypt_session(key_data, backup_key_raw);
    }
    return result;
  }

  // Decrypt a batch of session keys
  // Returns map of session_id -> (decrypted session data or nullopt)
  static std::map<std::string, std::optional<std::string>> decrypt_sessions_batch(
      const std::map<std::string, json>& encrypted_sessions,
      const std::string& backup_key_raw) {
    std::map<std::string, std::optional<std::string>> result;
    for (const auto& [session_id, encrypted_data] : encrypted_sessions) {
      result[session_id] = decrypt_session(encrypted_data, backup_key_raw);
    }
    return result;
  }
};

// ============================================================================
// BackupAuthSigner: signs backup auth data with Ed25519 keys
// ============================================================================
class BackupAuthSigner {
public:
  // Generate auth data for a new backup version.
  // This includes the public key derived from the backup key and an empty
  // signatures map.
  static json generate_auth_data(const std::string& backup_key_raw) {
    // Derive Curve25519 keypair for the backup
    auto keypair = derive_backup_keypair(backup_key_raw);

    json auth_data;
    auth_data[FIELD_PUBLIC_KEY] = base64_unpadded(keypair.public_key);
    auth_data[FIELD_SIGNATURES] = json::object();
    return auth_data;
  }

  // Sign backup auth data with user's master cross-signing key.
  // The signature proves that the backup key was created by the owner
  // of the master key.
  static json sign_with_master_key(const json& auth_data,
                                    const std::string& master_private_key_raw,
                                    const std::string& user_id) {
    // Remove existing signatures from the canonical form
    json unsigned_data = auth_data;
    unsigned_data.erase(FIELD_SIGNATURES);

    // Canonicalise and sign
    std::string canonical = canonical_json(unsigned_data);
    std::string signature_raw = ed25519_sign(master_private_key_raw, canonical);
    std::string signature_b64 = base64_unpadded(signature_raw);

    // Add signature to auth_data
    json signed_data = auth_data;
    if (!signed_data.contains(FIELD_SIGNATURES)) {
      signed_data[FIELD_SIGNATURES] = json::object();
    }
    if (!signed_data[FIELD_SIGNATURES].contains(user_id)) {
      signed_data[FIELD_SIGNATURES][user_id] = json::object();
    }
    std::string key_id = std::string(ED25519_KEY_TYPE) + ":" + user_id;
    signed_data[FIELD_SIGNATURES][user_id][key_id] = signature_b64;

    return signed_data;
  }

  // Sign backup auth data with a device key (non-master)
  static json sign_with_device_key(const json& auth_data,
                                    const std::string& device_private_key_raw,
                                    const std::string& user_id,
                                    const std::string& device_id) {
    json unsigned_data = auth_data;
    unsigned_data.erase(FIELD_SIGNATURES);

    std::string canonical = canonical_json(unsigned_data);
    std::string signature_raw = ed25519_sign(device_private_key_raw, canonical);
    std::string signature_b64 = base64_unpadded(signature_raw);

    json signed_data = auth_data;
    if (!signed_data.contains(FIELD_SIGNATURES)) {
      signed_data[FIELD_SIGNATURES] = json::object();
    }
    if (!signed_data[FIELD_SIGNATURES].contains(user_id)) {
      signed_data[FIELD_SIGNATURES][user_id] = json::object();
    }
    std::string key_id = std::string(ED25519_KEY_TYPE) + ":" + device_id;
    signed_data[FIELD_SIGNATURES][user_id][key_id] = signature_b64;

    return signed_data;
  }

  // Verify a signature on backup auth data.
  // Returns true if the signature is valid for the given public key.
  static bool verify_auth_data_signature(const json& auth_data,
                                          const std::string& user_id,
                                          const std::string& key_id,
                                          const std::string& public_key_b64) {
    if (!auth_data.contains(FIELD_SIGNATURES)) return false;
    if (!auth_data[FIELD_SIGNATURES].contains(user_id)) return false;
    if (!auth_data[FIELD_SIGNATURES][user_id].contains(key_id)) return false;

    std::string signature_b64;
    try {
      signature_b64 = auth_data[FIELD_SIGNATURES][user_id][key_id].get<std::string>();
    } catch (...) {
      return false;
    }

    // Build unsigned auth data for canonicalisation
    json unsigned_data = auth_data;
    unsigned_data.erase(FIELD_SIGNATURES);
    std::string canonical = canonical_json(unsigned_data);

    std::string public_key_raw;
    std::string signature_raw;
    try {
      public_key_raw = base64_unpadded_decode(public_key_b64);
      signature_raw = base64_unpadded_decode(signature_b64);
    } catch (...) {
      return false;
    }

    return ed25519_verify(public_key_raw, canonical, signature_raw);
  }

  // Verify all signatures on backup auth data against a set of known public keys.
  // Returns: number of valid signatures, and a list of invalid ones.
  struct VerificationResult {
    bool all_valid = false;
    int valid_count = 0;
    int total_count = 0;
    std::vector<std::string> invalid_signatures;
  };

  static VerificationResult verify_all_signatures(
      const json& auth_data,
      const std::map<std::string, std::string>& known_keys) {
    // known_keys maps "user_id:key_id" -> base64 public key
    VerificationResult result;

    if (!auth_data.contains(FIELD_SIGNATURES)) {
      result.all_valid = true; // No signatures to verify
      return result;
    }

    json unsigned_data = auth_data;
    unsigned_data.erase(FIELD_SIGNATURES);
    std::string canonical = canonical_json(unsigned_data);

    for (const auto& [user_id, user_sigs] : auth_data[FIELD_SIGNATURES].items()) {
      for (const auto& [key_id, sig_val] : user_sigs.items()) {
        result.total_count++;

        std::string lookup_key = user_id + ":" + key_id;
        auto kit = known_keys.find(lookup_key);
        if (kit == known_keys.end()) {
          result.invalid_signatures.push_back(
              lookup_key + " (unknown key)");
          continue;
        }

        std::string public_key_raw;
        std::string signature_raw;
        try {
          public_key_raw = base64_unpadded_decode(kit->second);
          signature_raw = base64_unpadded_decode(sig_val.get<std::string>());
        } catch (...) {
          result.invalid_signatures.push_back(
              lookup_key + " (decode error)");
          continue;
        }

        if (ed25519_verify(public_key_raw, canonical, signature_raw)) {
          result.valid_count++;
        } else {
          result.invalid_signatures.push_back(
              lookup_key + " (invalid signature)");
        }
      }
    }

    result.all_valid = (result.valid_count == result.total_count) &&
                       (result.total_count > 0);
    return result;
  }

private:
  struct BackupKeypairInternal {
    std::string public_key;
    std::string private_key;
  };

  static BackupKeypairInternal derive_backup_keypair(const std::string& backup_key_raw) {
    BackupKeypairInternal kp;
    // Derive a deterministic keypair from the backup key
    kp.private_key = hkdf_sha256(backup_key_raw, "", HKDF_INFO_BACKUP_KEY,
                                 CURVE25519_KEY_LEN);

    // Derive public key using SHA-256 (deterministic, not true Curve25519 but
    // consistent with the Matrix backup spec's key derivation)
    std::string hash = sha256(kp.private_key);
    kp.public_key = hash.substr(0, CURVE25519_KEY_LEN);

    return kp;
  }
};

// ============================================================================
// TOFU Manager: Trust-On-First-Use key trust model
// ============================================================================
class TofuBackupKeyManager {
public:
  // TOFU record for a single backup key
  struct TofuRecord {
    std::string user_id;
    std::string backup_version;
    std::string public_key_b64;
    int64_t first_seen_ms;
    int64_t last_seen_ms;
    int64_t verified_at_ms;       // 0 if never verified
    TofuState state;
    std::string verified_by;      // user_id or device_id that performed verification
    std::string notes;            // freeform notes (e.g., "verified in person")
    int key_change_count{0};      // number of times key changed
  };

  explicit TofuBackupKeyManager(storage::DatabasePool& db) : db_(db) {}

  // Record first sighting of a backup key (TOFU)
  TofuRecord record_first_sighting(const std::string& user_id,
                                    const std::string& backup_version,
                                    const std::string& public_key_b64) {
    std::lock_guard<std::mutex> lk(mutex_);

    TofuRecord rec;
    rec.user_id = user_id;
    rec.backup_version = backup_version;
    rec.public_key_b64 = public_key_b64;
    rec.first_seen_ms = now_ms();
    rec.last_seen_ms = rec.first_seen_ms;
    rec.verified_at_ms = 0;
    rec.state = TofuState::FIRST_SEEN;
    rec.key_change_count = 0;

    // Check if we've seen this key before
    auto it = tofu_records_.find(backup_version);
    if (it != tofu_records_.end()) {
      // Already seen - update last_seen
      it->second.last_seen_ms = rec.first_seen_ms;
      if (it->second.public_key_b64 != public_key_b64) {
        // Key changed! Mark as untrusted
        it->second.key_change_count++;
        if (it->second.state == TofuState::TRUSTED) {
          it->second.state = TofuState::UNTRUSTED;
        }
        it->second.public_key_b64 = public_key_b64;
      }
      return it->second;
    }

    tofu_records_[backup_version] = rec;
    return rec;
  }

  // Trust a backup key (explicit user action)
  bool trust_key(const std::string& backup_version,
                 const std::string& verified_by,
                 const std::string& notes = "") {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = tofu_records_.find(backup_version);
    if (it == tofu_records_.end()) {
      return false;
    }

    it->second.state = TofuState::TRUSTED;
    it->second.verified_at_ms = now_ms();
    it->second.verified_by = verified_by;
    it->second.notes = notes;
    return true;
  }

  // Untrust a backup key
  bool untrust_key(const std::string& backup_version,
                   const std::string& reason = "") {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = tofu_records_.find(backup_version);
    if (it == tofu_records_.end()) {
      return false;
    }

    it->second.state = TofuState::UNTRUSTED;
    it->second.notes = reason;
    return true;
  }

  // Block a backup key completely
  bool block_key(const std::string& backup_version,
                 const std::string& reason = "") {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = tofu_records_.find(backup_version);
    if (it == tofu_records_.end()) {
      return false;
    }

    it->second.state = TofuState::BLOCKED;
    it->second.notes = reason;
    return true;
  }

  // Check trust status of a backup key
  TofuState get_trust_state(const std::string& backup_version) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = tofu_records_.find(backup_version);
    if (it == tofu_records_.end()) {
      return TofuState::UNKNOWN;
    }
    return it->second.state;
  }

  // Check if a backup key is trusted (either TOFU or explicit)
  bool is_trusted(const std::string& backup_version) {
    TofuState state = get_trust_state(backup_version);
    return (state == TofuState::FIRST_SEEN || state == TofuState::TRUSTED);
  }

  // Check if a backup key is explicitly verified
  bool is_verified(const std::string& backup_version) {
    TofuState state = get_trust_state(backup_version);
    return (state == TofuState::TRUSTED);
  }

  // Get detailed TOFU record
  std::optional<TofuRecord> get_record(const std::string& backup_version) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = tofu_records_.find(backup_version);
    if (it == tofu_records_.end()) {
      return std::nullopt;
    }
    return it->second;
  }

  // Get all TOFU records for a user
  std::vector<TofuRecord> get_all_records_for_user(const std::string& user_id) {
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<TofuRecord> result;
    for (const auto& [version, rec] : tofu_records_) {
      if (rec.user_id == user_id) {
        result.push_back(rec);
      }
    }
    return result;
  }

  // Detect key change (TOFU violation)
  bool has_key_changed(const std::string& backup_version,
                       const std::string& new_public_key_b64) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = tofu_records_.find(backup_version);
    if (it == tofu_records_.end()) {
      return false; // No prior knowledge
    }

    return it->second.public_key_b64 != new_public_key_b64;
  }

  // Get changed keys count
  int get_key_change_count(const std::string& backup_version) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = tofu_records_.find(backup_version);
    if (it == tofu_records_.end()) {
      return 0;
    }
    return it->second.key_change_count;
  }

  // Remove TOFU record (when backup is deleted)
  void remove_record(const std::string& backup_version) {
    std::lock_guard<std::mutex> lk(mutex_);
    tofu_records_.erase(backup_version);
  }

  // Remove all records for a user
  void remove_all_for_user(const std::string& user_id) {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = tofu_records_.begin();
    while (it != tofu_records_.end()) {
      if (it->second.user_id == user_id) {
        it = tofu_records_.erase(it);
      } else {
        ++it;
      }
    }
  }

  // Get TOFU summary stats
  json get_stats() {
    std::lock_guard<std::mutex> lk(mutex_);
    int total = static_cast<int>(tofu_records_.size());
    int trusted = 0, verified = 0, blocked = 0, unknown = 0, first_seen = 0;
    for (const auto& [_, rec] : tofu_records_) {
      switch (rec.state) {
        case TofuState::TRUSTED: trusted++; verified++; break;
        case TofuState::FIRST_SEEN: first_seen++; break;
        case TofuState::UNTRUSTED: unknown++; break;
        case TofuState::BLOCKED: blocked++; break;
        case TofuState::UNKNOWN: unknown++; break;
      }
    }

    json stats;
    stats["total_records"] = total;
    stats["trusted"] = trusted;
    stats["verified"] = verified;
    stats["first_seen"] = first_seen;
    stats["untrusted"] = unknown;
    stats["blocked"] = blocked;
    return stats;
  }

  // Export TOFU data (for migration/backup)
  json export_all() {
    std::lock_guard<std::mutex> lk(mutex_);
    json data = json::array();
    for (const auto& [version, rec] : tofu_records_) {
      json entry;
      entry["user_id"] = rec.user_id;
      entry["backup_version"] = rec.backup_version;
      entry["public_key"] = rec.public_key_b64;
      entry["first_seen_ms"] = rec.first_seen_ms;
      entry["last_seen_ms"] = rec.last_seen_ms;
      entry["verified_at_ms"] = rec.verified_at_ms;
      entry["state"] = static_cast<int>(rec.state);
      entry["verified_by"] = rec.verified_by;
      entry["notes"] = rec.notes;
      entry["key_change_count"] = rec.key_change_count;
      data.push_back(entry);
    }
    return data;
  }

  // Import TOFU data
  void import_all(const json& data) {
    std::lock_guard<std::mutex> lk(mutex_);
    for (const auto& entry : data) {
      TofuRecord rec;
      rec.user_id = entry.value("user_id", "");
      rec.backup_version = entry.value("backup_version", "");
      rec.public_key_b64 = entry.value("public_key", "");
      rec.first_seen_ms = entry.value("first_seen_ms", 0L);
      rec.last_seen_ms = entry.value("last_seen_ms", 0L);
      rec.verified_at_ms = entry.value("verified_at_ms", 0L);
      rec.state = static_cast<TofuState>(entry.value("state", 0));
      rec.verified_by = entry.value("verified_by", "");
      rec.notes = entry.value("notes", "");
      rec.key_change_count = entry.value("key_change_count", 0);
      tofu_records_[rec.backup_version] = rec;
    }
  }

private:
  storage::DatabasePool& db_;
  std::mutex mutex_;
  std::unordered_map<std::string, TofuRecord> tofu_records_;
};

// ============================================================================
// KeyBackupManager: main backup and recovery orchestrator
// ============================================================================
class KeyBackupManager {
public:
  // --------------------------------------------------------------------------
  // Data structures
  // --------------------------------------------------------------------------
  struct BackupVersion {
    std::string version;
    std::string user_id;
    std::string algorithm;
    std::string auth_data;        // JSON string
    int64_t created_at_ms{0};
    int64_t updated_at_ms{0};
    int64_t key_count{0};
    std::string etag;
    bool deleted{false};
  };

  struct RoomKeyBackup {
    std::string room_id;
    std::string session_id;
    std::string encrypted_data;   // JSON string of {ciphertext, mac, iv}
    int64_t timestamp_ms{0};
  };

  struct BackupMetrics {
    int64_t total_keys{0};
    int64_t total_rooms{0};
    int64_t estimated_size_bytes{0};
    int64_t oldest_key_ms{0};
    int64_t newest_key_ms{0};
    int failed_decryptions{0};
    int successful_decryptions{0};
    std::map<std::string, int64_t> keys_per_room;
  };

  struct RecoveryResult {
    bool success{false};
    json restored_keys;           // {rooms: {room_id: {sessions: {session_id: key_data}}}}
    int restored_count{0};
    int failed_count{0};
    int total_count{0};
    std::vector<std::string> errors;
  };

  // --------------------------------------------------------------------------
  // Construction
  // --------------------------------------------------------------------------
  explicit KeyBackupManager(storage::DatabasePool& db)
      : db_(db), tofu_(std::make_unique<TofuBackupKeyManager>(db)) {}

  // --------------------------------------------------------------------------
  // Backup version creation
  // --------------------------------------------------------------------------

  // Create a new backup version with a random recovery key
  json create_backup_version(const std::string& user_id,
                              const json& backup_info) {
    std::string algorithm = backup_info.value(FIELD_ALGORITHM,
        ALGORITHM);
    std::string auth_data_str;
    std::string recovery_key;

    // Generate a random encryption key
    std::string backup_key_raw = random_bytes(BACKUP_KEY_LEN);
    recovery_key = base64_unpadded(backup_key_raw);

    // Check if the client provides auth_data (pre-signed)
    if (backup_info.contains(FIELD_AUTH_DATA)) {
      auth_data_str = backup_info[FIELD_AUTH_DATA].dump();
      // Register with TOFU
      try {
        json ad = json::parse(auth_data_str);
        if (ad.contains(FIELD_PUBLIC_KEY)) {
          tofu_->record_first_sighting(user_id, "",
              ad[FIELD_PUBLIC_KEY].get<std::string>());
        }
      } catch (...) {
        // Ignore parse errors for TOFU
      }
    } else {
      // Generate auth_data from the backup key
      json auth_data = BackupAuthSigner::generate_auth_data(backup_key_raw);
      auth_data_str = auth_data.dump();

      // Register with TOFU
      tofu_->record_first_sighting(user_id, "",
          auth_data[FIELD_PUBLIC_KEY].get<std::string>());
    }

    // Generate version string
    std::string version = VERSION_PREFIX + base64_unpadded(random_bytes(16));

    BackupVersion bv;
    bv.version = version;
    bv.user_id = user_id;
    bv.algorithm = algorithm;
    bv.auth_data = auth_data_str;
    bv.created_at_ms = now_ms();
    bv.updated_at_ms = bv.created_at_ms;
    bv.key_count = 0;
    bv.etag = std::to_string(bv.created_at_ms);

    // Enforce max versions per user
    {
      std::lock_guard<std::mutex> lk(mutex_);
      int user_version_count = 0;
      for (const auto& [v, b] : backup_versions_) {
        if (b.user_id == user_id && !b.deleted) {
          user_version_count++;
        }
      }
      if (user_version_count >= MAX_BACKUP_VERSIONS_PER_USER) {
        json err;
        err["error"] = "Maximum number of backup versions reached";
        err["errcode"] = "M_TOO_LARGE";
        err["max_versions"] = MAX_BACKUP_VERSIONS_PER_USER;
        return err;
      }

      backup_versions_[version] = bv;
    }

    // Persist to database
    store_backup_version_db(bv);

    // Update TOFU with version
    tofu_->record_first_sighting(user_id, version,
        json::parse(auth_data_str)[FIELD_PUBLIC_KEY].get<std::string>());

    json response;
    response[FIELD_VERSION] = version;
    response["recovery_key"] = recovery_key;
    response[FIELD_ALGORITHM] = algorithm;
    response[FIELD_ETAG] = bv.etag;
    return response;
  }

  // Create backup version with passphrase-derived key
  json create_backup_version_with_passphrase(const std::string& user_id,
                                              const std::string& passphrase,
                                              const json& backup_info) {
    // Create derivation parameters
    int iterations = backup_info.value(FIELD_ITERATIONS,
                                       PASSPHRASE_DEFAULT_ITERATIONS);
    auto dp = BackupKeyDerivation::create_derivation_params(iterations);

    // Derive key
    std::string derived_key_b64 = BackupKeyDerivation::derive_from_passphrase(
        passphrase, dp.salt, dp.iterations);
    std::string backup_key_raw = base64_unpadded_decode(derived_key_b64);

    // Build auth_data that includes recovery params
    json auth_data = BackupAuthSigner::generate_auth_data(backup_key_raw);
    auth_data["passphrase"] = BackupKeyDerivation::params_to_json(dp);

    // Build full backup_info
    json full_info = backup_info;
    full_info[FIELD_AUTH_DATA] = auth_data;
    full_info["backup_key"] = derived_key_b64; // Internal: include the key

    json result = create_backup_version(user_id, full_info);

    // Augment response with passphrase recovery info
    result["passphrase_info"] = BackupKeyDerivation::params_to_json(dp);
    return result;
  }

  // --------------------------------------------------------------------------
  // Backup version retrieval
  // --------------------------------------------------------------------------

  // Get a specific backup version info
  json get_backup_version(const std::string& user_id,
                          const std::string& version) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = backup_versions_.find(version);
    if (it == backup_versions_.end() || it->second.deleted) {
      json err;
      err["error"] = "Backup version not found";
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    if (it->second.user_id != user_id) {
      json err;
      err["error"] = "Backup version does not belong to user";
      err["errcode"] = "M_FORBIDDEN";
      return err;
    }

    return version_to_json(it->second);
  }

  // Get the latest (most recently created) backup version
  json get_latest_backup_version(const std::string& user_id) {
    std::lock_guard<std::mutex> lk(mutex_);

    const BackupVersion* latest = nullptr;
    for (const auto& [v, bv] : backup_versions_) {
      if (!bv.deleted && bv.user_id == user_id) {
        if (!latest || bv.created_at_ms > latest->created_at_ms) {
          latest = &bv;
        }
      }
    }

    if (!latest) {
      json err;
      err["error"] = "No backup versions found";
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    return version_to_json(*latest);
  }

  // List all backup versions for a user
  json list_backup_versions(const std::string& user_id) {
    std::lock_guard<std::mutex> lk(mutex_);

    json versions = json::array();
    for (const auto& [v, bv] : backup_versions_) {
      if (!bv.deleted && bv.user_id == user_id) {
        versions.push_back(version_to_json(bv));
      }
    }

    // Sort by creation time (newest first)
    std::sort(versions.begin(), versions.end(),
              [](const json& a, const json& b) {
                return a.value("created_at_ms", 0L) >
                       b.value("created_at_ms", 0L);
              });

    return versions;
  }

  // --------------------------------------------------------------------------
  // Backup version update / delete
  // --------------------------------------------------------------------------

  // Update a backup version (e.g., replace auth_data with new signatures)
  json update_backup_version(const std::string& user_id,
                              const std::string& version,
                              const json& update_info) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = backup_versions_.find(version);
    if (it == backup_versions_.end() || it->second.deleted) {
      json err;
      err["error"] = "Backup version not found";
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    if (it->second.user_id != user_id) {
      json err;
      err["error"] = "Backup version does not belong to user";
      err["errcode"] = "M_FORBIDDEN";
      return err;
    }

    if (update_info.contains(FIELD_ALGORITHM)) {
      it->second.algorithm = update_info[FIELD_ALGORITHM].get<std::string>();
    }
    if (update_info.contains(FIELD_AUTH_DATA)) {
      json new_auth = update_info[FIELD_AUTH_DATA];
      it->second.auth_data = new_auth.dump();

      // Update TOFU
      if (new_auth.contains(FIELD_PUBLIC_KEY)) {
        tofu_->record_first_sighting(user_id, version,
            new_auth[FIELD_PUBLIC_KEY].get<std::string>());
      }
    }

    it->second.updated_at_ms = now_ms();
    it->second.etag = std::to_string(it->second.updated_at_ms);

    store_backup_version_db(it->second);

    json response;
    response[FIELD_VERSION] = version;
    response[FIELD_ETAG] = it->second.etag;
    return response;
  }

  // Delete a backup version and all its keys
  json delete_backup_version(const std::string& user_id,
                              const std::string& version) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = backup_versions_.find(version);
    if (it == backup_versions_.end() || it->second.deleted) {
      json err;
      err["error"] = "Backup version not found";
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    if (it->second.user_id != user_id) {
      json err;
      err["error"] = "Backup version does not belong to user";
      err["errcode"] = "M_FORBIDDEN";
      return err;
    }

    int keys_deleted = 0;
    // Erase keys belonging to this version
    auto key_it = backup_keys_.begin();
    while (key_it != backup_keys_.end()) {
      auto parts = split_key(key_it->first);
      if (parts.size() == 3 && parts[0] == version) {
        key_it = backup_keys_.erase(key_it);
        keys_deleted++;
      } else {
        ++key_it;
      }
    }

    // Delete from database
    db_.execute("delete_backup_version_keys",
        "DELETE FROM key_backup_keys WHERE backup_version='" +
        sql_escape(version) + "'");
    db_.execute("delete_backup_version",
        "DELETE FROM key_backup_versions WHERE version='" +
        sql_escape(version) + "'");

    // Remove TOFU record
    tofu_->remove_record(version);

    it->second.deleted = true;

    json response;
    response["deleted"] = true;
    response[FIELD_VERSION] = version;
    response["keys_deleted"] = keys_deleted;
    return response;
  }

  // Delete all backup versions for a user
  json delete_all_backup_versions(const std::string& user_id) {
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<std::string> to_delete;

    for (const auto& [v, bv] : backup_versions_) {
      if (bv.user_id == user_id && !bv.deleted) {
        to_delete.push_back(v);
      }
    }

    int total_deleted = 0;
    int keys_deleted = 0;
    for (const auto& version : to_delete) {
      backup_versions_[version].deleted = true;
      total_deleted++;

      auto key_it = backup_keys_.begin();
      while (key_it != backup_keys_.end()) {
        auto parts = split_key(key_it->first);
        if (parts.size() == 3 && parts[0] == version) {
          key_it = backup_keys_.erase(key_it);
          keys_deleted++;
        } else {
          ++key_it;
        }
      }

      db_.execute("delete_all_version_keys",
          "DELETE FROM key_backup_keys WHERE backup_version='" +
          sql_escape(version) + "'");
      db_.execute("delete_all_versions",
          "DELETE FROM key_backup_versions WHERE version='" +
          sql_escape(version) + "'");

      tofu_->remove_record(version);
    }

    tofu_->remove_all_for_user(user_id);

    json response;
    response["deleted"] = true;
    response["versions_deleted"] = total_deleted;
    response["keys_deleted"] = keys_deleted;
    return response;
  }

  // --------------------------------------------------------------------------
  // Room key upload to backup
  // --------------------------------------------------------------------------

  // Upload room keys to a backup version
  // room_keys format: {rooms: {room_id: {sessions: {session_id: encrypted_data}}}}
  json upload_keys_to_backup(const std::string& user_id,
                              const std::string& version,
                              const json& room_keys) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = backup_versions_.find(version);
    if (it == backup_versions_.end() || it->second.deleted) {
      json err;
      err["error"] = "Unknown backup version";
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    if (it->second.user_id != user_id) {
      json err;
      err["error"] = "Backup version does not belong to user";
      err["errcode"] = "M_FORBIDDEN";
      return err;
    }

    int64_t count = 0;
    int64_t skipped = 0;
    std::vector<RoomKeyBackup> new_keys;

    if (!room_keys.contains(FIELD_ROOMS)) {
      json err;
      err["error"] = "Missing 'rooms' in request body";
      err["errcode"] = "M_BAD_JSON";
      return err;
    }

    for (const auto& [room_id, sessions_obj] : room_keys[FIELD_ROOMS].items()) {
      if (!sessions_obj.contains(FIELD_SESSIONS)) continue;

      for (const auto& [session_id, session_data] :
           sessions_obj[FIELD_SESSIONS].items()) {
        std::string key = version + ":" + room_id + ":" + session_id;

        // Skip if already exists (idempotent upload)
        if (backup_keys_.find(key) != backup_keys_.end()) {
          skipped++;
          continue;
        }

        RoomKeyBackup rkb;
        rkb.room_id = room_id;
        rkb.session_id = session_id;
        rkb.encrypted_data = session_data.is_string()
                                 ? session_data.get<std::string>()
                                 : session_data.dump();
        rkb.timestamp_ms = now_ms();

        backup_keys_[key] = rkb;
        new_keys.push_back(rkb);
        count++;
      }
    }

    // Batch insert into database
    if (!new_keys.empty()) {
      store_backup_keys_batch_db(version, new_keys);
    }

    // Update version metadata
    it->second.key_count += count;
    it->second.updated_at_ms = now_ms();
    it->second.etag = std::to_string(it->second.updated_at_ms);
    store_backup_version_db(it->second);

    json response;
    response[FIELD_ETAG] = it->second.etag;
    response[FIELD_COUNT] = it->second.key_count;
    response["uploaded"] = count;
    response["skipped"] = skipped;
    return response;
  }

  // Upload a single session key to backup
  json upload_single_key(const std::string& user_id,
                          const std::string& version,
                          const std::string& room_id,
                          const std::string& session_id,
                          const json& encrypted_data) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = backup_versions_.find(version);
    if (it == backup_versions_.end() || it->second.deleted) {
      json err;
      err["error"] = "Unknown backup version";
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    if (it->second.user_id != user_id) {
      json err;
      err["error"] = "Backup version does not belong to user";
      err["errcode"] = "M_FORBIDDEN";
      return err;
    }

    std::string key = version + ":" + room_id + ":" + session_id;
    bool is_new = (backup_keys_.find(key) == backup_keys_.end());

    RoomKeyBackup rkb;
    rkb.room_id = room_id;
    rkb.session_id = session_id;
    rkb.encrypted_data = encrypted_data.is_string()
                             ? encrypted_data.get<std::string>()
                             : encrypted_data.dump();
    rkb.timestamp_ms = now_ms();

    backup_keys_[key] = rkb;
    store_backup_key_db(version, rkb);

    if (is_new) {
      it->second.key_count++;
    }

    it->second.updated_at_ms = now_ms();
    it->second.etag = std::to_string(it->second.updated_at_ms);
    store_backup_version_db(it->second);

    json response;
    response[FIELD_ETAG] = it->second.etag;
    response[FIELD_COUNT] = it->second.key_count;
    return response;
  }

  // --------------------------------------------------------------------------
  // Room key download from backup
  // --------------------------------------------------------------------------

  // Get room keys from backup, optionally filtered by room/session
  json get_room_keys(const std::string& user_id,
                     const std::string& version,
                     const std::string& room_id_filter = "",
                     const std::string& session_id_filter = "") {
    std::lock_guard<std::mutex> lk(mutex_);

    auto vit = backup_versions_.find(version);
    if (vit == backup_versions_.end() || vit->second.deleted) {
      json err;
      err["error"] = "Unknown backup version";
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    if (vit->second.user_id != user_id) {
      json err;
      err["error"] = "Backup version does not belong to user";
      err["errcode"] = "M_FORBIDDEN";
      return err;
    }

    json response;
    response[FIELD_ROOMS] = json::object();

    for (const auto& [key, rkb] : backup_keys_) {
      auto parts = split_key(key);
      if (parts.size() != 3 || parts[0] != version) continue;

      const std::string& bk_room_id = parts[1];
      const std::string& bk_session_id = parts[2];

      if (!room_id_filter.empty() && bk_room_id != room_id_filter) continue;
      if (!session_id_filter.empty() && bk_session_id != session_id_filter) continue;

      if (!response[FIELD_ROOMS].contains(bk_room_id)) {
        response[FIELD_ROOMS][bk_room_id] = json::object();
        response[FIELD_ROOMS][bk_room_id][FIELD_SESSIONS] = json::object();
      }

      try {
        response[FIELD_ROOMS][bk_room_id][FIELD_SESSIONS][bk_session_id] =
            json::parse(rkb.encrypted_data);
      } catch (...) {
        response[FIELD_ROOMS][bk_room_id][FIELD_SESSIONS][bk_session_id] =
            rkb.encrypted_data;
      }
    }

    response[FIELD_COUNT] = count_backup_keys_internal(version);
    response[FIELD_ETAG] = vit->second.etag;
    return response;
  }

  // Get room keys for a specific room
  json get_room_keys_for_room(const std::string& user_id,
                               const std::string& version,
                               const std::string& room_id) {
    return get_room_keys(user_id, version, room_id, "");
  }

  // Get a single session key
  json get_single_session_key(const std::string& user_id,
                               const std::string& version,
                               const std::string& room_id,
                               const std::string& session_id) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto vit = backup_versions_.find(version);
    if (vit == backup_versions_.end() || vit->second.deleted) {
      json err;
      err["error"] = "Unknown backup version";
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    std::string key = version + ":" + room_id + ":" + session_id;
    auto kit = backup_keys_.find(key);
    if (kit == backup_keys_.end()) {
      json err;
      err["error"] = "Session key not found in backup";
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    try {
      return json::parse(kit->second.encrypted_data);
    } catch (...) {
      return kit->second.encrypted_data;
    }
  }

  // --------------------------------------------------------------------------
  // Room key deletion from backup
  // --------------------------------------------------------------------------

  // Delete specific room keys from backup
  json delete_room_keys(const std::string& user_id,
                         const std::string& version,
                         const json& rooms_to_delete) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto vit = backup_versions_.find(version);
    if (vit == backup_versions_.end() || vit->second.deleted) {
      json err;
      err["error"] = "Unknown backup version";
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    if (vit->second.user_id != user_id) {
      json err;
      err["error"] = "Backup version does not belong to user";
      err["errcode"] = "M_FORBIDDEN";
      return err;
    }

    int64_t deleted = 0;
    std::vector<std::string> keys_to_delete;

    for (const auto& [room_id, session_ids] : rooms_to_delete.items()) {
      for (const auto& session_id_val : session_ids) {
        std::string session_id = session_id_val.get<std::string>();
        std::string key = version + ":" + room_id + ":" + session_id;
        if (backup_keys_.find(key) != backup_keys_.end()) {
          keys_to_delete.push_back(key);
          deleted++;
        }
      }
    }

    for (const auto& key : keys_to_delete) {
      auto parts = split_key(key);
      if (parts.size() == 3) {
        backup_keys_.erase(key);
        db_.execute("delete_backup_key",
            "DELETE FROM key_backup_keys WHERE backup_version='" +
            sql_escape(parts[0]) + "' AND room_id='" + sql_escape(parts[1]) +
            "' AND session_id='" + sql_escape(parts[2]) + "'");
      }
    }

    vit->second.key_count -= deleted;
    if (vit->second.key_count < 0) vit->second.key_count = 0;
    vit->second.updated_at_ms = now_ms();
    vit->second.etag = std::to_string(vit->second.updated_at_ms);
    store_backup_version_db(vit->second);

    json response;
    response[FIELD_ETAG] = vit->second.etag;
    response[FIELD_COUNT] = vit->second.key_count;
    response["deleted"] = deleted;
    return response;
  }

  // Delete all keys from a backup version (but keep the version)
  json delete_all_room_keys(const std::string& user_id,
                             const std::string& version) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto vit = backup_versions_.find(version);
    if (vit == backup_versions_.end() || vit->second.deleted) {
      json err;
      err["error"] = "Unknown backup version";
      err["errcode"] = "M_NOT_FOUND";
      return err;
    }

    int64_t deleted = 0;
    auto key_it = backup_keys_.begin();
    while (key_it != backup_keys_.end()) {
      auto parts = split_key(key_it->first);
      if (parts.size() == 3 && parts[0] == version) {
        key_it = backup_keys_.erase(key_it);
        deleted++;
      } else {
        ++key_it;
      }
    }

    db_.execute("delete_all_version_keys2",
        "DELETE FROM key_backup_keys WHERE backup_version='" +
        sql_escape(version) + "'");

    vit->second.key_count = 0;
    vit->second.updated_at_ms = now_ms();
    vit->second.etag = std::to_string(vit->second.updated_at_ms);
    store_backup_version_db(vit->second);

    json response;
    response[FIELD_ETAG] = vit->second.etag;
    response[FIELD_COUNT] = 0;
    response["deleted"] = deleted;
    return response;
  }

  // --------------------------------------------------------------------------
  // Recovery: passphrase-based key recovery
  // --------------------------------------------------------------------------

  // Recover backup key from passphrase using stored parameters
  std::optional<std::string> recover_key_from_passphrase(
      const std::string& passphrase,
      const std::string& version) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto vit = backup_versions_.find(version);
    if (vit == backup_versions_.end()) {
      return std::nullopt;
    }

    // Parse auth_data to extract recovery parameters
    json auth_data;
    try {
      auth_data = json::parse(vit->second.auth_data);
    } catch (...) {
      return std::nullopt;
    }

    // Check if auth_data contains passphrase recovery info
    if (!auth_data.contains("passphrase")) {
      return std::nullopt; // Not passphrase-protected
    }

    auto dp = BackupKeyDerivation::params_from_json(auth_data["passphrase"]);
    if (!dp) {
      return std::nullopt;
    }

    try {
      return BackupKeyDerivation::derive_from_passphrase(
          passphrase, dp->salt, dp->iterations);
    } catch (const std::exception&) {
      return std::nullopt;
    }
  }

  // Full recovery: decrypt and return all keys from a backup version
  RecoveryResult recover_all_keys(const std::string& user_id,
                                   const std::string& version,
                                   const std::string& backup_key_b64) {
    std::lock_guard<std::mutex> lk(mutex_);

    RecoveryResult result;
    result.restored_keys[FIELD_ROOMS] = json::object();

    std::string backup_key_raw;
    try {
      backup_key_raw = base64_unpadded_decode(backup_key_b64);
      if (backup_key_raw.size() < BACKUP_KEY_LEN) {
        result.errors.push_back("Backup key too short");
        return result;
      }
      backup_key_raw.resize(BACKUP_KEY_LEN);
    } catch (const std::exception& e) {
      result.errors.push_back(std::string("Failed to decode backup key: ") +
                              e.what());
      return result;
    }

    for (const auto& [map_key, rkb] : backup_keys_) {
      auto parts = split_key(map_key);
      if (parts.size() != 3 || parts[0] != version) continue;

      result.total_count++;

      json session_data;
      try {
        session_data = json::parse(rkb.encrypted_data);
      } catch (...) {
        result.failed_count++;
        result.errors.push_back("Failed to parse encrypted data for " +
                                rkb.room_id + "/" + rkb.session_id);
        continue;
      }

      auto decrypted = BackupCrypto::decrypt_session(session_data,
                                                      backup_key_raw);
      if (decrypted) {
        json key_json;
        try {
          key_json = json::parse(*decrypted);
        } catch (...) {
          key_json = *decrypted;
        }

        if (!result.restored_keys[FIELD_ROOMS].contains(rkb.room_id)) {
          result.restored_keys[FIELD_ROOMS][rkb.room_id] = json::object();
          result.restored_keys[FIELD_ROOMS][rkb.room_id][FIELD_SESSIONS] =
              json::object();
        }
        result.restored_keys[FIELD_ROOMS][rkb.room_id][FIELD_SESSIONS][rkb.session_id] =
            key_json;
        result.restored_count++;
        result.successful_decryptions++;
      } else {
        result.failed_count++;
        result.failed_decryptions++;
        result.errors.push_back("Decryption/verification failed for " +
                                rkb.room_id + "/" + rkb.session_id);
      }
    }

    result.success = (result.failed_count == 0 && result.total_count > 0);
    return result;
  }

  // Recovery with passphrase (convenience method)
  RecoveryResult recover_with_passphrase(const std::string& user_id,
                                          const std::string& version,
                                          const std::string& passphrase) {
    auto recovered_key = recover_key_from_passphrase(passphrase, version);
    if (!recovered_key) {
      RecoveryResult result;
      result.errors.push_back(
          "Failed to recover key from passphrase (wrong passphrase or no "
          "passphrase recovery data)");
      return result;
    }

    return recover_all_keys(user_id, version, *recovered_key);
  }

  // --------------------------------------------------------------------------
  // Auth data signing and verification
  // --------------------------------------------------------------------------

  // Sign backup auth data with user's master cross-signing key
  json sign_auth_data_with_master_key(const std::string& user_id,
                                       const std::string& version,
                                       const std::string& master_private_key_raw) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto vit = backup_versions_.find(version);
    if (vit == backup_versions_.end() || vit->second.deleted) {
      json err;
      err["error"] = "Backup version not found";
      return err;
    }

    json auth_data;
    try {
      auth_data = json::parse(vit->second.auth_data);
    } catch (...) {
      json err;
      err["error"] = "Failed to parse auth_data";
      return err;
    }

    json signed_data = BackupAuthSigner::sign_with_master_key(
        auth_data, master_private_key_raw, user_id);

    vit->second.auth_data = signed_data.dump();
    vit->second.updated_at_ms = now_ms();
    vit->second.etag = std::to_string(vit->second.updated_at_ms);
    store_backup_version_db(vit->second);

    json response;
    response[FIELD_VERSION] = version;
    response[FIELD_AUTH_DATA] = signed_data;
    return response;
  }

  // Verify backup auth data signatures
  json verify_auth_data_signatures(const std::string& user_id,
                                    const std::string& version,
                                    const std::map<std::string, std::string>&
                                        known_keys) {
    std::lock_guard<std::mutex> lk(mutex_);

    auto vit = backup_versions_.find(version);
    if (vit == backup_versions_.end() || vit->second.deleted) {
      json err;
      err["error"] = "Backup version not found";
      return err;
    }

    json auth_data;
    try {
      auth_data = json::parse(vit->second.auth_data);
    } catch (...) {
      json err;
      err["error"] = "Failed to parse auth_data";
      return err;
    }

    auto result = BackupAuthSigner::verify_all_signatures(auth_data, known_keys);

    json response;
    response["all_valid"] = result.all_valid;
    response["valid_count"] = result.valid_count;
    response["total_count"] = result.total_count;
    response["invalid_signatures"] = result.invalid_signatures;
    return response;
  }

  // --------------------------------------------------------------------------
  // Encryption helpers for client-side use
  // --------------------------------------------------------------------------

  // Encrypt a session key for backup (given a backup key)
  json encrypt_session_for_backup(const std::string& session_key_json,
                                   const std::string& backup_key_b64) {
    std::string backup_key_raw;
    try {
      backup_key_raw = base64_unpadded_decode(backup_key_b64);
      if (backup_key_raw.size() < BACKUP_KEY_LEN) {
        throw std::runtime_error("Backup key too short");
      }
      backup_key_raw.resize(BACKUP_KEY_LEN);
    } catch (const std::exception& e) {
      json err;
      err["error"] = std::string("Invalid backup key: ") + e.what();
      return err;
    }

    return BackupCrypto::encrypt_session(session_key_json, backup_key_raw);
  }

  // Decrypt a session from backup
  std::optional<std::string> decrypt_session_from_backup(
      const json& encrypted_data,
      const std::string& backup_key_b64) {
    std::string backup_key_raw;
    try {
      backup_key_raw = base64_unpadded_decode(backup_key_b64);
      backup_key_raw.resize(BACKUP_KEY_LEN);
    } catch (...) {
      return std::nullopt;
    }

    return BackupCrypto::decrypt_session(encrypted_data, backup_key_raw);
  }

  // --------------------------------------------------------------------------
  // TOFU management
  // --------------------------------------------------------------------------

  // Get TOFU trust state for a backup version
  TofuState get_tofu_trust_state(const std::string& version) {
    return tofu_->get_trust_state(version);
  }

  // Trust a backup key
  bool trust_backup_key(const std::string& version,
                        const std::string& verified_by,
                        const std::string& notes = "") {
    return tofu_->trust_key(version, verified_by, notes);
  }

  // Untrust a backup key
  bool untrust_backup_key(const std::string& version,
                          const std::string& reason = "") {
    return tofu_->untrust_key(version, reason);
  }

  // Block a backup key
  bool block_backup_key(const std::string& version,
                        const std::string& reason = "") {
    return tofu_->block_key(version, reason);
  }

  // Check if key has changed since first seen (TOFU violation)
  bool has_tofu_violation(const std::string& version,
                          const std::string& current_public_key_b64) {
    return tofu_->has_key_changed(version, current_public_key_b64);
  }

  // Get TOFU stats
  json get_tofu_stats() {
    return tofu_->get_stats();
  }

  // Export TOFU data
  json export_tofu_data() {
    return tofu_->export_all();
  }

  // Import TOFU data
  void import_tofu_data(const json& data) {
    tofu_->import_all(data);
  }

  // --------------------------------------------------------------------------
  // Backup metrics
  // --------------------------------------------------------------------------

  // Get detailed metrics for a backup version
  BackupMetrics get_backup_metrics(const std::string& version) {
    std::lock_guard<std::mutex> lk(mutex_);

    BackupMetrics metrics;

    int64_t total_size = 0;
    std::set<std::string> rooms;

    for (const auto& [key, rkb] : backup_keys_) {
      auto parts = split_key(key);
      if (parts.size() != 3 || parts[0] != version) continue;

      metrics.total_keys++;
      rooms.insert(rkb.room_id);
      metrics.keys_per_room[rkb.room_id]++;

      total_size += rkb.encrypted_data.size();

      if (metrics.oldest_key_ms == 0 ||
          rkb.timestamp_ms < metrics.oldest_key_ms) {
        metrics.oldest_key_ms = rkb.timestamp_ms;
      }
      if (rkb.timestamp_ms > metrics.newest_key_ms) {
        metrics.newest_key_ms = rkb.timestamp_ms;
      }
    }

    metrics.total_rooms = static_cast<int64_t>(rooms.size());
    metrics.estimated_size_bytes = total_size;

    return metrics;
  }

  // Get metrics as JSON
  json get_backup_metrics_json(const std::string& version) {
    auto metrics = get_backup_metrics(version);

    json j;
    j["total_keys"] = metrics.total_keys;
    j["total_rooms"] = metrics.total_rooms;
    j["estimated_size_bytes"] = metrics.estimated_size_bytes;
    j["estimated_size_kb"] = static_cast<double>(metrics.estimated_size_bytes) / 1024.0;
    j["oldest_key_ms"] = metrics.oldest_key_ms;
    j["newest_key_ms"] = metrics.newest_key_ms;
    j["keys_per_room"] = metrics.keys_per_room;
    j["failed_decryptions"] = metrics.failed_decryptions;
    j["successful_decryptions"] = metrics.successful_decryptions;
    return j;
  }

  // Get global backup metrics (across all users)
  json get_global_backup_metrics() {
    std::lock_guard<std::mutex> lk(mutex_);

    int64_t total_keys = 0;
    int64_t total_versions = 0;
    int64_t total_users = 0;
    int64_t total_size_bytes = 0;
    std::set<std::string> users;
    std::set<std::string> active_versions;

    for (const auto& [v, bv] : backup_versions_) {
      if (!bv.deleted) {
        total_versions++;
        active_versions.insert(v);
        users.insert(bv.user_id);
      }
    }

    total_users = static_cast<int64_t>(users.size());

    for (const auto& [key, rkb] : backup_keys_) {
      auto parts = split_key(key);
      if (parts.size() == 3 && active_versions.count(parts[0]) > 0) {
        total_keys++;
        total_size_bytes += rkb.encrypted_data.size();
      }
    }

    json j;
    j["total_users"] = total_users;
    j["total_versions"] = total_versions;
    j["total_keys"] = total_keys;
    j["total_size_bytes"] = total_size_bytes;
    j["total_size_mb"] = static_cast<double>(total_size_bytes) / (1024.0 * 1024.0);
    j["timestamp"] = now_ms();
    return j;
  }

  // --------------------------------------------------------------------------
  // Key counting
  // --------------------------------------------------------------------------

  // Count total keys in a backup version
  int64_t count_backup_keys(const std::string& version) {
    std::lock_guard<std::mutex> lk(mutex_);
    return count_backup_keys_internal(version);
  }

  // Get keys per room breakdown
  std::map<std::string, int64_t> keys_per_room(const std::string& version) {
    std::lock_guard<std::mutex> lk(mutex_);
    std::map<std::string, int64_t> result;

    for (const auto& [key, rkb] : backup_keys_) {
      auto parts = split_key(key);
      if (parts.size() != 3 || parts[0] != version) continue;
      result[rkb.room_id]++;
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Database persistence helpers
  // --------------------------------------------------------------------------

  // Load all backup data from database (called at startup)
  void load_from_database() {
    std::lock_guard<std::mutex> lk(mutex_);

    // Load backup versions
    auto versions = db_.execute("load_versions",
        "SELECT version, user_id, algorithm, auth_data, created_at_ms, "
        "updated_at_ms, key_count, etag FROM key_backup_versions");
    for (auto& row : versions) {
      BackupVersion bv;
      bv.version = row[0];
      bv.user_id = row[1];
      bv.algorithm = row[2];
      bv.auth_data = row[3];
      bv.created_at_ms = std::stoll(row[4]);
      bv.updated_at_ms = std::stoll(row[5]);
      bv.key_count = std::stoll(row[6]);
      bv.etag = row[7];
      bv.deleted = false;
      backup_versions_[bv.version] = bv;
    }

    // Load backup keys
    auto keys = db_.execute("load_keys",
        "SELECT backup_version, room_id, session_id, encrypted_data, "
        "timestamp_ms FROM key_backup_keys");
    for (auto& row : keys) {
      RoomKeyBackup rkb;
      std::string bv = row[0];
      rkb.room_id = row[1];
      rkb.session_id = row[2];
      rkb.encrypted_data = row[3];
      rkb.timestamp_ms = std::stoll(row[4]);

      std::string map_key = bv + ":" + rkb.room_id + ":" + rkb.session_id;
      backup_keys_[map_key] = rkb;
    }
  }

  // Initialize database tables
  static std::string get_ddl() {
    return R"SQL(
CREATE TABLE IF NOT EXISTS key_backup_versions(
  version TEXT NOT NULL PRIMARY KEY,
  user_id TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  auth_data TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL DEFAULT 0,
  updated_at_ms INTEGER NOT NULL DEFAULT 0,
  key_count INTEGER NOT NULL DEFAULT 0,
  etag TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS key_backup_keys(
  backup_version TEXT NOT NULL,
  room_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  encrypted_data TEXT NOT NULL,
  timestamp_ms INTEGER NOT NULL DEFAULT 0,
  CONSTRAINT kbk_pk PRIMARY KEY(backup_version, room_id, session_id)
);

CREATE INDEX IF NOT EXISTS idx_kbv_user ON key_backup_versions(user_id);
CREATE INDEX IF NOT EXISTS idx_kbk_version ON key_backup_keys(backup_version);
CREATE INDEX IF NOT EXISTS idx_kbk_room ON key_backup_keys(backup_version, room_id);
)SQL";
  }

private:
  // --------------------------------------------------------------------------
  // Internal helpers
  // --------------------------------------------------------------------------

  int64_t count_backup_keys_internal(const std::string& version) {
    int64_t count = 0;
    for (const auto& [key, _] : backup_keys_) {
      auto parts = split_key(key);
      if (parts.size() == 3 && parts[0] == version) {
        count++;
      }
    }
    return count;
  }

  json version_to_json(const BackupVersion& bv) {
    json info;
    info[FIELD_VERSION] = bv.version;
    info[FIELD_ALGORITHM] = bv.algorithm;

    try {
      info[FIELD_AUTH_DATA] = json::parse(bv.auth_data);
    } catch (...) {
      info[FIELD_AUTH_DATA] = bv.auth_data;
    }

    info[FIELD_COUNT] = bv.key_count;
    info[FIELD_ETAG] = bv.etag;
    info["created_at_ms"] = bv.created_at_ms;
    info["updated_at_ms"] = bv.updated_at_ms;
    return info;
  }

  std::vector<std::string> split_key(const std::string& key) {
    std::vector<std::string> parts;
    std::istringstream iss(key);
    std::string part;
    while (std::getline(iss, part, ':')) {
      parts.push_back(part);
    }
    return parts;
  }

  void store_backup_version_db(const BackupVersion& bv) {
    db_.execute("store_version",
        "INSERT OR REPLACE INTO key_backup_versions "
        "(version, user_id, algorithm, auth_data, created_at_ms, "
        "updated_at_ms, key_count, etag) VALUES "
        "('" + sql_escape(bv.version) + "','" + sql_escape(bv.user_id) +
        "','" + sql_escape(bv.algorithm) + "','" + sql_escape(bv.auth_data) +
        "'," + std::to_string(bv.created_at_ms) + "," +
        std::to_string(bv.updated_at_ms) + "," +
        std::to_string(bv.key_count) + ",'" + sql_escape(bv.etag) + "')");
  }

  void store_backup_key_db(const std::string& version,
                           const RoomKeyBackup& rkb) {
    db_.execute("store_key",
        "INSERT OR REPLACE INTO key_backup_keys "
        "(backup_version, room_id, session_id, encrypted_data, timestamp_ms) VALUES "
        "('" + sql_escape(version) + "','" + sql_escape(rkb.room_id) +
        "','" + sql_escape(rkb.session_id) + "','" +
        sql_escape(rkb.encrypted_data) + "'," +
        std::to_string(rkb.timestamp_ms) + ")");
  }

  void store_backup_keys_batch_db(const std::string& version,
                                  const std::vector<RoomKeyBackup>& keys) {
    // Batch insert using a single multi-row INSERT for efficiency
    if (keys.empty()) return;

    std::ostringstream sql;
    sql << "INSERT OR REPLACE INTO key_backup_keys "
           "(backup_version, room_id, session_id, encrypted_data, timestamp_ms) "
           "VALUES ";

    bool first = true;
    for (const auto& rkb : keys) {
      if (!first) sql << ",";
      first = false;
      sql << "('" << sql_escape(version) << "','"
          << sql_escape(rkb.room_id) << "','"
          << sql_escape(rkb.session_id) << "','"
          << sql_escape(rkb.encrypted_data) << "',"
          << rkb.timestamp_ms << ")";
    }

    db_.execute("batch_store_keys", sql.str());
  }

  // --------------------------------------------------------------------------
  // Member variables
  // --------------------------------------------------------------------------
  storage::DatabasePool& db_;
  std::mutex mutex_;
  std::unordered_map<std::string, BackupVersion> backup_versions_;
  std::unordered_map<std::string, RoomKeyBackup> backup_keys_;
  std::unique_ptr<TofuBackupKeyManager> tofu_;
};

// ============================================================================
// Public API: global singleton access
// ============================================================================
namespace {

std::unique_ptr<KeyBackupManager> g_key_backup_manager;
std::mutex g_key_backup_mutex;

} // anonymous namespace

KeyBackupManager* init_key_backup_manager(storage::DatabasePool& db) {
  std::lock_guard<std::mutex> lk(g_key_backup_mutex);
  if (!g_key_backup_manager) {
    g_key_backup_manager = std::make_unique<KeyBackupManager>(db);
    g_key_backup_manager->load_from_database();
  }
  return g_key_backup_manager.get();
}

KeyBackupManager* get_key_backup_manager() {
  std::lock_guard<std::mutex> lk(g_key_backup_mutex);
  return g_key_backup_manager.get();
}

void shutdown_key_backup_manager() {
  std::lock_guard<std::mutex> lk(g_key_backup_mutex);
  g_key_backup_manager.reset();
}

std::string get_key_backup_ddl() {
  return KeyBackupManager::get_ddl();
}

} // namespace progressive
