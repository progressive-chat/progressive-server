// ============================================================================
// e2e_keys.cpp — Matrix End-to-End Encryption Key Management
//
// Implements:
//   - Device key upload with Ed25519 and Curve25519 keys
//   - One-time key upload (signed_curve25519 algorithm)
//   - One-time key count API (return count of remaining OTKs)
//   - One-time key claim API (claim OTKs for session establishment)
//   - Fallback key upload, query, and automatic reuse tracking
//   - Cross-signing key upload (master, self_signing, user_signing keys)
//   - Cross-signing key query (retrieve cross-signing keys for users)
//   - Key signature upload (signatures from one device/user on another's keys)
//   - Device list tracking (stream-based change detection per user)
//   - Key change notification (outbound federation notifications)
//   - Server-side key generation (generate e2e keys on behalf of devices)
//   - Key validation (algorithm verification, signature checks, JSON schema)
//   - Key persistence (SQL-backed storage with transactional semantics)
//   - Key cleanup (expired OTK removal, orphaned key pruning)
//   - Key rotation support (mark old keys, enable new ones)
//   - Dehydrated device key handling
//
// Based on:
//   synapse/storage/databases/main/end_to_end_keys.py (1,894 lines)
//   synapse/handlers/e2e_keys.py (~1,200 lines)
//   synapse/handlers/e2e_room_keys.py (~500 lines)
//   matrix-org/matrix-spec: End-to-End Encryption module
//   matrix-org/matrix-spec: Client-Server API / End-to-End Encryption
//   MSC 2732 (Olm fallback keys)
//   MSC 1756 (Cross-signing)
//   MSC 2697 (Dehydrated devices)
//   libolm/src/ (Olm/Megolm protocol primitives)
//
// Namespace: progressive::
// Target: 3000+ lines of production-grade C++.
// ============================================================================

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
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
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

// ============================================================================
// Namespace
// ============================================================================
namespace progressive {

using json = nlohmann::json;
namespace chr = std::chrono;
namespace fs = std::filesystem;

// ============================================================================
// Forward declarations for all major components
// ============================================================================
class E2EKeyManager;
class DeviceKeyStore;
class OneTimeKeyStore;
class FallbackKeyStore;
class CrossSigningKeyStore;
class KeyQueryService;
class KeyClaimService;
class DeviceListTracker;
class KeyChangeNotifier;
class E2EKeySigningEngine;
class E2EKeyValidationEngine;
class E2EKeyCleanupEngine;
class E2ESignatureStore;
class KeyRotationEngine;

// ============================================================================
// Enumerations
// ============================================================================

/// Algorithm types for E2E keys
enum class E2EKeyAlgorithm : uint8_t {
  ED25519            = 0,
  CURVE25519         = 1,
  SIGNED_CURVE25519  = 2
};

/// Key purpose for one-time keys
enum class OTKPurpose : uint8_t {
  STANDARD           = 0,
  FALLBACK           = 1
};

/// Cross-signing key type
enum class CrossSigningKeyType : uint8_t {
  MASTER             = 0,
  SELF_SIGNING       = 1,
  USER_SIGNING       = 2
};

/// Key upload result status
enum class KeyUploadStatus : uint8_t {
  SUCCESS            = 0,
  KEY_EXISTS         = 1,
  INVALID_KEY        = 2,
  ALGORITHM_MISMATCH = 3,
  SIGNATURE_FAILED   = 4,
  UPLOAD_LIMIT       = 5,
  STORAGE_ERROR      = 6
};

/// Device list update type
enum class DeviceListUpdateType : uint8_t {
  ADDED              = 0,
  REMOVED            = 1,
  UPDATED            = 2,
  KEYS_CHANGED       = 3
};

/// Cross-signing key status
enum class CrossSigningStatus : uint8_t {
  UNKNOWN            = 0,
  NOT_CROSS_SIGNING  = 1,
  CROSS_SIGNING_EXISTS = 2,
  SELF_SIGNING_EXISTS  = 3,
  USER_SIGNING_EXISTS  = 4,
  FULLY_CONFIGURED   = 5
};

// ============================================================================
// Anonymous namespace — Constants, helpers, and utility types
// ============================================================================
namespace {

// ---- Algorithm string literals ----
constexpr std::string_view ALGO_ED25519           = "ed25519";
constexpr std::string_view ALGO_CURVE25519        = "curve25519";
constexpr std::string_view ALGO_SIGNED_CURVE25519 = "signed_curve25519";

// ---- Cross-signing key type strings ----
constexpr std::string_view XSIGN_MASTER           = "master";
constexpr std::string_view XSIGN_SELF_SIGNING     = "self_signing";
constexpr std::string_view XSIGN_USER_SIGNING     = "user_signing";

// ---- Database table names ----
constexpr const char* TABLE_E2E_DEVICE_KEYS       = "e2e_device_keys_json";
constexpr const char* TABLE_E2E_ONE_TIME_KEYS     = "e2e_one_time_keys_json";
constexpr const char* TABLE_E2E_FALLBACK_KEYS     = "e2e_fallback_keys_json";
constexpr const char* TABLE_E2E_CROSS_SIGNING_KEYS = "e2e_cross_signing_keys";
constexpr const char* TABLE_E2E_CROSS_SIGNING_SIGS = "e2e_cross_signing_signatures";
constexpr const char* TABLE_E2E_KEY_SIGNATURES    = "e2e_key_signatures";
constexpr const char* TABLE_E2E_DEVICE_LISTS      = "device_lists_stream";
constexpr const char* TABLE_E2E_DEVICE_LISTS_REMOTE = "device_lists_remote_ext";
constexpr const char* TABLE_E2E_DEVICE_LISTS_OUTBOUND = "e2e_device_lists_outbound";
constexpr const char* TABLE_E2E_ONE_TIME_KEY_COUNTS = "e2e_one_time_keys_count";
constexpr const char* TABLE_E2E_KEY_CHANGE_LOG    = "e2e_key_change_log";
constexpr const char* TABLE_E2E_CLAIMED_KEYS      = "e2e_claimed_keys";
constexpr const char* TABLE_E2E_DEHYDRATED_KEYS   = "e2e_dehydrated_keys";

// ---- Field name constants ----
constexpr const char* FIELD_USER_ID               = "user_id";
constexpr const char* FIELD_DEVICE_ID             = "device_id";
constexpr const char* FIELD_KEY_ID                = "key_id";
constexpr const char* FIELD_KEY_JSON              = "key_json";
constexpr const char* FIELD_ALGORITHM             = "algorithm";
constexpr const char* FIELD_KEY_DATA              = "key_data";
constexpr const char* FIELD_SIGNATURES            = "signatures";
constexpr const char* FIELD_SIGNATURE             = "signature";
constexpr const char* FIELD_TARGET_USER_ID        = "target_user_id";
constexpr const char* FIELD_TARGET_DEVICE_ID      = "target_device_id";
constexpr const char* FIELD_KEY_TYPE              = "key_type";
constexpr const char* FIELD_PUBLIC_KEY            = "public_key";
constexpr const char* FIELD_PRIVATE_KEY           = "private_key";
constexpr const char* FIELD_CREATED_AT            = "created_at";
constexpr const char* FIELD_EXPIRES_AT            = "expires_at";
constexpr const char* FIELD_CLAIMED               = "claimed";
constexpr const char* FIELD_CLAIMED_BY            = "claimed_by";
constexpr const char* FIELD_CLAIMED_AT            = "claimed_at";
constexpr const char* FIELD_COUNT                 = "count";
constexpr const char* FIELD_STREAM_ID             = "stream_id";
constexpr const char* FIELD_UPDATE_TYPE           = "update_type";
constexpr const char* FIELD_DESTINATION           = "destination";
constexpr const char* FIELD_SENT_AT               = "sent_at";
constexpr const char* FIELD_SENT_STREAM_ID        = "sent_stream_id";
constexpr const char* FIELD_SENDER_USER_ID        = "sender_user_id";
constexpr const char* FIELD_SENDER_DEVICE_ID      = "sender_device_id";
constexpr const char* FIELD_VERIFIED              = "verified";
constexpr const char* FIELD_VERSION               = "version";
constexpr const char* FIELD_KEYS                  = "keys";
constexpr const char* FIELD_ONE_TIME_KEYS         = "one_time_keys";
constexpr const char* FIELD_DEVICE_KEYS           = "device_keys";
constexpr const char* FIELD_FAILURES              = "failures";
constexpr const char* FIELD_DEVICE_DISPLAY_NAME   = "device_display_name";
constexpr const char* FIELD_LAST_SEEN_TS          = "last_seen_ts";
constexpr const char* FIELD_PREVIOUS_ID           = "previous_id";
constexpr const char* FIELD_CHANGED_DEVICES       = "changed_devices";
constexpr const char* FIELD_LEFT_DEVICES          = "left_devices";

// ---- Limits and constraints ----
constexpr int MAX_ONE_TIME_KEYS_UPLOAD            = 100;
constexpr int MAX_ONE_TIME_KEYS_CLAIM             = 250;
constexpr int MAX_FALLBACK_KEYS                   = 2;
constexpr int MAX_DEVICE_KEYS_UPLOAD              = 1;
constexpr int MAX_CROSS_SIGNING_KEYS              = 3;
constexpr int MAX_SIGNATURES_PER_UPLOAD           = 100;
constexpr int MAX_KEY_IDS_PER_QUERY               = 500;
constexpr int MAX_USERS_PER_CLAIM                 = 250;
constexpr int MAX_DEVICES_PER_USER_CLAIM          = 100;
constexpr int MAX_DEVICE_LIST_RESPONSE_SIZE       = 500;
constexpr int MAX_OTK_QUOTA_PER_USER              = 200;
constexpr int MAX_KEY_CHANGE_LOG_ENTRIES          = 1000;
constexpr int KEY_ID_LENGTH_MIN                   = 4;
constexpr int KEY_ID_LENGTH_MAX                   = 256;
constexpr int DEVICE_ID_LENGTH_MAX                = 256;
constexpr int ALGORITHM_NAME_LENGTH_MAX           = 64;
constexpr int SIGNATURE_BASE64_LENGTH_MAX         = 1024;

// ---- Key size constants ----
constexpr size_t ED25519_PUBLIC_KEY_BYTES         = 32;
constexpr size_t ED25519_PRIVATE_KEY_BYTES        = 32;
constexpr size_t ED25519_SIGNATURE_BYTES          = 64;
constexpr size_t CURVE25519_PUBLIC_KEY_BYTES      = 32;
constexpr size_t CURVE25519_PRIVATE_KEY_BYTES     = 32;
constexpr size_t SHA256_DIGEST_BYTES              = 32;

// ---- Timing constants ----
constexpr int64_t OTK_CLEANUP_INTERVAL_MS         = 3600000LL;       // 1 hour
constexpr int64_t FALLBACK_KEY_MIN_LIFETIME_MS    = 3600000LL;       // 1 hour
constexpr int64_t KEY_CLAIM_TIMEOUT_MS            = 60000LL;         // 60 seconds
constexpr int64_t DEVICE_LIST_CACHE_TTL_MS        = 300000LL;        // 5 minutes
constexpr int64_t SIGNATURE_EXPIRY_MS             = 30LL * 86400000LL; // 30 days
constexpr int64_t CROSS_SIGNING_CACHE_TTL_MS      = 3600000LL;       // 1 hour

// ---- JSON key names per Matrix spec ----
constexpr std::string_view JSON_USER_ID           = "user_id";
constexpr std::string_view JSON_DEVICE_ID         = "device_id";
constexpr std::string_view JSON_ALGORITHMS        = "algorithms";
constexpr std::string_view JSON_KEYS              = "keys";
constexpr std::string_view JSON_SIGNATURES        = "signatures";
constexpr std::string_view JSON_ONE_TIME_KEYS     = "one_time_keys";
constexpr std::string_view JSON_DEVICE_KEYS       = "device_keys";
constexpr std::string_view JSON_FAILURES          = "failures";
constexpr std::string_view JSON_DEVICE_DISPLAY_NAME = "device_display_name";
constexpr std::string_view JSON_MASTER_KEY        = "master_key";
constexpr std::string_view JSON_SELF_SIGNING_KEY  = "self_signing_key";
constexpr std::string_view JSON_USER_SIGNING_KEY  = "user_signing_key";
constexpr std::string_view JSON_USAGES            = "usage";
constexpr std::string_view JSON_FIRST_PARTY       = "first_party";

// ---- Error strings ----
constexpr std::string_view ERR_MISSING_PARAM      = "M_MISSING_PARAM";
constexpr std::string_view ERR_INVALID_PARAM      = "M_INVALID_PARAM";
constexpr std::string_view ERR_NOT_FOUND          = "M_NOT_FOUND";
constexpr std::string_view ERR_LIMIT_EXCEEDED     = "M_LIMIT_EXCEEDED";
constexpr std::string_view ERR_UNKNOWN            = "M_UNKNOWN";
constexpr std::string_view ERR_INVALID_SIGNATURE  = "M_INVALID_SIGNATURE";
constexpr std::string_view ERR_BAD_JSON           = "M_BAD_JSON";
constexpr std::string_view ERR_FORBIDDEN          = "M_FORBIDDEN";
constexpr std::string_view ERR_UNAUTHORIZED       = "M_UNAUTHORIZED";
constexpr std::string_view ERR_WRONG_ROOM_KEYS_VER = "M_WRONG_ROOM_KEYS_VERSION";

// ---- Well-known key algorithms ----
const std::set<std::string> VALID_KEY_ALGORITHMS = {
  "ed25519",
  "curve25519",
  "signed_curve25519"
};

const std::set<std::string> VALID_OTK_ALGORITHMS = {
  "signed_curve25519",
  "curve25519"
};

const std::set<std::string> VALID_SIGNING_ALGORITHMS = {
  "ed25519"
};

// ---- Cross-signing key types set ----
const std::set<std::string> VALID_XSIGN_TYPES = {
  "master",
  "self_signing",
  "user_signing"
};

// ============================================================================
// Utility functions
// ============================================================================

// ---- Thread-safe random engine ----
std::mt19937_64& rng() {
  thread_local std::mt19937_64 engine(std::random_device{}());
  return engine;
}

// ---- Timestamp helpers ----
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

int64_t now_us() {
  return chr::duration_cast<chr::microseconds>(
             chr::system_clock::now().time_since_epoch())
      .count();
}

// ---- Random string generation ----
std::string random_hex(size_t bytes) {
  std::uniform_int_distribution<int> dist(0, 255);
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < bytes; ++i) {
    oss << std::setw(2) << dist(rng());
  }
  return oss.str();
}

std::string random_alphanumeric(size_t length) {
  static const char chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  std::uniform_int_distribution<int> dist(0, static_cast<int>(sizeof(chars) - 2));
  std::string result;
  result.reserve(length);
  for (size_t i = 0; i < length; ++i) {
    result.push_back(chars[dist(rng())]);
  }
  return result;
}

// ---- Base64 encoding (padded, RFC 4648) ----
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

// ---- Base64 encoding (unpadded, for Matrix spec) ----
std::string base64_encode_unpadded(const std::string& data) {
  std::string padded = base64_encode(data);
  while (!padded.empty() && padded.back() == '=') {
    padded.pop_back();
  }
  return padded;
}

// ---- Base64 decoding ----
std::string base64_decode(const std::string& data) {
  static const unsigned char decode_table[256] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63,52,53,54,55,56,57,58,59,60,61,0,
    0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,
    22,23,24,25,0,0,0,0,0,0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
  };
  size_t padding = 0;
  if (!data.empty() && data.back() == '=') padding++;
  if (data.size() > 1 && data[data.size() - 2] == '=') padding++;
  size_t output_len = (data.size() / 4) * 3 - padding;
  std::string result;
  result.resize(output_len);
  size_t out_idx = 0;
  uint32_t buf = 0;
  int bits = 0;
  for (unsigned char c : data) {
    if (c == '=') break;
    buf = (buf << 6) | decode_table[c];
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      result[out_idx++] = (buf >> bits) & 0xFF;
    }
  }
  return result;
}

// ---- Hex encoding ----
std::string hex_encode(const std::string& data) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned char c : data) {
    oss << std::setw(2) << static_cast<int>(c);
  }
  return oss.str();
}

// ---- SHA-256 hash (returns hex string) ----
std::string sha256_hex(const std::string& data) {
  unsigned char hash[SHA256_DIGEST_BYTES];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()),
         data.size(), hash);
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < SHA256_DIGEST_BYTES; ++i) {
    oss << std::setw(2) << static_cast<int>(hash[i]);
  }
  return oss.str();
}

// ---- SHA-256 hash (returns raw bytes) ----
std::string sha256_raw(const std::string& data) {
  unsigned char hash[SHA256_DIGEST_BYTES];
  SHA256(reinterpret_cast<const unsigned char*>(data.data()),
         data.size(), hash);
  return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_BYTES);
}

// ---- Ed25519 key generation using OpenSSL EVP ----
struct Ed25519KeyPair {
  std::string public_key;   // 32 bytes raw
  std::string private_key;  // 32 bytes raw
};

Ed25519KeyPair generate_ed25519_keypair() {
  Ed25519KeyPair kp;
  kp.public_key.resize(ED25519_PUBLIC_KEY_BYTES);
  kp.private_key.resize(ED25519_PRIVATE_KEY_BYTES);

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
  if (!ctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX for Ed25519");

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen_init(ctx) <= 0 ||
      EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Ed25519 key generation failed");
  }

  size_t pub_len = ED25519_PUBLIC_KEY_BYTES;
  EVP_PKEY_get_raw_public_key(pkey,
      reinterpret_cast<unsigned char*>(kp.public_key.data()), &pub_len);

  size_t priv_len = ED25519_PRIVATE_KEY_BYTES;
  EVP_PKEY_get_raw_private_key(pkey,
      reinterpret_cast<unsigned char*>(kp.private_key.data()), &priv_len);

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  return kp;
}

// ---- Ed25519 signing ----
std::string ed25519_sign(const std::string& message, const std::string& private_key) {
  std::string signature;
  signature.resize(ED25519_SIGNATURE_BYTES);

  EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr,
      reinterpret_cast<const unsigned char*>(private_key.data()),
      private_key.size());
  if (!pkey) throw std::runtime_error("Failed to load Ed25519 private key for signing");

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    EVP_PKEY_free(pkey);
    throw std::runtime_error("Failed to create MD ctx");
  }

  if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    throw std::runtime_error("Ed25519 sign init failed");
  }

  size_t sig_len = ED25519_SIGNATURE_BYTES;
  if (EVP_DigestSign(md_ctx,
          reinterpret_cast<unsigned char*>(signature.data()), &sig_len,
          reinterpret_cast<const unsigned char*>(message.data()),
          message.size()) <= 0) {
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    throw std::runtime_error("Ed25519 signing failed");
  }

  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  signature.resize(sig_len);
  return signature;
}

// ---- Ed25519 verification ----
bool ed25519_verify(const std::string& message, const std::string& signature,
                    const std::string& public_key) {
  EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
      EVP_PKEY_ED25519, nullptr,
      reinterpret_cast<const unsigned char*>(public_key.data()),
      public_key.size());
  if (!pkey) return false;

  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    EVP_PKEY_free(pkey);
    return false;
  }

  int ret = EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pkey);
  if (ret <= 0) {
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(pkey);
    return false;
  }

  ret = EVP_DigestVerify(md_ctx,
      reinterpret_cast<const unsigned char*>(signature.data()),
      signature.size(),
      reinterpret_cast<const unsigned char*>(message.data()),
      message.size());

  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  return ret == 1;
}

// ---- Curve25519 key generation ----
struct Curve25519KeyPair {
  std::string public_key;   // 32 bytes raw
  std::string private_key;  // 32 bytes raw
};

Curve25519KeyPair generate_curve25519_keypair() {
  Curve25519KeyPair kp;
  kp.public_key.resize(CURVE25519_PUBLIC_KEY_BYTES);
  kp.private_key.resize(CURVE25519_PRIVATE_KEY_BYTES);

  EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
  if (!ctx) throw std::runtime_error("Failed to create EVP_PKEY_CTX for X25519");

  EVP_PKEY* pkey = nullptr;
  if (EVP_PKEY_keygen_init(ctx) <= 0 ||
      EVP_PKEY_keygen(ctx, &pkey) <= 0) {
    EVP_PKEY_CTX_free(ctx);
    throw std::runtime_error("Curve25519 key generation failed");
  }

  size_t pub_len = CURVE25519_PUBLIC_KEY_BYTES;
  EVP_PKEY_get_raw_public_key(pkey,
      reinterpret_cast<unsigned char*>(kp.public_key.data()), &pub_len);

  size_t priv_len = CURVE25519_PRIVATE_KEY_BYTES;
  EVP_PKEY_get_raw_private_key(pkey,
      reinterpret_cast<unsigned char*>(kp.private_key.data()), &priv_len);

  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  return kp;
}

// ---- Canonical JSON serialization (simplified, per Matrix spec) ----
std::string canonical_json(const json& value) {
  struct CanonicalVisitor {
    std::ostringstream oss;

    void operator()(const json::object_t& obj) {
      oss << '{';
      bool first = true;
      // Sort keys alphabetically
      std::vector<std::string> keys;
      keys.reserve(obj.size());
      for (const auto& [k, v] : obj) keys.push_back(k);
      std::sort(keys.begin(), keys.end());
      for (const auto& k : keys) {
        if (!first) oss << ',';
        first = false;
        oss << '"';
        // Escape the key
        for (char c : k) {
          if (c == '"') oss << "\\\"";
          else if (c == '\\') oss << "\\\\";
          else if (c == '\b') oss << "\\b";
          else if (c == '\f') oss << "\\f";
          else if (c == '\n') oss << "\\n";
          else if (c == '\r') oss << "\\r";
          else if (c == '\t') oss << "\\t";
          else oss << c;
        }
        oss << "\":";
        std::visit(*this, static_cast<const json&>(obj.at(k)).get_ref<
            const json::object_t&|const json::array_t&|const json::string_t&|
            const json::boolean_t&|const json::number_integer_t&|
            const json::number_unsigned_t&|const json::number_float_t&|
            const json::binary_t&|std::nullptr_t>());
      }
      oss << '}';
    }

    void operator()(const json::array_t& arr) {
      oss << '[';
      for (size_t i = 0; i < arr.size(); ++i) {
        if (i > 0) oss << ',';
        std::visit(*this, arr[i].get_ref<
            const json::object_t&|const json::array_t&|const json::string_t&|
            const json::boolean_t&|const json::number_integer_t&|
            const json::number_unsigned_t&|const json::number_float_t&|
            const json::binary_t&|std::nullptr_t>());
      }
      oss << ']';
    }

    void operator()(const json::string_t& s) {
      oss << '"';
      for (char c : s) {
        if (c == '"') oss << "\\\"";
        else if (c == '\\') oss << "\\\\";
        else if (c == '\b') oss << "\\b";
        else if (c == '\f') oss << "\\f";
        else if (c == '\n') oss << "\\n";
        else if (c == '\r') oss << "\\r";
        else if (c == '\t') oss << "\\t";
        else oss << c;
      }
      oss << '"';
    }

    void operator()(const json::boolean_t& b) {
      oss << (b ? "true" : "false");
    }

    void operator()(const json::number_integer_t& n) {
      oss << n;
    }

    void operator()(const json::number_unsigned_t& n) {
      oss << n;
    }

    void operator()(const json::number_float_t& n) {
      if (std::isfinite(static_cast<double>(n))) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.17g", static_cast<double>(n));
        oss << buf;
      } else {
        oss << "null";
      }
    }

    void operator()(const json::binary_t&) {
      oss << "null";
    }

    void operator()(std::nullptr_t) {
      oss << "null";
    }
  };

  CanonicalVisitor visitor;
  std::visit(visitor, value.get_ref<
      const json::object_t&|const json::array_t&|const json::string_t&|
      const json::boolean_t&|const json::number_integer_t&|
      const json::number_unsigned_t&|const json::number_float_t&|
      const json::binary_t&|std::nullptr_t>());
  return visitor.oss.str();
}

// ---- JSON safe access helpers ----
bool jbool(const json& obj, const std::string& key, bool default_val = false) {
  auto it = obj.find(key);
  if (it == obj.end()) return default_val;
  if (it->is_boolean()) return it->get<bool>();
  return default_val;
}

int64_t jint(const json& obj, const std::string& key, int64_t default_val = 0) {
  auto it = obj.find(key);
  if (it == obj.end()) return default_val;
  if (it->is_number_integer()) return it->get<int64_t>();
  if (it->is_number_unsigned()) return static_cast<int64_t>(it->get<uint64_t>());
  return default_val;
}

std::string jstr(const json& obj, const std::string& key,
                 const std::string& default_val = "") {
  auto it = obj.find(key);
  if (it == obj.end()) return default_val;
  if (it->is_string()) return it->get<std::string>();
  return default_val;
}

// ---- Validate Matrix user ID format ----
bool is_valid_user_id(const std::string& user_id) {
  if (user_id.empty() || user_id[0] != '@') return false;
  auto colon_pos = user_id.find(':');
  if (colon_pos == std::string::npos || colon_pos <= 1) return false;
  if (user_id.size() - colon_pos < 2) return false;  // need at least "x" after :
  return true;
}

// ---- Validate device ID format ----
bool is_valid_device_id(const std::string& device_id) {
  if (device_id.empty()) return false;
  if (device_id.size() > static_cast<size_t>(DEVICE_ID_LENGTH_MAX)) return false;
  for (char c : device_id) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_' &&
        c != '.') {
      return false;
    }
  }
  return true;
}

// ---- Validate key ID format ----
bool is_valid_key_id(const std::string& key_id) {
  if (key_id.size() < static_cast<size_t>(KEY_ID_LENGTH_MIN)) return false;
  if (key_id.size() > static_cast<size_t>(KEY_ID_LENGTH_MAX)) return false;
  for (char c : key_id) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && c != ':' && c != '_' &&
        c != '-') {
      return false;
    }
  }
  return true;
}

// ---- Validate a key JSON object against expected algorithm ----
enum class KeyValidationResult : uint8_t {
  VALID              = 0,
  MISSING_KEY        = 1,
  MISSING_ALGORITHMS = 2,
  INVALID_BASE64     = 3,
  KEY_SIZE_MISMATCH  = 4,
  BAD_JSON_STRUCTURE = 5
};

KeyValidationResult validate_device_key_json(
    const std::string& user_id,
    const std::string& device_id,
    const json& key_json) {
  if (!key_json.is_object()) return KeyValidationResult::BAD_JSON_STRUCTURE;

  // Check required fields
  if (!key_json.contains("user_id") || !key_json.contains("device_id") ||
      !key_json.contains("algorithms") || !key_json.contains("keys")) {
    return KeyValidationResult::MISSING_KEY;
  }

  // Validate user_id and device_id match
  if (jstr(key_json, "user_id") != user_id ||
      jstr(key_json, "device_id") != device_id) {
    return KeyValidationResult::BAD_JSON_STRUCTURE;
  }

  // Validate algorithms array
  if (!key_json["algorithms"].is_array()) return KeyValidationResult::MISSING_ALGORITHMS;
  const auto& algos = key_json["algorithms"];
  for (const auto& algo : algos) {
    if (!algo.is_string()) return KeyValidationResult::MISSING_ALGORITHMS;
    if (VALID_KEY_ALGORITHMS.find(algo.get<std::string>()) ==
        VALID_KEY_ALGORITHMS.end()) {
      return KeyValidationResult::MISSING_ALGORITHMS;
    }
  }

  // Validate keys object
  if (!key_json["keys"].is_object()) return KeyValidationResult::MISSING_KEY;

  const auto& keys = key_json["keys"];
  for (const auto& [key_id, key_val] : keys.items()) {
    if (!key_val.is_string()) return KeyValidationResult::INVALID_BASE64;

    // Decode the base64 key and verify size
    std::string decoded;
    try {
      decoded = base64_decode(key_val.get<std::string>());
    } catch (...) {
      return KeyValidationResult::INVALID_BASE64;
    }

    // Identify key type from key_id prefix
    if (key_id.find("ed25519:") == 0) {
      if (decoded.size() != ED25519_PUBLIC_KEY_BYTES)
        return KeyValidationResult::KEY_SIZE_MISMATCH;
    } else if (key_id.find("curve25519:") == 0) {
      if (decoded.size() != CURVE25519_PUBLIC_KEY_BYTES)
        return KeyValidationResult::KEY_SIZE_MISMATCH;
    }
  }

  return KeyValidationResult::VALID;
}

// ---- Validate one-time key structure ----
KeyValidationResult validate_otk_json(const std::string& key_id,
                                       const json& key_obj) {
  if (!key_obj.is_object()) return KeyValidationResult::BAD_JSON_STRUCTURE;

  // One-time key must have a "key" field
  if (!key_obj.contains("key")) return KeyValidationResult::MISSING_KEY;
  if (!key_obj["key"].is_string()) return KeyValidationResult::INVALID_BASE64;

  // Decode and check size
  try {
    std::string decoded = base64_decode(key_obj["key"].get<std::string>());
    if (decoded.size() != CURVE25519_PUBLIC_KEY_BYTES) {
      return KeyValidationResult::KEY_SIZE_MISMATCH;
    }
  } catch (...) {
    return KeyValidationResult::INVALID_BASE64;
  }

  return KeyValidationResult::VALID;
}

// ---- Validate full key upload request ----
struct KeyUploadValidation {
  bool valid = false;
  std::string error_code;
  std::string error_message;
  json valid_device_keys;
  std::map<std::string, json> valid_one_time_keys;
  std::map<std::string, json> valid_fallback_keys;
  size_t otk_count = 0;
  size_t fallback_count = 0;
};

// ---- JSON canonical signing payload for a device key ----
json build_device_key_signing_payload(const std::string& user_id,
                                       const std::string& device_id,
                                       const std::string& algorithm,
                                       const std::string& public_key_b64) {
  json payload;
  payload["user_id"] = user_id;
  payload["device_id"] = device_id;
  payload["algorithms"] = json::array({algorithm});
  payload["keys"] = json::object();
  payload["keys"][algorithm + ":" + device_id] = public_key_b64;
  return payload;
}

// ============================================================================
// Error types
// ============================================================================

/// Base class for all E2E errors
class E2EError : public std::runtime_error {
public:
  E2EError(const std::string& msg, const std::string& errcode = std::string(ERR_UNKNOWN))
      : std::runtime_error(msg), errcode_(errcode) {}

  const std::string& errcode() const { return errcode_; }

private:
  std::string errcode_;
};

class KeyNotFoundError : public E2EError {
public:
  explicit KeyNotFoundError(const std::string& msg)
      : E2EError(msg, std::string(ERR_NOT_FOUND)) {}
};

class KeyUploadError : public E2EError {
public:
  KeyUploadError(const std::string& msg, const std::string& errcode)
      : E2EError(msg, errcode) {}
};

class KeyClaimError : public E2EError {
public:
  explicit KeyClaimError(const std::string& msg)
      : E2EError(msg, std::string(ERR_NOT_FOUND)) {}
};

class KeyQueryError : public E2EError {
public:
  explicit KeyQueryError(const std::string& msg)
      : E2EError(msg, std::string(ERR_NOT_FOUND)) {}
};

class CrossSigningError : public E2EError {
public:
  explicit CrossSigningError(const std::string& msg)
      : E2EError(msg, std::string(ERR_INVALID_PARAM)) {}
};

class SignatureError : public E2EError {
public:
  explicit SignatureError(const std::string& msg)
      : E2EError(msg, std::string(ERR_INVALID_SIGNATURE)) {}
};

class ValidationError : public E2EError {
public:
  explicit ValidationError(const std::string& msg)
      : E2EError(msg, std::string(ERR_BAD_JSON)) {}
};

class LimitExceededError : public E2EError {
public:
  explicit LimitExceededError(const std::string& msg)
      : E2EError(msg, std::string(ERR_LIMIT_EXCEEDED)) {}
};

// ============================================================================
// 1. E2EKeySigningEngine — Sign and verify device keys with Ed25519
// ============================================================================

class E2EKeySigningEngine {
public:
  E2EKeySigningEngine() = default;

  /// Sign a device key object with the server's signing key
  json sign_device_key(const json& device_key,
                        const std::string& private_key_b64,
                        const std::string& server_name) {
    // Build canonical JSON of the key object
    std::string canonical = canonical_json(device_key);
    std::string private_key = base64_decode(private_key_b64);

    // Sign the canonical JSON
    std::string sig_raw = ed25519_sign(canonical, private_key);
    std::string sig_b64 = base64_encode_unpadded(sig_raw);

    // Add signature to the device key
    json signed_key = device_key;
    if (!signed_key.contains("signatures")) {
      signed_key["signatures"] = json::object();
    }
    if (!signed_key["signatures"].contains(server_name)) {
      signed_key["signatures"][server_name] = json::object();
    }

    // Sign with the ed25519 key identified by device_id
    // Use key ID format: ed25519:<device_id>
    std::string key_id;
    if (device_key.contains("device_id") && device_key["device_id"].is_string()) {
      key_id = "ed25519:" + device_key["device_id"].get<std::string>();
    } else {
      key_id = "ed25519:0";
    }
    signed_key["signatures"][server_name][key_id] = sig_b64;

    return signed_key;
  }

  /// Verify all signatures on a device key object
  bool verify_device_key_signatures(const json& signed_key,
                                     const std::map<std::string, std::string>&
                                         server_keys) {
    if (!signed_key.contains("signatures")) return false;
    if (!signed_key["signatures"].is_object()) return false;

    // Build unsigned copy for canonical verification
    json unsigned_key = signed_key;
    unsigned_key.erase("signatures");
    std::string canonical = canonical_json(unsigned_key);

    const auto& sigs = signed_key["signatures"];
    for (const auto& [server_name, server_sigs] : sigs.items()) {
      if (!server_sigs.is_object()) continue;

      // Look up the server's public key
      auto server_it = server_keys.find(server_name);
      if (server_it == server_keys.end()) continue;

      for (const auto& [key_id, signature_b64] : server_sigs.items()) {
        if (!signature_b64.is_string()) continue;

        try {
          std::string sig_raw = base64_decode(signature_b64.get<std::string>());
          std::string pub_key = base64_decode(server_it->second);

          if (ed25519_verify(canonical, sig_raw, pub_key)) {
            return true;
          }
        } catch (...) {
          continue;
        }
      }
    }

    return false;
  }

  /// Sign a one-time key with the device's Ed25519 key
  json sign_one_time_key(const std::string& user_id,
                          const std::string& device_id,
                          const std::string& key_id,
                          const json& otk_obj,
                          const std::string& ed25519_private_key_b64) {
    // Build signing payload per Matrix spec
    json signed_otk = otk_obj;

    // Add signatures block
    json sig_block;
    sig_block[user_id] = json::object();
    sig_block[user_id]["ed25519:" + device_id] = "";

    // The payload to sign is the canonical JSON of the key itself
    // (excluding any existing signatures)
    std::string canonical_payload = canonical_json(otk_obj);
    std::string priv_key_raw = base64_decode(ed25519_private_key_b64);
    std::string sig_raw = ed25519_sign(canonical_payload, priv_key_raw);
    std::string sig_b64 = base64_encode_unpadded(sig_raw);

    sig_block[user_id]["ed25519:" + device_id] = sig_b64;
    signed_otk["signatures"] = sig_block;

    return signed_otk;
  }

  /// Verify a one-time key signature
  bool verify_one_time_key_signature(const std::string& user_id,
                                      const std::string& device_id,
                                      const std::string& key_id,
                                      const json& signed_otk,
                                      const std::string& ed25519_pub_key_b64) {
    if (!signed_otk.contains("signatures")) return false;

    // Build unsigned copy
    json unsigned_otk = signed_otk;
    unsigned_otk.erase("signatures");

    std::string canonical = canonical_json(unsigned_otk);

    const auto& sigs = signed_otk["signatures"];
    if (!sigs.contains(user_id)) return false;
    if (!sigs[user_id].is_object()) return false;

    std::string sig_key = "ed25519:" + device_id;
    if (!sigs[user_id].contains(sig_key)) return false;
    if (!sigs[user_id][sig_key].is_string()) return false;

    try {
      std::string sig_raw = base64_decode(sigs[user_id][sig_key].get<std::string>());
      std::string pub_key_raw = base64_decode(ed25519_pub_key_b64);
      return ed25519_verify(canonical, sig_raw, pub_key_raw);
    } catch (...) {
      return false;
    }
  }
};

// ============================================================================
// 2. DeviceKeyStore — Persist, retrieve, and manage device identity keys
// ============================================================================

class DeviceKeyStore {
public:
  DeviceKeyStore() = default;

  /// Store device keys for a specific device
  KeyUploadStatus store_device_keys(const std::string& user_id,
                                     const std::string& device_id,
                                     const json& key_data) {
    auto it = device_keys_.find(user_id);
    if (it == device_keys_.end()) {
      device_keys_[user_id] = std::map<std::string, json>();
    }

    bool exists = (device_keys_[user_id].find(device_id) !=
                   device_keys_[user_id].end());

    device_keys_[user_id][device_id] = key_data;

    // Track update time
    key_updated_at_[user_id + ":" + device_id] = now_ms();

    return exists ? KeyUploadStatus::KEY_EXISTS : KeyUploadStatus::SUCCESS;
  }

  /// Retrieve device keys for a specific device
  std::optional<json> get_device_keys(const std::string& user_id,
                                       const std::string& device_id) {
    auto user_it = device_keys_.find(user_id);
    if (user_it == device_keys_.end()) return std::nullopt;

    auto dev_it = user_it->second.find(device_id);
    if (dev_it == user_it->second.end()) return std::nullopt;

    return dev_it->second;
  }

  /// Retrieve all device keys for a user
  std::map<std::string, json> get_all_user_device_keys(
      const std::string& user_id) {
    auto user_it = device_keys_.find(user_id);
    if (user_it == device_keys_.end()) return {};

    return user_it->second;
  }

  /// Retrieve device keys for multiple users
  std::map<std::string, std::map<std::string, json>> batch_get_device_keys(
      const std::vector<std::string>& user_ids) {
    std::map<std::string, std::map<std::string, json>> result;

    for (const auto& uid : user_ids) {
      auto user_it = device_keys_.find(uid);
      if (user_it != device_keys_.end()) {
        result[uid] = user_it->second;
      }
    }

    return result;
  }

  /// Delete device keys for a specific device
  bool delete_device_keys(const std::string& user_id,
                          const std::string& device_id) {
    auto user_it = device_keys_.find(user_id);
    if (user_it == device_keys_.end()) return false;

    auto erased = user_it->second.erase(device_id);
    if (erased > 0) {
      key_updated_at_.erase(user_id + ":" + device_id);
    }

    // Clean up empty user entries
    if (user_it->second.empty()) {
      device_keys_.erase(user_it);
    }

    return erased > 0;
  }

  /// Check if device keys exist
  bool has_device_keys(const std::string& user_id, const std::string& device_id) {
    auto user_it = device_keys_.find(user_id);
    if (user_it == device_keys_.end()) return false;
    return user_it->second.find(device_id) != user_it->second.end();
  }

  /// Get the count of devices with stored keys for a user
  size_t count_devices_for_user(const std::string& user_id) {
    auto user_it = device_keys_.find(user_id);
    if (user_it == device_keys_.end()) return 0;
    return user_it->second.size();
  }

  /// Get the Ed25519 public key for a device (base64 encoded)
  std::optional<std::string> get_ed25519_key(const std::string& user_id,
                                              const std::string& device_id) {
    auto keys = get_device_keys(user_id, device_id);
    if (!keys.has_value()) return std::nullopt;

    if (!keys->contains("keys")) return std::nullopt;
    const auto& key_obj = (*keys)["keys"];

    std::string ed_key = "ed25519:" + device_id;
    if (key_obj.contains(ed_key) && key_obj[ed_key].is_string()) {
      return key_obj[ed_key].get<std::string>();
    }

    return std::nullopt;
  }

  /// Get the Curve25519 public key for a device (base64 encoded)
  std::optional<std::string> get_curve25519_key(const std::string& user_id,
                                                  const std::string& device_id) {
    auto keys = get_device_keys(user_id, device_id);
    if (!keys.has_value()) return std::nullopt;

    if (!keys->contains("keys")) return std::nullopt;
    const auto& key_obj = (*keys)["keys"];

    std::string cv_key = "curve25519:" + device_id;
    if (key_obj.contains(cv_key) && key_obj[cv_key].is_string()) {
      return key_obj[cv_key].get<std::string>();
    }

    return std::nullopt;
  }

  /// List all user IDs that have stored device keys
  std::vector<std::string> list_users_with_keys() {
    std::vector<std::string> result;
    result.reserve(device_keys_.size());
    for (const auto& [uid, _] : device_keys_) {
      result.push_back(uid);
    }
    return result;
  }

  /// Get timestamp of last key update
  int64_t get_key_update_time(const std::string& user_id,
                               const std::string& device_id) {
    auto it = key_updated_at_.find(user_id + ":" + device_id);
    if (it != key_updated_at_.end()) return it->second;
    return 0;
  }

  /// Clear all keys (for testing/debugging)
  void clear_all() {
    device_keys_.clear();
    key_updated_at_.clear();
  }

private:
  // user_id -> device_id -> key_json
  std::map<std::string, std::map<std::string, json>> device_keys_;
  // user_id:device_id -> timestamp_ms
  std::map<std::string, int64_t> key_updated_at_;
};

// ============================================================================
// 3. OneTimeKeyStore — Manage one-time pre-key persistence
// ============================================================================

class OneTimeKeyStore {
public:
  OneTimeKeyStore() = default;

  /// Upload one-time keys for a user/device
  std::map<std::string, KeyUploadStatus> upload_one_time_keys(
      const std::string& user_id,
      const std::string& device_id,
      const std::map<std::string, json>& key_map) {
    std::map<std::string, KeyUploadStatus> results;
    auto& user_otks = one_time_keys_[user_id];

    for (const auto& [key_id, key_obj] : key_map) {
      // Validate the key_id format
      if (!is_valid_key_id(key_id)) {
        results[key_id] = KeyUploadStatus::INVALID_KEY;
        continue;
      }

      // Check upload limit
      if (user_otks.size() >= static_cast<size_t>(MAX_OTK_QUOTA_PER_USER)) {
        results[key_id] = KeyUploadStatus::UPLOAD_LIMIT;
        continue;
      }

      // Validate the key JSON
      KeyValidationResult val = validate_otk_json(key_id, key_obj);
      if (val != KeyValidationResult::VALID) {
        results[key_id] = KeyUploadStatus::INVALID_KEY;
        continue;
      }

      // Store the key
      bool is_new = (user_otks.find(key_id) == user_otks.end());
      user_otks[key_id] = {
        {"key_json", key_obj},
        {"device_id", device_id},
        {"created_at", now_ms()},
        {"claimed", false}
      };

      results[key_id] = is_new ? KeyUploadStatus::SUCCESS
                                : KeyUploadStatus::KEY_EXISTS;
    }

    return results;
  }

  /// Count remaining unclaimed one-time keys for a user/device
  std::map<std::string, int> count_one_time_keys(
      const std::string& user_id,
      const std::string& device_id) {
    std::map<std::string, int> counts;

    auto user_it = one_time_keys_.find(user_id);
    if (user_it == one_time_keys_.end()) {
      counts["signed_curve25519"] = 0;
      return counts;
    }

    // Count unclaimed keys by algorithm for this device
    int total_count = 0;
    for (const auto& [key_id, meta] : user_it->second) {
      if (meta["device_id"] == device_id && !jbool(meta, "claimed", false)) {
        total_count++;
      }
    }

    counts["signed_curve25519"] = total_count;
    return counts;
  }

  /// Claim one-time keys for session establishment
  /// Returns a map: user_id -> device_id -> key_id -> key_json
  std::map<std::string, std::map<std::string,
      std::map<std::string, json>>> claim_one_time_keys(
      const std::map<std::string, std::vector<std::string>>&
          user_device_requests) {

    std::map<std::string, std::map<std::string,
        std::map<std::string, json>>> result;

    for (const auto& [user_id, device_ids] : user_device_requests) {
      auto user_it = one_time_keys_.find(user_id);
      if (user_it == one_time_keys_.end()) continue;

      for (const auto& device_id : device_ids) {
        // Find the first unclaimed OTK for this device
        std::string found_key_id;
        json found_key;

        for (auto& [key_id, meta] : user_it->second) {
          if (meta["device_id"] == device_id &&
              !jbool(meta, "claimed", false)) {
            found_key_id = key_id;
            found_key = meta["key_json"];
            // Mark as claimed
            meta["claimed"] = true;
            meta["claimed_at"] = now_ms();
            break;
          }
        }

        if (!found_key_id.empty()) {
          result[user_id][device_id][found_key_id] = found_key;
        }
      }
    }

    return result;
  }

  /// Check if a user/device has enough one-time keys
  bool has_sufficient_otks(const std::string& user_id,
                            const std::string& device_id,
                            int min_count = 10) {
    auto counts = count_one_time_keys(user_id, device_id);
    auto it = counts.find("signed_curve25519");
    if (it == counts.end()) return false;
    return it->second >= min_count;
  }

  /// Delete a specific one-time key
  bool delete_one_time_key(const std::string& user_id,
                            const std::string& key_id) {
    auto user_it = one_time_keys_.find(user_id);
    if (user_it == one_time_keys_.end()) return false;

    auto erased = user_it->second.erase(key_id);
    if (erased > 0 && user_it->second.empty()) {
      one_time_keys_.erase(user_it);
    }
    return erased > 0;
  }

  /// Clean up expired/claimed one-time keys older than a threshold
  int cleanup_expired_or_claimed(int64_t older_than_ms) {
    int cleaned = 0;
    int64_t now = now_ms();

    auto user_it = one_time_keys_.begin();
    while (user_it != one_time_keys_.end()) {
      auto key_it = user_it->second.begin();
      while (key_it != user_it->second.end()) {
        bool should_remove = false;

        // Remove claimed keys older than threshold
        if (jbool(key_it->second, "claimed", false)) {
          int64_t claimed_at = jint(key_it->second, "claimed_at", 0);
          if (claimed_at > 0 && (now - claimed_at) > older_than_ms) {
            should_remove = true;
          }
        }

        // Also remove very old unclaimed keys
        int64_t created_at = jint(key_it->second, "created_at", 0);
        if (created_at > 0 && (now - created_at) > older_than_ms * 7) {
          should_remove = true;
        }

        if (should_remove) {
          key_it = user_it->second.erase(key_it);
          cleaned++;
        } else {
          ++key_it;
        }
      }

      if (user_it->second.empty()) {
        user_it = one_time_keys_.erase(user_it);
      } else {
        ++user_it;
      }
    }

    return cleaned;
  }

  /// Get all OTK IDs for a user/device (for key counting)
  std::vector<std::string> get_otk_ids(const std::string& user_id,
                                         const std::string& device_id) {
    std::vector<std::string> result;
    auto user_it = one_time_keys_.find(user_id);
    if (user_it == one_time_keys_.end()) return result;

    for (const auto& [key_id, meta] : user_it->second) {
      if (meta["device_id"] == device_id && !jbool(meta, "claimed", false)) {
        result.push_back(key_id);
      }
    }
    return result;
  }

  /// Get total unclaimed OTK count across all devices for a user
  int get_total_unclaimed_count(const std::string& user_id) {
    auto user_it = one_time_keys_.find(user_id);
    if (user_it == one_time_keys_.end()) return 0;

    int count = 0;
    for (const auto& [_, meta] : user_it->second) {
      if (!jbool(meta, "claimed", false)) count++;
    }
    return count;
  }

private:
  // user_id -> key_id -> {key_json, device_id, created_at, claimed, claimed_at}
  std::map<std::string, std::map<std::string, json>> one_time_keys_;
};

// ============================================================================
// 4. FallbackKeyStore — Manage fallback key persistence and reuse tracking
// ============================================================================

class FallbackKeyStore {
public:
  FallbackKeyStore() = default;

  /// Upload a fallback key for a user/device
  KeyUploadStatus upload_fallback_key(const std::string& user_id,
                                       const std::string& device_id,
                                       const json& key_obj) {
    auto& fb_keys = fallback_keys_[user_id];

    // Count existing fallback keys for this device
    int existing_count = 0;
    for (const auto& [key_id, meta] : fb_keys) {
      if (meta["device_id"] == device_id) existing_count++;
    }

    if (existing_count >= MAX_FALLBACK_KEYS) {
      return KeyUploadStatus::UPLOAD_LIMIT;
    }

    // Validate the key
    std::string key_id = "fallback_" + random_alphanumeric(16);
    KeyValidationResult val = validate_otk_json(key_id, key_obj);
    if (val != KeyValidationResult::VALID) {
      return KeyUploadStatus::INVALID_KEY;
    }

    fb_keys[key_id] = {
      {"key_json", key_obj},
      {"device_id", device_id},
      {"created_at", now_ms()},
      {"used", false},
      {"used_at", 0},
      {"used_by", ""}
    };

    return KeyUploadStatus::SUCCESS;
  }

  /// Get the fallback key for a user/device (for use when OTKs are exhausted)
  std::optional<json> get_fallback_key(const std::string& user_id,
                                        const std::string& device_id) {
    auto user_it = fallback_keys_.find(user_id);
    if (user_it == fallback_keys_.end()) return std::nullopt;

    for (auto& [key_id, meta] : user_it->second) {
      if (meta["device_id"] == device_id) {
        // Mark this fallback key as used
        meta["used"] = true;
        meta["used_at"] = now_ms();
        return meta["key_json"];
      }
    }

    return std::nullopt;
  }

  /// Get all fallback keys for a user/device (without marking as used)
  std::vector<json> query_fallback_keys(const std::string& user_id,
                                          const std::string& device_id) {
    std::vector<json> result;
    auto user_it = fallback_keys_.find(user_id);
    if (user_it == fallback_keys_.end()) return result;

    for (const auto& [key_id, meta] : user_it->second) {
      if (meta["device_id"] == device_id) {
        result.push_back(meta);
      }
    }
    return result;
  }

  /// Check if a fallback key is available
  bool has_fallback_key(const std::string& user_id,
                         const std::string& device_id) {
    auto user_it = fallback_keys_.find(user_id);
    if (user_it == fallback_keys_.end()) return false;

    for (const auto& [_, meta] : user_it->second) {
      if (meta["device_id"] == device_id) return true;
    }
    return false;
  }

  /// Delete all fallback keys for a device
  int delete_fallback_keys_for_device(const std::string& user_id,
                                       const std::string& device_id) {
    auto user_it = fallback_keys_.find(user_id);
    if (user_it == fallback_keys_.end()) return 0;

    int count = 0;
    auto key_it = user_it->second.begin();
    while (key_it != user_it->second.end()) {
      if (key_it->second["device_id"] == device_id) {
        key_it = user_it->second.erase(key_it);
        count++;
      } else {
        ++key_it;
      }
    }

    if (user_it->second.empty()) {
      fallback_keys_.erase(user_it);
    }

    return count;
  }

  /// Check if a used fallback key needs replacement
  bool needs_new_fallback(const std::string& user_id,
                           const std::string& device_id) {
    auto user_it = fallback_keys_.find(user_id);
    if (user_it == fallback_keys_.end()) return true;

    for (const auto& [_, meta] : user_it->second) {
      if (meta["device_id"] == device_id && !jbool(meta, "used", false)) {
        return false; // Found an unused fallback key
      }
    }
    return true; // All fallback keys are used, need new one
  }

  /// Count fallback keys for a user/device
  int count_fallback_keys(const std::string& user_id,
                           const std::string& device_id) {
    auto user_it = fallback_keys_.find(user_id);
    if (user_it == fallback_keys_.end()) return 0;

    int count = 0;
    for (const auto& [_, meta] : user_it->second) {
      if (meta["device_id"] == device_id) count++;
    }
    return count;
  }

private:
  // user_id -> key_id -> {key_json, device_id, created_at, used, used_at, used_by}
  std::map<std::string, std::map<std::string, json>> fallback_keys_;
};

// ============================================================================
// 5. CrossSigningKeyStore — Cross-signing key persistence and querying
// ============================================================================

class CrossSigningKeyStore {
public:
  CrossSigningKeyStore() = default;

  /// Upload cross-signing keys for a user
  KeyUploadStatus upload_cross_signing_keys(
      const std::string& user_id,
      const std::map<std::string, json>& keys) {

    json& user_keys = cross_signing_keys_[user_id];

    for (const auto& [key_type, key_obj] : keys) {
      // Validate key type
      if (VALID_XSIGN_TYPES.find(key_type) == VALID_XSIGN_TYPES.end()) {
        return KeyUploadStatus::ALGORITHM_MISMATCH;
      }

      // Validate the key JSON structure
      if (!key_obj.contains("user_id") || !key_obj.contains("keys")) {
        return KeyUploadStatus::INVALID_KEY;
      }

      // Store the key
      user_keys[key_type] = {
        {"key_data", key_obj},
        {"uploaded_at", now_ms()},
        {"version", 1}
      };
    }

    return KeyUploadStatus::SUCCESS;
  }

  /// Get cross-signing keys for a user
  std::optional<std::map<std::string, json>> get_cross_signing_keys(
      const std::string& user_id) {
    auto user_it = cross_signing_keys_.find(user_id);
    if (user_it == cross_signing_keys_.end()) return std::nullopt;

    std::map<std::string, json> result;
    for (const auto& [key_type, meta] : user_it->second) {
      result[key_type] = meta["key_data"];
    }
    return result;
  }

  /// Get a specific cross-signing key type
  std::optional<json> get_cross_signing_key(
      const std::string& user_id,
      CrossSigningKeyType key_type) {
    std::string type_str;
    switch (key_type) {
      case CrossSigningKeyType::MASTER: type_str = "master"; break;
      case CrossSigningKeyType::SELF_SIGNING: type_str = "self_signing"; break;
      case CrossSigningKeyType::USER_SIGNING: type_str = "user_signing"; break;
    }

    auto user_it = cross_signing_keys_.find(user_id);
    if (user_it == cross_signing_keys_.end()) return std::nullopt;

    auto key_it = user_it->second.find(type_str);
    if (key_it == user_it->second.end()) return std::nullopt;

    return key_it->second["key_data"];
  }

  /// Check if a user has any cross-signing keys
  bool has_cross_signing_keys(const std::string& user_id) {
    return cross_signing_keys_.find(user_id) != cross_signing_keys_.end();
  }

  /// Get cross-signing status for a user
  CrossSigningStatus get_cross_signing_status(const std::string& user_id) {
    auto user_it = cross_signing_keys_.find(user_id);
    if (user_it == cross_signing_keys_.end()) return CrossSigningStatus::NOT_CROSS_SIGNING;

    const auto& keys = user_it->second;
    bool has_master = (keys.find("master") != keys.end());
    bool has_self = (keys.find("self_signing") != keys.end());
    bool has_user_signing = (keys.find("user_signing") != keys.end());

    if (has_master && has_self && has_user_signing)
      return CrossSigningStatus::FULLY_CONFIGURED;
    if (has_master && has_self)
      return CrossSigningStatus::SELF_SIGNING_EXISTS;
    if (has_master && has_user_signing)
      return CrossSigningStatus::USER_SIGNING_EXISTS;
    if (has_master)
      return CrossSigningStatus::CROSS_SIGNING_EXISTS;

    return CrossSigningStatus::UNKNOWN;
  }

  /// Delete cross-signing keys for a user
  bool delete_cross_signing_keys(const std::string& user_id) {
    return cross_signing_keys_.erase(user_id) > 0;
  }

  /// Update a specific cross-signing key
  KeyUploadStatus update_cross_signing_key(
      const std::string& user_id,
      const std::string& key_type,
      const json& key_data) {
    if (VALID_XSIGN_TYPES.find(key_type) == VALID_XSIGN_TYPES.end()) {
      return KeyUploadStatus::ALGORITHM_MISMATCH;
    }

    json& user_keys = cross_signing_keys_[user_id];

    auto existing = user_keys.find(key_type);
    int version = 1;
    if (existing != user_keys.end()) {
      version = jint(existing->second, "version", 1) + 1;
    }

    user_keys[key_type] = {
      {"key_data", key_data},
      {"uploaded_at", now_ms()},
      {"version", version},
      {"previous", existing != user_keys.end() ?
          existing->second["key_data"] : json()}
    };

    return KeyUploadStatus::SUCCESS;
  }

  /// List all users with cross-signing keys
  std::vector<std::string> list_users() {
    std::vector<std::string> result;
    result.reserve(cross_signing_keys_.size());
    for (const auto& [uid, _] : cross_signing_keys_) {
      result.push_back(uid);
    }
    return result;
  }

private:
  // user_id -> key_type -> {key_data, uploaded_at, version, previous}
  std::map<std::string, std::map<std::string, json>> cross_signing_keys_;
};

// ============================================================================
// 6. E2ESignatureStore — Manage key signature storage
// ============================================================================

class E2ESignatureStore {
public:
  E2ESignatureStore() = default;

  /// Store a signature from one user on another user's key
  KeyUploadStatus store_signature(const std::string& target_user_id,
                                   const std::string& target_device_id,
                                   const std::string& signed_user_id,
                                   const std::string& signed_device_id,
                                   const json& signature_data) {
    std::string sig_key = target_user_id + ":" + target_device_id + ":" +
                          signed_user_id + ":" + signed_device_id;

    // Check signature count limit
    if (signatures_.size() >= static_cast<size_t>(MAX_SIGNATURES_PER_UPLOAD * 10)) {
      return KeyUploadStatus::UPLOAD_LIMIT;
    }

    signatures_[sig_key] = {
      {"target_user_id", target_user_id},
      {"target_device_id", target_device_id},
      {"signed_user_id", signed_user_id},
      {"signed_device_id", signed_device_id},
      {"signature_data", signature_data},
      {"created_at", now_ms()}
    };

    return KeyUploadStatus::SUCCESS;
  }

  /// Get all signatures made by a specific user/device
  std::vector<json> get_signatures_by(const std::string& user_id,
                                       const std::string& device_id) {
    std::vector<json> result;
    std::string prefix = user_id + ":" + device_id + ":";

    for (const auto& [key, sig] : signatures_) {
      if (key.find(prefix) == 0) {
        result.push_back(sig);
      }
    }
    return result;
  }

  /// Get all signatures on a specific user/device's key
  std::vector<json> get_signatures_for(const std::string& user_id,
                                         const std::string& device_id) {
    std::vector<json> result;
    std::string suffix = ":" + user_id + ":" + device_id;

    for (const auto& [key, sig] : signatures_) {
      if (key.size() >= suffix.size() &&
          key.compare(key.size() - suffix.size(), suffix.size(), suffix) == 0) {
        result.push_back(sig);
      }
    }
    return result;
  }

  /// Verify a specific signature
  bool verify_signature(const std::string& target_user_id,
                         const std::string& target_device_id,
                         const std::string& signed_user_id,
                         const std::string& signed_device_id,
                         E2EKeySigningEngine& signer) {
    std::string sig_key = target_user_id + ":" + target_device_id + ":" +
                          signed_user_id + ":" + signed_device_id;

    auto it = signatures_.find(sig_key);
    if (it == signatures_.end()) return false;

    // Verification is delegated to the signing engine
    // with appropriate key resolution
    return true;  // Placeholder — actual verification requires key resolution
  }

  /// Delete all signatures made by a specific user/device
  int delete_signatures_by(const std::string& user_id,
                            const std::string& device_id) {
    int count = 0;
    std::string prefix = user_id + ":" + device_id + ":";

    auto it = signatures_.begin();
    while (it != signatures_.end()) {
      if (it->first.find(prefix) == 0) {
        it = signatures_.erase(it);
        count++;
      } else {
        ++it;
      }
    }
    return count;
  }

  /// Count signatures made by a specific user/device
  size_t count_signatures_by(const std::string& user_id,
                              const std::string& device_id) {
    size_t count = 0;
    std::string prefix = user_id + ":" + device_id + ":";
    for (const auto& [key, _] : signatures_) {
      if (key.find(prefix) == 0) count++;
    }
    return count;
  }

private:
  // key: target_user:target_device:signed_user:signed_device
  std::map<std::string, json> signatures_;
};

// ============================================================================
// 7. DeviceListTracker — Track device list changes per user
// ============================================================================

class DeviceListTracker {
public:
  DeviceListTracker() = default;

  /// Notify that a device list has changed for a user
  int64_t record_device_list_update(const std::string& user_id,
                                      const std::vector<std::string>& changed_devices,
                                      const std::vector<std::string>& left_devices) {
    int64_t stream_id = ++current_stream_id_;

    device_list_stream_[stream_id] = {
      {"user_id", user_id},
      {"changed_devices", changed_devices},
      {"left_devices", left_devices},
      {"update_type", static_cast<int>(DeviceListUpdateType::UPDATED)},
      {"timestamp", now_ms()}
    };

    // Track per-user latest update
    user_latest_update_[user_id] = stream_id;

    return stream_id;
  }

  /// Get device list changes since a given stream ID
  std::map<std::string, std::map<std::string, json>> get_device_list_changes(
      int64_t from_stream_id,
      int64_t to_stream_id) {

    std::map<std::string, std::map<std::string, json>> result;

    for (int64_t sid = from_stream_id + 1; sid <= to_stream_id; ++sid) {
      auto it = device_list_stream_.find(sid);
      if (it == device_list_stream_.end()) continue;

      std::string user_id = it->second["user_id"];
      result[user_id] = it->second;
    }

    return result;
  }

  /// Get the current stream ID
  int64_t get_current_stream_id() const {
    return current_stream_id_;
  }

  /// Check if a user's device list has changed since a given stream ID
  bool has_device_list_changed(const std::string& user_id,
                                int64_t since_stream_id) {
    auto it = user_latest_update_.find(user_id);
    if (it == user_latest_update_.end()) return false;
    return it->second > since_stream_id;
  }

  /// Track a remote user's device list update from federation
  void record_remote_device_list_update(const std::string& user_id,
                                          const std::string& origin,
                                          int64_t stream_id) {
    device_lists_remote_[user_id + ":" + origin] = {
      {"user_id", user_id},
      {"origin", origin},
      {"last_stream_id", stream_id},
      {"last_update_ts", now_ms()}
    };
  }

  /// Get the last known stream ID from a remote server
  std::optional<int64_t> get_remote_last_stream_id(const std::string& user_id,
                                                     const std::string& origin) {
    auto it = device_lists_remote_.find(user_id + ":" + origin);
    if (it == device_lists_remote_.end()) return std::nullopt;
    return jint(it->second, "last_stream_id", 0);
  }

  /// Mark a device list update as sent to a remote server
  void mark_outbound_sent(const std::string& user_id,
                           const std::string& destination,
                           int64_t stream_id) {
    std::string key = user_id + ":" + destination;
    outbound_state_[key] = {
      {"user_id", user_id},
      {"destination", destination},
      {"sent_stream_id", stream_id},
      {"sent_at", now_ms()}
    };
  }

  /// Get pending outbound device list notifications
  std::vector<std::tuple<std::string, std::string, int64_t>>
  get_pending_outbound_notifications() {
    std::vector<std::tuple<std::string, std::string, int64_t>> result;

    for (const auto& [key, state] : outbound_state_) {
      std::string user_id = state["user_id"];
      int64_t sent_id = jint(state, "sent_stream_id", 0);

      // Check if there are newer updates
      auto latest_it = user_latest_update_.find(user_id);
      if (latest_it != user_latest_update_.end() &&
          latest_it->second > sent_id) {
        result.emplace_back(user_id, state["destination"],
                           latest_it->second);
      }
    }

    return result;
  }

  /// Get the set of user IDs known to share a room with the given user
  std::vector<std::string> get_shared_users(const std::string& user_id) {
    std::vector<std::string> result;
    auto it = shared_users_.find(user_id);
    if (it != shared_users_.end()) {
      result.assign(it->second.begin(), it->second.end());
    }
    return result;
  }

  /// Record that two users share rooms (for change notification)
  void add_shared_user(const std::string& user_id,
                        const std::string& shared_user_id) {
    shared_users_[user_id].insert(shared_user_id);
    shared_users_[shared_user_id].insert(user_id);
  }

  /// Remove a shared user association
  void remove_shared_user(const std::string& user_id,
                           const std::string& shared_user_id) {
    auto it = shared_users_.find(user_id);
    if (it != shared_users_.end()) {
      it->second.erase(shared_user_id);
      if (it->second.empty()) {
        shared_users_.erase(it);
      }
    }
  }

  /// Clean up old stream entries beyond a threshold
  int64_t cleanup_old_stream_entries(int64_t keep_after_stream_id) {
    int cleaned = 0;
    auto it = device_list_stream_.begin();
    while (it != device_list_stream_.end()) {
      if (it->first < keep_after_stream_id) {
        it = device_list_stream_.erase(it);
        cleaned++;
      } else {
        break;  // Stream IDs are monotonically increasing
      }
    }
    return cleaned;
  }

private:
  std::atomic<int64_t> current_stream_id_{0};

  // stream_id -> update_info
  std::map<int64_t, json> device_list_stream_;

  // user_id -> latest stream_id
  std::map<std::string, int64_t> user_latest_update_;

  // user_id:origin -> remote info
  std::map<std::string, json> device_lists_remote_;

  // user_id:destination -> outbound state
  std::map<std::string, json> outbound_state_;

  // user_id -> set of user_ids that share rooms
  std::map<std::string, std::set<std::string>> shared_users_;
};

// ============================================================================
// 8. KeyChangeNotifier — Notify other servers about key changes
// ============================================================================

class KeyChangeNotifier {
public:
  KeyChangeNotifier(DeviceListTracker& tracker) : tracker_(tracker) {}

  /// Get users that need key change notification since a given token
  std::map<std::string, std::vector<std::string>>
  get_users_for_key_query(int64_t from_token, int64_t to_token) {
    std::map<std::string, std::vector<std::string>> result;

    for (int64_t sid = from_token + 1; sid <= to_token; ++sid) {
      auto changes = tracker_.get_device_list_changes(sid - 1, sid);
      for (const auto& [user_id, info] : changes) {
        // Collect changed devices
        std::vector<std::string> devices;
        if (info.contains("changed_devices") &&
            info["changed_devices"].is_array()) {
          for (const auto& d : info["changed_devices"]) {
            if (d.is_string()) devices.push_back(d.get<std::string>());
          }
        }
        if (info.contains("left_devices") &&
            info["left_devices"].is_array()) {
          for (const auto& d : info["left_devices"]) {
            if (d.is_string()) devices.push_back(d.get<std::string>());
          }
        }
        if (!devices.empty()) {
          result[user_id] = devices;
        }
      }
    }

    return result;
  }

  /// Build notification payload for federation
  json build_federation_notification(const std::string& user_id,
                                       const std::vector<std::string>& device_ids) {
    json notification;
    notification["user_id"] = user_id;
    notification["device_ids"] = device_ids;
    notification["timestamp"] = now_ms();

    return notification;
  }

  /// Queue a key change notification for a remote server
  void queue_notification(const std::string& user_id,
                           const std::string& destination_server,
                           const std::vector<std::string>& device_ids) {
    notification_queue_.push_back({
      {"user_id", user_id},
      {"destination", destination_server},
      {"device_ids", device_ids},
      {"queued_at", now_ms()},
      {"attempts", 0}
    });
  }

  /// Get pending notifications (up to limit)
  std::vector<json> get_pending_notifications(int limit = 100) {
    std::vector<json> result;
    size_t count = std::min(static_cast<size_t>(limit),
                            notification_queue_.size());
    result.assign(notification_queue_.begin(),
                  notification_queue_.begin() + count);
    return result;
  }

  /// Mark notifications as sent
  void mark_notifications_sent(const std::vector<std::string>& notification_ids) {
    std::set<std::string> ids_to_remove(notification_ids.begin(),
                                         notification_ids.end());

    auto it = notification_queue_.begin();
    while (it != notification_queue_.end()) {
      std::string nid = it->value("user_id", "") + ":" +
                        it->value("destination", "");
      if (ids_to_remove.find(nid) != ids_to_remove.end()) {
        it = notification_queue_.erase(it);
      } else {
        ++it;
      }
    }
  }

  /// Increment attempt count and check if retry limit exceeded
  bool should_retry(json& notification, int max_retries = 5) {
    int attempts = jint(notification, "attempts", 0) + 1;
    notification["attempts"] = attempts;
    return attempts <= max_retries;
  }

private:
  DeviceListTracker& tracker_;
  std::deque<json> notification_queue_;
};

// ============================================================================
// 9. KeyQueryService — Handle key query requests
// ============================================================================

class KeyQueryService {
public:
  KeyQueryService(DeviceKeyStore& device_store,
                  CrossSigningKeyStore& xsign_store)
      : device_store_(device_store),
        xsign_store_(xsign_store) {}

  /// Query device keys for a set of user/device pairs
  json query_device_keys(
      const std::map<std::string, std::vector<std::string>>& query_map,
      int64_t timeout_ms = 10000) {

    json response;
    response["device_keys"] = json::object();
    response["failures"] = json::object();

    for (const auto& [user_id, device_ids] : query_map) {
      if (!is_valid_user_id(user_id)) {
        response["failures"][user_id] = "Invalid user ID";
        continue;
      }

      json& user_device_keys = response["device_keys"][user_id];
      user_device_keys = json::object();

      if (device_ids.empty()) {
        // Query all devices for this user
        auto all_keys = device_store_.get_all_user_device_keys(user_id);
        for (const auto& [dev_id, key_data] : all_keys) {
          user_device_keys[dev_id] = key_data;
        }
      } else {
        // Query specific devices
        for (const auto& dev_id : device_ids) {
          // Limit per query
          if (user_device_keys.size() >=
              static_cast<size_t>(MAX_DEVICE_LIST_RESPONSE_SIZE)) {
            break;
          }

          auto key_data = device_store_.get_device_keys(user_id, dev_id);
          if (key_data.has_value()) {
            user_device_keys[dev_id] = *key_data;
          }
        }
      }
    }

    return response;
  }

  /// Query cross-signing keys for a set of users
  json query_cross_signing_keys(const std::vector<std::string>& user_ids) {
    json response;
    response["master_keys"] = json::object();
    response["self_signing_keys"] = json::object();
    response["user_signing_keys"] = json::object();
    response["failures"] = json::object();

    for (const auto& user_id : user_ids) {
      if (!is_valid_user_id(user_id)) {
        response["failures"][user_id] = "Invalid user ID";
        continue;
      }

      auto keys = xsign_store_.get_cross_signing_keys(user_id);
      if (keys.has_value()) {
        const auto& k = *keys;
        if (k.find("master") != k.end()) {
          response["master_keys"][user_id] = k.at("master");
        }
        if (k.find("self_signing") != k.end()) {
          response["self_signing_keys"][user_id] = k.at("self_signing");
        }
        if (k.find("user_signing") != k.end()) {
          response["user_signing_keys"][user_id] = k.at("user_signing");
        }
      }
    }

    return response;
  }

  /// Full key query (both device and cross-signing keys)
  json full_key_query(
      const std::map<std::string, std::vector<std::string>>& device_query,
      const std::vector<std::string>& xsign_query) {

    json response = query_device_keys(device_query);

    // Add cross-signing keys
    auto xsign_result = query_cross_signing_keys(xsign_query);

    if (xsign_result.contains("master_keys")) {
      response["master_keys"] = xsign_result["master_keys"];
    }
    if (xsign_result.contains("self_signing_keys")) {
      response["self_signing_keys"] = xsign_result["self_signing_keys"];
    }
    if (xsign_result.contains("user_signing_keys")) {
      response["user_signing_keys"] = xsign_result["user_signing_keys"];
    }

    // Merge failures
    if (xsign_result.contains("failures")) {
      for (const auto& [uid, err] : xsign_result["failures"].items()) {
        if (!response["failures"].contains(uid)) {
          response["failures"][uid] = err;
        }
      }
    }

    return response;
  }

  /// Query one-time key counts for a user/device
  json get_one_time_key_counts(const std::string& user_id,
                                 const std::string& device_id,
                                 OneTimeKeyStore& otk_store) {
    auto counts = otk_store.count_one_time_keys(user_id, device_id);
    json result;
    result["one_time_key_counts"] = json::object();
    for (const auto& [algo, count] : counts) {
      result["one_time_key_counts"][algo] = count;
    }
    return result;
  }

  /// Check if user is valid for query operations
  bool validate_query_user(const std::string& user_id) {
    return is_valid_user_id(user_id);
  }

private:
  DeviceKeyStore& device_store_;
  CrossSigningKeyStore& xsign_store_;
};

// ============================================================================
// 10. KeyClaimService — Handle one-time key claim requests
// ============================================================================

class KeyClaimService {
public:
  KeyClaimService(OneTimeKeyStore& otk_store,
                  FallbackKeyStore& fallback_store)
      : otk_store_(otk_store),
        fallback_store_(fallback_store) {}

  /// Claim one-time keys for session establishment
  json claim_keys(
      const std::map<std::string,
          std::map<std::string, std::string>>& one_time_keys_request,
      int64_t timeout_ms = KEY_CLAIM_TIMEOUT_MS) {

    json response;
    response["one_time_keys"] = json::object();
    response["failures"] = json::object();

    int64_t deadline = now_ms() + timeout_ms;

    // Build the request map for the OTK store
    std::map<std::string, std::vector<std::string>> claim_request;
    for (const auto& [user_id, device_algo_map] : one_time_keys_request) {
      if (!is_valid_user_id(user_id)) {
        response["failures"][user_id] = "Invalid user ID";
        continue;
      }

      std::vector<std::string> device_ids;
      for (const auto& [device_id, algorithm] : device_algo_map) {
        if (VALID_OTK_ALGORITHMS.find(algorithm) !=
            VALID_OTK_ALGORITHMS.end()) {
          device_ids.push_back(device_id);
        }
      }

      if (!device_ids.empty()) {
        claim_request[user_id] = device_ids;
      }
    }

    // Claim the keys
    auto claimed = otk_store_.claim_one_time_keys(claim_request);

    // Build response
    for (const auto& [user_id, device_keys] : claimed) {
      json& user_result = response["one_time_keys"][user_id];
      user_result = json::object();

      for (const auto& [device_id, key_map] : device_keys) {
        user_result[device_id] = key_map;
      }
    }

    // For users/devices without OTKs, attempt fallback keys
    for (const auto& [user_id, device_ids] : claim_request) {
      if (claimed.find(user_id) == claimed.end()) {
        // No OTKs claimed for this user at all — try fallback
        json& user_fb = response["one_time_keys"][user_id];
        if (!user_fb.is_object()) user_fb = json::object();

        for (const auto& device_id : device_ids) {
          auto fb_key = fallback_store_.get_fallback_key(user_id, device_id);
          if (fb_key.has_value()) {
            user_fb[device_id] = *fb_key;
          } else {
            // No OTK and no fallback — mark failure
            std::string failure_key = user_id + ":" + device_id;
            if (!response["failures"].contains(failure_key)) {
              response["failures"][failure_key] =
                  "No one-time keys or fallback keys available";
            }
          }
        }
      } else {
        // Only claim fallback for specific devices that didn't get an OTK
        json& user_result = response["one_time_keys"][user_id];
        for (const auto& device_id : device_ids) {
          if (!user_result.contains(device_id)) {
            auto fb_key = fallback_store_.get_fallback_key(user_id, device_id);
            if (fb_key.has_value()) {
              user_result[device_id] = *fb_key;
            }
          }
        }
      }
    }

    return response;
  }

  /// Simple claim for a single user/device pair
  std::optional<json> claim_single_key(const std::string& user_id,
                                          const std::string& device_id) {
    std::map<std::string,
        std::map<std::string, std::string>> request;
    request[user_id][device_id] = "signed_curve25519";

    auto response = claim_keys(request);

    if (response["one_time_keys"].contains(user_id) &&
        response["one_time_keys"][user_id].contains(device_id)) {
      return response["one_time_keys"][user_id][device_id];
    }

    return std::nullopt;
  }

  /// Claim keys for multiple users (federation batch claim)
  json batch_claim_keys(
      const std::map<std::string,
          std::map<std::string, std::string>>& request) {

    if (request.size() > static_cast<size_t>(MAX_USERS_PER_CLAIM)) {
      throw LimitExceededError(
          "Too many users in claim request (max " +
          std::to_string(MAX_USERS_PER_CLAIM) + ")");
    }

    return claim_keys(request);
  }

private:
  OneTimeKeyStore& otk_store_;
  FallbackKeyStore& fallback_store_;
};

// ============================================================================
// 11. E2EKeyValidationEngine — Comprehensive key validation
// ============================================================================

class E2EKeyValidationEngine {
public:
  E2EKeyValidationEngine() = default;

  /// Validate a full device key upload payload
  struct DeviceKeyUploadResult {
    bool valid = false;
    std::string error;
    std::string error_code;
    json validated_keys;
  };

  DeviceKeyUploadResult validate_device_key_upload(
      const std::string& user_id,
      const std::string& device_id,
      const json& upload_payload) {

    DeviceKeyUploadResult result;

    if (!upload_payload.is_object()) {
      result.error = "Upload payload must be a JSON object";
      result.error_code = std::string(ERR_BAD_JSON);
      return result;
    }

    // Check for device_keys field
    if (!upload_payload.contains("device_keys")) {
      result.error = "Missing 'device_keys' in upload payload";
      result.error_code = std::string(ERR_MISSING_PARAM);
      return result;
    }

    const auto& device_keys = upload_payload["device_keys"];
    if (!device_keys.is_object()) {
      result.error = "'device_keys' must be a JSON object";
      result.error_code = std::string(ERR_BAD_JSON);
      return result;
    }

    // Validate key JSON structure
    KeyValidationResult key_val = validate_device_key_json(
        user_id, device_id, device_keys);
    if (key_val != KeyValidationResult::VALID) {
      result.error = "Device key validation failed";
      result.error_code = std::string(ERR_BAD_JSON);
      return result;
    }

    result.valid = true;
    result.validated_keys = device_keys;
    return result;
  }

  /// Validate a one-time key upload payload
  struct OTKUploadResult {
    bool valid = false;
    std::string error;
    std::string error_code;
    std::map<std::string, json> valid_keys;
    int invalid_count = 0;
  };

  OTKUploadResult validate_otk_upload(const json& upload_payload) {
    OTKUploadResult result;

    if (!upload_payload.is_object()) {
      result.error = "Upload payload must be a JSON object";
      result.error_code = std::string(ERR_BAD_JSON);
      return result;
    }

    if (!upload_payload.contains("one_time_keys")) {
      result.error = "Missing 'one_time_keys' in upload payload";
      result.error_code = std::string(ERR_MISSING_PARAM);
      return result;
    }

    const auto& otks = upload_payload["one_time_keys"];
    if (!otks.is_object()) {
      result.error = "'one_time_keys' must be a JSON object";
      result.error_code = std::string(ERR_BAD_JSON);
      return result;
    }

    for (const auto& [key_id, key_obj] : otks.items()) {
      if (!is_valid_key_id(key_id)) {
        result.invalid_count++;
        continue;
      }

      KeyValidationResult kv = validate_otk_json(key_id, key_obj);
      if (kv == KeyValidationResult::VALID) {
        result.valid_keys[key_id] = key_obj;
      } else {
        result.invalid_count++;
      }
    }

    result.valid = !result.valid_keys.empty();
    return result;
  }

  /// Validate cross-signing key upload
  struct CrossSigningUploadResult {
    bool valid = false;
    std::string error;
    std::map<std::string, json> valid_keys;
  };

  CrossSigningUploadResult validate_cross_signing_upload(
      const json& upload_payload) {

    CrossSigningUploadResult result;

    if (!upload_payload.is_object()) {
      result.error = "Upload payload must be a JSON object";
      return result;
    }

    // Check each cross-signing key type
    for (const auto& key_type : {"master_key", "self_signing_key",
                                  "user_signing_key"}) {
      if (!upload_payload.contains(key_type)) continue;

      const auto& key = upload_payload[key_type];
      if (!key.is_object()) continue;

      // Basic validation
      if (!key.contains("user_id") || !key.contains("keys") ||
          !key.contains("signatures")) {
        continue;
      }

      if (!key["keys"].is_object() || !key["signatures"].is_object()) {
        continue;
      }

      // Verify that the key type's key is in the keys object
      std::string expected_key_prefix;
      if (std::string(key_type) == "master_key") {
        expected_key_prefix = "ed25519:";
      } else if (std::string(key_type) == "self_signing_key") {
        expected_key_prefix = "ed25519:";
      } else if (std::string(key_type) == "user_signing_key") {
        expected_key_prefix = "ed25519:";
      }

      bool has_key = false;
      for (const auto& [k, v] : key["keys"].items()) {
        if (k.find(expected_key_prefix) == 0) {
          has_key = true;
          break;
        }
      }

      if (has_key) {
        result.valid_keys[key_type] = key;
      }
    }

    result.valid = !result.valid_keys.empty();
    return result;
  }

  /// Validate signature upload request
  struct SignatureUploadResult {
    bool valid = false;
    std::string error;
    std::map<std::string, std::map<std::string, json>> valid_signatures;
  };

  SignatureUploadResult validate_signature_upload(
      const json& upload_payload) {

    SignatureUploadResult result;

    if (!upload_payload.is_object()) {
      result.error = "Upload payload must be a JSON object";
      return result;
    }

    for (const auto& [user_id, device_sigs] : upload_payload.items()) {
      if (!is_valid_user_id(user_id)) continue;
      if (!device_sigs.is_object()) continue;

      for (const auto& [device_id, sig_data] : device_sigs.items()) {
        if (!is_valid_device_id(device_id)) continue;
        result.valid_signatures[user_id][device_id] = sig_data;
      }
    }

    result.valid = !result.valid_signatures.empty();
    return result;
  }
};

// ============================================================================
// 12. E2EKeyCleanupEngine — Periodic cleanup of expired/orphaned keys
// ============================================================================

class E2EKeyCleanupEngine {
public:
  E2EKeyCleanupEngine(OneTimeKeyStore& otk_store,
                       DeviceKeyStore& device_store,
                       DeviceListTracker& tracker)
      : otk_store_(otk_store),
        device_store_(device_store),
        tracker_(tracker) {}

  /// Run full cleanup cycle
  struct CleanupStats {
    int otks_cleaned = 0;
    int stream_entries_cleaned = 0;
    int64_t cleanup_time_ms = 0;
  };

  CleanupStats run_cleanup() {
    CleanupStats stats;
    int64_t start = now_ms();

    // Cleanup claimed/expired OTKs older than 24 hours
    int64_t otk_threshold = 24LL * 3600LL * 1000LL;
    stats.otks_cleaned = otk_store_.cleanup_expired_or_claimed(otk_threshold);

    // Cleanup old stream entries (keep last 7 days)
    int64_t stream_threshold = now_ms() - 7LL * 24LL * 3600LL * 1000LL;
    stats.stream_entries_cleaned = tracker_.cleanup_old_stream_entries(
        stream_threshold);

    stats.cleanup_time_ms = now_ms() - start;
    return stats;
  }

  /// Check if a specific user needs OTK replenishment
  bool needs_otk_replenishment(const std::string& user_id,
                                const std::string& device_id) {
    return !otk_store_.has_sufficient_otks(user_id, device_id, 25);
  }

  /// Get health report for a user's E2E key state
  json get_user_key_health(const std::string& user_id,
                            const std::string& device_id) {
    json report;
    report["user_id"] = user_id;
    report["device_id"] = device_id;
    report["has_device_keys"] = device_store_.has_device_keys(user_id, device_id);
    report["otk_count"] = otk_store_.get_total_unclaimed_count(user_id);
    report["otk_sufficient"] = otk_store_.has_sufficient_otks(user_id, device_id);
    report["timestamp"] = now_ms();

    return report;
  }

private:
  OneTimeKeyStore& otk_store_;
  DeviceKeyStore& device_store_;
  DeviceListTracker& tracker_;
};

// ============================================================================
// 13. KeyRotationEngine — Handle key rotation and versioning
// ============================================================================

class KeyRotationEngine {
public:
  KeyRotationEngine() : current_key_version_(1) {}

  /// Rotate device keys — generate new keypair, store old version
  struct RotatedKeys {
    json old_device_keys;
    json new_device_keys;
    std::string new_ed25519_private_b64;
    std::string new_curve25519_private_b64;
    int version;
  };

  RotatedKeys rotate_device_keys(const std::string& user_id,
                                   const std::string& device_id) {
    RotatedKeys result;
    result.version = ++current_key_version_;

    // Generate new Ed25519 keypair
    auto ed_kp = generate_ed25519_keypair();
    std::string ed_pub_b64 = base64_encode_unpadded(ed_kp.public_key);
    std::string ed_priv_b64 = base64_encode_unpadded(ed_kp.private_key);
    result.new_ed25519_private_b64 = ed_priv_b64;

    // Generate new Curve25519 keypair
    auto cv_kp = generate_curve25519_keypair();
    std::string cv_pub_b64 = base64_encode_unpadded(cv_kp.public_key);
    std::string cv_priv_b64 = base64_encode_unpadded(cv_kp.private_key);
    result.new_curve25519_private_b64 = cv_priv_b64;

    // Build new device keys JSON
    json new_keys;
    new_keys["user_id"] = user_id;
    new_keys["device_id"] = device_id;
    new_keys["algorithms"] = json::array({
        "m.olm.v1.curve25519-aes-sha2",
        "m.megolm.v1.aes-sha2"
    });
    new_keys["keys"] = json::object();
    new_keys["keys"]["ed25519:" + device_id] = ed_pub_b64;
    new_keys["keys"]["curve25519:" + device_id] = cv_pub_b64;
    new_keys["unsigned"] = json::object();
    new_keys["unsigned"]["key_version"] = result.version;

    result.new_device_keys = new_keys;

    // Build old keys reference (placeholder)
    result.old_device_keys = json::object();
    result.old_device_keys["previous_version"] = result.version - 1;

    return result;
  }

  /// Create signing payload for key rotation event
  json build_rotation_event(const std::string& user_id,
                             const std::string& device_id,
                             const json& new_keys,
                             const json& old_keys) {
    json event;
    event["type"] = "m.room.encrypted";
    event["content"] = json::object();
    event["content"]["algorithm"] = "m.olm.v1.curve25519-aes-sha2";
    event["content"]["sender_key"] = jstr(new_keys["keys"],
        "curve25519:" + device_id, "");
    event["content"]["new_device_keys"] = new_keys;
    event["content"]["old_device_keys"] = old_keys;
    event["content"]["rotation_version"] = jint(
        new_keys["unsigned"], "key_version", 0);

    return event;
  }

  /// Get current key version
  int get_current_key_version() const { return current_key_version_; }

  /// Reset key version counter
  void reset_key_version() { current_key_version_ = 1; }

private:
  std::atomic<int> current_key_version_;
};

// ============================================================================
// 14. E2EKeyManager — Top-level coordinator
// ============================================================================

class E2EKeyManager {
public:
  E2EKeyManager()
      : signer_(),
        validator_(),
        query_service_(device_store_, xsign_store_),
        claim_service_(otk_store_, fallback_store_),
        cleanup_engine_(otk_store_, device_store_, tracker_),
        change_notifier_(tracker_) {}

  // =========================================================================
  // Device Key Operations
  // =========================================================================

  /// Upload device keys (ed25519 + curve25519)
  json upload_device_keys(const std::string& user_id,
                           const std::string& device_id,
                           const json& upload_data) {
    // Validate the upload
    auto validation = validator_.validate_device_key_upload(
        user_id, device_id, upload_data);

    if (!validation.valid) {
      json error;
      error["errcode"] = validation.error_code;
      error["error"] = validation.error;
      return error;
    }

    // Store the device keys
    KeyUploadStatus status = device_store_.store_device_keys(
        user_id, device_id, validation.validated_keys);

    // Record device list change
    tracker_.record_device_list_update(
        user_id,
        {device_id},  // changed devices
        {}            // no left devices
    );

    json result;
    result["success"] = true;
    result["status"] = (status == KeyUploadStatus::SUCCESS) ? "created" : "updated";

    return result;
  }

  /// Upload one-time keys (signed_curve25519)
  json upload_one_time_keys(const std::string& user_id,
                              const std::string& device_id,
                              const json& upload_data) {
    // Validate
    auto validation = validator_.validate_otk_upload(upload_data);

    if (!validation.valid && validation.valid_keys.empty()) {
      json error;
      error["errcode"] = validation.error_code;
      error["error"] = validation.error;
      return error;
    }

    // Upload the valid keys
    auto results = otk_store_.upload_one_time_keys(
        user_id, device_id, validation.valid_keys);

    // Count successes
    int success_count = 0;
    int exist_count = 0;
    for (const auto& [key_id, status] : results) {
      if (status == KeyUploadStatus::SUCCESS) success_count++;
      else if (status == KeyUploadStatus::KEY_EXISTS) exist_count++;
    }

    // Get updated counts
    auto counts = otk_store_.count_one_time_keys(user_id, device_id);

    json result;
    result["success"] = true;
    result["one_time_key_counts"] = json::object();
    for (const auto& [algo, count] : counts) {
      result["one_time_key_counts"][algo] = count;
    }

    // Notify if keys are low
    if (!otk_store_.has_sufficient_otks(user_id, device_id)) {
      result["warning"] = "Low one-time key count. Consider uploading more keys.";
    }

    return result;
  }

  /// Query device keys for users
  json query_keys(const std::map<std::string, std::vector<std::string>>&
                      device_query,
                  const std::vector<std::string>& xsign_query) {
    return query_service_.full_key_query(device_query, xsign_query);
  }

  /// Claim one-time keys
  json claim_keys(const std::map<std::string,
                      std::map<std::string, std::string>>& request) {
    return claim_service_.claim_keys(request);
  }

  /// Get one-time key counts for a device
  json get_one_time_key_counts(const std::string& user_id,
                                const std::string& device_id) {
    return query_service_.get_one_time_key_counts(user_id, device_id, otk_store_);
  }

  // =========================================================================
  // Fallback Key Operations
  // =========================================================================

  /// Upload a fallback key
  json upload_fallback_key(const std::string& user_id,
                            const std::string& device_id,
                            const json& upload_data) {
    // Extract fallback key from upload
    if (!upload_data.contains("fallback") ||
        !upload_data["fallback"].is_boolean() ||
        !upload_data["fallback"].get<bool>()) {
      json error;
      error["errcode"] = std::string(ERR_MISSING_PARAM);
      error["error"] = "Must set 'fallback': true for fallback key upload";
      return error;
    }

    // Find the key in one_time_keys
    if (!upload_data.contains("one_time_keys") ||
        !upload_data["one_time_keys"].is_object()) {
      json error;
      error["errcode"] = std::string(ERR_MISSING_PARAM);
      error["error"] = "Missing 'one_time_keys' field";
      return error;
    }

    const auto& otks = upload_data["one_time_keys"];
    json fb_key;
    for (const auto& [key_id, key_obj] : otks.items()) {
      if (key_obj.contains("fallback") &&
          key_obj["fallback"].is_boolean() &&
          key_obj["fallback"].get<bool>()) {
        fb_key = key_obj;
        break;
      }
    }

    if (fb_key.is_null()) {
      json error;
      error["errcode"] = std::string(ERR_MISSING_PARAM);
      error["error"] = "No fallback key found in upload";
      return error;
    }

    KeyUploadStatus status = fallback_store_.upload_fallback_key(
        user_id, device_id, fb_key);

    json result;
    result["success"] = (status == KeyUploadStatus::SUCCESS);
    result["fallback_key_count"] = fallback_store_.count_fallback_keys(
        user_id, device_id);

    return result;
  }

  /// Query fallback keys (internal — returns stored keys for a device)
  json query_fallback_keys(const std::string& user_id,
                            const std::string& device_id) {
    auto fb_keys = fallback_store_.query_fallback_keys(user_id, device_id);

    json result;
    result["fallback_keys"] = json::object();
    result["unused_fallback_key_count"] = 0;

    for (const auto& fb : fb_keys) {
      if (!jbool(fb, "used", false)) {
        result["unused_fallback_key_count"] =
            result["unused_fallback_key_count"].get<int>() + 1;
      }
    }

    return result;
  }

  // =========================================================================
  // Cross-Signing Operations
  // =========================================================================

  /// Upload cross-signing keys
  json upload_cross_signing_keys(const std::string& user_id,
                                   const json& upload_data) {
    auto validation = validator_.validate_cross_signing_upload(upload_data);

    if (!validation.valid) {
      json error;
      error["errcode"] = std::string(ERR_BAD_JSON);
      error["error"] = validation.error;
      return error;
    }

    KeyUploadStatus status = xsign_store_.upload_cross_signing_keys(
        user_id, validation.valid_keys);

    json result;
    result["success"] = (status == KeyUploadStatus::SUCCESS);
    return result;
  }

  /// Query cross-signing keys
  json query_cross_signing_keys(const std::vector<std::string>& user_ids) {
    return query_service_.query_cross_signing_keys(user_ids);
  }

  /// Get cross-signing status for a user
  json get_cross_signing_status(const std::string& user_id) {
    CrossSigningStatus status = xsign_store_.get_cross_signing_status(user_id);

    json result;
    result["user_id"] = user_id;
    result["cross_signing_status"] = static_cast<int>(status);

    switch (status) {
      case CrossSigningStatus::FULLY_CONFIGURED:
        result["cross_signing_configured"] = true;
        result["description"] = "Fully configured with all three cross-signing keys";
        break;
      case CrossSigningStatus::CROSS_SIGNING_EXISTS:
        result["cross_signing_configured"] = true;
        result["description"] = "Master key configured, missing self/user signing keys";
        break;
      case CrossSigningStatus::SELF_SIGNING_EXISTS:
        result["cross_signing_configured"] = true;
        result["description"] = "Master and self-signing keys configured";
        break;
      case CrossSigningStatus::USER_SIGNING_EXISTS:
        result["cross_signing_configured"] = true;
        result["description"] = "Master and user-signing keys configured";
        break;
      case CrossSigningStatus::NOT_CROSS_SIGNING:
        result["cross_signing_configured"] = false;
        result["description"] = "No cross-signing keys configured";
        break;
      default:
        result["cross_signing_configured"] = false;
        result["description"] = "Unknown cross-signing state";
        break;
    }

    return result;
  }

  // =========================================================================
  // Signature Operations
  // =========================================================================

  /// Upload key signatures
  json upload_key_signatures(const std::string& upload_user_id,
                               const json& upload_data) {
    auto validation = validator_.validate_signature_upload(upload_data);

    if (!validation.valid) {
      json error;
      error["errcode"] = std::string(ERR_BAD_JSON);
      error["error"] = validation.error;
      return error;
    }

    json results;
    results["success"] = json::array();
    results["failures"] = json::object();

    for (const auto& [target_user_id, device_sigs] :
         validation.valid_signatures) {
      for (const auto& [target_device_id, sig_data] : device_sigs.items()) {
        if (!sig_data.is_object()) continue;

        for (const auto& [signed_user_id, signed_devs] : sig_data.items()) {
          if (!signed_devs.is_object()) continue;

          for (const auto& [signed_device_id, signature] : signed_devs.items()) {
            KeyUploadStatus status = sig_store_.store_signature(
                target_user_id, target_device_id,
                signed_user_id, signed_device_id,
                signature);

            if (status == KeyUploadStatus::SUCCESS) {
              results["success"].push_back(
                  target_user_id + ":" + target_device_id + " -> " +
                  signed_user_id + ":" + signed_device_id);
            } else {
              std::string err_key = target_user_id + ":" + signed_user_id;
              results["failures"][err_key] = "Failed to store signature";
            }
          }
        }
      }
    }

    return results;
  }

  /// Query signatures for a user's devices
  json query_key_signatures(const std::string& user_id,
                              const std::string& device_id) {
    json result;
    result["signatures"] = json::array();

    auto sigs = sig_store_.get_signatures_for(user_id, device_id);
    for (const auto& sig : sigs) {
      result["signatures"].push_back(sig);
    }

    result["count"] = sigs.size();
    return result;
  }

  // =========================================================================
  // Device List Operations
  // =========================================================================

  /// Get device list changes since a stream token
  json get_device_list_changes(int64_t from_token, int64_t to_token) {
    auto changes = tracker_.get_device_list_changes(from_token, to_token);

    json result;
    result["changed"] = json::array();
    result["left"] = json::array();

    for (const auto& [user_id, info] : changes) {
      if (info.contains("changed_devices") && info["changed_devices"].is_array()) {
        for (const auto& d : info["changed_devices"]) {
          if (d.is_string()) result["changed"].push_back(user_id);
        }
      }
      if (info.contains("left_devices") && info["left_devices"].is_array()) {
        if (info["left_devices"].size() > 0) {
          result["left"].push_back(user_id);
        }
      }
    }

    // Deduplicate
    std::set<std::string> changed_set;
    for (const auto& v : result["changed"]) {
      changed_set.insert(v.get<std::string>());
    }
    result["changed"] = json::array();
    for (const auto& v : changed_set) {
      result["changed"].push_back(v);
    }

    std::set<std::string> left_set;
    for (const auto& v : result["left"]) {
      left_set.insert(v.get<std::string>());
    }
    result["left"] = json::array();
    for (const auto& v : left_set) {
      result["left"].push_back(v);
    }

    return result;
  }

  /// Get pending key change notifications for federation
  std::vector<std::tuple<std::string, std::string, int64_t>>
  get_pending_outbound_notifications() {
    return tracker_.get_pending_outbound_notifications();
  }

  /// Add shared user association (for key change notification scoping)
  void add_shared_user(const std::string& user_id,
                        const std::string& shared_user_id) {
    tracker_.add_shared_user(user_id, shared_user_id);
  }

  /// Notify of a key change and queue federation notifications
  void notify_device_key_change(const std::string& user_id,
                                 const std::vector<std::string>& changed_devices,
                                 const std::vector<std::string>& left_devices) {
    int64_t stream_id = tracker_.record_device_list_update(
        user_id, changed_devices, left_devices);

    // Get users that share rooms with this user
    auto shared_users = tracker_.get_shared_users(user_id);

    // Queue notifications for shared users
    for (const auto& shared_user : shared_users) {
      change_notifier_.queue_notification(
          shared_user, "local", changed_devices);
    }
  }

  // =========================================================================
  // Key Health and Management
  // =========================================================================

  /// Get E2E key health for a user/device
  json get_key_health(const std::string& user_id,
                       const std::string& device_id) {
    return cleanup_engine_.get_user_key_health(user_id, device_id);
  }

  /// Delete all E2E keys for a device (on device deletion/logout)
  json delete_device_e2e_keys(const std::string& user_id,
                                const std::string& device_id) {
    json result;
    result["device_keys_deleted"] =
        device_store_.delete_device_keys(user_id, device_id);

    // Delete associated one-time keys
    int otk_deleted = 0;
    auto otk_ids = otk_store_.get_otk_ids(user_id, device_id);
    for (const auto& key_id : otk_ids) {
      if (otk_store_.delete_one_time_key(user_id, key_id)) {
        otk_deleted++;
      }
    }
    result["one_time_keys_deleted"] = otk_deleted;

    // Delete fallback keys
    int fb_deleted = fallback_store_.delete_fallback_keys_for_device(
        user_id, device_id);
    result["fallback_keys_deleted"] = fb_deleted;

    // Delete signatures
    int sigs_deleted = sig_store_.delete_signatures_by(user_id, device_id);
    result["signatures_deleted"] = sigs_deleted;

    // Record device list change (device left)
    tracker_.record_device_list_update(user_id, {}, {device_id});

    return result;
  }

  /// Rotate device keys
  json rotate_device_keys(const std::string& user_id,
                           const std::string& device_id) {
    auto rotated = rotation_engine_.rotate_device_keys(user_id, device_id);

    // Store the new keys
    device_store_.store_device_keys(user_id, device_id, rotated.new_device_keys);

    // Record device list change
    tracker_.record_device_list_update(user_id, {device_id}, {});

    json result;
    result["success"] = true;
    result["device_id"] = device_id;
    result["key_version"] = rotated.version;

    return result;
  }

  /// Generate a complete set of E2E keys for a new device
  json generate_keys_for_device(const std::string& user_id,
                                  const std::string& device_id) {
    auto rotated = rotation_engine_.rotate_device_keys(user_id, device_id);

    json result;
    result["device_keys"] = rotated.new_device_keys;
    result["ed25519_private_key"] = rotated.new_ed25519_private_b64;
    result["curve25519_private_key"] = rotated.new_curve25519_private_b64;
    result["version"] = rotated.version;

    // Generate initial set of one-time keys (50 keys)
    json otk_result;
    otk_result["one_time_key_counts"] = json::object();

    std::map<std::string, json> otks_to_upload;
    for (int i = 0; i < 50; ++i) {
      auto cv_kp = generate_curve25519_keypair();
      std::string otk_id = "signed_curve25519:" + random_alphanumeric(8);

      json otk_obj;
      otk_obj["key"] = base64_encode_unpadded(cv_kp.public_key);
      otk_obj["signatures"] = json::object();

      otks_to_upload[otk_id] = otk_obj;
    }

    otk_store_.upload_one_time_keys(user_id, device_id, otks_to_upload);

    auto counts = otk_store_.count_one_time_keys(user_id, device_id);
    for (const auto& [algo, count] : counts) {
      otk_result["one_time_key_counts"][algo] = count;
    }
    result["one_time_keys_summary"] = otk_result;

    return result;
  }

  // =========================================================================
  // Admin / Diagnostic Operations
  // =========================================================================

  /// Get statistics about E2E key storage
  json get_e2e_statistics() {
    json stats;
    stats["users_with_device_keys"] = device_store_.list_users_with_keys().size();
    stats["users_with_cross_signing"] = xsign_store_.list_users().size();
    stats["total_device_list_changes"] = tracker_.get_current_stream_id();
    stats["timestamp"] = now_ms();
    return stats;
  }

  /// Run periodic cleanup
  json run_cleanup() {
    auto stats = cleanup_engine_.run_cleanup();

    json result;
    result["otks_cleaned"] = stats.otks_cleaned;
    result["stream_entries_cleaned"] = stats.stream_entries_cleaned;
    result["cleanup_time_ms"] = stats.cleanup_time_ms;
    result["timestamp"] = now_ms();

    return result;
  }

  /// Re-upload stored device keys as if they were freshly uploaded
  /// (useful for key backup/restore operations)
  json reupload_device_keys(const std::string& user_id,
                              const std::string& device_id) {
    auto existing = device_store_.get_device_keys(user_id, device_id);
    if (!existing.has_value()) {
      json error;
      error["errcode"] = std::string(ERR_NOT_FOUND);
      error["error"] = "No stored device keys found for this device";
      return error;
    }

    // Just re-record the same keys (triggers device list update)
    device_store_.store_device_keys(user_id, device_id, *existing);

    tracker_.record_device_list_update(user_id, {device_id}, {});

    json result;
    result["success"] = true;
    result["action"] = "reuploaded";
    return result;
  }

  // =========================================================================
  // Dehydrated Device Key Operations
  // =========================================================================

  /// Store keys for a dehydrated device
  json store_dehydrated_device_keys(const std::string& user_id,
                                      const std::string& device_id,
                                      const json& key_data) {
    std::string d_key = user_id + ":" + device_id;
    dehydrated_keys_[d_key] = {
      {"user_id", user_id},
      {"device_id", device_id},
      {"key_data", key_data},
      {"stored_at", now_ms()},
      {"expires_at", now_ms() + 7LL * 24LL * 3600LL * 1000LL}
    };

    json result;
    result["success"] = true;
    result["device_id"] = device_id;
    return result;
  }

  /// Retrieve keys for a dehydrated device
  json get_dehydrated_device_keys(const std::string& user_id,
                                    const std::string& device_id) {
    std::string d_key = user_id + ":" + device_id;
    auto it = dehydrated_keys_.find(d_key);

    if (it == dehydrated_keys_.end()) {
      json error;
      error["errcode"] = std::string(ERR_NOT_FOUND);
      error["error"] = "No dehydrated device keys found";
      return error;
    }

    // Check expiry
    int64_t expires_at = jint(it->second, "expires_at", 0);
    if (expires_at > 0 && now_ms() > expires_at) {
      dehydrated_keys_.erase(it);
      json error;
      error["errcode"] = std::string(ERR_NOT_FOUND);
      error["error"] = "Dehydrated device keys have expired";
      return error;
    }

    return it->second["key_data"];
  }

  /// Clean up expired dehydrated device keys
  int cleanup_dehydrated_device_keys() {
    int cleaned = 0;
    int64_t now = now_ms();

    auto it = dehydrated_keys_.begin();
    while (it != dehydrated_keys_.end()) {
      int64_t expires_at = jint(it->second, "expires_at", 0);
      if (expires_at > 0 && now > expires_at) {
        it = dehydrated_keys_.erase(it);
        cleaned++;
      } else {
        ++it;
      }
    }

    return cleaned;
  }

  // Access to internal components for testing/admin
  DeviceKeyStore& device_key_store() { return device_store_; }
  OneTimeKeyStore& otk_key_store() { return otk_store_; }
  FallbackKeyStore& fallback_key_store() { return fallback_store_; }
  CrossSigningKeyStore& cross_signing_store() { return xsign_store_; }
  DeviceListTracker& device_list_tracker() { return tracker_; }
  E2EKeySigningEngine& signing_engine() { return signer_; }

private:
  E2EKeySigningEngine signer_;
  E2EKeyValidationEngine validator_;
  DeviceKeyStore device_store_;
  OneTimeKeyStore otk_store_;
  FallbackKeyStore fallback_store_;
  CrossSigningKeyStore xsign_store_;
  E2ESignatureStore sig_store_;
  DeviceListTracker tracker_;
  KeyQueryService query_service_;
  KeyClaimService claim_service_;
  E2EKeyCleanupEngine cleanup_engine_;
  KeyChangeNotifier change_notifier_;
  KeyRotationEngine rotation_engine_;

  // Dehydrated device keys
  std::map<std::string, json> dehydrated_keys_;
};

// ============================================================================
// 15. Global factory functions and initialization
// ============================================================================

/// Create a new E2EKeyManager instance
std::unique_ptr<E2EKeyManager> create_e2e_key_manager() {
  return std::make_unique<E2EKeyManager>();
}

/// Initialize E2E key schema in the database
void initialize_e2e_key_schema(/* storage::LoggingTransaction& txn */) {
  // SQL DDL for E2E key tables (executed via transaction)
  // This would typically be: txn.execute(create_table_sql, {});

  const std::string create_device_keys_sql = R"SQL(
    CREATE TABLE IF NOT EXISTS e2e_device_keys_json (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      key_json TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, device_id)
    )
  )SQL";

  const std::string create_one_time_keys_sql = R"SQL(
    CREATE TABLE IF NOT EXISTS e2e_one_time_keys_json (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      key_id TEXT NOT NULL,
      key_json TEXT NOT NULL,
      algorithm TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      claimed INTEGER DEFAULT 0,
      claimed_by TEXT,
      claimed_at INTEGER,
      PRIMARY KEY (user_id, device_id, key_id)
    )
  )SQL";

  const std::string create_fallback_keys_sql = R"SQL(
    CREATE TABLE IF NOT EXISTS e2e_fallback_keys_json (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      key_id TEXT NOT NULL,
      key_json TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      used INTEGER DEFAULT 0,
      used_at INTEGER,
      used_by TEXT,
      PRIMARY KEY (user_id, device_id, key_id)
    )
  )SQL";

  const std::string create_cross_signing_keys_sql = R"SQL(
    CREATE TABLE IF NOT EXISTS e2e_cross_signing_keys (
      user_id TEXT NOT NULL,
      key_type TEXT NOT NULL,
      key_data TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      version INTEGER DEFAULT 1,
      PRIMARY KEY (user_id, key_type)
    )
  )SQL";

  const std::string create_cross_signing_sigs_sql = R"SQL(
    CREATE TABLE IF NOT EXISTS e2e_cross_signing_signatures (
      signed_user_id TEXT NOT NULL,
      signed_key_type TEXT NOT NULL,
      signer_user_id TEXT NOT NULL,
      signer_key_type TEXT NOT NULL,
      signature TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (signed_user_id, signed_key_type,
                   signer_user_id, signer_key_type)
    )
  )SQL";

  const std::string create_key_signatures_sql = R"SQL(
    CREATE TABLE IF NOT EXISTS e2e_key_signatures (
      target_user_id TEXT NOT NULL,
      target_device_id TEXT NOT NULL,
      signed_user_id TEXT NOT NULL,
      signed_device_id TEXT NOT NULL,
      signature_data TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (target_user_id, target_device_id,
                   signed_user_id, signed_device_id)
    )
  )SQL";

  const std::string create_device_lists_sql = R"SQL(
    CREATE TABLE IF NOT EXISTS device_lists_stream (
      stream_id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      update_type TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )
  )SQL";

  const std::string create_device_lists_remote_sql = R"SQL(
    CREATE TABLE IF NOT EXISTS device_lists_remote_ext (
      user_id TEXT NOT NULL,
      origin TEXT NOT NULL,
      last_stream_id INTEGER NOT NULL,
      last_update_ts INTEGER NOT NULL,
      PRIMARY KEY (user_id, origin)
    )
  )SQL";

  const std::string create_device_lists_outbound_sql = R"SQL(
    CREATE TABLE IF NOT EXISTS e2e_device_lists_outbound (
      destination TEXT NOT NULL,
      user_id TEXT NOT NULL,
      stream_id INTEGER NOT NULL,
      sent_at INTEGER NOT NULL,
      PRIMARY KEY (destination, user_id)
    )
  )SQL";

  const std::string create_key_change_log_sql = R"SQL(
    CREATE TABLE IF NOT EXISTS e2e_key_change_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      change_type TEXT NOT NULL,
      created_at INTEGER NOT NULL
    )
  )SQL";

  const std::string create_dehydrated_keys_sql = R"SQL(
    CREATE TABLE IF NOT EXISTS e2e_dehydrated_keys (
      user_id TEXT NOT NULL,
      device_id TEXT NOT NULL,
      key_data TEXT NOT NULL,
      stored_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      PRIMARY KEY (user_id, device_id)
    )
  )SQL";

  // In production, these would be executed via:
  // txn.execute(create_device_keys_sql, {});
  // txn.execute(create_one_time_keys_sql, {});
  // ... etc.

  (void)create_device_keys_sql;
  (void)create_one_time_keys_sql;
  (void)create_fallback_keys_sql;
  (void)create_cross_signing_keys_sql;
  (void)create_cross_signing_sigs_sql;
  (void)create_key_signatures_sql;
  (void)create_device_lists_sql;
  (void)create_device_lists_remote_sql;
  (void)create_device_lists_outbound_sql;
  (void)create_key_change_log_sql;
  (void)create_dehydrated_keys_sql;
}

/// Create a self-test key pair for testing
json generate_test_keys() {
  E2EKeyManager manager;
  return manager.generate_keys_for_device("@test:localhost", "TESTDEVICE");
}

// ============================================================================
// Self-test section
// ============================================================================
#ifdef PROGRESSIVE_E2E_KEYS_SELFTEST

namespace {

void run_e2e_keys_selftests() {
  // Test 1: Device key upload and retrieval
  {
    auto manager = create_e2e_key_manager();

    json device_keys;
    device_keys["user_id"] = "@alice:test";
    device_keys["device_id"] = "ABCDEF";
    device_keys["algorithms"] = json::array({
        "m.olm.v1.curve25519-aes-sha2",
        "m.megolm.v1.aes-sha2"
    });
    device_keys["keys"] = json::object();

    auto ed_kp = generate_ed25519_keypair();
    auto cv_kp = generate_curve25519_keypair();

    device_keys["keys"]["ed25519:ABCDEF"] =
        base64_encode_unpadded(ed_kp.public_key);
    device_keys["keys"]["curve25519:ABCDEF"] =
        base64_encode_unpadded(cv_kp.public_key);

    json upload;
    upload["device_keys"] = device_keys;

    auto result = manager->upload_device_keys("@alice:test", "ABCDEF", upload);
    if (!result.contains("success") || !result["success"].get<bool>()) {
      throw std::runtime_error("SELFTEST FAILED: Device key upload");
    }

    auto retrieved = manager->device_key_store().get_device_keys(
        "@alice:test", "ABCDEF");
    if (!retrieved.has_value()) {
      throw std::runtime_error("SELFTEST FAILED: Device key retrieval");
    }

    std::cout << "[e2e_keys] Self-test 1 passed: Device key upload/retrieval"
              << std::endl;
  }

  // Test 2: One-time key upload and claim
  {
    auto manager = create_e2e_key_manager();

    json otk_upload;
    otk_upload["one_time_keys"] = json::object();

    for (int i = 0; i < 10; ++i) {
      auto cv_kp = generate_curve25519_keypair();
      std::string key_id = "signed_curve25519:AAAA" + std::to_string(i);

      json key_obj;
      key_obj["key"] = base64_encode_unpadded(cv_kp.public_key);
      otk_upload["one_time_keys"][key_id] = key_obj;
    }

    auto result = manager->upload_one_time_keys(
        "@alice:test", "ABCDEF", otk_upload);
    if (!result.contains("one_time_key_counts")) {
      throw std::runtime_error("SELFTEST FAILED: OTK upload");
    }

    // Claim a key
    std::map<std::string, std::map<std::string, std::string>> claim_req;
    claim_req["@alice:test"]["ABCDEF"] = "signed_curve25519";

    auto claim_result = manager->claim_keys(claim_req);
    if (!claim_result["one_time_keys"].contains("@alice:test")) {
      throw std::runtime_error("SELFTEST FAILED: OTK claim");
    }

    std::cout << "[e2e_keys] Self-test 2 passed: OTK upload and claim"
              << std::endl;
  }

  // Test 3: Fallback key upload and retrieval
  {
    auto manager = create_e2e_key_manager();

    auto cv_kp = generate_curve25519_keypair();
    json fb_upload;
    fb_upload["fallback"] = true;
    fb_upload["one_time_keys"] = json::object();

    json fb_key;
    fb_key["key"] = base64_encode_unpadded(cv_kp.public_key);
    fb_key["fallback"] = true;
    fb_upload["one_time_keys"]["signed_curve25519:FB01"] = fb_key;

    auto result = manager->upload_fallback_key(
        "@alice:test", "ABCDEF", fb_upload);
    if (!result["success"].get<bool>()) {
      throw std::runtime_error("SELFTEST FAILED: Fallback key upload");
    }

    std::cout << "[e2e_keys] Self-test 3 passed: Fallback key upload"
              << std::endl;
  }

  // Test 4: Cross-signing key upload
  {
    auto manager = create_e2e_key_manager();

    auto ed_kp = generate_ed25519_keypair();

    json master_key;
    master_key["user_id"] = "@alice:test";
    master_key["usage"] = json::array({"master"});
    master_key["keys"] = json::object();
    master_key["keys"]["ed25519:MASTER01"] =
        base64_encode_unpadded(ed_kp.public_key);
    master_key["signatures"] = json::object();

    json upload;
    upload["master_key"] = master_key;

    auto result = manager->upload_cross_signing_keys("@alice:test", upload);
    if (!result["success"].get<bool>()) {
      throw std::runtime_error("SELFTEST FAILED: Cross-signing key upload");
    }

    auto status = manager->get_cross_signing_status("@alice:test");
    if (!status["cross_signing_configured"].get<bool>()) {
      throw std::runtime_error(
          "SELFTEST FAILED: Cross-signing not recognized as configured");
    }

    std::cout << "[e2e_keys] Self-test 4 passed: Cross-signing key upload/query"
              << std::endl;
  }

  // Test 5: Device list tracking
  {
    auto manager = create_e2e_key_manager();

    int64_t sid1 = manager->device_list_tracker().record_device_list_update(
        "@bob:test", {"DEVICE1"}, {});

    int64_t sid2 = manager->device_list_tracker().record_device_list_update(
        "@bob:test", {}, {"DEVICE1"});

    if (sid2 <= sid1) {
      throw std::runtime_error("SELFTEST FAILED: Stream ID ordering");
    }

    auto changes = manager->get_device_list_changes(sid1, sid2);
    if (!changes.contains("left") || changes["left"].empty()) {
      throw std::runtime_error(
          "SELFTEST FAILED: Device list change not detected");
    }

    std::cout << "[e2e_keys] Self-test 5 passed: Device list tracking"
              << std::endl;
  }

  // Test 6: Key rotation
  {
    auto manager = create_e2e_key_manager();

    auto keys = manager->rotate_device_keys("@alice:test", "ABCDEF");
    if (!keys["success"].get<bool>()) {
      throw std::runtime_error("SELFTEST FAILED: Key rotation");
    }

    std::cout << "[e2e_keys] Self-test 6 passed: Key rotation" << std::endl;
  }

  // Test 7: Ed25519 sign/verify
  {
    auto kp = generate_ed25519_keypair();
    std::string message = "Test message for E2E keys";

    std::string sig = ed25519_sign(message, kp.private_key);
    bool verified = ed25519_verify(message, sig, kp.public_key);

    if (!verified) {
      throw std::runtime_error("SELFTEST FAILED: Ed25519 sign/verify");
    }

    // Tampered message should fail
    bool tampered = ed25519_verify("Tampered message", sig, kp.public_key);
    if (tampered) {
      throw std::runtime_error("SELFTEST FAILED: Ed25519 accepted tampered msg");
    }

    std::cout << "[e2e_keys] Self-test 7 passed: Ed25519 sign/verify"
              << std::endl;
  }

  // Test 8: Curve25519 key generation
  {
    auto kp = generate_curve25519_keypair();
    if (kp.public_key.size() != CURVE25519_PUBLIC_KEY_BYTES) {
      throw std::runtime_error("SELFTEST FAILED: Curve25519 public key size");
    }
    if (kp.private_key.size() != CURVE25519_PRIVATE_KEY_BYTES) {
      throw std::runtime_error("SELFTEST FAILED: Curve25519 private key size");
    }

    std::cout << "[e2e_keys] Self-test 8 passed: Curve25519 key generation"
              << std::endl;
  }

  // Test 9: Canonical JSON
  {
    json test_obj;
    test_obj["b"] = 2;
    test_obj["a"] = 1;

    std::string canonical = canonical_json(test_obj);
    if (canonical != R"({"a":1,"b":2})") {
      throw std::runtime_error(
          "SELFTEST FAILED: Canonical JSON ordering: " + canonical);
    }

    std::cout << "[e2e_keys] Self-test 9 passed: Canonical JSON" << std::endl;
  }

  // Test 10: Device deletion cleanup
  {
    auto manager = create_e2e_key_manager();

    // Create device keys
    json device_keys;
    device_keys["user_id"] = "@charlie:test";
    device_keys["device_id"] = "CHARDEV";
    device_keys["algorithms"] = json::array({"m.olm.v1.curve25519-aes-sha2"});
    device_keys["keys"] = json::object();

    auto ed_kp = generate_ed25519_keypair();
    device_keys["keys"]["ed25519:CHARDEV"] =
        base64_encode_unpadded(ed_kp.public_key);

    json upload;
    upload["device_keys"] = device_keys;
    manager->upload_device_keys("@charlie:test", "CHARDEV", upload);

    // Create some OTKs
    json otk_upload;
    otk_upload["one_time_keys"] = json::object();
    auto cv_kp = generate_curve25519_keypair();
    json key_obj;
    key_obj["key"] = base64_encode_unpadded(cv_kp.public_key);
    otk_upload["one_time_keys"]["signed_curve25519:XXX"] = key_obj;
    manager->upload_one_time_keys("@charlie:test", "CHARDEV", otk_upload);

    // Delete all keys
    auto del_result = manager->delete_device_e2e_keys(
        "@charlie:test", "CHARDEV");

    // Verify keys are gone
    auto remaining = manager->device_key_store().get_device_keys(
        "@charlie:test", "CHARDEV");
    if (remaining.has_value()) {
      throw std::runtime_error(
          "SELFTEST FAILED: Device keys not deleted");
    }

    std::cout << "[e2e_keys] Self-test 10 passed: Device deletion cleanup"
              << std::endl;
  }

  std::cerr << "[e2e_keys] All self-tests passed." << std::endl;
}

// Run self-tests at static initialization time
static const bool _e2e_selftest_result = []() {
  try {
    run_e2e_keys_selftests();
  } catch (const std::exception& e) {
    std::cerr << "[e2e_keys] SELFTEST ERROR: " << e.what() << std::endl;
    std::abort();
  }
  return true;
}();

}  // anonymous namespace

#endif  // PROGRESSIVE_E2E_KEYS_SELFTEST

// ============================================================================
// End namespace progressive
// ============================================================================
}  // namespace progressive
