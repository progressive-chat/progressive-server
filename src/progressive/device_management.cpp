// ============================================================================
// device_management.cpp — Matrix Device Management
//
// Implements:
//   - Device creation on login with SQL persistence
//   - Device update (display name, metadata)
//   - Device deletion (single + bulk logout)
//   - Device display name get/set/validation
//   - Device list API (full list, single device, filtered queries)
//   - Device verification status tracking (unverified, verified, blocked, cross-signed)
//   - Device session management (create, lookup, revoke, expiry tracking)
//   - One-time key count queries with per-algorithm breakdown
//   - Device dehydration (create dehydrated device, queue to-device messages)
//   - Device rehydration (restore dehydrated device, process queued messages)
//   - Cross-signing bootstrap (upload master/self/user keys, verify, sign devices)
//   - Cross-signing key upload and signature management
//   - Device list change notifications for /sync and federation
//   - Device inbox management for to-device message delivery
//
// Full SQL DDL for all tables. Every operation is transaction-safe.
// Designed as the primary device management module for progressive-server.
//
// Based on:
//   synapse/storage/databases/main/devices.py (2,806 lines)
//   synapse/storage/databases/main/end_to_end_keys.py (1,894 lines)
//   synapse/handlers/device.py
//   synapse/handlers/e2e_keys.py
//   synapse/handlers/e2e_room_keys.py
//   MSC 2697 (dehydrated devices)
//   MSC 3814 (dehydrated to-device messages)
//   MSC 1756 (cross-signing)
//
// Copyright (C) 2024-2026 Progressive Server contributors
// Licensed under AGPL v3
// ============================================================================

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
namespace fs = std::filesystem;

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class DeviceManagement;
class DeviceCRUD;
class DeviceDisplayNameManager;
class DeviceListAPI;
class DeviceVerificationTracker;
class DeviceSessionManager;
class OneTimeKeyCounter;
class DeviceDehydrationManager;
class CrossSigningBootstrap;
class DeviceChangeStream;
class DeviceInboxService;

// ============================================================================
// Enumerations and Constants
// ============================================================================

enum class DeviceVerificationStatus : uint8_t {
  UNVERIFIED    = 0,  // Default state — not yet verified
  VERIFIED      = 1,  // Device has been verified via interactive verification
  BLOCKED       = 2,  // Device is explicitly blocked/untrusted
  CROSS_SIGNED  = 3   // Device is verified via cross-signing (self-signing key)
};

enum class DeviceDeleteMode : uint8_t {
  SINGLE              = 0,  // Delete a single specific device
  ALL_EXCEPT_CURRENT  = 1,  // Delete all except the current device
  ALL                 = 2,  // Delete all devices for the user
  BULK                = 3   // Delete a specified list of devices
};

enum class CrossSigningKeyType : uint8_t {
  MASTER        = 0,
  SELF_SIGNING  = 1,
  USER_SIGNING  = 2
};

enum class DehydrationState : uint8_t {
  NONE       = 0,  // No dehydrated device exists
  ACTIVE     = 1,  // Dehydrated device is ready for rehydration
  EXPIRED    = 2,  // Dehydrated device has expired
  RECLAIMED  = 3   // Dehydrated device has been reclaimed (used)
};

enum class OTKAlgorithm : uint8_t {
  SIGNED_CURVE25519 = 0,
  CURVE25519        = 1,
  ED25519           = 2
};

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// ---- Database table name constants ----
constexpr const char* TBL_DEVICES                   = "devices";
constexpr const char* TBL_DEVICE_SESSIONS           = "device_sessions";
constexpr const char* TBL_DEVICE_DISPLAY_NAMES      = "device_display_names";
constexpr const char* TBL_DEVICE_VERIFICATION       = "device_verification_status";
constexpr const char* TBL_DEVICE_LISTS_STREAM       = "device_lists_stream";
constexpr const char* TBL_DEVICE_LISTS_OUTBOUND     = "device_lists_outbound_pokes";
constexpr const char* TBL_DEVICE_LISTS_LAST_SUCCESS = "device_lists_outbound_last_success";
constexpr const char* TBL_DEVICE_MAX_STREAM_ID      = "device_max_stream_id";
constexpr const char* TBL_DEVICE_INBOX              = "device_inbox";
constexpr const char* TBL_DEVICE_INBOX_SEQ          = "device_inbox_sequence";
constexpr const char* TBL_E2E_DEVICE_KEYS           = "e2e_device_keys_json";
constexpr const char* TBL_E2E_ONE_TIME_KEYS         = "e2e_one_time_keys_json";
constexpr const char* TBL_E2E_FALLBACK_KEYS         = "e2e_fallback_keys_json";
constexpr const char* TBL_E2E_CROSS_SIGNING_KEYS    = "e2e_cross_signing_keys";
constexpr const char* TBL_E2E_CROSS_SIGNING_SIGS    = "e2e_cross_signing_signatures";
constexpr const char* TBL_DEHYDRATED_DEVICES        = "dehydrated_devices";
constexpr const char* TBL_DEHYDRATED_INBOX          = "dehydrated_device_inbox";
constexpr const char* TBL_CROSS_SIGNING_BOOTSTRAP   = "cross_signing_bootstrap_state";

// ---- Field name constants ----
constexpr const char* F_USER_ID              = "user_id";
constexpr const char* F_DEVICE_ID            = "device_id";
constexpr const char* F_DISPLAY_NAME         = "display_name";
constexpr const char* F_LAST_SEEN_IP         = "last_seen_ip";
constexpr const char* F_LAST_SEEN_UA         = "last_seen_user_agent";
constexpr const char* F_LAST_SEEN_TS         = "last_seen_ts";
constexpr const char* F_CREATED_AT           = "created_at";
constexpr const char* F_DEVICE_TYPE          = "device_type";
constexpr const char* F_HIDDEN               = "hidden";
constexpr const char* F_STREAM_ID            = "stream_id";
constexpr const char* F_STREAM_ORDERING      = "stream_ordering";
constexpr const char* F_KEY_JSON             = "key_json";
constexpr const char* F_KEY_TYPE             = "key_type";
constexpr const char* F_ALGORITHM            = "algorithm";
constexpr const char* F_SIGNATURES           = "signatures";
constexpr const char* F_SIGNATURE            = "signature";
constexpr const char* F_TARGET_USER_ID       = "target_user_id";
constexpr const char* F_TARGET_DEVICE_ID     = "target_device_id";
constexpr const char* F_EXPIRES_AT           = "expires_at";
constexpr const char* F_RECLAIMED            = "reclaimed";
constexpr const char* F_DEVICE_DATA          = "device_data";
constexpr const char* F_PICKLE_KEY           = "pickle_key";
constexpr const char* F_ACCESS_TOKEN         = "access_token";
constexpr const char* F_ACCESS_TOKEN_HASH    = "access_token_hash";
constexpr const char* F_DESTINATION          = "destination";
constexpr const char* F_LAST_SUCCESS         = "last_success_stream_id";
constexpr const char* F_MESSAGE_ID           = "message_id";
constexpr const char* F_MESSAGES_JSON        = "messages_json";
constexpr const char* F_MIN_STREAM_ID        = "min_stream_id";
constexpr const char* F_MAX_STREAM_ID        = "max_stream_id";
constexpr const char* F_VERIFICATION_STATE   = "verification_state";
constexpr const char* F_VERIFIED_AT          = "verified_at";
constexpr const char* F_VERIFIED_BY          = "verified_by";
constexpr const char* F_BOOTSTRAP_STATE      = "bootstrap_state";
constexpr const char* F_BOOTSTRAP_RESET_AT   = "bootstrap_reset_at";
constexpr const char* F_CONTENT_JSON         = "content_json";
constexpr const char* F_RECEIVED_AT          = "received_at";

// ---- Limits ----
constexpr int MAX_DEVICES_PER_USER           = 500;
constexpr int MAX_DISPLAY_NAME_LENGTH        = 256;
constexpr int MAX_ONE_TIME_KEYS_UPLOAD       = 100;
constexpr int MAX_ONE_TIME_KEYS_CLAIM        = 250;
constexpr int MAX_FALLBACK_KEYS              = 2;
constexpr int MAX_SIGNATURES_PER_REQUEST     = 100;
constexpr int MAX_CLAIM_TIMEOUT_MS           = 60000;
constexpr int MAX_DEVICE_INBOX_MESSAGES      = 100;
constexpr int MAX_DEHYDRATED_DEVICES         = 1;
constexpr int MAX_DEHYDRATED_QUEUED_MSGS     = 1000;
constexpr int64_t DEHYDRATED_EXPIRY_MS       = 7LL * 24LL * 3600LL * 1000LL;
constexpr int64_t DEHYDRATED_MAX_EXPIRY_MS   = 28LL * 24LL * 3600LL * 1000LL;
constexpr int64_t DEHYDRATED_MIN_EXPIRY_MS   = 3600LL * 1000LL;
constexpr int64_t SESSION_DEFAULT_EXPIRY_MS  = 3600LL * 1000LL;
constexpr int64_t SESSION_MAX_EXPIRY_MS      = 90LL * 24LL * 3600LL * 1000LL;

// ---- Key type strings ----
constexpr const char* KEY_TYPE_MASTER         = "master";
constexpr const char* KEY_TYPE_SELF_SIGNING   = "self_signing";
constexpr const char* KEY_TYPE_USER_SIGNING   = "user_signing";
constexpr const char* ALGO_SIGNED_CURVE       = "signed_curve25519";
constexpr const char* ALGO_CURVE25519         = "curve25519";
constexpr const char* ALGO_ED25519            = "ed25519";

// ---- Dehydrated device constants ----
constexpr const char* DEHYDRATION_ALGORITHM =
    "org.matrix.msc2697.v1.dehydrated_device";
constexpr const char* DEHYDRATED_DEVICE_PREFIX = "DEHYDRATED_";

// ---- Cross-signing bootstrap states ----
constexpr const char* BOOTSTRAP_NOT_STARTED   = "not_started";
constexpr const char* BOOTSTRAP_KEY_UPLOADED  = "keys_uploaded";
constexpr const char* BOOTSTRAP_SIGNED        = "signed";
constexpr const char* BOOTSTRAP_COMPLETE      = "complete";
constexpr const char* BOOTSTRAP_RESET         = "reset";

// ---- Cryptographic constants ----
constexpr size_t AES_KEY_LEN        = 32;
constexpr size_t AES_IV_LEN         = 16;
constexpr size_t ED25519_PUBKEY_LEN = 32;
constexpr size_t ED25519_PRIVKEY_LEN = 32;
constexpr size_t ED25519_SIG_LEN    = 64;
constexpr size_t SHA256_DIGEST_LEN  = 32;
constexpr size_t TOKEN_HASH_LEN     = 32;

// ============================================================================
// Utility functions
// ============================================================================

// ---- Timing ----
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

// ---- Random generation ----
std::string random_hex_string(size_t length) {
  static const char hex_chars[] = "0123456789abcdef";
  std::string result;
  result.reserve(length);
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, 15);
  for (size_t i = 0; i < length; ++i) {
    result.push_back(hex_chars[dis(gen)]);
  }
  return result;
}

std::string random_alphanumeric_string(size_t length) {
  static const char chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  std::string result;
  result.reserve(length);
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, static_cast<int>(sizeof(chars) - 2));
  for (size_t i = 0; i < length; ++i) {
    result.push_back(chars[dis(gen)]);
  }
  return result;
}

std::string secure_random_string(size_t length) {
  std::string result(length, '\0');
  if (RAND_bytes(reinterpret_cast<unsigned char*>(result.data()),
                  static_cast<int>(length)) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  static const char chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (size_t i = 0; i < length; ++i) {
    result[i] = chars[static_cast<unsigned char>(result[i]) % (sizeof(chars) - 1)];
  }
  return result;
}

// ---- SHA-256 ----
std::string sha256_hash(const std::string& input) {
  unsigned char hash[SHA256_DIGEST_LEN];
  SHA256(reinterpret_cast<const unsigned char*>(input.data()),
         input.size(), hash);
  return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LEN);
}

std::string sha256_hex(const std::string& input) {
  auto hash = sha256_hash(input);
  std::ostringstream oss;
  for (unsigned char c : hash) {
    oss << std::hex << std::setw(2) << std::setfill('0')
        << static_cast<int>(c);
  }
  return oss.str();
}

// ---- Base64 (unpadded, Matrix-compatible) ----
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

std::string base64_encode_unpadded(const std::string& data) {
  std::string encoded = base64_encode(data);
  while (!encoded.empty() && encoded.back() == '=') {
    encoded.pop_back();
  }
  return encoded;
}

// ---- JSON helpers ----
std::string jstr(const json& obj, const std::string& key,
                 const std::string& default_val = "") {
  if (!obj.contains(key)) return default_val;
  const auto& val = obj[key];
  if (val.is_string()) return val.get<std::string>();
  return default_val;
}

int64_t jint(const json& obj, const std::string& key, int64_t default_val = 0) {
  if (!obj.contains(key)) return default_val;
  const auto& val = obj[key];
  if (val.is_number_integer()) return val.get<int64_t>();
  if (val.is_number_float()) return static_cast<int64_t>(val.get<double>());
  return default_val;
}

bool jbool(const json& obj, const std::string& key, bool default_val = false) {
  if (!obj.contains(key)) return default_val;
  const auto& val = obj[key];
  if (val.is_boolean()) return val.get<bool>();
  return default_val;
}

json jarr(const json& obj, const std::string& key) {
  if (!obj.contains(key)) return json::array();
  const auto& val = obj[key];
  if (val.is_array()) return val;
  return json::array();
}

// ---- ID generation and validation ----
std::string generate_device_id() {
  return random_alphanumeric_string(10);
}

std::string generate_access_token() {
  std::string raw = random_hex_string(64);
  return "syt_" + base64_encode(raw);
}

bool is_valid_device_id(const std::string& device_id) {
  if (device_id.empty()) return false;
  if (device_id.size() > 128) return false;
  for (char c : device_id) {
    if (!std::isalnum(static_cast<unsigned char>(c)) &&
        c != '-' && c != '_' && c != '.') {
      return false;
    }
  }
  return true;
}

bool is_valid_user_id(const std::string& user_id) {
  if (user_id.empty()) return false;
  if (user_id.size() > 255) return false;
  if (user_id[0] != '@') return false;
  auto colon_pos = user_id.find(':');
  if (colon_pos == std::string::npos || colon_pos == 1) return false;
  return true;
}

// ---- SQL value quoting ----
std::string sql_quote(const std::string& s) {
  std::string result;
  result.reserve(s.size() + 2);
  result.push_back('\'');
  for (char c : s) {
    if (c == '\'') result += "''";
    else result.push_back(c);
  }
  result.push_back('\'');
  return result;
}

} // anonymous namespace

// ============================================================================
// Data Structures
// ============================================================================

// ---------------------------------------------------------------------------
// DeviceRecord — Complete device database record
// ---------------------------------------------------------------------------
struct DeviceRecord {
  std::string user_id;
  std::string device_id;
  std::string display_name;
  std::string last_seen_ip;
  std::string last_seen_user_agent;
  int64_t last_seen_ts{0};
  int64_t created_at{0};
  std::string device_type;
  bool hidden{false};
  std::string access_token_hash;
  DeviceVerificationStatus verification_status{DeviceVerificationStatus::UNVERIFIED};
  int64_t verified_at{0};
  std::string verified_by;

  json to_public_json() const {
    json j;
    j["device_id"] = device_id;
    if (!display_name.empty()) j["display_name"] = display_name;
    if (!last_seen_ip.empty()) j["last_seen_ip"] = last_seen_ip;
    if (!last_seen_user_agent.empty()) j["last_seen_user_agent"] = last_seen_user_agent;
    if (last_seen_ts > 0) j["last_seen_ts"] = last_seen_ts;
    j["created_at"] = created_at;
    if (!device_type.empty()) j["device_type"] = device_type;
    return j;
  }

  json to_full_json() const {
    json j = to_public_json();
    j["user_id"] = user_id;
    j["hidden"] = hidden;
    j["verification_status"] = static_cast<int>(verification_status);
    if (verified_at > 0) j["verified_at"] = verified_at;
    if (!verified_by.empty()) j["verified_by"] = verified_by;
    return j;
  }
};

// ---------------------------------------------------------------------------
// SessionRecord — Device session entry
// ---------------------------------------------------------------------------
struct SessionRecord {
  std::string access_token_hash;
  std::string user_id;
  std::string device_id;
  std::string ip_address;
  std::string user_agent;
  int64_t created_at{0};
  int64_t expires_at{0};
  int64_t last_used_at{0};
  bool revoked{false};
  std::string scope;

  bool is_expired() const {
    return expires_at > 0 && now_ms() > expires_at;
  }

  json to_json() const {
    json j;
    j["user_id"] = user_id;
    j["device_id"] = device_id;
    j["ip_address"] = ip_address;
    j["user_agent"] = user_agent;
    j["created_at"] = created_at;
    j["expires_at"] = expires_at;
    j["last_used_at"] = last_used_at;
    j["revoked"] = revoked;
    j["scope"] = scope;
    return j;
  }
};

// ---------------------------------------------------------------------------
// OneTimeKeyCount — Per-algorithm OTK count
// ---------------------------------------------------------------------------
struct OneTimeKeyCount {
  std::string algorithm;
  std::string device_id;
  int count{0};
  int fallback_count{0};
  bool has_unused_fallback{false};
};

// ---------------------------------------------------------------------------
// DehydratedDeviceRecord — Dehydrated device data
// ---------------------------------------------------------------------------
struct DehydratedDeviceRecord {
  std::string user_id;
  std::string device_id;
  json device_data;
  json device_keys;
  std::string algorithm;
  int64_t created_at{0};
  int64_t expires_at{0};
  bool reclaimed{false};
  std::string pickle_key;
  DehydrationState state{DehydrationState::NONE};

  bool is_expired() const {
    return expires_at > 0 && now_ms() > expires_at;
  }
};

// ---------------------------------------------------------------------------
// CrossSigningKeyRecord — A cross-signing key entry
// ---------------------------------------------------------------------------
struct CrossSigningKeyRecord {
  std::string user_id;
  std::string key_type;
  json key_data;
  int64_t stream_id{0};
  bool replaced{false};

  json to_json() const {
    return {
      {"user_id", user_id},
      {"key_type", key_type},
      {"key_data", key_data},
      {"replaced", replaced}
    };
  }
};

// ---------------------------------------------------------------------------
// BootstrapState — Cross-signing bootstrap progress
// ---------------------------------------------------------------------------
struct BootstrapState {
  std::string user_id;
  std::string state;  // not_started, keys_uploaded, signed, complete, reset
  int64_t created_at{0};
  int64_t updated_at{0};
  int64_t reset_at{0};
  bool master_key_uploaded{false};
  bool self_signing_key_uploaded{false};
  bool user_signing_key_uploaded{false};
  bool master_signed_by_self{false};
  bool self_signing_signed_by_master{false};
  bool user_signing_signed_by_master{false};
  int devices_signed{0};
  int total_devices{0};

  json to_json() const {
    json j;
    j["state"] = state;
    j["created_at"] = created_at;
    j["updated_at"] = updated_at;
    j["keys"] = {
      {"master", master_key_uploaded},
      {"self_signing", self_signing_key_uploaded},
      {"user_signing", user_signing_key_uploaded}
    };
    j["signatures"] = {
      {"master_signed_by_self", master_signed_by_self},
      {"self_signing_signed_by_master", self_signing_signed_by_master},
      {"user_signing_signed_by_master", user_signing_signed_by_master}
    };
    j["device_signing"] = {
      {"devices_signed", devices_signed},
      {"total_devices", total_devices}
    };
    return j;
  }
};

// ---------------------------------------------------------------------------
// DeviceListChanges — Device list change set
// ---------------------------------------------------------------------------
struct DeviceListChanges {
  int64_t from_stream_id{0};
  int64_t to_stream_id{0};
  std::vector<std::string> changed_user_ids;
  std::vector<std::string> left_user_ids;
};

// ---------------------------------------------------------------------------
// OperationResult — Generic operation result
// ---------------------------------------------------------------------------
struct OperationResult {
  bool success{false};
  std::string error;
  std::string error_code;
  json data;

  static OperationResult ok(json d = json::object()) {
    OperationResult r;
    r.success = true;
    r.data = std::move(d);
    return r;
  }

  static OperationResult fail(std::string err, std::string code = "M_UNKNOWN") {
    OperationResult r;
    r.success = false;
    r.error = std::move(err);
    r.error_code = std::move(code);
    return r;
  }
};

// ---------------------------------------------------------------------------
// DeviceListResult — Device list query result
// ---------------------------------------------------------------------------
struct DeviceListResult {
  bool success{false};
  std::vector<DeviceRecord> devices;
  int total_count{0};
  std::string error;
  std::string error_code;

  json to_json() const {
    json j;
    j["devices"] = json::array();
    for (const auto& d : devices) {
      j["devices"].push_back(d.to_public_json());
    }
    j["total"] = total_count;
    return j;
  }
};

// ============================================================================
// SQL Schema Definitions (DDL)
// ============================================================================
namespace device_schema {

const std::string CREATE_DEVICES_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    display_name TEXT DEFAULT '',
    last_seen_ip TEXT DEFAULT '',
    last_seen_user_agent TEXT DEFAULT '',
    last_seen_ts BIGINT DEFAULT 0,
    created_at BIGINT NOT NULL,
    device_type TEXT DEFAULT '',
    hidden SMALLINT DEFAULT 0,
    access_token_hash TEXT DEFAULT '',
    verification_state SMALLINT DEFAULT 0,
    verified_at BIGINT DEFAULT 0,
    verified_by TEXT DEFAULT '',
    CONSTRAINT device_pk PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(user_id, last_seen_ts);
CREATE INDEX IF NOT EXISTS idx_devices_hidden ON devices(user_id, hidden);
CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(access_token_hash);
CREATE INDEX IF NOT EXISTS idx_devices_verification ON devices(user_id, verification_state);
)SQL";

const std::string CREATE_DEVICE_SESSIONS_TABLE = R"SQL(
CREATE TABLE IF NOT EXISTS device_sessions (
    access_token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    ip_address TEXT DEFAULT '',
    user_agent TEXT DEFAULT '',
    created_at BIGINT NOT NULL,
    expires_at BIGINT DEFAULT 0,
    last_used_at BIGINT NOT NULL,
    revoked SMALLINT DEFAULT 0,
    scope TEXT DEFAULT 'full'
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON device_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_device ON device_sessions(user_id, device_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON device_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_revoked ON device_sessions(revoked);
)SQL";

const std::string CREATE_DEVICE_LISTS_STREAM = R"SQL(
CREATE TABLE IF NOT EXISTS device_lists_stream (
    stream_id BIGINT PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_lists_stream_user
    ON device_lists_stream(user_id, stream_id);
CREATE INDEX IF NOT EXISTS idx_device_lists_stream_range
    ON device_lists_stream(stream_id);
)SQL";

const std::string CREATE_DEVICE_LISTS_OUTBOUND = R"SQL(
CREATE TABLE IF NOT EXISTS device_lists_outbound_pokes (
    destination TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    sent SMALLINT DEFAULT 0,
    ts BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_lists_outbound_dest
    ON device_lists_outbound_pokes(destination, stream_id);
CREATE INDEX IF NOT EXISTS idx_device_lists_outbound_sent
    ON device_lists_outbound_pokes(destination, sent, stream_id);
)SQL";

const std::string CREATE_DEVICE_LISTS_LAST_SUCCESS = R"SQL(
CREATE TABLE IF NOT EXISTS device_lists_outbound_last_success (
    destination TEXT PRIMARY KEY,
    stream_id BIGINT NOT NULL,
    last_success_stream_id BIGINT NOT NULL
);
)SQL";

const std::string CREATE_DEVICE_MAX_STREAM_ID = R"SQL(
CREATE TABLE IF NOT EXISTS device_max_stream_id (
    stream_id BIGINT NOT NULL DEFAULT 0
);

INSERT INTO device_max_stream_id (stream_id)
SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM device_max_stream_id);
)SQL";

const std::string CREATE_DEVICE_INBOX = R"SQL(
CREATE TABLE IF NOT EXISTS device_inbox (
    message_id BIGINT PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    content_json TEXT NOT NULL,
    received_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_inbox_user_device
    ON device_inbox(user_id, device_id, stream_id);
CREATE INDEX IF NOT EXISTS idx_device_inbox_stream
    ON device_inbox(stream_id);
)SQL";

const std::string CREATE_DEVICE_INBOX_SEQ = R"SQL(
CREATE TABLE IF NOT EXISTS device_inbox_sequence (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    min_stream_id BIGINT NOT NULL DEFAULT 0,
    max_stream_id BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT device_inbox_seq_pk PRIMARY KEY (user_id, device_id)
);
)SQL";

const std::string CREATE_E2E_DEVICE_KEYS = R"SQL(
CREATE TABLE IF NOT EXISTS e2e_device_keys_json (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    ts_added_ms BIGINT NOT NULL,
    key_json TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_e2e_device_keys
    ON e2e_device_keys_json(user_id, device_id);
)SQL";

const std::string CREATE_E2E_ONE_TIME_KEYS = R"SQL(
CREATE TABLE IF NOT EXISTS e2e_one_time_keys_json (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    key_id TEXT NOT NULL,
    ts_added_ms BIGINT NOT NULL,
    key_json TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_e2e_otk
    ON e2e_one_time_keys_json(user_id, device_id, algorithm, key_id);
CREATE INDEX IF NOT EXISTS idx_e2e_otk_count
    ON e2e_one_time_keys_json(user_id, device_id, algorithm);
)SQL";

const std::string CREATE_E2E_FALLBACK_KEYS = R"SQL(
CREATE TABLE IF NOT EXISTS e2e_fallback_keys_json (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_json TEXT NOT NULL,
    used SMALLINT DEFAULT 0,
    ts_added_ms BIGINT NOT NULL,
    ts_used_ms BIGINT DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_e2e_fallback
    ON e2e_fallback_keys_json(user_id, device_id, algorithm);
CREATE INDEX IF NOT EXISTS idx_e2e_fallback_unused
    ON e2e_fallback_keys_json(user_id, device_id, algorithm, used);
)SQL";

const std::string CREATE_E2E_CROSS_SIGNING_KEYS = R"SQL(
CREATE TABLE IF NOT EXISTS e2e_cross_signing_keys (
    user_id TEXT NOT NULL,
    key_type TEXT NOT NULL,
    key_data TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    replaced SMALLINT DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_e2e_cross_keys
    ON e2e_cross_signing_keys(user_id, key_type);
CREATE INDEX IF NOT EXISTS idx_e2e_cross_stream
    ON e2e_cross_signing_keys(stream_id);
)SQL";

const std::string CREATE_E2E_CROSS_SIGNING_SIGS = R"SQL(
CREATE TABLE IF NOT EXISTS e2e_cross_signing_signatures (
    user_id TEXT NOT NULL,
    key_type TEXT NOT NULL,
    signer_user_id TEXT NOT NULL,
    signer_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    stream_id BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_e2e_cross_sigs
    ON e2e_cross_signing_signatures(user_id, key_type);
CREATE INDEX IF NOT EXISTS idx_e2e_cross_sigs_stream
    ON e2e_cross_signing_signatures(stream_id);
)SQL";

const std::string CREATE_DEHYDRATED_DEVICES = R"SQL(
CREATE TABLE IF NOT EXISTS dehydrated_devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_data TEXT NOT NULL,
    device_keys TEXT DEFAULT '',
    algorithm TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    reclaimed SMALLINT DEFAULT 0,
    pickle_key TEXT DEFAULT '',
    CONSTRAINT dehyd_dev_pk PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_dehyd_devices_user
    ON dehydrated_devices(user_id, reclaimed, expires_at);
CREATE INDEX IF NOT EXISTS idx_dehyd_devices_expiry
    ON dehydrated_devices(expires_at) WHERE reclaimed = 0;
)SQL";

const std::string CREATE_DEHYDRATED_INBOX = R"SQL(
CREATE TABLE IF NOT EXISTS dehydrated_device_inbox (
    message_id BIGINT PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    content_json TEXT NOT NULL,
    received_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dehyd_inbox_user_device
    ON dehydrated_device_inbox(user_id, device_id);
CREATE INDEX IF NOT EXISTS idx_dehyd_inbox_received
    ON dehydrated_device_inbox(received_at);
)SQL";

const std::string CREATE_CROSS_SIGNING_BOOTSTRAP = R"SQL(
CREATE TABLE IF NOT EXISTS cross_signing_bootstrap_state (
    user_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'not_started',
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    reset_at BIGINT DEFAULT 0,
    master_key_uploaded SMALLINT DEFAULT 0,
    self_signing_key_uploaded SMALLINT DEFAULT 0,
    user_signing_key_uploaded SMALLINT DEFAULT 0,
    master_signed_by_self SMALLINT DEFAULT 0,
    self_signing_signed_by_master SMALLINT DEFAULT 0,
    user_signing_signed_by_master SMALLINT DEFAULT 0,
    devices_signed INT DEFAULT 0,
    total_devices INT DEFAULT 0,
    CONSTRAINT bootstrap_pk PRIMARY KEY (user_id)
);
)SQL";

// Aggregate all DDL
const std::string ALL_SCHEMA =
    CREATE_DEVICES_TABLE + "\n" +
    CREATE_DEVICE_SESSIONS_TABLE + "\n" +
    CREATE_DEVICE_LISTS_STREAM + "\n" +
    CREATE_DEVICE_LISTS_OUTBOUND + "\n" +
    CREATE_DEVICE_LISTS_LAST_SUCCESS + "\n" +
    CREATE_DEVICE_MAX_STREAM_ID + "\n" +
    CREATE_DEVICE_INBOX + "\n" +
    CREATE_DEVICE_INBOX_SEQ + "\n" +
    CREATE_E2E_DEVICE_KEYS + "\n" +
    CREATE_E2E_ONE_TIME_KEYS + "\n" +
    CREATE_E2E_FALLBACK_KEYS + "\n" +
    CREATE_E2E_CROSS_SIGNING_KEYS + "\n" +
    CREATE_E2E_CROSS_SIGNING_SIGS + "\n" +
    CREATE_DEHYDRATED_DEVICES + "\n" +
    CREATE_DEHYDRATED_INBOX + "\n" +
    CREATE_CROSS_SIGNING_BOOTSTRAP;

} // namespace device_schema

// ============================================================================
// 1. DeviceCRUD — Core device creation, update, and deletion
// ============================================================================

class DeviceCRUD {
public:
  explicit DeviceCRUD(storage::DatabasePool& db)
      : db_(db) {}

  // ---- Schema initialization ----
  static void create_tables(storage::LoggingTransaction& txn) {
    txn.executescript(device_schema::ALL_SCHEMA);
  }

  // ---- Device creation ----
  OperationResult create_device(
      const std::string& user_id,
      const std::string& device_id,
      const std::string& initial_display_name,
      const std::string& ip_address,
      const std::string& user_agent,
      const std::string& access_token_hash,
      const std::string& device_type) {

    if (!is_valid_user_id(user_id)) {
      return OperationResult::fail("Invalid user ID", "M_INVALID_PARAM");
    }
    if (!is_valid_device_id(device_id)) {
      return OperationResult::fail("Invalid device ID", "M_INVALID_PARAM");
    }

    OperationResult result;

    try {
      db_.runInteraction("create_device",
        [&](storage::LoggingTransaction& txn) {
          create_device_txn(txn, user_id, device_id,
                            initial_display_name, ip_address,
                            user_agent, access_token_hash,
                            device_type, result);
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  void create_device_txn(storage::LoggingTransaction& txn,
                         const std::string& user_id,
                         const std::string& device_id,
                         const std::string& initial_display_name,
                         const std::string& ip_address,
                         const std::string& user_agent,
                         const std::string& access_token_hash,
                         const std::string& device_type,
                         OperationResult& result) {

    // Check device limit
    int64_t count = count_devices_txn(txn, user_id);
    if (count >= MAX_DEVICES_PER_USER) {
      result = OperationResult::fail(
          "Maximum device count (" +
          std::to_string(MAX_DEVICES_PER_USER) + ") exceeded",
          "M_LIMIT_EXCEEDED");
      return;
    }

    int64_t now = now_ms();
    std::string display_name = initial_display_name;
    if (display_name.size() > MAX_DISPLAY_NAME_LENGTH) {
      display_name = display_name.substr(0, MAX_DISPLAY_NAME_LENGTH);
    }

    // Upsert device record
    std::string sql = R"SQL(
      INSERT INTO devices (user_id, device_id, display_name, last_seen_ip,
                           last_seen_user_agent, last_seen_ts, created_at,
                           device_type, hidden, access_token_hash,
                           verification_state, verified_at, verified_by)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
      ON CONFLICT(user_id, device_id) DO UPDATE SET
        display_name = ?3,
        last_seen_ip = ?4,
        last_seen_user_agent = ?5,
        last_seen_ts = ?6,
        device_type = ?8,
        access_token_hash = ?10
    )SQL";

    txn.execute(sql, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id},
      storage::SQLParam{display_name},
      storage::SQLParam{ip_address},
      storage::SQLParam{user_agent},
      storage::SQLParam{now},
      storage::SQLParam{now},
      storage::SQLParam{device_type},
      storage::SQLParam{0LL},
      storage::SQLParam{access_token_hash},
      storage::SQLParam{static_cast<int64_t>(DeviceVerificationStatus::UNVERIFIED)},
      storage::SQLParam{0LL},
      storage::SQLParam{std::string("")}
    });

    // Record device change for notifications
    add_device_change_txn(txn, user_id, device_id);

    result.success = true;
    result.data = {
      {"device_id", device_id},
      {"display_name", display_name},
      {"device_type", device_type},
      {"created_at", now}
    };
  }

  // ---- Device update ----
  OperationResult update_device_metadata(
      const std::string& user_id,
      const std::string& device_id,
      const std::string& new_display_name,
      const std::string& new_device_type) {

    if (new_display_name.size() > MAX_DISPLAY_NAME_LENGTH) {
      return OperationResult::fail(
          "Display name exceeds maximum length of " +
          std::to_string(MAX_DISPLAY_NAME_LENGTH), "M_INVALID_PARAM");
    }

    OperationResult result;

    try {
      db_.runInteraction("update_device_metadata",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            UPDATE devices
            SET display_name = ?1, device_type = ?2
            WHERE user_id = ?3 AND device_id = ?4
          )SQL";

          txn.execute(sql, {
            storage::SQLParam{new_display_name},
            storage::SQLParam{new_device_type},
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          if (txn.rowcount() == 0) {
            result = OperationResult::fail("Device not found", "M_NOT_FOUND");
            return;
          }

          add_device_change_txn(txn, user_id, device_id);
          result.success = true;
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Device deletion ----
  OperationResult delete_device(
      const std::string& user_id,
      const std::string& device_id) {

    OperationResult result;

    try {
      db_.runInteraction("delete_device",
        [&](storage::LoggingTransaction& txn) {
          delete_device_txn(txn, user_id, device_id, result);
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  void delete_device_txn(storage::LoggingTransaction& txn,
                         const std::string& user_id,
                         const std::string& device_id,
                         OperationResult& result) {

    // Delete the device record
    std::string del_device = R"SQL(
      DELETE FROM devices WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(del_device, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    if (txn.rowcount() == 0) {
      result = OperationResult::fail("Device not found", "M_NOT_FOUND");
      return;
    }

    // Cascade: revoke all sessions for this device
    std::string revoke_sessions = R"SQL(
      UPDATE device_sessions SET revoked = 1
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(revoke_sessions, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    // Cascade: delete E2E device keys
    std::string del_e2e = R"SQL(
      DELETE FROM e2e_device_keys_json WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(del_e2e, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    // Cascade: delete one-time keys
    std::string del_otk = R"SQL(
      DELETE FROM e2e_one_time_keys_json WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(del_otk, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    // Cascade: delete fallback keys
    std::string del_fallback = R"SQL(
      DELETE FROM e2e_fallback_keys_json WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(del_fallback, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    // Cascade: delete device inbox
    std::string del_inbox = R"SQL(
      DELETE FROM device_inbox WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(del_inbox, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    std::string del_inbox_seq = R"SQL(
      DELETE FROM device_inbox_sequence WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(del_inbox_seq, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    // Add to change stream
    add_device_change_txn(txn, user_id, device_id);

    result.success = true;
    result.data = {{"deleted", true}, {"device_id", device_id}};
  }

  // ---- Bulk device deletion ----
  OperationResult delete_all_devices(
      const std::string& user_id,
      const std::optional<std::string>& except_device_id) {

    OperationResult result;
    int deleted_count = 0;

    try {
      db_.runInteraction("delete_all_devices",
        [&](storage::LoggingTransaction& txn) {
          // Get all device IDs for user
          std::vector<std::string> device_ids;
          std::string sel = "SELECT device_id FROM devices WHERE user_id = ?1";
          txn.execute(sel, {storage::SQLParam{user_id}});

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value) {
              std::string did = *row[0].value;
              if (!except_device_id || did != *except_device_id) {
                device_ids.push_back(did);
              }
            }
          }

          // Delete each device with cascade
          for (const auto& did : device_ids) {
            OperationResult r;
            delete_device_txn(txn, user_id, did, r);
            if (r.success) deleted_count++;
          }

          // Revoke sessions for non-excepted devices
          if (except_device_id) {
            std::string revoke = R"SQL(
              UPDATE device_sessions SET revoked = 1
              WHERE user_id = ?1 AND device_id != ?2
            )SQL";
            txn.execute(revoke, {
              storage::SQLParam{user_id},
              storage::SQLParam{*except_device_id}
            });
          } else {
            std::string revoke = R"SQL(
              UPDATE device_sessions SET revoked = 1
              WHERE user_id = ?1
            )SQL";
            txn.execute(revoke, {storage::SQLParam{user_id}});
          }

          result.success = true;
          result.data = {
            {"deleted_devices", deleted_count},
            {"user_id", user_id}
          };
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Device hiding (soft-delete) ----
  OperationResult hide_device(const std::string& user_id,
                              const std::string& device_id) {
    OperationResult result;

    try {
      db_.runInteraction("hide_device",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            UPDATE devices SET hidden = 1
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          if (txn.rowcount() == 0) {
            result = OperationResult::fail("Device not found", "M_NOT_FOUND");
          } else {
            add_device_change_txn(txn, user_id, device_id);
            result.success = true;
          }
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Device unhiding ----
  OperationResult unhide_device(const std::string& user_id,
                                const std::string& device_id) {
    OperationResult result;

    try {
      db_.runInteraction("unhide_device",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            UPDATE devices SET hidden = 0
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          if (txn.rowcount() == 0) {
            result = OperationResult::fail("Device not found", "M_NOT_FOUND");
          } else {
            add_device_change_txn(txn, user_id, device_id);
            result.success = true;
          }
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Device fetch ----
  std::optional<DeviceRecord> get_device(const std::string& user_id,
                                         const std::string& device_id) {
    std::optional<DeviceRecord> result;

    try {
      db_.runInteraction("get_device",
        [&](storage::LoggingTransaction& txn) {
          result = get_device_txn(txn, user_id, device_id);
        });
    } catch (const std::exception&) {}

    return result;
  }

  std::optional<DeviceRecord> get_device_txn(storage::LoggingTransaction& txn,
                                             const std::string& user_id,
                                             const std::string& device_id) {
    std::string sql = R"SQL(
      SELECT user_id, device_id, display_name, last_seen_ip,
             last_seen_user_agent, last_seen_ts, created_at,
             device_type, hidden, access_token_hash,
             verification_state, verified_at, verified_by
      FROM devices
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";

    txn.execute(sql, {storage::SQLParam{user_id}, storage::SQLParam{device_id}});

    Row row;
    if (txn.iter_next(row) && !row.empty()) {
      return parse_device_row(row);
    }
    return std::nullopt;
  }

  // ---- Get all devices for user ----
  std::vector<DeviceRecord> get_user_devices(const std::string& user_id,
                                              bool include_hidden = false) {
    std::vector<DeviceRecord> devices;

    try {
      db_.runInteraction("get_user_devices",
        [&](storage::LoggingTransaction& txn) {
          std::string sql;
          if (include_hidden) {
            sql = R"SQL(
              SELECT user_id, device_id, display_name, last_seen_ip,
                     last_seen_user_agent, last_seen_ts, created_at,
                     device_type, hidden, access_token_hash,
                     verification_state, verified_at, verified_by
              FROM devices
              WHERE user_id = ?1
              ORDER BY last_seen_ts DESC
            )SQL";
          } else {
            sql = R"SQL(
              SELECT user_id, device_id, display_name, last_seen_ip,
                     last_seen_user_agent, last_seen_ts, created_at,
                     device_type, hidden, access_token_hash,
                     verification_state, verified_at, verified_by
              FROM devices
              WHERE user_id = ?1 AND hidden = 0
              ORDER BY last_seen_ts DESC
            )SQL";
          }

          txn.execute(sql, {storage::SQLParam{user_id}});

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty()) {
              auto d = parse_device_row(row);
              if (d.has_value()) devices.push_back(*d);
            }
          }
        });
    } catch (const std::exception&) {}

    return devices;
  }

  // ---- Device count ----
  int64_t count_devices(const std::string& user_id) {
    int64_t count = 0;

    try {
      db_.runInteraction("count_devices",
        [&](storage::LoggingTransaction& txn) {
          count = count_devices_txn(txn, user_id);
        });
    } catch (const std::exception&) {}

    return count;
  }

  int64_t count_devices_txn(storage::LoggingTransaction& txn,
                             const std::string& user_id) {
    std::string sql = "SELECT COUNT(*) FROM devices WHERE user_id = ?1 AND hidden = 0";
    txn.execute(sql, {storage::SQLParam{user_id}});

    Row row;
    if (txn.iter_next(row) && !row.empty() && row[0].value) {
      return std::stoll(*row[0].value);
    }
    return 0;
  }

  // ---- Lookup device by token hash ----
  std::optional<DeviceRecord> get_device_by_token(const std::string& token_hash) {
    std::optional<DeviceRecord> result;

    try {
      db_.runInteraction("get_device_by_token",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT user_id, device_id, display_name, last_seen_ip,
                   last_seen_user_agent, last_seen_ts, created_at,
                   device_type, hidden, access_token_hash,
                   verification_state, verified_at, verified_by
            FROM devices
            WHERE access_token_hash = ?1 AND hidden = 0
          )SQL";
          txn.execute(sql, {storage::SQLParam{token_hash}});

          Row row;
          if (txn.iter_next(row) && !row.empty()) {
            result = parse_device_row(row);
          }
        });
    } catch (const std::exception&) {}

    return result;
  }

  // ---- Track device activity ----
  void track_activity(const std::string& user_id,
                      const std::string& device_id,
                      const std::string& ip_address,
                      const std::string& user_agent) {
    try {
      db_.runInteraction("track_activity",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();

          std::string dev_sql = R"SQL(
            UPDATE devices
            SET last_seen_ip = ?1,
                last_seen_user_agent = ?2,
                last_seen_ts = ?3
            WHERE user_id = ?4 AND device_id = ?5
          )SQL";

          txn.execute(dev_sql, {
            storage::SQLParam{ip_address},
            storage::SQLParam{user_agent},
            storage::SQLParam{now},
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          std::string sess_sql = R"SQL(
            UPDATE device_sessions
            SET last_used_at = ?1, ip_address = ?2, user_agent = ?3
            WHERE user_id = ?4 AND device_id = ?5 AND revoked = 0
          )SQL";

          txn.execute(sess_sql, {
            storage::SQLParam{now},
            storage::SQLParam{ip_address},
            storage::SQLParam{user_agent},
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });
        });
    } catch (const std::exception&) {}
  }

  // ---- Device change stream ----
  int64_t add_device_change_txn(storage::LoggingTransaction& txn,
                                 const std::string& user_id,
                                 const std::string& device_id) {
    int64_t stream_id = next_stream_id_txn(txn);

    std::string sql = R"SQL(
      INSERT INTO device_lists_stream (stream_id, user_id, device_id)
      VALUES (?1, ?2, ?3)
    )SQL";

    txn.execute(sql, {
      storage::SQLParam{stream_id},
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    return stream_id;
  }

  int64_t next_stream_id_txn(storage::LoggingTransaction& txn) {
    std::string update_sql =
        "UPDATE device_max_stream_id SET stream_id = stream_id + 1";
    txn.execute(update_sql);

    std::string sel_sql = "SELECT stream_id FROM device_max_stream_id";
    txn.execute(sel_sql);

    Row row;
    if (txn.iter_next(row) && !row.empty() && row[0].value) {
      return std::stoll(*row[0].value);
    }
    return 1;
  }

  int64_t get_max_stream_id() {
    int64_t sid = 0;
    try {
      db_.runInteraction("get_max_stream_id",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = "SELECT stream_id FROM device_max_stream_id";
          txn.execute(sql);
          Row row;
          if (txn.iter_next(row) && !row.empty() && row[0].value) {
            sid = std::stoll(*row[0].value);
          }
        });
    } catch (const std::exception&) {}
    return sid;
  }

  // ---- Get stale devices ----
  std::vector<DeviceRecord> get_stale_devices(int64_t stale_threshold_ms) {
    std::vector<DeviceRecord> devices;

    try {
      db_.runInteraction("get_stale_devices",
        [&](storage::LoggingTransaction& txn) {
          int64_t threshold = now_ms() - stale_threshold_ms;

          std::string sql = R"SQL(
            SELECT user_id, device_id, display_name, last_seen_ip,
                   last_seen_user_agent, last_seen_ts, created_at,
                   device_type, hidden, access_token_hash,
                   verification_state, verified_at, verified_by
            FROM devices
            WHERE last_seen_ts < ?1 AND last_seen_ts > 0 AND hidden = 0
            ORDER BY last_seen_ts ASC
          )SQL";

          txn.execute(sql, {storage::SQLParam{threshold}});

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty()) {
              auto d = parse_device_row(row);
              if (d.has_value()) devices.push_back(*d);
            }
          }
        });
    } catch (const std::exception&) {}

    return devices;
  }

  // ---- Delete all E2E keys for a user ----
  void delete_e2e_keys_for_user(const std::string& user_id) {
    try {
      db_.runInteraction("delete_e2e_keys_for_user",
        [&](storage::LoggingTransaction& txn) {
          std::vector<std::string> tables = {
            TBL_E2E_DEVICE_KEYS,
            TBL_E2E_ONE_TIME_KEYS,
            TBL_E2E_FALLBACK_KEYS,
            TBL_E2E_CROSS_SIGNING_KEYS,
            TBL_E2E_CROSS_SIGNING_SIGS
          };
          for (const auto& tbl : tables) {
            txn.execute("DELETE FROM " + tbl + " WHERE user_id = ?1",
                       {storage::SQLParam{user_id}});
          }
        });
    } catch (const std::exception&) {}
  }

private:
  std::optional<DeviceRecord> parse_device_row(const Row& row) {
    DeviceRecord d;
    if (row.size() < 13) return std::nullopt;

    d.user_id = row[0].value.value_or("");
    d.device_id = row[1].value.value_or("");
    d.display_name = row[2].value.value_or("");
    d.last_seen_ip = row[3].value.value_or("");
    d.last_seen_user_agent = row[4].value.value_or("");
    d.last_seen_ts = row[5].value ? std::stoll(*row[5].value) : 0;
    d.created_at = row[6].value ? std::stoll(*row[6].value) : 0;
    d.device_type = row[7].value.value_or("");
    d.hidden = row[8].value && *row[8].value == "1";
    d.access_token_hash = row[9].value.value_or("");
    if (row[10].value) {
      d.verification_status = static_cast<DeviceVerificationStatus>(
          std::stoi(*row[10].value));
    }
    d.verified_at = row[11].value ? std::stoll(*row[11].value) : 0;
    d.verified_by = row[12].value.value_or("");
    return d;
  }

  storage::DatabasePool& db_;
};

// ============================================================================
// 2. DeviceDisplayNameManager — Display name operations
// ============================================================================

class DeviceDisplayNameManager {
public:
  explicit DeviceDisplayNameManager(storage::DatabasePool& db,
                                    DeviceCRUD* crud = nullptr)
      : db_(db), crud_(crud) {}

  // ---- Set display name ----
  OperationResult set_display_name(const std::string& user_id,
                                   const std::string& device_id,
                                   const std::string& display_name) {

    if (display_name.size() > MAX_DISPLAY_NAME_LENGTH) {
      return OperationResult::fail(
          "Display name too long (max " +
          std::to_string(MAX_DISPLAY_NAME_LENGTH) + " chars)",
          "M_INVALID_PARAM");
    }

    // Sanitize: strip leading/trailing whitespace
    std::string sanitized = display_name;
    while (!sanitized.empty() && std::isspace(sanitized.front())) {
      sanitized.erase(0, 1);
    }
    while (!sanitized.empty() && std::isspace(sanitized.back())) {
      sanitized.pop_back();
    }

    OperationResult result;

    try {
      db_.runInteraction("set_display_name",
        [&](storage::LoggingTransaction& txn) {
          // Verify device exists
          std::string check_sql = R"SQL(
            SELECT 1 FROM devices WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(check_sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          Row row;
          if (!txn.iter_next(row)) {
            result = OperationResult::fail("Device not found", "M_NOT_FOUND");
            return;
          }

          std::string update_sql = R"SQL(
            UPDATE devices SET display_name = ?1
            WHERE user_id = ?2 AND device_id = ?3
          )SQL";

          txn.execute(update_sql, {
            storage::SQLParam{sanitized},
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          // Add change notification
          if (crud_) {
            crud_->add_device_change_txn(txn, user_id, device_id);
          }

          result.success = true;
          result.data = {
            {"device_id", device_id},
            {"display_name", sanitized}
          };
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Get display name ----
  OperationResult get_display_name(const std::string& user_id,
                                   const std::string& device_id) {
    OperationResult result;

    try {
      db_.runInteraction("get_display_name",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT display_name FROM devices
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          Row row;
          if (txn.iter_next(row) && !row.empty()) {
            result.success = true;
            result.data = {
              {"device_id", device_id},
              {"display_name", row[0].value.value_or("")}
            };
          } else {
            result = OperationResult::fail("Device not found", "M_NOT_FOUND");
          }
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Clear display name ----
  OperationResult clear_display_name(const std::string& user_id,
                                     const std::string& device_id) {
    return set_display_name(user_id, device_id, "");
  }

private:
  storage::DatabasePool& db_;
  DeviceCRUD* crud_;
};

// ============================================================================
// 3. DeviceListAPI — Device listing and querying
// ============================================================================

class DeviceListAPI {
public:
  explicit DeviceListAPI(storage::DatabasePool& db, DeviceCRUD* crud = nullptr)
      : db_(db), crud_(crud) {}

  // ---- List all user devices ----
  DeviceListResult list_user_devices(const std::string& user_id,
                                      const std::string& current_token) {
    DeviceListResult result;

    if (!is_valid_user_id(user_id)) {
      result.error = "Invalid user ID";
      result.error_code = "M_INVALID_PARAM";
      return result;
    }

    // Find current device
    std::string current_device_id;
    if (!current_token.empty()) {
      std::string token_hash = sha256_hash(current_token);
      auto session = get_session_by_token(token_hash);
      if (session.has_value()) {
        current_device_id = session->device_id;
      }
    }

    auto devices = crud_ ? crud_->get_user_devices(user_id)
                         : get_user_devices_direct(user_id);

    for (const auto& d : devices) {
      DeviceRecord info = d;
      result.devices.push_back(info);
    }

    result.total_count = static_cast<int>(result.devices.size());
    result.success = true;
    return result;
  }

  // ---- Get single device details ----
  DeviceListResult get_device_detail(const std::string& user_id,
                                      const std::string& device_id) {
    DeviceListResult result;

    auto dev = crud_ ? crud_->get_device(user_id, device_id)
                     : get_device_direct(user_id, device_id);

    if (!dev.has_value()) {
      result.error = "Device not found";
      result.error_code = "M_NOT_FOUND";
      return result;
    }

    result.devices.push_back(*dev);
    result.total_count = 1;
    result.success = true;
    return result;
  }

  // ---- Get devices filtered by verification status ----
  DeviceListResult list_devices_by_verification(
      const std::string& user_id,
      DeviceVerificationStatus status) {

    DeviceListResult result;

    try {
      db_.runInteraction("list_devices_by_verification",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT user_id, device_id, display_name, last_seen_ip,
                   last_seen_user_agent, last_seen_ts, created_at,
                   device_type, hidden, access_token_hash,
                   verification_state, verified_at, verified_by
            FROM devices
            WHERE user_id = ?1 AND verification_state = ?2 AND hidden = 0
            ORDER BY last_seen_ts DESC
          )SQL";

          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{static_cast<int64_t>(status)}
          });

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty()) {
              DeviceRecord d;
              d.user_id = row[0].value.value_or("");
              d.device_id = row[1].value.value_or("");
              d.display_name = row[2].value.value_or("");
              d.last_seen_ip = row[3].value.value_or("");
              d.last_seen_user_agent = row[4].value.value_or("");
              d.last_seen_ts = row[5].value ? std::stoll(*row[5].value) : 0;
              d.created_at = row[6].value ? std::stoll(*row[6].value) : 0;
              d.device_type = row[7].value.value_or("");
              result.devices.push_back(d);
            }
          }

          result.total_count = static_cast<int>(result.devices.size());
          result.success = true;
        });
    } catch (const std::exception& e) {
      result.error = std::string("Database error: ") + e.what();
      result.error_code = "M_UNKNOWN";
    }

    return result;
  }

  // ---- Get device changes for sync ----
  DeviceListChanges get_device_changes(int64_t from_stream_id,
                                        int64_t to_stream_id) {
    DeviceListChanges changes;
    changes.from_stream_id = from_stream_id;
    changes.to_stream_id = to_stream_id;

    try {
      db_.runInteraction("get_device_changes",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT DISTINCT user_id
            FROM device_lists_stream
            WHERE stream_id > ?1 AND stream_id <= ?2
            ORDER BY stream_id ASC
          )SQL";

          txn.execute(sql, {
            storage::SQLParam{from_stream_id},
            storage::SQLParam{to_stream_id}
          });

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value) {
              changes.changed_user_ids.push_back(*row[0].value);
            }
          }
        });
    } catch (const std::exception&) {}

    return changes;
  }

  // ---- Get max device stream ID ----
  int64_t get_max_stream_id() {
    if (crud_) {
      return crud_->get_max_stream_id();
    }
    int64_t sid = 0;
    try {
      db_.runInteraction("get_max_stream_id",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = "SELECT stream_id FROM device_max_stream_id";
          txn.execute(sql);
          Row row;
          if (txn.iter_next(row) && !row.empty() && row[0].value) {
            sid = std::stoll(*row[0].value);
          }
        });
    } catch (const std::exception&) {}
    return sid;
  }

private:
  std::optional<SessionRecord> get_session_by_token(const std::string& token_hash) {
    std::optional<SessionRecord> result;
    try {
      db_.runInteraction("get_session_by_token",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT access_token_hash, user_id, device_id,
                   ip_address, user_agent, created_at,
                   expires_at, last_used_at, revoked, scope
            FROM device_sessions
            WHERE access_token_hash = ?1 AND revoked = 0
          )SQL";
          txn.execute(sql, {storage::SQLParam{token_hash}});

          Row row;
          if (txn.iter_next(row) && !row.empty()) {
            SessionRecord s;
            s.access_token_hash = row[0].value.value_or("");
            s.user_id = row[1].value.value_or("");
            s.device_id = row[2].value.value_or("");
            s.ip_address = row[3].value.value_or("");
            s.user_agent = row[4].value.value_or("");
            s.created_at = row[5].value ? std::stoll(*row[5].value) : 0;
            s.expires_at = row[6].value ? std::stoll(*row[6].value) : 0;
            s.last_used_at = row[7].value ? std::stoll(*row[7].value) : 0;
            s.revoked = row[8].value && *row[8].value == "1";
            s.scope = row[9].value.value_or("full");
            result = s;
          }
        });
    } catch (const std::exception&) {}
    return result;
  }

  std::vector<DeviceRecord> get_user_devices_direct(const std::string& user_id) {
    std::vector<DeviceRecord> devices;
    try {
      db_.runInteraction("get_user_devices_direct",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT user_id, device_id, display_name, last_seen_ip,
                   last_seen_user_agent, last_seen_ts, created_at,
                   device_type, hidden, access_token_hash,
                   verification_state, verified_at, verified_by
            FROM devices
            WHERE user_id = ?1 AND hidden = 0
            ORDER BY last_seen_ts DESC
          )SQL";
          txn.execute(sql, {storage::SQLParam{user_id}});

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty()) {
              DeviceRecord d;
              d.user_id = row[0].value.value_or("");
              d.device_id = row[1].value.value_or("");
              d.display_name = row[2].value.value_or("");
              d.last_seen_ip = row[3].value.value_or("");
              d.last_seen_user_agent = row[4].value.value_or("");
              d.last_seen_ts = row[5].value ? std::stoll(*row[5].value) : 0;
              d.created_at = row[6].value ? std::stoll(*row[6].value) : 0;
              d.device_type = row[7].value.value_or("");
              devices.push_back(d);
            }
          }
        });
    } catch (const std::exception&) {}
    return devices;
  }

  std::optional<DeviceRecord> get_device_direct(const std::string& user_id,
                                                 const std::string& device_id) {
    std::optional<DeviceRecord> result;
    try {
      db_.runInteraction("get_device_direct",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT user_id, device_id, display_name, last_seen_ip,
                   last_seen_user_agent, last_seen_ts, created_at,
                   device_type, hidden, access_token_hash,
                   verification_state, verified_at, verified_by
            FROM devices
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          Row row;
          if (txn.iter_next(row) && !row.empty()) {
            DeviceRecord d;
            d.user_id = row[0].value.value_or("");
            d.device_id = row[1].value.value_or("");
            d.display_name = row[2].value.value_or("");
            d.last_seen_ip = row[3].value.value_or("");
            d.last_seen_user_agent = row[4].value.value_or("");
            d.last_seen_ts = row[5].value ? std::stoll(*row[5].value) : 0;
            d.created_at = row[6].value ? std::stoll(*row[6].value) : 0;
            d.device_type = row[7].value.value_or("");
            result = d;
          }
        });
    } catch (const std::exception&) {}
    return result;
  }

  storage::DatabasePool& db_;
  DeviceCRUD* crud_;
};

// ============================================================================
// 4. DeviceVerificationTracker — Verification status management
// ============================================================================

class DeviceVerificationTracker {
public:
  explicit DeviceVerificationTracker(storage::DatabasePool& db)
      : db_(db) {}

  // ---- Set verification state ----
  OperationResult set_verification_state(
      const std::string& user_id,
      const std::string& device_id,
      DeviceVerificationStatus new_state,
      const std::string& verified_by_user = "") {

    OperationResult result;

    try {
      db_.runInteraction("set_verification_state",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();

          std::string sql = R"SQL(
            UPDATE devices
            SET verification_state = ?1,
                verified_at = ?2,
                verified_by = ?3
            WHERE user_id = ?4 AND device_id = ?5
          )SQL";

          txn.execute(sql, {
            storage::SQLParam{static_cast<int64_t>(new_state)},
            storage::SQLParam{now},
            storage::SQLParam{verified_by_user},
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          if (txn.rowcount() == 0) {
            result = OperationResult::fail("Device not found", "M_NOT_FOUND");
            return;
          }

          result.success = true;
          result.data = {
            {"device_id", device_id},
            {"verification_state", static_cast<int>(new_state)},
            {"verified_at", now}
          };
          if (!verified_by_user.empty()) {
            result.data["verified_by"] = verified_by_user;
          }
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Mark device as verified ----
  OperationResult mark_verified(const std::string& user_id,
                                const std::string& device_id,
                                const std::string& verified_by) {
    return set_verification_state(user_id, device_id,
        DeviceVerificationStatus::VERIFIED, verified_by);
  }

  // ---- Mark device as cross-signed ----
  OperationResult mark_cross_signed(const std::string& user_id,
                                    const std::string& device_id) {
    return set_verification_state(user_id, device_id,
        DeviceVerificationStatus::CROSS_SIGNED);
  }

  // ---- Block a device ----
  OperationResult block_device(const std::string& user_id,
                               const std::string& device_id) {
    return set_verification_state(user_id, device_id,
        DeviceVerificationStatus::BLOCKED);
  }

  // ---- Unblock a device ----
  OperationResult unblock_device(const std::string& user_id,
                                 const std::string& device_id) {
    return set_verification_state(user_id, device_id,
        DeviceVerificationStatus::UNVERIFIED);
  }

  // ---- Get verification state ----
  std::optional<DeviceVerificationStatus> get_verification(
      const std::string& user_id,
      const std::string& device_id) {

    std::optional<DeviceVerificationStatus> result;

    try {
      db_.runInteraction("get_verification",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT verification_state FROM devices
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          Row row;
          if (txn.iter_next(row) && !row.empty() && row[0].value) {
            result = static_cast<DeviceVerificationStatus>(
                std::stoi(*row[0].value));
          }
        });
    } catch (const std::exception&) {}

    return result;
  }

  // ---- Count devices by verification state ----
  std::map<DeviceVerificationStatus, int> count_by_verification(
      const std::string& user_id) {

    std::map<DeviceVerificationStatus, int> counts;

    try {
      db_.runInteraction("count_by_verification",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT verification_state, COUNT(*)
            FROM devices
            WHERE user_id = ?1 AND hidden = 0
            GROUP BY verification_state
          )SQL";
          txn.execute(sql, {storage::SQLParam{user_id}});

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value && row[1].value) {
              auto state = static_cast<DeviceVerificationStatus>(
                  std::stoi(*row[0].value));
              counts[state] = std::stoi(*row[1].value);
            }
          }
        });
    } catch (const std::exception&) {}

    return counts;
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 5. DeviceSessionManager — Session creation, lookup, revocation
// ============================================================================

class DeviceSessionManager {
public:
  explicit DeviceSessionManager(storage::DatabasePool& db)
      : db_(db) {}

  // ---- Create session ----
  OperationResult create_session(
      const std::string& access_token,
      const std::string& user_id,
      const std::string& device_id,
      const std::string& ip_address,
      const std::string& user_agent,
      int64_t expires_at_ms = SESSION_DEFAULT_EXPIRY_MS) {

    std::string token_hash = sha256_hash(access_token);

    OperationResult result;

    try {
      db_.runInteraction("create_session",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();
          int64_t expires = (expires_at_ms > 0)
              ? now + expires_at_ms
              : 0;

          if (expires_at_ms > SESSION_MAX_EXPIRY_MS) {
            expires = now + SESSION_MAX_EXPIRY_MS;
          }

          std::string sql = R"SQL(
            INSERT INTO device_sessions
              (access_token_hash, user_id, device_id, ip_address,
               user_agent, created_at, expires_at, last_used_at,
               revoked, scope)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 'full')
          )SQL";

          txn.execute(sql, {
            storage::SQLParam{token_hash},
            storage::SQLParam{user_id},
            storage::SQLParam{device_id},
            storage::SQLParam{ip_address},
            storage::SQLParam{user_agent},
            storage::SQLParam{now},
            storage::SQLParam{expires},
            storage::SQLParam{now}
          });

          result.success = true;
          result.data = {
            {"token_hash", token_hash},
            {"user_id", user_id},
            {"device_id", device_id},
            {"expires_at", expires}
          };
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Lookup session by token ----
  std::optional<SessionRecord> lookup_session(const std::string& access_token) {
    std::string token_hash = sha256_hash(access_token);
    return lookup_session_by_hash(token_hash);
  }

  std::optional<SessionRecord> lookup_session_by_hash(
      const std::string& token_hash) {

    std::optional<SessionRecord> result;

    try {
      db_.runInteraction("lookup_session",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT access_token_hash, user_id, device_id,
                   ip_address, user_agent, created_at,
                   expires_at, last_used_at, revoked, scope
            FROM device_sessions
            WHERE access_token_hash = ?1
          )SQL";
          txn.execute(sql, {storage::SQLParam{token_hash}});

          Row row;
          if (txn.iter_next(row) && !row.empty()) {
            SessionRecord s;
            s.access_token_hash = row[0].value.value_or("");
            s.user_id = row[1].value.value_or("");
            s.device_id = row[2].value.value_or("");
            s.ip_address = row[3].value.value_or("");
            s.user_agent = row[4].value.value_or("");
            s.created_at = row[5].value ? std::stoll(*row[5].value) : 0;
            s.expires_at = row[6].value ? std::stoll(*row[6].value) : 0;
            s.last_used_at = row[7].value ? std::stoll(*row[7].value) : 0;
            s.revoked = row[8].value && *row[8].value == "1";
            s.scope = row[9].value.value_or("full");
            result = s;
          }
        });
    } catch (const std::exception&) {}

    return result;
  }

  // ---- Verify token validity ----
  std::optional<SessionRecord> verify_token(const std::string& access_token) {
    auto session = lookup_session(access_token);
    if (!session.has_value()) return std::nullopt;
    if (session->revoked) return std::nullopt;
    if (session->is_expired()) {
      revoke_session_by_hash(session->access_token_hash);
      return std::nullopt;
    }
    return session;
  }

  // ---- Revoke session ----
  OperationResult revoke_session(const std::string& access_token) {
    std::string token_hash = sha256_hash(access_token);
    return revoke_session_by_hash(token_hash);
  }

  OperationResult revoke_session_by_hash(const std::string& token_hash) {
    OperationResult result;

    try {
      db_.runInteraction("revoke_session",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            UPDATE device_sessions SET revoked = 1
            WHERE access_token_hash = ?1
          )SQL";
          txn.execute(sql, {storage::SQLParam{token_hash}});

          result.success = (txn.rowcount() > 0);
          if (!result.success) {
            result.error = "Session not found";
            result.error_code = "M_UNKNOWN_TOKEN";
          }
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Revoke all sessions for a device ----
  OperationResult revoke_device_sessions(const std::string& user_id,
                                         const std::string& device_id) {
    OperationResult result;

    try {
      db_.runInteraction("revoke_device_sessions",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            UPDATE device_sessions SET revoked = 1
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          result.success = true;
          result.data = {
            {"user_id", user_id},
            {"device_id", device_id},
            {"revoked", txn.rowcount()}
          };
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Revoke all sessions for a user ----
  OperationResult revoke_all_user_sessions(const std::string& user_id,
      const std::optional<std::string>& except_device_id = std::nullopt) {

    OperationResult result;

    try {
      db_.runInteraction("revoke_all_user_sessions",
        [&](storage::LoggingTransaction& txn) {
          if (except_device_id) {
            std::string sql = R"SQL(
              UPDATE device_sessions SET revoked = 1
              WHERE user_id = ?1 AND device_id != ?2
            )SQL";
            txn.execute(sql, {
              storage::SQLParam{user_id},
              storage::SQLParam{*except_device_id}
            });
          } else {
            std::string sql = R"SQL(
              UPDATE device_sessions SET revoked = 1
              WHERE user_id = ?1
            )SQL";
            txn.execute(sql, {storage::SQLParam{user_id}});
          }

          result.success = true;
          result.data = {
            {"user_id", user_id},
            {"sessions_revoked", txn.rowcount()}
          };
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- List user sessions ----
  std::vector<SessionRecord> list_user_sessions(const std::string& user_id,
                                                 bool include_revoked = false) {
    std::vector<SessionRecord> sessions;

    try {
      db_.runInteraction("list_user_sessions",
        [&](storage::LoggingTransaction& txn) {
          std::string sql;
          if (include_revoked) {
            sql = R"SQL(
              SELECT access_token_hash, user_id, device_id,
                     ip_address, user_agent, created_at,
                     expires_at, last_used_at, revoked, scope
              FROM device_sessions
              WHERE user_id = ?1
              ORDER BY last_used_at DESC
            )SQL";
          } else {
            sql = R"SQL(
              SELECT access_token_hash, user_id, device_id,
                     ip_address, user_agent, created_at,
                     expires_at, last_used_at, revoked, scope
              FROM device_sessions
              WHERE user_id = ?1 AND revoked = 0
              ORDER BY last_used_at DESC
            )SQL";
          }

          txn.execute(sql, {storage::SQLParam{user_id}});

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty()) {
              SessionRecord s;
              s.access_token_hash = row[0].value.value_or("");
              s.user_id = row[1].value.value_or("");
              s.device_id = row[2].value.value_or("");
              s.ip_address = row[3].value.value_or("");
              s.user_agent = row[4].value.value_or("");
              s.created_at = row[5].value ? std::stoll(*row[5].value) : 0;
              s.expires_at = row[6].value ? std::stoll(*row[6].value) : 0;
              s.last_used_at = row[7].value ? std::stoll(*row[7].value) : 0;
              s.revoked = row[8].value && *row[8].value == "1";
              s.scope = row[9].value.value_or("full");
              sessions.push_back(s);
            }
          }
        });
    } catch (const std::exception&) {}

    return sessions;
  }

  // ---- Cleanup expired sessions ----
  int cleanup_expired_sessions() {
    int cleaned = 0;

    try {
      db_.runInteraction("cleanup_expired_sessions",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();

          std::string sql = R"SQL(
            UPDATE device_sessions SET revoked = 1
            WHERE expires_at > 0 AND expires_at < ?1 AND revoked = 0
          )SQL";
          txn.execute(sql, {storage::SQLParam{now}});
          cleaned = txn.rowcount();
        });
    } catch (const std::exception&) {}

    return cleaned;
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 6. OneTimeKeyCounter — OTK count and availability
// ============================================================================

class OneTimeKeyCounter {
public:
  explicit OneTimeKeyCounter(storage::DatabasePool& db)
      : db_(db) {}

  // ---- Count OTKs for a device by algorithm ----
  std::vector<OneTimeKeyCount> count_for_device(
      const std::string& user_id,
      const std::string& device_id) {

    std::vector<OneTimeKeyCount> counts;

    try {
      db_.runInteraction("count_otk_for_device",
        [&](storage::LoggingTransaction& txn) {
          // Count non-claimed OTKs grouped by algorithm
          std::string otk_sql = R"SQL(
            SELECT algorithm, COUNT(*) as cnt
            FROM e2e_one_time_keys_json
            WHERE user_id = ?1 AND device_id = ?2
            GROUP BY algorithm
          )SQL";

          txn.execute(otk_sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          std::map<std::string, int> otk_map;
          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value && row[1].value) {
              otk_map[*row[0].value] = std::stoi(*row[1].value);
            }
          }

          // Count unused fallbacks by algorithm
          std::string fb_sql = R"SQL(
            SELECT algorithm, COUNT(*) as cnt
            FROM e2e_fallback_keys_json
            WHERE user_id = ?1 AND device_id = ?2 AND used = 0
            GROUP BY algorithm
          )SQL";

          txn.execute(fb_sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          std::map<std::string, int> fb_map;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value && row[1].value) {
              fb_map[*row[0].value] = std::stoi(*row[1].value);
            }
          }

          // Merge
          std::set<std::string> all_algos;
          for (const auto& [algo, _] : otk_map) all_algos.insert(algo);
          for (const auto& [algo, _] : fb_map) all_algos.insert(algo);

          for (const auto& algo : all_algos) {
            OneTimeKeyCount c;
            c.algorithm = algo;
            c.device_id = device_id;
            c.count = otk_map.count(algo) ? otk_map[algo] : 0;
            c.fallback_count = fb_map.count(algo) ? fb_map[algo] : 0;
            c.has_unused_fallback = c.fallback_count > 0;
            counts.push_back(c);
          }
        });
    } catch (const std::exception&) {}

    return counts;
  }

  // ---- Count total OTKs for a device ----
  int count_all_for_device(const std::string& user_id,
                           const std::string& device_id) {
    int total = 0;

    try {
      db_.runInteraction("count_all_otk",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT COUNT(*) FROM e2e_one_time_keys_json
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          Row row;
          if (txn.iter_next(row) && !row.empty() && row[0].value) {
            total = std::stoi(*row[0].value);
          }
        });
    } catch (const std::exception&) {}

    return total;
  }

  // ---- Bulk count OTKs for multiple users (federation) ----
  std::map<std::string,
           std::map<std::string,
                    std::map<std::string, int>>>
  count_bulk(const std::set<std::string>& user_ids) {

    std::map<std::string,
             std::map<std::string,
                      std::map<std::string, int>>> result;

    if (user_ids.empty()) return result;

    try {
      db_.runInteraction("count_otk_bulk",
        [&](storage::LoggingTransaction& txn) {
          std::string in_list;
          for (const auto& uid : user_ids) {
            if (!in_list.empty()) in_list += ",";
            in_list += sql_quote(uid);
          }

          std::string sql =
              "SELECT user_id, device_id, algorithm, COUNT(*) "
              "FROM e2e_one_time_keys_json "
              "WHERE user_id IN (" + in_list + ") "
              "GROUP BY user_id, device_id, algorithm";

          txn.execute(sql);

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value && row[1].value &&
                row[2].value && row[3].value) {
              result[*row[0].value][*row[1].value][*row[2].value] =
                  std::stoi(*row[3].value);
            }
          }
        });
    } catch (const std::exception&) {}

    return result;
  }

  // ---- Get minimum count across all devices for a user ----
  std::map<std::string, int> min_otk_counts(const std::string& user_id) {
    std::map<std::string, int> mins;

    try {
      db_.runInteraction("min_otk_counts",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT algorithm, device_id, COUNT(*) as cnt
            FROM e2e_one_time_keys_json
            WHERE user_id = ?1
            GROUP BY algorithm, device_id
          )SQL";
          txn.execute(sql, {storage::SQLParam{user_id}});

          std::map<std::string, std::vector<int>> algo_counts;
          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value && row[2].value) {
              algo_counts[*row[0].value].push_back(std::stoi(*row[2].value));
            }
          }

          for (auto& [algo, counts] : algo_counts) {
            if (!counts.empty()) {
              mins[algo] = *std::min_element(counts.begin(), counts.end());
            }
          }
        });
    } catch (const std::exception&) {}

    return mins;
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 7. DeviceDehydrationManager — Dehydrated device lifecycle
// ============================================================================

class DeviceDehydrationManager {
public:
  explicit DeviceDehydrationManager(storage::DatabasePool& db)
      : db_(db) {}

  // ---- Create dehydrated device ----
  OperationResult dehydrate_device(
      const std::string& user_id,
      const json& device_data,
      const json& device_keys,
      int64_t expiry_ms = DEHYDRATED_EXPIRY_MS) {

    int64_t expiry = std::max(DEHYDRATED_MIN_EXPIRY_MS,
                     std::min(expiry_ms, DEHYDRATED_MAX_EXPIRY_MS));

    std::string device_id = std::string(DEHYDRATED_DEVICE_PREFIX) +
                            random_hex_string(16);

    OperationResult result;

    try {
      db_.runInteraction("dehydrate_device",
        [&](storage::LoggingTransaction& txn) {
          // Check existing count
          std::string count_sql = R"SQL(
            SELECT COUNT(*) FROM dehydrated_devices
            WHERE user_id = ?1 AND reclaimed = 0
          )SQL";
          txn.execute(count_sql, {storage::SQLParam{user_id}});

          Row row;
          int existing = 0;
          if (txn.iter_next(row) && !row.empty() && row[0].value) {
            existing = std::stoi(*row[0].value);
          }

          if (existing >= MAX_DEHYDRATED_DEVICES) {
            // Delete existing device to make room
            std::string del_existing = R"SQL(
              DELETE FROM dehydrated_devices
              WHERE user_id = ?1 AND reclaimed = 0
            )SQL";
            txn.execute(del_existing, {storage::SQLParam{user_id}});

            std::string del_inbox = R"SQL(
              DELETE FROM dehydrated_device_inbox
              WHERE user_id = ?1
            )SQL";
            txn.execute(del_inbox, {storage::SQLParam{user_id}});
          }

          int64_t now = now_ms();
          std::string pickle_key = random_hex_string(64);

          std::string insert_sql = R"SQL(
            INSERT INTO dehydrated_devices
              (user_id, device_id, device_data, device_keys,
               algorithm, created_at, expires_at, reclaimed, pickle_key)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)
          )SQL";

          txn.execute(insert_sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id},
            storage::SQLParam{device_data.dump()},
            storage::SQLParam{device_keys.dump()},
            storage::SQLParam{std::string(DEHYDRATION_ALGORITHM)},
            storage::SQLParam{now},
            storage::SQLParam{now + expiry},
            storage::SQLParam{pickle_key}
          });

          result.success = true;
          result.data = {
            {"device_id", device_id},
            {"algorithm", DEHYDRATION_ALGORITHM},
            {"expires_at", now + expiry},
            {"expires_in_ms", expiry},
            {"pickle_key", pickle_key}
          };
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Get dehydrated device ----
  OperationResult get_dehydrated_device(const std::string& user_id) {
    OperationResult result;

    try {
      db_.runInteraction("get_dehydrated_device",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT user_id, device_id, device_data, device_keys,
                   algorithm, created_at, expires_at, reclaimed, pickle_key
            FROM dehydrated_devices
            WHERE user_id = ?1 AND reclaimed = 0
            ORDER BY created_at DESC
            LIMIT 1
          )SQL";
          txn.execute(sql, {storage::SQLParam{user_id}});

          Row row;
          if (txn.iter_next(row) && !row.empty()) {
            DehydratedDeviceRecord dd;
            dd.user_id = row[0].value.value_or("");
            dd.device_id = row[1].value.value_or("");
            if (row[2].value) {
              try { dd.device_data = json::parse(*row[2].value); } catch (...) {}
            }
            if (row[3].value) {
              try { dd.device_keys = json::parse(*row[3].value); } catch (...) {}
            }
            dd.algorithm = row[4].value.value_or("");
            dd.created_at = row[5].value ? std::stoll(*row[5].value) : 0;
            dd.expires_at = row[6].value ? std::stoll(*row[6].value) : 0;
            dd.reclaimed = row[7].value && *row[7].value == "1";
            dd.pickle_key = row[8].value.value_or("");

            if (dd.is_expired()) {
              dd.state = DehydrationState::EXPIRED;
            } else {
              dd.state = dd.reclaimed
                  ? DehydrationState::RECLAIMED
                  : DehydrationState::ACTIVE;
            }

            result.success = true;
            result.data = {
              {"device_id", dd.device_id},
              {"device_data", dd.device_data},
              {"device_keys", dd.device_keys},
              {"algorithm", dd.algorithm},
              {"created_at", dd.created_at},
              {"expires_at", dd.expires_at},
              {"state", static_cast<int>(dd.state)},
              {"pickle_key", dd.pickle_key}
            };
          } else {
            result = OperationResult::fail(
                "No dehydrated device found", "M_NOT_FOUND");
          }
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Check if dehydrated device exists ----
  bool has_dehydrated_device(const std::string& user_id) {
    bool found = false;
    try {
      db_.runInteraction("has_dehydrated_device",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();
          std::string sql = R"SQL(
            SELECT 1 FROM dehydrated_devices
            WHERE user_id = ?1 AND reclaimed = 0 AND expires_at > ?2
            LIMIT 1
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{now}
          });
          Row row;
          found = txn.iter_next(row);
        });
    } catch (const std::exception&) {}
    return found;
  }

  // ---- Rehydrate (reclaim) device ----
  OperationResult rehydrate_device(const std::string& user_id,
                                   const std::string& device_id) {
    OperationResult result;

    try {
      db_.runInteraction("rehydrate_device",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            UPDATE dehydrated_devices SET reclaimed = 1
            WHERE user_id = ?1 AND device_id = ?2 AND reclaimed = 0
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          if (txn.rowcount() == 0) {
            result = OperationResult::fail(
                "Dehydrated device not found or already reclaimed",
                "M_NOT_FOUND");
            return;
          }

          result.success = true;
          result.data = {
            {"device_id", device_id},
            {"rehydrated", true}
          };
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Delete dehydrated device ----
  OperationResult delete_dehydrated_device(const std::string& user_id,
                                           const std::string& device_id) {
    OperationResult result;

    try {
      db_.runInteraction("delete_dehydrated_device",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            DELETE FROM dehydrated_devices
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          if (txn.rowcount() == 0) {
            result = OperationResult::fail(
                "Dehydrated device not found", "M_NOT_FOUND");
            return;
          }

          // Clean inbox
          std::string inbox_sql = R"SQL(
            DELETE FROM dehydrated_device_inbox
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(inbox_sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          result.success = true;
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Queue to-device message for dehydrated device ----
  OperationResult queue_message(const std::string& user_id,
                                const std::string& device_id,
                                const json& content) {
    OperationResult result;

    try {
      db_.runInteraction("queue_dehydrated_message",
        [&](storage::LoggingTransaction& txn) {
          // Check queue size
          std::string count_sql = R"SQL(
            SELECT COUNT(*) FROM dehydrated_device_inbox
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(count_sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          Row row;
          int count = 0;
          if (txn.iter_next(row) && !row.empty() && row[0].value) {
            count = std::stoi(*row[0].value);
          }

          // Enforce limit
          if (count >= MAX_DEHYDRATED_QUEUED_MSGS) {
            int to_delete = count - MAX_DEHYDRATED_QUEUED_MSGS + 1;
            std::string del_sql = R"SQL(
              DELETE FROM dehydrated_device_inbox
              WHERE message_id IN (
                SELECT message_id FROM dehydrated_device_inbox
                WHERE user_id = ?1 AND device_id = ?2
                ORDER BY received_at ASC
                LIMIT ?3
              )
            )SQL";
            txn.execute(del_sql, {
              storage::SQLParam{user_id},
              storage::SQLParam{device_id},
              storage::SQLParam{static_cast<int64_t>(to_delete)}
            });
          }

          // Insert message
          int64_t now = now_ms();
          std::string insert_sql = R"SQL(
            INSERT INTO dehydrated_device_inbox
              (user_id, device_id, content_json, received_at)
            VALUES (?1, ?2, ?3, ?4)
          )SQL";
          txn.execute(insert_sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id},
            storage::SQLParam{content.dump()},
            storage::SQLParam{now}
          });

          result.success = true;
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Get queued messages for dehydrated device ----
  std::vector<json> get_queued_messages(const std::string& user_id,
                                         const std::string& device_id) {
    std::vector<json> messages;

    try {
      db_.runInteraction("get_dehydrated_messages",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT content_json FROM dehydrated_device_inbox
            WHERE user_id = ?1 AND device_id = ?2
            ORDER BY received_at ASC
            LIMIT 100
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value) {
              try {
                messages.push_back(json::parse(*row[0].value));
              } catch (...) {}
            }
          }

          // Delete retrieved messages
          std::string del_sql = R"SQL(
            DELETE FROM dehydrated_device_inbox
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";
          txn.execute(del_sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });
        });
    } catch (const std::exception&) {}

    return messages;
  }

  // ---- Cleanup expired dehydrated devices ----
  int cleanup_expired() {
    int cleaned = 0;

    try {
      db_.runInteraction("cleanup_dehydrated",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();

          // Find expired devices
          std::string sel_sql = R"SQL(
            SELECT user_id, device_id FROM dehydrated_devices
            WHERE reclaimed = 0 AND expires_at < ?1
          )SQL";
          txn.execute(sel_sql, {storage::SQLParam{now}});

          std::vector<std::pair<std::string, std::string>> expired;
          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value && row[1].value) {
              expired.push_back({*row[0].value, *row[1].value});
            }
          }

          for (const auto& [uid, did] : expired) {
            std::string del_dev = R"SQL(
              DELETE FROM dehydrated_devices
              WHERE user_id = ?1 AND device_id = ?2
            )SQL";
            txn.execute(del_dev, {
              storage::SQLParam{uid},
              storage::SQLParam{did}
            });

            std::string del_inbox = R"SQL(
              DELETE FROM dehydrated_device_inbox
              WHERE user_id = ?1 AND device_id = ?2
            )SQL";
            txn.execute(del_inbox, {
              storage::SQLParam{uid},
              storage::SQLParam{did}
            });

            cleaned++;
          }
        });
    } catch (const std::exception&) {}

    return cleaned;
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 8. CrossSigningBootstrap — Cross-signing key bootstrap and management
// ============================================================================

class CrossSigningBootstrap {
public:
  explicit CrossSigningBootstrap(storage::DatabasePool& db,
                                  DeviceCRUD* crud = nullptr)
      : db_(db), crud_(crud) {}

  // ---- Upload a cross-signing key ----
  OperationResult upload_cross_signing_key(
      const std::string& user_id,
      const std::string& key_type,
      const json& key_data) {

    if (key_type != KEY_TYPE_MASTER &&
        key_type != KEY_TYPE_SELF_SIGNING &&
        key_type != KEY_TYPE_USER_SIGNING) {
      return OperationResult::fail(
          "Invalid key type. Must be master, self_signing, or user_signing",
          "M_INVALID_PARAM");
    }

    OperationResult result;

    try {
      db_.runInteraction("upload_cross_signing_key",
        [&](storage::LoggingTransaction& txn) {
          int64_t stream_id = crud_
              ? crud_->next_stream_id_txn(txn)
              : 1;

          std::string sql = R"SQL(
            INSERT INTO e2e_cross_signing_keys
              (user_id, key_type, key_data, stream_id, replaced)
            VALUES (?1, ?2, ?3, ?4, 0)
            ON CONFLICT(user_id, key_type) DO UPDATE SET
              key_data = ?3,
              stream_id = ?4,
              replaced = 1
          )SQL";

          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{key_type},
            storage::SQLParam{key_data.dump()},
            storage::SQLParam{stream_id}
          });

          // Update bootstrap state
          update_bootstrap_state_txn(txn, user_id, key_type);

          result.success = true;
          result.data = {
            {"user_id", user_id},
            {"key_type", key_type},
            {"uploaded", true}
          };
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Database error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Bootstrap all three cross-signing keys at once ----
  OperationResult bootstrap_cross_signing(
      const std::string& user_id,
      const json& master_key,
      const json& self_signing_key,
      const json& user_signing_key,
      const std::map<std::string, std::string>& signatures) {

    OperationResult result;

    try {
      db_.runInteraction("bootstrap_cross_signing",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();

          // 1. Upload master key
          upload_key_txn(txn, user_id, KEY_TYPE_MASTER, master_key);

          // 2. Upload self-signing key
          upload_key_txn(txn, user_id, KEY_TYPE_SELF_SIGNING,
                         self_signing_key);

          // 3. Upload user-signing key
          upload_key_txn(txn, user_id, KEY_TYPE_USER_SIGNING,
                         user_signing_key);

          // 4. Store signatures
          if (!signatures.empty()) {
            for (const auto& [key_type, signature] : signatures) {
              store_signature_txn(txn, user_id, key_type,
                                  user_id, key_type, signature);
            }
          }

          // 5. Update bootstrap state to complete
          std::string bs_sql = R"SQL(
            INSERT INTO cross_signing_bootstrap_state
              (user_id, state, created_at, updated_at,
               master_key_uploaded, self_signing_key_uploaded,
               user_signing_key_uploaded,
               master_signed_by_self, self_signing_signed_by_master,
               user_signing_signed_by_master)
            VALUES (?1, ?2, ?3, ?4, 1, 1, 1, 1, 1, 1)
            ON CONFLICT(user_id) DO UPDATE SET
              state = ?2,
              updated_at = ?4,
              master_key_uploaded = 1,
              self_signing_key_uploaded = 1,
              user_signing_key_uploaded = 1,
              master_signed_by_self = 1,
              self_signing_signed_by_master = 1,
              user_signing_signed_by_master = 1
          )SQL";

          txn.execute(bs_sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{std::string(BOOTSTRAP_COMPLETE)},
            storage::SQLParam{now},
            storage::SQLParam{now}
          });

          result.success = true;
          result.data = {
            {"user_id", user_id},
            {"state", BOOTSTRAP_COMPLETE},
            {"bootstrap_complete", true}
          };
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Bootstrap error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Get cross-signing keys ----
  json get_cross_signing_keys(const std::string& user_id) {
    json result;

    try {
      db_.runInteraction("get_cross_signing_keys",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT key_type, key_data
            FROM e2e_cross_signing_keys
            WHERE user_id = ?1
          )SQL";
          txn.execute(sql, {storage::SQLParam{user_id}});

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value && row[1].value) {
              try {
                result[*row[0].value] = json::parse(*row[1].value);
              } catch (...) {}
            }
          }
        });
    } catch (const std::exception&) {}

    return result;
  }

  // ---- Get bootstrap state ----
  std::optional<BootstrapState> get_bootstrap_state(
      const std::string& user_id) {

    std::optional<BootstrapState> result;

    try {
      db_.runInteraction("get_bootstrap_state",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT user_id, state, created_at, updated_at, reset_at,
                   master_key_uploaded, self_signing_key_uploaded,
                   user_signing_key_uploaded,
                   master_signed_by_self, self_signing_signed_by_master,
                   user_signing_signed_by_master,
                   devices_signed, total_devices
            FROM cross_signing_bootstrap_state
            WHERE user_id = ?1
          )SQL";
          txn.execute(sql, {storage::SQLParam{user_id}});

          Row row;
          if (txn.iter_next(row) && !row.empty()) {
            BootstrapState bs;
            bs.user_id = row[0].value.value_or("");
            bs.state = row[1].value.value_or(BOOTSTRAP_NOT_STARTED);
            bs.created_at = row[2].value ? std::stoll(*row[2].value) : 0;
            bs.updated_at = row[3].value ? std::stoll(*row[3].value) : 0;
            bs.reset_at = row[4].value ? std::stoll(*row[4].value) : 0;
            bs.master_key_uploaded = row[5].value && *row[5].value == "1";
            bs.self_signing_key_uploaded = row[6].value && *row[6].value == "1";
            bs.user_signing_key_uploaded = row[7].value && *row[7].value == "1";
            bs.master_signed_by_self = row[8].value && *row[8].value == "1";
            bs.self_signing_signed_by_master = row[9].value && *row[9].value == "1";
            bs.user_signing_signed_by_master = row[10].value && *row[10].value == "1";
            bs.devices_signed = row[11].value ? std::stoi(*row[11].value) : 0;
            bs.total_devices = row[12].value ? std::stoi(*row[12].value) : 0;
            result = bs;
          }
        });
    } catch (const std::exception&) {}

    return result;
  }

  // ---- Check if bootstrapping is complete ----
  bool is_bootstrap_complete(const std::string& user_id) {
    auto state = get_bootstrap_state(user_id);
    return state.has_value() && state->state == BOOTSTRAP_COMPLETE;
  }

  // ---- Reset cross-signing (initiate re-bootstrap) ----
  OperationResult reset_cross_signing(const std::string& user_id) {
    OperationResult result;

    try {
      db_.runInteraction("reset_cross_signing",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();

          // Delete existing keys
          std::string del_keys = R"SQL(
            DELETE FROM e2e_cross_signing_keys WHERE user_id = ?1
          )SQL";
          txn.execute(del_keys, {storage::SQLParam{user_id}});

          // Delete existing signatures
          std::string del_sigs = R"SQL(
            DELETE FROM e2e_cross_signing_signatures WHERE user_id = ?1
          )SQL";
          txn.execute(del_sigs, {storage::SQLParam{user_id}});

          // Update bootstrap state
          std::string bs_sql = R"SQL(
            INSERT INTO cross_signing_bootstrap_state
              (user_id, state, created_at, updated_at, reset_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT(user_id) DO UPDATE SET
              state = ?2,
              updated_at = ?4,
              reset_at = ?5,
              master_key_uploaded = 0,
              self_signing_key_uploaded = 0,
              user_signing_key_uploaded = 0,
              master_signed_by_self = 0,
              self_signing_signed_by_master = 0,
              user_signing_signed_by_master = 0,
              devices_signed = 0,
              total_devices = 0
          )SQL";

          txn.execute(bs_sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{std::string(BOOTSTRAP_RESET)},
            storage::SQLParam{now},
            storage::SQLParam{now},
            storage::SQLParam{now}
          });

          result.success = true;
          result.data = {
            {"user_id", user_id},
            {"state", BOOTSTRAP_RESET},
            {"reset", true}
          };
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Reset error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Sign a device with self-signing key ----
  OperationResult sign_device(const std::string& user_id,
                              const std::string& device_id,
                              const std::string& signature) {

    OperationResult result;

    try {
      db_.runInteraction("sign_device",
        [&](storage::LoggingTransaction& txn) {
          int64_t stream_id = crud_
              ? crud_->next_stream_id_txn(txn)
              : 1;

          // Store signature (self_signing key signing the device)
          std::string sql = R"SQL(
            INSERT OR REPLACE INTO e2e_cross_signing_signatures
              (user_id, key_type, signer_user_id, signer_key,
               signature, stream_id)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
          )SQL";

          std::string signer_key = user_id + ":" + device_id;

          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{std::string(KEY_TYPE_SELF_SIGNING)},
            storage::SQLParam{user_id},
            storage::SQLParam{signer_key},
            storage::SQLParam{signature},
            storage::SQLParam{stream_id}
          });

          // Mark device as cross-signed
          std::string ver_sql = R"SQL(
            UPDATE devices
            SET verification_state = ?1, verified_at = ?2
            WHERE user_id = ?3 AND device_id = ?4
          )SQL";

          txn.execute(ver_sql, {
            storage::SQLParam{static_cast<int64_t>(
                DeviceVerificationStatus::CROSS_SIGNED)},
            storage::SQLParam{now_ms()},
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          // Update bootstrap device count
          std::string bs_sql = R"SQL(
            UPDATE cross_signing_bootstrap_state
            SET devices_signed = devices_signed + 1, updated_at = ?1
            WHERE user_id = ?2
          )SQL";
          txn.execute(bs_sql, {
            storage::SQLParam{now_ms()},
            storage::SQLParam{user_id}
          });

          result.success = true;
          result.data = {
            {"device_id", device_id},
            {"signed", true},
            {"verification_state",
             static_cast<int>(DeviceVerificationStatus::CROSS_SIGNED)}
          };
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Sign device error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Store signatures for a key ----
  OperationResult store_signatures(
      const std::string& user_id,
      const std::map<std::string,
                     std::map<std::string, std::string>>& sigs_by_key_type) {

    OperationResult result;

    try {
      db_.runInteraction("store_signatures",
        [&](storage::LoggingTransaction& txn) {
          int sig_count = 0;

          for (const auto& [key_type, sig_map] : sigs_by_key_type) {
            for (const auto& [signer_key, signature] : sig_map) {
              if (sig_count >= MAX_SIGNATURES_PER_REQUEST) break;

              std::string signer_user_id = signer_key;
              auto colon = signer_key.find(':');
              if (colon != std::string::npos) {
                signer_user_id = signer_key.substr(0, colon);
              }

              store_signature_txn(txn, user_id, key_type,
                                  signer_user_id, signer_key, signature);
              sig_count++;
            }
          }

          result.success = true;
          result.data = {{"signatures_stored", sig_count}};
        });
    } catch (const std::exception& e) {
      return OperationResult::fail(
          std::string("Store signatures error: ") + e.what(), "M_UNKNOWN");
    }

    return result;
  }

  // ---- Get device keys (for key query) ----
  json get_device_keys(const std::string& user_id,
                        const std::vector<std::string>& device_ids) {
    json result;

    try {
      db_.runInteraction("get_device_keys",
        [&](storage::LoggingTransaction& txn) {
          std::string sql;

          if (device_ids.empty()) {
            sql = R"SQL(
              SELECT user_id, device_id, key_json
              FROM e2e_device_keys_json
              WHERE user_id = ?1
            )SQL";
          } else {
            std::string in_list;
            for (size_t i = 0; i < device_ids.size(); ++i) {
              if (i > 0) in_list += ", ";
              in_list += "?" + std::to_string(i + 2);
            }
            sql = "SELECT user_id, device_id, key_json "
                  "FROM e2e_device_keys_json "
                  "WHERE user_id = ?1 AND device_id IN (" + in_list + ")";
          }

          std::vector<storage::SQLParam> params;
          params.push_back(storage::SQLParam{user_id});
          for (const auto& did : device_ids) {
            params.push_back(storage::SQLParam{did});
          }

          txn.execute(sql, params);

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[1].value && row[2].value) {
              try {
                json key_data = json::parse(*row[2].value);
                result[*row[0].value][*row[1].value] = key_data;
              } catch (...) {}
            }
          }
        });
    } catch (const std::exception&) {}

    return result;
  }

private:
  void upload_key_txn(storage::LoggingTransaction& txn,
                      const std::string& user_id,
                      const std::string& key_type,
                      const json& key_data) {
    int64_t stream_id = crud_
        ? crud_->next_stream_id_txn(txn)
        : 1;

    std::string sql = R"SQL(
      INSERT INTO e2e_cross_signing_keys
        (user_id, key_type, key_data, stream_id, replaced)
      VALUES (?1, ?2, ?3, ?4, 0)
      ON CONFLICT(user_id, key_type) DO UPDATE SET
        key_data = ?3,
        stream_id = ?4,
        replaced = 1
    )SQL";

    txn.execute(sql, {
      storage::SQLParam{user_id},
      storage::SQLParam{key_type},
      storage::SQLParam{key_data.dump()},
      storage::SQLParam{stream_id}
    });
  }

  void store_signature_txn(storage::LoggingTransaction& txn,
                           const std::string& user_id,
                           const std::string& key_type,
                           const std::string& signer_user_id,
                           const std::string& signer_key,
                           const std::string& signature) {
    int64_t stream_id = crud_
        ? crud_->next_stream_id_txn(txn)
        : 1;

    std::string sql = R"SQL(
      INSERT OR REPLACE INTO e2e_cross_signing_signatures
        (user_id, key_type, signer_user_id, signer_key,
         signature, stream_id)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6)
    )SQL";

    txn.execute(sql, {
      storage::SQLParam{user_id},
      storage::SQLParam{key_type},
      storage::SQLParam{signer_user_id},
      storage::SQLParam{signer_key},
      storage::SQLParam{signature},
      storage::SQLParam{stream_id}
    });
  }

  void update_bootstrap_state_txn(storage::LoggingTransaction& txn,
                                  const std::string& user_id,
                                  const std::string& key_type) {
    int64_t now = now_ms();

    std::string check_sql = R"SQL(
      SELECT state, master_key_uploaded, self_signing_key_uploaded,
             user_signing_key_uploaded
      FROM cross_signing_bootstrap_state
      WHERE user_id = ?1
    )SQL";
    txn.execute(check_sql, {storage::SQLParam{user_id}});

    bool master_ok = (key_type == KEY_TYPE_MASTER);
    bool self_ok = (key_type == KEY_TYPE_SELF_SIGNING);
    bool user_ok = (key_type == KEY_TYPE_USER_SIGNING);

    Row row;
    if (txn.iter_next(row) && !row.empty()) {
      if (row[1].value && *row[1].value == "1") master_ok = true;
      if (row[2].value && *row[2].value == "1") self_ok = true;
      if (row[3].value && *row[3].value == "1") user_ok = true;
    }

    std::string new_state = BOOTSTRAP_NOT_STARTED;
    if (master_ok && self_ok && user_ok) {
      new_state = BOOTSTRAP_KEY_UPLOADED;
    } else if (master_ok) {
      new_state = BOOTSTRAP_NOT_STARTED;
    }

    std::string upsert_sql = R"SQL(
      INSERT INTO cross_signing_bootstrap_state
        (user_id, state, created_at, updated_at,
         master_key_uploaded, self_signing_key_uploaded,
         user_signing_key_uploaded)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
      ON CONFLICT(user_id) DO UPDATE SET
        state = ?2,
        updated_at = ?4,
        master_key_uploaded = ?5,
        self_signing_key_uploaded = ?6,
        user_signing_key_uploaded = ?7
    )SQL";

    txn.execute(upsert_sql, {
      storage::SQLParam{user_id},
      storage::SQLParam{new_state},
      storage::SQLParam{now},
      storage::SQLParam{now},
      storage::SQLParam{master_ok ? 1LL : 0LL},
      storage::SQLParam{self_ok ? 1LL : 0LL},
      storage::SQLParam{user_ok ? 1LL : 0LL}
    });
  }

  storage::DatabasePool& db_;
  DeviceCRUD* crud_;
};

// ============================================================================
// 9. DeviceChangeStream — Device list change notifications
// ============================================================================

class DeviceChangeStream {
public:
  explicit DeviceChangeStream(storage::DatabasePool& db)
      : db_(db) {}

  // ---- Get changes for /sync ----
  std::map<std::string, std::vector<std::string>>
  get_changes_for_sync(int64_t from_token, int64_t to_token) {
    std::map<std::string, std::vector<std::string>> result;

    try {
      db_.runInteraction("get_changes_for_sync",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT DISTINCT user_id
            FROM device_lists_stream
            WHERE stream_id > ?1 AND stream_id <= ?2
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{from_token},
            storage::SQLParam{to_token}
          });

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value) {
              result[*row[0].value] = {};
            }
          }
        });
    } catch (const std::exception&) {}

    return result;
  }

  // ---- Get pending pokes for federation ----
  std::vector<std::tuple<int64_t, std::string, std::string>>
  get_pending_pokes(const std::string& destination, int limit = 100) {
    std::vector<std::tuple<int64_t, std::string, std::string>> entries;

    try {
      db_.runInteraction("get_pending_pokes",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT stream_id, user_id, device_id
            FROM device_lists_outbound_pokes
            WHERE destination = ?1 AND sent = 0
            ORDER BY stream_id ASC
            LIMIT ?2
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{destination},
            storage::SQLParam{static_cast<int64_t>(limit)}
          });

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value) {
              entries.push_back({
                row[0].value ? std::stoll(*row[0].value) : 0LL,
                row[1].value.value_or(""),
                row[2].value.value_or("")
              });
            }
          }
        });
    } catch (const std::exception&) {}

    return entries;
  }

  // ---- Mark pokes as sent ----
  void mark_pokes_sent(const std::string& destination,
                       const std::set<std::string>& user_ids) {
    try {
      db_.runInteraction("mark_pokes_sent",
        [&](storage::LoggingTransaction& txn) {
          for (const auto& uid : user_ids) {
            std::string sql = R"SQL(
              UPDATE device_lists_outbound_pokes
              SET sent = 1
              WHERE destination = ?1 AND user_id = ?2
            )SQL";
            txn.execute(sql, {
              storage::SQLParam{destination},
              storage::SQLParam{uid}
            });
          }
        });
    } catch (const std::exception&) {}
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 10. DeviceInboxService — To-device message delivery
// ============================================================================

class DeviceInboxService {
public:
  explicit DeviceInboxService(storage::DatabasePool& db)
      : db_(db) {}

  // ---- Add to-device messages ----
  void add_messages(const std::string& user_id,
                    const std::string& message_id,
                    const std::map<std::string,
                                   std::map<std::string, json>>& messages) {

    try {
      db_.runInteraction("add_to_device_messages",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();

          for (const auto& [device_id, msg_map] : messages) {
            // Get next stream ID
            int64_t stream_id = next_inbox_stream_id(txn, user_id, device_id);

            for (const auto& [msg_type, content] : msg_map) {
              json full_content;
              full_content["type"] = msg_type;
              full_content["content"] = content;

              std::string sql = R"SQL(
                INSERT INTO device_inbox
                  (user_id, device_id, stream_id, content_json, received_at)
                VALUES (?1, ?2, ?3, ?4, ?5)
              )SQL";
              txn.execute(sql, {
                storage::SQLParam{user_id},
                storage::SQLParam{device_id},
                storage::SQLParam{stream_id},
                storage::SQLParam{full_content.dump()},
                storage::SQLParam{now}
              });
            }

            // Enforce message limit
            enforce_inbox_limit(txn, user_id, device_id);
          }
        });
    } catch (const std::exception&) {}
  }

  // ---- Get to-device messages since a token ----
  std::vector<json> get_messages(const std::string& user_id,
                                  const std::string& device_id,
                                  int64_t since_stream_id,
                                  int limit = 100) {
    std::vector<json> messages;

    try {
      db_.runInteraction("get_to_device_messages",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT message_id, stream_id, content_json, received_at
            FROM device_inbox
            WHERE user_id = ?1 AND device_id = ?2
              AND stream_id > ?3
            ORDER BY stream_id ASC
            LIMIT ?4
          )SQL";
          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id},
            storage::SQLParam{since_stream_id},
            storage::SQLParam{static_cast<int64_t>(limit)}
          });

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[2].value) {
              try {
                json entry;
                entry["message_id"] = row[0].value
                    ? std::stoll(*row[0].value) : 0LL;
                entry["stream_id"] = row[1].value
                    ? std::stoll(*row[1].value) : 0LL;
                entry["content"] = json::parse(*row[2].value);
                entry["received_at"] = row[3].value
                    ? std::stoll(*row[3].value) : 0LL;
                messages.push_back(entry);
              } catch (...) {}
            }
          }
        });
    } catch (const std::exception&) {}

    return messages;
  }

private:
  int64_t next_inbox_stream_id(storage::LoggingTransaction& txn,
                                const std::string& user_id,
                                const std::string& device_id) {
    std::string sql = R"SQL(
      INSERT INTO device_inbox_sequence (user_id, device_id, min_stream_id, max_stream_id)
      VALUES (?1, ?2, 0, 1)
      ON CONFLICT(user_id, device_id) DO UPDATE SET
        max_stream_id = max_stream_id + 1
    )SQL";
    txn.execute(sql, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    std::string sel = R"SQL(
      SELECT max_stream_id FROM device_inbox_sequence
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(sel, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    Row row;
    if (txn.iter_next(row) && !row.empty() && row[0].value) {
      return std::stoll(*row[0].value);
    }
    return 1;
  }

  void enforce_inbox_limit(storage::LoggingTransaction& txn,
                            const std::string& user_id,
                            const std::string& device_id) {
    std::string count_sql = R"SQL(
      SELECT COUNT(*) FROM device_inbox
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(count_sql, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    Row row;
    int count = 0;
    if (txn.iter_next(row) && !row.empty() && row[0].value) {
      count = std::stoi(*row[0].value);
    }

    if (count > MAX_DEVICE_INBOX_MESSAGES) {
      std::string del_sql = R"SQL(
        DELETE FROM device_inbox
        WHERE user_id = ?1 AND device_id = ?2
          AND message_id NOT IN (
            SELECT message_id FROM device_inbox
            WHERE user_id = ?1 AND device_id = ?2
            ORDER BY stream_id DESC
            LIMIT ?3
          )
      )SQL";
      txn.execute(del_sql, {
        storage::SQLParam{user_id},
        storage::SQLParam{device_id},
        storage::SQLParam{static_cast<int64_t>(MAX_DEVICE_INBOX_MESSAGES)}
      });
    }
  }

  storage::DatabasePool& db_;
};

// ============================================================================
// 11. DeviceManagement — Top-level orchestrator
// ============================================================================

class DeviceManagement {
public:
  // ---- Public result types ----
  struct DeviceInfo {
    std::string device_id;
    std::string display_name;
    std::string last_seen_ip;
    std::string last_seen_user_agent;
    int64_t last_seen_ts{0};
    int64_t created_at{0};
    std::string device_type;
    bool is_current{false};
    DeviceVerificationStatus verification_status{
        DeviceVerificationStatus::UNVERIFIED};
    int64_t verified_at{0};
    std::string verified_by;

    json to_json() const {
      json j;
      j["device_id"] = device_id;
      if (!display_name.empty()) j["display_name"] = display_name;
      if (!last_seen_ip.empty()) j["last_seen_ip"] = last_seen_ip;
      if (!last_seen_user_agent.empty()) j["last_seen_user_agent"] = last_seen_user_agent;
      j["last_seen_ts"] = last_seen_ts;
      j["created_at"] = created_at;
      if (!device_type.empty()) j["device_type"] = device_type;
      j["verification_status"] = static_cast<int>(verification_status);
      if (verified_at > 0) j["verified_at"] = verified_at;
      if (!verified_by.empty()) j["verified_by"] = verified_by;
      return j;
    }
  };

  struct DeviceListResponse {
    bool success{false};
    std::vector<DeviceInfo> devices;
    int total_count{0};
    std::string error;
    std::string error_code;

    json to_json() const {
      json j;
      j["devices"] = json::array();
      for (const auto& d : devices) {
        j["devices"].push_back(d.to_json());
      }
      j["total"] = total_count;
      if (!error.empty()) j["error"] = error;
      return j;
    }
  };

  // ---- Constructor ----
  DeviceManagement(storage::DatabasePool& db,
                   const std::string& server_name)
      : db_(db),
        server_name_(server_name),
        crud_(db),
        display_name_mgr_(db, &crud_),
        list_api_(db, &crud_),
        verification_tracker_(db),
        session_mgr_(db),
        otk_counter_(db),
        dehydration_mgr_(db),
        cross_signing_bootstrap_(db, &crud_),
        change_stream_(db),
        inbox_service_(db) {}

  // ---- Schema initialization ----
  static void initialize_schema(storage::LoggingTransaction& txn) {
    DeviceCRUD::create_tables(txn);
  }

  // ---- Device registration ----
  DeviceListResponse register_device(
      const std::string& user_id,
      const std::string& device_id,
      const std::string& initial_display_name,
      const std::string& ip_address,
      const std::string& user_agent,
      const std::string& device_type) {

    DeviceListResponse response;

    // Generate or validate device ID
    std::string effective_device_id = device_id;
    if (effective_device_id.empty()) {
      effective_device_id = generate_device_id();
    }

    if (!is_valid_device_id(effective_device_id)) {
      response.error = "Invalid device ID format";
      response.error_code = "M_INVALID_PARAM";
      return response;
    }

    // Generate access token
    std::string access_token = generate_access_token();
    std::string token_hash = sha256_hash(access_token);

    // Create device record
    auto create_result = crud_.create_device(
        user_id, effective_device_id, initial_display_name,
        ip_address, user_agent, token_hash, device_type);

    if (!create_result.success) {
      response.error = create_result.error;
      response.error_code = create_result.error_code;
      return response;
    }

    // Create session
    session_mgr_.create_session(
        access_token, user_id, effective_device_id,
        ip_address, user_agent, SESSION_DEFAULT_EXPIRY_MS);

    // Return device info
    DeviceInfo info;
    info.device_id = effective_device_id;
    info.display_name = initial_display_name;
    info.last_seen_ip = ip_address;
    info.last_seen_user_agent = user_agent;
    info.last_seen_ts = now_ms();
    info.created_at = now_ms();
    info.device_type = device_type;
    info.is_current = true;

    response.devices.push_back(info);
    response.total_count = 1;
    response.success = true;

    return response;
  }

  // ---- List devices ----
  DeviceListResponse list_devices(const std::string& user_id,
                                   const std::string& current_token) {
    DeviceListResponse response;

    if (!is_valid_user_id(user_id)) {
      response.error = "Invalid user ID";
      response.error_code = "M_INVALID_PARAM";
      return response;
    }

    // Find current device from token
    std::string current_device_id;
    std::string token_hash = sha256_hash(current_token);
    auto session = session_mgr_.lookup_session_by_hash(token_hash);
    if (session.has_value()) {
      current_device_id = session->device_id;
    }

    auto devices = crud_.get_user_devices(user_id);

    for (const auto& d : devices) {
      DeviceInfo info;
      info.device_id = d.device_id;
      info.display_name = d.display_name;
      info.last_seen_ip = d.last_seen_ip;
      info.last_seen_user_agent = d.last_seen_user_agent;
      info.last_seen_ts = d.last_seen_ts;
      info.created_at = d.created_at;
      info.device_type = d.device_type;
      info.is_current = (d.device_id == current_device_id);
      info.verification_status = d.verification_status;
      info.verified_at = d.verified_at;
      info.verified_by = d.verified_by;
      response.devices.push_back(info);
    }

    response.total_count = static_cast<int>(response.devices.size());
    response.success = true;
    return response;
  }

  // ---- Get single device ----
  DeviceListResponse get_device(const std::string& user_id,
                                 const std::string& device_id) {
    DeviceListResponse response;

    auto dev = crud_.get_device(user_id, device_id);
    if (!dev.has_value()) {
      response.error = "Device not found";
      response.error_code = "M_NOT_FOUND";
      return response;
    }

    DeviceInfo info;
    info.device_id = dev->device_id;
    info.display_name = dev->display_name;
    info.last_seen_ip = dev->last_seen_ip;
    info.last_seen_user_agent = dev->last_seen_user_agent;
    info.last_seen_ts = dev->last_seen_ts;
    info.created_at = dev->created_at;
    info.device_type = dev->device_type;
    info.verification_status = dev->verification_status;
    info.verified_at = dev->verified_at;
    info.verified_by = dev->verified_by;

    response.devices.push_back(info);
    response.total_count = 1;
    response.success = true;
    return response;
  }

  // ---- Update display name ----
  DeviceListResponse update_display_name(const std::string& user_id,
                                          const std::string& device_id,
                                          const std::string& display_name) {
    DeviceListResponse response;

    if (display_name.size() > MAX_DISPLAY_NAME_LENGTH) {
      response.error = "Display name too long (max " +
                       std::to_string(MAX_DISPLAY_NAME_LENGTH) + " chars)";
      response.error_code = "M_INVALID_PARAM";
      return response;
    }

    auto result = display_name_mgr_.set_display_name(user_id, device_id,
                                                      display_name);
    if (!result.success) {
      response.error = result.error;
      response.error_code = result.error_code;
      return response;
    }

    response.success = true;
    return response;
  }

  // ---- Delete device ----
  DeviceListResponse delete_device(const std::string& user_id,
                                    const std::string& device_id,
                                    const std::string& current_token) {
    DeviceListResponse response;

    // Revoke current session
    if (!current_token.empty()) {
      session_mgr_.revoke_session(current_token);
    }

    auto result = crud_.delete_device(user_id, device_id);
    if (!result.success) {
      response.error = result.error;
      response.error_code = result.error_code;
      return response;
    }

    response.success = true;
    return response;
  }

  // ---- Delete all devices except current ----
  DeviceListResponse delete_all_except_current(
      const std::string& user_id,
      const std::string& current_token) {

    DeviceListResponse response;

    std::string token_hash = sha256_hash(current_token);
    auto session = session_mgr_.lookup_session_by_hash(token_hash);
    if (!session.has_value()) {
      response.error = "Invalid token";
      response.error_code = "M_UNKNOWN_TOKEN";
      return response;
    }

    std::string current_device_id = session->device_id;
    auto result = crud_.delete_all_devices(user_id, current_device_id);

    response.success = result.success;
    response.error = result.error;
    response.error_code = result.error_code;
    return response;
  }

  // ---- Set verification status ----
  DeviceListResponse set_verification(const std::string& user_id,
                                       const std::string& device_id,
                                       DeviceVerificationStatus status) {
    DeviceListResponse response;

    auto result = verification_tracker_.set_verification_state(
        user_id, device_id, status);
    if (!result.success) {
      response.error = result.error;
      response.error_code = result.error_code;
      return response;
    }

    response.success = true;
    return response;
  }

  // ---- Get verification statuses ----
  std::map<DeviceVerificationStatus, int> get_verification_counts(
      const std::string& user_id) {
    return verification_tracker_.count_by_verification(user_id);
  }

  // ---- Verify token ----
  std::optional<json> verify_token(const std::string& access_token) {
    auto session = session_mgr_.verify_token(access_token);
    if (!session.has_value()) return std::nullopt;

    json j;
    j["user_id"] = session->user_id;
    j["device_id"] = session->device_id;
    j["scope"] = session->scope;
    j["created_at"] = session->created_at;
    j["expires_at"] = session->expires_at;
    j["last_used_at"] = session->last_used_at;
    return j;
  }

  // ---- OTK counts ----
  std::vector<OneTimeKeyCount> count_one_time_keys(
      const std::string& user_id,
      const std::string& device_id) {
    return otk_counter_.count_for_device(user_id, device_id);
  }

  // ---- Dehydrated device operations ----
  DeviceListResponse create_dehydrated_device(
      const std::string& user_id,
      const json& device_data,
      const json& device_keys,
      int64_t expiry_ms = DEHYDRATED_EXPIRY_MS) {

    DeviceListResponse response;

    auto result = dehydration_mgr_.dehydrate_device(
        user_id, device_data, device_keys, expiry_ms);
    if (!result.success) {
      response.error = result.error;
      response.error_code = result.error_code;
      return response;
    }

    response.success = true;
    return response;
  }

  DeviceListResponse get_dehydrated_device(const std::string& user_id) {
    DeviceListResponse response;

    auto result = dehydration_mgr_.get_dehydrated_device(user_id);
    if (!result.success) {
      response.error = result.error;
      response.error_code = result.error_code;
      return response;
    }

    response.success = true;
    return response;
  }

  DeviceListResponse rehydrate_device(const std::string& user_id,
                                       const std::string& device_id) {
    DeviceListResponse response;

    auto result = dehydration_mgr_.rehydrate_device(user_id, device_id);
    if (!result.success) {
      response.error = result.error;
      response.error_code = result.error_code;
      return response;
    }

    response.success = true;
    return response;
  }

  DeviceListResponse delete_dehydrated(const std::string& user_id,
                                        const std::string& device_id) {
    DeviceListResponse response;

    auto result = dehydration_mgr_.delete_dehydrated_device(
        user_id, device_id);
    if (!result.success) {
      response.error = result.error;
      response.error_code = result.error_code;
      return response;
    }

    response.success = true;
    return response;
  }

  // ---- Cross-signing bootstrap operations ----
  DeviceListResponse bootstrap_cross_signing(
      const std::string& user_id,
      const json& master_key,
      const json& self_signing_key,
      const json& user_signing_key,
      const std::map<std::string, std::string>& signatures) {

    DeviceListResponse response;

    auto result = cross_signing_bootstrap_.bootstrap_cross_signing(
        user_id, master_key, self_signing_key, user_signing_key,
        signatures);
    if (!result.success) {
      response.error = result.error;
      response.error_code = result.error_code;
      return response;
    }

    response.success = true;
    return response;
  }

  DeviceListResponse upload_cross_signing_key(
      const std::string& user_id,
      const std::string& key_type,
      const json& key_data) {

    DeviceListResponse response;

    auto result = cross_signing_bootstrap_.upload_cross_signing_key(
        user_id, key_type, key_data);
    if (!result.success) {
      response.error = result.error;
      response.error_code = result.error_code;
      return response;
    }

    response.success = true;
    return response;
  }

  json get_cross_signing_keys(const std::string& user_id) {
    return cross_signing_bootstrap_.get_cross_signing_keys(user_id);
  }

  DeviceListResponse sign_device_with_cross_signing(
      const std::string& user_id,
      const std::string& device_id,
      const std::string& signature) {

    DeviceListResponse response;

    auto result = cross_signing_bootstrap_.sign_device(
        user_id, device_id, signature);
    if (!result.success) {
      response.error = result.error;
      response.error_code = result.error_code;
      return response;
    }

    response.success = true;
    return response;
  }

  DeviceListResponse reset_cross_signing(const std::string& user_id) {
    DeviceListResponse response;

    auto result = cross_signing_bootstrap_.reset_cross_signing(user_id);
    if (!result.success) {
      response.error = result.error;
      response.error_code = result.error_code;
      return response;
    }

    response.success = true;
    return response;
  }

  std::optional<BootstrapState> get_bootstrap_state(
      const std::string& user_id) {
    return cross_signing_bootstrap_.get_bootstrap_state(user_id);
  }

  // ---- Device list changes ----
  std::map<std::string, std::vector<std::string>>
  get_device_list_changes(int64_t from_token, int64_t to_token) {
    return change_stream_.get_changes_for_sync(from_token, to_token);
  }

  // ---- Track device activity ----
  void track_activity(const std::string& user_id,
                      const std::string& device_id,
                      const std::string& ip_address,
                      const std::string& user_agent) {
    crud_.track_activity(user_id, device_id, ip_address, user_agent);
  }

  // ---- Session management ----
  DeviceListResponse revoke_session(const std::string& access_token) {
    DeviceListResponse response;
    auto result = session_mgr_.revoke_session(access_token);
    response.success = result.success;
    response.error = result.error;
    response.error_code = result.error_code;
    return response;
  }

  std::vector<SessionRecord> list_sessions(const std::string& user_id) {
    return session_mgr_.list_user_sessions(user_id);
  }

  // ---- Stale device detection ----
  std::vector<DeviceRecord> get_stale_devices(int64_t stale_threshold_ms) {
    return crud_.get_stale_devices(stale_threshold_ms);
  }

  // ---- Device count ----
  int64_t count_user_devices(const std::string& user_id) {
    return crud_.count_devices(user_id);
  }

  // ---- Max stream ID ----
  int64_t get_max_stream_id() {
    return crud_.get_max_stream_id();
  }

  // ---- Cleanup tasks ----
  int cleanup_expired_dehydrated() {
    return dehydration_mgr_.cleanup_expired();
  }

  int cleanup_expired_sessions() {
    return session_mgr_.cleanup_expired_sessions();
  }

  // ---- Admin: full cleanup for user ----
  void admin_cleanup_user(const std::string& user_id) {
    crud_.delete_e2e_keys_for_user(user_id);
    crud_.delete_all_devices(user_id, std::nullopt);
    session_mgr_.revoke_all_user_sessions(user_id);
  }

private:
  storage::DatabasePool& db_;
  std::string server_name_;

  DeviceCRUD crud_;
  DeviceDisplayNameManager display_name_mgr_;
  DeviceListAPI list_api_;
  DeviceVerificationTracker verification_tracker_;
  DeviceSessionManager session_mgr_;
  OneTimeKeyCounter otk_counter_;
  DeviceDehydrationManager dehydration_mgr_;
  CrossSigningBootstrap cross_signing_bootstrap_;
  DeviceChangeStream change_stream_;
  DeviceInboxService inbox_service_;
};

// ============================================================================
// 12. Global factory functions and utilities
// ============================================================================

// Factory function — creates a fully initialized DeviceManagement instance
std::unique_ptr<DeviceManagement> create_device_management(
    storage::DatabasePool& db, const std::string& server_name) {
  return std::make_unique<DeviceManagement>(db, server_name);
}

// Schema initialization helper
void initialize_device_management_schema(
    storage::LoggingTransaction& txn) {
  DeviceManagement::initialize_schema(txn);
}

// Standalone verification status query
DeviceVerificationStatus get_device_verification_status(
    storage::DatabasePool& db,
    const std::string& user_id,
    const std::string& device_id) {

  DeviceVerificationTracker tracker(db);
  auto status = tracker.get_verification(user_id, device_id);
  return status.value_or(DeviceVerificationStatus::UNVERIFIED);
}

// Standalone device count utility
int64_t count_user_devices_standalone(storage::DatabasePool& db,
                                       const std::string& user_id) {
  DeviceCRUD crud(db);
  return crud.count_devices(user_id);
}

// Standalone OTK count utility
std::vector<OneTimeKeyCount> get_one_time_key_counts(
    storage::DatabasePool& db,
    const std::string& user_id,
    const std::string& device_id) {

  OneTimeKeyCounter counter(db);
  return counter.count_for_device(user_id, device_id);
}

// Standalone session verification
bool verify_access_token(storage::DatabasePool& db,
                         const std::string& access_token,
                         std::string& out_user_id,
                         std::string& out_device_id) {

  DeviceSessionManager sm(db);
  auto session = sm.verify_token(access_token);

  if (!session.has_value()) return false;

  out_user_id = session->user_id;
  out_device_id = session->device_id;
  return true;
}

} // namespace progressive

// ============================================================================
// File ends here
// ============================================================================
