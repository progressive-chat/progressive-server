// ============================================================================
// device_manager_v2.cpp — Full Matrix Device Management (v2)
//
// Implements:
//   - Device registration on login with SQL persistence
//   - Device list (full + single-device queries)
//   - Device display name update
//   - Device deletion (logout) with session revocation
//   - Delete all devices (bulk logout)
//   - Device tracking (last_seen IP, user agent, timestamps)
//   - Device list changes notification (stream-based change tracking)
//   - One-time key upload, count, and claim (full SQL)
//   - Fallback key upload, query, and claim
//   - Cross-signing key upload (master/self_signing/user_signing)
//   - Cross-signing signature storage and retrieval
//   - Dehydrated device support (create, rehydrate, delete, auto-expire)
//   - Device inbox for to-device messages
//   - Device list federation outbound tracking
//
// Full SQL DDL for all tables. Every operation is transaction-safe.
// Designed to replace the thin DeviceManager stub in account_management.cpp
// with a full production-grade implementation.
//
// Based on:
//   synapse/storage/databases/main/devices.py (2,806 lines)
//   synapse/storage/databases/main/end_to_end_keys.py (1,894 lines)
//   synapse/handlers/device.py
//   synapse/handlers/e2e_keys.py
//   synapse/handlers/e2e_room_keys.py
//   MSC 2697 (dehydrated devices)
//   MSC 3814 (dehydrated to-device messages)
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

// ============================================================================
// Forward declarations for internal classes
// ============================================================================
class DeviceManagerV2;
class DeviceStore;
class OneTimeKeyManager;
class FallbackKeyManager;
class CrossSigningManager;
class DehydratedDeviceManager;
class DeviceInboxManager;
class DeviceChangeNotifier;
class DeviceTrackingService;

// ============================================================================
// Enums and Constants
// ============================================================================

enum class DeviceVerificationState : uint8_t {
  UNVERIFIED   = 0,
  VERIFIED     = 1,
  BLOCKED      = 2,
  CROSS_SIGNED = 3
};

enum class DeviceDeletionScope : uint8_t {
  SINGLE_DEVICE       = 0,
  ALL_EXCEPT_CURRENT  = 1,
  ALL_DEVICES         = 2,
  ALL_WITH_EXCEPTIONS = 3
};

enum class OTKAlgorithm : uint8_t {
  SIGNED_CURVE25519 = 0,
  CURVE25519        = 1
};

// ============================================================================
// Anonymous namespace — Internal helpers, constants, and utility types
// ============================================================================
namespace {

// ---- Database table names ----
constexpr const char* TABLE_DEVICES               = "devices";
constexpr const char* TABLE_DEVICE_LISTS_STREAM   = "device_lists_stream";
constexpr const char* TABLE_DEVICE_LISTS_REMOTE   = "device_lists_remote";
constexpr const char* TABLE_DEVICE_LISTS_FEDERATION= "device_lists_federation";
constexpr const char* TABLE_DEVICE_LISTS_OUTBOUND = "device_lists_outbound_pokes";
constexpr const char* TABLE_DEVICE_LISTS_OUTBOUND_LAST_SUCCESS =
    "device_lists_outbound_last_success";
constexpr const char* TABLE_DEVICE_MAX_STREAM_ID  = "device_max_stream_id";
constexpr const char* TABLE_DEVICE_INBOX          = "device_inbox";
constexpr const char* TABLE_DEVICE_INBOX_SEQ      = "device_inbox_sequence";
constexpr const char* TABLE_E2E_DEVICE_KEYS_JSON  = "e2e_device_keys_json";
constexpr const char* TABLE_E2E_ONE_TIME_KEYS_JSON= "e2e_one_time_keys_json";
constexpr const char* TABLE_E2E_FALLBACK_KEYS_JSON= "e2e_fallback_keys_json";
constexpr const char* TABLE_E2E_CROSS_SIGNING_KEYS= "e2e_cross_signing_keys";
constexpr const char* TABLE_E2E_CROSS_SIGNING_SIGS= "e2e_cross_signing_signatures";
constexpr const char* TABLE_DEHYDRATED_DEVICES    = "dehydrated_devices";
constexpr const char* TABLE_DEHYDRATED_INBOX      = "dehydrated_device_inbox";
constexpr const char* TABLE_DEVICE_SESSIONS       = "device_sessions";

// ---- Field name constants ----
constexpr const char* FIELD_USER_ID       = "user_id";
constexpr const char* FIELD_DEVICE_ID     = "device_id";
constexpr const char* FIELD_DISPLAY_NAME  = "display_name";
constexpr const char* FIELD_LAST_SEEN_IP  = "last_seen_ip";
constexpr const char* FIELD_LAST_SEEN_UA  = "last_seen_user_agent";
constexpr const char* FIELD_LAST_SEEN_TS  = "last_seen_ts";
constexpr const char* FIELD_CREATED_AT    = "created_at";
constexpr const char* FIELD_DEVICE_TYPE   = "device_type";
constexpr const char* FIELD_HIDDEN        = "hidden";
constexpr const char* FIELD_STREAM_ID     = "stream_id";
constexpr const char* FIELD_STREAM_ORDERING = "stream_ordering";
constexpr const char* FIELD_KEY_JSON      = "key_json";
constexpr const char* FIELD_KEY_TYPE      = "key_type";
constexpr const char* FIELD_ALGORITHM     = "algorithm";
constexpr const char* FIELD_SIGNATURES    = "signatures";
constexpr const char* FIELD_SIGNATURE     = "signature";
constexpr const char* FIELD_TARGET_USER_ID= "target_user_id";
constexpr const char* FIELD_TARGET_DEVICE_ID = "target_device_id";
constexpr const char* FIELD_EXPIRES_AT    = "expires_at";
constexpr const char* FIELD_RECLAIMED     = "reclaimed";
constexpr const char* FIELD_DEVICE_DATA   = "device_data";
constexpr const char* FIELD_PICKLE_KEY    = "pickle_key";
constexpr const char* FIELD_ACCESS_TOKEN  = "access_token";
constexpr const char* FIELD_ACCESS_TOKEN_HASH = "access_token_hash";
constexpr const char* FIELD_DESTINATION   = "destination";
constexpr const char* FIELD_LAST_SUCCESS  = "last_success_stream_id";
constexpr const char* FIELD_MESSAGE_ID    = "message_id";
constexpr const char* FIELD_MESSAGES_JSON = "messages_json";
constexpr const char* FIELD_MIN_STREAM_ID = "min_stream_id";
constexpr const char* FIELD_MAX_STREAM_ID = "max_stream_id";

// ---- Limits ----
constexpr int MAX_DEVICES_PER_USER       = 500;
constexpr int MAX_DISPLAY_NAME_LENGTH    = 256;
constexpr int MAX_ONE_TIME_KEYS_UPLOAD   = 100;
constexpr int MAX_ONE_TIME_KEYS_CLAIM    = 250;
constexpr int MAX_FALLBACK_KEYS          = 2;
constexpr int MAX_SIGNATURES_PER_REQUEST = 100;
constexpr int MAX_CLAIM_TIMEOUT_MS       = 60000;
constexpr int MAX_DEVICE_INBOX_MESSAGES  = 100;
constexpr int MAX_DEHYDRATED_DEVICES     = 1;
constexpr int MAX_DEHYDRATED_QUEUED_MSGS = 1000;
constexpr int64_t DEHYDRATED_EXPIRY_MS   = 7LL * 24LL * 3600LL * 1000LL;  // 7 days
constexpr int64_t DEHYDRATED_MAX_EXPIRY_MS = 28LL * 24LL * 3600LL * 1000LL;
constexpr int64_t DEHYDRATED_MIN_EXPIRY_MS = 3600LL * 1000LL;  // 1 hour

// ---- Key type strings ----
constexpr const char* KEY_TYPE_MASTER         = "master";
constexpr const char* KEY_TYPE_SELF_SIGNING   = "self_signing";
constexpr const char* KEY_TYPE_USER_SIGNING   = "user_signing";
constexpr const char* ALGORITHM_SIGNED_CURVE  = "signed_curve25519";
constexpr const char* ALGORITHM_CURVE25519    = "curve25519";

// ---- Dehydrated device constants ----
constexpr const char* DEHYDRATION_ALGORITHM =
    "org.matrix.msc2697.v1.dehydrated_device";
constexpr const char* DEHYDRATED_DEVICE_PREFIX = "DEHYDRATED_";

// ---- Cryptographic constants ----
constexpr size_t AES_KEY_LEN       = 32;
constexpr size_t AES_IV_LEN        = 16;
constexpr size_t ED25519_PUBKEY_LEN= 32;
constexpr size_t ED25519_PRIVKEY_LEN = 32;
constexpr size_t ED25519_SIG_LEN   = 64;
constexpr size_t SHA256_DIGEST_LEN = 32;

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

// ---- Random string generation ----
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

// ---- Base64 encoding (unpadded, for Matrix compatibility) ----
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

// ---- SHA-256 hash ----
std::string sha256_hash(const std::string& input) {
  unsigned char hash[SHA256_DIGEST_LEN];
  SHA256(reinterpret_cast<const unsigned char*>(input.data()),
         input.size(), hash);
  return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LEN);
}

// ---- JSON value extraction helpers ----
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

// ---- Device ID generation ----
std::string generate_device_id() {
  return random_alphanumeric_string(10);
}

// ---- Access token generation ----
std::string generate_access_token() {
  std::string raw = random_hex_string(64);
  return "syt_" + base64_encode(raw);
}

// ---- SQL value quoting helper ----
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

// ---- Validate device_id format ----
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

// ---- Validate user_id format ----
bool is_valid_user_id(const std::string& user_id) {
  if (user_id.empty()) return false;
  if (user_id.size() > 255) return false;
  if (user_id[0] != '@') return false;
  auto colon_pos = user_id.find(':');
  if (colon_pos == std::string::npos || colon_pos == 1) return false;
  return true;
}

} // anonymous namespace

// ============================================================================
// 1. Device Data Structures
// ============================================================================

// ---------------------------------------------------------------------------
// DeviceEntity - Full device record stored in DB
// ---------------------------------------------------------------------------
struct DeviceEntity {
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
  DeviceVerificationState verification_state{DeviceVerificationState::UNVERIFIED};

  json to_json() const {
    json j;
    j["user_id"] = user_id;
    j["device_id"] = device_id;
    if (!display_name.empty()) j["display_name"] = display_name;
    if (!last_seen_ip.empty()) j["last_seen_ip"] = last_seen_ip;
    if (!last_seen_user_agent.empty()) j["last_seen_user_agent"] = last_seen_user_agent;
    if (last_seen_ts > 0) j["last_seen_ts"] = last_seen_ts;
    j["created_at"] = created_at;
    if (!device_type.empty()) j["device_type"] = device_type;
    if (hidden) j["hidden"] = true;
    return j;
  }

  static DeviceEntity from_json(const json& j) {
    DeviceEntity d;
    d.user_id = jstr(j, "user_id");
    d.device_id = jstr(j, "device_id");
    d.display_name = jstr(j, "display_name");
    d.last_seen_ip = jstr(j, "last_seen_ip");
    d.last_seen_user_agent = jstr(j, "last_seen_user_agent");
    d.last_seen_ts = jint(j, "last_seen_ts");
    d.created_at = jint(j, "created_at");
    d.device_type = jstr(j, "device_type");
    d.hidden = jbool(j, "hidden");
    d.access_token_hash = jstr(j, "access_token_hash");
    return d;
  }
};

// ---------------------------------------------------------------------------
// DeviceListEntry - Entry in the device_lists_stream
// ---------------------------------------------------------------------------
struct DeviceListEntry {
  int64_t stream_id{0};
  std::string user_id;
  std::string device_id;

  json to_json() const {
    return {{"stream_id", stream_id},
            {"user_id", user_id},
            {"device_id", device_id}};
  }
};

// ---------------------------------------------------------------------------
// OneTimeKey - A single one-time key record
// ---------------------------------------------------------------------------
struct OneTimeKey {
  std::string user_id;
  std::string device_id;
  std::string algorithm;
  std::string key_id;
  json key_data;
  int64_t added_at{0};
  bool claimed{false};
};

// ---------------------------------------------------------------------------
// FallbackKey - A fallback key record
// ---------------------------------------------------------------------------
struct FallbackKey {
  std::string user_id;
  std::string device_id;
  std::string algorithm;
  json key_data;
  bool used{false};
  int64_t added_at{0};
  int64_t used_at{0};
};

// ---------------------------------------------------------------------------
// CrossSigningKey - A cross-signing key record
// ---------------------------------------------------------------------------
struct CrossSigningKey {
  std::string user_id;
  std::string key_type;  // master, self_signing, user_signing
  json key_data;
  int64_t stream_id{0};
  bool replaced{false};
};

// ---------------------------------------------------------------------------
// CrossSigningSignature - A cross-signing signature record
// ---------------------------------------------------------------------------
struct CrossSigningSignature {
  std::string user_id;
  std::string key_type;
  std::string signer_user_id;
  std::string signer_key;
  std::string signature;
};

// ---------------------------------------------------------------------------
// DehydratedDevice - A dehydrated device record
// ---------------------------------------------------------------------------
struct DehydratedDevice {
  std::string user_id;
  std::string device_id;
  json device_data;
  json device_keys;
  std::string algorithm;
  int64_t created_at{0};
  int64_t expires_at{0};
  bool reclaimed{false};
  std::string pickle_key;

  bool is_expired() const {
    return expires_at > 0 && now_ms() > expires_at;
  }
};

// ---------------------------------------------------------------------------
// DeviceInboxMessage - A to-device inbox message
// ---------------------------------------------------------------------------
struct DeviceInboxMessage {
  int64_t message_id{0};
  int64_t stream_id{0};
  std::string user_id;
  std::string device_id;
  json content;
  int64_t received_at{0};
};

// ---------------------------------------------------------------------------
// DeviceRegistrationResult
// ---------------------------------------------------------------------------
struct DeviceRegistrationResult {
  bool success{false};
  std::string device_id;
  std::string access_token;
  std::string error;
  std::string errcode;
  json device_info;
};

// ---------------------------------------------------------------------------
// DeviceQueryResult
// ---------------------------------------------------------------------------
struct DeviceQueryResult {
  bool success{false};
  std::vector<DeviceEntity> devices;
  std::string error;
  std::string errcode;
  int total_count{0};
};

// ---------------------------------------------------------------------------
// OTKUploadResult
// ---------------------------------------------------------------------------
struct OTKUploadResult {
  bool success{false};
  std::map<std::string, int> counts;  // algorithm -> count uploaded
  std::string error;
  std::string errcode;
};

// ---------------------------------------------------------------------------
// OTKCountResult
// ---------------------------------------------------------------------------
struct OTKCountResult {
  bool success{false};
  std::map<std::string, int> counts;  // algorithm -> count
  std::string error;
  std::string errcode;
};

// ---------------------------------------------------------------------------
// OTKClaimResult
// ---------------------------------------------------------------------------
struct OTKClaimResult {
  bool success{false};
  // user_id -> device_id -> algorithm -> key_id -> key_data
  std::map<std::string,
           std::map<std::string,
                    std::map<std::string,
                             std::map<std::string, json>>>> keys;
  // user_id -> device_id -> algorithm -> key_id (fallback)
  std::map<std::string,
           std::map<std::string,
                    std::map<std::string,
                             std::map<std::string, json>>>> fallback_keys;
  std::string error;
  std::string errcode;
};

// ============================================================================
// 2. SQL Schema Definition (DDL)
// ============================================================================
namespace device_schema {

const std::string SCHEMA_DEVICES = R"SQL(
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
    CONSTRAINT device_pk PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_id);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(user_id, last_seen_ts);
CREATE INDEX IF NOT EXISTS idx_devices_hidden ON devices(user_id, hidden);
CREATE INDEX IF NOT EXISTS idx_devices_token_hash ON devices(access_token_hash);
)SQL";

const std::string SCHEMA_DEVICE_SESSIONS = R"SQL(
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

CREATE INDEX IF NOT EXISTS idx_device_sessions_user ON device_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_device_sessions_device ON device_sessions(user_id, device_id);
CREATE INDEX IF NOT EXISTS idx_device_sessions_expires ON device_sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_device_sessions_revoked ON device_sessions(revoked);
)SQL";

const std::string SCHEMA_DEVICE_LISTS_STREAM = R"SQL(
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

const std::string SCHEMA_DEVICE_LISTS_REMOTE = R"SQL(
CREATE TABLE IF NOT EXISTS device_lists_remote (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    sent_to_destinations TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_device_lists_remote_stream
    ON device_lists_remote(stream_id);
)SQL";

const std::string SCHEMA_DEVICE_LISTS_OUTBOUND = R"SQL(
CREATE TABLE IF NOT EXISTS device_lists_outbound_pokes (
    destination TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    sent BIGINT DEFAULT 0,
    ts BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_lists_outbound_dest
    ON device_lists_outbound_pokes(destination, stream_id);
CREATE INDEX IF NOT EXISTS idx_device_lists_outbound_sent
    ON device_lists_outbound_pokes(destination, sent, stream_id);
)SQL";

const std::string SCHEMA_DEVICE_LISTS_OUTBOUND_LAST = R"SQL(
CREATE TABLE IF NOT EXISTS device_lists_outbound_last_success (
    destination TEXT PRIMARY KEY,
    stream_id BIGINT NOT NULL,
    last_success_stream_id BIGINT NOT NULL
);
)SQL";

const std::string SCHEMA_DEVICE_MAX_STREAM_ID = R"SQL(
CREATE TABLE IF NOT EXISTS device_max_stream_id (
    stream_id BIGINT NOT NULL DEFAULT 0
);

INSERT INTO device_max_stream_id (stream_id)
SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM device_max_stream_id);
)SQL";

const std::string SCHEMA_DEVICE_INBOX = R"SQL(
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
CREATE INDEX IF NOT EXISTS idx_device_inbox_message_id
    ON device_inbox(message_id);
)SQL";

const std::string SCHEMA_DEVICE_INBOX_SEQ = R"SQL(
CREATE TABLE IF NOT EXISTS device_inbox_sequence (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    min_stream_id BIGINT NOT NULL DEFAULT 0,
    max_stream_id BIGINT NOT NULL DEFAULT 0,
    CONSTRAINT device_inbox_seq_pk PRIMARY KEY (user_id, device_id)
);
)SQL";

const std::string SCHEMA_E2E_DEVICE_KEYS = R"SQL(
CREATE TABLE IF NOT EXISTS e2e_device_keys_json (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    ts_added_ms BIGINT NOT NULL,
    key_json TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_e2e_device_keys
    ON e2e_device_keys_json(user_id, device_id);
)SQL";

const std::string SCHEMA_E2E_ONE_TIME_KEYS = R"SQL(
CREATE TABLE IF NOT EXISTS e2e_one_time_keys_json (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    key_id TEXT NOT NULL,
    ts_added_ms BIGINT NOT NULL,
    key_json TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_e2e_one_time_keys
    ON e2e_one_time_keys_json(user_id, device_id, algorithm, key_id);
CREATE INDEX IF NOT EXISTS idx_e2e_one_time_keys_count
    ON e2e_one_time_keys_json(user_id, device_id, algorithm);
)SQL";

const std::string SCHEMA_E2E_FALLBACK_KEYS = R"SQL(
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

CREATE UNIQUE INDEX IF NOT EXISTS idx_e2e_fallback_keys
    ON e2e_fallback_keys_json(user_id, device_id, algorithm);
CREATE INDEX IF NOT EXISTS idx_e2e_fallback_keys_unused
    ON e2e_fallback_keys_json(user_id, device_id, algorithm, used);
)SQL";

const std::string SCHEMA_E2E_CROSS_SIGNING_KEYS = R"SQL(
CREATE TABLE IF NOT EXISTS e2e_cross_signing_keys (
    user_id TEXT NOT NULL,
    key_type TEXT NOT NULL,  -- master, self_signing, user_signing
    key_data TEXT NOT NULL,
    stream_id BIGINT NOT NULL,
    replaced SMALLINT DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_e2e_cross_signing_keys
    ON e2e_cross_signing_keys(user_id, key_type);
CREATE INDEX IF NOT EXISTS idx_e2e_cross_signing_stream
    ON e2e_cross_signing_keys(stream_id);
)SQL";

const std::string SCHEMA_E2E_CROSS_SIGNING_SIGS = R"SQL(
CREATE TABLE IF NOT EXISTS e2e_cross_signing_signatures (
    user_id TEXT NOT NULL,
    key_type TEXT NOT NULL,
    signer_user_id TEXT NOT NULL,
    signer_key TEXT NOT NULL,
    signature TEXT NOT NULL,
    stream_id BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_e2e_cross_signing_sigs
    ON e2e_cross_signing_signatures(user_id, key_type);
CREATE INDEX IF NOT EXISTS idx_e2e_cross_signing_sigs_stream
    ON e2e_cross_signing_signatures(stream_id);
)SQL";

const std::string SCHEMA_DEHYDRATED_DEVICES = R"SQL(
CREATE TABLE IF NOT EXISTS dehydrated_devices (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_data TEXT NOT NULL,       -- JSON blob of encrypted key material
    device_keys TEXT DEFAULT '',     -- JSON blob of device public keys
    algorithm TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    reclaimed SMALLINT DEFAULT 0,
    pickle_key TEXT DEFAULT '',
    CONSTRAINT dehyd_dev_pk PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_dehydrated_devices_user
    ON dehydrated_devices(user_id, reclaimed, expires_at);
CREATE INDEX IF NOT EXISTS idx_dehydrated_devices_expiry
    ON dehydrated_devices(expires_at) WHERE reclaimed = 0;
)SQL";

const std::string SCHEMA_DEHYDRATED_INBOX = R"SQL(
CREATE TABLE IF NOT EXISTS dehydrated_device_inbox (
    message_id BIGINT PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    content_json TEXT NOT NULL,
    received_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_dehydrated_inbox_user_device
    ON dehydrated_device_inbox(user_id, device_id);
CREATE INDEX IF NOT EXISTS idx_dehydrated_inbox_received
    ON dehydrated_device_inbox(received_at);
)SQL";

// Aggregate all DDL into one script
const std::string ALL_SCHEMA =
    SCHEMA_DEVICES + "\n" +
    SCHEMA_DEVICE_SESSIONS + "\n" +
    SCHEMA_DEVICE_LISTS_STREAM + "\n" +
    SCHEMA_DEVICE_LISTS_REMOTE + "\n" +
    SCHEMA_DEVICE_LISTS_OUTBOUND + "\n" +
    SCHEMA_DEVICE_LISTS_OUTBOUND_LAST + "\n" +
    SCHEMA_DEVICE_MAX_STREAM_ID + "\n" +
    SCHEMA_DEVICE_INBOX + "\n" +
    SCHEMA_DEVICE_INBOX_SEQ + "\n" +
    SCHEMA_E2E_DEVICE_KEYS + "\n" +
    SCHEMA_E2E_ONE_TIME_KEYS + "\n" +
    SCHEMA_E2E_FALLBACK_KEYS + "\n" +
    SCHEMA_E2E_CROSS_SIGNING_KEYS + "\n" +
    SCHEMA_E2E_CROSS_SIGNING_SIGS + "\n" +
    SCHEMA_DEHYDRATED_DEVICES + "\n" +
    SCHEMA_DEHYDRATED_INBOX;

} // namespace device_schema

// ============================================================================
// 3. DeviceStore — Core device CRUD with full SQL
// ============================================================================

class DeviceStore {
public:
  explicit DeviceStore(storage::DatabasePool& db)
      : db_(db) {}

  // --------------------------------------------------------------------------
  // Schema creation
  // --------------------------------------------------------------------------
  static void create_tables(storage::LoggingTransaction& txn) {
    txn.executescript(device_schema::ALL_SCHEMA);
  }

  // --------------------------------------------------------------------------
  // Device registration — called on login to create/update device record
  // --------------------------------------------------------------------------
  DeviceRegistrationResult register_device(
      const std::string& user_id,
      const std::string& device_id,
      const std::string& initial_display_name,
      const std::string& ip_address,
      const std::string& user_agent,
      const std::string& access_token_hash,
      const std::string& device_type) {

    DeviceRegistrationResult result;

    if (!is_valid_user_id(user_id)) {
      result.success = false;
      result.error = "Invalid user ID";
      result.errcode = "M_INVALID_PARAM";
      return result;
    }

    if (!is_valid_device_id(device_id)) {
      result.success = false;
      result.error = "Invalid device ID";
      result.errcode = "M_INVALID_PARAM";
      return result;
    }

    try {
      db_.runInteraction("register_device",
        [&](storage::LoggingTransaction& txn) {
          register_device_txn(txn, user_id, device_id,
                              initial_display_name, ip_address,
                              user_agent, access_token_hash, device_type,
                              result);
        });
    } catch (const std::exception& e) {
      result.success = false;
      result.error = std::string("Database error: ") + e.what();
      result.errcode = "M_UNKNOWN";
    }

    return result;
  }

  void register_device_txn(storage::LoggingTransaction& txn,
                           const std::string& user_id,
                           const std::string& device_id,
                           const std::string& initial_display_name,
                           const std::string& ip_address,
                           const std::string& user_agent,
                           const std::string& access_token_hash,
                           const std::string& device_type,
                           DeviceRegistrationResult& result) {

    // Check device limit
    int64_t count = count_devices_for_user_txn(txn, user_id);
    if (count >= MAX_DEVICES_PER_USER) {
      result.success = false;
      result.error = "Too many devices. Maximum is " +
                     std::to_string(MAX_DEVICES_PER_USER);
      result.errcode = "M_LIMIT_EXCEEDED";
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
                           verification_state)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
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
      storage::SQLParam{0LL},        // hidden
      storage::SQLParam{access_token_hash},
      storage::SQLParam{static_cast<int64_t>(DeviceVerificationState::UNVERIFIED)}
    });

    // Insert into device_lists_stream for change notification
    int64_t stream_id = add_device_change_txn(txn, user_id, device_id, "127.0.0.1");

    // Build result
    result.success = true;
    result.device_id = device_id;
    result.device_info = json{
      {"device_id", device_id},
      {"display_name", display_name},
      {"last_seen_ip", ip_address},
      {"last_seen_ts", now},
      {"device_type", device_type}
    };
  }

  // --------------------------------------------------------------------------
  // Device listing — get all devices for a user
  // --------------------------------------------------------------------------
  DeviceQueryResult get_devices_for_user(const std::string& user_id) {
    DeviceQueryResult result;

    try {
      db_.runInteraction("get_devices_for_user",
        [&](storage::LoggingTransaction& txn) {
          auto devices = get_devices_for_user_txn(txn, user_id);
          result.devices = std::move(devices);
          result.total_count = static_cast<int>(result.devices.size());
          result.success = true;
        });
    } catch (const std::exception& e) {
      result.success = false;
      result.error = std::string("Database error: ") + e.what();
      result.errcode = "M_UNKNOWN";
    }

    return result;
  }

  std::vector<DeviceEntity> get_devices_for_user_txn(
      storage::LoggingTransaction& txn, const std::string& user_id) {

    std::vector<DeviceEntity> devices;

    std::string sql = R"SQL(
      SELECT user_id, device_id, display_name, last_seen_ip,
             last_seen_user_agent, last_seen_ts, created_at,
             device_type, hidden, access_token_hash, verification_state
      FROM devices
      WHERE user_id = ?1 AND hidden = 0
      ORDER BY last_seen_ts DESC
    )SQL";

    txn.execute(sql, {storage::SQLParam{user_id}});

    Row row;
    while (txn.iter_next(row)) {
      DeviceEntity d;
      if (!row.empty()) {
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
          int vs = std::stoi(*row[10].value);
          d.verification_state = static_cast<DeviceVerificationState>(vs);
        }
      }
      devices.push_back(std::move(d));
    }

    return devices;
  }

  // --------------------------------------------------------------------------
  // Single device lookup
  // --------------------------------------------------------------------------
  std::optional<DeviceEntity> get_device(const std::string& user_id,
                                          const std::string& device_id) {
    std::optional<DeviceEntity> result;

    try {
      db_.runInteraction("get_device",
        [&](storage::LoggingTransaction& txn) {
          result = get_device_txn(txn, user_id, device_id);
        });
    } catch (const std::exception& e) {
      // Return empty optional on error
    }

    return result;
  }

  std::optional<DeviceEntity> get_device_txn(
      storage::LoggingTransaction& txn,
      const std::string& user_id,
      const std::string& device_id) {

    std::string sql = R"SQL(
      SELECT user_id, device_id, display_name, last_seen_ip,
             last_seen_user_agent, last_seen_ts, created_at,
             device_type, hidden, access_token_hash, verification_state
      FROM devices
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";

    txn.execute(sql, {storage::SQLParam{user_id}, storage::SQLParam{device_id}});

    Row row;
    if (txn.iter_next(row) && !row.empty()) {
      DeviceEntity d;
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
        int vs = std::stoi(*row[10].value);
        d.verification_state = static_cast<DeviceVerificationState>(vs);
      }
      return d;
    }

    return std::nullopt;
  }

  // --------------------------------------------------------------------------
  // Device display name update
  // --------------------------------------------------------------------------
  bool update_device_display_name(const std::string& user_id,
                                   const std::string& device_id,
                                   const std::string& display_name) {
    if (display_name.size() > MAX_DISPLAY_NAME_LENGTH) {
      return false;
    }

    bool updated = false;

    try {
      db_.runInteraction("update_device_display_name",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            UPDATE devices
            SET display_name = ?1
            WHERE user_id = ?2 AND device_id = ?3
          )SQL";

          txn.execute(sql, {
            storage::SQLParam{display_name},
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          updated = (txn.rowcount() > 0);

          // Add to device list changes
          if (updated) {
            add_device_change_txn(txn, user_id, device_id, "127.0.0.1");
          }
        });
    } catch (const std::exception&) {
      return false;
    }

    return updated;
  }

  // --------------------------------------------------------------------------
  // Device deletion (single device logout)
  // --------------------------------------------------------------------------
  bool delete_device(const std::string& user_id,
                     const std::string& device_id) {
    bool deleted = false;

    try {
      db_.runInteraction("delete_device",
        [&](storage::LoggingTransaction& txn) {
          delete_device_txn(txn, user_id, device_id, deleted);
        });
    } catch (const std::exception&) {
      return false;
    }

    return deleted;
  }

  void delete_device_txn(storage::LoggingTransaction& txn,
                          const std::string& user_id,
                          const std::string& device_id,
                          bool& deleted) {

    // Delete device record
    std::string sql = R"SQL(
      DELETE FROM devices
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";

    txn.execute(sql, {storage::SQLParam{user_id}, storage::SQLParam{device_id}});
    deleted = (txn.rowcount() > 0);

    if (deleted) {
      // Revoke all sessions for this device
      std::string revoke_sql = R"SQL(
        UPDATE device_sessions
        SET revoked = 1
        WHERE user_id = ?1 AND device_id = ?2
      )SQL";
      txn.execute(revoke_sql,
                  {storage::SQLParam{user_id}, storage::SQLParam{device_id}});

      // Add device list change notification
      add_device_change_txn(txn, user_id, device_id, "127.0.0.1");

      // Delete device E2E keys
      delete_e2e_device_keys_txn(txn, user_id, device_id);

      // Delete one-time keys for this device
      delete_one_time_keys_for_device_txn(txn, user_id, device_id);

      // Delete fallback keys for this device
      delete_fallback_keys_for_device_txn(txn, user_id, device_id);

      // Delete device inbox messages
      delete_device_inbox_txn(txn, user_id, device_id);
    }
  }

  // --------------------------------------------------------------------------
  // Delete all devices for a user (full logout)
  // --------------------------------------------------------------------------
  int delete_all_devices(const std::string& user_id,
                         const std::optional<std::string>& except_device_id) {
    int deleted = 0;

    try {
      db_.runInteraction("delete_all_devices",
        [&](storage::LoggingTransaction& txn) {
          deleted = delete_all_devices_txn(txn, user_id, except_device_id);
        });
    } catch (const std::exception&) {
      return 0;
    }

    return deleted;
  }

  int delete_all_devices_txn(storage::LoggingTransaction& txn,
                              const std::string& user_id,
                              const std::optional<std::string>& except_device_id) {

    int deleted = 0;

    // Get all device IDs for the user first
    std::vector<std::string> device_ids;
    std::string select_sql = R"SQL(
      SELECT device_id FROM devices WHERE user_id = ?1
    )SQL";
    txn.execute(select_sql, {storage::SQLParam{user_id}});

    Row row;
    while (txn.iter_next(row)) {
      if (!row.empty() && row[0].value) {
        std::string did = *row[0].value;
        if (!except_device_id || did != *except_device_id) {
          device_ids.push_back(did);
        }
      }
    }

    // Delete each device
    for (const auto& did : device_ids) {
      bool d = false;
      delete_device_txn(txn, user_id, did, d);
      if (d) deleted++;
    }

    // Revoke all remaining sessions
    if (except_device_id) {
      std::string revoke_sql = R"SQL(
        UPDATE device_sessions
        SET revoked = 1
        WHERE user_id = ?1 AND device_id != ?2
      )SQL";
      txn.execute(revoke_sql,
                  {storage::SQLParam{user_id}, storage::SQLParam{*except_device_id}});
    } else {
      std::string revoke_sql = R"SQL(
        UPDATE device_sessions
        SET revoked = 1
        WHERE user_id = ?1
      )SQL";
      txn.execute(revoke_sql, {storage::SQLParam{user_id}});
    }

    return deleted;
  }

  // --------------------------------------------------------------------------
  // Device tracking — update last_seen on activity
  // --------------------------------------------------------------------------
  void update_device_last_seen(const std::string& user_id,
                                const std::string& device_id,
                                const std::string& ip_address,
                                const std::string& user_agent) {
    db_.runInteraction("update_device_last_seen",
      [&](storage::LoggingTransaction& txn) {
        int64_t now = now_ms();

        std::string sql = R"SQL(
          UPDATE devices
          SET last_seen_ip = ?1,
              last_seen_user_agent = ?2,
              last_seen_ts = ?3
          WHERE user_id = ?4 AND device_id = ?5
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{ip_address},
          storage::SQLParam{user_agent},
          storage::SQLParam{now},
          storage::SQLParam{user_id},
          storage::SQLParam{device_id}
        });

        // Also update session last_used_at
        std::string session_sql = R"SQL(
          UPDATE device_sessions
          SET last_used_at = ?1, ip_address = ?2, user_agent = ?3
          WHERE user_id = ?4 AND device_id = ?5 AND revoked = 0
        )SQL";

        txn.execute(session_sql, {
          storage::SQLParam{now},
          storage::SQLParam{ip_address},
          storage::SQLParam{user_agent},
          storage::SQLParam{user_id},
          storage::SQLParam{device_id}
        });
      });
  }

  // --------------------------------------------------------------------------
  // Device count
  // --------------------------------------------------------------------------
  int64_t count_devices_for_user(const std::string& user_id) {
    int64_t count = 0;

    db_.runInteraction("count_devices_for_user",
      [&](storage::LoggingTransaction& txn) {
        count = count_devices_for_user_txn(txn, user_id);
      });

    return count;
  }

  int64_t count_devices_for_user_txn(storage::LoggingTransaction& txn,
                                      const std::string& user_id) {
    std::string sql = R"SQL(
      SELECT COUNT(*) FROM devices WHERE user_id = ?1 AND hidden = 0
    )SQL";

    txn.execute(sql, {storage::SQLParam{user_id}});

    Row row;
    if (txn.iter_next(row) && !row.empty() && row[0].value) {
      return std::stoll(*row[0].value);
    }

    return 0;
  }

  // --------------------------------------------------------------------------
  // Device hiding (soft delete / mark as hidden)
  // --------------------------------------------------------------------------
  bool hide_device(const std::string& user_id,
                   const std::string& device_id) {
    bool updated = false;

    db_.runInteraction("hide_device",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          UPDATE devices SET hidden = 1
          WHERE user_id = ?1 AND device_id = ?2
        )SQL";
        txn.execute(sql, {storage::SQLParam{user_id}, storage::SQLParam{device_id}});
        updated = (txn.rowcount() > 0);

        if (updated) {
          add_device_change_txn(txn, user_id, device_id, "127.0.0.1");
        }
      });

    return updated;
  }

  // --------------------------------------------------------------------------
  // Device verification state update
  // --------------------------------------------------------------------------
  bool set_device_verification_state(const std::string& user_id,
                                      const std::string& device_id,
                                      DeviceVerificationState state) {
    bool updated = false;

    db_.runInteraction("set_device_verification_state",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          UPDATE devices SET verification_state = ?1
          WHERE user_id = ?2 AND device_id = ?3
        )SQL";
        txn.execute(sql, {
          storage::SQLParam{static_cast<int64_t>(state)},
          storage::SQLParam{user_id},
          storage::SQLParam{device_id}
        });
        updated = (txn.rowcount() > 0);
      });

    return updated;
  }

  // --------------------------------------------------------------------------
  // Get device by access token hash
  // --------------------------------------------------------------------------
  std::optional<DeviceEntity> get_device_by_token_hash(
      const std::string& token_hash) {
    std::optional<DeviceEntity> result;

    db_.runInteraction("get_device_by_token_hash",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT user_id, device_id, display_name, last_seen_ip,
                 last_seen_user_agent, last_seen_ts, created_at,
                 device_type, hidden, access_token_hash, verification_state
          FROM devices
          WHERE access_token_hash = ?1 AND hidden = 0
        )SQL";

        txn.execute(sql, {storage::SQLParam{token_hash}});

        Row row;
        if (txn.iter_next(row) && !row.empty()) {
          DeviceEntity d;
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
          result = d;
        }
      });

    return result;
  }

  // --------------------------------------------------------------------------
  // Device change stream operations
  // --------------------------------------------------------------------------
  int64_t add_device_change_txn(storage::LoggingTransaction& txn,
                                 const std::string& user_id,
                                 const std::string& device_id,
                                 const std::string& host) {
    int64_t stream_id = next_device_stream_id_txn(txn);

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

  int64_t next_device_stream_id_txn(storage::LoggingTransaction& txn) {
    // Increment and return new stream ID
    std::string sql = R"SQL(
      UPDATE device_max_stream_id
      SET stream_id = stream_id + 1;
    )SQL";
    txn.execute(sql);

    std::string sel_sql = "SELECT stream_id FROM device_max_stream_id";
    txn.execute(sel_sql);

    Row row;
    if (txn.iter_next(row) && !row.empty() && row[0].value) {
      return std::stoll(*row[0].value);
    }

    return 1;
  }

  // Get current max stream ID
  int64_t get_device_max_stream_id() {
    int64_t sid = 0;
    db_.runInteraction("get_device_max_stream_id",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = "SELECT stream_id FROM device_max_stream_id";
        txn.execute(sql);
        Row row;
        if (txn.iter_next(row) && !row.empty() && row[0].value) {
          sid = std::stoll(*row[0].value);
        }
      });
    return sid;
  }

  // Get device list changes since a stream token
  std::map<std::string, std::vector<std::string>>
  get_users_whose_devices_changed(int64_t from_stream_id,
                                   int64_t to_stream_id) {
    std::map<std::string, std::vector<std::string>> result;

    db_.runInteraction("get_users_whose_devices_changed",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT user_id, device_id
          FROM device_lists_stream
          WHERE stream_id > ?1 AND stream_id <= ?2
          ORDER BY stream_id ASC
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{from_stream_id},
          storage::SQLParam{to_stream_id}
        });

        Row row;
        std::set<std::string> seen_users;
        while (txn.iter_next(row)) {
          if (!row.empty() && row[0].value) {
            std::string uid = *row[0].value;
            // For each user, we note they changed — the actual device list
            // is rebuilt by the caller from the current devices table
            if (seen_users.find(uid) == seen_users.end()) {
              seen_users.insert(uid);
              result[uid] = {};  // Empty vector = all devices changed
            }
          }
        }
      });

    return result;
  }

  // Get device list changes for federation outbound
  std::vector<DeviceListEntry> get_device_list_changes_for_remotes(
      int64_t from_stream_id, int64_t to_stream_id) {
    std::vector<DeviceListEntry> entries;

    db_.runInteraction("get_device_list_changes_for_remotes",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT stream_id, user_id, device_id
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
          if (!row.empty()) {
            DeviceListEntry entry;
            entry.stream_id = row[0].value ? std::stoll(*row[0].value) : 0;
            entry.user_id = row[1].value.value_or("");
            entry.device_id = row[2].value.value_or("");
            entries.push_back(entry);
          }
        }
      });

    return entries;
  }

  // --------------------------------------------------------------------------
  // Device list outbound pokes (federation)
  // --------------------------------------------------------------------------
  void add_device_list_outbound_poke(storage::LoggingTransaction& txn,
                                      const std::string& destination,
                                      int64_t stream_id,
                                      const std::string& user_id,
                                      const std::string& device_id) {
    int64_t now = now_ms();
    std::string sql = R"SQL(
      INSERT INTO device_lists_outbound_pokes
        (destination, stream_id, user_id, device_id, sent, ts)
      VALUES (?1, ?2, ?3, ?4, 0, ?5)
    )SQL";

    txn.execute(sql, {
      storage::SQLParam{destination},
      storage::SQLParam{stream_id},
      storage::SQLParam{user_id},
      storage::SQLParam{device_id},
      storage::SQLParam{now}
    });
  }

  // --------------------------------------------------------------------------
  // Session management
  // --------------------------------------------------------------------------
  bool create_session(const std::string& token_hash,
                      const std::string& user_id,
                      const std::string& device_id,
                      const std::string& ip_address,
                      const std::string& user_agent,
                      int64_t expires_at_ms) {
    bool created = false;

    db_.runInteraction("create_session",
      [&](storage::LoggingTransaction& txn) {
        int64_t now = now_ms();

        std::string sql = R"SQL(
          INSERT INTO device_sessions
            (access_token_hash, user_id, device_id, ip_address,
             user_agent, created_at, expires_at, last_used_at, revoked)
          VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{token_hash},
          storage::SQLParam{user_id},
          storage::SQLParam{device_id},
          storage::SQLParam{ip_address},
          storage::SQLParam{user_agent},
          storage::SQLParam{now},
          storage::SQLParam{expires_at_ms},
          storage::SQLParam{now}
        });

        created = true;
      });

    return created;
  }

  bool revoke_session(const std::string& token_hash) {
    bool revoked = false;

    db_.runInteraction("revoke_session",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          UPDATE device_sessions SET revoked = 1
          WHERE access_token_hash = ?1
        )SQL";
        txn.execute(sql, {storage::SQLParam{token_hash}});
        revoked = (txn.rowcount() > 0);
      });

    return revoked;
  }

  std::optional<json> get_session(const std::string& token_hash) {
    std::optional<json> result;

    db_.runInteraction("get_session",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT user_id, device_id, ip_address, user_agent,
                 created_at, expires_at, last_used_at, revoked, scope
          FROM device_sessions
          WHERE access_token_hash = ?1
        )SQL";
        txn.execute(sql, {storage::SQLParam{token_hash}});

        Row row;
        if (txn.iter_next(row) && !row.empty()) {
          json j;
          j["user_id"] = row[0].value.value_or("");
          j["device_id"] = row[1].value.value_or("");
          j["ip_address"] = row[2].value.value_or("");
          j["user_agent"] = row[3].value.value_or("");
          j["created_at"] = row[4].value ? std::stoll(*row[4].value) : 0LL;
          j["expires_at"] = row[5].value ? std::stoll(*row[5].value) : 0LL;
          j["last_used_at"] = row[6].value ? std::stoll(*row[6].value) : 0LL;
          j["revoked"] = row[7].value && *row[7].value == "1";
          j["scope"] = row[8].value.value_or("full");
          result = j;
        }
      });

    return result;
  }

  // --------------------------------------------------------------------------
  // Private helpers for cascading deletes
  // --------------------------------------------------------------------------
private:
  void delete_e2e_device_keys_txn(storage::LoggingTransaction& txn,
                                   const std::string& user_id,
                                   const std::string& device_id) {
    std::string sql = R"SQL(
      DELETE FROM e2e_device_keys_json
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(sql, {storage::SQLParam{user_id}, storage::SQLParam{device_id}});
  }

  void delete_one_time_keys_for_device_txn(
      storage::LoggingTransaction& txn,
      const std::string& user_id,
      const std::string& device_id) {
    std::string sql = R"SQL(
      DELETE FROM e2e_one_time_keys_json
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(sql, {storage::SQLParam{user_id}, storage::SQLParam{device_id}});
  }

  void delete_fallback_keys_for_device_txn(
      storage::LoggingTransaction& txn,
      const std::string& user_id,
      const std::string& device_id) {
    std::string sql = R"SQL(
      DELETE FROM e2e_fallback_keys_json
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(sql, {storage::SQLParam{user_id}, storage::SQLParam{device_id}});
  }

  void delete_device_inbox_txn(storage::LoggingTransaction& txn,
                                const std::string& user_id,
                                const std::string& device_id) {
    std::string sql = R"SQL(
      DELETE FROM device_inbox
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(sql, {storage::SQLParam{user_id}, storage::SQLParam{device_id}});

    std::string seq_sql = R"SQL(
      DELETE FROM device_inbox_sequence
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";
    txn.execute(seq_sql, {storage::SQLParam{user_id}, storage::SQLParam{device_id}});
  }

public:
  storage::DatabasePool& db_;
};

// ============================================================================
// 4. OneTimeKeyManager — OTK upload, count, and claim
// ============================================================================

class OneTimeKeyManager {
public:
  explicit OneTimeKeyManager(storage::DatabasePool& db)
      : db_(db) {}

  // --------------------------------------------------------------------------
  // Upload one-time keys
  // --------------------------------------------------------------------------
  OTKUploadResult upload_one_time_keys(
      const std::string& user_id,
      const std::string& device_id,
      const std::map<std::string, std::map<std::string, json>>& keys) {

    OTKUploadResult result;

    try {
      db_.runInteraction("upload_one_time_keys",
        [&](storage::LoggingTransaction& txn) {
          upload_one_time_keys_txn(txn, user_id, device_id, keys, result);
        });
    } catch (const std::exception& e) {
      result.success = false;
      result.error = std::string("Database error: ") + e.what();
      result.errcode = "M_UNKNOWN";
    }

    return result;
  }

  void upload_one_time_keys_txn(
      storage::LoggingTransaction& txn,
      const std::string& user_id,
      const std::string& device_id,
      const std::map<std::string, std::map<std::string, json>>& keys,
      OTKUploadResult& result) {

    int64_t now = now_ms();
    int total_count = 0;

    // First check how many keys already exist for this device
    int existing = count_one_time_keys_for_device_txn(txn, user_id, device_id);

    for (const auto& [algorithm, key_map] : keys) {
      int algo_count = 0;

      for (const auto& [key_id, key_data] : key_map) {
        if (existing + total_count >= MAX_ONE_TIME_KEYS_UPLOAD) {
          break;
        }

        std::string sql = R"SQL(
          INSERT INTO e2e_one_time_keys_json
            (user_id, device_id, algorithm, key_id, ts_added_ms, key_json)
          VALUES (?1, ?2, ?3, ?4, ?5, ?6)
          ON CONFLICT(user_id, device_id, algorithm, key_id) DO NOTHING
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{user_id},
          storage::SQLParam{device_id},
          storage::SQLParam{algorithm},
          storage::SQLParam{key_id},
          storage::SQLParam{now},
          storage::SQLParam{key_data.dump()}
        });

        if (txn.rowcount() > 0) {
          algo_count++;
          total_count++;
        }
      }

      result.counts[algorithm] = algo_count;
    }

    result.success = true;
  }

  // --------------------------------------------------------------------------
  // Count one-time keys
  // --------------------------------------------------------------------------
  OTKCountResult count_one_time_keys(const std::string& user_id,
                                      const std::string& device_id) {
    OTKCountResult result;

    try {
      db_.runInteraction("count_one_time_keys",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            SELECT algorithm, COUNT(*) as cnt
            FROM e2e_one_time_keys_json
            WHERE user_id = ?1 AND device_id = ?2
            GROUP BY algorithm
          )SQL";

          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value && row[1].value) {
              result.counts[*row[0].value] = std::stoi(*row[1].value);
            }
          }

          result.success = true;
        });
    } catch (const std::exception& e) {
      result.success = false;
      result.error = std::string("Database error: ") + e.what();
      result.errcode = "M_UNKNOWN";
    }

    return result;
  }

  int count_one_time_keys_for_device_txn(storage::LoggingTransaction& txn,
                                          const std::string& user_id,
                                          const std::string& device_id) {
    std::string sql = R"SQL(
      SELECT COUNT(*) FROM e2e_one_time_keys_json
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";

    txn.execute(sql, {storage::SQLParam{user_id}, storage::SQLParam{device_id}});

    Row row;
    if (txn.iter_next(row) && !row.empty() && row[0].value) {
      return std::stoi(*row[0].value);
    }

    return 0;
  }

  // --------------------------------------------------------------------------
  // Claim one-time keys (used by other users to establish Olm sessions)
  // --------------------------------------------------------------------------
  OTKClaimResult claim_one_time_keys(
      const std::map<std::string,
                     std::map<std::string,
                              std::map<std::string, int>>>& query_list,
      int64_t timeout_ms = MAX_CLAIM_TIMEOUT_MS) {

    OTKClaimResult result;

    try {
      db_.runInteraction("claim_one_time_keys",
        [&](storage::LoggingTransaction& txn) {
          claim_one_time_keys_txn(txn, query_list, timeout_ms, result);
        });
    } catch (const std::exception& e) {
      result.success = false;
      result.error = std::string("Database error: ") + e.what();
      result.errcode = "M_UNKNOWN";
    }

    return result;
  }

  void claim_one_time_keys_txn(
      storage::LoggingTransaction& txn,
      const std::map<std::string,
                     std::map<std::string,
                              std::map<std::string, int>>>& query_list,
      int64_t timeout_ms,
      OTKClaimResult& result) {

    int64_t now = now_ms();
    int64_t expiry_threshold = now - timeout_ms;

    for (const auto& [user_id, device_map] : query_list) {
      for (const auto& [device_id, algo_map] : device_map) {
        for (const auto& [algorithm, count] : algo_map) {
          if (count <= 0) continue;

          // Select up to 'count' OTKs, ordered by ts_added_ms (oldest first)
          std::string select_sql = R"SQL(
            SELECT key_id, key_json
            FROM e2e_one_time_keys_json
            WHERE user_id = ?1 AND device_id = ?2 AND algorithm = ?3
              AND ts_added_ms > ?4
            ORDER BY ts_added_ms ASC
            LIMIT ?5
          )SQL";

          txn.execute(select_sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id},
            storage::SQLParam{algorithm},
            storage::SQLParam{expiry_threshold},
            storage::SQLParam{static_cast<int64_t>(count)}
          });

          std::vector<std::pair<std::string, std::string>> keys_to_delete;
          Row row;
          while (txn.iter_next(row)) {
            if (!row.empty() && row[0].value && row[1].value) {
              std::string key_id = *row[0].value;
              std::string key_json_str = *row[1].value;

              try {
                json key_data = json::parse(key_json_str);
                result.keys[user_id][device_id][algorithm][key_id] = key_data;
                keys_to_delete.push_back({key_id, key_json_str});
              } catch (...) {
                // Skip malformed keys
              }
            }
          }

          // Delete the claimed keys
          for (const auto& [kid, _] : keys_to_delete) {
            std::string del_sql = R"SQL(
              DELETE FROM e2e_one_time_keys_json
              WHERE user_id = ?1 AND device_id = ?2
                AND algorithm = ?3 AND key_id = ?4
            )SQL";
            txn.execute(del_sql, {
              storage::SQLParam{user_id},
              storage::SQLParam{device_id},
              storage::SQLParam{algorithm},
              storage::SQLParam{kid}
            });
          }

          // If no OTKs found, try fallback keys
          if (keys_to_delete.empty()) {
            claim_fallback_keys_txn(txn, user_id, device_id,
                                     algorithm, result);
          }
        }
      }
    }

    result.success = true;
  }

  // --------------------------------------------------------------------------
  // Bulk count one-time keys (for federation key query)
  // --------------------------------------------------------------------------
  std::map<std::string,
           std::map<std::string,
                    std::map<std::string, int64_t>>>
  count_bulk_one_time_keys(const std::set<std::string>& user_ids) {
    std::map<std::string,
             std::map<std::string,
                      std::map<std::string, int64_t>>> result;

    if (user_ids.empty()) return result;

    db_.runInteraction("count_bulk_one_time_keys",
      [&](storage::LoggingTransaction& txn) {
        // Build comma-separated user ID list
        std::string user_list;
        for (const auto& uid : user_ids) {
          if (!user_list.empty()) user_list += ",";
          user_list += sql_quote(uid);
        }

        std::string sql = "SELECT user_id, device_id, algorithm, COUNT(*) "
                          "FROM e2e_one_time_keys_json "
                          "WHERE user_id IN (" + user_list + ") "
                          "GROUP BY user_id, device_id, algorithm";

        txn.execute(sql);

        Row row;
        while (txn.iter_next(row)) {
          if (!row.empty() && row[0].value && row[1].value &&
              row[2].value && row[3].value) {
            result[*row[0].value][*row[1].value][*row[2].value] =
                std::stoll(*row[3].value);
          }
        }
      });

    return result;
  }

  // --------------------------------------------------------------------------
  // Fallback key claim helper
  // --------------------------------------------------------------------------
private:
  void claim_fallback_keys_txn(storage::LoggingTransaction& txn,
                                const std::string& user_id,
                                const std::string& device_id,
                                const std::string& algorithm,
                                OTKClaimResult& result) {
    std::string sql = R"SQL(
      SELECT key_id, key_json
      FROM e2e_fallback_keys_json
      WHERE user_id = ?1 AND device_id = ?2
        AND algorithm = ?3 AND used = 0
      LIMIT 1
    )SQL";

    txn.execute(sql, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id},
      storage::SQLParam{algorithm}
    });

    Row row;
    if (txn.iter_next(row) && !row.empty() && row[0].value && row[1].value) {
      try {
        json key_data = json::parse(*row[1].value);
        result.fallback_keys[user_id][device_id][algorithm][*row[0].value] =
            key_data;

        // Mark fallback key as used
        int64_t now = now_ms();
        std::string mark_sql = R"SQL(
          UPDATE e2e_fallback_keys_json
          SET used = 1, ts_used_ms = ?1
          WHERE user_id = ?2 AND device_id = ?3 AND algorithm = ?4
        )SQL";
        txn.execute(mark_sql, {
          storage::SQLParam{now},
          storage::SQLParam{user_id},
          storage::SQLParam{device_id},
          storage::SQLParam{algorithm}
        });
      } catch (...) {}
    }
  }

public:
  storage::DatabasePool& db_;
};

// ============================================================================
// 5. FallbackKeyManager — Upload, set, and get fallback keys
// ============================================================================

class FallbackKeyManager {
public:
  explicit FallbackKeyManager(storage::DatabasePool& db)
      : db_(db) {}

  // --------------------------------------------------------------------------
  // Upload fallback keys
  // --------------------------------------------------------------------------
  bool upload_fallback_keys(
      const std::string& user_id,
      const std::string& device_id,
      const std::map<std::string, json>& fallback_keys) {

    bool success = false;

    try {
      db_.runInteraction("upload_fallback_keys",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();

          for (const auto& [algorithm, key_data] : fallback_keys) {
            std::string key_id = algorithm;

            // Upsert: replace existing fallback key for this algorithm
            std::string sql = R"SQL(
              INSERT INTO e2e_fallback_keys_json
                (user_id, device_id, algorithm, key_id, key_json,
                 used, ts_added_ms, ts_used_ms)
              VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6, 0)
              ON CONFLICT(user_id, device_id, algorithm) DO UPDATE SET
                key_json = ?5,
                key_id = ?4,
                used = 0,
                ts_added_ms = ?6,
                ts_used_ms = 0
            )SQL";

            txn.execute(sql, {
              storage::SQLParam{user_id},
              storage::SQLParam{device_id},
              storage::SQLParam{algorithm},
              storage::SQLParam{key_id},
              storage::SQLParam{key_data.dump()},
              storage::SQLParam{now}
            });
          }

          success = true;
        });
    } catch (const std::exception&) {
      return false;
    }

    return success;
  }

  // --------------------------------------------------------------------------
  // Get fallback keys for a device
  // --------------------------------------------------------------------------
  std::map<std::string, json> get_fallback_keys(
      const std::string& user_id,
      const std::string& device_id) {

    std::map<std::string, json> result;

    db_.runInteraction("get_fallback_keys",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT algorithm, key_json, used
          FROM e2e_fallback_keys_json
          WHERE user_id = ?1 AND device_id = ?2
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{user_id},
          storage::SQLParam{device_id}
        });

        Row row;
        while (txn.iter_next(row)) {
          if (!row.empty() && row[0].value && row[1].value) {
            try {
              json key_data = json::parse(*row[1].value);
              result[*row[0].value] = key_data;
            } catch (...) {}
          }
        }
      });

    return result;
  }

  // --------------------------------------------------------------------------
  // Get unused fallback key types for a device
  // --------------------------------------------------------------------------
  std::vector<std::string> get_unused_fallback_key_types(
      const std::string& user_id,
      const std::string& device_id) {

    std::vector<std::string> result;

    db_.runInteraction("get_unused_fallback_key_types",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT algorithm
          FROM e2e_fallback_keys_json
          WHERE user_id = ?1 AND device_id = ?2 AND used = 0
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{user_id},
          storage::SQLParam{device_id}
        });

        Row row;
        while (txn.iter_next(row)) {
          if (!row.empty() && row[0].value) {
            result.push_back(*row[0].value);
          }
        }
      });

    return result;
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 6. CrossSigningManager — Cross-signing key upload and signatures
// ============================================================================

class CrossSigningManager {
public:
  explicit CrossSigningManager(storage::DatabasePool& db)
      : db_(db) {}

  // --------------------------------------------------------------------------
  // Upload E2E device keys (identity keys: ed25519, curve25519)
  // --------------------------------------------------------------------------
  bool upload_device_keys(const std::string& user_id,
                           const std::string& device_id,
                           const json& device_keys) {
    bool success = false;

    try {
      db_.runInteraction("upload_device_keys",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();

          std::string sql = R"SQL(
            INSERT INTO e2e_device_keys_json
              (user_id, device_id, ts_added_ms, key_json)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(user_id, device_id) DO UPDATE SET
              ts_added_ms = ?3,
              key_json = ?4
          )SQL";

          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id},
            storage::SQLParam{now},
            storage::SQLParam{device_keys.dump()}
          });

          success = true;
        });
    } catch (const std::exception&) {
      return false;
    }

    return success;
  }

  // --------------------------------------------------------------------------
  // Get device keys (for key query endpoint)
  // --------------------------------------------------------------------------
  std::map<std::string, std::map<std::string, json>>
  get_device_keys(const std::string& user_id,
                  const std::vector<std::string>& device_ids) {

    std::map<std::string, std::map<std::string, json>> result;

    db_.runInteraction("get_device_keys",
      [&](storage::LoggingTransaction& txn) {
        std::string sql;
        std::vector<storage::SQLParam> params;

        if (device_ids.empty()) {
          // Get all devices for user
          sql = R"SQL(
            SELECT user_id, device_id, key_json
            FROM e2e_device_keys_json
            WHERE user_id = ?1
          )SQL";
          params = {storage::SQLParam{user_id}};
        } else {
          // Get specific devices
          std::string in_list;
          params.push_back(storage::SQLParam{user_id});

          for (size_t i = 0; i < device_ids.size(); ++i) {
            if (i > 0) in_list += ", ";
            in_list += "?" + std::to_string(i + 2);
            params.push_back(storage::SQLParam{device_ids[i]});
          }

          sql = "SELECT user_id, device_id, key_json "
                "FROM e2e_device_keys_json "
                "WHERE user_id = ?1 AND device_id IN (" + in_list + ")";
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

    return result;
  }

  // --------------------------------------------------------------------------
  // Upload cross-signing key (master, self_signing, or user_signing)
  // --------------------------------------------------------------------------
  bool upload_cross_signing_key(const std::string& user_id,
                                 const std::string& key_type,
                                 const json& key_data) {

    if (key_type != KEY_TYPE_MASTER &&
        key_type != KEY_TYPE_SELF_SIGNING &&
        key_type != KEY_TYPE_USER_SIGNING) {
      return false;
    }

    bool success = false;

    try {
      db_.runInteraction("upload_cross_signing_key",
        [&](storage::LoggingTransaction& txn) {
          int64_t stream_id = device_store_.next_device_stream_id_txn(txn);

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

          success = true;
        });
    } catch (const std::exception&) {
      return false;
    }

    return success;
  }

  // --------------------------------------------------------------------------
  // Get cross-signing key
  // --------------------------------------------------------------------------
  std::optional<json> get_cross_signing_key(const std::string& user_id,
                                             const std::string& key_type) {
    std::optional<json> result;

    db_.runInteraction("get_cross_signing_key",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT key_data
          FROM e2e_cross_signing_keys
          WHERE user_id = ?1 AND key_type = ?2
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{user_id},
          storage::SQLParam{key_type}
        });

        Row row;
        if (txn.iter_next(row) && !row.empty() && row[0].value) {
          try {
            result = json::parse(*row[0].value);
          } catch (...) {}
        }
      });

    return result;
  }

  // --------------------------------------------------------------------------
  // Get all cross-signing keys for a user
  // --------------------------------------------------------------------------
  std::map<std::string, json> get_cross_signing_keys(
      const std::string& user_id) {

    std::map<std::string, json> result;

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

    return result;
  }

  // --------------------------------------------------------------------------
  // Bulk get cross-signing keys (for federation)
  // --------------------------------------------------------------------------
  std::map<std::string, std::map<std::string, json>>
  get_cross_signing_keys_bulk(const std::set<std::string>& user_ids) {
    std::map<std::string, std::map<std::string, json>> result;

    if (user_ids.empty()) return result;

    db_.runInteraction("get_cross_signing_keys_bulk",
      [&](storage::LoggingTransaction& txn) {
        std::string user_list;
        for (const auto& uid : user_ids) {
          if (!user_list.empty()) user_list += ",";
          user_list += sql_quote(uid);
        }

        std::string sql = "SELECT user_id, key_type, key_data "
                          "FROM e2e_cross_signing_keys "
                          "WHERE user_id IN (" + user_list + ")";

        txn.execute(sql);

        Row row;
        while (txn.iter_next(row)) {
          if (!row.empty() && row[0].value && row[1].value && row[2].value) {
            try {
              result[*row[0].value][*row[1].value] =
                  json::parse(*row[2].value);
            } catch (...) {}
          }
        }
      });

    return result;
  }

  // --------------------------------------------------------------------------
  // Store cross-signing signatures
  // --------------------------------------------------------------------------
  bool store_signatures(
      const std::string& user_id,
      const std::map<std::string,
                     std::map<std::string, std::string>>& signatures) {

    bool success = false;

    try {
      db_.runInteraction("store_signatures",
        [&](storage::LoggingTransaction& txn) {
          int64_t stream_id = device_store_.next_device_stream_id_txn(txn);
          int sig_count = 0;

          for (const auto& [key_type, sig_map] : signatures) {
            for (const auto& [signer_key, signature] : sig_map) {
              if (sig_count >= MAX_SIGNATURES_PER_REQUEST) break;

              // signer_key is "<user_id>:<device_id>"
              std::string signer_user_id = signer_key;
              auto colon = signer_key.find(':');
              if (colon != std::string::npos) {
                signer_user_id = signer_key.substr(0, colon);
              }

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

              sig_count++;
            }
          }

          success = true;
        });
    } catch (const std::exception&) {
      return false;
    }

    return success;
  }

  // --------------------------------------------------------------------------
  // Get signatures for a user's cross-signing key
  // --------------------------------------------------------------------------
  std::map<std::string, std::map<std::string, std::string>>
  get_signatures(const std::string& user_id,
                 const std::string& key_type) {

    std::map<std::string, std::map<std::string, std::string>> result;

    db_.runInteraction("get_signatures",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT signer_key, signature
          FROM e2e_cross_signing_signatures
          WHERE user_id = ?1 AND key_type = ?2
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{user_id},
          storage::SQLParam{key_type}
        });

        Row row;
        while (txn.iter_next(row)) {
          if (!row.empty() && row[0].value && row[1].value) {
            result[*row[0].value][*row[1].value] = "";  // edge case
            result[*row[0].value] = {};
            result[*row[0].value][*row[0].value] = *row[1].value;
          }
        }

        // Fix: properly group signatures by signer_key
        result.clear();
        txn.iter_reset();
        while (txn.iter_next(row)) {
          if (!row.empty() && row[0].value && row[1].value) {
            std::string signer_key = *row[0].value;
            std::string sig = *row[1].value;

            // signer_key is in "user_id:device_id" format
            auto colon = signer_key.find(':');
            if (colon != std::string::npos) {
              std::string signer_user = signer_key.substr(0, colon);
              std::string signer_device = signer_key.substr(colon + 1);
              result[signer_user][signer_device] = sig;
            }
          }
        }
      });

    return result;
  }

  // --------------------------------------------------------------------------
  // Get all user signature changes for federation
  // --------------------------------------------------------------------------
  std::vector<CrossSigningSignature> get_signature_changes(
      int64_t from_stream_id, int64_t to_stream_id) {

    std::vector<CrossSigningSignature> changes;

    db_.runInteraction("get_signature_changes",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT user_id, key_type, signer_user_id, signer_key, signature
          FROM e2e_cross_signing_signatures
          WHERE stream_id > ?1 AND stream_id <= ?2
          ORDER BY stream_id ASC
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{from_stream_id},
          storage::SQLParam{to_stream_id}
        });

        Row row;
        while (txn.iter_next(row)) {
          if (!row.empty()) {
            CrossSigningSignature cs;
            cs.user_id = row[0].value.value_or("");
            cs.key_type = row[1].value.value_or("");
            cs.signer_user_id = row[2].value.value_or("");
            cs.signer_key = row[3].value.value_or("");
            cs.signature = row[4].value.value_or("");
            changes.push_back(cs);
          }
        }
      });

    return changes;
  }

  // --------------------------------------------------------------------------
  // Check if master cross-signing key is known
  // --------------------------------------------------------------------------
  bool is_master_key_known(const std::string& user_id) {
    auto key = get_cross_signing_key(user_id, KEY_TYPE_MASTER);
    return key.has_value();
  }

  // --------------------------------------------------------------------------
  // Delete all E2E keys for a user
  // --------------------------------------------------------------------------
  void delete_e2e_keys_for_user(const std::string& user_id) {
    db_.runInteraction("delete_e2e_keys_for_user",
      [&](storage::LoggingTransaction& txn) {
        std::string sql1 =
            "DELETE FROM e2e_device_keys_json WHERE user_id = ?1";
        txn.execute(sql1, {storage::SQLParam{user_id}});

        std::string sql2 =
            "DELETE FROM e2e_one_time_keys_json WHERE user_id = ?1";
        txn.execute(sql2, {storage::SQLParam{user_id}});

        std::string sql3 =
            "DELETE FROM e2e_fallback_keys_json WHERE user_id = ?1";
        txn.execute(sql3, {storage::SQLParam{user_id}});

        std::string sql4 =
            "DELETE FROM e2e_cross_signing_keys WHERE user_id = ?1";
        txn.execute(sql4, {storage::SQLParam{user_id}});

        std::string sql5 =
            "DELETE FROM e2e_cross_signing_signatures WHERE user_id = ?1";
        txn.execute(sql5, {storage::SQLParam{user_id}});
      });
  }

private:
  storage::DatabasePool& db_;
  DeviceStore device_store_{db_};  // For stream ID generation
};

// ============================================================================
// 7. DehydratedDeviceManager — Dehydrated device support
// ============================================================================

class DehydratedDeviceManagerV2 {
public:
  explicit DehydratedDeviceManagerV2(storage::DatabasePool& db)
      : db_(db) {}

  // --------------------------------------------------------------------------
  // Create a dehydrated device
  // --------------------------------------------------------------------------
  bool create_dehydrated_device(
      const std::string& user_id,
      const std::string& device_id,
      const json& device_data,
      const json& device_keys,
      int64_t expiry_ms = DEHYDRATED_EXPIRY_MS) {

    // Clamp expiry
    int64_t expiry = std::max(DEHYDRATED_MIN_EXPIRY_MS,
                     std::min(expiry_ms, DEHYDRATED_MAX_EXPIRY_MS));

    // Validate device ID prefix
    if (device_id.find(DEHYDRATED_DEVICE_PREFIX) != 0) {
      return false;
    }

    bool success = false;

    try {
      db_.runInteraction("create_dehydrated_device",
        [&](storage::LoggingTransaction& txn) {
          create_dehydrated_device_txn(txn, user_id, device_id,
                                        device_data, device_keys, expiry,
                                        success);
        });
    } catch (const std::exception&) {
      return false;
    }

    return success;
  }

  void create_dehydrated_device_txn(
      storage::LoggingTransaction& txn,
      const std::string& user_id,
      const std::string& device_id,
      const json& device_data,
      const json& device_keys,
      int64_t expiry_ms,
      bool& success) {

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
      success = false;
      return;
    }

    int64_t now = now_ms();

    std::string sql = R"SQL(
      INSERT INTO dehydrated_devices
        (user_id, device_id, device_data, device_keys, algorithm,
         created_at, expires_at, reclaimed, pickle_key)
      VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, ?8)
      ON CONFLICT(user_id, device_id) DO UPDATE SET
        device_data = ?3,
        device_keys = ?4,
        algorithm = ?5,
        created_at = ?6,
        expires_at = ?7,
        reclaimed = 0,
        pickle_key = ?8
    )SQL";

    // Generate pickle key (random 32-byte key for encrypting device data)
    std::string pickle_key = random_hex_string(64);

    txn.execute(sql, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id},
      storage::SQLParam{device_data.dump()},
      storage::SQLParam{device_keys.dump()},
      storage::SQLParam{std::string(DEHYDRATION_ALGORITHM)},
      storage::SQLParam{now},
      storage::SQLParam{now + expiry_ms},
      storage::SQLParam{pickle_key}
    });

    success = true;
  }

  // --------------------------------------------------------------------------
  // Get dehydrated device for a user
  // --------------------------------------------------------------------------
  std::optional<DehydratedDevice> get_dehydrated_device(
      const std::string& user_id) {

    std::optional<DehydratedDevice> result;

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
          DehydratedDevice dd;
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

          // Don't return expired devices
          if (!dd.is_expired()) {
            result = dd;
          }
        }
      });

    return result;
  }

  // --------------------------------------------------------------------------
  // Reclaim (rehydrate) a dehydrated device
  // --------------------------------------------------------------------------
  bool reclaim_dehydrated_device(const std::string& user_id,
                                  const std::string& device_id) {
    bool success = false;

    try {
      db_.runInteraction("reclaim_dehydrated_device",
        [&](storage::LoggingTransaction& txn) {
          std::string sql = R"SQL(
            UPDATE dehydrated_devices
            SET reclaimed = 1
            WHERE user_id = ?1 AND device_id = ?2
          )SQL";

          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id}
          });

          success = (txn.rowcount() > 0);
        });
    } catch (const std::exception&) {
      return false;
    }

    return success;
  }

  // --------------------------------------------------------------------------
  // Delete a dehydrated device
  // --------------------------------------------------------------------------
  bool delete_dehydrated_device(const std::string& user_id,
                                 const std::string& device_id) {
    bool success = false;

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
          success = (txn.rowcount() > 0);

          // Also clean up dehydrated inbox
          if (success) {
            std::string inbox_sql = R"SQL(
              DELETE FROM dehydrated_device_inbox
              WHERE user_id = ?1 AND device_id = ?2
            )SQL";
            txn.execute(inbox_sql, {
              storage::SQLParam{user_id},
              storage::SQLParam{device_id}
            });
          }
        });
    } catch (const std::exception&) {
      return false;
    }

    return success;
  }

  // --------------------------------------------------------------------------
  // Store a to-device message for a dehydrated device
  // --------------------------------------------------------------------------
  bool queue_dehydrated_message(const std::string& user_id,
                                 const std::string& device_id,
                                 const json& content) {
    bool success = false;

    try {
      db_.runInteraction("queue_dehydrated_message",
        [&](storage::LoggingTransaction& txn) {
          // Check message count to avoid unbounded growth
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

          if (count >= MAX_DEHYDRATED_QUEUED_MSGS) {
            // Delete oldest messages to make room
            std::string del_sql = R"SQL(
              DELETE FROM dehydrated_device_inbox
              WHERE message_id IN (
                SELECT message_id FROM dehydrated_device_inbox
                WHERE user_id = ?1 AND device_id = ?2
                ORDER BY received_at ASC
                LIMIT ?3
              )
            )SQL";

            int to_delete = count - MAX_DEHYDRATED_QUEUED_MSGS + 1;
            txn.execute(del_sql, {
              storage::SQLParam{user_id},
              storage::SQLParam{device_id},
              storage::SQLParam{static_cast<int64_t>(to_delete)}
            });
          }

          // Insert the message
          int64_t now = now_ms();
          std::string sql = R"SQL(
            INSERT INTO dehydrated_device_inbox
              (user_id, device_id, content_json, received_at)
            VALUES (?1, ?2, ?3, ?4)
          )SQL";

          txn.execute(sql, {
            storage::SQLParam{user_id},
            storage::SQLParam{device_id},
            storage::SQLParam{content.dump()},
            storage::SQLParam{now}
          });

          success = true;
        });
    } catch (const std::exception&) {
      return false;
    }

    return success;
  }

  // --------------------------------------------------------------------------
  // Get queued messages for a dehydrated device
  // --------------------------------------------------------------------------
  std::vector<json> get_dehydrated_messages(const std::string& user_id,
                                              const std::string& device_id) {
    std::vector<json> messages;

    db_.runInteraction("get_dehydrated_messages",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT content_json
          FROM dehydrated_device_inbox
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

    return messages;
  }

  // --------------------------------------------------------------------------
  // Clean up expired dehydrated devices
  // --------------------------------------------------------------------------
  int cleanup_expired_dehydrated_devices() {
    int cleaned = 0;

    try {
      db_.runInteraction("cleanup_expired_dehydrated_devices",
        [&](storage::LoggingTransaction& txn) {
          int64_t now = now_ms();

          // Get expired devices
          std::string sel_sql = R"SQL(
            SELECT user_id, device_id
            FROM dehydrated_devices
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
            // Delete the device
            std::string del_sql = R"SQL(
              DELETE FROM dehydrated_devices
              WHERE user_id = ?1 AND device_id = ?2
            )SQL";
            txn.execute(del_sql, {
              storage::SQLParam{uid},
              storage::SQLParam{did}
            });

            // Clean inbox
            std::string inbox_sql = R"SQL(
              DELETE FROM dehydrated_device_inbox
              WHERE user_id = ?1 AND device_id = ?2
            )SQL";
            txn.execute(inbox_sql, {
              storage::SQLParam{uid},
              storage::SQLParam{did}
            });

            cleaned++;
          }
        });
    } catch (const std::exception&) {
      return 0;
    }

    return cleaned;
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 8. DeviceInboxManager — To-device message inbox
// ============================================================================

class DeviceInboxManager {
public:
  explicit DeviceInboxManager(storage::DatabasePool& db)
      : db_(db) {}

  // --------------------------------------------------------------------------
  // Add messages to device inbox
  // --------------------------------------------------------------------------
  void add_messages_to_inbox(
      const std::string& local_user_id,
      const std::string& message_id,
      const std::map<std::string, std::map<std::string, json>>&
          messages_by_device) {

    db_.runInteraction("add_messages_to_inbox",
      [&](storage::LoggingTransaction& txn) {
        int64_t now = now_ms();

        for (const auto& [device_id, messages] : messages_by_device) {
          // Get next stream ID for this device inbox
          int64_t stream_id = get_next_inbox_stream_id_txn(
              txn, local_user_id, device_id);

          for (const auto& [msg_type, content] : messages) {
            json full_content;
            full_content["type"] = msg_type;
            full_content["content"] = content;

            std::string sql = R"SQL(
              INSERT INTO device_inbox
                (user_id, device_id, stream_id, content_json, received_at)
              VALUES (?1, ?2, ?3, ?4, ?5)
            )SQL";

            txn.execute(sql, {
              storage::SQLParam{local_user_id},
              storage::SQLParam{device_id},
              storage::SQLParam{stream_id},
              storage::SQLParam{full_content.dump()},
              storage::SQLParam{now}
            });
          }

          // Enforce message limit per device
          enforce_inbox_limit_txn(txn, local_user_id, device_id);
        }
      });
  }

  // --------------------------------------------------------------------------
  // Get to-device messages since a stream token
  // --------------------------------------------------------------------------
  std::vector<json> get_to_device_messages(const std::string& user_id,
                                            const std::string& device_id,
                                            int64_t since_stream_id) {
    std::vector<json> messages;

    db_.runInteraction("get_to_device_messages",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT message_id, stream_id, content_json, received_at
          FROM device_inbox
          WHERE user_id = ?1 AND device_id = ?2
            AND stream_id > ?3
          ORDER BY stream_id ASC
          LIMIT 100
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{user_id},
          storage::SQLParam{device_id},
          storage::SQLParam{since_stream_id}
        });

        Row row;
        while (txn.iter_next(row)) {
          if (!row.empty() && row[2].value) {
            try {
              json entry;
              entry["message_id"] = row[0].value ? std::stoll(*row[0].value) : 0LL;
              entry["stream_id"] = row[1].value ? std::stoll(*row[1].value) : 0LL;
              entry["content"] = json::parse(*row[2].value);
              entry["received_at"] = row[3].value ? std::stoll(*row[3].value) : 0LL;
              messages.push_back(entry);
            } catch (...) {}
          }
        }
      });

    return messages;
  }

  // --------------------------------------------------------------------------
  // Delete messages up to a stream ID for a device
  // --------------------------------------------------------------------------
  void delete_messages_up_to(const std::string& user_id,
                              const std::string& device_id,
                              int64_t up_to_stream_id) {
    db_.runInteraction("delete_messages_up_to",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          DELETE FROM device_inbox
          WHERE user_id = ?1 AND device_id = ?2
            AND stream_id <= ?3
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{user_id},
          storage::SQLParam{device_id},
          storage::SQLParam{up_to_stream_id}
        });
      });
  }

  // --------------------------------------------------------------------------
  // Get min/max stream ID for a device inbox
  // --------------------------------------------------------------------------
  std::pair<int64_t, int64_t> get_inbox_stream_range(
      const std::string& user_id,
      const std::string& device_id) {
    std::pair<int64_t, int64_t> range{0, 0};

    db_.runInteraction("get_inbox_stream_range",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT min_stream_id, max_stream_id
          FROM device_inbox_sequence
          WHERE user_id = ?1 AND device_id = ?2
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{user_id},
          storage::SQLParam{device_id}
        });

        Row row;
        if (txn.iter_next(row) && !row.empty()) {
          range.first = row[0].value ? std::stoll(*row[0].value) : 0LL;
          range.second = row[1].value ? std::stoll(*row[1].value) : 0LL;
        }
      });

    return range;
  }

private:
  int64_t get_next_inbox_stream_id_txn(storage::LoggingTransaction& txn,
                                        const std::string& user_id,
                                        const std::string& device_id) {
    // Upsert the sequence record and increment
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

    // Read back the new max
    std::string sel_sql = R"SQL(
      SELECT max_stream_id FROM device_inbox_sequence
      WHERE user_id = ?1 AND device_id = ?2
    )SQL";

    txn.execute(sel_sql, {
      storage::SQLParam{user_id},
      storage::SQLParam{device_id}
    });

    Row row;
    if (txn.iter_next(row) && !row.empty() && row[0].value) {
      return std::stoll(*row[0].value);
    }

    return 1;
  }

  void enforce_inbox_limit_txn(storage::LoggingTransaction& txn,
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
      // Delete oldest messages, keeping latest MAX_DEVICE_INBOX_MESSAGES
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
// 9. DeviceChangeNotifier — Device list change notification
// ============================================================================

class DeviceChangeNotifier {
public:
  explicit DeviceChangeNotifier(storage::DatabasePool& db)
      : db_(db) {}

  // --------------------------------------------------------------------------
  // Notify local users about device list changes (for /sync responses)
  // --------------------------------------------------------------------------
  std::map<std::string, std::vector<std::string>>
  get_device_list_changes(int64_t from_token, int64_t to_token) {
    DeviceStore ds(db_);
    return ds.get_users_whose_devices_changed(from_token, to_token);
  }

  // --------------------------------------------------------------------------
  // Notify remote servers (for federation EDUs)
  // --------------------------------------------------------------------------
  std::vector<DeviceListEntry> get_federation_device_changes(
      int64_t from_id, int64_t to_id) {
    DeviceStore ds(db_);
    return ds.get_device_list_changes_for_remotes(from_id, to_id);
  }

  // --------------------------------------------------------------------------
  // Get device list changes for a specific destination
  // --------------------------------------------------------------------------
  std::vector<DeviceListEntry> get_pending_pokes_for_destination(
      const std::string& destination, int64_t limit = 100) {

    std::vector<DeviceListEntry> entries;

    db_.runInteraction("get_pending_pokes_for_destination",
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
          storage::SQLParam{limit}
        });

        Row row;
        while (txn.iter_next(row)) {
          if (!row.empty()) {
            DeviceListEntry entry;
            entry.stream_id = row[0].value ? std::stoll(*row[0].value) : 0;
            entry.user_id = row[1].value.value_or("");
            entry.device_id = row[2].value.value_or("");
            entries.push_back(entry);
          }
        }
      });

    return entries;
  }

  // --------------------------------------------------------------------------
  // Mark destination as up-to-date
  // --------------------------------------------------------------------------
  void mark_destination_up_to_date(const std::string& destination,
                                    const std::set<std::string>& user_ids) {
    db_.runInteraction("mark_destination_up_to_date",
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
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 10. DeviceTrackingService — IP, UA, and activity tracking
// ============================================================================

class DeviceTrackingService {
public:
  explicit DeviceTrackingService(storage::DatabasePool& db)
      : db_(db) {}

  // --------------------------------------------------------------------------
  // Track device activity (called on every authenticated request)
  // --------------------------------------------------------------------------
  void track_activity(const std::string& user_id,
                      const std::string& device_id,
                      const std::string& ip_address,
                      const std::string& user_agent) {
    db_.runInteraction("track_activity",
      [&](storage::LoggingTransaction& txn) {
        int64_t now = now_ms();

        std::string sql = R"SQL(
          UPDATE devices
          SET last_seen_ip = ?1,
              last_seen_user_agent = ?2,
              last_seen_ts = ?3
          WHERE user_id = ?4 AND device_id = ?5
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{ip_address},
          storage::SQLParam{user_agent},
          storage::SQLParam{now},
          storage::SQLParam{user_id},
          storage::SQLParam{device_id}
        });
      });
  }

  // --------------------------------------------------------------------------
  // Get stale devices (not seen for N milliseconds)
  // --------------------------------------------------------------------------
  std::vector<DeviceEntity> get_stale_devices(int64_t stale_threshold_ms) {
    std::vector<DeviceEntity> devices;

    db_.runInteraction("get_stale_devices",
      [&](storage::LoggingTransaction& txn) {
        int64_t threshold = now_ms() - stale_threshold_ms;

        std::string sql = R"SQL(
          SELECT user_id, device_id, display_name, last_seen_ip,
                 last_seen_user_agent, last_seen_ts, created_at,
                 device_type, hidden, access_token_hash, verification_state
          FROM devices
          WHERE last_seen_ts < ?1 AND last_seen_ts > 0 AND hidden = 0
          ORDER BY last_seen_ts ASC
        )SQL";

        txn.execute(sql, {storage::SQLParam{threshold}});

        Row row;
        while (txn.iter_next(row)) {
          if (!row.empty()) {
            DeviceEntity d;
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
            devices.push_back(d);
          }
        }
      });

    return devices;
  }

  // --------------------------------------------------------------------------
  // Get device access log (recent activity)
  // --------------------------------------------------------------------------
  std::vector<json> get_device_activity_log(const std::string& user_id,
                                              const std::string& device_id,
                                              int limit = 50) {
    std::vector<json> log;

    db_.runInteraction("get_device_activity_log",
      [&](storage::LoggingTransaction& txn) {
        std::string sql = R"SQL(
          SELECT ip_address, user_agent, last_used_at
          FROM device_sessions
          WHERE user_id = ?1 AND device_id = ?2
          ORDER BY last_used_at DESC
          LIMIT ?3
        )SQL";

        txn.execute(sql, {
          storage::SQLParam{user_id},
          storage::SQLParam{device_id},
          storage::SQLParam{static_cast<int64_t>(limit)}
        });

        Row row;
        while (txn.iter_next(row)) {
          if (!row.empty()) {
            json entry;
            entry["ip_address"] = row[0].value.value_or("");
            entry["user_agent"] = row[1].value.value_or("");
            entry["last_used_at"] = row[2].value ?
                std::stoll(*row[2].value) : 0LL;
            log.push_back(entry);
          }
        }
      });

    return log;
  }

private:
  storage::DatabasePool& db_;
};

// ============================================================================
// 11. DeviceManagerV2 — Main orchestrator class
// ============================================================================

class DeviceManagerV2 {
public:
  // ---- Public data structures ----
  struct DeviceInfo {
    std::string device_id;
    std::string display_name;
    std::string last_seen_ip;
    std::string last_seen_user_agent;
    int64_t last_seen_ts{0};
    int64_t created_at{0};
    std::string device_type;
    std::string user_agent;
    bool is_current{false};
    DeviceVerificationState verification_state{DeviceVerificationState::UNVERIFIED};

    json to_json() const {
      json j;
      j["device_id"] = device_id;
      if (!display_name.empty()) j["display_name"] = display_name;
      if (!last_seen_ip.empty()) j["last_seen_ip"] = last_seen_ip;
      if (!last_seen_user_agent.empty()) j["last_seen_user_agent"] = last_seen_user_agent;
      j["last_seen_ts"] = last_seen_ts;
      j["created_at"] = created_at;
      if (!device_type.empty()) j["device_type"] = device_type;
      return j;
    }
  };

  struct DeviceListResult {
    bool success{false};
    std::vector<DeviceInfo> devices;
    int total_count{0};
    std::string error;
    std::string errcode;
  };

  struct DeviceActionResult {
    bool success{false};
    std::string error;
    std::string errcode;
    std::string device_id;
    json data;
  };

  struct KeyUploadResult {
    bool success{false};
    std::map<std::string, int> one_time_key_counts;
    std::string error;
    std::string errcode;
  };

  struct KeyQueryResult {
    bool success{false};
    std::map<std::string, std::map<std::string, json>> device_keys;
    std::map<std::string, std::map<std::string, json>> signatures;
    std::map<std::string, std::map<std::string,
             std::map<std::string, int64_t>>> one_time_key_counts;
    std::string error;
    std::string errcode;
  };

  // ---- Constructor ----
  DeviceManagerV2(storage::DatabasePool& db,
                  const std::string& server_name)
      : db_(db),
        server_name_(server_name),
        device_store_(db),
        otk_manager_(db),
        fallback_manager_(db),
        cross_signing_manager_(db),
        dehydrated_manager_(db),
        inbox_manager_(db),
        change_notifier_(db),
        tracking_service_(db) {}

  // --------------------------------------------------------------------------
  // Schema initialization
  // --------------------------------------------------------------------------
  static void create_all_tables(storage::LoggingTransaction& txn) {
    DeviceStore::create_tables(txn);
  }

  // --------------------------------------------------------------------------
  // Device registration on login
  // --------------------------------------------------------------------------
  DeviceActionResult register_device_on_login(
      const std::string& user_id,
      const std::string& device_id,
      const std::string& initial_display_name,
      const std::string& ip_address,
      const std::string& user_agent,
      const std::string& device_type) {

    DeviceActionResult result;

    // Generate device ID if not provided
    std::string effective_device_id = device_id;
    if (effective_device_id.empty()) {
      effective_device_id = generate_device_id();
    }

    if (!is_valid_device_id(effective_device_id)) {
      result.success = false;
      result.error = "Invalid device ID format";
      result.errcode = "M_INVALID_PARAM";
      return result;
    }

    // Generate access token
    std::string access_token = generate_access_token();
    std::string token_hash = sha256_hash(access_token);

    // Register device in database
    auto reg_result = device_store_.register_device(
        user_id, effective_device_id, initial_display_name,
        ip_address, user_agent, token_hash, device_type);

    if (!reg_result.success) {
      result.success = false;
      result.error = reg_result.error;
      result.errcode = reg_result.errcode;
      return result;
    }

    // Create session
    int64_t expires_at = now_ms() + (3600LL * 1000LL);  // 1 hour default
    device_store_.create_session(token_hash, user_id,
                                  effective_device_id,
                                  ip_address, user_agent, expires_at);

    result.success = true;
    result.device_id = effective_device_id;
    result.data = {
      {"device_id", effective_device_id},
      {"access_token", access_token},
      {"user_id", user_id},
      {"home_server", server_name_},
      {"device_info", reg_result.device_info}
    };

    return result;
  }

  // --------------------------------------------------------------------------
  // List devices
  // --------------------------------------------------------------------------
  DeviceListResult list_devices(const std::string& user_id,
                                 const std::string& current_token) {
    DeviceListResult result;

    if (!is_valid_user_id(user_id)) {
      result.success = false;
      result.error = "Invalid user ID";
      result.errcode = "M_INVALID_PARAM";
      return result;
    }

    // Find current device ID from token
    std::string current_device_id;
    std::string token_hash = sha256_hash(current_token);
    auto session = device_store_.get_session(token_hash);
    if (session.has_value()) {
      current_device_id = jstr(*session, "device_id");
    }

    auto devices = device_store_.get_devices_for_user(user_id);
    if (!devices.success) {
      result.success = false;
      result.error = devices.error;
      result.errcode = devices.errcode;
      return result;
    }

    for (const auto& d : devices.devices) {
      DeviceInfo info;
      info.device_id = d.device_id;
      info.display_name = d.display_name;
      info.last_seen_ip = d.last_seen_ip;
      info.last_seen_user_agent = d.last_seen_user_agent;
      info.last_seen_ts = d.last_seen_ts;
      info.created_at = d.created_at;
      info.device_type = d.device_type;
      info.is_current = (d.device_id == current_device_id);
      info.verification_state = d.verification_state;
      result.devices.push_back(info);
    }

    result.total_count = static_cast<int>(result.devices.size());
    result.success = true;
    return result;
  }

  // --------------------------------------------------------------------------
  // Get single device
  // --------------------------------------------------------------------------
  DeviceActionResult get_device_info(const std::string& user_id,
                                      const std::string& device_id) {
    DeviceActionResult result;

    auto dev = device_store_.get_device(user_id, device_id);
    if (!dev.has_value()) {
      result.success = false;
      result.error = "Device not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    result.success = true;
    result.device_id = device_id;
    result.data = dev->to_json();
    result.data["verification_state"] =
        static_cast<int>(dev->verification_state);
    return result;
  }

  // --------------------------------------------------------------------------
  // Update device display name
  // --------------------------------------------------------------------------
  DeviceActionResult update_device_display_name(
      const std::string& user_id,
      const std::string& device_id,
      const std::string& display_name) {

    DeviceActionResult result;

    if (display_name.size() > MAX_DISPLAY_NAME_LENGTH) {
      result.success = false;
      result.error = "Display name too long (max " +
                     std::to_string(MAX_DISPLAY_NAME_LENGTH) + " characters)";
      result.errcode = "M_INVALID_PARAM";
      return result;
    }

    bool updated = device_store_.update_device_display_name(
        user_id, device_id, display_name);

    if (!updated) {
      result.success = false;
      result.error = "Device not found or update failed";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    result.success = true;
    result.device_id = device_id;
    return result;
  }

  // --------------------------------------------------------------------------
  // Delete device (logout)
  // --------------------------------------------------------------------------
  DeviceActionResult delete_device(const std::string& user_id,
                                    const std::string& device_id,
                                    const std::string& current_token) {
    DeviceActionResult result;

    // Verify the device exists and belongs to user
    auto dev = device_store_.get_device(user_id, device_id);
    if (!dev.has_value()) {
      result.success = false;
      result.error = "Device not found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    // Revoke current session if deleting current device
    std::string token_hash = sha256_hash(current_token);
    device_store_.revoke_session(token_hash);

    // Delete the device
    bool deleted = device_store_.delete_device(user_id, device_id);
    if (!deleted) {
      result.success = false;
      result.error = "Failed to delete device";
      result.errcode = "M_UNKNOWN";
      return result;
    }

    result.success = true;
    result.device_id = device_id;
    return result;
  }

  // --------------------------------------------------------------------------
  // Delete all devices except current
  // --------------------------------------------------------------------------
  DeviceActionResult delete_all_devices_except_current(
      const std::string& user_id,
      const std::string& current_token) {

    DeviceActionResult result;

    std::string token_hash = sha256_hash(current_token);
    auto session = device_store_.get_session(token_hash);
    if (!session.has_value()) {
      result.success = false;
      result.error = "Invalid token";
      result.errcode = "M_UNKNOWN_TOKEN";
      return result;
    }

    std::string current_device_id = jstr(*session, "device_id");
    if (current_device_id.empty()) {
      result.success = false;
      result.error = "No device associated with token";
      result.errcode = "M_UNKNOWN";
      return result;
    }

    int deleted = device_store_.delete_all_devices(user_id, current_device_id);

    result.success = true;
    result.data = {
      {"devices_deleted", deleted},
      {"kept_device", current_device_id}
    };
    return result;
  }

  // --------------------------------------------------------------------------
  // Admin: delete all devices for a user
  // --------------------------------------------------------------------------
  DeviceActionResult admin_delete_all_devices(const std::string& user_id) {
    DeviceActionResult result;

    // Also clean up E2E keys
    cross_signing_manager_.delete_e2e_keys_for_user(user_id);

    int deleted = device_store_.delete_all_devices(user_id, std::nullopt);

    result.success = true;
    result.data = {
      {"devices_deleted", deleted},
      {"user_id", user_id},
      {"e2e_keys_cleaned", true}
    };
    return result;
  }

  // --------------------------------------------------------------------------
  // Update device tracking (last seen)
  // --------------------------------------------------------------------------
  void track_device_activity(const std::string& user_id,
                              const std::string& device_id,
                              const std::string& ip_address,
                              const std::string& user_agent) {
    tracking_service_.track_activity(user_id, device_id,
                                      ip_address, user_agent);
  }

  // --------------------------------------------------------------------------
  // Get stash devices
  // --------------------------------------------------------------------------
  std::vector<DeviceInfo> get_stale_devices(int64_t stale_threshold_ms) {
    std::vector<DeviceInfo> result;
    auto devices = tracking_service_.get_stale_devices(stale_threshold_ms);
    for (const auto& d : devices) {
      DeviceInfo info;
      info.device_id = d.device_id;
      info.display_name = d.display_name;
      info.last_seen_ip = d.last_seen_ip;
      info.last_seen_user_agent = d.last_seen_user_agent;
      info.last_seen_ts = d.last_seen_ts;
      info.created_at = d.created_at;
      result.push_back(info);
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Count devices for a user
  // --------------------------------------------------------------------------
  int64_t count_devices(const std::string& user_id) {
    return device_store_.count_devices_for_user(user_id);
  }

  // --------------------------------------------------------------------------
  // One-time key upload
  // --------------------------------------------------------------------------
  KeyUploadResult upload_one_time_keys(
      const std::string& user_id,
      const std::string& device_id,
      const std::map<std::string, std::map<std::string, json>>& keys) {

    KeyUploadResult result;

    auto r = otk_manager_.upload_one_time_keys(user_id, device_id, keys);
    if (!r.success) {
      result.success = false;
      result.error = r.error;
      result.errcode = r.errcode;
      return result;
    }

    result.success = true;
    result.one_time_key_counts = r.counts;
    return result;
  }

  // --------------------------------------------------------------------------
  // One-time key count
  // --------------------------------------------------------------------------
  KeyUploadResult count_one_time_keys(const std::string& user_id,
                                       const std::string& device_id) {
    KeyUploadResult result;

    auto r = otk_manager_.count_one_time_keys(user_id, device_id);
    if (!r.success) {
      result.success = false;
      result.error = r.error;
      result.errcode = r.errcode;
      return result;
    }

    result.success = true;
    result.one_time_key_counts = r.counts;
    return result;
  }

  // --------------------------------------------------------------------------
  // Claim one-time keys
  // --------------------------------------------------------------------------
  KeyQueryResult claim_keys(
      const std::map<std::string,
                     std::map<std::string,
                              std::map<std::string, int>>>& query) {

    KeyQueryResult result;

    auto claim = otk_manager_.claim_one_time_keys(query);
    if (!claim.success) {
      result.success = false;
      result.error = claim.error;
      result.errcode = claim.errcode;
      return result;
    }

    result.success = true;
    result.device_keys = claim.keys;
    if (!claim.fallback_keys.empty()) {
      result.device_keys.insert(
          claim.fallback_keys.begin(), claim.fallback_keys.end());
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Upload fallback keys
  // --------------------------------------------------------------------------
  DeviceActionResult upload_fallback_keys(
      const std::string& user_id,
      const std::string& device_id,
      const std::map<std::string, json>& fallback_keys) {

    DeviceActionResult result;

    bool ok = fallback_manager_.upload_fallback_keys(
        user_id, device_id, fallback_keys);
    result.success = ok;
    if (!ok) {
      result.error = "Failed to upload fallback keys";
      result.errcode = "M_UNKNOWN";
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Upload device identity keys
  // --------------------------------------------------------------------------
  DeviceActionResult upload_device_keys(const std::string& user_id,
                                         const std::string& device_id,
                                         const json& device_keys) {
    DeviceActionResult result;

    bool ok = cross_signing_manager_.upload_device_keys(
        user_id, device_id, device_keys);
    result.success = ok;
    if (!ok) {
      result.error = "Failed to upload device keys";
      result.errcode = "M_UNKNOWN";
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Upload cross-signing key
  // --------------------------------------------------------------------------
  DeviceActionResult upload_cross_signing_key(
      const std::string& user_id,
      const std::string& key_type,
      const json& key_data) {

    DeviceActionResult result;

    bool ok = cross_signing_manager_.upload_cross_signing_key(
        user_id, key_type, key_data);
    result.success = ok;
    if (!ok) {
      result.error = "Failed to upload cross-signing key";
      result.errcode = "M_UNKNOWN";
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Get cross-signing keys
  // --------------------------------------------------------------------------
  json get_cross_signing_keys_for_user(const std::string& user_id) {
    json result;
    auto keys = cross_signing_manager_.get_cross_signing_keys(user_id);
    for (const auto& [key_type, key_data] : keys) {
      result[key_type] = key_data;
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Upload cross-signing signatures
  // --------------------------------------------------------------------------
  DeviceActionResult upload_signatures(
      const std::string& user_id,
      const std::map<std::string,
                     std::map<std::string, std::string>>& signatures) {

    DeviceActionResult result;

    bool ok = cross_signing_manager_.store_signatures(user_id, signatures);
    result.success = ok;
    if (!ok) {
      result.error = "Failed to store signatures";
      result.errcode = "M_UNKNOWN";
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Query device keys (federation key query or local key query)
  // --------------------------------------------------------------------------
  KeyQueryResult query_device_keys(
      const std::map<std::string, std::vector<std::string>>& query_map,
      int64_t timeout_ms = 10000) {

    KeyQueryResult result;

    std::set<std::string> user_ids;
    for (const auto& [uid, _] : query_map) {
      user_ids.insert(uid);
    }

    for (const auto& [user_id, device_ids] : query_map) {
      // Get device identity keys
      auto dev_keys = cross_signing_manager_.get_device_keys(
          user_id, device_ids);
      for (const auto& [uid, dev_map] : dev_keys) {
        result.device_keys[uid] = dev_map;
      }

      // Get cross-signing keys
      auto cs_keys = cross_signing_manager_.get_cross_signing_keys(user_id);
      for (const auto& [key_type, key_data] : cs_keys) {
        result.device_keys[user_id][key_type] = key_data;
      }

      // Get signatures
      for (const auto& kt : {KEY_TYPE_MASTER, KEY_TYPE_SELF_SIGNING,
                              KEY_TYPE_USER_SIGNING}) {
        auto sigs = cross_signing_manager_.get_signatures(user_id, kt);
        if (!sigs.empty()) {
          result.signatures[user_id][kt] = json(sigs);
        }
      }
    }

    // Get one-time key counts
    if (!user_ids.empty()) {
      auto otk_counts = otk_manager_.count_bulk_one_time_keys(user_ids);
      result.one_time_key_counts = otk_counts;
    }

    result.success = true;
    return result;
  }

  // --------------------------------------------------------------------------
  // Dehydrated device operations
  // --------------------------------------------------------------------------
  DeviceActionResult create_dehydrated_device(
      const std::string& user_id,
      const json& device_data,
      const json& device_keys,
      int64_t expiry_ms = DEHYDRATED_EXPIRY_MS) {

    DeviceActionResult result;

    // Generate dehydrated device ID
    std::string device_id = std::string(DEHYDRATED_DEVICE_PREFIX) +
                            random_hex_string(16);

    bool ok = dehydrated_manager_.create_dehydrated_device(
        user_id, device_id, device_data, device_keys, expiry_ms);

    result.success = ok;
    if (ok) {
      result.device_id = device_id;
      result.data = {
        {"device_id", device_id},
        {"algorithm", DEHYDRATION_ALGORITHM},
        {"expires_in_ms", expiry_ms}
      };
    } else {
      result.error = "Failed to create dehydrated device";
      result.errcode = "M_UNKNOWN";
    }

    return result;
  }

  DeviceActionResult get_dehydrated_device(const std::string& user_id) {
    DeviceActionResult result;

    auto dd = dehydrated_manager_.get_dehydrated_device(user_id);
    if (!dd.has_value()) {
      result.success = false;
      result.error = "No active dehydrated device found";
      result.errcode = "M_NOT_FOUND";
      return result;
    }

    result.success = true;
    result.device_id = dd->device_id;
    result.data = {
      {"device_id", dd->device_id},
      {"device_data", dd->device_data},
      {"device_keys", dd->device_keys},
      {"algorithm", dd->algorithm},
      {"created_at", dd->created_at},
      {"expires_at", dd->expires_at},
      {"pickle_key", dd->pickle_key}
    };
    return result;
  }

  DeviceActionResult rehydrate_device(const std::string& user_id,
                                       const std::string& device_id) {
    DeviceActionResult result;

    bool ok = dehydrated_manager_.reclaim_dehydrated_device(
        user_id, device_id);
    result.success = ok;
    if (!ok) {
      result.error = "Failed to rehydrate device";
      result.errcode = "M_NOT_FOUND";
    }
    return result;
  }

  DeviceActionResult delete_dehydrated_device(
      const std::string& user_id,
      const std::string& device_id) {

    DeviceActionResult result;

    bool ok = dehydrated_manager_.delete_dehydrated_device(
        user_id, device_id);
    result.success = ok;
    if (!ok) {
      result.error = "Failed to delete dehydrated device";
      result.errcode = "M_NOT_FOUND";
    }
    return result;
  }

  // --------------------------------------------------------------------------
  // Queue a to-device message for a dehydrated device
  // --------------------------------------------------------------------------
  bool queue_dehydrated_to_device(const std::string& user_id,
                                   const std::string& device_id,
                                   const json& content) {
    return dehydrated_manager_.queue_dehydrated_message(
        user_id, device_id, content);
  }

  // --------------------------------------------------------------------------
  // Get queued messages for a dehydrated device
  // --------------------------------------------------------------------------
  std::vector<json> get_dehydrated_to_device_messages(
      const std::string& user_id, const std::string& device_id) {
    return dehydrated_manager_.get_dehydrated_messages(user_id, device_id);
  }

  // --------------------------------------------------------------------------
  // Cleanup expired dehydrated devices
  // --------------------------------------------------------------------------
  int cleanup_expired_dehydrated() {
    return dehydrated_manager_.cleanup_expired_dehydrated_devices();
  }

  // --------------------------------------------------------------------------
  // Device inbox operations
  // --------------------------------------------------------------------------
  void add_to_device_messages(
      const std::string& user_id,
      const std::string& message_id,
      const std::map<std::string, std::map<std::string, json>>&
          messages_by_device) {
    inbox_manager_.add_messages_to_inbox(user_id, message_id,
                                          messages_by_device);
  }

  std::vector<json> get_to_device_messages(const std::string& user_id,
                                            const std::string& device_id,
                                            int64_t since_stream_id) {
    return inbox_manager_.get_to_device_messages(
        user_id, device_id, since_stream_id);
  }

  void delete_to_device_messages_up_to(const std::string& user_id,
                                        const std::string& device_id,
                                        int64_t up_to_stream_id) {
    inbox_manager_.delete_messages_up_to(user_id, device_id,
                                          up_to_stream_id);
  }

  // --------------------------------------------------------------------------
  // Verify a session/token is valid
  // --------------------------------------------------------------------------
  std::optional<json> verify_token(const std::string& access_token) {
    std::string token_hash = sha256_hash(access_token);
    auto session = device_store_.get_session(token_hash);

    if (!session.has_value()) return std::nullopt;

    // Check if revoked
    if (jbool(*session, "revoked", false)) return std::nullopt;

    // Check if expired
    int64_t expires_at = jint(*session, "expires_at", 0LL);
    if (expires_at > 0 && now_ms() > expires_at) {
      device_store_.revoke_session(token_hash);
      return std::nullopt;
    }

    return session;
  }

  // --------------------------------------------------------------------------
  // Device list changes for /sync
  // --------------------------------------------------------------------------
  std::map<std::string, std::vector<std::string>>
  get_device_list_changes_since(int64_t from_token, int64_t to_token) {
    return change_notifier_.get_device_list_changes(from_token, to_token);
  }

  // --------------------------------------------------------------------------
  // Get max device stream ID
  // --------------------------------------------------------------------------
  int64_t get_max_device_stream_id() {
    return device_store_.get_device_max_stream_id();
  }

private:
  storage::DatabasePool& db_;
  std::string server_name_;

  DeviceStore device_store_;
  OneTimeKeyManager otk_manager_;
  FallbackKeyManager fallback_manager_;
  CrossSigningManager cross_signing_manager_;
  DehydratedDeviceManagerV2 dehydrated_manager_;
  DeviceInboxManager inbox_manager_;
  DeviceChangeNotifier change_notifier_;
  DeviceTrackingService tracking_service_;
};

// ============================================================================
// 12. Global factory function and cleanup
// ============================================================================

// Factory to create a DeviceManagerV2 instance
// The caller owns the DatabasePool and must ensure it outlives the manager.
std::unique_ptr<DeviceManagerV2> create_device_manager(
    storage::DatabasePool& db, const std::string& server_name) {
  return std::make_unique<DeviceManagerV2>(db, server_name);
}

// Schema initialization helper
void initialize_device_schema(storage::LoggingTransaction& txn) {
  DeviceStore::create_tables(txn);
}

// Background task: cleanup expired dehydrated devices
int run_dehydrated_cleanup(DeviceManagerV2& manager) {
  return manager.cleanup_expired_dehydrated();
}

// Background task: cleanup expired sessions
int run_session_cleanup(storage::DatabasePool& db) {
  int cleaned = 0;

  try {
    db.runInteraction("session_cleanup",
      [&](storage::LoggingTransaction& txn) {
        int64_t now = now_ms();

        std::string del_sql = R"SQL(
          DELETE FROM device_sessions
          WHERE expires_at > 0 AND expires_at < ?1
        )SQL";
        txn.execute(del_sql, {storage::SQLParam{now}});
        cleaned = static_cast<int>(txn.rowcount());
      });
  } catch (const std::exception&) {}

  return cleaned;
}

// ============================================================================
// End namespace progressive
// ============================================================================
} // namespace progressive
